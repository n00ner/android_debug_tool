"""apkdbg CLI — one command per invocation, one minified JSON line per reply.

For stateful debugging (breakpoint -> events -> read_var -> ...), spawning a
fresh process per command disconnects the JDWP socket each time. Use
`apkdbg serve` (JSON-RPC over stdio) for agent integration; the CLI debug
verbs are for one-shot actions (each does connect -> act -> disconnect when
--pkg is given) and for the stateless init/query commands.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import commands
from .commands import Ctx
from .errors import ApkDbgError
from .protocol import emit, err, ok


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="apkdbg")
    p.add_argument("--project", default=".", help="apkdbg project dir")
    p.add_argument("--serial", default=None, help="adb device serial")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="decompile APK and build mapping DB "
                                     "(transactional re-index)")
    sp.add_argument("--apk", required=True)
    sp.add_argument("--out", default=".")
    sp.add_argument("--skip-apktool", action="store_true",
                    help="reuse cached apktool output (must match the APK's "
                         "recorded provenance)")
    sp.add_argument("--skip-jadx", action="store_true",
                    help="no jadx enrichment: reuse cached jadx output when "
                         "its provenance matches, else proceed jadx-free")

    sp = sub.add_parser("classes", help="search classes in mapping DB")
    sp.add_argument("--filter", default="")
    sp.add_argument("--limit", type=int, default=50)

    sp = sub.add_parser("methods", help="list methods of a class")
    sp.add_argument("class_", metavar="class")

    sp = sub.add_parser("res", help="look up resources")
    sp.add_argument("--name")
    sp.add_argument("--id")

    sp = sub.add_parser("res_refs", help="call sites of a resource id")
    sp.add_argument("--id", required=True)

    sp = sub.add_parser("connect", help="attach JDWP to app")
    sp.add_argument("--pkg")
    sp.add_argument("--launch", action="store_true")
    sp.add_argument("--activity")
    sp.add_argument("--timeout", type=int, default=30)
    sp.add_argument("--recovery", choices=["kill-server"], default=None,
                    help="explicitly allow a global adb server restart as "
                         "last-resort recovery (default: session-scoped "
                         "only — never touches other sessions' forwards)")

    sp = sub.add_parser("restore", help="re-install symbolic "
                                        "breakpoints/hooks after a reconnect")
    sp.add_argument("--pkg")

    sp = sub.add_parser("bp", help="set breakpoint: com.foo.Class.method:42")
    sp.add_argument("spec")
    sp.add_argument("--pkg")

    sp = sub.add_parser("bp_del")
    sp.add_argument("request_id", type=int)

    sub.add_parser("bp_list")

    sp = sub.add_parser("events", help="wait for debug events")
    sp.add_argument("--timeout", type=float, default=60.0)
    sp.add_argument("--pkg")

    sp = sub.add_parser("read_var")
    sp.add_argument("--thread", type=int, required=True)
    sp.add_argument("--name")
    sp.add_argument("--slot", type=int)
    sp.add_argument("--frame", type=int, default=0)
    sp.add_argument("--pkg")

    sp = sub.add_parser("write_var")
    sp.add_argument("--thread", type=int, required=True)
    sp.add_argument("--name")
    sp.add_argument("--slot", type=int)
    sp.add_argument("--frame", type=int, default=0)
    sp.add_argument("--value", required=True, help="JSON value")
    sp.add_argument("--vtype")
    sp.add_argument("--pkg")

    sp = sub.add_parser("invoke")
    sp.add_argument("--thread", type=int, required=True)
    sp.add_argument("--obj", type=int, required=True)
    sp.add_argument("--method", required=True)
    sp.add_argument("--sig", default="")
    sp.add_argument("--args", help="JSON list")
    sp.add_argument("--pkg")

    sp = sub.add_parser("step")
    sp.add_argument("--thread", type=int, required=True)
    sp.add_argument("--kind", default="over", choices=["into", "over", "out"])
    sp.add_argument("--timeout", type=float, default=30.0)
    sp.add_argument("--pkg")

    sp = sub.add_parser("resume")
    sp.add_argument("--thread", type=int)
    sp.add_argument("--pkg")

    sp = sub.add_parser("snapshot")
    sp.add_argument("--thread", type=int, required=True)
    sp.add_argument("--depth", type=int, default=3)
    sp.add_argument("--record", action="store_true",
                    help="persist as an artifact under a run manifest")
    sp.add_argument("--run-id", help="attach to an existing run")
    sp.add_argument("--scenario")
    sp.add_argument("--collect-aliases", action="store_true",
                    help="feed captured strings to the alias collector "
                         "(implies --record for evidence)")
    sp.add_argument("--pkg")

    sp = sub.add_parser("dump_object")
    sp.add_argument("--obj", type=int, required=True)
    sp.add_argument("--depth", type=int, default=3)
    sp.add_argument("--record", action="store_true",
                    help="persist as an artifact under a run manifest")
    sp.add_argument("--run-id", help="attach to an existing run")
    sp.add_argument("--scenario")
    sp.add_argument("--collect-aliases", action="store_true",
                    help="feed captured strings to the alias collector "
                         "(implies --record for evidence)")
    sp.add_argument("--pkg")

    sp = sub.add_parser("cond", help="conditional breakpoint")
    sp.add_argument("spec")
    sp.add_argument("--pred", required=True, help="JSON predicate")
    sp.add_argument("--capture", required=True, help="JSON capture spec")
    sp.add_argument("--max-events", type=int, default=2000)
    sp.add_argument("--timeout", type=float, default=120.0)
    sp.add_argument("--collect-aliases", action="store_true",
                    help="feed captured strings to the alias collector")
    sp.add_argument("--pkg")

    sp = sub.add_parser("hook_crypto", help="watch javax.crypto for N seconds")
    sp.add_argument("--duration", type=float, default=60.0)
    sp.add_argument("--hooks", help="comma-separated hook names")
    sp.add_argument("--returns", action="store_true")
    sp.add_argument("--max-events", type=int, default=1000)
    sp.add_argument("--max-bytes", type=int, default=1 << 20)
    sp.add_argument("--defer", action="store_true",
                    help="CLASS_PREPARE-watch pending hooks and auto-install "
                         "when their class loads")
    sp.add_argument("--record", action="store_true",
                    help="persist the watch as a run manifest with one "
                         "event row per captured record")
    sp.add_argument("--scenario")
    sp.add_argument("--collect-aliases", action="store_true",
                    help="feed captured strings to the alias collector "
                         "(implies --record for evidence)")
    sp.add_argument("--pkg")

    sp = sub.add_parser("watch_strings",
                        help="scoped string watchers (issue #26)")
    sp.add_argument("--duration", type=float, default=60.0)
    sp.add_argument("--profiles",
                    help="JSON array: builtin names and/or explicit "
                         '{"cls","method","sig"} objects '
                         "(default: stringbuilder.tostring)")
    sp.add_argument("--mode", default="attributed",
                    choices=["best_effort", "attributed"],
                    help="best_effort: SP_NONE, no attribution, object loss "
                         "counted; attributed: SP_EVENT_THREAD, string + "
                         "bounded stack while suspended")
    sp.add_argument("--scope",
                    help="app scope for attribution (JDWP class-match "
                         "pattern, e.g. com.example.*)")
    sp.add_argument("--text-regex",
                    help="keep only matching texts (post-read filter)")
    sp.add_argument("--min-printable", type=float, default=0.0,
                    help="min printable-char ratio 0..1 (post-read filter)")
    sp.add_argument("--no-dedupe", action="store_true",
                    help="disable value-based session dedupe")
    sp.add_argument("--max-events", type=int, default=1000)
    sp.add_argument("--max-reads", type=int, default=5000)
    sp.add_argument("--max-output-bytes", type=int, default=1 << 20)
    sp.add_argument("--max-queue", type=int, default=64,
                    help="stop when unrelated stashed composites exceed "
                         "this (queue pressure)")
    sp.add_argument("--max-stack", type=int, default=8)
    sp.add_argument("--max-str", type=int, default=512)
    sp.add_argument("--thread", type=int,
                    help="restrict capture to this thread (ThreadOnly "
                         "request modifier)")
    sp.add_argument("--mod-count", type=int,
                    help="MOD_COUNT=N: ONE event after N-1 earlier matches "
                         "are skipped — NOT a first-N budget")
    sp.add_argument("--defer", action="store_true",
                    help="CLASS_PREPARE-watch pending profiles and "
                         "auto-install when their class loads")
    sp.add_argument("--record", action="store_true",
                    help="persist the watch as a run manifest with one "
                         "event row per captured record")
    sp.add_argument("--scenario")
    sp.add_argument("--collect-aliases", action="store_true",
                    help="feed captured strings to the alias collector "
                         "(implies --record for evidence)")
    sp.add_argument("--pkg")

    sp = sub.add_parser("strings",
                        help="offline query of persisted string-watch "
                             "records (issue #26)")
    sp.add_argument("--run-id")
    sp.add_argument("--profile")
    sp.add_argument("--mode", choices=["best_effort", "attributed"])
    sp.add_argument("--text", help="substring match on captured text")
    sp.add_argument("--limit", type=int, default=50)
    sp.add_argument("--offset", type=int, default=0)

    sp = sub.add_parser("watch_framework",
                        help="opt-in framework watcher profiles "
                             "(issue #27)")
    sp.add_argument("--duration", type=float, default=60.0)
    sp.add_argument("--families",
                    help="comma-separated: navigation,storage,services "
                         "(default: all three)")
    sp.add_argument("--profiles",
                    help="JSON array: builtin profile names, family names, "
                         "and/or explicit {\"cls\",\"method\",\"sig\"} "
                         "objects (overrides --families)")
    sp.add_argument("--mode", default="attributed",
                    choices=["best_effort", "attributed"],
                    help="best_effort: SP_NONE, no attribution/args, object "
                         "loss counted; attributed: SP_EVENT_THREAD, "
                         "args + bounded stack while suspended")
    sp.add_argument("--scope",
                    help="app scope for attribution (JDWP class-match "
                         "pattern, e.g. com.example.*)")
    sp.add_argument("--exclude",
                    help="comma-separated class-match patterns excluded "
                         "from attribution (framework wrappers are never "
                         "reported as app callers)")
    sp.add_argument("--invoke-getters", action="store_true",
                    help="EXPLICIT opt-in: invoke metadata getters "
                         "(Intent.getAction/getComponent/...) on the "
                         "suspended thread via the validated invoke path; "
                         "runs application code — off by default")
    sp.add_argument("--corr-window-ms", type=int, default=250,
                    help="one call traversing several watched methods "
                         "shares a correlation id within this window; "
                         "0 disables correlation")
    sp.add_argument("--max-events", type=int, default=1000)
    sp.add_argument("--max-reads", type=int, default=5000)
    sp.add_argument("--max-output-bytes", type=int, default=1 << 20)
    sp.add_argument("--max-queue", type=int, default=64,
                    help="stop when unrelated stashed composites exceed "
                         "this (queue pressure)")
    sp.add_argument("--max-stack", type=int, default=8)
    sp.add_argument("--max-str", type=int, default=512)
    sp.add_argument("--thread", type=int,
                    help="restrict capture to this thread (ThreadOnly "
                         "request modifier)")
    sp.add_argument("--mod-count", type=int,
                    help="MOD_COUNT=N: ONE event after N-1 earlier matches "
                         "are skipped — NOT a first-N budget")
    sp.add_argument("--defer", action="store_true",
                    help="CLASS_PREPARE-watch pending profiles and "
                         "auto-install when their class loads "
                         "(custom/late-loaded implementations)")
    sp.add_argument("--record", action="store_true",
                    help="persist the watch as a run manifest with one "
                         "event row per captured record")
    sp.add_argument("--scenario")
    sp.add_argument("--pkg")

    sp = sub.add_parser("framework_events",
                        help="offline query of persisted framework-watch "
                             "records (issue #27)")
    sp.add_argument("--run-id")
    sp.add_argument("--family",
                    choices=["navigation", "storage", "services", "custom"])
    sp.add_argument("--profile")
    sp.add_argument("--role",
                    choices=["request", "lifecycle", "staged", "submit",
                             "lookup", "custom"])
    sp.add_argument("--limit", type=int, default=50)
    sp.add_argument("--offset", type=int, default=0)

    sp = sub.add_parser("coverage", help="branch/method coverage")
    sp.add_argument("--packages", required=True, help="comma-separated")
    sp.add_argument("--mode", default="method", choices=["method", "line"])
    sp.add_argument("--thread", type=int)
    sp.add_argument("--budget", type=int, default=20000)
    sp.add_argument("--seconds", type=int, default=60)
    sp.add_argument("--scenario")
    sp.add_argument("--pkg")

    sp = sub.add_parser("runs", help="investigation run manifests")
    sp.add_argument("action", choices=["list", "get", "export", "import"])
    sp.add_argument("run_id", nargs="?")
    sp.add_argument("--file", help="export destination / import source")
    sp.add_argument("--limit", type=int, default=50)
    sp.add_argument("--offset", type=int, default=0)
    sp.add_argument("--kind")
    sp.add_argument("--replace", action="store_true",
                    help="import: overwrite an existing run_id")

    sp = sub.add_parser("snapshot_diff",
                        help="structural diff of two snapshot artifacts")
    sp.add_argument("a", help="artifact id (or run id with one snapshot)")
    sp.add_argument("b", help="artifact id (or run id with one snapshot)")
    sp.add_argument("--force", action="store_true",
                    help="compare despite incompatibilities (qualifications "
                         "are kept in the output)")

    sub.add_parser("native", help="list native methods + lldb plan")

    sp = sub.add_parser("export_buffer",
                        help="bounded export of a byte[] / heap ByteBuffer "
                             "(issue #38)")
    sp.add_argument("--obj", type=int, required=True,
                    help="object handle of the array or ByteBuffer")
    sp.add_argument("--epoch", type=int, required=True,
                    help="connection epoch the handle came from (stale "
                         "handles fail before any read)")
    sp.add_argument("--source", default="auto",
                    choices=["auto", "array", "bytebuffer"])
    sp.add_argument("--offset", type=int,
                    help="array index / offset relative to the buffer "
                         "position (default 0)")
    sp.add_argument("--length", type=int,
                    help="bytes to export (default: to the array end / "
                         "buffer limit)")
    sp.add_argument("--dest", help="destination file (default: "
                                   "<project>/exports/buffer-<id>.bin)")
    sp.add_argument("--max-bytes", type=int, default=16 << 20)
    sp.add_argument("--chunk-size", type=int, default=1 << 16)
    sp.add_argument("--deadline", type=float,
                    help="abort the export after this many seconds")
    sp.add_argument("--capped", action="store_true",
                    help="deliberate bounded preview: export at most "
                         "--max-bytes of an over-long range (reported as "
                         "a capped, incomplete export)")
    sp.add_argument("--keep-partial", action="store_true",
                    help="retain the partial temp file on abort "
                         "(default: removed)")
    sp.add_argument("--record", action="store_true",
                    help="persist export metadata as a run artifact")
    sp.add_argument("--run-id", help="attach to an existing run")
    sp.add_argument("--scenario")
    sp.add_argument("--event-id", help="parent event for the artifact")
    sp.add_argument("--pkg")

    sp = sub.add_parser("unpack",
                        help="discover/validate runtime DEX payloads at "
                             "loading boundaries (issue #28, experimental)")
    sp.add_argument("--duration", type=float, default=60.0)
    sp.add_argument("--boundaries",
                    help="comma-separated: in_memory_dex_class_loader "
                         "(default) | dex_class_loader_path | hook names")
    sp.add_argument("--cipher-overloads",
                    help="comma-separated Cipher.doFinal overloads to "
                         "observe (opt-in), e.g. 'Cipher.doFinal(byte[])'")
    sp.add_argument("--defer", action="store_true",
                    help="CLASS_PREPARE-watch pending boundaries and "
                         "auto-install when their class loads")
    sp.add_argument("--max-events", type=int, default=200)
    sp.add_argument("--max-candidates", type=int, default=25)
    sp.add_argument("--max-candidate-bytes", type=int, default=16 << 20)
    sp.add_argument("--max-run-bytes", type=int, default=64 << 20)
    sp.add_argument("--prefix-bytes", type=int, default=4096)
    sp.add_argument("--export-dir",
                    help="artifact destination (default: "
                         "<project>/exports)")
    sp.add_argument("--record", action="store_true",
                    help="persist the watch as a run manifest with one "
                         "event row per observation")
    sp.add_argument("--scenario")
    sp.add_argument("--index", action="store_true",
                    help="register each validated artifact into the "
                         "project's runtime_artifacts table (additive; "
                         "never replaces the APK index)")
    sp.add_argument("--pkg")

    sp = sub.add_parser("unpack_index",
                        help="register validated runtime DEX artifacts "
                             "into the project DB (issue #28)")
    sp.add_argument("action", choices=["list", "index"])
    sp.add_argument("artifact_id", nargs="?",
                    help="unpack_dex artifact id from a recorded unpack "
                         "run (action=index)")
    sp.add_argument("--limit", type=int, default=50)
    sp.add_argument("--offset", type=int, default=0)

    sp = sub.add_parser("aliases", help="review runtime alias candidates "
                                        "(issue #25)")
    sp.add_argument("action",
                    choices=["list", "get", "accept", "reject", "revise",
                             "add", "export"])
    sp.add_argument("candidate_id", nargs="?")
    sp.add_argument("--class-sig", help="original runtime descriptor, "
                                        "e.g. Lcom/foo/Bar;")
    sp.add_argument("--alias", help="alias text (add: new alias; revise: "
                                    "replacement text)")
    sp.add_argument("--method", help="method-scoped alias: method name")
    sp.add_argument("--method-sig", help="method-scoped alias: descriptor")
    sp.add_argument("--status",
                    choices=["suggested", "accepted", "rejected",
                             "superseded"])
    sp.add_argument("--filter", help="substring match on candidate/class")
    sp.add_argument("--note")
    sp.add_argument("--file", help="export destination path")
    sp.add_argument("--limit", type=int, default=50)
    sp.add_argument("--offset", type=int, default=0)
    sp.add_argument("--all-apks", action="store_true",
                    help="list candidates of every indexed APK, not just "
                         "the current one")

    sp = sub.add_parser("job_start",
                        help="start a cancellable background job (issue "
                             "#34); serve mode is the job surface — a "
                             "one-shot CLI job is cancelled at exit")
    sp.add_argument("--command", required=True,
                    help="hook_crypto | watch_strings | watch_framework | "
                         "coverage | export_buffer")
    sp.add_argument("--params", help="JSON object of params for --command")
    sp.add_argument("--max-records", type=int, default=1000)
    sp.add_argument("--max-record-bytes", type=int, default=1 << 20)
    sp.add_argument("--pkg")

    sp = sub.add_parser("job_status", help="job lifecycle + progress")
    sp.add_argument("operation_id")

    sp = sub.add_parser("job_read", help="bounded cursor page of records")
    sp.add_argument("operation_id")
    sp.add_argument("--cursor")
    sp.add_argument("--limit", type=int, default=100)

    sp = sub.add_parser("job_cancel", help="cooperatively cancel a job")
    sp.add_argument("operation_id")

    sp = sub.add_parser("job_list", help="retained jobs")
    sp.add_argument("--limit", type=int, default=50)
    sp.add_argument("--offset", type=int, default=0)

    sub.add_parser("serve", help="JSON-RPC over stdio (for LLM agents)")
    return p


# verbs that need a live JDWP session; CLI auto-connects when --pkg is given
SESSION_VERBS = {"bp", "bp_del", "bp_list", "events", "read_var", "write_var",
                 "invoke", "step", "resume", "restore", "snapshot",
                 "dump_object", "cond", "hook_crypto", "watch_strings",
                 "watch_framework", "coverage", "native", "export_buffer",
                 "unpack", "job_start"}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "serve":
        from .server import serve_stdio
        serve_stdio(args.project, serial=args.serial)
        return 0

    fn = commands.COMMANDS[args.cmd]
    try:
        if args.cmd == "init":
            data = fn(None, apk=args.apk, out=args.out,
                      skip_apktool=args.skip_apktool, skip_jadx=args.skip_jadx)
        else:
            ctx = Ctx(args.project, serial=args.serial)
            try:
                kw = _kwargs(args)
                if args.cmd in SESSION_VERBS and args.cmd != "connect":
                    # one-shot CLI: connect (pkg from flag or project state),
                    # act, disconnect. Use `serve` for persistent sessions.
                    ctx.connect_session(kw.pop("pkg", None))
                data = fn(ctx, **kw)
            finally:
                ctx.close()
        emit(ok(data))
        return 0
    except Exception as e:
        emit(err(e))
        return 1 if isinstance(e, ApkDbgError) else 2


def _kwargs(args: argparse.Namespace) -> dict:
    kw = {}
    for k, v in vars(args).items():
        if k in ("cmd", "project", "serial") or v is None:
            continue
        if k in ("value", "pred", "capture", "args", "profiles",
                 "params") and isinstance(v, str):
            v = json.loads(v)
        if k == "no_dedupe":
            k, v = "dedupe", not v
        if k == "hooks" and isinstance(v, str):
            v = [x.strip() for x in v.split(",") if x.strip()]
        if k in ("families", "exclude", "boundaries") \
                and isinstance(v, str):
            v = [x.strip() for x in v.split(",") if x.strip()]
        if k == "cipher_overloads" and isinstance(v, str):
            # overload names contain commas ("Cipher.doFinal(byte[],int,int)")
            v = [x.strip() for x in v.split(";") if x.strip()]
        if k == "packages" and isinstance(v, str):
            v = [x.strip() for x in v.split(",") if x.strip()]
        kw[k] = v
    return kw


if __name__ == "__main__":
    sys.exit(main())

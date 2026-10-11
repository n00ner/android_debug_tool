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
    sp.add_argument("--pkg")

    sp = sub.add_parser("dump_object")
    sp.add_argument("--obj", type=int, required=True)
    sp.add_argument("--depth", type=int, default=3)
    sp.add_argument("--record", action="store_true",
                    help="persist as an artifact under a run manifest")
    sp.add_argument("--run-id", help="attach to an existing run")
    sp.add_argument("--scenario")
    sp.add_argument("--pkg")

    sp = sub.add_parser("cond", help="conditional breakpoint")
    sp.add_argument("spec")
    sp.add_argument("--pred", required=True, help="JSON predicate")
    sp.add_argument("--capture", required=True, help="JSON capture spec")
    sp.add_argument("--max-events", type=int, default=2000)
    sp.add_argument("--timeout", type=float, default=120.0)
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
    sp.add_argument("--pkg")

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

    sub.add_parser("serve", help="JSON-RPC over stdio (for LLM agents)")
    return p


# verbs that need a live JDWP session; CLI auto-connects when --pkg is given
SESSION_VERBS = {"bp", "bp_del", "bp_list", "events", "read_var", "write_var",
                 "invoke", "step", "resume", "snapshot", "dump_object",
                 "cond", "hook_crypto", "coverage", "native"}


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
        if k in ("value", "pred", "capture", "args") and isinstance(v, str):
            v = json.loads(v)
        if k == "hooks" and isinstance(v, str):
            v = [x.strip() for x in v.split(",") if x.strip()]
        if k == "packages" and isinstance(v, str):
            v = [x.strip() for x in v.split(",") if x.strip()]
        kw[k] = v
    return kw


if __name__ == "__main__":
    sys.exit(main())

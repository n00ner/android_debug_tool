"""Scoped string watchers (issue #26) — observe runtime strings at selected
producer-return and consumer-argument points via METHOD_EXIT_WITH_RETURN_VALUE
requests (event kind 42), with explicit capture modes and honest coverage.

Observation points and their limits
-----------------------------------
A *producer* profile reads the RETURN value of a string-returning method:
user-selected decryptors (explicit class+method+signature) and, opt-in only,
`StringBuilder.toString()Ljava/lang/String;`. A *consumer* profile reads the
String ARGUMENTS of a method at its exit: logging (android.util.Log d/e/i/w),
URL builders (java.net.URL.<init>), preference writes
(SharedPreferences$Editor.putString).

These are observation points, not full coverage:
  - `StringBuilder.toString` does NOT capture every constructed string.
    `new String(byte[])` / `new String(char[])` constructors, String.concat,
    `+` concatenation compiled to `StringConcatFactory` (invokedynamic,
    Android 14+ desugaring), native code, reflection-built strings, and
    custom decryptors that never touch StringBuilder all bypass it.
  - A consumer profile sees only the strings actually passed to that sink;
    it says nothing about unobserved construction paths.
  - A producer profile sees only the return values of the selected methods.
Bypass paths are documented in every result ("coverage_note"), never
reported as full coverage.

Capture modes
-------------
best_effort
  SP_NONE (non-suspending) exit requests. The returned object id may be
  collected before the string read runs (the VM moved on); failed reads
  are counted and reported as explicit "unavailable" records — never
  silently dropped. No stack attribution is promised or fabricated. No
  object-retention trick is used: JDWP-level collection would suspend
  exactly the threads a hot loop needs, and disabling it later cannot
  erase an earlier collection race.
attributed
  SP_EVENT_THREAD requests: the event thread is suspended, the string is
  read while it is definitely alive, and a bounded stack is resolved. The
  nearest frame matching the configured application scope (JDWP-style
  class-match pattern, e.g. "com.example.*") becomes the caller, with full
  class/method descriptors and bytecode index. When no frame matches, the
  record carries an explicit attribution status ("no_app_frame" /
  "no_scope_configured") — a caller is never fabricated from a thread
  that merely happened to be running. The suspension is released only
  through the dispatcher's SuspensionLease (once per thread, after every
  consumer of the composite finished).

Protocol facts this module relies on (corrected in issue #26):
  - METHOD_EXIT_WITH_RETURN_VALUE = event kind 42.
  - SP_NONE=0 / SP_EVENT_THREAD=1 / SP_ALL=2.
  - MOD_COUNT=N delivers ONE event after N-1 earlier matches are skipped;
    it is NOT a first-N budget (max_events is the budget knob here).
  - Standard method-exit requests can only be class-filtered: the VM still
    generates exit events for every OTHER method of that class, which are
    filtered host-side by exact method id (counted as "filtered").

Filtering, dedupe, and limits
-----------------------------
Class filters (and optional thread/count modifiers) are applied at request
level; text regex and printable-ratio filters run AFTER the text has been
read; dedupe is value-based within the watch session (object-id identity
is per-connection and is NOT used as durable string identity). Limits are
independent: max_events (emitted records), duration_s, max_queue (stashed
unrelated composites — queue pressure), max_reads (JDWP reads issued by
extraction), max_output_bytes (JSON payload bytes). The result reports
received/filtered/matched/unavailable/truncated/dropped counts plus the
stop reason.

Lifecycle
---------
Cancellation is cooperative (a `cancel` event checked every loop pass).
Teardown clears every owned request — including deferred CLASS_PREPARE
watches and auto-installed late classes — with its original event kind on
every exit path, but only while the transport epoch is unchanged: after a
reconnect the old epoch's handles are dead, numeric ids may have been
reused by the new connection, and remote cleanup is reported as
UNCONFIRMED (issue #32 contract) instead of claiming a clear/resume that
cannot be verified. Capture exceptions never block resume or teardown.
"""

from __future__ import annotations

import json
import re
import time

from ...core.manifests import RunStore, capture_environment
from ...device.jdwp import (
    EVK_METHOD_EXIT_RET, SP_EVENT_THREAD, SP_NONE, TAG_STRING,
)
from ...errors import SessionError
from ...protocol import log_progress
from ..capture import arg_vreg_map, capture_spec
from .crypto import ClassNotLoaded, MethodNotFound, UnsupportedHook

OWNER = "strings"

CAPTURE_RETURN, CAPTURE_ARGS = "return", "args"
MODES = ("best_effort", "attributed")

COVERAGE_NOTE = (
    "observation points only: StringBuilder.toString misses strings built "
    "via new String(byte[]/char[]), String.concat, invokedynamic "
    "concatenation, native code, reflection, and custom decryptors; "
    "consumer profiles see only strings actually passed to the sink; "
    "producer profiles see only selected methods' return values")

_NATIVE, _ABSTRACT, _STATIC = 0x0100, 0x0400, 0x0008


def _profile(name, kind, cls, method, sig, note, cls_alts=()):
    return {"name": name, "kind": kind, "cls": cls, "method": method,
            "sig": sig, "cls_alts": list(cls_alts), "note": note}


def _producer(name, cls, method, sig, note, cls_alts=()):
    return _profile(name, CAPTURE_RETURN, cls, method, sig, note, cls_alts)


def _consumer(name, cls, method, sig, note, cls_alts=()):
    return _profile(name, CAPTURE_ARGS, cls, method, sig, note, cls_alts)


BUILTIN_PROFILES: list[dict] = [
    _producer(
        "stringbuilder.tostring",
        "Ljava/lang/StringBuilder;", "toString", "()Ljava/lang/String;",
        "broad; opt-in only — does NOT capture every constructed string "
        "(constructors, concat strategies, native and custom decryptor "
        "paths bypass it)"),
    _consumer("log.d", "Landroid/util/Log;", "d",
              "(Ljava/lang/String;Ljava/lang/String;)I",
              "tag=arg0, message=arg1"),
    _consumer("log.e", "Landroid/util/Log;", "e",
              "(Ljava/lang/String;Ljava/lang/String;)I",
              "tag=arg0, message=arg1"),
    _consumer("log.i", "Landroid/util/Log;", "i",
              "(Ljava/lang/String;Ljava/lang/String;)I",
              "tag=arg0, message=arg1"),
    _consumer("log.w", "Landroid/util/Log;", "w",
              "(Ljava/lang/String;Ljava/lang/String;)I",
              "tag=arg0, message=arg1"),
    _consumer("url.init", "Ljava/net/URL;", "<init>",
              "(Ljava/lang/String;)V", "URL spec string"),
    _consumer("prefs.putstring",
              "Landroid/content/SharedPreferences$Editor;", "putString",
              "(Ljava/lang/String;Ljava/lang/String;)"
              "Landroid/content/SharedPreferences$Editor;",
              "key=arg0, value=arg1; the interface itself is abstract, "
              "so the AOSP impl class is hooked as an alternative",
              cls_alts=["Landroid/app/SharedPreferencesImpl$Editor;"]),
]

_BUILTINS = {p["name"]: p for p in BUILTIN_PROFILES}


# ------------------------------------------------------------------ profiles
def resolve_profile(spec) -> dict:
    """Resolve one profile selector: a builtin name (string) or an explicit
    custom profile dict {"cls": "Lcom/foo/Dec;", "method": "decrypt",
    "sig": "([B)Ljava/lang/String;", "kind"?: "return"|"args",
    "name"?: ..., "cls_alts"?: [...]}. Custom profiles are the way to watch
    user-selected decryptor methods; kind defaults to "return" for
    String-returning methods and "args" otherwise."""
    if isinstance(spec, str):
        p = _BUILTINS.get(spec)
        if p is None:
            raise SessionError(
                f"unknown builtin profile {spec!r}",
                hint="available: " + ", ".join(sorted(_BUILTINS))
                     + " — or pass an explicit "
                     '{"cls","method","sig"} profile')
        return dict(p)
    if not isinstance(spec, dict):
        raise SessionError("profile must be a builtin name or an explicit "
                           '{"cls","method","sig"} object')
    cls, method, sig = spec.get("cls"), spec.get("method"), spec.get("sig")
    if not (isinstance(cls, str) and cls.startswith("L")
            and isinstance(method, str) and method
            and isinstance(sig, str) and sig.startswith("(")):
        raise SessionError(
            "custom profile needs cls (L...; descriptor), method, and sig "
            "((...)... descriptor)",
            hint='{"cls":"Lcom/foo/Dec;","method":"decrypt",'
                 '"sig":"([B)Ljava/lang/String;"}')
    args, ret = parse_sig(sig)
    kind = spec.get("kind")
    if kind is None:
        kind = CAPTURE_RETURN if ret == "Ljava/lang/String;" \
            else CAPTURE_ARGS
    if kind not in (CAPTURE_RETURN, CAPTURE_ARGS):
        raise SessionError(f"unknown profile kind {kind!r}",
                           hint="return | args")
    if kind == CAPTURE_ARGS and "Ljava/lang/String;" not in args:
        raise SessionError(
            f"args profile {method}{sig} has no String argument",
            hint="consumer profiles capture String arguments")
    return {"name": spec.get("name") or f"custom:{method}{sig}",
            "kind": kind, "cls": cls, "method": method, "sig": sig,
            "cls_alts": list(spec.get("cls_alts") or []),
            "note": spec.get("note") or "user-selected profile"}


def parse_sig(sig: str) -> tuple[list[str], str]:
    """'([BLjava/lang/String;)[B' -> (['[B','Ljava/lang/String;'], '[B')."""
    if not sig.startswith("("):
        raise SessionError(f"not a method descriptor: {sig!r}")
    args, i = [], 1
    while i < len(sig) and sig[i] != ")":
        j = i
        while sig[j] == "[":
            j += 1
        if sig[j] == "L":
            k = sig.index(";", j)
            args.append(sig[i:k + 1])
            i = k + 1
        else:
            args.append(sig[i:j + 1])
            i = j + 1
    return args, sig[i + 1:]


def _capture_slots(args: list[str], is_static: bool) -> list[dict]:
    """Capture spec for the String arguments: JVM slots (0 = this for
    instance methods; long/double take two slots). Translated to ART DEX
    vregs at install time via capture.arg_vreg_map."""
    slot = 0 if is_static else 1
    spec = []
    for idx, t in enumerate(args):
        if t == "Ljava/lang/String;":
            spec.append({"slot": slot, "type": "string",
                         "label": f"arg{idx}"})
        slot += 2 if t in ("J", "D") else 1
    return spec


def _class_pattern(sig: str) -> str:
    """'Lcom/foo/Bar;' -> 'com.foo.Bar' (JDWP ClassMatch pattern base)."""
    return sig[1:-1].replace("/", ".") if sig.startswith("L") else sig


# ------------------------------------------------------------------- install
def install(session, profiles: list, mode: str = "attributed", *,
            defer: bool = False, thread: int | None = None,
            mod_count: int | None = None) -> dict:
    """Register class-scoped METHOD_EXIT_WITH_RETURN_VALUE requests for the
    resolved profiles. Every profile ends in one distinct state: installed /
    pending (class not loaded — deferrable) / not-found / unsupported /
    failed. Overloads are matched by exact (name, sig); native and abstract
    methods are reported as unsupported; late class loading is handled with
    defer=True (CLASS_PREPARE auto-install, exactly once per classloader
    instance). mod_count, when given, is MOD_COUNT semantics: ONE event
    after N-1 earlier matches are skipped — not a first-N budget."""
    if mode not in MODES:
        raise SessionError(f"unknown capture mode {mode!r}",
                           hint=" | ".join(MODES))
    sp = SP_NONE if mode == "best_effort" else SP_EVENT_THREAD
    d = session.events
    installed, pending, deferred = [], [], []
    states = {}
    for prof in profiles:
        try:
            regs = _install_one(session, prof, sp, thread, mod_count)
        except ClassNotLoaded as e:
            states[prof["name"]] = "pending"
            pending.append({"profile": prof["name"], "state": "pending",
                            "reason": str(e)[:120]})
            if defer:
                rid = d.defer_hook(
                    OWNER, prof["name"], _class_pattern(prof["cls"]),
                    _make_on_prepare(session, prof, sp, thread, mod_count))
                deferred.append({"profile": prof["name"], "request_id": rid})
            continue
        except (MethodNotFound, UnsupportedHook) as e:
            state = ("not-found" if isinstance(e, MethodNotFound)
                     else "unsupported")
            states[prof["name"]] = state
            pending.append({"profile": prof["name"], "state": state,
                            "reason": str(e)[:120]})
            continue
        except Exception as e:
            states[prof["name"]] = "failed"
            pending.append({"profile": prof["name"], "state": "failed",
                            "reason": str(e)[:120]})
            continue
        states[prof["name"]] = "installed"
        installed.append({"profile": prof["name"],
                          "request_ids": [r["rid"] for r in regs]})
    return {"installed": installed, "pending": pending,
            "deferred": deferred, "states": states,
            "note": "pending profiles: class not loaded yet; re-install "
                    "later or install with defer=True for CLASS_PREPARE "
                    "auto-install"}


def _install_one(session, prof: dict, sp: int, thread: int | None,
                 mod_count: int | None,
                 only_type_ids: set[int] | None = None) -> list[dict]:
    """Register the exit request of one profile for every loaded class
    (primary sig first, then alternatives such as AOSP impl classes).
    Idempotent per (profile, type_id): classes already watched in this
    epoch contribute their existing request ids. On partial failure only
    the requests registered by THIS call are cleared."""
    c = session.client
    live = {rid: m for rid, m in session.bp_registry.items()
            if m.get("owner") == OWNER and m.get("profile_name")
            == prof["name"] and session.events.is_live(m)}
    regs = [{"rid": rid} for rid in live]
    new = []
    loaded, saw_method = 0, False
    try:
        for sig in [prof["cls"], *prof.get("cls_alts", [])]:
            for cls in c.classes_by_signature(sig):
                tid = cls["type_id"]
                if only_type_ids is not None and tid not in only_type_ids:
                    continue
                if any(m["type_id"] == tid for m in live.values()):
                    continue
                loaded += 1
                m = next((m for m in c.rt_methods(tid)
                          if m["name"] == prof["method"]
                          and m["sig"] == prof["sig"]), None)
                if not m:
                    continue
                saw_method = True
                bits = m.get("mod_bits", 0)
                if bits & _NATIVE:
                    raise UnsupportedHook(
                        f"{prof['method']}{prof['sig']} is native")
                if bits & _ABSTRACT:
                    continue  # e.g. the SharedPreferences$Editor interface
                mods = [c.mod_class_only(tid)]
                if thread is not None:
                    mods.append(c.mod_thread_only(thread))
                if mod_count is not None:
                    mods.append(c.mod_count(mod_count))
                args, _ = parse_sig(prof["sig"])
                spec = _capture_slots(args, bool(bits & _STATIC))
                vregs = arg_vreg_map(c, tid, m["id"]) if spec else None
                try:
                    loader = c.rt_class_loader(tid)
                except Exception:
                    loader = None  # type_id identity still dedupes per loader
                rid = c.set_event(EVK_METHOD_EXIT_RET, sp, mods)
                new.append({"rid": rid, "type_id": tid, "cls_sig": sig,
                            "method_id": m["id"], "spec": spec,
                            "vregs": vregs, "loader": loader})
    except Exception:
        for r in new:
            try:
                c.clear_event(EVK_METHOD_EXIT_RET, r["rid"])
            except Exception:
                pass
        raise
    if not new and not regs:
        if not loaded:
            raise ClassNotLoaded(f"{prof['cls']} not loaded")
        if not saw_method:
            raise MethodNotFound(
                f"{prof['method']}{prof['sig']} not found "
                f"(overloaded methods need the exact sig)")
        raise UnsupportedHook(
            f"{prof['method']}{prof['sig']} has no concrete implementation "
            f"in the loaded classes (abstract/interface only)")
    for r in new:
        session.events.register(r["rid"], {
            "owner": OWNER, "profile_name": prof["name"],
            "profile": {k: prof[k] for k in
                        ("name", "kind", "cls", "method", "sig", "note")},
            "entry": "hook", "hook": prof["name"],
            "kind": EVK_METHOD_EXIT_RET, "cls": r["cls_sig"],
            "type_id": r["type_id"], "loader": r["loader"],
            "method": prof["method"], "sig": prof["sig"],
            "method_id": r["method_id"], "capture_spec": r["spec"],
            "vregs": r["vregs"], "suspend_policy": sp,
            "spec": prof["method"] + prof["sig"]})
    return regs + new


def _make_on_prepare(session, prof: dict, sp: int, thread: int | None,
                     mod_count: int | None):
    def on_prepare(ev: dict, handler: dict) -> None:
        regs = _install_one(session, prof, sp, thread, mod_count,
                            only_type_ids={ev.get("type_id")})
        handler["installed_rids"].extend(r["rid"] for r in regs)
    return on_prepare


# ------------------------------------------------------------------ extract
def _new_stats() -> dict:
    return {"received": 0, "filtered": 0, "matched": 0, "unavailable": 0,
            "truncated": 0, "dropped": 0, "deduped": 0, "non_string": 0,
            "reads": 0}


def _printable_ratio(s: str) -> float:
    if not s:
        return 1.0
    ok = sum(1 for ch in s if ch.isprintable() or ch in "\r\n\t")
    return ok / len(s)


def _class_match(pattern: str, dotted: str) -> bool:
    """JDWP ClassMatch semantics: exact match except '*' wildcards."""
    rx = ".*".join(re.escape(part) for part in pattern.split("*"))
    return re.fullmatch(rx, dotted) is not None


def extract_event(session, ev: dict, cfg: dict) -> dict | None:
    """Build the watcher record for one owned exit event, or None when the
    event is not ours or is filtered. Counters accumulate in cfg["_stats"];
    cfg["_stop"] is set when a read budget is exhausted. The suspension
    (attributed mode) is owned by the dispatcher lease, never resumed here.
    """
    stats = cfg["_stats"]
    reg = session.bp_registry.get(ev.get("request_id"))
    if reg is None or reg.get("owner") != OWNER:
        return None
    if ev.get("kind_id") != EVK_METHOD_EXIT_RET:
        return None
    stats["received"] += 1
    loc = ev.get("location") or {}
    if loc.get("method") != reg.get("method_id"):
        # class-scoped request: the VM emits exits of every method of the
        # class; host-side filtering keeps only the hooked one
        stats["filtered"] += 1
        return None
    if cfg.get("_stop"):
        stats["dropped"] += 1
        return None
    rec = {"profile": reg["profile_name"], "kind": reg["profile"]["kind"],
           "thread": ev.get("thread"), "cls": reg["cls"],
           "method": reg["method"], "sig": reg["sig"]}
    mode = cfg["mode"]
    frames = None
    if mode == "attributed" and ev.get("thread") is not None and (
            reg["capture_spec"] or cfg.get("scope")
            or cfg.get("capture_stack")):
        try:
            frames = session.client.thread_frames(
                ev["thread"], max(1, cfg.get("max_stack", 8)))
            stats["reads"] += 1
        except Exception as e:
            rec["attribution"] = {"status": "unavailable",
                                  "reason": f"frames: {str(e)[:100]}"}
    texts = _read_texts(session, ev, reg, cfg, stats, frames, rec)
    kept = []
    for text in texts:
        if text is None:
            continue
        if len(text) > cfg.get("max_str", 512):
            text = text[: cfg["max_str"]]
            stats["truncated"] += 1
            rec["truncated"] = True
        if _printable_ratio(text) < cfg.get("min_printable", 0.0):
            stats["filtered"] += 1
            continue
        rx = cfg.get("_text_re")
        if rx is not None and not rx.search(text):
            stats["filtered"] += 1
            continue
        if cfg.get("dedupe", True):
            seen = cfg["_seen"]
            if text in seen:
                stats["deduped"] += 1
                continue
            if len(seen) < (1 << 16):
                seen.add(text)
        kept.append(text)
    if kept:
        stats["matched"] += 1
        rec["texts"] = kept
    elif "status" not in rec:
        return None  # all texts filtered/deduped: not a record
    rec["attribution"] = rec.get("attribution") or _attribute(
        session, ev, reg, cfg, stats, frames)
    return rec


def _read_texts(session, ev: dict, reg: dict, cfg: dict, stats: dict,
                frames: list | None, rec: dict) -> list:
    """Read the string value(s) per the profile kind and capture mode.
    Failed reads (dead object, invalid frame) are non-fatal: counted as
    'unavailable' and reported explicitly on the record."""
    c = session.client
    mode = cfg["mode"]
    max_str = cfg.get("max_str", 512) + 1

    def unavailable(reason: str) -> list:
        stats["unavailable"] += 1
        rec["status"] = "unavailable"
        rec["unavailable_reason"] = reason
        rec.setdefault("texts", [])
        return []

    if reg["profile"]["kind"] == CAPTURE_RETURN:
        rv = ev.get("return_value") or {}
        if rv.get("tag") != TAG_STRING or not rv.get("v"):
            stats["non_string"] += 1
            rec["status"] = "non_string_return"
            rec.setdefault("texts", [])
            return []
        try:
            stats["reads"] += 1
            return [c.string_value(rv["v"], max_str)]
        except Exception as e:
            # best_effort: the VM kept running and the id may be dead;
            # attributed: still possible on a racing dispose
            return unavailable(f"return value unreadable: {str(e)[:100]}")
    # consumer profile: String arguments at frame 0 — valid only while the
    # event thread is suspended (attributed mode)
    if mode != "attributed":
        return unavailable("argument capture requires a suspended thread "
                           "(attributed mode); best_effort events have no "
                           "valid frames")
    if not frames:
        return unavailable("no frames on the suspended thread")
    try:
        got = capture_spec(c, ev["thread"], frames[0]["frame_id"],
                           reg["capture_spec"], vregs=reg.get("vregs"),
                           max_str=max_str)
        stats["reads"] += len(reg["capture_spec"])
    except Exception as e:
        return unavailable(f"argument read failed: {str(e)[:100]}")
    out = []
    for label in sorted(got):
        node = got[label]
        if isinstance(node, dict) and isinstance(node.get("v"), str):
            out.append(node["v"])
        else:
            stats["unavailable"] += 1
            err = (node or {}).get("error", "not a string")
            rec.setdefault("arg_errors", {})[label] = str(err)[:100]
    return out


def _attribute(session, ev: dict, reg: dict, cfg: dict, stats: dict,
               frames: list | None) -> dict:
    """Nearest frame matching the configured app scope, with full
    descriptors and location. Explicit status when attribution is
    impossible — a caller is never fabricated."""
    if cfg["mode"] != "attributed":
        return {"status": "not_captured",
                "reason": "best_effort mode does not suspend; no stack "
                          "attribution is promised"}
    scope = cfg.get("scope")
    if not scope:
        return {"status": "no_scope_configured",
                "reason": "pass scope (e.g. 'com.example.*') to select "
                          "the nearest app frame"}
    if not frames:
        return {"status": "unavailable",
                "reason": "no frames on the suspended thread"}
    c = session.client
    for fr in frames:
        floc = fr.get("location") or {}
        if floc.get("class") == reg["type_id"] \
                and floc.get("method") == reg["method_id"]:
            continue  # the hooked method itself
        try:
            stats["reads"] += 1
            csig = session._sig_of(floc["class"])
        except Exception:
            continue
        if not _class_match(scope, _class_pattern(csig)):
            continue
        caller = {"class_sig": csig, "class": _class_pattern(csig),
                  "index": floc.get("index")}
        try:
            stats["reads"] += 1
            m = next((m for m in c.rt_methods(floc["class"])
                      if m["id"] == floc.get("method")), None)
            if m:
                caller["method"] = m["name"]
                caller["method_sig"] = m["sig"]
        except Exception:
            pass
        return {"status": "matched", "caller": caller}
    return {"status": "no_app_frame",
            "reason": f"no frame within {len(frames)} frames matches "
                      f"scope {scope!r}"}


# ----------------------------------------------------------------- run_watch
def run_watch(session, profiles=None, mode: str = "attributed", *,
              duration_s: float = 60.0, max_events: int = 1000,
              max_reads: int = 5000, max_output_bytes: int = 1 << 20,
              max_queue: int = 64, max_stack: int = 8, max_str: int = 512,
              text_regex: str | None = None, min_printable: float = 0.0,
              dedupe: bool = True, scope: str | None = None,
              capture_stack: bool = False, thread: int | None = None,
              mod_count: int | None = None, defer: bool = False,
              record: bool = False, scenario: str | None = None,
              collect_aliases: bool = False, cancel=None) -> dict:
    """Blocking string-watch loop: install the profiles, then consume
    strings-owned events through the session dispatcher until a limit
    stops it. Stop reasons: duration | max_events | max_reads |
    max_output_bytes | queue_pressure | cancelled | error.

    Claims only its own events: unrelated stops are stashed for the public
    wait_events caller (their suspensions belong to that caller — the
    watch never resumes them). Cooperative cancellation: `cancel` is any
    object with is_set() (e.g. threading.Event), checked every loop pass.
    Queue pressure: if unrelated stashed composites pile up beyond
    max_queue, the watch stops instead of flooding the session. Teardown
    clears every owned request with its original kind while the transport
    epoch is unchanged; after a reconnect the old ids are reported in
    "unconfirmed" and the remote is left untouched (issue #32).

    With record=True (and a project-backed session) the watch persists as
    a run manifest (kind "string_watch"): capture config + limits on the
    run, one "string_record" event per emitted record carrying profile,
    capture mode, and attribution status. collect_aliases=True additionally
    feeds captured texts to the opt-in alias collector (issue #25;
    implies recording for evidence)."""
    from ...core.aliases import AliasStore
    from ..aliascollect import AliasCollector
    profs = [resolve_profile(p) for p in
             (profiles if profiles else ["stringbuilder.tostring"])]
    cfg = {"mode": mode, "scope": scope, "max_stack": max_stack,
           "max_str": max_str, "min_printable": min_printable,
           "dedupe": dedupe, "capture_stack": capture_stack,
           "_stats": _new_stats(), "_seen": set(), "_stop": None,
           "_text_re": re.compile(text_regex) if text_regex else None}
    d = session.events
    epoch = d.epoch
    rep = install(session, profs, mode=mode, defer=defer, thread=thread,
                  mod_count=mod_count)
    owned = {rid for i in rep["installed"] for rid in i["request_ids"]}
    owned |= {dfr["request_id"] for dfr in rep["deferred"]}
    base_owned = set(owned)
    records, errors, cleanup_errors = [], [], []
    out_bytes, unrelated = 0, 0
    reason = "duration"

    store = RunStore.for_session(session) \
        if (record or collect_aliases) else None
    collector = AliasCollector(
        session, store=AliasStore.for_session(session)) \
        if collect_aliases else None
    run_id = None
    if store is not None:
        run_id = store.begin_run(
            "string_watch",
            capture_config={
                "profiles": [{k: p[k] for k in
                              ("name", "kind", "cls", "method", "sig",
                               "note")} for p in profs],
                "mode": mode, "scope": scope,
                "limits": {"duration_s": duration_s,
                           "max_events": max_events,
                           "max_reads": max_reads,
                           "max_output_bytes": max_output_bytes,
                           "max_queue": max_queue, "max_stack": max_stack,
                           "max_str": max_str},
                "text_regex": text_regex, "min_printable": min_printable,
                "dedupe": dedupe, "defer": defer, "thread": thread,
                "mod_count": mod_count},
            scenario=scenario, epoch=epoch,
            environment=capture_environment(session))

    def on_event(ev: dict, lease) -> None:
        nonlocal out_bytes
        try:
            rec = extract_event(session, ev, cfg)
        except Exception as e:
            # capture exceptions never block resume or teardown
            errors.append(f"capture: {str(e)[:120]}")
            cfg["_stats"]["dropped"] += 1
            return
        if rec is None:
            return
        records.append(rec)
        out_bytes += len(json.dumps(rec, default=str))
        # budgets apply mid-composite too: once exhausted, further events
        # of the batch are counted dropped (not read) and the loop stops
        if cfg["_stats"]["reads"] >= max_reads:
            cfg["_stop"] = "max_reads"
        elif len(records) >= max_events:
            cfg["_stop"] = "max_events"
        if store is not None:
            event_id = store.add_event(
                run_id, "string_record", rec,
                class_sig=rec.get("cls"), method_name=rec.get("method"),
                method_sig=rec.get("sig"), epoch=epoch)
        else:
            event_id = None
        if collector is not None and rec.get("texts"):
            reg = session.bp_registry.get(ev.get("request_id")) or {}
            collector.collect_from_record(
                rec, {"class_sig": rec.get("cls"),
                      "method_name": rec.get("method"),
                      "method_sig": rec.get("sig"),
                      "classloader_id": reg.get("loader") or None,
                      "epoch": epoch},
                run_id=run_id, event_id=event_id, client=session.client)

    sub = d.subscribe(OWNER, on_event)
    deadline = time.time() + duration_s
    try:
        while time.time() < deadline:
            if cancel is not None and cancel.is_set():
                reason = "cancelled"
                break
            try:
                r = d.next_routed(
                    timeout=max(1.0, deadline - time.time()))
            except Exception as e:
                if getattr(e, "code", None) != "E_JDWP_TIMEOUT":
                    reason = "error"
                    errors.append(f"wait: {str(e)[:120]}")
                    log_progress(f"string watch loop: {e}")
                break
            errors.extend(r.lease.errors)
            for h in d.deferred_handlers(OWNER):
                owned.update(h["installed_rids"])
            if r["events"]:
                unrelated += len(r["events"])
                d.stash(r)
                if len(d._pending) > max_queue:
                    reason = "queue_pressure"
                    break
            if cfg["_stop"]:
                reason = cfg["_stop"]
                break
            if out_bytes >= max_output_bytes:
                reason = "max_output_bytes"
                break
    finally:
        sub.close()
        for h in d.deferred_handlers(OWNER):
            owned.update(h["installed_rids"])
        auto_installed = sorted(owned - base_owned)
        unconfirmed = []
        if d.epoch != epoch:
            # reconnected mid-watch: handles are dead and the numeric ids
            # may have been reused by the new connection — never clear
            unconfirmed = sorted(owned)
        else:
            for rid in sorted(owned):
                if d.lookup(rid) is None:
                    continue
                try:
                    session.clear_request(rid)
                except Exception as e:
                    cleanup_errors.append(f"clear {rid}: {str(e)[:120]}")
        if store is not None:
            store.end_run(run_id, reason,
                          counts={**cfg["_stats"], "unrelated": unrelated})
    stats = cfg["_stats"]
    out = {"records": records, "counts": {**stats, "unrelated": unrelated},
           "reason": reason, "truncated": reason == "max_output_bytes",
           "captured_bytes": out_bytes,
           "installed": len(rep["installed"]), "pending": rep["pending"],
           "states": rep["states"], "deferred": rep["deferred"],
           "auto_installed": auto_installed, "unconfirmed": unconfirmed,
           "errors": errors, "cleanup_errors": cleanup_errors,
           "coverage_note": COVERAGE_NOTE, "run_id": run_id}
    if collector is not None:
        out["alias_collection"] = collector.report()
    return out


# ------------------------------------------------------------ offline query
def query_records(project, run_id: str | None = None,
                  profile: str | None = None, mode: str | None = None,
                  text: str | None = None, limit: int = 50,
                  offset: int = 0) -> dict:
    """Paginated offline query over persisted string_watch records (events
    of kind "string_record"). Filters: run_id, source profile, capture
    mode (run capture_config), and a substring match on captured text.
    Follows the `runs list` pagination shape (issue #33/#36)."""
    where, params = ["e.kind='string_record'"], []
    if run_id:
        where.append("e.run_id=?")
        params.append(run_id)
    if profile:
        where.append("e.payload LIKE ?")
        params.append(f'%"profile":"{profile}"%')
    if mode:
        where.append("r.capture_config LIKE ?")
        params.append(f'%"mode":"{mode}"%')
    if text:
        where.append("instr(e.payload, ?) > 0")
        params.append(text)
    cond = " AND ".join(where)
    with project.db() as db:
        rows = db.query(
            "SELECT e.event_id, e.run_id, e.class_sig, e.method_name, "
            "e.method_sig, e.payload FROM events e JOIN runs r ON "
            "r.run_id=e.run_id WHERE " + cond +
            " ORDER BY e.rowid LIMIT ? OFFSET ?",
            tuple(params) + (limit, offset))
        total = db.one(
            "SELECT COUNT(*) AS n FROM events e JOIN runs r ON "
            "r.run_id=e.run_id WHERE " + cond, tuple(params))["n"]
    records = []
    for row in rows:
        payload = json.loads(row.pop("payload") or "{}")
        row["texts"] = payload.get("texts")
        row["profile"] = payload.get("profile")
        row["attribution"] = payload.get("attribution")
        row["status"] = payload.get("status", "ok")
        records.append(row)
    return {"records": records, "count": len(records), "total": total,
            "limit": limit, "offset": offset,
            "truncated": offset + len(records) < total}

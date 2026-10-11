"""Out-of-the-box crypto hooks — intercept javax.crypto at the API boundary
so plaintext, keys, and IVs are captured before/after processing, regardless
of how obfuscated the caller is (framework signatures are never obfuscated).

Mechanics per hook:
  1. ClassesBySignature on the *framework* class (always loadable once used)
  2. Breakpoint at the method's first bytecode index (method entry)
  3. On hit (suspend EVENT_THREAD): frame 0 -> read args by position
     (capture spec uses JVM-style slots: 0 = this, args follow, wide args
     take two slots; translated to ART DEX vregs via the LocalVariableTable
     at install time, see capture.arg_vreg_map)
  4. byte[] args -> hex+b64+utf8 via ArrayReference; String via
     StringReference; Key objects -> invoke getEncoded()/getAlgorithm()
  5. Resume the thread; emit one minified JSON record per hit

To also capture doFinal's OUTPUT, pair the entry hook with a
METHOD_EXIT_WITH_RETURN_VALUE request on the same method (see
install(..., capture_returns=True)). Exit requests are class-scoped
(mod_class_only), so exit events fire for every method of the class and
must be filtered by exact method id at capture time.

Registration state lives in session.bp_registry (per-session, per connection
epoch) via session.events, the EventDispatcher: every request id maps to its
event kind, hook name, target class/method/sig, capture phase, classloader
identity, and owner ("crypto"). Entries are stamped with the connection
epoch and go dead on (re)attach; the symbolic hook definition survives for
the re-install path (dispatcher.symbolic_hooks). Install is idempotent per
(hook, type_id, phase): re-running it never duplicates requests. Hooks whose
classes are not yet loaded are reported with state "pending" — or, with
install(..., defer=True), get a CLASS_PREPARE watch that auto-installs the
hook exactly once per prepared class instance (per classloader).

The watch loop (run_watch) is a subscription-based consumer of the
dispatcher: it receives only crypto-owned events, routed by request id AND
event kind. Threads suspended by claimed events form a shared lease that is
released once per thread after every consumer of the composite finished.
Events the watch does NOT own (user breakpoints, other watchers) are never
resumed by the loop and never dropped: they are stashed back into the
dispatcher and surface through the public wait_events interface, whose
caller inherits resume responsibility for them (the app waits at that stop
exactly as if the watch were not running). Cleanup runs on completion,
timeout, capture failure, and cancellation, clears each request with its
actual event kind, and — if the connection was re-established mid-watch —
reports the old epoch's requests as UNCONFIRMED instead of clearing numeric
ids the new connection may have reused.

Metadata (algorithm, encoded key bytes) is captured WITHOUT invokes
wherever possible: declared instance fields are read directly
(capture.read_fields), which cannot re-enter hooked code. Metadata
invokes (getAlgorithm/getEncoded) are used only as a fallback and only
when install ran with capture_returns=False — with capture_returns=True
the class-scoped METHOD_EXIT_WITH_RETURN_VALUE requests would suspend the
invoked thread at its own method exit mid-invoke and the invoke reply
never arrives (observed on Android 15: every meta invoke stalled until
the 15s reply timeout). This is the documented reentrancy policy: no
invoke may run while class-scoped exit requests are armed; a failed
capture is reported in the record and never blocks resume or teardown.
"""

from __future__ import annotations

import base64
import json
import time

from ...device.jdwp import (
    EVK_BREAKPOINT, EVK_METHOD_EXIT_RET, SP_EVENT_THREAD, JdwpClient,
)
from ...core.manifests import RunStore, capture_environment
from ...errors import ResolveError, SessionError
from ...protocol import log_progress
from ..capture import (
    arg_vreg_map, capture_spec, decode_tagged, invoke_meta, read_fields,
)

GET_ALGO = {"method": "getAlgorithm", "sig": "()Ljava/lang/String;",
            "label": "algorithm"}
GET_ENCODED = {"method": "getEncoded", "sig": "()[B", "label": "_encoded"}
# AOSP field names backing the same metadata (read without invokes)
FLD_ALGO = {"name": "algorithm", "label": "algorithm"}
FLD_TRANSFORMATION = {"name": "transformation", "label": "algorithm"}
FLD_KEY = {"name": "key", "label": "_encoded"}

CRYPTO_HOOKS: list[dict] = [
    {"name": "Cipher.doFinal(byte[])",
     "cls": "Ljavax/crypto/Cipher;", "method": "doFinal", "sig": "([B)[B",
     "capture": [{"slot": 1, "type": "byte[]", "label": "input"}],
     "meta": [GET_ALGO], "meta_fields": [FLD_TRANSFORMATION]},
    {"name": "Cipher.doFinal(byte[],int,int)",
     "cls": "Ljavax/crypto/Cipher;", "method": "doFinal",
     "sig": "([BII)[B",
     "capture": [{"slot": 1, "type": "byte[]", "label": "input"},
                 {"slot": 2, "type": "int", "label": "offset"},
                 {"slot": 3, "type": "int", "label": "len"}],
     "meta": [GET_ALGO], "meta_fields": [FLD_TRANSFORMATION]},
    {"name": "Cipher.doFinal()",
     "cls": "Ljavax/crypto/Cipher;", "method": "doFinal", "sig": "()[B",
     "capture": [], "meta": [GET_ALGO], "meta_fields": [FLD_TRANSFORMATION]},
    {"name": "Cipher.init(int,Key)",
     "cls": "Ljavax/crypto/Cipher;", "method": "init",
     "sig": "(ILjava/security/Key;)V",
     "capture": [{"slot": 1, "type": "int", "label": "opmode"},
                 {"slot": 2, "type": "object", "label": "key"}],
     "meta": [GET_ALGO], "meta_fields": [FLD_TRANSFORMATION],
     "key_invoke": [GET_ALGO, GET_ENCODED],
     "key_fields": [FLD_ALGO, FLD_KEY]},
    {"name": "SecretKeySpec.<init>(byte[],String)",
     "cls": "Ljavax/crypto/spec/SecretKeySpec;", "method": "<init>",
     "sig": "([BLjava/lang/String;)V",
     "capture": [{"slot": 1, "type": "byte[]", "label": "key"},
                 {"slot": 2, "type": "string", "label": "algorithm"}],
     "meta": []},
    {"name": "IvParameterSpec.<init>(byte[])",
     "cls": "Ljavax/crypto/spec/IvParameterSpec;", "method": "<init>",
     "sig": "([B)V",
     "capture": [{"slot": 1, "type": "byte[]", "label": "iv"}], "meta": []},
    {"name": "Mac.doFinal(byte[])",
     "cls": "Ljavax/crypto/Mac;", "method": "doFinal", "sig": "([B)[B",
     "capture": [{"slot": 1, "type": "byte[]", "label": "input"}],
     "meta": [GET_ALGO], "meta_fields": [FLD_ALGO]},
    {"name": "MessageDigest.digest(byte[])",
     "cls": "Ljava/security/MessageDigest;", "method": "digest",
     "sig": "([B)[B",
     "capture": [{"slot": 1, "type": "byte[]", "label": "input"}],
     "meta": [GET_ALGO], "meta_fields": [FLD_ALGO]},
]


class ClassNotLoaded(ResolveError):
    """Hook class not loaded yet — the pending (deferrable) state."""


class MethodNotFound(ResolveError):
    """Class loaded but the hooked (method, sig) is absent."""


class UnsupportedHook(ResolveError):
    """Hook target cannot be breakpointed (e.g. native method)."""


def install(session, names: list[str] | None = None,
            capture_returns: bool = False, defer: bool = False) -> dict:
    """Register breakpoints for the selected hooks. Every hook ends in one
    distinct state: installed / pending (class not loaded — deferrable) /
    not-found / unsupported / failed. With defer=True, pending hooks also
    get a CLASS_PREPARE watch that installs them exactly once per prepared
    class instance; the watch request is crypto-owned and is cleaned up
    like any other request."""
    d = session.events
    installed, pending, deferred = [], [], []
    states = {}
    for hook in CRYPTO_HOOKS:
        if names and hook["name"] not in names:
            continue
        try:
            regs = _install_one(session, hook, capture_returns)
        except ClassNotLoaded as e:
            states[hook["name"]] = "pending"
            pending.append({"hook": hook["name"], "state": "pending",
                            "reason": str(e)[:120]})
            if defer:
                rid = d.defer_hook(
                    "crypto", hook["name"], _class_pattern(hook["cls"]),
                    _make_on_prepare(session, hook, capture_returns),
                    symbolic={"owner": "crypto", "hook": hook["name"],
                              "hook_def": hook,
                              "capture_returns": capture_returns})
                deferred.append({"hook": hook["name"], "request_id": rid})
            continue
        except (MethodNotFound, UnsupportedHook) as e:
            state = ("not-found" if isinstance(e, MethodNotFound)
                     else "unsupported")
            states[hook["name"]] = state
            pending.append({"hook": hook["name"], "state": state,
                            "reason": str(e)[:120]})
            continue
        except Exception as e:
            states[hook["name"]] = "failed"
            pending.append({"hook": hook["name"], "state": "failed",
                            "reason": str(e)[:120]})
            continue
        states[hook["name"]] = "installed"
        installed.append({"hook": hook["name"],
                          "request_ids": [r["rid"] for r in regs]})
    return {"installed": installed, "pending": pending,
            "deferred": deferred, "states": states,
            "note": "pending hooks: class not loaded yet; re-install later "
                    "or install with defer=True for CLASS_PREPARE "
                    "auto-install"}


def _install_one(session, hook: dict, capture_returns: bool,
                 only_type_ids: set[int] | None = None) -> list[dict]:
    """Register entry breakpoint (+ optional class-scoped method-exit) for
    every loaded class implementing the hooked method. Idempotent per
    (hook, type_id, phase): classes already hooked in this epoch contribute
    their existing request ids instead of duplicate requests. On partial
    failure, only the requests registered by THIS call are cleared."""
    c = session.client
    classes = c.classes_by_signature(hook["cls"])
    if not classes:
        raise ClassNotLoaded(f"{hook['cls']} not loaded")
    live = {rid: m for rid, m in session.bp_registry.items()
            if m.get("owner") == "crypto" and m.get("hook") == hook["name"]
            and session.events.is_live(m)}
    done = {(m["type_id"], m["phase"]) for m in live.values()}
    regs = [{"rid": rid, "kind": m["kind"], "phase": m["phase"],
             "type_id": m["type_id"], "method_id": m["method_id"],
             "vregs": m.get("vregs")}
            for rid, m in live.items()]
    new = []
    try:
        for cls in classes:
            tid = cls["type_id"]
            if only_type_ids is not None and tid not in only_type_ids:
                continue
            want_exit = capture_returns and (tid, "return") not in done
            if (tid, "entry") in done and not want_exit:
                continue
            m = next((m for m in c.rt_methods(tid)
                      if m["name"] == hook["method"]
                      and m["sig"] == hook["sig"]), None)
            if not m:
                raise MethodNotFound(
                    f"{hook['method']}{hook['sig']} not found")
            if m.get("mod_bits", 0) & 0x0100:
                raise UnsupportedHook(
                    f"{hook['method']}{hook['sig']} is native")
            try:
                lt = c.method_line_table(tid, m["id"])
                idx = lt["lines"][0]["index"] if lt["lines"] else 0
            except Exception:
                idx = 0  # no debug info on framework classes: entry = index 0
            vregs = arg_vreg_map(c, tid, m["id"])
            try:
                loader = c.rt_class_loader(tid)
            except Exception:
                loader = None  # type_id identity still dedupes per loader
            if (tid, "entry") not in done:
                rid = c.set_breakpoint(tid, m["id"], idx, SP_EVENT_THREAD)
                new.append({"rid": rid, "kind": EVK_BREAKPOINT,
                            "phase": "entry", "type_id": tid,
                            "method_id": m["id"], "vregs": vregs,
                            "loader": loader})
            if want_exit:
                rid = c.set_event(
                    EVK_METHOD_EXIT_RET, SP_EVENT_THREAD,
                    [c.mod_class_only(tid)])
                new.append({"rid": rid, "kind": EVK_METHOD_EXIT_RET,
                            "phase": "return", "type_id": tid,
                            "method_id": m["id"], "vregs": vregs,
                            "loader": loader})
    except Exception:
        for r in new:
            try:
                c.clear_event(r["kind"], r["rid"])
            except Exception:
                pass
        raise
    for r in new:
        session.events.register(r["rid"], {
            "owner": "crypto", "hook": hook["name"], "hook_def": hook,
            "entry": "hook", "kind": r["kind"], "phase": r["phase"],
            "cls": hook["cls"], "type_id": r["type_id"],
            "loader": r["loader"],
            "method": hook["method"], "sig": hook["sig"],
            "method_id": r["method_id"], "vregs": r["vregs"],
            "can_invoke": not capture_returns,
            "spec": hook["method"] + hook["sig"]})
    return regs + new


def _class_pattern(sig: str) -> str:
    """'Ljavax/crypto/Cipher;' -> 'javax.crypto.Cipher' (ClassMatch)."""
    return sig[1:-1].replace("/", ".") if sig.startswith("L") else sig


def _make_on_prepare(session, hook: dict, capture_returns: bool):
    def on_prepare(ev: dict, handler: dict) -> None:
        regs = _install_one(session, hook, capture_returns,
                            only_type_ids={ev.get("type_id")})
        handler["installed_rids"].extend(r["rid"] for r in regs)
    return on_prepare


def extract_event(session, ev: dict) -> dict | None:
    """Build the compact JSON record for a crypto-hook event. Returns None
    for events not owned by the crypto hooks, and for class-scoped exit
    events of a different method than the hooked one (the owning
    subscription still releases the suspension via the lease)."""
    reg = session.bp_registry.get(ev.get("request_id"))
    thread = ev.get("thread")
    if reg is None or reg.get("owner") != "crypto" or thread is None:
        return None
    hook = reg["hook_def"]
    if ev.get("kind_id") == EVK_METHOD_EXIT_RET:
        loc = ev.get("location") or {}
        if loc.get("method") != reg.get("method_id"):
            return None  # class-scoped exit: some other method of the class
        rec = {"hook": hook["name"], "thread": thread, "phase": "return"}
        try:  # tagged return_value; frames are not valid at exit
            rec["return"] = decode_tagged(session.client,
                                          ev.get("return_value") or {})
        except Exception as e:
            rec["capture_error"] = str(e)[:120]
        return rec
    return _extract_entry(session, reg, thread)


def _extract_entry(session, reg: dict, thread: int) -> dict:
    hook = reg["hook_def"]
    c = session.client
    rec = {"hook": hook["name"], "thread": thread, "phase": "entry"}
    try:
        frames = c.thread_frames(thread, 1)
        if not frames:
            raise SessionError(f"thread {thread} has no frames")
        fr = frames[0]
        rec["args"] = capture_spec(c, thread, fr["frame_id"],
                                   hook["capture"], vregs=reg.get("vregs"))
    except Exception as e:
        rec["capture_error"] = str(e)[:120]
        return rec
    # this-object metadata (algorithm, opmode...) — field reads first
    # (deadlock-free); invokes only when no class-scoped exit requests are
    # armed, see module docstring
    try:
        this = c.frame_this_object(thread, fr["frame_id"])
        if this["v"]:
            if hook.get("meta_fields"):
                rec["meta"] = read_fields(c, this["v"],
                                          hook["meta_fields"])
            elif hook.get("meta") and reg.get("can_invoke"):
                rec["meta"] = invoke_meta(c, thread, this["v"],
                                          hook["meta"])
        # Key objects: expand via declared fields (or invokes when safe)
        key_node = rec["args"].get("key")
        if key_node and key_node.get("id"):
            if hook.get("key_fields"):
                meta = read_fields(c, key_node["id"], hook["key_fields"])
            elif hook.get("key_invoke") and reg.get("can_invoke"):
                meta = invoke_meta(c, thread, key_node["id"],
                                   hook["key_invoke"])
            else:
                meta = {}
            enc = meta.pop("_encoded", None)
            if isinstance(enc, dict) and enc.get("hex"):
                meta["encoded"] = enc
            elif isinstance(enc, int) and enc:
                meta["encoded"] = _bytes_of(c, enc)
            rec["args"]["key"].update(meta)
    except Exception as e:
        rec["meta_error"] = str(e)[:120]
    return rec


def _bytes_of(c: JdwpClient, oid: int) -> dict:
    raw = c.byte_array(oid, 4096)
    return {"len": c.array_length(oid), "hex": raw.hex(),
            "b64": base64.b64encode(raw).decode()}


def run_watch(session, duration_s: float = 60.0,
              names: list[str] | None = None,
              capture_returns: bool = False,
              max_events: int = 1000,
              max_bytes: int = 1 << 20,
              defer: bool = False,
              record: bool = False,
              scenario: str | None = None) -> dict:
    """Blocking watch loop: install hooks, then consume crypto-owned events
    through the session dispatcher for duration_s (bounded by max_events
    records / max_bytes of captured JSON). The loop claims only its own
    events: unrelated stops are stashed for the public wait_events caller
    (counted in "unrelated"), whose consumer owns resume responsibility for
    them — the watch never resumes threads from events it does not own.
    Teardown clears every crypto request (including deferred CLASS_PREPARE
    watches and auto-installed hooks) with its original event kind, on
    every exit path. If the connection was re-established mid-watch, the
    dead epoch's requests are reported in "unconfirmed" and the remote is
    left untouched. Capture/cleanup failures are reported in the result,
    never swallowed.

    With record=True (and a project-backed session), the watch is persisted
    as a versioned run manifest (issue #36): capture config, completion
    reason, and counters on the run; one event row per captured record
    (bounded by max_events), keyed by the hook's original class/method
    descriptor. The result gains a "run_id" key."""
    d = session.events
    epoch = d.epoch
    rep = install(session, names=names, capture_returns=capture_returns,
                  defer=defer)
    owned = {rid for i in rep["installed"] for rid in i["request_ids"]}
    owned |= {dfr["request_id"] for dfr in rep["deferred"]}
    base_owned = set(owned)
    records, errors, cleanup_errors = [], [], []
    captured_bytes, unrelated = 0, 0
    reason = "duration"

    def on_event(ev: dict, lease) -> None:
        nonlocal captured_bytes
        rec = extract_event(session, ev)
        if rec:
            records.append(rec)
            captured_bytes += len(json.dumps(rec))

    sub = d.subscribe("crypto", on_event)
    deadline = time.time() + duration_s
    try:
        while time.time() < deadline:
            try:
                r = d.next_routed(
                    timeout=max(1.0, deadline - time.time()))
            except Exception as e:
                if getattr(e, "code", None) != "E_JDWP_TIMEOUT":
                    reason = "error"
                    errors.append(f"wait: {str(e)[:120]}")
                    log_progress(f"watch loop: {e}")
                break
            errors.extend(r.lease.errors)
            for h in d.deferred_handlers("crypto"):
                owned.update(h["installed_rids"])
            if r["events"]:
                unrelated += len(r["events"])
                d.stash(r)
            if len(records) >= max_events:
                reason = "max_events"
                break
            if captured_bytes >= max_bytes:
                reason = "max_bytes"
                break
    finally:
        sub.close()
        for h in d.deferred_handlers("crypto"):
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
    return {"records": records, "hits": len(records),
            "installed": len(rep["installed"]), "pending": rep["pending"],
            "states": rep["states"], "deferred": rep["deferred"],
            "auto_installed": auto_installed,
            "reason": reason, "truncated": reason == "max_bytes",
            "captured_bytes": captured_bytes, "unrelated": unrelated,
            "unconfirmed": unconfirmed,
            "errors": errors, "cleanup_errors": cleanup_errors,
            "run_id": _record_run(
                session, epoch, records, reason, unrelated, errors,
                {"duration_s": duration_s, "names": names,
                 "capture_returns": capture_returns,
                 "max_events": max_events, "max_bytes": max_bytes,
                 "defer": defer}, record, scenario)}


def _record_run(session, epoch: int, records: list, reason: str,
                unrelated: int, errors: list, capture_config: dict,
                record: bool, scenario: str | None) -> str | None:
    """Persist the watch as a run manifest with one event row per record
    (issue #36); None when recording is off or the session has no project.
    Event identity uses the hook's original class/method descriptor —
    never runtime ids."""
    store = RunStore.for_session(session) if record else None
    if store is None:
        return None
    run_id = store.begin_run(
        "crypto_watch", capture_config=capture_config, scenario=scenario,
        epoch=epoch, environment=capture_environment(session))
    hooks = {h["name"]: h for h in CRYPTO_HOOKS}
    for rec in records:
        hook = hooks.get(rec.get("hook"), {})
        store.add_event(run_id, "crypto_record", rec,
                        class_sig=hook.get("cls"),
                        method_name=hook.get("method"),
                        method_sig=hook.get("sig"), epoch=epoch)
    store.end_run(run_id, reason,
                  counts={"hits": len(records), "unrelated": unrelated,
                          "errors": len(errors)})
    return run_id

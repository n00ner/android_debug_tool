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

Registration state lives in session.bp_registry (per-session, cleared on
reconnect): every request id maps to its event kind, hook name, target
class/method/sig, and owner.

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


def install(session, names: list[str] | None = None,
            capture_returns: bool = False) -> dict:
    """Register breakpoints for the selected hooks. Hooks whose classes are
    not yet loaded are reported as pending — the agent should re-run install
    after the app touches crypto (or drive it with a CLASS_PREPARE watch)."""
    installed, pending = [], []
    for hook in CRYPTO_HOOKS:
        if names and hook["name"] not in names:
            continue
        try:
            regs = _install_one(session.client, hook, capture_returns)
        except Exception as e:
            pending.append({"hook": hook["name"], "reason": str(e)[:120]})
            continue
        installed.append({"hook": hook["name"],
                          "request_ids": [r["rid"] for r in regs]})
        for r in regs:
            session.bp_registry[r["rid"]] = {
                "owner": "crypto", "hook": hook["name"], "hook_def": hook,
                "kind": r["kind"], "phase": r["phase"],
                "cls": hook["cls"], "type_id": r["type_id"],
                "method": hook["method"], "sig": hook["sig"],
                "method_id": r["method_id"], "vregs": r["vregs"],
                "can_invoke": not capture_returns,
                "spec": hook["method"] + hook["sig"]}
    return {"installed": installed, "pending": pending,
            "note": "pending hooks: class not loaded yet; re-install later"}


def _install_one(c: JdwpClient, hook: dict,
                 capture_returns: bool) -> list[dict]:
    """Register entry breakpoint (+ optional class-scoped method-exit) for
    every loaded class implementing the hooked method. On partial failure,
    already-registered requests are cleared before re-raising."""
    classes = c.classes_by_signature(hook["cls"])
    if not classes:
        raise ResolveError(f"{hook['cls']} not loaded")
    regs = []
    try:
        for cls in classes:
            m = next((m for m in c.rt_methods(cls["type_id"])
                      if m["name"] == hook["method"]
                      and m["sig"] == hook["sig"]), None)
            if not m:
                raise ResolveError(f"{hook['method']}{hook['sig']} not found")
            try:
                lt = c.method_line_table(cls["type_id"], m["id"])
                idx = lt["lines"][0]["index"] if lt["lines"] else 0
            except Exception:
                idx = 0  # no debug info on framework classes: entry = index 0
            vregs = arg_vreg_map(c, cls["type_id"], m["id"])
            rid = c.set_breakpoint(cls["type_id"], m["id"], idx,
                                   SP_EVENT_THREAD)
            regs.append({"rid": rid, "kind": EVK_BREAKPOINT,
                         "phase": "entry", "type_id": cls["type_id"],
                         "method_id": m["id"], "vregs": vregs})
            if capture_returns:
                rid = c.set_event(
                    EVK_METHOD_EXIT_RET, SP_EVENT_THREAD,
                    [c.mod_class_only(cls["type_id"])])
                regs.append({"rid": rid, "kind": EVK_METHOD_EXIT_RET,
                             "phase": "return", "type_id": cls["type_id"],
                             "method_id": m["id"], "vregs": vregs})
    except Exception:
        for r in regs:
            try:
                c.clear_event(r["kind"], r["rid"])
            except Exception:
                pass
        raise
    return regs


def extract_event(session, ev: dict) -> dict | None:
    """Build the compact JSON record for a crypto-hook event. Returns None
    for events not owned by the crypto hooks, and for class-scoped exit
    events of a different method than the hooked one (caller still resumes
    the thread)."""
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
    # (deadlock-free); getters fill only labels the field reads missed,
    # and only when no class-scoped exit requests are armed (see module
    # docstring)
    try:
        this = c.frame_this_object(thread, fr["frame_id"])
        if this["v"] and (hook.get("meta_fields") or hook.get("meta")):
            rec["meta"] = _meta_with_fallback(
                c, thread, this["v"], hook.get("meta_fields"),
                hook.get("meta") if reg.get("can_invoke") else None)
        # Key objects: expand via declared fields, getters as fallback
        key_node = rec["args"].get("key")
        if key_node and key_node.get("id") and (
                hook.get("key_fields") or hook.get("key_invoke")):
            meta = _meta_with_fallback(
                c, thread, key_node["id"], hook.get("key_fields"),
                hook.get("key_invoke") if reg.get("can_invoke") else None)
            enc = meta.pop("_encoded", None)
            if isinstance(enc, dict) and enc.get("hex"):
                meta["encoded"] = enc
            elif isinstance(enc, int) and enc:
                meta["encoded"] = _bytes_of(c, enc)
            rec["args"]["key"].update(meta)
    except Exception as e:
        rec["meta_error"] = str(e)[:120]
    return rec


def _meta_with_fallback(c: JdwpClient, thread: int, obj: int,
                        field_specs: list[dict] | None,
                        invoke_specs: list[dict] | None) -> dict:
    """Merge field-read metadata with getter invokes: declared fields win;
    labels whose field read failed (or which have no field spec, e.g. a
    custom/provider Key with differently-named backing fields) are filled
    from the corresponding getters — but only when invoke_specs is not
    None, i.e. the caller verified invokes are safe (can_invoke)."""
    meta = read_fields(c, obj, field_specs) if field_specs else {}
    if not invoke_specs:
        return meta
    retry = [inv for inv in invoke_specs
             if _is_error(meta.get(inv["label"]))]
    for label, val in invoke_meta(c, thread, obj, retry).items():
        if not _is_error(val) or label not in meta:
            meta[label] = val  # getter won, or no field error to keep
    return meta


def _is_error(node) -> bool:
    return node is None or (isinstance(node, dict) and "error" in node)


def _bytes_of(c: JdwpClient, oid: int) -> dict:
    raw = c.byte_array(oid, 4096)
    return {"len": c.array_length(oid), "hex": raw.hex(),
            "b64": base64.b64encode(raw).decode()}


def run_watch(session, duration_s: float = 60.0,
              names: list[str] | None = None,
              capture_returns: bool = False,
              max_events: int = 1000,
              max_bytes: int = 1 << 20) -> dict:
    """Blocking watch loop: install hooks, collect events for duration_s
    (bounded by max_events records / max_bytes of captured JSON), resume
    suspended threads after each composite, then uninstall every request
    with its original event kind. Capture/cleanup failures are reported in
    the result, never swallowed."""
    rep = install(session, names=names, capture_returns=capture_returns)
    owned = {rid for i in rep["installed"] for rid in i["request_ids"]}
    records, errors, cleanup_errors = [], [], []
    captured_bytes, unrelated = 0, 0
    reason = "duration"
    deadline = time.time() + duration_s
    try:
        while time.time() < deadline:
            try:
                ev = session.wait_events(
                    timeout=max(1.0, deadline - time.time()))
            except Exception as e:
                if getattr(e, "code", None) != "E_JDWP_TIMEOUT":
                    reason = "error"
                    errors.append(f"wait: {str(e)[:120]}")
                    log_progress(f"watch loop: {e}")
                break
            own_threads, other_threads = set(), set()
            for e in ev.get("events", []):
                if e.get("request_id") in owned:
                    if "thread" in e:
                        own_threads.add(e["thread"])
                    rec = extract_event(session, e)
                    if rec:
                        records.append(rec)
                        captured_bytes += len(json.dumps(rec))
                else:
                    # not ours: report it, but still resume its thread so
                    # the app is not left stopped on our account
                    unrelated += 1
                    if "thread" in e:
                        other_threads.add(e["thread"])
            for t in own_threads | other_threads:
                try:
                    session.resume(thread=t)
                except Exception as ex:
                    errors.append(f"resume {t}: {str(ex)[:80]}")
            if len(records) >= max_events:
                reason = "max_events"
                break
            if captured_bytes >= max_bytes:
                reason = "max_bytes"
                break
    finally:
        for rid in owned:
            try:
                session.clear_request(rid)
            except Exception as e:
                cleanup_errors.append(f"clear {rid}: {str(e)[:120]}")
    return {"records": records, "hits": len(records),
            "installed": len(rep["installed"]), "pending": rep["pending"],
            "reason": reason, "truncated": reason == "max_bytes",
            "captured_bytes": captured_bytes, "unrelated": unrelated,
            "errors": errors, "cleanup_errors": cleanup_errors}

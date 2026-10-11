"""Out-of-the-box crypto hooks — intercept javax.crypto at the API boundary
so plaintext, keys, and IVs are captured before/after processing, regardless
of how obfuscated the caller is (framework signatures are never obfuscated).

Mechanics per hook:
  1. ClassesBySignature on the *framework* class (always loadable once used)
  2. Breakpoint at the method's first bytecode index (method entry)
  3. On hit (suspend EVENT_THREAD): frame 0 -> read arg slots by position
     (instance method: slot 0 = this, args follow, longs/doubles take 2 slots)
  4. byte[] args -> hex+b64+utf8 via ArrayReference; String via
     StringReference; Key objects -> invoke getEncoded()/getAlgorithm()
  5. Resume the thread; emit one minified JSON record per hit

To also capture doFinal's OUTPUT, pair the entry hook with a
METHOD_EXIT_WITH_RETURN_VALUE request on the same method (see
install(..., capture_returns=True)).
"""

from __future__ import annotations

import time

from ...device.jdwp import (
    EVK_BREAKPOINT, EVK_METHOD_EXIT_RET, SP_EVENT_THREAD, JdwpClient,
)
from ...errors import ResolveError
from ...protocol import log_progress
from ..capture import capture_spec, invoke_meta

GET_ALGO = {"method": "getAlgorithm", "sig": "()Ljava/lang/String;",
            "label": "algorithm"}
GET_ENCODED = {"method": "getEncoded", "sig": "()[B", "label": "_encoded"}

CRYPTO_HOOKS: list[dict] = [
    {"name": "Cipher.doFinal(byte[])",
     "cls": "Ljavax/crypto/Cipher;", "method": "doFinal", "sig": "([B)[B",
     "capture": [{"slot": 1, "type": "byte[]", "label": "input"}],
     "meta": [GET_ALGO]},
    {"name": "Cipher.doFinal(byte[],int,int)",
     "cls": "Ljavax/crypto/Cipher;", "method": "doFinal",
     "sig": "([BII)[B",
     "capture": [{"slot": 1, "type": "byte[]", "label": "input"},
                 {"slot": 2, "type": "int", "label": "offset"},
                 {"slot": 3, "type": "int", "label": "len"}],
     "meta": [GET_ALGO]},
    {"name": "Cipher.doFinal()",
     "cls": "Ljavax/crypto/Cipher;", "method": "doFinal", "sig": "()[B",
     "capture": [], "meta": [GET_ALGO]},
    {"name": "Cipher.init(int,Key)",
     "cls": "Ljavax/crypto/Cipher;", "method": "init",
     "sig": "(ILjava/security/Key;)V",
     "capture": [{"slot": 1, "type": "int", "label": "opmode"},
                 {"slot": 2, "type": "object", "label": "key"}],
     "meta": [GET_ALGO], "key_invoke": [GET_ALGO, GET_ENCODED]},
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
     "meta": [GET_ALGO]},
    {"name": "MessageDigest.digest(byte[])",
     "cls": "Ljava/security/MessageDigest;", "method": "digest",
     "sig": "([B)[B",
     "capture": [{"slot": 1, "type": "byte[]", "label": "input"}],
     "meta": [GET_ALGO]},
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
            req_ids = _install_one(session.client, hook, capture_returns)
            entry = {"hook": hook["name"], "request_ids": req_ids}
            installed.append(entry)
            for rid in req_ids:
                session.bp_registry[rid] = {"hook": hook["name"],
                                            "spec": hook["method"] + hook["sig"]}
            _hook_by_rid[rid] = hook
        except Exception as e:
            pending.append({"hook": hook["name"], "reason": str(e)[:120]})
    return {"installed": installed, "pending": pending,
            "note": "pending hooks: class not loaded yet; re-install later"}


_hook_by_rid: dict[int, dict] = {}


def _install_one(c: JdwpClient, hook: dict, capture_returns: bool) -> list[int]:
    classes = c.classes_by_signature(hook["cls"])
    if not classes:
        raise ResolveError(f"{hook['cls']} not loaded")
    rids = []
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
        rids.append(c.set_breakpoint(cls["type_id"], m["id"], idx,
                                     SP_EVENT_THREAD))
        if capture_returns:
            rids.append(c.set_event(
                EVK_METHOD_EXIT_RET, SP_EVENT_THREAD,
                [c.mod_class_only(cls["type_id"])]))
    return rids


def extract_event(session, ev: dict) -> dict | None:
    """Build the compact JSON record for a crypto-hook event. Returns None
    for unrelated events (caller should still resume the thread)."""
    hook = _hook_by_rid.get(ev.get("request_id"))
    thread = ev.get("thread")
    if hook is None or thread is None:
        return None
    c = session.client
    fr = c.thread_frames(thread, 1)[0]
    rec = {"hook": hook["name"], "thread": thread,
           "args": capture_spec(c, thread, fr["frame_id"], hook["capture"])}
    # this-object metadata (algorithm, opmode...)
    try:
        this = c.frame_this_object(thread, fr["frame_id"])
        if this["v"] and hook.get("meta"):
            rec["meta"] = invoke_meta(c, thread, this["v"], hook["meta"])
        # Key objects: expand via getEncoded/getAlgorithm
        key_node = rec["args"].get("key")
        if key_node and key_node.get("id") and hook.get("key_invoke"):
            meta = invoke_meta(c, thread, key_node["id"], hook["key_invoke"])
            enc = meta.pop("_encoded", None)
            if isinstance(enc, int) and enc:
                meta["encoded"] = _bytes_of(c, enc)
            rec["args"]["key"].update(meta)
    except Exception as e:
        rec["meta_error"] = str(e)[:120]
    return rec


def _bytes_of(c: JdwpClient, oid: int) -> dict:
    raw = c.byte_array(oid, 4096)
    import base64
    return {"len": c.array_length(oid), "hex": raw.hex(),
            "b64": base64.b64encode(raw).decode()}


def run_watch(session, duration_s: float = 60.0,
              names: list[str] | None = None,
              capture_returns: bool = False) -> dict:
    """Blocking watch loop: install hooks, collect events for duration_s,
    resume threads after each capture, then uninstall."""
    rep = install(session, names=names, capture_returns=capture_returns)
    records = []
    deadline = time.time() + duration_s
    while time.time() < deadline:
        try:
            ev = session.wait_events(timeout=max(1.0, deadline - time.time()))
        except Exception as e:
            log_progress(f"watch loop: {e}")
            break
        for e in ev.get("events", []):
            rec = extract_event(session, e)
            if rec:
                records.append(rec)
            if "thread" in e:
                try:
                    session.resume(thread=e["thread"])
                except Exception:
                    pass
    for rid in [r for i in rep["installed"] for r in i["request_ids"]]:
        try:
            session.delete_breakpoint(rid)
        except Exception:
            pass
    return {"records": records, "hits": len(records),
            "installed": len(rep["installed"]), "pending": rep["pending"]}

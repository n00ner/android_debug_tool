"""Shared value extraction at a suspended frame — used by crypto hooks,
conditional breakpoints, and read_var. Produces compact JSON-native nodes."""

from __future__ import annotations

import base64

from ..device.jdwp import JdwpClient, TAG_ARRAY, TAG_STRING, sig_to_tag
from ..errors import SessionError

PRIM_TYPES = {"int": 73, "long": 74, "boolean": 90, "byte": 66,
              "short": 83, "char": 67, "float": 70, "double": 68}


def capture_value(c: JdwpClient, thread: int, frame_id: int, slot: int,
                  typ: str, *, max_bytes: int = 4096,
                  max_str: int = 512) -> dict:
    """Read one slot as `typ` and decode to a compact JSON node.

    typ: int|long|boolean|byte|short|char|float|double|string|byte[]|object
    """
    if typ in PRIM_TYPES:
        v = c.frame_get_values(thread, frame_id, [(slot, PRIM_TYPES[typ])])[0]
        return {"type": typ, "v": v["v"]}
    if typ == "string":
        v = c.frame_get_values(thread, frame_id, [(slot, TAG_STRING)])[0]
        return {"type": "string",
                "v": c.string_value(v["v"], max_str) if v["v"] else None}
    if typ == "byte[]":
        v = c.frame_get_values(thread, frame_id, [(slot, TAG_ARRAY)])[0]
        if not v["v"]:
            return {"type": "byte[]", "v": None}
        raw = c.byte_array(v["v"], max_bytes)
        return {"type": "byte[]", "len": c.array_length(v["v"]),
                "hex": raw.hex(),
                "b64": base64.b64encode(raw).decode(),
                "utf8": _try_utf8(raw),
                "trunc": c.array_length(v["v"]) > max_bytes}
    if typ == "object":
        v = c.frame_get_values(thread, frame_id, [(slot, 76)])[0]
        node = {"type": "object", "id": v["v"]}
        if v["v"]:
            node["cls"] = _safe_sig(c, v["v"])
        return node
    raise SessionError(f"unknown capture type {typ!r}",
                       hint="one of: " + ", ".join(
                           list(PRIM_TYPES) + ["string", "byte[]", "object"]))


def capture_spec(c: JdwpClient, thread: int, frame_id: int,
                 spec: list[dict], **kw) -> dict:
    """spec: [{"slot": 1, "type": "byte[]", "label": "input"}, ...]"""
    out = {}
    for item in spec:
        label = item.get("label", f"slot{item['slot']}")
        try:
            out[label] = capture_value(c, thread, frame_id, item["slot"],
                                       item["type"], **kw)
        except Exception as e:  # slot may be invalid for some overloads
            out[label] = {"error": str(e)[:120]}
    return out


def invoke_meta(c: JdwpClient, thread: int, obj: int,
                invokes: list[dict]) -> dict:
    """Run metadata invokes on `this` (e.g. Cipher.getAlgorithm) while the
    thread is suspended. Each: {"method": "getAlgorithm",
    "sig": "()Ljava/lang/String;", "label": "algorithm"}."""
    out = {}
    if not obj:
        return out
    try:
        _, type_id = c.object_reftype(obj)
        methods = c.rt_methods(type_id)
    except Exception:
        return out
    for inv in invokes:
        m = next((m for m in methods
                  if m["name"] == inv["method"] and m["sig"] == inv["sig"]),
                 None)
        if not m:
            out[inv["label"]] = {"error": "method not found"}
            continue
        try:
            r = c.invoke_object_method(obj, thread, type_id, m["id"], [])
            val = r["value"]
            if r["exception"]:
                out[inv["label"]] = {"error": "threw", "exc_id": r["exception"]}
            elif val["tag"] == TAG_STRING and val["v"]:
                out[inv["label"]] = c.string_value(val["v"])
            else:
                out[inv["label"]] = val["v"]
        except Exception as e:
            out[inv["label"]] = {"error": str(e)[:120]}
    return out


def _safe_sig(c: JdwpClient, obj: int) -> str | None:
    try:
        _, tid = c.object_reftype(obj)
        return c.rt_signature(tid)
    except Exception:
        return None


def _try_utf8(raw: bytes) -> str | None:
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if all(ch.isprintable() or ch in "\r\n\t" for ch in s) else None

"""AI-driven conditional breakpoints.

JDWP has a Conditional modifier (modKind 2) but it is unimplemented on ART —
expressions were never supported. So conditions are evaluated HOST-SIDE:

  breakpoint (suspend policy EVENT_THREAD) -> capture only the slots the
  predicate reads -> evaluate -> no match: resume thread and keep waiting;
  match: return the captured state and leave the thread suspended.

Predicate DSL (JSON):

  {"kind": "bytes", "label": "input",            # a captured byte[] node
   "len_in": [16, 24, 32],                        # AES key/IV sizes
   "hex_prefix": "2b7e", "hex_suffix": "...", "contains_hex": "...",
   "min_entropy": 3.5}                            # bits/byte, Shannon
  {"kind": "string", "label": "url", "regex": "https?://", "contains": "...",
   "equals": "..."}
  {"kind": "int", "label": "opmode", "eq": 1, "ne": 0, "lt": 3, "gt": 0,
   "between": [1, 2]}
  {"all": [pred, ...]} / {"any": [...]} / {"not": pred}

The capture spec declares what to fetch per hit:
  [{"slot": 1, "type": "byte[]", "label": "input"}, ...]
"""

from __future__ import annotations

import math
import re
import time

from ..device.jdwp import SP_EVENT_THREAD
from ..errors import SessionError
from .capture import capture_spec


def evaluate(pred: dict, captured: dict) -> bool:
    if "all" in pred:
        return all(evaluate(p, captured) for p in pred["all"])
    if "any" in pred:
        return any(evaluate(p, captured) for p in pred["any"])
    if "not" in pred:
        return not evaluate(pred["not"], captured)

    node = captured.get(pred.get("label"))
    if not isinstance(node, dict) or node.get("v") is None and "hex" not in node:
        return False
    kind = pred.get("kind")

    if kind == "bytes":
        raw_hex = node.get("hex")
        if raw_hex is None:
            return False
        if "len_in" in pred and node.get("len") not in pred["len_in"]:
            return False
        if pred.get("hex_prefix") and not raw_hex.startswith(pred["hex_prefix"]):
            return False
        if pred.get("hex_suffix") and not raw_hex.endswith(pred["hex_suffix"]):
            return False
        if pred.get("contains_hex") and pred["contains_hex"] not in raw_hex:
            return False
        if "min_entropy" in pred:
            if _entropy(bytes.fromhex(raw_hex)) < pred["min_entropy"]:
                return False
        return True

    if kind == "string":
        s = node.get("v")
        if s is None:
            return False
        if pred.get("regex") and not re.search(pred["regex"], s):
            return False
        if pred.get("contains") and pred["contains"] not in s:
            return False
        if pred.get("equals") is not None and s != pred["equals"]:
            return False
        return True

    if kind == "int":
        v = node.get("v")
        if not isinstance(v, int):
            return False
        if "eq" in pred and v != pred["eq"]:
            return False
        if "ne" in pred and v == pred["ne"]:
            return False
        if "lt" in pred and not v < pred["lt"]:
            return False
        if "gt" in pred and not v > pred["gt"]:
            return False
        if "between" in pred and not pred["between"][0] <= v <= pred["between"][1]:
            return False
        return True

    raise SessionError(f"unknown predicate kind {kind!r}",
                       hint="bytes | string | int | all | any | not")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((f / n) * math.log2(f / n) for f in freq if f)


class ConditionalEngine:
    """Runs a capture-evaluate-resume loop until the predicate matches."""

    def __init__(self, session):
        self.session = session

    def run(self, spec: str, predicate: dict, capture: list[dict], *,
            max_events: int = 2000, timeout_s: float = 120.0) -> dict:
        bp = self.session.set_breakpoint(spec, suspend_all=False)
        rids = [b["request_id"] for b in bp["breakpoints"]]
        rid_set = set(rids)
        deadline = time.time() + timeout_s
        checked = 0
        try:
            while checked < max_events and time.time() < deadline:
                ev = self.session.wait_events(
                    timeout=max(1.0, deadline - time.time()))
                for e in ev["events"]:
                    if e["request_id"] not in rid_set or "thread" not in e:
                        continue
                    checked += 1
                    thread = e["thread"]
                    c = self.session.client
                    fr = c.thread_frames(thread, 1)[0]
                    captured = capture_spec(c, thread, fr["frame_id"], capture)
                    if evaluate(predicate, captured):
                        return {"matched": True, "checked": checked,
                                "at": {k: e["breakpoint"].get(k) for k in
                                       ("spec", "java_line", "method")}
                                       if e.get("breakpoint") else None,
                                "captured": captured, "thread": thread,
                                "note": "thread left suspended for inspection"}
                    self.session.resume(thread=thread)
            return {"matched": False, "checked": checked,
                    "reason": "budget" if checked >= max_events else "timeout"}
        finally:
            for rid in rids:
                try:
                    self.session.delete_breakpoint(rid)
                except Exception:
                    pass

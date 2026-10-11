"""State snapshot engine — recursive object-graph dump over JDWP.

Context-window discipline: hard budgets on depth, fields, array items,
string length, and total nodes. Cycles collapse to {"$ref": id}. Output is
minified JSON with short keys.

Node shapes:
  primitive        ->  plain value (5, true, "x" is a String object though)
  string           ->  {"s": "...", "trunc": true?}
  byte[]           ->  {"bytes": "<hex>", "len": n, "trunc": true?}
  other array      ->  {"arr": [...], "len": n, "trunc": true?}
  object           ->  {"cls": "Lcom/x/Foo;", "id": 123, "f": {"name": node}}
  cycle            ->  {"$ref": 123}
"""

from __future__ import annotations

from ..device.jdwp import (
    JdwpClient, TAG_ARRAY, TAG_CLASS_OBJECT, TAG_OBJECT, TAG_STRING,
    sig_to_tag,
)


class Budgets:
    def __init__(self, max_depth=3, max_fields=12, max_items=8,
                 max_str=120, max_bytes=64, max_nodes=300):
        self.max_depth, self.max_fields = max_depth, max_fields
        self.max_items, self.max_str = max_items, max_str
        self.max_bytes, self.max_nodes = max_bytes, max_nodes


class Snapshotter:
    def __init__(self, client: JdwpClient, budgets: Budgets | None = None):
        self.c = client
        self.b = budgets or Budgets()
        self._nodes = 0
        self._seen: set[int] = set()

    # ------------------------------------------------------------------ entry
    def snapshot_frame(self, thread: int, frame_idx: int = 0) -> dict:
        """All locals + `this` of a frame, expanded per budgets."""
        fr = self.c.thread_frames(thread, frame_idx + 1)[frame_idx]
        loc = fr["location"]
        out = {"frame": frame_idx, "class": self.c.rt_signature(loc["class"]),
               "locals": {}}
        try:
            this = self.c.frame_this_object(thread, fr["frame_id"])
            if this["v"]:
                out["this"] = self._node(this["tag"], this["v"], 0)
        except Exception:
            pass
        try:
            vt = self.c.method_var_table(loc["class"], loc["method"])
            cur = loc["index"]
            slots = [(s["slot"], sig_to_tag(s["sig"]), s["name"])
                     for s in vt["slots"]
                     if s["code_index"] <= cur < s["code_index"] + s["length"]]
        except Exception:
            slots = []  # ProGuard-stripped: caller can read by raw slot
        if slots:
            try:
                vals = self.c.frame_get_values(
                    thread, fr["frame_id"], [(s, t) for s, t, _ in slots])
                for (slot, tag, name), v in zip(slots, vals):
                    out["locals"][name or f"slot{slot}"] = self._node(
                        v["tag"], v["v"], 0)
            except Exception as e:
                out["locals_error"] = str(e)[:120]
        return out

    def dump_object(self, obj: int, depth: int = 0) -> dict:
        return self._node(TAG_OBJECT, obj, depth)

    # ----------------------------------------------------------------- engine
    def _node(self, tag: int, v, depth: int):
        self._nodes += 1
        if self._nodes > self.b.max_nodes:
            return {"...": "node budget exhausted"}

        if v is None or (tag in (TAG_OBJECT, TAG_ARRAY, TAG_STRING) and not v):
            return None
        if tag == TAG_STRING:
            s = self.c.string_value(v, self.b.max_str + 1)
            node = {"s": s[:self.b.max_str]}
            if len(s) > self.b.max_str:
                node["trunc"] = True
            return node
        if tag == TAG_ARRAY:
            return self._array_node(v, depth)
        if tag in (TAG_OBJECT, TAG_CLASS_OBJECT):
            return self._object_node(v, depth)
        return v  # primitives

    def _array_node(self, oid: int, depth: int) -> dict:
        if oid in self._seen:
            return {"$ref": oid}
        self._seen.add(oid)
        n = self.c.array_length(oid)
        if n == 0:
            return {"arr": [], "len": 0}
        probe = self.c.array_get_values(oid, 0, min(n, self.b.max_items))
        tag = probe["component_tag"]
        if tag == 66:  # byte[]: compact hex instead of per-element nodes
            raw = bytes(x & 0xFF for x in
                        self.c.array_get_values(
                            oid, 0, min(n, self.b.max_bytes))["items"])
            node = {"bytes": raw.hex(), "len": n}
            if n > self.b.max_bytes:
                node["trunc"] = True
            return node
        node = {"arr": [], "len": n}
        for item in probe["items"]:
            if isinstance(item, dict):
                node["arr"].append(self._node(item["tag"], item["v"],
                                              depth + 1))
            else:
                node["arr"].append(item)
        if n > self.b.max_items:
            node["trunc"] = True
        return node

    def _object_node(self, oid: int, depth: int) -> dict:
        if oid in self._seen:
            return {"$ref": oid}
        self._seen.add(oid)
        try:
            _, type_id = self.c.object_reftype(oid)
            node = {"cls": self.c.rt_signature(type_id), "id": oid}
        except Exception as e:
            return {"id": oid, "error": str(e)[:80]}
        if depth >= self.b.max_depth:
            node["..."] = "depth limit"
            return node
        try:
            fields = self.c.rt_fields(type_id)[: self.b.max_fields]
            inst = [f for f in fields if not f["mod_bits"] & 0x8]
            stat = [f for f in fields if f["mod_bits"] & 0x8]
            if inst:
                vals = self.c.object_get_values(oid, [f["id"] for f in inst])
                node["f"] = {f["name"]: self._node(v["tag"], v["v"], depth + 1)
                             for f, v in zip(inst, vals)}
            if stat:
                vals = self.c.rt_get_values(type_id, [f["id"] for f in stat])
                node["s"] = {f["name"]: self._node(v["tag"], v["v"], depth + 1)
                             for f, v in zip(stat, vals)}
        except Exception as e:
            node["fields_error"] = str(e)[:80]
        return node

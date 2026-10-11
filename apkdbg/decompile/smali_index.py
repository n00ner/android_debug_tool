"""Smali indexer.

Parses apktool smali into a structural model used for:
  - line mapping:  `.line N` directives -> DEX LineNumberTable lines
  - branch sites:  if-* / goto / switch with resolved label targets
  - resource refs: `const vX, 0x7f......` followed by a Resources getter invoke

This is a line-oriented parser, not a full smali grammar — tolerant by design
(apktool output is regular and machine-generated).
"""

from __future__ import annotations

import re
from pathlib import Path

RE_CLASS = re.compile(r"^\.class\s+(?:\S+\s+)*?(L[^;\s]+;)\s*$")
RE_SOURCE = re.compile(r'^\.source\s+"([^"]+)"')
RE_METHOD = re.compile(r"^\.method\s+(.+?)\s+(\S+?\(.*\)\S+)\s*$")
RE_LINE = re.compile(r"^\.line\s+(\d+)")
RE_LABEL = re.compile(r"^:(\w+)")
RE_INSN = re.compile(r"^([a-z][a-z0-9\-/]*)\b\s*(.*)")
RE_CONST_RES = re.compile(
    r"^(const(?:/\w+)?)\s+([vp]\d+),\s*(0x7f[0-9a-fA-F]{6})\b")
RE_INVOKE = re.compile(
    r"^invoke-\S+\s+\{([^}]*)\},\s*\S+?;->(\w+)\(")

BRANCH_OPS = {"if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le",
              "if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"}
GOTO_OPS = {"goto", "goto/16", "goto/32"}
SWITCH_OPS = {"packed-switch", "sparse-switch"}

RESOURCE_GETTERS = {
    "getString", "getText", "getQuantityString", "getDrawable", "getColor",
    "getDimension", "getDimensionPixelSize", "getDimensionPixelOffset",
    "getInteger", "getBoolean", "getLayout", "getAnimation", "getXml",
    "openRawResource", "obtainTypedArray", "getStringArray", "getIntArray",
    "getIdentifier", "inflate",
}
# how many instructions after a const we look for a consuming invoke
RES_LOOKAHEAD = 8


def parse_smali_file(path: str | Path) -> dict:
    """Returns {sig, source_file, methods:[...]} — insns carry both the smali
    file line (fl) and the dalvik line (dl, from the enclosing .line block)."""
    text = Path(path).read_text("utf-8", errors="replace")
    cls = {"sig": None, "source_file": None, "methods": []}
    cur = None            # current method dict
    cur_dl = None         # current dalvik line (.line N)
    pending_label = None  # label awaiting its first insn

    for ln, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if cur is None:
            m = RE_CLASS.match(line)
            if m:
                cls["sig"] = m.group(1)
                continue
            m = RE_SOURCE.match(line)
            if m:
                cls["source_file"] = m.group(1)
                continue
            m = RE_METHOD.match(line)
            if m:
                flags, name_sig = m.group(1), m.group(2)
                name = name_sig[:name_sig.index("(")]
                sig = name_sig[name_sig.index("("):]
                cur = {"name": name, "sig": sig, "flags": flags,
                       "is_native": "native" in flags.split(),
                       "line_start": ln, "line_end": None,
                       "insns": [], "labels": {}, "branches": [],
                       "res_consts": []}
                cur_dl = None
            continue

        # inside a method
        if line.startswith(".end method"):
            cur["line_end"] = ln
            cls["methods"].append(cur)
            cur = None
            continue
        m = RE_LINE.match(line)
        if m:
            cur_dl = int(m.group(1))
            continue
        m = RE_LABEL.match(line)
        if m:
            pending_label = m.group(1)
            continue
        if line.startswith("."):
            continue  # .locals/.registers/.param/.local/.prologue/...

        m = RE_INSN.match(line)
        if not m:
            continue
        op, operands = m.group(1), m.group(2)
        insn = {"fl": ln, "dl": cur_dl, "op": op, "ops": operands}
        cur["insns"].append(insn)
        if pending_label is not None:
            cur["labels"][pending_label] = {"fl": ln, "dl": cur_dl}
            pending_label = None

        if op in BRANCH_OPS or op in GOTO_OPS:
            target = operands.rsplit(None, 1)[-1] if operands else ""
            cur["branches"].append({
                "fl": ln, "dl": cur_dl, "op": op,
                "kind": "if" if op in BRANCH_OPS else "goto",
                "label": target.lstrip(":")})
        elif op in SWITCH_OPS:
            cur["branches"].append({"fl": ln, "dl": cur_dl, "op": op,
                                    "kind": "switch", "label": None})
        else:
            mc = RE_CONST_RES.match(line)
            if mc:
                cur["res_consts"].append({
                    "fl": ln, "dl": cur_dl, "reg": mc.group(2),
                    "res_id": int(mc.group(3), 16)})

    # second pass: resolve branch labels and classify resource consts
    for meth in cls["methods"]:
        labels = meth["labels"]
        insns = meth["insns"]
        for br in meth["branches"]:
            lbl = br.pop("label", None)
            tgt = labels.get(lbl) if lbl else None
            br["target_fl"] = tgt["fl"] if tgt else None
            br["target_dl"] = tgt["dl"] if tgt else None
        for rc in meth["res_consts"]:
            rc["kind"] = _classify_res_use(insns, rc)
    return cls


def _classify_res_use(insns: list[dict], rc: dict) -> str:
    """Look ahead from the const for an invoke that consumes its register and
    names a known Resources getter."""
    reg = rc["reg"]
    start = next((i for i, x in enumerate(insns) if x["fl"] == rc["fl"]), None)
    if start is None:
        return "const_load"
    for insn in insns[start + 1:start + 1 + RES_LOOKAHEAD]:
        m = RE_INVOKE.match(f'{insn["op"]} {insn["ops"]}')
        if m and reg in [r.strip() for r in m.group(1).split(",")]:
            name = m.group(2)
            return name if name in RESOURCE_GETTERS else "const_load"
    return "const_load"


def iter_smali_files(apktool_dir: str | Path):
    """Yields (smali_root_name, path) across smali/, smali_classes2/, ..."""
    root = Path(apktool_dir)
    for sub in sorted(root.iterdir()):
        if sub.is_dir() and (sub.name == "smali"
                             or sub.name.startswith("smali_classes")):
            yield from ((sub.name, p) for p in sorted(sub.rglob("*.smali")))

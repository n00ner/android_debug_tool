"""Parsers for external mapping artifacts:

  - apktool res/values/public.xml  -> resources table (0x7f...... -> type/name)
  - jadx mapping json              -> deobfuscated class names + java<->dalvik
                                      line tables, when jadx emits them

jadx mapping formats vary by version, so the loader normalizes several shapes:
  1. {"classes": [{"oldName": "a.b.c", "newName": "com.x.Foo",
                   "lines": [{"java": 12, "smali": 3456}],
                   "methods": [{"oldName": "a", "newName": "run"}]}]}
  2. flat {"a.b.c": "com.x.Foo"}
"""

from __future__ import annotations

import json
import re
from pathlib import Path

RE_PUBLIC = re.compile(
    r'<public\s+type="([^"]+)"\s+name="([^"]+)"\s+id="(0x[0-9a-fA-F]+)"')


def parse_public_xml(public_xml: str | Path) -> list[dict]:
    p = Path(public_xml)
    if not p.exists():
        return []
    out = []
    for m in RE_PUBLIC.finditer(p.read_text("utf-8", errors="replace")):
        out.append({"type": m.group(1), "name": m.group(2),
                    "res_id": int(m.group(3), 16)})
    return out


def parse_manifest_package(manifest: str | Path) -> str | None:
    p = Path(manifest)
    if not p.exists():
        return None
    m = re.search(r'package="([^"]+)"', p.read_text("utf-8", errors="replace"))
    return m.group(1) if m else None


def load_jadx_mapping(path: str | Path | None) -> dict:
    """Returns {"names": {obf_fqcn: deobf_fqcn},
                 "methods": {obf_fqcn: {obf_m: new_m}},
                 "lines": {obf_fqcn: {java_line: dalvik_line}}}"""
    empty = {"names": {}, "methods": {}, "lines": {}}
    if not path or not Path(path).exists():
        return empty
    try:
        data = json.loads(Path(path).read_text("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return empty

    if isinstance(data, dict) and "classes" not in data:
        # flat shape
        for k, v in data.items():
            if isinstance(v, str):
                empty["names"][k] = v
        return empty

    for c in data.get("classes", []):
        old = c.get("oldName") or c.get("source") or c.get("name")
        new = c.get("newName") or c.get("target")
        if not old:
            continue
        if new and new != old:
            empty["names"][old] = new
        for mm in c.get("methods", []):
            mo, mn = mm.get("oldName"), mm.get("newName")
            if mo and mn and mo != mn:
                empty["methods"].setdefault(old, {})[mo] = mn
        for lm in c.get("lines", []):
            jl = lm.get("java") or lm.get("javaLine")
            dl = lm.get("smali") or lm.get("smaliLine") or lm.get("dalvik")
            if jl is not None and dl is not None:
                empty["lines"].setdefault(old, {})[int(jl)] = int(dl)
    return empty

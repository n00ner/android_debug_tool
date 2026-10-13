"""Java-level spec -> runtime breakpoint location resolution ("Perfect Sync").

Spec forms:
  "com.foo.Bar:42"              class + java line
  "com.foo.Bar.run:42"          class + method + java line
  "Lcom/foo/Bar;:42"            raw descriptor also accepted

Resolution order for the line number:
  1. jadx_lines table (jadx java line -> dalvik line), when a mapping json
     was found during init
  2. identity: java line == dalvik line == `.line N` (true for debuggable,
     non-recompiled APKs — the DEX LineNumberTable is the shared pivot)

The final java->bytecode-index step happens at runtime via JDWP
Method.LineTable (session.set_breakpoint), never from static data alone.
"""

from __future__ import annotations

import re

from ..core.aliases import accepted_alias
from ..core.database import MappingDB
from ..errors import ResolveError

RE_SPEC = re.compile(r"^(?P<head>.+?):(?P<line>\d+)$")


def parse_spec(spec: str) -> tuple[str, str | None, int]:
    m = RE_SPEC.match(spec.strip())
    if not m:
        raise ResolveError(f"invalid breakpoint spec: {spec!r}",
                           hint="use 'com.foo.Class.method:line' or "
                                "'com.foo.Class:line'")
    head, line = m.group("head"), int(m.group("line"))
    if head.endswith(":"):
        head = head[:-1]
    # split method: last dot segment — validated against the DB by the caller
    cls, _, method = head.rpartition(".")
    if not cls or head.startswith("L"):      # raw descriptor, no method
        return head, None, line
    return cls, method, line


def resolve(db: MappingDB, spec: str) -> dict:
    cls_part, method, line = parse_spec(spec)

    # find the class: exact fqcn, deobfuscated name, or raw descriptor
    row = db.one("SELECT * FROM classes WHERE fqcn=? OR deobf_fqcn=? OR sig=?",
                 (cls_part, cls_part, cls_part))
    if row is None and method is not None:
        # maybe the 'method' segment is actually part of the class name
        row = db.one(
            "SELECT * FROM classes WHERE fqcn=? OR deobf_fqcn=? OR sig=?",
            (f"{cls_part}.{method}",) * 3)
        if row:
            method = None
    if row is None:
        near = db.query("SELECT fqcn, deobf_fqcn FROM classes WHERE fqcn LIKE "
                        "? OR deobf_fqcn LIKE ? LIMIT 5",
                        (f"%{cls_part.split('.')[-1]}%",) * 2)
        raise ResolveError(f"class not found in mapping db: {cls_part}",
                           hint="did you mean one of: "
                                + ", ".join(sorted({r["fqcn"] for r in near}
                                                   | {r["deobf_fqcn"] for r in near
                                                      if r["deobf_fqcn"]})) or None)
    class_id, sig = row["id"], row["sig"]

    # java line -> dalvik line (jadx mapping when present, else identity)
    jl = db.one("SELECT dalvik_line FROM jadx_lines WHERE class_id=? AND "
                "java_line=?", (class_id, line))
    dalvik_line = jl["dalvik_line"] if jl else line

    # candidate methods
    if method:
        methods = db.query(
            "SELECT * FROM methods WHERE class_id=? AND name=?", (class_id, method))
        if not methods:
            raise ResolveError(
                f"method {method} not found in {cls_part}",
                hint="available: " + ", ".join(
                    r["name"] for r in db.query(
                        "SELECT DISTINCT name FROM methods WHERE class_id=? "
                        "LIMIT 20", (class_id,))))
    else:
        methods = db.query(
            "SELECT DISTINCT m.* FROM methods m JOIN line_map lm ON "
            "lm.method_id=m.id WHERE m.class_id=? AND lm.dalvik_line=?",
            (class_id, dalvik_line))
        if not methods:
            # fall back: methods whose smali span brackets a matching .line
            methods = db.query(
                "SELECT * FROM methods WHERE class_id=? AND id IN (SELECT "
                "method_id FROM line_map WHERE dalvik_line BETWEEN ? AND ?)",
                (class_id, dalvik_line - 3, dalvik_line + 3))
    if not methods:
        raise ResolveError(
            f"no method contains dalvik line {dalvik_line} in {row['fqcn']}",
            hint="check that the line holds executable code (not a "
                 "declaration/comment)")

    smali = db.one(
        "SELECT lm.smali_line, lm.method_id FROM line_map lm JOIN methods m "
        "ON m.id=lm.method_id WHERE m.class_id=? AND lm.dalvik_line=? "
        "ORDER BY lm.smali_line LIMIT 1", (class_id, dalvik_line))

    return {
        "class": row["fqcn"], "deobf": row["deobf_fqcn"], "sig": sig,
        # accepted runtime alias (issue #25): a distinct, review-only
        # annotation next to sig/deobf — never an input to resolution,
        # method matching, or breakpoint targeting
        "alias": accepted_alias(db, sig),
        "java_line": line, "dalvik_line": dalvik_line,
        "smali": {"path": row["smali_path"],
                  "line": smali["smali_line"] if smali else None},
        "methods": [{"name": m["name"], "sig": m["sig"],
                     "is_native": bool(m["is_native"])}
                    for m in methods],
    }

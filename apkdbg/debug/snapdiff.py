"""Structural snapshot diff across runs (issue #36).

Snapshots are compared as LOGICAL object graphs: structural paths plus
type-aware values. Raw runtime object ids ("id"/"$ref" node values) are
per-connection and never compared across runs — cycles are re-anchored to
the structural path of the target's first occurrence within the same
snapshot, so two equal logical snapshots captured under different runtime
ids produce no spurious changes.

Results are reported in four disjoint buckets:
  changed  — same path, both observed, different type-aware value
  added    — path observed only in B, with B's ancestors fully observed
  removed  — path observed only in A, with A's ancestors fully observed
  unknown  — comparison impossible: budget-truncated, inaccessible
             (capture error), or absent-debug-info data on either side.
             Truncated/error/depth-limited subtrees never masquerade as
             added or removed values.

Before comparing, check_compatible() lists provenance differences between
the two captures (APK identity, scope, capture settings, completeness).
Incompatible captures return explicit reasons and no diff, unless forced —
forced diffs keep every qualification in the output.
"""

from __future__ import annotations

# severities
INCOMPATIBLE = "incompatible"
WARNING = "warning"
INFO = "info"


# --------------------------------------------------------------- flattening
def flatten_snapshot(data) -> dict:
    """Flatten a snapshot (frame snapshot or object-graph node) to
    {path tuple: marker}. Markers:
      {"t": "value",  "v": ...}                    primitive / null
      {"t": "str",    "v": ..., "trunc": bool}     string (observed prefix)
      {"t": "bytes",  "v": hex, "len": n, "trunc": bool}
      {"t": "array",  "len": n, "observed": n, "trunc": bool}
      {"t": "object", "cls": ..., "incomplete": reason?}
      {"t": "ref",    "path": (..)}                cycle, re-anchored
      {"t": "unknown", "reason": ...}              unobserved
    """
    out: dict[tuple, dict] = {}
    refs: dict[int, tuple] = {}  # runtime id -> first structural path

    def walk(node, path: tuple) -> None:
        if node is None or isinstance(node, (bool, int, float, str)):
            out[path] = {"t": "value", "v": node}
            return
        if isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, path + (f"[{i}]",))
            return
        if not isinstance(node, dict):
            out[path] = {"t": "unknown", "reason": "unrecognized node"}
            return
        if "$ref" in node:
            target = refs.get(node["$ref"])
            if target is not None:
                out[path] = {"t": "ref", "path": target}
            else:
                out[path] = {"t": "unknown",
                             "reason": "unresolved cycle reference"}
            return
        if "..." in node and len(node) == 1:
            out[path] = {"t": "unknown", "reason": str(node["..."])}
            return
        if "s" in node and isinstance(node["s"], str):  # string node
            out[path] = {"t": "str", "v": node["s"],
                         "trunc": bool(node.get("trunc"))}
            return
        if "bytes" in node:
            out[path] = {"t": "bytes", "v": node["bytes"],
                         "len": node.get("len"),
                         "trunc": bool(node.get("trunc"))}
            return
        if "arr" in node:
            items = node["arr"] if isinstance(node["arr"], list) else []
            out[path] = {"t": "array", "len": node.get("len"),
                         "observed": len(items),
                         "trunc": bool(node.get("trunc"))}
            for i, item in enumerate(items):
                walk(item, path + (f"[{i}]",))
            return
        if "error" in node and "cls" not in node:  # inaccessible object
            out[path] = {"t": "unknown",
                         "reason": f"inaccessible: {str(node['error'])[:80]}"}
            return
        if "cls" in node:  # object node; runtime id is never identity
            marker = {"t": "object", "cls": node["cls"]}
            out[path] = marker
            if isinstance(node.get("id"), int):
                refs.setdefault(node["id"], path)
            if "..." in node:  # depth/node budget: children unobserved
                marker["incomplete"] = str(node["..."])
                return
            for name, val in (node.get("f") or {}).items():
                walk(val, path + ("f", name))
            for name, val in (node.get("s") or {}).items():
                walk(val, path + ("s", name))
            if node.get("fields_error"):
                out[path + ("f",)] = {
                    "t": "unknown",
                    "reason": f"fields_error: "
                              f"{str(node['fields_error'])[:80]}"}
            return
        out[path] = {"t": "unknown", "reason": "unrecognized node shape"}

    if isinstance(data, dict) and "locals" in data:  # frame snapshot
        out[("class",)] = {"t": "value", "v": data.get("class")}
        if "this" in data:
            walk(data["this"], ("this",))
        if data.get("locals_error"):
            out[("locals",)] = {"t": "unknown",
                                "reason": f"locals_error: "
                                          f"{str(data['locals_error'])[:80]}"}
        for name, node in (data.get("locals") or {}).items():
            walk(node, ("locals", name))
    else:
        walk(data, ())
    return out


def _pstr(path: tuple) -> str:
    return ".".join(path) if path else "$"


def _covers(marker: dict) -> bool:
    """True when the marker means 'this subtree went unobserved'."""
    if marker["t"] == "unknown" or marker.get("incomplete"):
        return True
    return (marker["t"] == "array" and marker.get("trunc")
            and (marker.get("len") or 0) > marker.get("observed", 0))


def _covering(flat: dict, path: tuple) -> dict | None:
    for i in range(len(path), -1, -1):
        m = flat.get(path[:i])
        if m is not None and _covers(m):
            return m
    return None


def _repr(marker: dict) -> dict:
    out = {k: v for k, v in marker.items() if k != "t"}
    out["type"] = marker["t"]
    if marker["t"] == "ref" and marker.get("path") is not None:
        out["path"] = _pstr(marker["path"])
    return out


# --------------------------------------------------------------- comparison
def diff_nodes(fa: dict, fb: dict) -> dict:
    changed: dict = {}
    added: dict = {}
    removed: dict = {}
    unknown: list = []

    def note_unknown(path, side, reason):
        unknown.append({"path": _pstr(path), "side": side,
                        "reason": reason})

    def compare(ma: dict, mb: dict, path: tuple) -> None:
        if ma["t"] == "unknown" or mb["t"] == "unknown":
            if ma["t"] != mb["t"] or ma.get("reason") != mb.get("reason"):
                side = "a" if ma["t"] == "unknown" else "b"
                note_unknown(path, side,
                             ma.get("reason") if side == "a"
                             else mb.get("reason"))
            return
        if ma["t"] != mb["t"]:
            changed[_pstr(path)] = {"a": _repr(ma), "b": _repr(mb),
                                    "type_change": True}
            return
        t = ma["t"]
        if t in ("value", "ref"):
            if t == "value" and ma["v"] != mb["v"] or \
                    t == "ref" and ma.get("path") != mb.get("path"):
                changed[_pstr(path)] = {"a": _repr(ma), "b": _repr(mb)}
        elif t == "object":
            if ma["cls"] != mb["cls"]:
                changed[_pstr(path)] = {"a": _repr(ma), "b": _repr(mb),
                                        "type_change": True}
            if ma.get("incomplete") or mb.get("incomplete"):
                side = "a" if ma.get("incomplete") else "b"
                note_unknown(path, side,
                             ma.get("incomplete") if side == "a"
                             else mb.get("incomplete"))
        elif t in ("str", "bytes"):
            if ma["v"] != mb["v"]:
                entry = {"a": _repr(ma), "b": _repr(mb)}
                if ma.get("trunc") or mb.get("trunc"):
                    entry["truncated"] = True  # observed prefixes differ
                changed[_pstr(path)] = entry
            elif t == "bytes" and ma.get("len") != mb.get("len"):
                changed[_pstr(path)] = {"a": _repr(ma), "b": _repr(mb),
                                        "truncated": True}
        elif t == "array":
            if ma.get("len") != mb.get("len"):
                entry = {"a": _repr(ma), "b": _repr(mb)}
                if ma.get("trunc") or mb.get("trunc"):
                    entry["truncated"] = True
                changed[_pstr(path)] = entry

    for path in sorted(fa):
        ma, mb = fa[path], fb.get(path)
        if mb is None:
            cov = _covering(fb, path)
            if cov is not None:
                note_unknown(path, "b",
                             cov.get("reason") or cov.get("incomplete")
                             or "array truncated at capture")
            else:
                removed[_pstr(path)] = _repr(ma)
        else:
            compare(ma, mb, path)
    for path in sorted(fb):
        if path not in fa:
            cov = _covering(fa, path)
            if cov is not None:
                note_unknown(path, "a",
                             cov.get("reason") or cov.get("incomplete")
                             or "array truncated at capture")
            else:
                added[_pstr(path)] = _repr(fb[path])
    return {"changed": changed, "added": added,
            "removed": removed, "unknown": unknown}


# ------------------------------------------------------- compatibility check
def check_compatible(run_a: dict, art_a: dict,
                     run_b: dict, art_b: dict) -> dict:
    """List provenance differences between two captures. `compatible` is
    False when the captures cannot meaningfully be compared (different APK
    identity or scope); `complete` is False when either capture is known to
    be partial (error/truncated). Warnings never block a diff but must stay
    visible in its output."""
    diffs: list = []

    def diff(field, a, b, severity, reason):
        diffs.append({"field": field, "a": a, "b": b,
                      "severity": severity, "reason": reason})

    if run_a.get("apk_sha256") != run_b.get("apk_sha256"):
        diff("apk_sha256", run_a.get("apk_sha256"), run_b.get("apk_sha256"),
             INCOMPATIBLE, "different APK identity")
    cfg_a = _cfg(run_a)
    cfg_b = _cfg(run_b)
    if cfg_a.get("scope") != cfg_b.get("scope"):
        diff("scope", cfg_a.get("scope"), cfg_b.get("scope"),
             INCOMPATIBLE, "different capture scope")
    if run_a.get("index_generation") != run_b.get("index_generation"):
        diff("index_generation", run_a.get("index_generation"),
             run_b.get("index_generation"), WARNING,
             "captured against different static-index generations")
    if run_a.get("tool_version") != run_b.get("tool_version"):
        diff("tool_version", run_a.get("tool_version"),
             run_b.get("tool_version"), INFO, "different tool versions")
    if run_a.get("epoch") != run_b.get("epoch"):
        diff("epoch", run_a.get("epoch"), run_b.get("epoch"), INFO,
             "captured in different connection epochs; runtime ids are "
             "never compared across epochs")
    budgets_a = _budgets(art_a)
    budgets_b = _budgets(art_b)
    if budgets_a != budgets_b:
        diff("capture_budgets", budgets_a, budgets_b, WARNING,
             "different capture budgets affect completeness")
    env_a = _env(run_a)
    env_b = _env(run_b)
    for k in sorted(set(env_a) | set(env_b)):
        if env_a.get(k) != env_b.get(k):
            diff(f"environment.{k}", env_a.get(k), env_b.get(k), WARNING,
                 "different capture environment")

    complete = True
    for side, run, art in (("a", run_a, art_a), ("b", run_b, art_b)):
        reason = run.get("completion_reason")
        if reason not in (None, "completed", "duration", "budget",
                          "max_events"):
            diff("completeness", side, reason, WARNING,
                 f"run {side} ended abnormally: {reason}")
            complete = False
        trunc = _trunc(art)
        if trunc and not trunc.get("complete", True):
            diff("completeness", side, trunc, WARNING,
                 f"snapshot {side} is partially observed "
                 f"(truncated/budget-limited/errors)")
            complete = False
    return {"compatible": not any(d["severity"] == INCOMPATIBLE
                                  for d in diffs),
            "complete": complete, "differences": diffs}


def _cfg(run: dict) -> dict:
    cfg = run.get("capture_config")
    return cfg if isinstance(cfg, dict) else {}


def _env(run: dict) -> dict:
    env = run.get("environment")
    return env if isinstance(env, dict) else {}


def _budgets(art: dict) -> dict:
    b = art.get("budgets")
    return b if isinstance(b, dict) else {}


def _trunc(art: dict) -> dict:
    t = art.get("truncation")
    return t if isinstance(t, dict) else {}


# ------------------------------------------------------------ orchestration
def snapshot_diff(store, ref_a: str, ref_b: str, *,
                  force: bool = False) -> dict:
    """Diff two persisted snapshot artifacts (refs: artifact ids, or run
    ids with exactly one snapshot artifact). Runs the compatibility check
    first: incompatible captures return explicit reasons and no diff unless
    forced; forced diffs retain every qualification."""
    run_a, art_a = store.resolve_snapshot_artifact(ref_a)
    run_b, art_b = store.resolve_snapshot_artifact(ref_b)
    run_a, art_a = _parse(run_a), _parse(art_a)
    run_b, art_b = _parse(run_b), _parse(art_b)
    compat = check_compatible(run_a, art_a, run_b, art_b)
    out = {"a": _summary(art_a), "b": _summary(art_b),
           "forced": force, **compat}
    if not compat["compatible"] and not force:
        out["reason"] = ("incompatible captures — differences above; "
                         "re-run with force to compare anyway")
        out.update({"changed": None, "added": None,
                    "removed": None, "unknown": None})
        return out
    fa = flatten_snapshot(art_a.get("body"))
    fb = flatten_snapshot(art_b.get("body"))
    out.update(diff_nodes(fa, fb))
    return out


def _parse(row: dict) -> dict:
    from ..core.manifests import _loads
    out = dict(row)
    for k in ("capture_config", "environment", "counts", "budgets",
              "truncation"):
        if isinstance(out.get(k), str):
            out[k] = _loads(out[k], {})
    if isinstance(out.get("errors"), str):
        out["errors"] = _loads(out["errors"], [])
    if out.get("format") == "json" and isinstance(out.get("body"), str):
        out["body"] = _loads(out["body"], out["body"])
    return out


def _summary(art: dict) -> dict:
    return {"artifact_id": art["artifact_id"], "run_id": art["run_id"],
            "kind": art["kind"], "format": art["format"],
            "checksum": art.get("checksum")}

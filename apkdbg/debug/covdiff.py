"""Offline coverage diff across stored runs (issue #29).

Compares two groups of persisted coverage runs (selected by label: the
run's scenario or run_id) and ranks observed coverage differences for
investigation. Everything is computed from stored observations only — no
JDWP connection, no target — so output is deterministic for fixed stored
inputs.

What a difference means, and what it does not:

  - Coverage captures are bounded samples (time- or budget-boxed), never
    exhaustive traces. A difference between two samples is a *candidate*
    for investigation, not a proof: subtracting two traces does not
    identify the exact causal branch. Every ranked entry carries its
    supporting counts and an explainable score.
  - Absence in a bounded trace is not proof of non-execution; presence
    changes are annotated as such.
  - Unknown branch outcomes stay unknown: they are stored with their
    reasons and never resolved into taken/fall-through edges here.
  - Degraded runs (budget stops, dropped events, cancellations) lower the
    confidence of every candidate they touch and are listed in the
    quality block; the comparison is never presented as exact
    subtraction.

Compatibility: groups are compared only when their runs share APK
identity (sha256), static-index generation (site identity is
index-bound), capture mode (method vs line), and package scope. Anything
else is rejected by default with explicit reasons. The exploratory flag
produces an annotated intersection of the observed keys instead — it
never implies equivalent coverage.

Grouping: baseline vs candidate are label-selected run sets. A/A (same
label twice) measures baseline variation: the matched runs are split
deterministically in half and compared, so repeat noise is visible as
low/zero scores instead of surfaced as scenario differences.

Ranking (explainable score, descending):
  presence   — observed in one group, absent in the other (score scaled
               by within-group presence consistency)
  direction  — branch sites whose supported edge (taken vs fall-through,
               evidenced by identified edges) flips between groups
               (score scaled by edge purity vs unknown outcomes)
  hit_count  — normalized hit counts (hits per captured event) whose
               between-group difference exceeds the within-group spread
               of both groups (A/A noise guard)
"""

from __future__ import annotations

import json

from ..core.manifests import _loads
from ..errors import SessionError

# severities (same vocabulary as snapdiff)
INCOMPATIBLE = "incompatible"
WARNING = "warning"
INFO = "info"

# change-type base weights: presence > direction > hit_count
_W_PRESENCE = 1.0
_W_DIRECTION = 0.9
_W_HITCOUNT = 0.5
_CHANGE_ORDER = {"presence": 0, "direction": 1, "hit_count": 2}

ABSENCE_NOTE = ("absence in a bounded trace is not proof of "
                "non-execution")


# ------------------------------------------------------------ run selection
def _group_runs(db, label: str) -> list[dict]:
    rows = db.query(
        "SELECT * FROM runs WHERE kind='coverage' AND (scenario=? OR "
        "run_id=?) ORDER BY started_at, run_id", (label, label))
    if not rows:
        raise SessionError(
            f"no coverage runs match label {label!r}",
            hint="labels match a run's scenario or run_id; see `runs list`")
    return [_parse_run(r) for r in rows]


def _parse_run(row: dict) -> dict:
    out = dict(row)
    out["capture_config"] = _loads(out.get("capture_config"), {})
    out["environment"] = _loads(out.get("environment"), {})
    out["counts"] = _loads(out.get("counts"), {})
    return out


# ------------------------------------------------------------- observations
def _load_observations(db, run: dict) -> dict:
    """One run's stored observations, normalized to a common shape:
    {"mode", "lines": {mkey: {line: hits}}, "branches": {site_key: rec},
     "methods": {mkey: hits}}. Line-mode data comes from the persisted
    coverage_hits / coverage_branch_sites rows; runs captured before
    branch persistence (or method-mode runs, which flush no tables) fall
    back to the stored coverage_report artifact."""
    mode = run["capture_config"].get("mode", "method")
    obs = {"mode": mode, "lines": {}, "branches": {}, "methods": {}}
    if mode == "line":
        for r in db.query(
                "SELECT class_sig,method_name,method_sig,dalvik_line,hits"
                " FROM coverage_hits WHERE run_id=?", (run["run_id"],)):
            mkey = _mkey(r["class_sig"], r["method_name"],
                         r["method_sig"])
            obs["lines"].setdefault(mkey, {})[r["dalvik_line"]] = r["hits"]
        for r in db.query(
                "SELECT * FROM coverage_branch_sites WHERE run_id=?",
                (run["run_id"],)):
            obs["branches"][r["site_key"]] = {
                "site_hits": r["site_hits"], "taken": r["taken"],
                "fallthrough": r["fallthrough"],
                "unknown": _loads(r.get("unknowns"), {}),
                "kind": r["kind"], "line": r["dalvik_line"]}
    if obs["lines"] or obs["branches"]:
        return obs
    body = _report_body(db, run["run_id"])
    if not body:
        return obs
    if mode == "method":
        obs["methods"] = dict(body.get("methods") or {})
    else:
        obs["lines"] = {k: dict(v) for k, v in
                        (body.get("lines") or {}).items()}
        detail = ((body.get("branches") or {}).get("detail")) or {}
        obs["branches"] = {k: {"site_hits": r.get("site_hits", 0),
                               "taken": r.get("taken", 0),
                               "fallthrough": r.get("fallthrough", 0),
                               "unknown": dict(r.get("unknown") or {}),
                               "kind": r.get("kind"),
                               "line": r.get("line")}
                           for k, r in detail.items()}
    return obs


def _mkey(class_sig, method_name, method_sig) -> str:
    # legacy rows (pre-#37) carry method_sig NULL; keep them loadable
    base = f"{class_sig}->{method_name}"
    return f"{base}{method_sig}" if method_sig else base


def _report_body(db, run_id: str) -> dict | None:
    row = db.one(
        "SELECT body FROM artifacts WHERE run_id=? AND kind="
        "'coverage_report' ORDER BY rowid", (run_id,))
    if row is None:
        return None
    body = _loads(row["body"], None)
    return body if isinstance(body, dict) else None


# --------------------------------------------------------- compatibility
def check_compatible(runs_a: list[dict], runs_b: list[dict]) -> dict:
    """Provenance differences across the two groups. Incompatible when
    the runs cannot mean equivalent coverage: different APK identity,
    index generation, capture mode, or package scope."""
    diffs: list = []

    def diff(field, a, b, severity, reason):
        diffs.append({"field": field, "a": a, "b": b,
                      "severity": severity, "reason": reason})

    def values(fn):
        vs = {fn(r) for r in runs_a + runs_b}
        return vs

    def check(field, fn, severity, reason):
        vs = values(fn)
        if len(vs) > 1:
            diff(field, sorted(str(v) for v in vs), None, severity, reason)

    check("apk_sha256", lambda r: r.get("apk_sha256"), INCOMPATIBLE,
          "different APK identity")
    check("index_generation", lambda r: r.get("index_generation"),
          INCOMPATIBLE,
          "captured against different static-index generations; branch "
          "site identity is index-bound")
    check("mode", lambda r: r["capture_config"].get("mode", "method"),
          INCOMPATIBLE, "method-mode and line-mode captures are not "
                        "equivalent coverage")
    check("packages",
          lambda r: tuple(sorted(r["capture_config"].get("packages")
                                 or [])),
          INCOMPATIBLE, "different package scope")
    check("tool_version", lambda r: r.get("tool_version"), INFO,
          "different tool versions")
    for k in sorted({k for r in runs_a + runs_b
                     for k in r["environment"]}):
        check(f"environment.{k}", lambda r, k=k: r["environment"].get(k),
              WARNING, "different capture environment")
    return {"compatible": not any(d["severity"] == INCOMPATIBLE
                                  for d in diffs),
            "differences": diffs}


# ------------------------------------------------------------------ quality
def _run_quality(run: dict) -> dict:
    """Per-run quality: every coverage capture is a bounded sample; a
    run is *degraded* when its sample is known to be cut short (budget
    stop, dropped events, cancellation/failure)."""
    warnings: list = []
    counts = run["counts"]
    reason = run.get("completion_reason")
    dropped = counts.get("dropped_events") or 0
    if reason == "budget":
        warnings.append("budget stop: the sample hit its event budget "
                        "and is more heavily truncated than a "
                        "duration-bounded capture")
    elif reason not in (None, "duration", "completed"):
        warnings.append(f"run ended abnormally: {reason}")
    if dropped:
        warnings.append(f"{dropped} events were dropped during capture")
    return {"run_id": run["run_id"], "scenario": run.get("scenario"),
            "started_at": run.get("started_at"),
            "events": counts.get("events"),
            "stop_reason": reason, "dropped_events": dropped,
            "degraded": bool(warnings), "warnings": warnings}


# ------------------------------------------------------------- aggregation
def _scale(run: dict, obs: dict) -> float:
    """Normalization denominator for hit counts: captured events when
    known, else the run's total observed hits (never zero)."""
    events = (run["counts"].get("events") or 0)
    if events > 0:
        return float(events)
    total = sum(h for lines in obs["lines"].values() for h in
                lines.values()) + sum(obs["methods"].values())
    return float(total) if total else 1.0


def _flatten(obs: dict) -> dict:
    """Comparable keys for one run:
    line mode   -> {"line:<mkey>:<line>": hits, "branch:<site_key>": rec}
    method mode -> {"method:<mkey>": hits}"""
    out: dict = {}
    for mkey, lines in obs["lines"].items():
        for line, hits in lines.items():
            out[f"line:{mkey}:{line}"] = hits
    for site_key, rec in obs["branches"].items():
        out[f"branch:{site_key}"] = rec
    for mkey, hits in obs["methods"].items():
        out[f"method:{mkey}"] = hits
    return out


def _group_view(runs: list[dict], observations: list[dict]) -> dict:
    """key -> {"runs": {run_id: observation}, "present": n, "total": n}
    across one group. Observation = hit count (line/method) or branch
    record."""
    keys: dict = {}
    total = len(runs)
    for run, obs in zip(runs, observations):
        scale = _scale(run, obs)
        for key, val in _flatten(obs).items():
            g = keys.setdefault(key, {"runs": {}, "present": 0,
                                      "total": total})
            if isinstance(val, dict):  # branch record
                unk = sum(val["unknown"].values())
                g["runs"][run["run_id"]] = {
                    "site_hits": val["site_hits"], "taken": val["taken"],
                    "fallthrough": val["fallthrough"],
                    "unknown": unk,
                    "unknown_reasons": dict(val["unknown"]),
                    "normalized": val["site_hits"] / scale}
            else:
                g["runs"][run["run_id"]] = {
                    "hits": val, "normalized": val / scale}
            g["present"] += 1
    return keys


# ---------------------------------------------------------------- ranking
def _rank_key(entry: dict):
    return (-entry["score"], _CHANGE_ORDER[entry["change"]], entry["key"])


def _presence_change(key, kind, ga, gb) -> dict | None:
    if ga["present"] and gb["present"]:
        return None
    side, present, absent = ("candidate", gb, ga) if gb["present"] \
        else ("baseline", ga, gb)
    consistency = present["present"] / present["total"]
    score = _W_PRESENCE * consistency
    entry = {"key": key, "kind": kind, "change": "presence",
             "present_in": side,
             "score": round(score, 6),
             "score_explanation": {
                 "base": _W_PRESENCE,
                 "presence_consistency": round(consistency, 6),
                 "detail": f"observed in {present['present']}/"
                           f"{present['total']} {side} run(s), absent "
                           f"from all {absent['total']} run(s) of the "
                           "other group"},
             "notes": [ABSENCE_NOTE]}
    return entry


def _branch_stats(g: dict) -> dict:
    taken = sum(r["taken"] for r in g["runs"].values())
    fall = sum(r["fallthrough"] for r in g["runs"].values())
    unk = sum(r["unknown"] for r in g["runs"].values())
    total = taken + fall + unk
    dominant = "taken" if taken >= fall else "fallthrough"
    purity = (max(taken, fall) / total) if total else 0.0
    return {"taken": taken, "fallthrough": fall, "unknown": unk,
            "dominant": dominant if (taken or fall) else None,
            "purity": purity}


def _direction_change(key, kind, ga, gb) -> dict | None:
    if not (ga["present"] and gb["present"]):
        return None
    sa, sb = _branch_stats(ga), _branch_stats(gb)
    if not sa["dominant"] or not sb["dominant"]:
        return None
    if sa["dominant"] == sb["dominant"]:
        return None
    # a flip is supported only by identified edges: each side's dominant
    # direction must have zero identified edges in the opposite direction
    if min(sa["taken"], sa["fallthrough"]) or \
            min(sb["taken"], sb["fallthrough"]):
        return None
    score = _W_DIRECTION * min(sa["purity"], sb["purity"])
    return {"key": key, "kind": kind, "change": "direction",
            "direction": {"baseline": sa["dominant"],
                          "candidate": sb["dominant"]},
            "score": round(score, 6),
            "score_explanation": {
                "base": _W_DIRECTION,
                "baseline_purity": round(sa["purity"], 6),
                "candidate_purity": round(sb["purity"], 6),
                "detail": "supported edge flips "
                          f"{sa['dominant']} -> {sb['dominant']}; "
                          "unknown outcomes lower purity, never an edge"},
            "edge_counts": {"baseline": {k: sa[k] for k in
                                         ("taken", "fallthrough",
                                          "unknown")},
                            "candidate": {k: sb[k] for k in
                                          ("taken", "fallthrough",
                                           "unknown")}}}


def _norm_values(g: dict) -> list[float]:
    """Per-run normalized hit counts, including zero for runs that did not
    observe the key: absence inside the captured sample is a 0.0 sample,
    so the spread reflects repeat noise and the A/A guard can suppress
    differences within it."""
    values = [r["normalized"] for r in g["runs"].values()]
    return values + [0.0] * (g["total"] - len(values))


def _hitcount_change(key, kind, ga, gb) -> dict | None:
    if not (ga["present"] and gb["present"]):
        return None
    va, vb = _norm_values(ga), _norm_values(gb)
    mean_a = sum(va) / len(va)
    mean_b = sum(vb) / len(vb)
    diff = abs(mean_a - mean_b)
    if diff == 0:
        return None
    spread_a = (max(va) - min(va)) if len(va) > 1 else 0.0
    spread_b = (max(vb) - min(vb)) if len(vb) > 1 else 0.0
    # A/A noise guard: a difference within the groups' own repeat
    # variation is baseline noise, not a scenario difference
    separation = diff - spread_a - spread_b
    if separation <= 0:
        return None
    score = _W_HITCOUNT * (separation / diff)
    return {"key": key, "kind": kind, "change": "hit_count",
            "score": round(score, 6),
            "score_explanation": {
                "base": _W_HITCOUNT,
                "baseline_mean": round(mean_a, 6),
                "candidate_mean": round(mean_b, 6),
                "baseline_spread": round(spread_a, 6),
                "candidate_spread": round(spread_b, 6),
                "detail": "normalized (hits/event) means differ beyond "
                          "the within-group spread of both groups"},
            "normalized": {"baseline": [round(v, 6) for v in va],
                           "candidate": [round(v, 6) for v in vb]}}


def _confidence(entry: dict, ga: dict, gb: dict,
                quality: dict[str, dict]) -> str:
    """Confidence in one ranked entry. Presence claims depend on every
    run (absence evidence included); direction/count claims depend on
    the runs that observed the key. Any degraded run lowers confidence;
    degraded runs elsewhere in the comparison cap it at medium."""
    if entry["change"] == "presence":
        relevant = set(quality)
    else:
        relevant = set(ga["runs"]) | set(gb["runs"])
    if any(quality[r]["degraded"] for r in relevant):
        level = "low"
    elif any(q["degraded"] for q in quality.values()):
        level = "medium"
    else:
        level = "high"
    if level == "high":
        # flaky presence inside a group caps confidence; for a presence
        # change only the present side's consistency is meaningful (the
        # absent side is 0/total by construction)
        if entry["change"] == "presence":
            side = ga if entry["present_in"] == "baseline" else gb
            if side["present"] < side["total"]:
                level = "medium"
        elif ga["present"] < ga["total"] or gb["present"] < gb["total"]:
            level = "medium"
    return level


# ------------------------------------------------------------ orchestration
def coverage_diff(project, baseline: str, candidate: str, *,
                  exploratory: bool = False, filter: str | None = None,
                  change: str | None = None, limit: int = 50,
                  offset: int = 0) -> dict:
    """Rank observed coverage differences between two label-selected
    groups of stored coverage runs. Fully offline and deterministic."""
    if change is not None and change not in _CHANGE_ORDER:
        raise SessionError(f"unknown change filter {change!r}",
                           hint="presence | direction | hit_count")
    with project.db() as db:
        runs_a = _group_runs(db, baseline)
        runs_b = _group_runs(db, candidate)
        aa_split = False
        if baseline == candidate:
            if len(runs_a) < 2:
                raise SessionError(
                    "A/A comparison of one label needs at least 2 runs",
                    hint="record repeated runs with the same scenario")
            half = len(runs_a) // 2
            runs_a, runs_b = runs_a[:half], runs_a[half:]
            aa_split = True
        observations = {r["run_id"]: _load_observations(db, r)
                        for r in runs_a + runs_b}

    compat = check_compatible(runs_a, runs_b)
    quality = {r["run_id"]: _run_quality(r)
               for r in runs_a + runs_b}
    degraded = [q for q in quality.values() if q["degraded"]]

    out = {"baseline": {"label": baseline,
                        "runs": [quality[r["run_id"]] for r in runs_a]},
           "candidate": {"label": candidate,
                         "runs": [quality[r["run_id"]] for r in runs_b]},
           "aa_baseline": aa_split,
           "mode": runs_a[0]["capture_config"].get("mode", "method"),
           "compatibility": compat, "exploratory": exploratory,
           "quality": {
               "degraded_runs": degraded,
               "exact_subtraction": False,
               "note": "coverage captures are bounded samples; ranked "
                       "entries are investigation candidates with "
                       "supporting counts, not a proof of the causal "
                       "branch"}}
    if not compat["compatible"] and not exploratory:
        out["reason"] = ("incompatible runs — see compatibility."
                         "differences; re-run with exploratory=True for "
                         "an annotated intersection that does not imply "
                         "equivalent coverage")
        out["ranked"] = None
        out.update({"count": 0, "total": 0, "limit": limit,
                    "offset": offset, "truncated": False})
        return out

    ga = _group_view(runs_a, [observations[r["run_id"]] for r in runs_a])
    gb = _group_view(runs_b, [observations[r["run_id"]] for r in runs_b])
    if exploratory and not compat["compatible"]:
        # annotated intersection only: keys observed on both sides —
        # never a union presented as equivalent coverage
        keys = sorted(set(ga) & set(gb))
        out["intersection_only"] = True
        out["equivalence"] = ("not_equivalent: incompatible capture "
                              "conditions; compared keys are an "
                              "intersection of observations, not "
                              "equivalent coverage")
    else:
        keys = sorted(set(ga) | set(gb))
    if filter:
        keys = [k for k in keys if filter in k]

    ranked: list = []
    for key in keys:
        kind = key.split(":", 1)[0]
        a = ga.get(key, {"runs": {}, "present": 0,
                         "total": len(runs_a)})
        b = gb.get(key, {"runs": {}, "present": 0,
                         "total": len(runs_b)})
        entry = _presence_change(key, kind, a, b)
        if entry is None and kind == "branch":
            entry = _direction_change(key, kind, a, b)
        if entry is None:
            entry = _hitcount_change(key, kind, a, b)
        if entry is None:
            continue
        entry["repeatability"] = {
            "baseline": f"{a['present']}/{a['total']}",
            "candidate": f"{b['present']}/{b['total']}"}
        entry["observations"] = {
            "baseline": {r: v for r, v in sorted(a["runs"].items())},
            "candidate": {r: v for r, v in sorted(b["runs"].items())}}
        entry["confidence"] = _confidence(entry, a, b, quality)
        if change and entry["change"] != change:
            continue
        ranked.append(entry)
    ranked.sort(key=_rank_key)

    total = len(ranked)
    page = ranked[offset:offset + limit]
    out["ranked"] = page
    out.update({"count": len(page), "total": total, "limit": limit,
                "offset": offset,
                "truncated": offset + len(page) < total})
    return out

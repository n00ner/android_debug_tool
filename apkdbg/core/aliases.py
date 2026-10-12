"""Runtime alias candidates — evidence-backed naming hypotheses (issue #25).

Runtime strings (log tags, enum-like values, route/preference names) can
hint at what an obfuscated class or method does, but they never establish
an original identifier. This module stores REVIEWABLE alias candidates
with their supporting observations, fully separate from the static index:

  - `classes.deobf_fqcn` and imported mappings are never read for writing
    and never modified; candidates live in alias_candidates/alias_decisions.
  - A candidate carries a HEURISTIC SCORE (rule strength), not a calibrated
    probability, plus the versioned rule that produced it.
  - Observations are identified within their session/classloader context:
    rows from distinct classloaders of one class signature stay separate
    (classloader_key), and runtime classes absent from the static index
    keep their evidence without a fabricated static match.
  - Nothing is ever auto-accepted: collector output starts as `suggested`;
    only an explicit accept/reject/revise (or a manual alias) changes the
    review state, and every change is recorded in alias_decisions so
    replacements are reversible. A rejected (text, rule) pair on the same
    entity stays rejected on re-observation — it is counted and linked to
    the rejection, never silently resurrected as fresh `suggested`.
  - Repeated observations dedupe into one row WITHOUT losing frequency or
    provenance: observations counter, first/last seen, and per-run/event
    evidence references (bounded; the counter keeps the true total).

Retention: candidates, decisions, and their evidence live in the project
mapping.db, are carried across re-indexing like the other observation
tables (issue #35), and are deleted only with the project. Candidate text
and evidence may contain application data (captured strings) — treat
`aliases export` output as sensitive.
"""

from __future__ import annotations

import json
import re
import time
import uuid

from .. import __version__
from ..errors import SessionError
from .manifests import index_generation

RULES_VERSION = 1
STATUSES = ("suggested", "accepted", "rejected", "superseded")
MAX_EVIDENCE_REFS = 32  # per-row ref cap; `observations` keeps the true count

# Suggestion floor: findings below this heuristic score are behavioral
# context, not name candidates. Nothing above it is auto-accepted either —
# `suggested` always requires an explicit review decision.
SUGGEST_MIN_SCORE = 0.4

# ------------------------------------------------------------------- rules
# Ordered: the first matching rule wins. Scores are heuristic strengths.
RE_URL = re.compile(r"^[a-z][a-z0-9+.-]*://\S+$", re.IGNORECASE)
RE_ROUTE = re.compile(r"^/[a-z0-9][a-z0-9_\-/.]{1,63}$")
RE_ENUM = re.compile(r"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$")
RE_PREF = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,5}$")
RE_LOG_TAG = re.compile(r"^(?=.*[a-z])[A-Z][A-Za-z0-9]{2,23}$")

RULES = (
    # a generic URL is behavioral context, NOT a name candidate
    ("url_context", RE_URL, 0.0, "context"),
    ("route_name", RE_ROUTE, 0.7, "candidate"),
    ("enum_like", RE_ENUM, 0.5, "candidate"),
    ("pref_key", RE_PREF, 0.5, "candidate"),
    ("log_tag", RE_LOG_TAG, 0.8, "candidate"),
)


def analyze(text: str) -> list[dict]:
    """Versioned heuristic findings for one observed string. At most one
    finding per string (first matching rule); a `context` finding is
    behavioral evidence only and never becomes a name candidate."""
    if not text:
        return []
    for rule, pattern, score, kind in RULES:
        if pattern.match(text):
            return [{"kind": kind, "rule": rule, "text": text,
                     "score": score, "rules_version": RULES_VERSION}]
    return []


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _json(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False,
                      default=str)


def _loads(text, default):
    if text is None:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


class AliasStore:
    """Project-DB-backed store for alias candidates and decision history."""

    def __init__(self, project):
        self.project = project

    @classmethod
    def for_session(cls, session) -> "AliasStore | None":
        """Store for a session's project, or None for project-less
        (test/embedded) sessions."""
        project = getattr(session, "project", None)
        return cls(project) if project is not None else None

    # ------------------------------------------------------------ observations
    def observe(self, *, class_sig: str, candidate: str, score: float,
                rule: str, source: str = "collector",
                method_name: str | None = None,
                method_sig: str | None = None,
                classloader_id: int | None = None,
                epoch: int | None = None,
                run_id: str | None = None,
                event_id: str | None = None,
                evidence: list | None = None) -> tuple[str, str]:
        """Record one observation of `candidate` for an entity. Dedupe key:
        (apk, entity incl. classloader, candidate text, rule). Repeats merge
        into the existing row (observations/first/last seen/evidence refs);
        a row rejected earlier stays rejected and the re-observation is
        recorded as resuggest_suppressed. Returns (candidate_id, action)
        with action in suggested | merged | suppressed."""
        now = _now()
        loader_key = (f"e{epoch}:{classloader_id}"
                      if classloader_id is not None else None)
        with self.project.db() as db:
            sha = db.get_meta("sha256")
            row = db.one(
                "SELECT * FROM alias_candidates WHERE apk_sha256 IS ? "
                "AND class_sig=? AND method_name IS ? AND method_sig IS ? "
                "AND classloader_key IS ? AND candidate=? AND rule=?",
                (sha, class_sig, method_name, method_sig, loader_key,
                 candidate, rule))
            if row is not None:
                refs = _loads(row["evidence"], []) + list(evidence or [])
                db.execute(
                    "UPDATE alias_candidates SET observations=observations+1,"
                    " last_seen=?, evidence=?,"
                    " run_id=COALESCE(?,run_id),"
                    " event_id=COALESCE(?,event_id) WHERE candidate_id=?",
                    (now, _json(refs[-MAX_EVIDENCE_REFS:]), run_id, event_id,
                     row["candidate_id"]))
                if row["status"] == "rejected":
                    self._decide(db, row["candidate_id"],
                                 "resuggest_suppressed", "rejected",
                                 "rejected",
                                 "identical text+rule re-observed; linked "
                                 "to the rejection, not re-suggested")
                    return row["candidate_id"], "suppressed"
                self._decide(db, row["candidate_id"], "resuggest_merged",
                             row["status"], row["status"],
                             "repeat observation merged (frequency kept)")
                return row["candidate_id"], "merged"
            cid = uuid.uuid4().hex
            db.execute(
                "INSERT INTO alias_candidates(candidate_id,apk_sha256,"
                "index_generation,class_sig,method_name,method_sig,"
                "classloader_id,classloader_key,candidate,heuristic_score,"
                "rule,rules_version,source,run_id,event_id,evidence,"
                "observations,first_seen,last_seen,status,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?)",
                (cid, sha, index_generation(db), class_sig, method_name,
                 method_sig, classloader_id, loader_key, candidate, score,
                 rule, RULES_VERSION, source, run_id, event_id,
                 _json(list(evidence or [])), now, now, "suggested", now))
            self._decide(db, cid, "suggest", None, "suggested",
                         f"rule {rule} v{RULES_VERSION}, "
                         f"heuristic score {score}")
            return cid, "suggested"

    # ---------------------------------------------------------------- review
    def add_alias(self, class_sig: str, alias: str, *,
                  method_name: str | None = None,
                  method_sig: str | None = None,
                  note: str | None = None) -> dict:
        """Manual alias: an explicit investigator decision, recorded as
        accepted (never as a heuristic score — heuristic_score stays NULL).
        Supersedes any accepted candidate of the same entity."""
        if not alias:
            raise SessionError("manual alias needs non-empty text")
        now = _now()
        with self.project.db() as db:
            superseded = self._supersede_accepted(
                db, class_sig, method_name, method_sig, None,
                replaced_by="manual alias")
            cid = uuid.uuid4().hex
            db.execute(
                "INSERT INTO alias_candidates(candidate_id,apk_sha256,"
                "index_generation,class_sig,method_name,method_sig,"
                "candidate,heuristic_score,rule,rules_version,source,"
                "evidence,observations,first_seen,last_seen,status,"
                "created_at,decided_at) "
                "VALUES(?,?,?,?,?,?,?,NULL,'manual',?,'manual','[]',1,?,?,"
                "'accepted',?,?)",
                (cid, db.get_meta("sha256"), index_generation(db), class_sig,
                 method_name, method_sig, alias, RULES_VERSION, now, now,
                 now, now))
            self._decide(db, cid, "manual_add", None, "accepted",
                         note or "manual alias")
        return {"candidate_id": cid, "status": "accepted",
                "superseded": superseded}

    def accept(self, candidate_id: str, note: str | None = None) -> dict:
        with self.project.db() as db:
            row = self._row(db, candidate_id)
            if row["status"] == "accepted":
                return {"candidate_id": candidate_id, "status": "accepted",
                        "superseded": [], "note": "already accepted"}
            superseded = self._supersede_accepted(
                db, row["class_sig"], row["method_name"], row["method_sig"],
                row["classloader_key"], replaced_by=candidate_id)
            db.execute(
                "UPDATE alias_candidates SET status='accepted', decided_at=?"
                " WHERE candidate_id=?", (_now(), candidate_id))
            self._decide(db, candidate_id, "accept", row["status"],
                         "accepted", note)
        return {"candidate_id": candidate_id, "status": "accepted",
                "superseded": superseded}

    def reject(self, candidate_id: str, note: str | None = None) -> dict:
        with self.project.db() as db:
            row = self._row(db, candidate_id)
            db.execute(
                "UPDATE alias_candidates SET status='rejected', decided_at=?"
                " WHERE candidate_id=?", (_now(), candidate_id))
            self._decide(db, candidate_id, "reject", row["status"],
                         "rejected", note)
        return {"candidate_id": candidate_id, "status": "rejected"}

    def revise(self, candidate_id: str, new_text: str,
               note: str | None = None) -> dict:
        """Accept a corrected text: the old row is superseded (reversible
        via the decision trail) and a new accepted row carries the revised
        text with the old row's evidence and observation count."""
        if not new_text:
            raise SessionError("revise needs non-empty replacement text")
        now = _now()
        with self.project.db() as db:
            row = self._row(db, candidate_id)
            if row["candidate"] == new_text:
                return self.accept(candidate_id, note=note)
            superseded = self._supersede_accepted(
                db, row["class_sig"], row["method_name"], row["method_sig"],
                row["classloader_key"], replaced_by="revision",
                exclude=candidate_id)
            new_id = uuid.uuid4().hex
            db.execute(
                "INSERT INTO alias_candidates(candidate_id,apk_sha256,"
                "index_generation,class_sig,method_name,method_sig,"
                "classloader_id,classloader_key,candidate,heuristic_score,"
                "rule,rules_version,source,run_id,event_id,evidence,"
                "observations,first_seen,last_seen,status,created_at,"
                "decided_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
                "'accepted',?,?)",
                (new_id, row["apk_sha256"], row["index_generation"],
                 row["class_sig"], row["method_name"], row["method_sig"],
                 row["classloader_id"], row["classloader_key"], new_text,
                 row["heuristic_score"], row["rule"], row["rules_version"],
                 "manual", row["run_id"], row["event_id"], row["evidence"],
                 row["observations"], row["first_seen"], now, now, now))
            self._decide(db, new_id, "revise", None, "accepted",
                         (note + "; " if note else "")
                         + f"revised from {candidate_id}: "
                           f"{row['candidate']!r} -> {new_text!r}")
            db.execute(
                "UPDATE alias_candidates SET status='superseded',"
                " decided_at=? WHERE candidate_id=?", (now, candidate_id))
            self._decide(db, candidate_id, "supersede", row["status"],
                         "superseded", f"revised into {new_id}")
        return {"candidate_id": new_id, "status": "accepted",
                "superseded": [candidate_id] + superseded}

    # ----------------------------------------------------------------- reads
    def list(self, *, status: str | None = None, q: str | None = None,
             class_sig: str | None = None, all_apks: bool = False,
             limit: int = 50, offset: int = 0) -> dict:
        where, params = [], []
        with self.project.db() as db:
            if not all_apks:
                where.append("apk_sha256 IS ?")
                params.append(db.get_meta("sha256"))
            if status:
                if status not in STATUSES:
                    raise SessionError(f"unknown alias status {status!r}",
                                       hint="one of: " + ", ".join(STATUSES))
                where.append("status=?")
                params.append(status)
            if class_sig:
                where.append("class_sig=?")
                params.append(class_sig)
            if q:
                where.append("(candidate LIKE ? OR class_sig LIKE ?)")
                params += [f"%{q}%", f"%{q}%"]
            sql_where = (" WHERE " + " AND ".join(where)) if where else ""
            rows = db.query(
                "SELECT * FROM alias_candidates" + sql_where
                + " ORDER BY last_seen DESC, rowid DESC LIMIT ? OFFSET ?",
                params + [limit, offset])
            total = db.one(
                "SELECT COUNT(*) AS n FROM alias_candidates" + sql_where,
                params)["n"]
        out = [_parse_candidate(r) for r in rows]
        return {"candidates": out, "count": len(out), "total": total,
                "limit": limit, "offset": offset,
                "truncated": offset + len(out) < total}

    def get(self, candidate_id: str) -> dict:
        """One candidate with its decision trail, resolved evidence (source
        event rows), and static links (smali location) where the runtime
        class exists in the index. Unmapped runtime classes report
        static_match=False and keep their evidence — no fabricated match."""
        with self.project.db() as db:
            row = _parse_candidate(self._row(db, candidate_id))
            row["decisions"] = db.query(
                "SELECT * FROM alias_decisions WHERE candidate_id=? "
                "ORDER BY id", (candidate_id,))
            events = []
            for ref in row["evidence"]:
                eid = ref.get("event_id") if isinstance(ref, dict) else None
                if not eid:
                    continue
                ev = db.one("SELECT * FROM events WHERE event_id=?", (eid,))
                if ev is not None:
                    ev["payload"] = _loads(ev.get("payload"), {})
                    events.append(ev)
            row["events"] = events
            cls = db.one("SELECT * FROM classes WHERE sig=?",
                         (row["class_sig"],))
            row["static_match"] = cls is not None
            row["static"] = None
            if cls is not None:
                link = {"fqcn": cls["fqcn"], "deobf_fqcn": cls["deobf_fqcn"],
                        "smali": {"path": cls["smali_path"]}}
                if row["method_name"]:
                    m = db.one(
                        "SELECT line_start, line_end FROM methods WHERE "
                        "class_id=? AND name=? AND sig IS ?",
                        (cls["id"], row["method_name"], row["method_sig"]))
                    if m is not None:
                        link["smali"]["line_start"] = m["line_start"]
                        link["smali"]["line_end"] = m["line_end"]
                row["static"] = link
        return row

    def export(self) -> dict:
        """Self-contained export of every candidate with its decision
        trail. May contain application data — treat as sensitive."""
        with self.project.db() as db:
            rows = db.query("SELECT * FROM alias_candidates ORDER BY rowid")
            out = []
            for r in rows:
                row = _parse_candidate(r)
                row["decisions"] = db.query(
                    "SELECT * FROM alias_decisions WHERE candidate_id=? "
                    "ORDER BY id", (r["candidate_id"],))
                out.append(row)
            sha = db.get_meta("sha256")
        return {"alias_export_version": 1, "tool_version": __version__,
                "apk_sha256": sha, "exported_at": _now(),
                "retention": "candidates and decision history live in the "
                             "project mapping.db, are carried across "
                             "re-indexing, and are deleted only with the "
                             "project; candidate text and evidence may "
                             "contain application data — treat this export "
                             "as sensitive",
                "candidates": out}

    # --------------------------------------------------------------- helpers
    def _row(self, db, candidate_id: str) -> dict:
        row = db.one("SELECT * FROM alias_candidates WHERE candidate_id=?",
                     (candidate_id,))
        if row is None:
            raise SessionError(f"no such alias candidate: {candidate_id}",
                               hint="see `aliases list`")
        return row

    def _supersede_accepted(self, db, class_sig, method_name, method_sig,
                            classloader_key, *, replaced_by: str,
                            exclude: str | None = None) -> list:
        """Move every OTHER accepted candidate of the same entity (same
        class/method/classloader scope — loaders are never merged) to
        superseded; returns their ids."""
        now = _now()
        others = db.query(
            "SELECT candidate_id, status FROM alias_candidates WHERE "
            "status='accepted' AND class_sig=? AND method_name IS ? AND "
            "method_sig IS ? AND classloader_key IS ?",
            (class_sig, method_name, method_sig, classloader_key))
        done = []
        for o in others:
            if o["candidate_id"] == exclude:
                continue
            db.execute(
                "UPDATE alias_candidates SET status='superseded',"
                " decided_at=? WHERE candidate_id=?", (now, o["candidate_id"]))
            self._decide(db, o["candidate_id"], "supersede", "accepted",
                         "superseded", f"replaced by {replaced_by}")
            done.append(o["candidate_id"])
        return done

    @staticmethod
    def _decide(db, candidate_id: str, action: str, from_status,
                to_status: str, note: str | None) -> None:
        db.execute(
            "INSERT INTO alias_decisions(candidate_id,action,from_status,"
            "to_status,note,decided_at) VALUES(?,?,?,?,?,?)",
            (candidate_id, action, from_status, to_status, note, _now()))


def accepted_alias(db, class_sig: str,
                   method_name: str | None = None) -> str | None:
    """The accepted alias text for an entity, or None. Annotation only —
    callers must never feed it back into resolution or targeting. With
    competing accepted rows (distinct classloaders), a loader-independent
    row wins; otherwise the most recently decided one."""
    rows = db.query(
        "SELECT candidate, classloader_key, decided_at FROM "
        "alias_candidates WHERE status='accepted' AND class_sig=? AND "
        "method_name IS ? AND apk_sha256 IS ?",
        (class_sig, method_name, db.get_meta("sha256")))
    if not rows:
        return None
    rows.sort(key=lambda r: r["decided_at"] or "", reverse=True)
    plain = [r for r in rows if r["classloader_key"] is None]
    return (plain[0] if plain else rows[0])["candidate"]


def accepted_alias_map(db, sigs) -> dict:
    """{sig: accepted alias} for output annotation (issue #25): aliases are
    additive fields next to sig/deobf, never a replacement identity."""
    out = {}
    for sig in sigs:
        alias = accepted_alias(db, sig)
        if alias is not None:
            out[sig] = alias
    return out


def _parse_candidate(row: dict) -> dict:
    out = dict(row)
    out["evidence"] = _loads(out.get("evidence"), [])
    return out

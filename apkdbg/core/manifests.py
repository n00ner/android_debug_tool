"""Investigation run manifests — durable identity for runtime observations
(issue #36).

A *run* is one investigation capture (coverage run, crypto watch, snapshot,
...). Its manifest records the capture conditions: APK hash + static-index
generation, tool version, capture configuration, environment/VM metadata,
scenario label, session epoch, start/end times, and completion reason.
Runs, events, and artifacts live in their own tables: re-indexing the
project (issue #35) rebuilds only the derived static tables and copies
these observation rows verbatim into each new index generation; every
observation keeps the index generation it was captured against.

Identity rules:
  - run/event/artifact ids are durable uuids, stable across export/import;
  - source identity is the original class/method descriptor plus
    bytecode/source location — recovered/deobfuscated names are payload
    annotations only;
  - runtime object ids are per-connection: observations keep the epoch of
    the session that captured them and are never reinterpreted after a
    reconnect.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid

from .. import __version__
from ..errors import SessionError

MANIFEST_VERSION = 1


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _json(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False,
                      default=str)


def index_generation(db) -> int:
    """Current static-index generation (1 for DBs predating generations)."""
    return int(db.get_meta("index_generation") or 1)


def bump_index_generation(db) -> int:
    """Advance the static-index generation counter in place. Re-indexing
    (issue #35) instead computes the next generation from the live DB and
    stamps it into the staged replacement database at publish time, so new
    observations are distinguishable from ones captured against the old
    index. Existing runs/events/artifacts keep their recorded generation.
    An absent counter means generation 1 (first init, or a legacy DB)."""
    gen = int(db.get_meta("index_generation") or 1) + 1
    db.set_meta("index_generation", str(gen))
    return gen


def capture_environment(session) -> dict:
    """Best-effort environment/VM metadata; only known keys are included."""
    env: dict = {}
    hs = getattr(getattr(session, "client", None), "handshake_info", None) or {}
    for k in ("vm_name", "vm_version", "jdwp_major", "jdwp_minor"):
        if hs.get(k) is not None:
            env[k] = hs[k]
    adb = getattr(session, "adb", None)
    if getattr(adb, "serial", None):
        env["device"] = adb.serial
    if adb is not None:
        try:
            api = adb.shell("getprop ro.build.version.sdk").strip()
            if api:
                env["android_api"] = api
        except Exception:
            pass
    return env


class RunStore:
    """Project-DB-backed store for run manifests, events, and artifacts."""

    def __init__(self, project):
        self.project = project

    @classmethod
    def for_session(cls, session) -> "RunStore | None":
        """Store for a session's project, or None for project-less
        (test/embedded) sessions."""
        project = getattr(session, "project", None)
        return cls(project) if project is not None else None

    # ------------------------------------------------------------------ runs
    def begin_run(self, kind: str, capture_config: dict | None = None, *,
                  run_id: str | None = None, scenario: str | None = None,
                  epoch: int | None = None, environment: dict | None = None,
                  started_at: str | None = None) -> str:
        run_id = run_id or uuid.uuid4().hex
        with self.project.db() as db:
            db.execute(
                "INSERT INTO runs(run_id,manifest_version,kind,scenario,"
                "apk_sha256,index_generation,tool_version,capture_config,"
                "environment,epoch,started_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, MANIFEST_VERSION, kind, scenario,
                 db.get_meta("sha256"), index_generation(db), __version__,
                 _json(capture_config or {}), _json(environment or {}),
                 epoch, started_at or _now()))
        return run_id

    def end_run(self, run_id: str, reason: str,
                counts: dict | None = None,
                ended_at: str | None = None) -> None:
        with self.project.db() as db:
            if db.one("SELECT run_id FROM runs WHERE run_id=?", (run_id,)) \
                    is None:
                raise SessionError(f"no such run: {run_id}")
            db.execute(
                "UPDATE runs SET ended_at=?, completion_reason=?, counts=? "
                "WHERE run_id=?",
                (ended_at or _now(), reason, _json(counts or {}), run_id))

    # ---------------------------------------------------------------- events
    def add_event(self, run_id: str, kind: str, payload: dict, *,
                  class_sig: str | None = None, method_name: str | None = None,
                  method_sig: str | None = None, dalvik_line: int | None = None,
                  bytecode_index: int | None = None, epoch: int | None = None,
                  event_id: str | None = None) -> str:
        event_id = event_id or uuid.uuid4().hex
        with self.project.db() as db:
            run = self._run_row(db, run_id)
            db.execute(
                "INSERT INTO events(event_id,run_id,index_generation,epoch,"
                "kind,class_sig,method_name,method_sig,dalvik_line,"
                "bytecode_index,payload) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (event_id, run_id, run["index_generation"],
                 epoch if epoch is not None else run["epoch"], kind,
                 class_sig, method_name, method_sig, dalvik_line,
                 bytecode_index, _json(payload)))
        return event_id

    # -------------------------------------------------------------- artifacts
    def add_artifact(self, run_id: str, kind: str, body, *,
                     format: str = "json",  # noqa: A002 - CLI-facing name
                     budgets: dict | None = None,
                     truncation: dict | None = None,
                     errors: list | None = None,
                     parent_event_id: str | None = None,
                     epoch: int | None = None,
                     artifact_id: str | None = None) -> str:
        artifact_id = artifact_id or uuid.uuid4().hex
        text = body if isinstance(body, str) else _json(body)
        with self.project.db() as db:
            run = self._run_row(db, run_id)
            db.execute(
                "INSERT INTO artifacts(artifact_id,run_id,parent_event_id,"
                "kind,format,index_generation,epoch,budgets,truncation,"
                "errors,checksum,body) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (artifact_id, run_id, parent_event_id, kind, format,
                 run["index_generation"],
                 epoch if epoch is not None else run["epoch"],
                 _json(budgets or {}), _json(truncation or {}),
                 _json(errors or []),
                 hashlib.sha256(text.encode("utf-8")).hexdigest(), text))
        return artifact_id

    # ----------------------------------------------------------------- reads
    def list_runs(self, limit: int = 50, offset: int = 0,
                  kind: str | None = None) -> dict:
        sql = "SELECT * FROM runs"
        params: list = []
        if kind:
            sql += " WHERE kind=?"
            params.append(kind)
        sql += " ORDER BY started_at DESC, rowid DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        with self.project.db() as db:
            rows = [_parse_run(r) for r in db.query(sql, params)]
            total = db.one(
                "SELECT COUNT(*) AS n FROM runs"
                + (" WHERE kind=?" if kind else ""),
                tuple(params[:1]) if kind else ())["n"]
        return {"runs": rows, "count": len(rows), "total": total,
                "limit": limit, "offset": offset}

    def get_run(self, run_id: str) -> dict:
        with self.project.db() as db:
            run = _parse_run(self._run_row(db, run_id))
            events = [_parse_event(r) for r in db.query(
                "SELECT * FROM events WHERE run_id=? ORDER BY rowid",
                (run_id,))]
            artifacts = [_parse_artifact(r) for r in db.query(
                "SELECT * FROM artifacts WHERE run_id=? ORDER BY rowid",
                (run_id,))]
        return {"run": run, "events": events, "artifacts": artifacts}

    def get_artifact(self, artifact_id: str) -> dict:
        with self.project.db() as db:
            row = db.one("SELECT * FROM artifacts WHERE artifact_id=?",
                         (artifact_id,))
        if row is None:
            raise SessionError(f"no such artifact: {artifact_id}")
        return _parse_artifact(row)

    def resolve_snapshot_artifact(self, ref: str) -> tuple[dict, dict]:
        """(run row, artifact row) for an artifact id, or for a run id with
        exactly one snapshot artifact."""
        with self.project.db() as db:
            row = db.one("SELECT * FROM artifacts WHERE artifact_id=?",
                         (ref,))
            if row is None:
                run = self._run_row(db, ref)
                cands = db.query(
                    "SELECT * FROM artifacts WHERE run_id=? AND kind="
                    "'snapshot' ORDER BY rowid", (ref,))
                if len(cands) != 1:
                    raise SessionError(
                        f"run {ref} has {len(cands)} snapshot artifacts",
                        hint="pass an artifact_id from `runs get` instead")
                row = cands[0]
            run = self._run_row(db, row["run_id"])
        return run, row

    # ----------------------------------------------------------- export/import
    def export_run(self, run_id: str) -> dict:
        """Self-contained JSON export: raw rows (JSON columns as stored) so
        export -> import -> export is byte-stable and preserves the manifest
        schema version and every id/relationship."""
        with self.project.db() as db:
            run = self._run_row(db, run_id)
            events = db.query(
                "SELECT * FROM events WHERE run_id=? ORDER BY rowid",
                (run_id,))
            artifacts = db.query(
                "SELECT * FROM artifacts WHERE run_id=? ORDER BY rowid",
                (run_id,))
        return {"manifest_version": run["manifest_version"],
                "tool_version": run["tool_version"],
                "run": run, "events": events, "artifacts": artifacts}

    def import_run(self, data: dict, *, replace: bool = False) -> dict:
        version = data.get("manifest_version")
        if not isinstance(version, int):
            raise SessionError("export has no manifest_version",
                               hint="not an apkdbg run export")
        if version > MANIFEST_VERSION:
            raise SessionError(
                f"export manifest_version {version} is newer than this "
                f"tool supports ({MANIFEST_VERSION})",
                hint="upgrade apkdbg to import this run")
        run = data.get("run") or {}
        run_id = run.get("run_id")
        if not run_id:
            raise SessionError("export has no run.run_id")
        events = data.get("events") or []
        artifacts = data.get("artifacts") or []
        with self.project.db() as db:
            if db.one("SELECT run_id FROM runs WHERE run_id=?",
                      (run_id,)) is not None:
                if not replace:
                    raise SessionError(
                        f"run {run_id} already exists",
                        hint="re-import with replace=True to overwrite")
                db.execute("DELETE FROM events WHERE run_id=?", (run_id,))
                db.execute("DELETE FROM artifacts WHERE run_id=?", (run_id,))
            db.execute(
                "INSERT OR REPLACE INTO runs(run_id,manifest_version,kind,"
                "scenario,apk_sha256,index_generation,tool_version,"
                "capture_config,environment,epoch,started_at,ended_at,"
                "completion_reason,counts) VALUES(?,?,?,?,?,?,?,?,?,?,?,"
                "?,?,?)",
                (run_id, version, run.get("kind"), run.get("scenario"),
                 run.get("apk_sha256"), run.get("index_generation"),
                 run.get("tool_version"), run.get("capture_config"),
                 run.get("environment"), run.get("epoch"),
                 run.get("started_at"), run.get("ended_at"),
                 run.get("completion_reason"), run.get("counts")))
            for e in events:
                db.execute(
                    "INSERT OR REPLACE INTO events(event_id,run_id,"
                    "index_generation,epoch,kind,class_sig,method_name,"
                    "method_sig,dalvik_line,bytecode_index,payload) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (e.get("event_id"), run_id, e.get("index_generation"),
                     e.get("epoch"), e.get("kind"), e.get("class_sig"),
                     e.get("method_name"), e.get("method_sig"),
                     e.get("dalvik_line"), e.get("bytecode_index"),
                     e.get("payload")))
            for a in artifacts:
                db.execute(
                    "INSERT OR REPLACE INTO artifacts(artifact_id,run_id,"
                    "parent_event_id,kind,format,index_generation,epoch,"
                    "budgets,truncation,errors,checksum,body) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (a.get("artifact_id"), run_id, a.get("parent_event_id"),
                     a.get("kind"), a.get("format"),
                     a.get("index_generation"), a.get("epoch"),
                     a.get("budgets"), a.get("truncation"), a.get("errors"),
                     a.get("checksum"), a.get("body")))
        return {"run_id": run_id, "manifest_version": version,
                "events": len(events), "artifacts": len(artifacts),
                "replaced": replace}

    # ------------------------------------------------------------------ misc
    @staticmethod
    def _run_row(db, run_id: str) -> dict:
        row = db.one("SELECT * FROM runs WHERE run_id=?", (run_id,))
        if row is None:
            raise SessionError(f"no such run: {run_id}",
                               hint="see `runs list`")
        return row


def _loads(text, default):
    if text is None:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


def _parse_run(row: dict) -> dict:
    out = dict(row)
    out["capture_config"] = _loads(out.get("capture_config"), {})
    out["environment"] = _loads(out.get("environment"), {})
    out["counts"] = _loads(out.get("counts"), {})
    return out


def _parse_event(row: dict) -> dict:
    out = dict(row)
    out["payload"] = _loads(out.get("payload"), {})
    return out


def _parse_artifact(row: dict) -> dict:
    out = dict(row)
    out["budgets"] = _loads(out.get("budgets"), {})
    out["truncation"] = _loads(out.get("truncation"), {})
    out["errors"] = _loads(out.get("errors"), [])
    if out.get("format") == "json":
        out["body"] = _loads(out.get("body"), out.get("body"))
    return out

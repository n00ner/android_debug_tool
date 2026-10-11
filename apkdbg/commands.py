"""Command implementations shared by the CLI and the JSON-RPC server.
Each function takes a Ctx plus kwargs and returns a JSON-native dict."""

from __future__ import annotations

import json
from pathlib import Path

from .core.init_pipeline import run_init
from .core.manifests import RunStore, capture_environment
from .core.project import Project
from .debug.conditions import ConditionalEngine
from .debug.coverage import CoverageTracker
from .debug.hooks import crypto as crypto_hooks
from .debug.session import DebugSession
from .debug.snapdiff import snapshot_diff
from .debug.snapshot import Budgets, Snapshotter
from .errors import SessionError


# ------------------------------------------------------------- pagination
MAX_PAGE = 500  # hard upper bound for any list command's page size


def _page(limit: int, offset: int) -> tuple[int, int]:
    """Clamp client-supplied pagination to bounded, deterministic values.
    The applied (clamped) values are echoed back in the reply metadata."""
    return max(1, min(int(limit), MAX_PAGE)), max(0, int(offset))


def _page_meta(rows: list, total: int, limit: int, offset: int) -> dict:
    """Truncation metadata, same shape as `runs list` (issue #36)."""
    return {"count": len(rows), "total": total, "limit": limit,
            "offset": offset, "truncated": offset + len(rows) < total}


class Ctx:
    """Holds the project handle and (lazily) the live debug session.
    The JSON-RPC server keeps one Ctx alive; the CLI builds one per call."""

    def __init__(self, project_root: str = ".", serial: str | None = None):
        self.project = Project.open(project_root)
        self.serial = serial
        self._session: DebugSession | None = None

    @property
    def session(self) -> DebugSession:
        if self._session is None or self._session.client is None:
            raise SessionError("not connected",
                               hint="run 'connect' first (or use serve mode "
                                    "for a persistent session)")
        return self._session

    def connect_session(self, package: str | None, **kw) -> DebugSession:
        pkg = package or self.project.state().get("package")
        if not pkg:
            raise SessionError("no package given and none in project state",
                               hint="pass --pkg com.example.app")
        if self._session:
            self._session.close()
        self._session = DebugSession(self.project, self.serial)
        self._info = self._session.connect(pkg, **kw)
        return self._session

    def close(self):
        if self._session:
            self._session.close()


# --------------------------------------------------------------------- init
def cmd_init(ctx: Ctx | None, apk: str, out: str = ".",
             skip_apktool: bool = False, skip_jadx: bool = False) -> dict:
    return run_init(apk, out, skip_apktool=skip_apktool, skip_jadx=skip_jadx)


# ------------------------------------------------------------------- queries
def cmd_classes(ctx: Ctx, filter: str = "", limit: int = 50,
                offset: int = 0) -> dict:
    limit, offset = _page(limit, offset)
    args = (f"%{filter}%",) * 2
    where = "WHERE fqcn LIKE ? OR deobf_fqcn LIKE ?"
    with ctx.project.db() as db:
        rows = db.query(
            "SELECT fqcn, deobf_fqcn, smali_path FROM classes " + where +
            " LIMIT ? OFFSET ?", args + (limit, offset))
        total = db.one("SELECT COUNT(*) AS n FROM classes " + where,
                       args)["n"]
    return {"classes": rows, **_page_meta(rows, total, limit, offset)}


def cmd_methods(ctx: Ctx, class_: str, limit: int = 100,
                offset: int = 0) -> dict:
    limit, offset = _page(limit, offset)
    args = (class_, class_, class_)
    where = ("WHERE c.fqcn=? OR c.deobf_fqcn=? OR c.sig=?")
    with ctx.project.db() as db:
        rows = db.query(
            "SELECT m.name, m.sig, m.is_native FROM methods m JOIN classes c "
            "ON c.id=m.class_id " + where + " LIMIT ? OFFSET ?",
            args + (limit, offset))
        total = db.one(
            "SELECT COUNT(*) AS n FROM methods m JOIN classes c ON "
            "c.id=m.class_id " + where, args)["n"]
    return {"methods": rows, **_page_meta(rows, total, limit, offset)}


def cmd_res(ctx: Ctx, name: str | None = None,
            id: str | None = None,  # noqa: A002 - CLI-facing name
            limit: int = 50, offset: int = 0) -> dict:
    with ctx.project.db() as db:
        if id:
            rid = int(id, 16) if id.startswith("0x") else int(id)
            return {"resource": db.one(
                "SELECT * FROM resources WHERE res_id=?", (rid,))}
        limit, offset = _page(limit, offset)
        rows = db.query(
            "SELECT * FROM resources WHERE name LIKE ? LIMIT ? OFFSET ?",
            (f"%{name or ''}%", limit, offset))
        total = db.one("SELECT COUNT(*) AS n FROM resources "
                       "WHERE name LIKE ?", (f"%{name or ''}%",))["n"]
    return {"resources": rows, **_page_meta(rows, total, limit, offset)}


def cmd_res_refs(ctx: Ctx, id: str,  # noqa: A002
                 limit: int = 100, offset: int = 0) -> dict:
    rid = int(id, 16) if id.startswith("0x") else int(id)
    limit, offset = _page(limit, offset)
    with ctx.project.db() as db:
        rows = db.query(
            "SELECT r.res_id, r.kind, r.dalvik_line, r.smali_line, c.fqcn, "
            "m.name AS method, m.sig FROM resource_refs r JOIN methods m ON "
            "m.id=r.method_id JOIN classes c ON c.id=m.class_id "
            "WHERE r.res_id=? LIMIT ? OFFSET ?", (rid, limit, offset))
        total = db.one("SELECT COUNT(*) AS n FROM resource_refs r "
                       "WHERE r.res_id=?", (rid,))["n"]
    return {"res_id": hex(rid), "refs": rows,
            **_page_meta(rows, total, limit, offset)}


# ------------------------------------------------------------------- session
def cmd_connect(ctx: Ctx, pkg: str | None = None, launch: bool = False,
                activity: str | None = None, timeout: int = 30) -> dict:
    ctx.connect_session(pkg, launch=launch, activity=activity,
                        timeout=timeout)
    return ctx._info


def cmd_bp(ctx: Ctx, spec: str) -> dict:
    return ctx.session.set_breakpoint(spec)


def cmd_bp_del(ctx: Ctx, request_id: int) -> dict:
    return ctx.session.delete_breakpoint(request_id)


def cmd_bp_list(ctx: Ctx, limit: int = 50, offset: int = 0) -> dict:
    limit, offset = _page(limit, offset)
    bps = ctx.session.list_breakpoints()
    page = bps[offset:offset + limit]
    return {"breakpoints": page, **_page_meta(page, len(bps), limit, offset)}


def cmd_events(ctx: Ctx, timeout: float = 60.0) -> dict:
    return ctx.session.wait_events(timeout)


def cmd_read_var(ctx: Ctx, thread: int, name: str | None = None,
                 slot: int | None = None, frame: int = 0) -> dict:
    return ctx.session.read_var(thread, name=name, slot=slot, frame=frame)


def cmd_write_var(ctx: Ctx, thread: int, value, name: str | None = None,
                  slot: int | None = None, frame: int = 0,
                  vtype: str | None = None) -> dict:
    return ctx.session.write_var(thread, value, name=name, slot=slot,
                                 frame=frame, vtype=vtype)


def cmd_invoke(ctx: Ctx, thread: int, obj: int, method: str,
               sig: str = "", args: list | None = None) -> dict:
    return ctx.session.invoke(thread, obj, method, sig, args)


def cmd_step(ctx: Ctx, thread: int, kind: str = "over",
             timeout: float = 30.0) -> dict:
    return ctx.session.step(thread, kind, timeout)


def cmd_resume(ctx: Ctx, thread: int | None = None) -> dict:
    return ctx.session.resume(thread)


def cmd_snapshot(ctx: Ctx, thread: int, depth: int = 3,
                 record: bool = False, run_id: str | None = None,
                 scenario: str | None = None) -> dict:
    s = Snapshotter(ctx.session.client, Budgets(max_depth=depth))
    data = s.snapshot_frame(thread)
    if record:
        _persist_snapshot(ctx, s, data, run_id, scenario,
                          scope={"type": "frame", "frame": data.get("frame"),
                                 "class": data.get("class")})
    return data


def cmd_dump_object(ctx: Ctx, obj: int, depth: int = 3,
                    record: bool = False, run_id: str | None = None,
                    scenario: str | None = None) -> dict:
    s = Snapshotter(ctx.session.client, Budgets(max_depth=depth))
    data = s.dump_object(obj)
    if record:
        _persist_snapshot(ctx, s, data, run_id, scenario,
                          scope={"type": "object",
                                 "class": data.get("cls")})
    return data


def _persist_snapshot(ctx: Ctx, s: Snapshotter, data: dict,
                      run_id: str | None, scenario: str | None,
                      scope: dict) -> None:
    """Persist a snapshot as an artifact (issue #36): under the given run,
    or under a new single-capture run. Adds run_id/artifact_id keys."""
    store = RunStore(ctx.project)
    epoch = ctx.session.events.epoch
    own_run = run_id is None
    if own_run:
        run_id = store.begin_run(
            "snapshot", capture_config={"scope": scope, **s.b.as_dict()},
            scenario=scenario, epoch=epoch,
            environment=capture_environment(ctx.session))
    data["artifact_id"] = s.persist(store, run_id, data, epoch=epoch)
    data["run_id"] = run_id
    if own_run:
        store.end_run(run_id, "completed")


def cmd_cond(ctx: Ctx, spec: str, pred: dict, capture: list[dict],
             max_events: int = 2000, timeout: float = 120.0) -> dict:
    return ConditionalEngine(ctx.session).run(
        spec, pred, capture, max_events=max_events, timeout_s=timeout)


def cmd_hook_crypto(ctx: Ctx, duration: float = 60.0,
                    hooks: list[str] | None = None,
                    returns: bool = False,
                    max_events: int = 1000,
                    max_bytes: int = 1 << 20,
                    defer: bool = False,
                    record: bool = False,
                    scenario: str | None = None) -> dict:
    return crypto_hooks.run_watch(ctx.session, duration_s=duration,
                                  names=hooks, capture_returns=returns,
                                  max_events=max_events,
                                  max_bytes=max_bytes, defer=defer,
                                  record=record, scenario=scenario)


def cmd_coverage(ctx: Ctx, packages: list[str], mode: str = "method",
                 thread: int | None = None, budget: int = 20000,
                 seconds: int = 60, scenario: str | None = None) -> dict:
    return CoverageTracker(ctx.session, packages, mode=mode, thread=thread,
                           budget=budget, seconds=seconds,
                           scenario=scenario).run()


# ---------------------------------------------------------- runs (issue #36)
def cmd_runs(ctx: Ctx, action: str = "list", run_id: str | None = None,
             file: str | None = None, limit: int = 50, offset: int = 0,
             kind: str | None = None, replace: bool = False) -> dict:
    """Run manifests: list (bounded pagination) | get | export | import.
    Export/import preserve the manifest schema version and every
    run/event/artifact relationship."""
    store = RunStore(ctx.project)
    if action == "list":
        limit, offset = _page(limit, offset)
        return store.list_runs(limit=limit, offset=offset, kind=kind)
    if action == "get":
        if not run_id:
            raise SessionError("runs get needs a run_id")
        return store.get_run(run_id)
    if action == "export":
        if not run_id:
            raise SessionError("runs export needs a run_id")
        data = store.export_run(run_id)
        if file:
            Path(file).write_text(
                json.dumps(data, indent=1, ensure_ascii=False), "utf-8")
        return {"run_id": run_id, "file": file, "manifest": data}
    if action == "import":
        if not file:
            raise SessionError("runs import needs --file",
                               hint="path of a `runs export` JSON file")
        data = json.loads(Path(file).read_text("utf-8"))
        return store.import_run(data, replace=replace)
    raise SessionError(f"unknown runs action {action!r}",
                       hint="list | get | export | import")


def cmd_snapshot_diff(ctx: Ctx, a: str, b: str, force: bool = False) -> dict:
    """Structural diff of two persisted snapshot artifacts (ids, or run ids
    with exactly one snapshot artifact). Compatibility is checked first;
    incompatible captures return explicit reasons unless forced."""
    return snapshot_diff(RunStore(ctx.project), a, b, force=force)


def cmd_native(ctx: Ctx, limit: int = 200, offset: int = 0) -> dict:
    """Dual-hex debugging scaffold: report native methods registered in the
    mapping DB and the lldb-server orchestration status (see device/lldb)."""
    limit, offset = _page(limit, offset)
    with ctx.project.db() as db:
        rows = db.query(
            "SELECT c.fqcn, m.name, m.sig FROM methods m JOIN classes c ON "
            "c.id=m.class_id WHERE m.is_native=1 LIMIT ? OFFSET ?",
            (limit, offset))
        total = db.one("SELECT COUNT(*) AS n FROM methods m "
                       "WHERE m.is_native=1")["n"]
    return {"native_methods": rows,
            **_page_meta(rows, total, limit, offset),
            "lldb": "not_implemented",
            "plan": "push lldb-server, `lldb-server platform --listen`, "
                    "suspend VM via JDWP before native attach to avoid races"}


COMMANDS = {
    "init": cmd_init,
    "classes": cmd_classes,
    "methods": cmd_methods,
    "res": cmd_res,
    "res_refs": cmd_res_refs,
    "connect": cmd_connect,
    "bp": cmd_bp,
    "bp_del": cmd_bp_del,
    "bp_list": cmd_bp_list,
    "events": cmd_events,
    "read_var": cmd_read_var,
    "write_var": cmd_write_var,
    "invoke": cmd_invoke,
    "step": cmd_step,
    "resume": cmd_resume,
    "snapshot": cmd_snapshot,
    "dump_object": cmd_dump_object,
    "cond": cmd_cond,
    "hook_crypto": cmd_hook_crypto,
    "coverage": cmd_coverage,
    "runs": cmd_runs,
    "snapshot_diff": cmd_snapshot_diff,
    "native": cmd_native,
}

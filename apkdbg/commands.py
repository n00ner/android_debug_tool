"""Command implementations shared by the CLI and the JSON-RPC server.
Each function takes a Ctx plus kwargs and returns a JSON-native dict."""

from __future__ import annotations

from .core.init_pipeline import run_init
from .core.project import Project
from .debug.conditions import ConditionalEngine
from .debug.coverage import CoverageTracker
from .debug.hooks import crypto as crypto_hooks
from .debug.session import DebugSession
from .debug.snapshot import Budgets, Snapshotter
from .errors import SessionError


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
def cmd_init(ctx: Ctx | None, apk: str, out: str = ".", **kw) -> dict:
    return run_init(apk, out,
                    skip_apktool=kw.get("skip_apktool", False),
                    skip_jadx=kw.get("skip_jadx", False))


# ------------------------------------------------------------------- queries
def cmd_classes(ctx: Ctx, filter: str = "", limit: int = 50) -> dict:
    with ctx.project.db() as db:
        rows = db.query(
            "SELECT fqcn, deobf_fqcn, smali_path FROM classes WHERE fqcn LIKE "
            "? OR deobf_fqcn LIKE ? LIMIT ?", (f"%{filter}%",) * 2 + (limit,))
    return {"classes": rows, "count": len(rows)}


def cmd_methods(ctx: Ctx, class_: str, limit: int = 100) -> dict:
    with ctx.project.db() as db:
        rows = db.query(
            "SELECT m.name, m.sig, m.is_native FROM methods m JOIN classes c "
            "ON c.id=m.class_id WHERE c.fqcn=? OR c.deobf_fqcn=? OR c.sig=? "
            "LIMIT ?", (class_, class_, class_, limit))
    return {"methods": rows}


def cmd_res(ctx: Ctx, name: str | None = None,
            id: str | None = None) -> dict:  # noqa: A002 - CLI-facing name
    with ctx.project.db() as db:
        if id:
            rid = int(id, 16) if id.startswith("0x") else int(id)
            return {"resource": db.one(
                "SELECT * FROM resources WHERE res_id=?", (rid,))}
        rows = db.query("SELECT * FROM resources WHERE name LIKE ? LIMIT 50",
                        (f"%{name or ''}%",))
        return {"resources": rows}


def cmd_res_refs(ctx: Ctx, id: str) -> dict:  # noqa: A002
    rid = int(id, 16) if id.startswith("0x") else int(id)
    with ctx.project.db() as db:
        rows = db.query(
            "SELECT r.res_id, r.kind, r.dalvik_line, r.smali_line, c.fqcn, "
            "m.name AS method, m.sig FROM resource_refs r JOIN methods m ON "
            "m.id=r.method_id JOIN classes c ON c.id=m.class_id "
            "WHERE r.res_id=? LIMIT 100", (rid,))
    return {"res_id": hex(rid), "refs": rows}


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


def cmd_bp_list(ctx: Ctx) -> dict:
    return {"breakpoints": ctx.session.list_breakpoints()}


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


def cmd_snapshot(ctx: Ctx, thread: int, depth: int = 3) -> dict:
    s = Snapshotter(ctx.session.client, Budgets(max_depth=depth))
    return s.snapshot_frame(thread)


def cmd_dump_object(ctx: Ctx, obj: int, depth: int = 3) -> dict:
    s = Snapshotter(ctx.session.client, Budgets(max_depth=depth))
    return s.dump_object(obj)


def cmd_cond(ctx: Ctx, spec: str, pred: dict, capture: list[dict],
             max_events: int = 2000, timeout: float = 120.0) -> dict:
    return ConditionalEngine(ctx.session).run(
        spec, pred, capture, max_events=max_events, timeout_s=timeout)


def cmd_hook_crypto(ctx: Ctx, duration: float = 60.0,
                    hooks: list[str] | None = None,
                    returns: bool = False,
                    max_events: int = 1000,
                    max_bytes: int = 1 << 20,
                    defer: bool = False) -> dict:
    return crypto_hooks.run_watch(ctx.session, duration_s=duration,
                                  names=hooks, capture_returns=returns,
                                  max_events=max_events,
                                  max_bytes=max_bytes, defer=defer)


def cmd_coverage(ctx: Ctx, packages: list[str], mode: str = "method",
                 thread: int | None = None, budget: int = 20000,
                 seconds: int = 60) -> dict:
    return CoverageTracker(ctx.session, packages, mode=mode, thread=thread,
                           budget=budget, seconds=seconds).run()


def cmd_native(ctx: Ctx) -> dict:
    """Dual-hex debugging scaffold: report native methods registered in the
    mapping DB and the lldb-server orchestration status (see device/lldb)."""
    with ctx.project.db() as db:
        rows = db.query(
            "SELECT c.fqcn, m.name, m.sig FROM methods m JOIN classes c ON "
            "c.id=m.class_id WHERE m.is_native=1 LIMIT 200")
    return {"native_methods": rows, "count": len(rows),
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
    "native": cmd_native,
}

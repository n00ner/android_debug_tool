"""Command implementations shared by the CLI and the JSON-RPC server.
Each function takes a Ctx plus kwargs and returns a JSON-native dict."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from .core.aliases import AliasStore, accepted_alias_map
from .core.init_pipeline import run_init
from .core.capabilities import collect as collect_capabilities, index_facts
from .core.manifests import RunStore, capture_environment
from .core.project import Project
from .debug.aliascollect import AliasCollector
from .debug.conditions import ConditionalEngine
from .debug.coverage import CoverageTracker
from .debug.hooks import crypto as crypto_hooks
from .debug.hooks import framework as framework_hooks
from .debug.hooks import strings as string_hooks
from .debug.session import DebugSession
from .debug.snapdiff import snapshot_diff
from .debug.snapshot import Budgets, Snapshotter
from .errors import ExportIncompleteError, SessionError


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
def _index_note(db, count: int) -> dict | None:
    """Precise explanation when a query comes back empty: distinguish 'the
    index genuinely has no such rows' from 'the index is incomplete'."""
    if count:
        return None
    facts = index_facts(db)
    note = {"table_empty": True, "index_complete": facts["complete"],
            "line_map": facts["line_map"],
            "hint": "run 'capabilities' for the full index/capability report"}
    if facts["warnings"]:
        note["warnings"] = facts["warnings"][:5]
    return note


def cmd_classes(ctx: Ctx, filter: str = "", limit: int = 50,
                offset: int = 0) -> dict:
    limit, offset = _page(limit, offset)
    args = (f"%{filter}%",) * 2
    where = "WHERE fqcn LIKE ? OR deobf_fqcn LIKE ?"
    with ctx.project.db() as db:
        rows = db.query(
            "SELECT sig, fqcn, deobf_fqcn, smali_path FROM classes " + where +
            " LIMIT ? OFFSET ?", args + (limit, offset))
        total = db.one("SELECT COUNT(*) AS n FROM classes " + where,
                       args)["n"]
        # accepted runtime aliases (issue #25): additive annotation next to
        # fqcn/deobf_fqcn — the original sig/fqcn identity is untouched
        aliases = accepted_alias_map(db, [r["sig"] for r in rows])
        note = _index_note(db, total)
    for r in rows:
        r["alias"] = aliases.get(r["sig"])
    out = {"classes": rows, **_page_meta(rows, total, limit, offset)}
    if note:
        out["index_note"] = note
    return out


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
        note = _index_note(db, total)
    out = {"methods": rows, **_page_meta(rows, total, limit, offset)}
    if note:
        out["index_note"] = note
    return out


def cmd_res(ctx: Ctx, name: str | None = None,
            id: str | None = None,  # noqa: A002 - CLI-facing name
            limit: int = 50, offset: int = 0) -> dict:
    with ctx.project.db() as db:
        if id:
            rid = int(id, 16) if id.startswith("0x") else int(id)
            row = db.one("SELECT * FROM resources WHERE res_id=?", (rid,))
            out = {"resource": row}
            note = _index_note(db, 1 if row else 0)
            if note:
                out["index_note"] = note
            return out
        limit, offset = _page(limit, offset)
        rows = db.query(
            "SELECT * FROM resources WHERE name LIKE ? LIMIT ? OFFSET ?",
            (f"%{name or ''}%", limit, offset))
        total = db.one("SELECT COUNT(*) AS n FROM resources "
                       "WHERE name LIKE ?", (f"%{name or ''}%",))["n"]
        note = _index_note(db, total)
    out = {"resources": rows, **_page_meta(rows, total, limit, offset)}
    if note:
        out["index_note"] = note
    return out


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
        note = _index_note(db, total)
    out = {"res_id": hex(rid), "refs": rows,
           **_page_meta(rows, total, limit, offset)}
    if note:
        out["index_note"] = note
    return out


# -------------------------------------------------------------- capabilities
def cmd_capabilities(ctx: Ctx, probe: bool = False) -> dict:
    """Offline capability matrix for this project/APK. With probe=True, adds
    live (transient) observations: device/process presence, JDWP attach,
    runtime line-table availability."""
    return collect_capabilities(ctx.project, probe_live=probe,
                                serial=ctx.serial)


# ------------------------------------------------------------------- session
def cmd_connect(ctx: Ctx, pkg: str | None = None, launch: bool = False,
                activity: str | None = None, timeout: int = 30,
                recovery: str | None = None) -> dict:
    """recovery: omit for session-scoped recovery only; "kill-server"
    explicitly allows a global adb server restart as a last resort
    (affects every attached device/session — never a silent fallback)."""
    ctx.connect_session(pkg, launch=launch, activity=activity,
                        timeout=timeout, recovery=recovery)
    return ctx._info


def cmd_restore(ctx: Ctx, defer: bool = True) -> dict:
    """Re-install symbolic breakpoint/hook definitions on the current
    connection (issue #32). Use after a reconnect or a process restart +
    connect; reports per-item installed (NEW request ids) / pending /
    failed — ids from a previous epoch are never revived."""
    return ctx.session.restore_requests(defer=defer)


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
                 scenario: str | None = None,
                 collect_aliases: bool = False) -> dict:
    s = Snapshotter(ctx.session.client, Budgets(max_depth=depth))
    data = s.snapshot_frame(thread)
    _annotate_alias(ctx, data, data.get("class"))
    if record or collect_aliases:
        # collecting implies recording: candidates need run/artifact evidence
        _persist_snapshot(ctx, s, data, run_id, scenario,
                          scope={"type": "frame", "frame": data.get("frame"),
                                 "class": data.get("class")})
    if collect_aliases:
        _collect_snapshot_aliases(ctx, data)
    return data


def cmd_dump_object(ctx: Ctx, obj: int, depth: int = 3,
                    record: bool = False, run_id: str | None = None,
                    scenario: str | None = None,
                    collect_aliases: bool = False) -> dict:
    s = Snapshotter(ctx.session.client, Budgets(max_depth=depth))
    data = s.dump_object(obj)
    _annotate_alias(ctx, data, data.get("cls"))
    if record or collect_aliases:
        _persist_snapshot(ctx, s, data, run_id, scenario,
                          scope={"type": "object",
                                 "class": data.get("cls")})
    if collect_aliases:
        _collect_snapshot_aliases(ctx, data)
    return data


def _annotate_alias(ctx: Ctx, data: dict, sig: str | None) -> None:
    """Additive "alias" field next to the original class identity
    (issue #25): the accepted runtime alias, never a replacement."""
    with ctx.project.db() as db:
        data["alias"] = accepted_alias_map(db, [sig]).get(sig) if sig else None


def _collect_snapshot_aliases(ctx: Ctx, data: dict) -> None:
    """Feed the already-captured snapshot tree to the alias collector
    (issue #25) and attach its measured report."""
    collector = AliasCollector(ctx.session, store=AliasStore(ctx.project))
    collector.collect_from_snapshot(
        data, {"class_sig": data.get("class") or data.get("cls"),
               "epoch": ctx.session.events.epoch},
        run_id=data.get("run_id"), artifact_id=data.get("artifact_id"))
    data["alias_collection"] = collector.report()


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
             max_events: int = 2000, timeout: float = 120.0,
             collect_aliases: bool = False) -> dict:
    return ConditionalEngine(ctx.session).run(
        spec, pred, capture, max_events=max_events, timeout_s=timeout,
        collect_aliases=collect_aliases)


def cmd_hook_crypto(ctx: Ctx, duration: float = 60.0,
                    hooks: list[str] | None = None,
                    returns: bool = False,
                    max_events: int = 1000,
                    max_bytes: int = 1 << 20,
                    defer: bool = False,
                    record: bool = False,
                    scenario: str | None = None,
                    collect_aliases: bool = False) -> dict:
    return crypto_hooks.run_watch(ctx.session, duration_s=duration,
                                  names=hooks, capture_returns=returns,
                                  max_events=max_events,
                                  max_bytes=max_bytes, defer=defer,
                                  record=record, scenario=scenario,
                                  collect_aliases=collect_aliases)


# ---------------------------------------------------- string watchers (issue #26)
def cmd_watch_strings(ctx: Ctx, duration: float = 60.0,
                      profiles: list | None = None,
                      mode: str = "attributed",
                      scope: str | None = None,
                      text_regex: str | None = None,
                      min_printable: float = 0.0,
                      dedupe: bool = True,
                      max_events: int = 1000,
                      max_reads: int = 5000,
                      max_output_bytes: int = 1 << 20,
                      max_queue: int = 64,
                      max_stack: int = 8,
                      max_str: int = 512,
                      thread: int | None = None,
                      mod_count: int | None = None,
                      defer: bool = False,
                      record: bool = False,
                      scenario: str | None = None,
                      collect_aliases: bool = False) -> dict:
    """Scoped string watchers: producer-return and consumer-argument
    observation points with explicit capture modes. profiles: builtin names
    and/or explicit {"cls","method","sig"} objects (default: the opt-in
    stringbuilder.tostring profile)."""
    return string_hooks.run_watch(
        ctx.session, profiles=profiles, mode=mode, duration_s=duration,
        scope=scope, text_regex=text_regex, min_printable=min_printable,
        dedupe=dedupe, max_events=max_events, max_reads=max_reads,
        max_output_bytes=max_output_bytes, max_queue=max_queue,
        max_stack=max_stack, max_str=max_str, thread=thread,
        mod_count=mod_count, defer=defer, record=record,
        scenario=scenario, collect_aliases=collect_aliases)


def cmd_strings(ctx: Ctx, run_id: str | None = None,
                profile: str | None = None, mode: str | None = None,
                text: str | None = None, limit: int = 50,
                offset: int = 0) -> dict:
    """Offline query over persisted string-watch records (bounded
    pagination, substring text filter)."""
    limit, offset = _page(limit, offset)
    return string_hooks.query_records(
        ctx.project, run_id=run_id, profile=profile, mode=mode, text=text,
        limit=limit, offset=offset)


# --------------------------------------------- framework watchers (issue #27)
def cmd_watch_framework(ctx: Ctx, duration: float = 60.0,
                        families: list | None = None,
                        profiles: list | None = None,
                        mode: str = "attributed",
                        scope: str | None = None,
                        exclude: list | None = None,
                        invoke_getters: bool = False,
                        corr_window_ms: int = 250,
                        max_events: int = 1000,
                        max_reads: int = 5000,
                        max_output_bytes: int = 1 << 20,
                        max_queue: int = 64,
                        max_stack: int = 8,
                        max_str: int = 512,
                        thread: int | None = None,
                        mod_count: int | None = None,
                        defer: bool = False,
                        record: bool = False,
                        scenario: str | None = None) -> dict:
    """Opt-in framework watcher profiles (issue #27): navigation requests,
    SharedPreferences edits, and system-service lookups at the framework
    methods actually hooked — observation points with explicit coverage
    notes, never full-coverage claims. families: navigation | storage |
    services (default all three); profiles narrows/extends with builtin
    names or explicit {"cls","method","sig"} objects."""
    return framework_hooks.run_watch(
        ctx.session, profiles=profiles, families=families, mode=mode,
        duration_s=duration, scope=scope, exclude=exclude,
        invoke_getters=invoke_getters, corr_window_ms=corr_window_ms,
        max_events=max_events, max_reads=max_reads,
        max_output_bytes=max_output_bytes, max_queue=max_queue,
        max_stack=max_stack, max_str=max_str, thread=thread,
        mod_count=mod_count, defer=defer, record=record,
        scenario=scenario)


def cmd_framework_events(ctx: Ctx, run_id: str | None = None,
                         family: str | None = None,
                         profile: str | None = None,
                         role: str | None = None, limit: int = 50,
                         offset: int = 0) -> dict:
    """Offline query over persisted framework-watch records (bounded
    pagination; filters: run, profile family, source profile, role)."""
    limit, offset = _page(limit, offset)
    return framework_hooks.query_events(
        ctx.project, run_id=run_id, family=family, profile=profile,
        role=role, limit=limit, offset=offset)


def cmd_coverage(ctx: Ctx, packages: list[str], mode: str = "method",
                 thread: int | None = None, budget: int = 20000,
                 seconds: int = 60, scenario: str | None = None) -> dict:
    rep = CoverageTracker(ctx.session, packages, mode=mode, thread=thread,
                          budget=budget, seconds=seconds,
                          scenario=scenario).run()
    # accepted runtime aliases (issue #25): additive {sig: alias} annotation
    sigs = [k.split("->", 1)[0] for k in
            (rep.get("methods") or rep.get("lines") or {})]
    if sigs:
        with ctx.project.db() as db:
            rep["aliases"] = accepted_alias_map(db, sigs)
    return rep


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


# ------------------------------------------------- buffer export (issue #38)
def cmd_export_buffer(ctx: Ctx, obj: int, epoch: int, source: str = "auto",
                      offset: int | None = None, length: int | None = None,
                      dest: str | None = None,
                      max_bytes: int = 16 << 20, chunk_size: int = 1 << 16,
                      deadline: float | None = None, capped: bool = False,
                      keep_partial: bool = False, record: bool = False,
                      run_id: str | None = None, scenario: str | None = None,
                      event_id: str | None = None) -> dict:
    """Bounded binary export of a byte[] or heap ByteBuffer (pure reads, no
    target mutation). offset/length are array indices for arrays and
    relative to the buffer position for ByteBuffers (default range:
    [position, limit)). dest defaults to <project>/exports/buffer-<id>.bin;
    bytes go to a temp file published by atomic rename on success. With
    record/run_id the export metadata (sha256, byte count, source range,
    completeness) is persisted as a run artifact referencing the file.
    Incomplete outcomes (deadline/disconnect/disk-full) remove the partial
    temp file unless keep_partial and are never reported as complete."""
    if dest is None:
        dest = str(ctx.project.root / "exports"
                   / f"buffer-{uuid.uuid4().hex[:12]}.bin")
    session = ctx.session
    store = RunStore(ctx.project) if (record or run_id) else None
    own_run = run_id is None
    if store and own_run:
        run_id = store.begin_run(
            "buffer_export",
            capture_config={"obj": obj, "epoch": epoch, "source": source,
                            "offset": offset, "length": length,
                            "max_bytes": max_bytes, "chunk_size": chunk_size,
                            "capped": capped},
            scenario=scenario, epoch=session.events.epoch,
            environment=capture_environment(session))
    try:
        res = session.export_buffer(
            obj, epoch, source=source, offset=offset, length=length,
            dest=dest, max_bytes=max_bytes, chunk_size=chunk_size,
            deadline=deadline, capped=capped, keep_partial=keep_partial)
    except ExportIncompleteError as e:
        if store:
            store.add_artifact(
                run_id, "buffer_export",
                {"complete": False, "file": e.context.get("partial_file"),
                 "error": e.to_dict()},
                format="json", errors=[e.to_dict()],
                parent_event_id=event_id, epoch=session.events.epoch)
        if store and own_run:
            store.end_run(run_id, "failed")
        raise
    except Exception:
        if store and own_run:
            store.end_run(run_id, "failed")
        raise
    if store:
        res["artifact_id"] = store.add_artifact(
            run_id, "buffer_export", res, format="json",
            parent_event_id=event_id, epoch=session.events.epoch)
        res["run_id"] = run_id
        if own_run:
            store.end_run(run_id, "completed",
                          counts={"bytes": res["bytes"]["exported"]})
    res["epoch"] = session.events.epoch
    return res


# -------------------------------------------------------- aliases (issue #25)
def cmd_aliases(ctx: Ctx, action: str = "list",
                candidate_id: str | None = None,
                class_sig: str | None = None, alias: str | None = None,
                method: str | None = None, method_sig: str | None = None,
                status: str | None = None, filter: str | None = None,
                note: str | None = None, file: str | None = None,
                limit: int = 50, offset: int = 0,
                all_apks: bool = False) -> dict:
    """Review runtime alias candidates: list (bounded pagination) | get |
    accept | reject | revise | add (manual alias) | export. Candidates are
    evidence-backed heuristic annotations stored separately from
    classes.deobf_fqcn and imported mappings; accepting one never changes
    method resolution or breakpoint targeting. Retention: rows live in the
    project mapping.db, are carried across re-indexing, and may contain
    application data — treat exports as sensitive."""
    store = AliasStore(ctx.project)
    if action == "list":
        limit, offset = _page(limit, offset)
        return store.list(status=status, q=filter, class_sig=class_sig,
                          all_apks=all_apks, limit=limit, offset=offset)
    if action == "get":
        if not candidate_id:
            raise SessionError("aliases get needs a candidate_id")
        return store.get(candidate_id)
    if action == "accept":
        if not candidate_id:
            raise SessionError("aliases accept needs a candidate_id")
        return store.accept(candidate_id, note=note)
    if action == "reject":
        if not candidate_id:
            raise SessionError("aliases reject needs a candidate_id")
        return store.reject(candidate_id, note=note)
    if action == "revise":
        if not candidate_id or not alias:
            raise SessionError("aliases revise needs candidate_id and --alias",
                               hint="the replacement alias text")
        return store.revise(candidate_id, alias, note=note)
    if action == "add":
        if not class_sig or not alias:
            raise SessionError("aliases add needs --class-sig and --alias",
                               hint="class_sig is the original runtime "
                                    "descriptor, e.g. Lcom/foo/Bar;")
        return store.add_alias(class_sig, alias, method_name=method,
                               method_sig=method_sig, note=note)
    if action == "export":
        data = store.export()
        if file:
            Path(file).write_text(
                json.dumps(data, indent=1, ensure_ascii=False), "utf-8")
        return {"file": file, "candidates": len(data["candidates"]),
                "manifest": data}
    raise SessionError(f"unknown aliases action {action!r}",
                       hint="list | get | accept | reject | revise | add | "
                            "export")


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
    "capabilities": cmd_capabilities,
    "connect": cmd_connect,
    "restore": cmd_restore,
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
    "watch_strings": cmd_watch_strings,
    "strings": cmd_strings,
    "watch_framework": cmd_watch_framework,
    "framework_events": cmd_framework_events,
    "coverage": cmd_coverage,
    "runs": cmd_runs,
    "snapshot_diff": cmd_snapshot_diff,
    "export_buffer": cmd_export_buffer,
    "aliases": cmd_aliases,
    "native": cmd_native,
}

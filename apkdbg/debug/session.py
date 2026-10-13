"""DebugSession — owns ADB + JDWP connection lifecycle and all runtime ops.

Recovery policy (issue #32): every public op goes through _op() with an
explicit safety class:

  read        no VM-side effects. Ops that re-derive their inputs from
              symbolic state on every attempt (wait_events) RETRY once
              after a scoped reconnect. Ops taking numeric handles
              (read_var's thread/frame ids, _sig_of's type id) NEVER
              auto-retry across an epoch: the new connection may reuse the
              id for an unrelated object, so the caller gets an actionable
              StaleHandleError instead of data from the wrong target.
  idempotent  the mutation dies with the connection (JDWP event requests
              are cleared when the transport breaks), so a post-reconnect
              replay cannot duplicate an effect — set_breakpoint and
              clear_request retry once.
  state       invoke, write_var, resume, vm_resume, step. When the fault
              could have occurred after the command reached the VM (fault
              phase transmit/post-send) the op is NEVER replayed: the
              caller gets OutcomeUnknownError (outcome "unknown") carrying
              the op name, connection epoch, and recovery state. The same
              applies when ANY state-changing packet of the op was already
              dispatched (client.state_dispatched moved): a later packet
              failing pre-dispatch (e.g. result decoding after a
              successful invoke) cannot undo it. A replay happens only
              when the fault is pre-dispatch AND nothing state-changing
              left the host during the whole op — and only for ops without
              numeric handles: thread/object ids die with the epoch, so a
              handle-carrying op gets StaleHandleError (re-acquire fresh
              ids, re-issue) instead of a blind replay.

Op call sites pass _class=/_name=/_reresolve=/_handles= to _op(); the
defaults (read, no re-resolve, no handles) are the conservative choice.

Recovery is SCOPED to this session: a failed op rebuilds only this
session's forward listener and (at most) `adb reconnect`s this device.
Another session's forward and the global adb server are never touched;
kill-server runs only when connect(recovery="kill-server") explicitly
opted in. A pid change is not a transport failure: ProcessDiedError
tells the caller a full re-attach plus restore is required.

Event ownership lives in the per-session EventDispatcher (session.events,
see debug/dispatcher.py): request ids are registered with an owner, event
kind, and epoch stamp; _attach bumps the epoch so handles from a previous
connection are dead even when the new connection reuses numeric ids.
bp_registry remains the request_id -> meta store (compatibility view) and
holds live entries of the current epoch only.
"""

from __future__ import annotations

import time
from typing import Callable

from ..core.project import Project
from ..core.capabilities import index_facts
from ..device.adb import Adb
from ..device.jdwp import (
    EVK_BREAKPOINT, EVK_SINGLE_STEP, SP_ALL, SP_EVENT_THREAD,
    STEP_INTO, STEP_LINE, STEP_OUT, STEP_OVER,
    JdwpClient, JdwpConnError, JdwpError, sig_to_tag, TAG_STRING,
)
from ..errors import (
    AttachUnavailableError, LineMappingError, OutcomeUnknownError,
    ProcessDiedError, ResolveError, SessionError, StaleHandleError,
)
from ..protocol import log_progress
from . import buffers, translate
from .dispatcher import EventDispatcher

STEP_KINDS = {"into": STEP_INTO, "over": STEP_OVER, "out": STEP_OUT}

# op safety classes for _op() (issue #32)
OP_READ, OP_IDEMPOTENT, OP_STATE = "read", "idempotent", "state"


class DebugSession:
    def __init__(self, project: Project, serial: str | None = None):
        self.project = project
        self.adb = Adb(serial)
        self.client: JdwpClient | None = None
        self.pkg: str | None = None
        self.pid: int | None = None
        self.port: int | None = None
        self.bp_registry: dict[int, dict] = {}   # request_id -> meta
        self._sig_cache: dict[int, str] = {}     # type_id -> signature

    @property
    def events(self) -> EventDispatcher:
        """Per-session event dispatcher (lazy so __new__-built test
        sessions get one on first use)."""
        d = self.__dict__.get("_dispatcher")
        if d is None:
            d = self.__dict__["_dispatcher"] = EventDispatcher(self)
        return d

    # ------------------------------------------------------------------ conn
    def connect(self, package: str, *, launch: bool = False,
                activity: str | None = None, timeout: int = 30,
                recovery: str | None = None) -> dict:
        """recovery: explicit escalation policy. Default (None) keeps
        recovery scoped to this session — our own forward listener plus
        `adb reconnect` for this device only. "kill-server" additionally
        allows a global adb server restart as a last resort; it affects
        every attached device and debug session, so it must be requested
        explicitly and is never a silent fallback."""
        if recovery not in (None, "kill-server"):
            raise SessionError(f"unknown recovery policy {recovery!r}",
                               hint="omit it, or pass "
                                    "recovery='kill-server'")
        self.adb.ensure_device()
        if launch:
            self.adb.force_stop(package)
            self.adb.launch_debug(package, activity)
        pid = self.adb.wait_pid(package, timeout=timeout)
        port = self.adb.forward_jdwp(pid)
        self.pkg, self.pid, self.port = package, pid, port
        self._attach(allow_global_restart=recovery == "kill-server")
        return {"package": package, "pid": pid, "port": port,
                "vm": self.client.handshake_info.get("vm_name"),
                "jdwp": f"{self.client.handshake_info.get('jdwp_major')}."
                        f"{self.client.handshake_info.get('jdwp_minor')}"}

    def _attach(self, *, allow_global_restart: bool = False) -> None:
        """Handshake with SCOPED recovery: plain re-attach, then `adb
        reconnect` for this device plus a rebuild of this session's own
        forward listener (stale jdwp state survives unclean debugger
        disconnects; observed on MIUI). Other sessions' forwards are never
        removed, and the global adb server is never restarted unless the
        caller explicitly opted in (connect(recovery="kill-server"))."""
        # request IDs and type IDs are per-connection: drop stale state
        self.bp_registry.clear()
        self._sig_cache.clear()
        self.events.bump_epoch()
        last: JdwpConnError | None = None
        levels = [None, "reconnect"]
        if allow_global_restart:
            levels.append("kill-server")
        for level in levels:
            if level:
                log_progress(f"JDWP attach recovery: {level}")
                getattr(self.adb, level.replace("-", "_"))()
                self.adb.wait_for_device()
                self.adb.remove_forward(self.port)
                self.adb.forward_jdwp(self.pid, self.port)
            if self.client:
                self.client.close()
            self.client = JdwpClient("127.0.0.1", self.port)
            try:
                self.client.connect()
                return
            except JdwpConnError as e:
                last = e
        raise AttachUnavailableError(
            f"JDWP attach failed after recovery attempts: {last}",
            hint="the VM refused the JDWP handshake — the app may be "
                 "non-debuggable (android:debuggable=false on a "
                 "ro.debuggable=0 device), or a previous debugger detached "
                 "uncleanly; run 'capabilities --probe' for live observations",
            package=self.pkg, pid=self.pid) from last

    def _op(self, fn: Callable, *args, _class: str = OP_READ,
            _name: str | None = None, _reresolve: bool = False,
            _handles: bool = False, **kwargs):
        """Run fn(self.client, ...) under the class-based recovery policy
        documented in the module docstring. _name names the op in
        structured errors; _reresolve marks a read whose inputs are fully
        re-derived from symbolic state on every attempt (only then is a
        read retried across an epoch boundary); _handles marks an op whose
        inputs are numeric per-connection ids (thread/object/frame), which
        are dead after a reconnect even when nothing was dispatched."""
        # duck-typed test doubles do not model packet-level tracking
        dispatched = getattr(self.client, "state_dispatched", 0)
        try:
            return fn(self.client, *args, **kwargs)
        except JdwpConnError as e:
            return self._recover_op(e, fn, args, kwargs, _class, _name,
                                    _reresolve, _handles, dispatched)

    def _recover_op(self, err: JdwpConnError, fn: Callable, args, kwargs,
                    op_class: str, name: str | None, reresolve: bool,
                    handles: bool, dispatched: int):
        op = name or getattr(fn, "__name__", "op")
        # untagged conn errors are treated as post-send (conservative)
        phase = err.context.get("phase") or "post-send"
        # the failing packet's phase alone says nothing about EARLIER
        # packets of the same op: once any state-changing command was
        # dispatched, the mutation may already be applied (issue #32)
        mutated = (getattr(self.client, "state_dispatched", 0)
                   != dispatched)
        epoch_before = self.events.epoch
        # Process restart is NOT a transport failure (issue #32): every
        # handle, frame, and event request is gone — reconnecting the old
        # forward would debug a different process incarnation.
        if self.pid:
            pid = self.adb.pidof(self.pkg)
            if pid != self.pid:
                raise ProcessDiedError(
                    f"target process died (pid {self.pid} -> {pid})",
                    op=op, epoch=epoch_before,
                    pid_old=self.pid, pid_new=pid) from err
        # Scoped recovery: only this session's forward listener is rebuilt.
        recovery = "not attempted (no live target)"
        if self.pid:
            try:
                log_progress("JDWP connection lost; scoped reconnect")
                self.adb.remove_forward(self.port)
                self.adb.forward_jdwp(self.pid, self.port)
                self._attach()
                recovery = (f"reconnected (epoch {epoch_before} -> "
                            f"{self.events.epoch})")
            except JdwpConnError as rec:
                recovery = f"reconnect failed: {rec}"
        # A state-changing op whose command may have reached the VM is
        # never replayed — report UNKNOWN instead of guessing either way.
        uncertain = op_class == OP_STATE and (mutated
                                              or phase != "pre-dispatch")
        if uncertain:
            raise OutcomeUnknownError(
                op, phase=phase, epoch=epoch_before,
                epoch_new=self.events.epoch
                if recovery.startswith("reconnected") else None,
                recovery=recovery) from err
        if not recovery.startswith("reconnected"):
            raise err
        if op_class == OP_READ and not reresolve:
            # numeric handles died with the old epoch even when nothing
            # was sent; replaying could address an unrelated object whose
            # id the new connection reused
            raise StaleHandleError(op, epoch=epoch_before) from err
        if op_class == OP_STATE and handles:
            # provably undispatched, but the op's numeric thread/object
            # ids died with the old epoch: the caller must re-acquire
            # fresh handles and re-issue — never a blind replay
            raise StaleHandleError(op, epoch=epoch_before) from err
        return fn(self.client, *args, **kwargs)

    def close(self) -> None:
        if self.client:
            self.client.close()
        if self.port:
            self.adb.remove_forward(self.port)

    # ------------------------------------------------------------ breakpoints
    def set_breakpoint(self, spec: str, *, suspend_all: bool = True) -> dict:
        """Java class:line -> dalvik line -> runtime LineNumberTable index ->
        JDWP BREAKPOINT request. Exact translation logic:

          1. translate.resolve(): spec -> (runtime sig, dalvik_line, methods)
          2. VirtualMachine.ClassesBySignature(sig) -> loaded class ids
          3. ReferenceType.Methods -> method ids
          4. Method.LineTable -> entries where lineNumber == dalvik_line;
             breakpoint index = the smallest lineCodeIndex of those entries
             (the first real instruction of the source line)
          5. EventRequest.Set(BREAKPOINT, suspend, [LocationOnly(location)])
        """
        with self.project.db() as db:
            lm = index_facts(db)["line_map"]
            if lm["state"] != "complete":
                raise LineMappingError(
                    f"source-line breakpoint requires a verified "
                    f"source-to-runtime line map (state={lm['state']}, "
                    f"reason={lm['reason']})",
                    hint="the static line map is empty or incomplete — a "
                         "java:line cannot be verified against .line "
                         "directives; use smali/method-entry coordinates "
                         "instead, or re-run init and check 'capabilities' "
                         "for the recorded reason",
                    line_map_state=lm["state"], line_map_reason=lm["reason"])
            res = translate.resolve(db, spec)
        placed = self._place(res, spec, suspend_all)
        return {"resolved": res, "breakpoints": placed}

    def _place(self, res: dict, spec: str, suspend_all: bool) -> list[dict]:
        """Resolve a translated spec against the CURRENT connection
        (loaded classes, method ids, LineNumberTable) and install the
        breakpoint request(s). Op class "idempotent": JDWP event requests
        die with the connection, so a post-reconnect replay of a
        half-finished placement cannot duplicate a request. Used by
        set_breakpoint and by restore_requests (which re-runs it from the
        symbolic definition)."""
        def do(c: JdwpClient):
            classes = c.classes_by_signature(res["sig"])
            if not classes:
                raise ResolveError(
                    f"class not loaded in VM: {res['sig']}",
                    hint="the class loads lazily — navigate the app to touch "
                         "it, or set a CLASS_PREPARE watch first")
            placed = []
            wanted = {(m["name"], m["sig"]) for m in res["methods"]} or None
            for cls in classes:
                for m in c.rt_methods(cls["type_id"]):
                    if wanted and (m["name"], m["sig"]) not in wanted:
                        continue
                    lt = c.method_line_table(cls["type_id"], m["id"])
                    idx = min((e["index"] for e in lt["lines"]
                               if e["line"] == res["dalvik_line"]),
                              default=None)
                    if idx is None:
                        continue
                    rid = c.set_breakpoint(
                        cls["type_id"], m["id"], idx,
                        SP_ALL if suspend_all else SP_EVENT_THREAD)
                    meta = {"request_id": rid, "class": res["class"],
                            "method": m["name"], "method_sig": m["sig"],
                            "java_line": res["java_line"],
                            "dalvik_line": res["dalvik_line"],
                            "bytecode_index": idx, "spec": spec,
                            "smali": res["smali"],
                            "owner": "user", "kind": EVK_BREAKPOINT,
                            "suspend_policy": SP_ALL if suspend_all
                            else SP_EVENT_THREAD,
                            "entry": "source"}
                    self.events.register(rid, meta)
                    placed.append(meta)
            if not placed:
                raise ResolveError(
                    f"line {res['java_line']} has no executable bytecode index "
                    f"in {res['class']} (runtime LineNumberTable has no entry "
                    f"for dalvik line {res['dalvik_line']})",
                    hint="adjacent lines: " + self._nearby_lines(res))
            return placed
        placed = self._op(do, _class=OP_IDEMPOTENT, _name="set_breakpoint")
        self.events.define_source(spec, res, suspend_all)
        return placed

    def _nearby_lines(self, res: dict) -> str:
        with self.project.db() as db:
            rows = db.query(
                "SELECT DISTINCT dalvik_line FROM line_map lm JOIN methods m "
                "ON m.id=lm.method_id JOIN classes c ON c.id=m.class_id "
                "WHERE c.sig=? AND dalvik_line BETWEEN ? AND ? LIMIT 8",
                (res["sig"], res["dalvik_line"] - 5, res["dalvik_line"] + 5))
        return ", ".join(str(r["dalvik_line"]) for r in rows) or "none"

    def delete_breakpoint(self, request_id: int) -> dict:
        """Clear a breakpoint. Non-BREAKPOINT entries are cleared with
        their registered kind (same path as clear_request): clearing a
        method-exit hook as BREAKPOINT would leave the real request armed."""
        return self.clear_request(request_id)

    def clear_request(self, request_id: int) -> dict:
        """Clear an event request with the event kind it was registered
        under (defaults to BREAKPOINT for untracked ids). Only LIVE entries
        of the current epoch are touched: after a reconnect a stale numeric
        id may belong to an unrelated request of the new connection, so the
        remote state is left alone and reported as unconfirmed."""
        meta = self.bp_registry.get(request_id)
        kind = (meta or {}).get("kind", EVK_BREAKPOINT)
        if not self.events.is_live(meta):
            return {"cleared": request_id, "kind": kind,
                    "was": self.events.unregister(request_id),
                    "status": "unconfirmed",
                    "note": "no live request with this id in the current "
                            "connection epoch; remote state left untouched"}
        def do(c: JdwpClient):
            c.clear_event(kind, request_id)
        self._op(do, _class=OP_IDEMPOTENT, _name="clear_request")
        was = self.events.unregister(request_id)
        return {"cleared": request_id, "kind": kind, "was": was,
                "status": "confirmed"}

    def list_breakpoints(self) -> list[dict]:
        return list(self.bp_registry.values())

    # ---------------------------------------------------------------- restore
    def restore_requests(self, *, defer: bool = True) -> dict:
        """Re-install symbolic breakpoint/hook definitions on the CURRENT
        connection (issue #32): call after a fresh attach, a reconnect, or
        a process restart + connect. Old request ids are never revived —
        every installed item reports its NEW request ids. Items already
        live in this epoch keep their ids (already_live=True). "pending"
        means the target class is not loaded right now (with defer=True,
        hooks also get a CLASS_PREPARE watch that auto-installs on load);
        "failed" means the definition no longer resolves."""
        from .hooks import crypto as crypto_hooks
        installed, pending, failed, deferred = [], [], [], []
        for d in self.events.symbolic_hooks():
            if d.get("entry") == "source":
                self._restore_source(d, installed, pending, failed)
            else:
                self._restore_hook(d, crypto_hooks, defer,
                                   installed, pending, failed, deferred)
        return {"epoch": self.events.epoch,
                "installed": installed, "pending": pending,
                "failed": failed, "deferred": deferred,
                "note": "request_ids are new current-epoch ids; ids from "
                        "before the reconnect are dead and never revived"}

    def _restore_source(self, d: dict, installed, pending, failed) -> None:
        spec = d["spec"]
        live = [m for m in self.bp_registry.values()
                if m.get("entry") == "source" and m.get("spec") == spec
                and self.events.is_live(m)]
        if live:
            installed.append({"kind": "source", "spec": spec,
                              "already_live": True,
                              "request_ids": [m["request_id"] for m in live]})
            return
        suspend_all = d.get("suspend_policy", SP_ALL) == SP_ALL
        try:
            metas = self._place(d["resolved"], spec, suspend_all)
            installed.append({"kind": "source", "spec": spec,
                              "request_ids": [m["request_id"]
                                              for m in metas]})
        except ResolveError as e:
            item = {"kind": "source", "spec": spec,
                    "reason": str(e)[:160]}
            (pending if str(e).startswith("class not loaded")
             else failed).append(item)
        except Exception as e:
            failed.append({"kind": "source", "spec": spec,
                           "reason": str(e)[:160]})

    def _restore_hook(self, d: dict, crypto_hooks, defer: bool,
                      installed, pending, failed, deferred) -> None:
        name = d.get("hook")
        try:
            rep = crypto_hooks.install(
                self, names=[name],
                capture_returns=d.get("capture_returns", False), defer=defer)
        except Exception as e:
            failed.append({"kind": "hook", "hook": name,
                           "reason": str(e)[:160]})
            return
        for i in rep["installed"]:
            installed.append({"kind": "hook", "hook": i["hook"],
                              "request_ids": i["request_ids"]})
        for p in rep["pending"]:
            item = {"kind": "hook", "hook": p["hook"],
                    "reason": p["reason"]}
            (pending if p["state"] == "pending" else failed).append(item)
        deferred.extend(rep["deferred"])

    # ----------------------------------------------------------------- events
    def wait_events(self, timeout: float = 60.0) -> dict:
        """Public event interface. Events stashed by background consumers
        (crypto watch, coverage, conditions — they claim only their own)
        are drained first; otherwise one composite is fetched and routed
        through the dispatcher. Only UNCLAIMED events are returned; their
        suspensions belong to the caller, who owns resume responsibility."""
        stashed = self.events.drain()
        if stashed is not None:
            return stashed
        return self.events.next_routed(timeout)

    def _enrich_event(self, e: dict) -> None:
        """Attach class signature and registry context to one event.
        Source breakpoints and hook entries carry different fields, so
        enrichment picks keys per entry type and never requires fields a
        hook entry does not have."""
        loc = e.get("location")
        if loc:
            e["class_sig"] = self._sig_of(loc["class"])
        hit = self.bp_registry.get(e.get("request_id"))
        if not hit:
            return
        keys = {"source": ("spec", "java_line", "smali", "method"),
                "hook": ("hook", "spec", "method")}.get(
            hit.get("entry"), ("spec", "java_line", "smali", "method",
                               "hook"))
        bp = {k: hit[k] for k in keys if k in hit}
        if bp:
            e["breakpoint"] = bp

    def _sig_of(self, type_id: int) -> str:
        if type_id not in self._sig_cache:
            # numeric type id: not re-resolvable across an epoch — a
            # reconnect surfaces StaleHandleError, never a wrong-class sig
            self._sig_cache[type_id] = self._op(
                lambda c: c.rt_signature(type_id), _name="sig_of")
        return self._sig_cache[type_id]

    # ---------------------------------------------------------------- control
    def resume(self, thread: int | None = None) -> dict:
        # state-changing: a lost reply means the suspension state is
        # UNKNOWN — never transparently replayed (issue #32)
        if thread:
            self._op(lambda c: c.thread_resume(thread),
                     _class=OP_STATE, _name="resume(thread)", _handles=True)
            return {"resumed": "thread", "thread": thread}
        self._op(lambda c: c.vm_resume(),
                 _class=OP_STATE, _name="resume(vm)")
        return {"resumed": "vm"}

    def step(self, thread: int, kind: str = "over",
             timeout: float = 30.0) -> dict:
        depth = STEP_KINDS.get(kind)
        if depth is None:
            raise SessionError(f"unknown step kind {kind!r}",
                               hint="into | over | out")

        def do(c: JdwpClient):
            rid = c.set_event(EVK_SINGLE_STEP, SP_EVENT_THREAD,
                              [c.mod_step(thread, STEP_LINE, depth)])
            try:
                c.thread_resume(thread)
                ev = c.next_event(timeout)
            finally:
                try:
                    c.clear_event(EVK_SINGLE_STEP, rid)
                except JdwpConnError:
                    pass  # never mask the original fault phase (issue #32)
            return ev
        return self._op(do, _class=OP_STATE, _name="step", _handles=True)

    # ----------------------------------------------------------------- frames
    def _frame0(self, c: JdwpClient, thread: int, frame_idx: int = 0) -> dict:
        frames = c.thread_frames(thread, frame_idx + 1)
        if len(frames) <= frame_idx:
            raise SessionError(f"thread {thread} has {len(frames)} frames, "
                               f"requested frame {frame_idx}")
        return frames[frame_idx]

    def read_var(self, thread: int, name: str | None = None,
                 slot: int | None = None, frame: int = 0) -> dict:
        def do(c: JdwpClient):
            fr = self._frame0(c, thread, frame)
            loc = fr["location"]
            vt = c.method_var_table(loc["class"], loc["method"])
            if name is not None:
                hit = next((s for s in vt["slots"] if s["name"] == name), None)
                if hit is None:
                    raise ResolveError(
                        f"no local named {name!r}",
                        hint="LocalVariableTable names: "
                             + ", ".join(s["name"] for s in vt["slots"])
                             or "(stripped by ProGuard — address by slot)")
                cur = loc["index"]
                if not (hit["code_index"] <= cur < hit["code_index"] + hit["length"]):
                    raise ResolveError(
                        f"local {name!r} not in scope at bytecode index {cur}",
                        hint=f"scope: [{hit['code_index']}, "
                             f"{hit['code_index'] + hit['length']}) — step "
                             "further into the method")
                slot_n, tag = hit["slot"], sig_to_tag(hit["sig"])
                var_name, sig = name, hit["sig"]
            elif slot is not None:
                hit = next((s for s in vt["slots"] if s["slot"] == slot), None)
                slot_n = slot
                tag = sig_to_tag(hit["sig"]) if hit else 73  # default int
                var_name = hit["name"] if hit else None
                sig = hit["sig"] if hit else "I"
            else:
                raise SessionError("read_var needs name or slot")
            vals = c.frame_get_values(thread, fr["frame_id"], [(slot_n, tag)])
            v = vals[0]
            out = {"name": var_name, "slot": slot_n, "sig": sig,
                   "tag": v["tag"], "value": v["v"]}
            if v["tag"] == TAG_STRING and v["v"]:
                out["string"] = c.string_value(v["v"])
            return out
        # read-only, but thread/frame ids are numeric handles of the
        # current epoch: after a reconnect the caller gets StaleHandleError
        # and must re-acquire fresh ids — never a silent retry against
        # reused ids (issue #32)
        return self._op(do, _class=OP_READ, _name="read_var")

    def write_var(self, thread: int, value, *, name: str | None = None,
                  slot: int | None = None, frame: int = 0,
                  vtype: str | None = None) -> dict:
        """Live local mutation. value: python scalar, or None for null ref.
        vtype: int|long|boolean|float|double|string|object (default int/str)."""
        def do(c: JdwpClient):
            fr = self._frame0(c, thread, frame)
            loc = fr["location"]
            if name is not None:
                vt = c.method_var_table(loc["class"], loc["method"])
                hit = next((s for s in vt["slots"] if s["name"] == name), None)
                if hit is None:
                    raise ResolveError(f"no local named {name!r}")
                slot_n, tag = hit["slot"], sig_to_tag(hit["sig"])
            elif slot is not None:
                slot_n = slot
                tag = _tag_for(value, vtype)
            else:
                raise SessionError("write_var needs name or slot")
            enc = c.create_string(value) if isinstance(value, str) \
                and tag == TAG_STRING else value
            c.frame_set_values(thread, fr["frame_id"], [(slot_n, tag, enc)])
            return {"slot": slot_n, "tag": tag, "written": value}
        return self._op(do, _class=OP_STATE, _name="write_var",
                        _handles=True)

    # ------------------------------------------------- buffer export (issue #38)
    def export_buffer(self, obj: int, epoch: int, *, source: str = "auto",
                      offset: int | None = None, length: int | None = None,
                      dest, max_bytes: int = buffers.DEFAULT_MAX_BYTES,
                      chunk_size: int = buffers.DEFAULT_CHUNK_SIZE,
                      deadline: float | None = None, capped: bool = False,
                      keep_partial: bool = False, cancel=None) -> dict:
        """Bounded binary export of a byte[] / heap ByteBuffer (pure reads).
        The caller must pass the connection epoch the handle came from: a
        mismatch is a stale handle and fails BEFORE any read or file.
        cancel: cooperative cancellation (issue #34), any is_set() object."""
        if epoch != self.events.epoch:
            raise StaleHandleError(
                "export_buffer", epoch=epoch,
                hint=f"the current connection epoch is {self.events.epoch}; "
                     "re-acquire a fresh object handle from new events and "
                     "pass that epoch")
        def do(c: JdwpClient):
            return buffers.BufferExporter(
                c, chunk_size=chunk_size, max_bytes=max_bytes,
                deadline_s=deadline, keep_partial=keep_partial,
                capped=capped, cancel=cancel).export(
                obj, source=source, offset=offset, length=length, dest=dest)
        # read-only, but the object handle is a numeric id of the current
        # epoch: after a reconnect the caller gets StaleHandleError, never
        # bytes from an unrelated object that reused the id (issue #32)
        return self._op(do, _class=OP_READ, _name="export_buffer")

    # ----------------------------------------------------------------- invoke
    def invoke(self, thread: int, obj: int, method: str, sig: str,
               args: list | None = None, class_sig: str | None = None) -> dict:
        """Force-invoke a method on a live object (no APK rebuild).
        args: [{"type": "int"|"string"|..., "value": ...}]."""
        def do(c: JdwpClient):
            _, type_id = c.object_reftype(obj)
            try:
                def_cls, method_id = c.resolve_instance_method(
                    type_id, method, sig or None)
            except JdwpError as e:
                raise ResolveError(str(e))
            encoded = []
            for a in args or []:
                t = a.get("type", "int")
                v = a["value"]
                if t == "string":
                    encoded.append((TAG_STRING, c.create_string(str(v))))
                else:
                    encoded.append((sig_to_tag(_TYPE_SIGS[t]), v))
            r = c.invoke_object_method(obj, thread, def_cls, method_id,
                                       encoded)
            out = {"method": method + (sig or ""), "exception": r["exception"]}
            rv = r["value"]
            out["tag"] = rv["tag"]
            out["value"] = rv["v"]
            if rv["tag"] == TAG_STRING and rv["v"]:
                out["string"] = c.string_value(rv["v"])
            return out
        # state-changing: if the reply is lost after the VM ran the
        # method, a replay would execute app code twice — reported as
        # OutcomeUnknownError instead (issue #32)
        return self._op(do, _class=OP_STATE, _name="invoke", _handles=True)


_TYPE_SIGS = {"int": "I", "long": "J", "boolean": "Z", "byte": "B",
              "short": "S", "char": "C", "float": "F", "double": "D"}


def _tag_for(value, vtype: str | None) -> int:
    if vtype:
        if vtype in ("string", "object"):
            return TAG_STRING if vtype == "string" else 76
        return sig_to_tag(_TYPE_SIGS[vtype])
    if isinstance(value, bool):
        return 90
    if isinstance(value, int):
        return 73
    if isinstance(value, float):
        return 68
    if isinstance(value, str):
        return TAG_STRING
    if value is None:
        return 76
    raise SessionError(f"cannot infer JDWP tag for {value!r}")

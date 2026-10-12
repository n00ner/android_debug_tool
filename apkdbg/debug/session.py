"""DebugSession — owns ADB + JDWP connection lifecycle and all runtime ops.

Robustness policy: every public op goes through _op(), which on a broken
JDWP socket re-establishes forwarding + handshake once before giving up.
ADB-level failures raise AdbError with the tool's stderr as the hint.
"""

from __future__ import annotations

import time
from typing import Callable

from ..core.project import Project
from ..device.adb import Adb
from ..device.jdwp import (
    EVK_BREAKPOINT, EVK_SINGLE_STEP, SP_ALL, SP_EVENT_THREAD,
    STEP_INTO, STEP_LINE, STEP_OUT, STEP_OVER,
    JdwpClient, JdwpConnError, JdwpError, sig_to_tag, TAG_STRING,
)
from ..errors import ResolveError, SessionError
from ..protocol import log_progress
from . import translate

STEP_KINDS = {"into": STEP_INTO, "over": STEP_OVER, "out": STEP_OUT}


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

    # ------------------------------------------------------------------ conn
    def connect(self, package: str, *, launch: bool = False,
                activity: str | None = None, timeout: int = 30) -> dict:
        self.adb.ensure_device()
        if launch:
            self.adb.force_stop(package)
            self.adb.launch_debug(package, activity)
        pid = self.adb.wait_pid(package, timeout=timeout)
        port = self.adb.forward_jdwp(pid)
        self.pkg, self.pid, self.port = package, pid, port
        self._attach()
        return {"package": package, "pid": pid, "port": port,
                "vm": self.client.handshake_info.get("vm_name"),
                "jdwp": f"{self.client.handshake_info.get('jdwp_major')}."
                        f"{self.client.handshake_info.get('jdwp_minor')}"}

    def _attach(self) -> None:
        """Handshake, with escalating recovery: plain -> adb reconnect ->
        adb kill-server (stale jdwp state survives unclean debugger
        disconnects; observed on MIUI)."""
        # request IDs and type IDs are per-connection: drop stale state
        self.bp_registry.clear()
        self._sig_cache.clear()
        last: JdwpConnError | None = None
        for level in (None, "reconnect", "kill-server"):
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
        raise last

    def _op(self, fn: Callable, *args, **kwargs):
        """Run fn(self.client, ...) with one transparent reconnect retry."""
        try:
            return fn(self.client, *args, **kwargs)
        except JdwpConnError:
            log_progress("JDWP connection lost; attempting reconnect")
            if not self.pid:
                raise
            pid = self.adb.pidof(self.pkg)
            if pid != self.pid:  # process restarted -> full re-attach
                raise SessionError(
                    f"target process died (pid {self.pid} -> {pid})",
                    hint="re-run connect; breakpoints must be re-registered")
            # release our own listener first: forward_jdwp uses --no-rebind
            self.adb.remove_forward(self.port)
            self.adb.forward_jdwp(self.pid, self.port)
            self._attach()
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
            res = translate.resolve(db, spec)

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
                            "smali": res["smali"]}
                    self.bp_registry[rid] = meta
                    placed.append(meta)
            if not placed:
                raise ResolveError(
                    f"line {res['java_line']} has no executable bytecode index "
                    f"in {res['class']} (runtime LineNumberTable has no entry "
                    f"for dalvik line {res['dalvik_line']})",
                    hint="adjacent lines: " + self._nearby_lines(res))
            return placed
        return {"resolved": res, "breakpoints": self._op(do)}

    def _nearby_lines(self, res: dict) -> str:
        with self.project.db() as db:
            rows = db.query(
                "SELECT DISTINCT dalvik_line FROM line_map lm JOIN methods m "
                "ON m.id=lm.method_id JOIN classes c ON c.id=m.class_id "
                "WHERE c.sig=? AND dalvik_line BETWEEN ? AND ? LIMIT 8",
                (res["sig"], res["dalvik_line"] - 5, res["dalvik_line"] + 5))
        return ", ".join(str(r["dalvik_line"]) for r in rows) or "none"

    def delete_breakpoint(self, request_id: int) -> dict:
        def do(c: JdwpClient):
            c.clear_event(EVK_BREAKPOINT, request_id)
        self._op(do)
        meta = self.bp_registry.pop(request_id, None)
        return {"cleared": request_id, "was": meta}

    def clear_request(self, request_id: int) -> dict:
        """Clear an event request with the event kind it was registered
        under (defaults to BREAKPOINT for untracked ids)."""
        kind = self.bp_registry.get(request_id, {}).get("kind",
                                                        EVK_BREAKPOINT)
        def do(c: JdwpClient):
            c.clear_event(kind, request_id)
        self._op(do)
        meta = self.bp_registry.pop(request_id, None)
        return {"cleared": request_id, "kind": kind, "was": meta}

    def list_breakpoints(self) -> list[dict]:
        return list(self.bp_registry.values())

    # ----------------------------------------------------------------- events
    def wait_events(self, timeout: float = 60.0) -> dict:
        ev = self._op(lambda c: c.next_event(timeout))
        for e in ev["events"]:
            loc = e.get("location")
            if loc:
                e["class_sig"] = self._sig_of(loc["class"])
                hit = self.bp_registry.get(e["request_id"])
                if hit:
                    e["breakpoint"] = {k: hit[k] for k in
                                       ("spec", "java_line", "smali",
                                        "method", "hook")
                                       if k in hit}
        return ev

    def _sig_of(self, type_id: int) -> str:
        if type_id not in self._sig_cache:
            self._sig_cache[type_id] = self._op(
                lambda c: c.rt_signature(type_id))
        return self._sig_cache[type_id]

    # ---------------------------------------------------------------- control
    def resume(self, thread: int | None = None) -> dict:
        if thread:
            self._op(lambda c: c.thread_resume(thread))
            return {"resumed": "thread", "thread": thread}
        self._op(lambda c: c.vm_resume())
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
                c.clear_event(EVK_SINGLE_STEP, rid)
            return ev
        return self._op(do)

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
        return self._op(do)

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
        return self._op(do)

    # ----------------------------------------------------------------- invoke
    def invoke(self, thread: int, obj: int, method: str, sig: str,
               args: list | None = None, class_sig: str | None = None) -> dict:
        """Force-invoke a method on a live object (no APK rebuild).
        args: [{"type": "int"|"string"|..., "value": ...}]."""
        def do(c: JdwpClient):
            _, type_id = c.object_reftype(obj)
            try:
                def_cls, method_id = c.find_method(type_id, method,
                                                   sig or None)
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
        return self._op(do)


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

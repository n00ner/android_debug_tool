"""Dependency-free JDWP client.

Why not automate jdb: jdb is a TTY-oriented REPL; parsing its output is
fragile and it exposes only a fraction of JDWP (no raw bytecode indices, no
MethodEntry filters, no per-slot SetValues tags). A direct socket client is
~400 lines and gives exact control over every packet.

Protocol reference: https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html
Packet header (11 bytes): length u32 | id u32 | flags u8 | then
  command: cmdset u8, cmd u8, payload
  reply:   error u16 (flags=0x80), payload
"""

from __future__ import annotations

import queue
import socket
import struct
import threading

from ..errors import JdwpError, JdwpReplyError

HANDSHAKE = b"JDWP-Handshake"
FLAG_REPLY = 0x80

# command sets
CS_VM, CS_REFTYPE, CS_CLASSTYPE, CS_METHOD, CS_OBJECTREF = 1, 2, 3, 6, 9
CS_STRINGREF, CS_THREADREF, CS_ARRAYREF = 10, 11, 13
CS_EVENTREQUEST, CS_STACKFRAME, CS_EVENT = 15, 16, 64

# VirtualMachine commands
VM_VERSION, VM_CLASSES_BY_SIG, VM_ALL_THREADS, VM_IDSIZES = 1, 2, 4, 7
VM_SUSPEND, VM_RESUME, VM_CREATE_STRING = 8, 9, 11
# ReferenceType commands
RT_SIGNATURE, RT_FIELDS, RT_METHODS, RT_GETVALUES = 1, 4, 5, 6
# ClassType commands
CT_SUPERCLASS, CT_INVOKE = 1, 3
# Method commands
M_LINETABLE, M_VARTABLE = 1, 2
# ObjectReference commands (spec: InvokeMethod is cmd 6; cmd 9 is unused on
# ART and answers with a 1-byte NOT_IMPLEMENTED-style reply)
OR_REFTYPE, OR_GETVALUES, OR_SETVALUES, OR_INVOKE = 1, 2, 3, 6
# StringReference
SR_VALUE = 1
# ThreadReference
TR_NAME, TR_SUSPEND, TR_RESUME, TR_FRAMES = 1, 2, 3, 6
# ArrayReference
AR_LENGTH, AR_GETVALUES = 1, 2
# EventRequest
ER_SET, ER_CLEAR = 1, 2
# StackFrame
SF_GETVALUES, SF_SETVALUES, SF_THISOBJECT = 1, 2, 3
# Event
EV_COMPOSITE = 100

# event kinds
EVK_SINGLE_STEP, EVK_BREAKPOINT, EVK_EXCEPTION = 1, 2, 4
EVK_THREAD_START, EVK_THREAD_DEATH = 6, 7
EVK_CLASS_PREPARE = 8
EVK_METHOD_ENTRY, EVK_METHOD_EXIT, EVK_METHOD_EXIT_RET = 40, 41, 42
EVK_VM_INIT, EVK_VM_DEATH = 90, 99

EVENT_KIND_NAMES = {
    1: "single_step", 2: "breakpoint", 4: "exception", 6: "thread_start",
    7: "thread_death", 8: "class_prepare", 40: "method_entry",
    41: "method_exit", 42: "method_exit_return", 90: "vm_init", 99: "vm_death",
}

# suspend policies
SP_NONE, SP_EVENT_THREAD, SP_ALL = 0, 1, 2
# step
STEP_MIN, STEP_LINE = 0, 1
STEP_INTO, STEP_OVER, STEP_OUT = 0, 1, 2
# invoke options
INVOKE_SINGLE_THREADED, INVOKE_NONVIRTUAL = 1, 2

# event request modifier kinds
MOD_COUNT, MOD_THREAD_ONLY, MOD_CLASS_ONLY, MOD_CLASS_MATCH = 1, 3, 4, 5
MOD_CLASS_EXCLUDE, MOD_LOCATION_ONLY, MOD_STEP, MOD_INSTANCE_ONLY = 6, 7, 10, 11

# type tags
TAGS_PRIMITIVE = {66: ">b", 90: ">b", 67: ">H", 83: ">h",
                  70: ">f", 68: ">d", 73: ">i", 74: ">q"}
TAG_OBJECT, TAG_ARRAY, TAG_STRING = 76, 91, 115
TAG_THREAD, TAG_THREAD_GROUP, TAG_CLASS_LOADER, TAG_CLASS_OBJECT = 116, 103, 108, 99
TAG_VOID = 86
TAG_NAMES = {66: "byte", 90: "boolean", 67: "char", 83: "short", 70: "float",
             68: "double", 73: "int", 74: "long", 76: "object", 91: "array",
             115: "string", 116: "thread", 103: "thread_group",
             108: "class_loader", 99: "class_object", 86: "void"}
OBJECT_TAGS = {TAG_OBJECT, TAG_ARRAY, TAG_STRING, TAG_THREAD,
               TAG_THREAD_GROUP, TAG_CLASS_LOADER, TAG_CLASS_OBJECT}
SIG_TO_TAG = {"B": 66, "Z": 90, "C": 67, "S": 83, "F": 70, "D": 68,
              "I": 73, "J": 74, "V": 86}


class JdwpConnError(JdwpError):
    code = "E_JDWP_CONN"


class IdSizes:
    """JDWP IDs are opaque and their width is VM-defined; query IDSizes
    right after handshake. ART uses 8 for referenceType/method/field."""
    def __init__(self, field=8, method=8, obj=8, reftype=8, frame=8):
        self.field, self.method, self.object = field, method, obj
        self.reftype, self.frame = reftype, frame


class Reader:
    __slots__ = ("b", "p", "sizes")

    def __init__(self, data: bytes, sizes: IdSizes | None = None):
        self.b, self.p, self.sizes = data, 0, sizes or IdSizes()

    def u8(self):
        v = self.b[self.p]; self.p += 1; return v

    def u16(self):
        v = struct.unpack_from(">H", self.b, self.p)[0]; self.p += 2; return v

    def u32(self):
        v = struct.unpack_from(">I", self.b, self.p)[0]; self.p += 4; return v

    def u64(self):
        v = struct.unpack_from(">Q", self.b, self.p)[0]; self.p += 8; return v

    i32 = u32  # line numbers are non-negative in practice; cast where needed

    def i64(self):
        v = struct.unpack_from(">q", self.b, self.p)[0]; self.p += 8; return v

    def string(self):
        n = self.u32()
        s = self.b[self.p:self.p + n].decode("utf-8", "replace")
        self.p += n
        return s

    def _id(self, n):
        v = int.from_bytes(self.b[self.p:self.p + n], "big"); self.p += n
        return v

    def object_id(self):  return self._id(self.sizes.object)
    def method_id(self):  return self._id(self.sizes.method)
    def field_id(self):   return self._id(self.sizes.field)
    def reftype_id(self): return self._id(self.sizes.reftype)
    def frame_id(self):   return self._id(self.sizes.frame)

    def location(self):
        return {"tag": self.u8(), "class": self.reftype_id(),
                "method": self.method_id(), "index": self.u64()}

    def value(self, tag: int | None = None):
        """Decode a tagged value. If tag is None, read tag byte first."""
        if tag is None:
            tag = self.u8()
        if tag in TAGS_PRIMITIVE:
            fmt = TAGS_PRIMITIVE[tag]
            v = struct.unpack_from(fmt, self.b, self.p)[0]
            self.p += struct.calcsize(fmt)
            if tag == 90:
                v = bool(v)
            return {"tag": tag, "v": v}
        if tag in OBJECT_TAGS:
            return {"tag": tag, "v": self.object_id()}
        if tag == TAG_VOID:
            return {"tag": tag, "v": None}
        raise JdwpError(f"unknown value tag {tag}")


class Writer:
    __slots__ = ("buf", "sizes")

    def __init__(self, sizes: IdSizes):
        self.buf = bytearray()
        self.sizes = sizes

    def u8(self, v): self.buf.append(v & 0xFF)
    def u16(self, v): self.buf += struct.pack(">H", v)
    def u32(self, v): self.buf += struct.pack(">I", v)
    def u64(self, v): self.buf += struct.pack(">Q", v)

    def string(self, s: str):
        b = s.encode("utf-8")
        self.u32(len(b))
        self.buf += b

    def _id(self, v, n):
        self.buf += v.to_bytes(n, "big")

    def object_id(self, v):  self._id(v, self.sizes.object)
    def method_id(self, v):  self._id(v, self.sizes.method)
    def field_id(self, v):   self._id(v, self.sizes.field)
    def reftype_id(self, v): self._id(v, self.sizes.reftype)
    def frame_id(self, v):   self._id(v, self.sizes.frame)

    def location(self, tag, class_id, method_id, index):
        self.u8(tag)
        self.reftype_id(class_id)
        self.method_id(method_id)
        self.u64(index)

    def value(self, tag: int, v):
        """Encode a tagged value (tag byte included)."""
        self.u8(tag)
        if tag in TAGS_PRIMITIVE:
            self.buf += struct.pack(TAGS_PRIMITIVE[tag], v)
        elif tag in OBJECT_TAGS:
            self.object_id(v if v is not None else 0)  # None = null ref
        elif tag == TAG_VOID:
            pass
        else:
            raise JdwpError(f"cannot encode tag {tag}")


def sig_to_tag(sig: str) -> int:
    """Map a JNI type signature to a JDWP value tag."""
    if sig.startswith("["):
        return TAG_ARRAY
    if sig.startswith("L"):
        return TAG_OBJECT
    return SIG_TO_TAG.get(sig, TAG_OBJECT)


class JdwpClient:
    def __init__(self, host: str, port: int, timeout: float = 15.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock: socket.socket | None = None
        self.sizes = IdSizes()
        self._send_lock = threading.Lock()
        self._id_lock = threading.Lock()
        self._next = 1
        self._pending: dict[int, dict] = {}
        self._events: queue.Queue = queue.Queue()
        self._alive = False
        self._dead: Exception | None = None
        self._reader_t: threading.Thread | None = None
        self.handshake_info: dict = {}

    # -- connection ----------------------------------------------------------
    def connect(self) -> None:
        try:
            self.sock = socket.create_connection((self.host, self.port),
                                                 timeout=self.timeout)
            self.sock.sendall(HANDSHAKE)
            resp = self._recv_exact(len(HANDSHAKE))
        except (OSError, JdwpConnError) as e:
            raise JdwpConnError(
                f"JDWP connect to {self.host}:{self.port} failed: {e}",
                hint="is the app debuggable and forwarded? (adb forward tcp:P jdwp:PID)")
        if resp != HANDSHAKE:
            self.sock.close()
            raise JdwpConnError("JDWP handshake rejected",
                                hint=f"got {resp!r}")
        self.sock.settimeout(None)  # reader thread blocks; requests have own timeouts
        self._alive = True
        self._reader_t = threading.Thread(target=self._reader_loop, daemon=True,
                                          name="jdwp-reader")
        self._reader_t.start()
        r = self.request(CS_VM, VM_IDSIZES)
        self.sizes = IdSizes(r.u32(), r.u32(), r.u32(), r.u32(), r.u32())
        vr = self.request(CS_VM, VM_VERSION)
        self.handshake_info = {"description": vr.string(),
                               "jdwp_major": vr.u32(), "jdwp_minor": vr.u32(),
                               "vm_version": vr.string(), "vm_name": vr.string()}

    def close(self) -> None:
        self._alive = False
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    # -- transport ------------------------------------------------------------
    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except OSError as e:
                raise JdwpConnError(f"JDWP socket error: {e}") from e
            if not chunk:
                raise JdwpConnError("JDWP socket closed by peer (VM died or "
                                    "debugger detached)")
            buf += chunk
        return bytes(buf)

    def _alloc_id(self) -> int:
        with self._id_lock:
            i = self._next
            self._next += 1
            return i

    def _reader_loop(self) -> None:
        try:
            while self._alive:
                hdr = self._recv_exact(11)
                length, pid, flags = struct.unpack_from(">IIB", hdr, 0)
                rest = self._recv_exact(length - 11)
                if flags & FLAG_REPLY:
                    # reply header includes the 2-byte error code in hdr
                    error = struct.unpack_from(">H", hdr, 9)[0]
                    slot = self._pending.pop(pid, None)
                    if slot is not None:
                        slot["error"], slot["data"] = error, rest
                        slot["event"].set()
                else:
                    # command header: last 2 bytes of hdr are cmdset + cmd
                    cmdset, cmd = hdr[9], hdr[10]
                    if cmdset == CS_EVENT and cmd == EV_COMPOSITE:
                        self._events.put(self._parse_composite(rest))
        except JdwpConnError as e:
            self._dead = e
        except Exception as e:  # decoder bugs must not kill diagnostics
            self._dead = JdwpConnError(f"JDWP reader crashed: {e!r}")
        finally:
            self._alive = False
            for pid, slot in list(self._pending.items()):
                slot["error"] = -1
                slot["event"].set()
            self._events.put(None)  # poison pill wakes waiters

    def request(self, cmdset: int, cmd: int, payload: bytes = b"",
                timeout: float | None = None) -> Reader:
        if self._dead:
            raise JdwpConnError(f"JDWP connection is dead: {self._dead}")
        pid = self._alloc_id()
        slot = {"event": threading.Event(), "error": None, "data": b""}
        with self._send_lock:
            self._pending[pid] = slot
            pkt = struct.pack(">IIBBB", 11 + len(payload), pid, 0, cmdset, cmd)
            try:
                self.sock.sendall(pkt + payload)
            except OSError as e:
                self._pending.pop(pid, None)
                raise JdwpConnError(f"JDWP send failed: {e}") from e
        if not slot["event"].wait(timeout or self.timeout):
            self._pending.pop(pid, None)
            raise JdwpConnError(f"JDWP reply timeout cmdset={cmdset} cmd={cmd}")
        if slot["error"] == -1:
            raise JdwpConnError(f"JDWP connection lost: {self._dead}")
        if slot["error"]:
            raise JdwpReplyError(slot["error"], cmdset, cmd)
        return Reader(slot["data"], self.sizes)

    # -- VM introspection ------------------------------------------------------
    def classes_by_signature(self, sig: str) -> list[dict]:
        w = Writer(self.sizes)
        w.string(sig)
        r = self.request(CS_VM, VM_CLASSES_BY_SIG, bytes(w.buf))
        out = []
        for _ in range(r.u32()):
            out.append({"tag": r.u8(), "type_id": r.reftype_id(),
                        "status": r.u32()})
        return out

    def all_threads(self) -> list[int]:
        r = self.request(CS_VM, VM_ALL_THREADS)
        return [r.object_id() for _ in range(r.u32())]

    def vm_suspend(self): self.request(CS_VM, VM_SUSPEND)
    def vm_resume(self):  self.request(CS_VM, VM_RESUME)

    def create_string(self, s: str) -> int:
        w = Writer(self.sizes)
        w.string(s)
        return self.request(CS_VM, VM_CREATE_STRING, bytes(w.buf)).object_id()

    # -- reference type / method metadata --------------------------------------
    def rt_signature(self, type_id: int) -> str:
        w = Writer(self.sizes)
        w.reftype_id(type_id)
        return self.request(CS_REFTYPE, RT_SIGNATURE, bytes(w.buf)).string()

    def rt_methods(self, type_id: int) -> list[dict]:
        w = Writer(self.sizes)
        w.reftype_id(type_id)
        r = self.request(CS_REFTYPE, RT_METHODS, bytes(w.buf))
        out = []
        for _ in range(r.u32()):
            out.append({"id": r.method_id(), "name": r.string(),
                        "sig": r.string(), "mod_bits": r.u32()})
        return out

    def rt_fields(self, type_id: int) -> list[dict]:
        w = Writer(self.sizes)
        w.reftype_id(type_id)
        r = self.request(CS_REFTYPE, RT_FIELDS, bytes(w.buf))
        out = []
        for _ in range(r.u32()):
            out.append({"id": r.field_id(), "name": r.string(),
                        "sig": r.string(), "mod_bits": r.u32()})
        return out

    def rt_get_values(self, type_id: int, field_ids: list[int]) -> list[dict]:
        """ReferenceType.GetValues — for STATIC fields. Passing static field
        IDs to ObjectReference.GetValues makes ART drop the connection."""
        w = Writer(self.sizes)
        w.reftype_id(type_id)
        w.u32(len(field_ids))
        for f in field_ids:
            w.field_id(f)
        r = self.request(CS_REFTYPE, RT_GETVALUES, bytes(w.buf))
        return [r.value() for _ in range(r.u32())]

    def method_line_table(self, type_id: int, method_id: int) -> dict:
        """DEX LineNumberTable: bytecode index -> line number. This is the
        authoritative runtime mapping used by Perfect Sync Tracing."""
        w = Writer(self.sizes)
        w.reftype_id(type_id)
        w.method_id(method_id)
        r = self.request(CS_METHOD, M_LINETABLE, bytes(w.buf))
        start, end = r.i64(), r.i64()
        lines = []
        for _ in range(r.u32()):
            lines.append({"index": r.i64(), "line": r.u32()})
        return {"start": start, "end": end, "lines": lines}

    def method_var_table(self, type_id: int, method_id: int) -> dict:
        """LocalVariableTable — absent when ProGuard strips debug attrs."""
        w = Writer(self.sizes)
        w.reftype_id(type_id)
        w.method_id(method_id)
        r = self.request(CS_METHOD, M_VARTABLE, bytes(w.buf))
        arg_cnt = r.u32()
        slots = []
        for _ in range(r.u32()):
            slots.append({"code_index": r.i64(), "name": r.string(),
                          "sig": r.string(), "length": r.u32(),
                          "slot": r.u32()})
        return {"arg_cnt": arg_cnt, "slots": slots}

    # -- event requests ----------------------------------------------------------
    def set_event(self, kind: int, suspend_policy: int,
                  modifiers: list[tuple[int, bytes]] | None = None) -> int:
        """Generic EventRequest.Set. modifiers: list of (modKind, payload)."""
        w = Writer(self.sizes)
        w.u8(kind)
        w.u8(suspend_policy)
        mods = modifiers or []
        w.u32(len(mods))
        for kind_b, payload in mods:
            w.u8(kind_b)
            w.buf += payload
        return self.request(CS_EVENTREQUEST, ER_SET, bytes(w.buf)).u32()

    def clear_event(self, kind: int, request_id: int) -> None:
        w = Writer(self.sizes)
        w.u8(kind)
        w.u32(request_id)
        self.request(CS_EVENTREQUEST, ER_CLEAR, bytes(w.buf))

    # modifier payload builders
    def mod_count(self, n: int) -> tuple[int, bytes]:
        return (MOD_COUNT, struct.pack(">I", n))

    def mod_thread_only(self, thread: int) -> tuple[int, bytes]:
        w = Writer(self.sizes)
        w.object_id(thread)
        return (MOD_THREAD_ONLY, bytes(w.buf))

    def mod_class_match(self, pattern: str) -> tuple[int, bytes]:
        w = Writer(self.sizes)
        w.string(pattern)
        return (MOD_CLASS_MATCH, bytes(w.buf))

    def mod_class_only(self, type_id: int) -> tuple[int, bytes]:
        w = Writer(self.sizes)
        w.reftype_id(type_id)
        return (MOD_CLASS_ONLY, bytes(w.buf))

    def mod_instance_only(self, obj: int) -> tuple[int, bytes]:
        w = Writer(self.sizes)
        w.object_id(obj)
        return (MOD_INSTANCE_ONLY, bytes(w.buf))

    def mod_location_only(self, class_id: int, method_id: int,
                          index: int, tag: int = 1) -> tuple[int, bytes]:
        w = Writer(self.sizes)
        w.location(tag, class_id, method_id, index)
        return (MOD_LOCATION_ONLY, bytes(w.buf))

    def mod_step(self, thread: int, size: int, depth: int) -> tuple[int, bytes]:
        w = Writer(self.sizes)
        w.object_id(thread)
        w.u32(size)
        w.u32(depth)
        return (MOD_STEP, bytes(w.buf))

    def set_breakpoint(self, class_id: int, method_id: int, index: int,
                       suspend_policy: int = SP_ALL) -> int:
        return self.set_event(EVK_BREAKPOINT, suspend_policy,
                              [self.mod_location_only(class_id, method_id, index)])

    # -- events --------------------------------------------------------------------
    def _parse_composite(self, data: bytes) -> dict:
        r = Reader(data, self.sizes)
        suspend_policy = r.u8()
        events = []
        for _ in range(r.u32()):
            kind = r.u8()
            ev: dict = {"kind": EVENT_KIND_NAMES.get(kind, f"kind_{kind}"),
                        "kind_id": kind, "request_id": r.u32()}
            if kind in (EVK_SINGLE_STEP, EVK_BREAKPOINT, EVK_METHOD_ENTRY,
                        EVK_METHOD_EXIT, EVK_METHOD_EXIT_RET, EVK_EXCEPTION):
                ev["thread"] = r.object_id()
                ev["location"] = r.location()
                if kind == EVK_METHOD_EXIT_RET:
                    ev["return_value"] = r.value()
            elif kind in (EVK_THREAD_START, EVK_THREAD_DEATH, EVK_VM_INIT):
                ev["thread"] = r.object_id()
            elif kind == EVK_CLASS_PREPARE:
                ev["thread"] = r.object_id()
                ev["tag"] = r.u8()
                ev["type_id"] = r.reftype_id()
                ev["signature"] = r.string()
                ev["status"] = r.u32()
            events.append(ev)
        return {"suspend_policy": suspend_policy, "events": events}

    def next_event(self, timeout: float | None = None) -> dict:
        """Block until a composite event arrives. Raises JdwpConnError on
        disconnect; raises queue.Empty-derived JdwpError on timeout."""
        try:
            item = self._events.get(timeout=timeout)
        except queue.Empty:
            raise _timeout_error(timeout)
        if item is None:
            raise JdwpConnError(f"JDWP connection lost: {self._dead}")
        return item

    # -- threads / frames ------------------------------------------------------------
    def thread_name(self, thread: int) -> str:
        w = Writer(self.sizes)
        w.object_id(thread)
        return self.request(CS_THREADREF, TR_NAME, bytes(w.buf)).string()

    def thread_suspend(self, thread: int):
        w = Writer(self.sizes)
        w.object_id(thread)
        self.request(CS_THREADREF, TR_SUSPEND, bytes(w.buf))

    def thread_resume(self, thread: int):
        w = Writer(self.sizes)
        w.object_id(thread)
        self.request(CS_THREADREF, TR_RESUME, bytes(w.buf))

    def thread_frames(self, thread: int, count: int = 32) -> list[dict]:
        w = Writer(self.sizes)
        w.object_id(thread)
        w.u32(0)
        w.u32(count)
        r = self.request(CS_THREADREF, TR_FRAMES, bytes(w.buf))
        return [{"frame_id": r.frame_id(), "location": r.location()}
                for _ in range(r.u32())]

    def frame_get_values(self, thread: int, frame_id: int,
                         slots: list[tuple[int, int]]) -> list[dict]:
        """slots: list of (slot_index, type_tag). Returns tagged values."""
        w = Writer(self.sizes)
        w.object_id(thread)
        w.frame_id(frame_id)
        w.u32(len(slots))
        for slot, tag in slots:
            w.u32(slot)
            w.u8(tag)
        r = self.request(CS_STACKFRAME, SF_GETVALUES, bytes(w.buf))
        return [r.value() for _ in range(r.u32())]

    def frame_set_values(self, thread: int, frame_id: int,
                         values: list[tuple[int, int, object]]) -> None:
        """values: list of (slot, tag, python_value)."""
        w = Writer(self.sizes)
        w.object_id(thread)
        w.frame_id(frame_id)
        w.u32(len(values))
        for slot, tag, v in values:
            w.u32(slot)
            w.value(tag, v)
        self.request(CS_STACKFRAME, SF_SETVALUES, bytes(w.buf))

    def frame_this_object(self, thread: int, frame_id: int) -> dict:
        w = Writer(self.sizes)
        w.object_id(thread)
        w.frame_id(frame_id)
        return self.request(CS_STACKFRAME, SF_THISOBJECT, bytes(w.buf)).value()

    # -- objects / arrays / strings ---------------------------------------------------
    def object_reftype(self, obj: int) -> tuple[int, int]:
        w = Writer(self.sizes)
        w.object_id(obj)
        r = self.request(CS_OBJECTREF, OR_REFTYPE, bytes(w.buf))
        return r.u8(), r.reftype_id()

    def object_get_values(self, obj: int, field_ids: list[int]) -> list[dict]:
        w = Writer(self.sizes)
        w.object_id(obj)
        w.u32(len(field_ids))
        for f in field_ids:
            w.field_id(f)
        r = self.request(CS_OBJECTREF, OR_GETVALUES, bytes(w.buf))
        return [r.value() for _ in range(r.u32())]

    def object_set_values(self, obj: int, values: list[tuple[int, int, object]]):
        w = Writer(self.sizes)
        w.object_id(obj)
        w.u32(len(values))
        for fid, tag, v in values:
            w.field_id(fid)
            w.value(tag, v)
        self.request(CS_OBJECTREF, OR_SETVALUES, bytes(w.buf))

    def invoke_object_method(self, obj: int, thread: int, class_id: int,
                             method_id: int, args: list[tuple[int, object]],
                             options: int = INVOKE_SINGLE_THREADED) -> dict:
        """Force-invoke a method on a live object in the suspended thread.
        args: list of (tag, python_value). Returns {value, exception}."""
        w = Writer(self.sizes)
        w.object_id(obj)
        w.object_id(thread)
        w.reftype_id(class_id)
        w.method_id(method_id)
        w.u32(len(args))
        for tag, v in args:
            w.value(tag, v)
        w.u32(options)
        r = self.request(CS_OBJECTREF, OR_INVOKE, bytes(w.buf))
        val = r.value()
        # spec says: exception is an untagged objectID. Android 15's
        # JVMTI-based JDWP agent emits it as a TAGGED value ('L' + id).
        remaining = len(r.b) - r.p
        if remaining == 1 + self.sizes.object and r.b[r.p] in OBJECT_TAGS:
            r.u8()  # skip the tag byte
        return {"value": val, "exception": r.object_id()}

    def ct_superclass(self, class_id: int) -> int:
        """ClassType.Superclass — returns classID of superclass, 0 for
        Object/interfaces."""
        w = Writer(self.sizes)
        w.reftype_id(class_id)
        return self.request(CS_CLASSTYPE, CT_SUPERCLASS,
                            bytes(w.buf)).reftype_id()

    def ct_new_instance(self, class_id: int, thread: int, method_id: int,
                        args: list[tuple[int, object]] | None = None,
                        options: int = INVOKE_SINGLE_THREADED) -> dict:
        """ClassType.NewInstance: allocate + run a constructor. Returns
        {value: tagged new object, exception: object_id}."""
        w = Writer(self.sizes)
        w.reftype_id(class_id)
        w.object_id(thread)
        w.method_id(method_id)
        args = args or []
        w.u32(len(args))
        for tag, v in args:
            w.value(tag, v)
        w.u32(options)
        r = self.request(CS_CLASSTYPE, 4, bytes(w.buf))
        val = r.value()
        remaining = len(r.b) - r.p
        if remaining == 1 + self.sizes.object and r.b[r.p] in OBJECT_TAGS:
            r.u8()
        return {"value": val, "exception": r.object_id()}

    def find_method(self, class_id: int, name: str,
                    sig: str | None = None) -> tuple[int, int]:
        """Walk the superclass chain for a method (rt_methods only lists
        DECLARED methods). Returns (defining_class_id, method_id)."""
        cid = class_id
        while cid:
            for m in self.rt_methods(cid):
                if m["name"] == name and (not sig or m["sig"] == sig):
                    return cid, m["id"]
            cid = self.ct_superclass(cid)
        raise JdwpError(f"method {name}{sig or ''} not found in class "
                        f"hierarchy of {class_id}")

    def string_value(self, obj: int, max_len: int = 4096) -> str:
        w = Writer(self.sizes)
        w.object_id(obj)
        s = self.request(CS_STRINGREF, SR_VALUE, bytes(w.buf)).string()
        return s[:max_len]

    def array_length(self, obj: int) -> int:
        w = Writer(self.sizes)
        w.object_id(obj)
        return self.request(CS_ARRAYREF, AR_LENGTH, bytes(w.buf)).u32()

    def array_get_values(self, obj: int, start: int = 0,
                         length: int = 256) -> dict:
        """Reply: component tag u8, count u32, then elements (raw for
        primitives, object ids otherwise)."""
        if length == 0:
            # ART rejects zero-length GetValues with an internal error
            return {"component_tag": 66, "items": [], "inferred": True}
        w = Writer(self.sizes)
        w.object_id(obj)
        w.u32(start)
        w.u32(length)
        r = self.request(CS_ARRAYREF, AR_GETVALUES, bytes(w.buf))
        tag = r.u8()
        n = r.u32()
        if tag in TAGS_PRIMITIVE:
            items = [r.value(tag)["v"] for _ in range(n)]
        else:
            items = [{"tag": tag, "v": r.object_id()} for _ in range(n)]
        return {"component_tag": tag, "items": items}

    def byte_array(self, obj: int, max_len: int = 65536) -> bytes:
        """Read a byte[] into python bytes (values are signed -> mask)."""
        n = min(self.array_length(obj), max_len)
        vals = self.array_get_values(obj, 0, n)["items"]
        return bytes(v & 0xFF for v in vals)


def _timeout_error(timeout):
    e = JdwpError(f"event wait timed out after {timeout}s",
                  hint="VM may be running; increase timeout or resume")
    e.code = "E_JDWP_TIMEOUT"
    return e

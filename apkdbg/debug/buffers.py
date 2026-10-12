"""Bounded binary export of byte[] and heap ByteBuffer instances (issue #38).

A reliable byte-extraction primitive for a later unpacker stage (#28); no
format recognition or entropy heuristics live here.

Sources
-------
byte[]         validated against ArrayReference.Length; offset/length are
               array indices. Zero-length and boundary ranges are legal.
heap ByteBuffer
               default range is [position, limit), translated through the
               backing-array offset; explicit offset/length are relative
               to the buffer's position. The adapter is resolved against
               the RUNTIME representation: instance fields are enumerated
               over the actual class hierarchy (OpenJDK-style hb/offset and
               libcore-style backingArray/arrayOffset are both recognized),
               never assumed from one Android version's layout. Nested
               slices work because each slice carries its own accumulated
               offset over the shared backing array.
               Read-only views, direct/native buffers, and unknown
               implementations raise CapabilityError — never silently
               wrong bytes. Pure field/array reads only: no method is ever
               invoked (the #22 invoke policy is not needed) and no value
               is written, so position/limit/mark/contents are preserved.

Bounded writes
--------------
Bytes flow chunk-by-chunk (JDWP ArrayReference.GetValues) through a
running SHA-256 into a temp file in the destination directory, published
by atomic rename only after the last byte is hashed — host memory stays
bounded regardless of export size. Deadline/cancel/disconnect/host-write
failure removes the partial temp file unless keep_partial=True explicitly
retains incomplete artifacts; the outcome is reported via
ExportIncompleteError and is never advertised as complete. A range export
whose length exceeds max_bytes fails BEFORE any file is created, unless
capped=True deliberately requests a bounded preview (export_kind "capped",
complete=False — distinct from a full range export).

Consistency
-----------
Reads assume the caller has the target suspended (breakpoint/stop they
own). Suspending the event thread does NOT stop other threads from
mutating the buffer between chunk reads: an export is not an atomic
snapshot. The limitation is recorded in the result's "consistency" block;
for ByteBuffers the position/limit/mark triple is re-read afterwards and
compared ("state_preserved").
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

from ..errors import CapabilityError, ExportIncompleteError, SessionError

DEFAULT_MAX_BYTES = 16 << 20
DEFAULT_CHUNK_SIZE = 1 << 16
MAX_CHUNK_SIZE = 1 << 20

_ACC_STATIC = 0x8
_BACKING_NAMES = ("hb", "backingArray")   # OpenJDK/ART, older libcore
_OFFSET_NAMES = ("offset", "arrayOffset")
# boolean read-only flags seen on actual runtime layouts: ART (API ~26+,
# verified on API 35) declares isReadOnly on java.nio.ByteBuffer and uses
# plain HeapByteBuffer for read-only views (no HeapByteBufferR subclass);
# "readOnly" covers libcore-style spellings. Value True => capability
# error; an absent flag is fine (the XxxR structural rule covers those).
_READ_ONLY_NAMES = ("isReadOnly", "readOnly")

CONSISTENCY_NOTE = (
    "pure JDWP reads while the caller's stop holds the target suspended; "
    "suspending the event thread does not prevent OTHER threads from "
    "mutating the buffer between chunk reads — this is not an atomic "
    "snapshot; suspend the whole VM (SP_ALL stop or VirtualMachine.Suspend) "
    "to narrow the race window")


class _Abort(Exception):
    """Internal control flow: deadline/cancel abort with a reason."""


class BufferExporter:
    """One bounded export against a live client. Re-created per attempt by
    DebugSession.export_buffer; safe against reconnect replays because it
    holds no cross-attempt state."""

    def __init__(self, client, *, chunk_size: int = DEFAULT_CHUNK_SIZE,
                 max_bytes: int = DEFAULT_MAX_BYTES,
                 deadline_s: float | None = None,
                 keep_partial: bool = False, capped: bool = False,
                 cancel=None):
        if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
            raise SessionError(
                f"chunk_size must be 1..{MAX_CHUNK_SIZE}, got {chunk_size}")
        if max_bytes < 0:
            raise SessionError(f"max_bytes must be >= 0, got {max_bytes}")
        self.c = client
        self.chunk_size = chunk_size
        self.max_bytes = max_bytes
        self.deadline_s = deadline_s
        self.keep_partial = keep_partial
        self.capped = capped
        self.cancel = cancel  # cooperative cancel (issue #34), is_set()
        self.requests = 0
        self.chunks = 0
        self._t0 = 0.0

    # ------------------------------------------------------------ entrypoint
    def export(self, obj: int, *, source: str = "auto",
               offset: int | None = None, length: int | None = None,
               dest: str | Path) -> dict:
        self._t0 = time.monotonic()
        plan = self._resolve(obj, source, offset, length)
        total = plan["range"]["length"]
        if total > self.max_bytes and not self.capped:
            raise SessionError(
                f"requested range is {total} bytes, over the max_bytes "
                f"bound {self.max_bytes}",
                hint="narrow offset/length, raise max_bytes, or pass "
                     "capped=True for a deliberate bounded preview",
                requested=total, max_bytes=self.max_bytes)
        export_len = min(total, self.max_bytes) if self.capped else total
        complete = export_len == total

        dest = Path(dest)
        tmp = dest.with_name(dest.name + ".part")
        sha = hashlib.sha256()
        done = 0
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(tmp, "wb") as fh:
                done = self._pump(plan["array_handle"],
                                  plan["backing_offset"], export_len,
                                  fh, sha)
            os.replace(tmp, dest)
        except _Abort as e:
            self._cleanup(tmp)
            raise self._incomplete(str(e), total, done, tmp)
        except KeyboardInterrupt:
            self._cleanup(tmp)
            raise self._incomplete("cancelled", total, done, tmp)
        except OSError as e:
            self._cleanup(tmp)
            raise self._incomplete(f"host write failed: {e}", total, done,
                                   tmp) from e
        except Exception:
            # JDWP disconnect/reply errors propagate with their own
            # structured code; the partial file policy still applies.
            self._cleanup(tmp)
            raise

        result = {
            "complete": complete,
            "export_kind": "full" if complete else "capped",
            "source": plan["source"],
            "range": plan["range"],
            "bytes": {"requested": total, "exported": done,
                      "sha256": sha.hexdigest()},
            "file": str(dest),
            "timing": {"elapsed_ms": self._elapsed_ms(),
                       "jdwp_requests": self.requests,
                       "chunks": self.chunks},
            "consistency": {"atomic_snapshot": False,
                            "suspension_scope": "caller-controlled",
                            "note": CONSISTENCY_NOTE},
        }
        if plan["source"]["kind"] == "heap_byte_buffer":
            after = self._buffer_state(obj, plan["fields"])
            result["state_preserved"] = after == plan["state_before"]
            result["buffer_state"] = plan["state_before"]
            if not result["state_preserved"]:
                result["buffer_state_after"] = after
        else:
            result["state_preserved"] = True
        return result

    # ------------------------------------------------------------ range math
    @staticmethod
    def _range(offset: int | None, length: int | None, total: int,
               what: str) -> tuple[int, int]:
        """Validate an [offset, offset+length) range against `total`.
        Defaults: offset 0, length up to the end. Fails BEFORE any
        destination file exists."""
        off = 0 if offset is None else offset
        ln = (total - off) if length is None else length
        if off < 0 or ln < 0:
            raise SessionError(
                f"negative range component for {what}: "
                f"offset={off} length={ln}",
                offset=off, length=ln, total=total)
        if off > total or off + ln > total:
            raise SessionError(
                f"range [{off}, {off + ln}) is out of bounds for {what} "
                f"of length {total}",
                hint="offsets/lengths are validated against the runtime "
                     "ArrayLength / buffer limit",
                offset=off, length=ln, total=total)
        return off, ln

    # ------------------------------------------------------------- resolve
    def _resolve(self, obj: int, source: str, offset: int | None,
                 length: int | None) -> dict:
        if source not in ("auto", "array", "bytebuffer"):
            raise SessionError(f"unknown source kind {source!r}",
                               hint="auto | array | bytebuffer")
        tag, type_id = self._req(self.c.object_reftype, obj)
        sig = self._req(self.c.rt_signature, type_id)
        if source == "auto":
            source = "array" if sig == "[B" else "bytebuffer"
        if source == "array":
            return self._resolve_array(obj, sig, offset, length)
        return self._resolve_bytebuffer(obj, type_id, sig, offset, length)

    def _resolve_array(self, obj: int, sig: str, offset, length) -> dict:
        if sig != "[B":
            raise CapabilityError(
                f"object {obj} is {sig}, not a byte[]",
                hint="only byte[] is supported for source=array; heap "
                     "ByteBuffer instances use source=bytebuffer",
                handle=obj, class_sig=sig)
        n = self._req(self.c.array_length, obj)
        off, ln = self._range(offset, length, n, f"byte[] of length {n}")
        return {"array_handle": obj, "backing_offset": off,
                "fields": None, "state_before": None,
                "source": {"kind": "byte_array", "handle": obj,
                           "class_sig": sig, "array_len": n},
                "range": {"offset": off, "length": ln,
                          "backing_offset": off}}

    def _resolve_bytebuffer(self, obj: int, type_id: int, sig: str,
                            offset, length) -> dict:
        chain = self._hierarchy(type_id)
        self._check_supported(chain, obj, sig)
        fields = self._instance_fields(chain)
        backing = self._backing_field(fields, chain, obj, sig)
        pos_f = self._int_field(fields, "position", chain, obj, sig)
        lim_f = self._int_field(fields, "limit", chain, obj, sig)
        off_f = next((fields[n] for n in _OFFSET_NAMES
                      if n in fields and fields[n]["sig"] == "I"), None)
        mark_f = fields.get("mark") if fields.get("mark", {}).get("sig") == "I" \
            else None
        ro_f = next((fields[n] for n in _READ_ONLY_NAMES
                     if n in fields and fields[n]["sig"] == "Z"), None)

        fetch = {"backing": backing, "position": pos_f, "limit": lim_f,
                 "array_offset": off_f, "mark": mark_f, "read_only": ro_f}
        ids = [f["id"] for f in fetch.values() if f]
        vals = self._req(self.c.object_get_values, obj, ids)
        got = {name: v for name, v in
               zip((n for n in fetch if fetch[n]), vals)}
        if got.get("read_only", {}).get("v"):
            raise CapabilityError(
                f"read-only ByteBuffer {obj} ({sig}): flag field "
                f"{ro_f['name']!r} is true; no array access in v1",
                hint="export the underlying byte[] handle instead, or "
                     "duplicate the buffer in-app before debugging",
                reason="read_only_no_array_access",
                handle=obj, class_sig=sig, flag_field=ro_f["name"])
        arr = got["backing"]["v"]
        if not arr:
            raise CapabilityError(
                f"ByteBuffer {obj} ({sig}) has a null backing array",
                hint="cannot read its bytes via the heap-array path",
                handle=obj, class_sig=sig)
        pos, lim = got["position"]["v"], got["limit"]["v"]
        mark = got["mark"]["v"] if "mark" in got else None
        arr_off = got["array_offset"]["v"] if "array_offset" in got else 0
        if not (0 <= pos <= lim):
            raise CapabilityError(
                f"ByteBuffer {obj} ({sig}) has inconsistent state "
                f"position={pos} limit={lim} — field adapter mismatch",
                hint="the runtime layout is not recognized; refusing to "
                     "guess instead of exporting wrong bytes",
                handle=obj, class_sig=sig,
                fields=self._field_summary(chain))

        window = lim - pos
        off, ln = self._range(offset, length, window,
                              f"ByteBuffer window [position, limit) of "
                              f"{window} bytes")
        abs_start = arr_off + pos + off
        n = self._req(self.c.array_length, arr)
        if abs_start + ln > n:
            raise CapabilityError(
                f"translated range [{abs_start}, {abs_start + ln}) escapes "
                f"the backing array of length {n} — field adapter mismatch",
                hint="the runtime layout is not recognized; refusing to "
                     "guess instead of exporting wrong bytes",
                handle=obj, class_sig=sig,
                fields=self._field_summary(chain))
        return {"array_handle": arr, "backing_offset": abs_start,
                "fields": fetch,
                "state_before": {"position": pos, "limit": lim,
                                 "mark": mark},
                "source": {"kind": "heap_byte_buffer", "handle": obj,
                           "class_sig": sig,
                           "backing_field": backing["name"],
                           "offset_field": off_f["name"] if off_f else None,
                           "buffer": {"position": pos, "limit": lim,
                                      "mark": mark,
                                      "array_offset": arr_off},
                           "array_handle": arr, "array_len": n},
                "range": {"offset": off, "length": ln,
                          "backing_offset": abs_start}}

    # ------------------------------------------- runtime representation walk
    def _hierarchy(self, type_id: int) -> list[dict]:
        """[runtime class, ...ancestors] with signatures; ends at Object."""
        chain = []
        cid = type_id
        while cid:
            sig = self._req(self.c.rt_signature, cid)
            chain.append({"type_id": cid, "sig": sig,
                          "simple": sig[1:-1].rsplit("/", 1)[-1]})
            cid = self._req(self.c.ct_superclass, cid)
        return chain

    @staticmethod
    def _check_supported(chain: list[dict], obj: int, sig: str) -> None:
        simples = [c["simple"] for c in chain]
        if any(s.endswith("R") and s[:-1] in simples for s in simples):
            raise CapabilityError(
                f"read-only ByteBuffer {obj} ({sig}): no array access in v1",
                hint="export the underlying byte[] handle instead, or "
                     "duplicate the buffer in-app before debugging",
                reason="read_only_no_array_access",
                handle=obj, class_sig=sig)
        if any("Direct" in s for s in simples):
            raise CapabilityError(
                f"direct/native ByteBuffer {obj} ({sig}) is not heap-backed "
                "and is unsupported in v1",
                hint="copy the region into a byte[] in-app, then export "
                     "that array",
                reason="direct_or_native",
                handle=obj, class_sig=sig)

    def _instance_fields(self, chain: list[dict]) -> dict:
        """name -> field over the whole hierarchy, most-derived first
        (a subclass declaration shadows the inherited one). Static fields
        are skipped: ObjectReference.GetValues takes instance fields."""
        fields: dict = {}
        for c in chain:
            for f in self._req(self.c.rt_fields, c["type_id"]):
                if f["mod_bits"] & _ACC_STATIC:
                    continue
                fields.setdefault(f["name"],
                                  {**f, "declaring": c["type_id"]})
        return fields

    def _backing_field(self, fields: dict, chain: list[dict], obj: int,
                       sig: str) -> dict:
        for name in _BACKING_NAMES:
            f = fields.get(name)
            if f and f["sig"] == "[B":
                return f
        cands = [f for f in fields.values() if f["sig"] == "[B"]
        if len(cands) == 1:
            return cands[0]
        raise CapabilityError(
            f"no usable heap backing byte[] field on {obj} ({sig})",
            hint="unknown ByteBuffer implementation; refusing to guess "
                 "instead of exporting wrong bytes",
            reason="unknown_implementation",
            handle=obj, class_sig=sig,
            fields=self._field_summary(chain))

    def _int_field(self, fields: dict, name: str, chain: list[dict],
                   obj: int, sig: str) -> dict:
        f = fields.get(name)
        if f and f["sig"] == "I":
            return f
        raise CapabilityError(
            f"no int field {name!r} on {obj} ({sig})",
            hint="unknown ByteBuffer implementation; refusing to guess "
                 "instead of exporting wrong bytes",
            reason="unknown_implementation",
            handle=obj, class_sig=sig,
            fields=self._field_summary(chain))

    def _field_summary(self, chain: list[dict]) -> list[dict]:
        """Enumerated runtime fields for capability-error context."""
        out = []
        for c in chain:
            for f in self._req(self.c.rt_fields, c["type_id"]):
                out.append({"name": f["name"], "sig": f["sig"],
                            "declaring": c["sig"],
                            "static": bool(f["mod_bits"] & _ACC_STATIC)})
        return out

    def _buffer_state(self, obj: int, fetch: dict) -> dict:
        ids = [f["id"] for f in
               (fetch["position"], fetch["limit"], fetch["mark"]) if f]
        vals = self._req(self.c.object_get_values, obj, ids)
        it = iter(v["v"] for v in vals)
        return {"position": next(it), "limit": next(it),
                "mark": next(it, None) if fetch["mark"] else None}

    # ---------------------------------------------------------------- pump
    def _pump(self, arr: int, start: int, total: int, fh,
              sha) -> int:
        done = 0
        while done < total:
            if self.cancel is not None and self.cancel.is_set():
                raise _Abort(f"cancelled after {done}/{total} bytes")
            if self.deadline_s is not None \
                    and time.monotonic() - self._t0 > self.deadline_s:
                raise _Abort(f"deadline exceeded after {done}/{total} bytes")
            n = min(self.chunk_size, total - done)
            items = self._req(self.c.array_get_values,
                              arr, start + done, n)["items"]
            data = bytes(v & 0xFF for v in items)
            fh.write(data)
            sha.update(data)
            done += n
            self.chunks += 1
        return done

    # ---------------------------------------------------------------- misc
    def _req(self, fn, *args):
        self.requests += 1
        return fn(*args)

    def _elapsed_ms(self) -> int:
        return int((time.monotonic() - self._t0) * 1000)

    def _cleanup(self, tmp: Path) -> None:
        if not self.keep_partial:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def _incomplete(self, reason: str, total: int, done: int,
                    tmp: Path) -> ExportIncompleteError:
        retained = tmp if (self.keep_partial and tmp.exists()) else None
        if retained is None:
            policy = "the partial temp file was removed"
        else:
            policy = f"keep_partial retained the partial file at {retained}"
        return ExportIncompleteError(
            f"buffer export incomplete: {reason} "
            f"({done}/{total} bytes written)",
            hint=f"re-issue the export against fresh handles/epoch; {policy}",
            reason=reason.split(":")[0],
            bytes_exported=done, bytes_requested=total,
            partial_file=str(retained) if retained else None,
            elapsed_ms=self._elapsed_ms(), jdwp_requests=self.requests)

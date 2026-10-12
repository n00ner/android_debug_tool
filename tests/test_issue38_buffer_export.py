"""Offline tests for issue #38 — bounded byte[]/heap-ByteBuffer export.
Duck-typed FakeClient drives the BufferExporter (and a real DebugSession
for the epoch/stale-handle and disconnect paths); no device."""

from __future__ import annotations

import builtins
import errno
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from apkdbg.core.manifests import RunStore
from apkdbg.core.project import Project
from apkdbg.debug import buffers
from apkdbg.debug.buffers import BufferExporter
from apkdbg.debug.session import DebugSession
from apkdbg.device.jdwp import JdwpConnError, JdwpError
from apkdbg.errors import (
    CapabilityError, ExportIncompleteError, SessionError, StaleHandleError,
)
from apkdbg.commands import cmd_export_buffer

ACC_STATIC = 0x8

CORPUS = bytes((i * 1103515245 + 12345 >> 16) & 0xFF for i in range(65536))


# ---------------------------------------------------------------- fake JDWP
def F(fid, name, sig, static=False):
    return {"id": fid, "name": name, "sig": sig,
            "mod_bits": ACC_STATIC if static else 0}


# OpenJDK/ART-style: Buffer{position,limit,mark,capacity} <-
# ByteBuffer{hb,offset} <- HeapByteBuffer
FIELDS_OPENJDK = {
    1: [F(11, "position", "I"), F(12, "limit", "I"), F(13, "mark", "I"),
        F(14, "capacity", "I")],
    2: [F(21, "hb", "[B"), F(22, "offset", "I")],
    3: [],
    4: [],  # java.lang.Object
}
SIGS_OPENJDK = {1: "Ljava/nio/Buffer;", 2: "Ljava/nio/ByteBuffer;",
                3: "Ljava/nio/HeapByteBuffer;", 4: "Ljava/lang/Object;"}
SUPERS_OPENJDK = {3: 2, 2: 1, 1: 4, 4: 0}

# older libcore-style: backingArray/arrayOffset on the heap class itself
FIELDS_LIBCORE = {
    5: [F(51, "position", "I"), F(52, "limit", "I"), F(53, "mark", "I")],
    6: [F(61, "backingArray", "[B"), F(62, "arrayOffset", "I")],
    4: [],
}
SIGS_LIBCORE = {5: "Ljava/nio/Buffer;", 6: "Ljava/nio/HeapByteBuffer;",
                4: "Ljava/lang/Object;"}
SUPERS_LIBCORE = {6: 5, 5: 4, 4: 0}


class FakeClient:
    def __init__(self):
        self.arrays = {}        # oid -> bytes
        self.obj_type = {}      # oid -> (tag, type_id)
        self.sigs = {}          # type_id -> sig
        self.supers = {}        # type_id -> super type_id (0 = end)
        self.fields = {}        # type_id -> [field dicts]
        self.field_vals = {}    # (oid, field_id) -> tagged value
        self.get_calls = []     # (oid, start, length) array reads
        self.mutations = []     # any state-changing call lands here
        self.fail_get_after = None  # JdwpConnError on the Nth array read

    # reads -------------------------------------------------------------
    def object_reftype(self, obj):
        return self.obj_type[obj]

    def rt_signature(self, type_id):
        return self.sigs[type_id]

    def ct_superclass(self, class_id):
        return self.supers.get(class_id, 0)

    def rt_fields(self, type_id):
        return self.fields.get(type_id, [])

    def object_get_values(self, obj, field_ids):
        return [self.field_vals[(obj, f)] for f in field_ids]

    def array_length(self, obj):
        return len(self.arrays[obj])

    def array_get_values(self, obj, start=0, length=256):
        self.get_calls.append((obj, start, length))
        if self.fail_get_after is not None \
                and len(self.get_calls) > self.fail_get_after:
            raise JdwpConnError("simulated disconnect", phase="post-send")
        data = self.arrays[obj]
        if length == 0:
            return {"component_tag": 66, "items": [], "inferred": True}
        if start < 0 or start + length > len(data):
            raise JdwpError(f"INVALID_LENGTH {start}+{length}")
        return {"component_tag": 66,
                "items": [b - 256 if b > 127 else b
                          for b in data[start:start + length]]}

    # mutators must never be reached by an export ------------------------
    def object_set_values(self, obj, values):
        self.mutations.append(("object_set_values", obj))

    def invoke_object_method(self, *a, **kw):
        self.mutations.append(("invoke_object_method",))

    def frame_set_values(self, *a, **kw):
        self.mutations.append(("frame_set_values",))

    def close(self):
        pass


def make_array_client(data=CORPUS, oid=800):
    c = FakeClient()
    c.arrays[oid] = data
    c.obj_type[oid] = (91, 50)
    c.sigs[50] = "[B"
    c.supers[50] = 0
    return c, oid


def make_buffer_client(layout="openjdk", position=4096, limit=61440,
                       mark=100, buf_offset=0, buf_oid=900, arr_oid=800,
                       readonly=None):
    c, _ = make_array_client()
    if layout == "openjdk":
        c.obj_type[buf_oid] = (76, 3)
        c.sigs.update(SIGS_OPENJDK)
        c.supers.update(SUPERS_OPENJDK)
        c.fields.update({k: list(v) for k, v in FIELDS_OPENJDK.items()})
        ids = {"position": 11, "limit": 12, "mark": 13,
               "hb": 21, "offset": 22}
        if readonly is not None:
            # ART API 35 layout: isReadOnly flag on java.nio.ByteBuffer,
            # plain HeapByteBuffer runtime class for read-only views
            c.fields[2].append(F(24, "isReadOnly", "Z"))
            ids["isReadOnly"] = 24
    else:
        c.obj_type[buf_oid] = (76, 6)
        c.sigs.update(SIGS_LIBCORE)
        c.supers.update(SUPERS_LIBCORE)
        c.fields.update({k: list(v) for k, v in FIELDS_LIBCORE.items()})
        ids = {"position": 51, "limit": 52, "mark": 53,
               "hb": 61, "offset": 62}
        if readonly is not None:
            c.fields[6].append(F(64, "readOnly", "Z"))
            ids["readOnly"] = 64
    c.field_vals[(buf_oid, ids["position"])] = {"tag": 73, "v": position}
    c.field_vals[(buf_oid, ids["limit"])] = {"tag": 73, "v": limit}
    c.field_vals[(buf_oid, ids["mark"])] = {"tag": 73, "v": mark}
    c.field_vals[(buf_oid, ids["hb"])] = {"tag": 91, "v": arr_oid}
    c.field_vals[(buf_oid, ids["offset"])] = {"tag": 73, "v": buf_offset}
    if readonly is not None:
        key = "isReadOnly" if layout == "openjdk" else "readOnly"
        c.field_vals[(buf_oid, ids[key])] = {"tag": 90, "v": readonly}
    return c, buf_oid, arr_oid


def make_session(client, project=None) -> DebugSession:
    s = DebugSession.__new__(DebugSession)
    s.project = project
    s.adb = None
    s.pkg = s.pid = s.port = None
    s.client = client
    s.bp_registry = {}
    s._sig_cache = {}
    return s


class _Ctx:
    """Minimal cmd ctx (project + session), mirroring commands.Ctx use."""

    def __init__(self, project, session):
        self.project = project
        self._session = session

    @property
    def session(self):
        return self._session


def make_project(tmp: str) -> Project:
    proj = Project.create(tmp)
    with proj.db() as db:
        db.set_meta("sha256", "ab" * 32)
    return proj


# -------------------------------------------------------------------- tests
CTOR_KEYS = {"chunk_size", "max_bytes", "deadline_s", "keep_partial",
             "capped"}


def run_export(client, oid, dest, **kw):
    ctor = {k: kw.pop(k) for k in list(kw) if k in CTOR_KEYS}
    return BufferExporter(client, **ctor).export(oid, dest=dest, **kw)


class ArrayExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self.tmp.name) / "out.bin"

    def tearDown(self):
        self.tmp.cleanup()

    def export(self, client, oid, **kw):
        return run_export(client, oid, self.dest, **kw)

    def test_full_array_export(self):
        c, oid = make_array_client()
        res = self.export(c, oid, chunk_size=1000)
        self.assertTrue(res["complete"])
        self.assertEqual(res["export_kind"], "full")
        self.assertEqual(self.dest.read_bytes(), CORPUS)
        self.assertEqual(res["bytes"]["sha256"],
                         hashlib.sha256(CORPUS).hexdigest())
        self.assertEqual(res["bytes"]["requested"], 65536)
        self.assertEqual(res["bytes"]["exported"], 65536)
        # chunk math: 65536 / 1000 -> 65 full + 1 partial read
        self.assertEqual(len(c.get_calls), 66)
        self.assertEqual(c.get_calls[0], (oid, 0, 1000))
        self.assertEqual(c.get_calls[-1], (oid, 65000, 536))
        self.assertEqual(res["timing"]["chunks"], 66)
        self.assertFalse(res["consistency"]["atomic_snapshot"])
        self.assertEqual(c.mutations, [])

    def test_array_range_export(self):
        c, oid = make_array_client()
        res = self.export(c, oid, offset=100, length=500)
        self.assertEqual(self.dest.read_bytes(), CORPUS[100:600])
        self.assertEqual(res["range"],
                         {"offset": 100, "length": 500,
                          "backing_offset": 100})
        self.assertEqual(res["bytes"]["sha256"],
                         hashlib.sha256(CORPUS[100:600]).hexdigest())

    def test_zero_length_array(self):
        c, oid = make_array_client(data=b"")
        res = self.export(c, oid)
        self.assertTrue(res["complete"])
        self.assertEqual(self.dest.read_bytes(), b"")
        self.assertEqual(res["bytes"]["sha256"],
                         hashlib.sha256(b"").hexdigest())
        self.assertEqual(c.get_calls, [])  # no GetValues for an empty range

    def test_boundary_ranges(self):
        c, oid = make_array_client(data=b"abc")
        res = self.export(c, oid, offset=3, length=0)  # empty tail range
        self.assertEqual(self.dest.read_bytes(), b"")
        self.assertTrue(res["complete"])
        res = self.export(c, oid, offset=1)  # length defaults to the end
        self.assertEqual(self.dest.read_bytes(), b"bc")
        res = self.export(c, oid, length=2)  # offset defaults to 0
        self.assertEqual(self.dest.read_bytes(), b"ab")

    def test_out_of_bounds_rejected_before_artifact(self):
        c, oid = make_array_client(data=b"abc")
        for kw in ({"offset": -1}, {"length": -1}, {"offset": 4},
                   {"offset": 2, "length": 2}, {"length": 4}):
            with self.assertRaises(SessionError) as cm:
                self.export(c, oid, **kw)
            self.assertEqual(cm.exception.outcome, "failed")
            self.assertFalse(self.dest.exists())
            self.assertFalse(self.dest.with_name("out.bin.part").exists())
        self.assertEqual(c.get_calls, [])  # rejected before any read

    def test_max_bytes_requires_explicit_cap(self):
        c, oid = make_array_client()
        with self.assertRaises(SessionError) as cm:
            self.export(c, oid, max_bytes=1024)
        self.assertEqual(cm.exception.context["requested"], 65536)
        self.assertFalse(self.dest.exists())

    def test_capped_preview_is_explicitly_incomplete(self):
        c, oid = make_array_client()
        res = self.export(c, oid, max_bytes=1024, capped=True)
        self.assertFalse(res["complete"])
        self.assertEqual(res["export_kind"], "capped")
        self.assertEqual(res["bytes"]["requested"], 65536)
        self.assertEqual(res["bytes"]["exported"], 1024)
        self.assertEqual(self.dest.read_bytes(), CORPUS[:1024])
        self.assertEqual(res["bytes"]["sha256"],
                         hashlib.sha256(CORPUS[:1024]).hexdigest())

    def test_source_array_rejects_non_byte_array(self):
        c, oid = make_array_client()
        c.sigs[50] = "[I"
        with self.assertRaises(CapabilityError):
            self.export(c, oid, source="array")
        self.assertFalse(self.dest.exists())


class ByteBufferExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self.tmp.name) / "out.bin"

    def tearDown(self):
        self.tmp.cleanup()

    def export(self, client, oid, **kw):
        return run_export(client, oid, self.dest, **kw)

    def test_default_range_is_position_to_limit(self):
        c, buf, arr = make_buffer_client()
        res = self.export(c, buf)
        want = CORPUS[4096:61440]
        self.assertEqual(self.dest.read_bytes(), want)
        self.assertEqual(res["bytes"]["sha256"],
                         hashlib.sha256(want).hexdigest())
        src = res["source"]
        self.assertEqual(src["kind"], "heap_byte_buffer")
        self.assertEqual(src["backing_field"], "hb")
        self.assertEqual(src["offset_field"], "offset")
        self.assertEqual(src["buffer"]["array_offset"], 0)
        self.assertEqual(res["range"]["backing_offset"], 4096)
        self.assertTrue(res["state_preserved"])
        self.assertEqual(res["buffer_state"],
                         {"position": 4096, "limit": 61440, "mark": 100})
        self.assertEqual(c.mutations, [])

    def test_explicit_range_relative_to_position(self):
        c, buf, arr = make_buffer_client()
        res = self.export(c, buf, offset=100, length=200)
        self.assertEqual(self.dest.read_bytes(), CORPUS[4196:4396])
        self.assertEqual(res["range"]["backing_offset"], 4196)

    def test_array_offset_translation_slice(self):
        # slice of a buffer at position 4096: own offset accumulates
        c, buf, arr = make_buffer_client(buf_offset=4096, position=16,
                                         limit=1000)
        res = self.export(c, buf)
        self.assertEqual(self.dest.read_bytes(), CORPUS[4112:4112 + 984])

    def test_nested_slice_offset_accumulates(self):
        # slice of the slice: offset 4096+16, own position adds again
        c, buf, arr = make_buffer_client(buf_offset=4112, position=4,
                                         limit=500)
        res = self.export(c, buf)
        self.assertEqual(self.dest.read_bytes(), CORPUS[4116:4116 + 496])

    def test_libcore_field_layout(self):
        c, buf, arr = make_buffer_client(layout="libcore")
        res = self.export(c, buf)
        self.assertEqual(self.dest.read_bytes(), CORPUS[4096:61440])
        self.assertEqual(res["source"]["backing_field"], "backingArray")
        self.assertEqual(res["source"]["offset_field"], "arrayOffset")

    def test_read_only_view_is_capability_error(self):
        c, buf, arr = make_buffer_client()
        c.obj_type[buf] = (76, 7)  # HeapByteBufferR extends HeapByteBuffer
        c.sigs[7] = "Ljava/nio/HeapByteBufferR;"
        c.supers[7] = 3
        with self.assertRaises(CapabilityError) as cm:
            self.export(c, buf)
        self.assertEqual(cm.exception.context["reason"],
                         "read_only_no_array_access")
        self.assertFalse(self.dest.exists())
        self.assertEqual(c.get_calls, [])

    def test_flag_based_read_only_is_capability_error(self):
        # ART API 35 layout: plain HeapByteBuffer runtime class, boolean
        # isReadOnly=True on java.nio.ByteBuffer (no R subclass at all)
        c, buf, arr = make_buffer_client(readonly=True)
        res_sig = c.sigs[c.obj_type[buf][1]]
        self.assertEqual(res_sig, "Ljava/nio/HeapByteBuffer;")
        with self.assertRaises(CapabilityError) as cm:
            self.export(c, buf)
        self.assertEqual(cm.exception.context["reason"],
                         "read_only_no_array_access")
        self.assertEqual(cm.exception.context["flag_field"], "isReadOnly")
        self.assertFalse(self.dest.exists())
        self.assertEqual(c.get_calls, [])  # no array reads before refusal

    def test_libcore_flag_read_only_is_capability_error(self):
        c, buf, arr = make_buffer_client(layout="libcore", readonly=True)
        with self.assertRaises(CapabilityError) as cm:
            self.export(c, buf)
        self.assertEqual(cm.exception.context["reason"],
                         "read_only_no_array_access")
        self.assertFalse(self.dest.exists())

    def test_flag_false_exports_normally(self):
        c, buf, arr = make_buffer_client(readonly=False)
        res = self.export(c, buf)
        self.assertEqual(self.dest.read_bytes(), CORPUS[4096:61440])
        self.assertTrue(res["state_preserved"])
        self.assertEqual(c.mutations, [])

    def test_direct_buffer_is_capability_error(self):
        c, buf, arr = make_buffer_client()
        c.obj_type[buf] = (76, 8)  # DirectByteBuffer extends ByteBuffer
        c.sigs[8] = "Ljava/nio/DirectByteBuffer;"
        c.supers[8] = 2
        c.fields[8] = [F(81, "address", "J")]
        with self.assertRaises(CapabilityError) as cm:
            self.export(c, buf)
        self.assertEqual(cm.exception.context["reason"], "direct_or_native")
        self.assertFalse(self.dest.exists())
        self.assertEqual(c.get_calls, [])

    def test_unknown_implementation_is_capability_error(self):
        c, buf, arr = make_buffer_client()
        c.obj_type[buf] = (76, 9)
        c.sigs[9] = "Lcom/vendor/WeirdBuffer;"
        c.supers[9] = 4  # straight subclass of Object
        c.fields[9] = [F(91, "dataPtr", "J")]
        with self.assertRaises(CapabilityError) as cm:
            self.export(c, buf)
        self.assertEqual(cm.exception.context["reason"],
                         "unknown_implementation")
        self.assertIn("fields", cm.exception.context)  # enumerated layout
        self.assertFalse(self.dest.exists())
        self.assertEqual(c.get_calls, [])

    def test_ambiguous_backing_field_is_capability_error(self):
        c, buf, arr = make_buffer_client()
        c.obj_type[buf] = (76, 10)  # two byte[] fields, no known name
        c.sigs[10] = "Lcom/vendor/TwoArrays;"
        c.supers[10] = 1  # extends Buffer (position/limit/mark)
        c.fields[10] = [F(101, "dataA", "[B"), F(102, "dataB", "[B")]
        with self.assertRaises(CapabilityError) as cm:
            self.export(c, buf)
        self.assertEqual(cm.exception.context["reason"],
                         "unknown_implementation")
        self.assertFalse(self.dest.exists())

    def test_state_mutation_detected(self):
        c, buf, arr = make_buffer_client()
        real = c.object_get_values
        calls = {"n": 0}

        def flipping(obj, field_ids):
            calls["n"] += 1
            vals = real(obj, field_ids)
            if calls["n"] == 2:  # the post-export state re-read
                vals = [dict(v) for v in vals]
                vals[0]["v"] += 1  # position moved under us
            return vals

        c.object_get_values = flipping
        res = self.export(c, buf)
        self.assertFalse(res["state_preserved"])
        self.assertIn("buffer_state_after", res)
        self.assertEqual(self.dest.read_bytes(), CORPUS[4096:61440])


class IncompleteExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self.tmp.name) / "out.bin"
        self.part = Path(self.tmp.name) / "out.bin.part"

    def tearDown(self):
        self.tmp.cleanup()

    def test_deadline_aborts_and_removes_partial(self):
        c, oid = make_array_client()
        with self.assertRaises(ExportIncompleteError) as cm:
            BufferExporter(c, deadline_s=0.0, chunk_size=1000).export(
                oid, dest=self.dest)
        e = cm.exception
        self.assertEqual(e.code, "E_EXPORT_INCOMPLETE")
        self.assertEqual(e.outcome, "partial")
        self.assertEqual(e.context["bytes_requested"], 65536)
        self.assertIsNone(e.context["partial_file"])
        self.assertFalse(self.dest.exists())
        self.assertFalse(self.part.exists())

    def test_keep_partial_retains_temp_file(self):
        c, oid = make_array_client()
        # fake clock: t0=0, first deadline check passes (1 chunk written),
        # second check exceeds the deadline -> abort mid-export
        clock = mock.Mock(side_effect=[0.0, 0.0, 10.0, 10.0, 10.0])
        with mock.patch("apkdbg.debug.buffers.time.monotonic", clock):
            with self.assertRaises(ExportIncompleteError) as cm:
                BufferExporter(c, deadline_s=5.0, chunk_size=1000,
                               keep_partial=True).export(oid, dest=self.dest)
        partial = cm.exception.context["partial_file"]
        self.assertIsNotNone(partial)
        got = Path(partial).read_bytes()
        self.assertTrue(0 < len(got) < 65536)
        self.assertEqual(got, CORPUS[:len(got)])
        self.assertFalse(self.dest.exists())  # never published

    def test_disconnect_mid_export_cleans_up(self):
        c, oid = make_array_client()
        c.fail_get_after = 2
        s = make_session(c)
        with self.assertRaises(JdwpConnError):
            s.export_buffer(oid, 0, dest=self.dest, chunk_size=1000)
        self.assertFalse(self.dest.exists())
        self.assertFalse(self.part.exists())

    def test_disk_full_is_incomplete_and_cleans_up(self):
        c, oid = make_array_client()
        real_open = builtins.open

        def full_disk(path, mode="r", *a, **kw):
            if str(path).endswith(".part") and "w" in mode:
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_open(path, mode, *a, **kw)

        with mock.patch("builtins.open", full_disk):
            with self.assertRaises(ExportIncompleteError) as cm:
                BufferExporter(c, chunk_size=1000).export(oid, dest=self.dest)
        self.assertIn("host write failed", str(cm.exception))
        self.assertFalse(self.dest.exists())
        self.assertFalse(self.part.exists())

    def test_bounded_host_memory_shape(self):
        # a large fake array: reads are chunked at chunk_size, so the
        # largest single JDWP read is chunk_size regardless of export size
        c, oid = make_array_client(data=bytes(300000))
        BufferExporter(c, chunk_size=65536).export(oid, dest=self.dest)
        self.assertEqual(self.dest.stat().st_size, 300000)
        for _, _, n in c.get_calls:
            self.assertLessEqual(n, 65536)


class SessionAndManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self.tmp.name) / "out.bin"

    def tearDown(self):
        self.tmp.cleanup()

    def test_stale_epoch_rejected_before_any_read(self):
        c, oid = make_array_client()
        s = make_session(c)
        with self.assertRaises(StaleHandleError) as cm:
            s.export_buffer(oid, 99, dest=self.dest)
        self.assertEqual(cm.exception.code, "E_STALE_HANDLE")
        self.assertEqual(c.get_calls, [])
        self.assertFalse(self.dest.exists())

    def test_epoch_echoed_in_result(self):
        c, oid = make_array_client()
        s = make_session(c)
        ctx = _Ctx(None, s)
        res = cmd_export_buffer(ctx, obj=oid, epoch=0, dest=str(self.dest))
        self.assertEqual(res["epoch"], 0)
        self.assertTrue(res["complete"])

    def test_record_persists_run_and_artifact(self):
        proj = make_project(str(Path(self.tmp.name) / "proj"))
        c, oid = make_array_client(data=b"hello")
        s = make_session(c, project=proj)
        ctx = _Ctx(proj, s)
        res = cmd_export_buffer(ctx, obj=oid, epoch=0, dest=str(self.dest),
                                record=True, scenario="unit")
        store = RunStore(proj)
        run = store.get_run(res["run_id"])
        self.assertEqual(run["run"]["kind"], "buffer_export")
        self.assertEqual(run["run"]["completion_reason"], "completed")
        self.assertEqual(run["run"]["counts"], {"bytes": 5})
        art = store.get_artifact(res["artifact_id"])
        self.assertEqual(art["kind"], "buffer_export")
        self.assertEqual(art["body"]["bytes"]["sha256"],
                         hashlib.sha256(b"hello").hexdigest())
        self.assertTrue(art["body"]["complete"])
        self.assertEqual(art["body"]["file"], str(self.dest))

    def test_failed_export_records_incomplete_artifact(self):
        proj = make_project(str(Path(self.tmp.name) / "proj"))
        c, oid = make_array_client()
        s = make_session(c, project=proj)
        ctx = _Ctx(proj, s)
        with self.assertRaises(ExportIncompleteError):
            cmd_export_buffer(ctx, obj=oid, epoch=0, dest=str(self.dest),
                              record=True, deadline=0.0, chunk_size=1000)
        store = RunStore(proj)
        runs = store.list_runs()["runs"]
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["completion_reason"], "failed")

    def test_default_dest_under_project_exports(self):
        proj = make_project(str(Path(self.tmp.name) / "proj"))
        c, oid = make_array_client(data=b"x")
        s = make_session(c, project=proj)
        ctx = _Ctx(proj, s)
        res = cmd_export_buffer(ctx, obj=oid, epoch=0)
        self.assertTrue(res["file"].startswith(str(proj.root / "exports")))
        self.assertEqual(Path(res["file"]).read_bytes(), b"x")


if __name__ == "__main__":
    unittest.main()

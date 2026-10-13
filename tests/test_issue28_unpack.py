"""Offline tests for issue #28 — runtime DEX payload discovery at loading
boundaries. Duck-typed FakeClient drives the collector against a real
DebugSession (no device); DEX header/full validation is exercised on
synthetic buffers, including the declared fixture corpus."""

from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from apkdbg.core.manifests import RunStore
from apkdbg.core.project import Project
from apkdbg.debug import unpack
from apkdbg.debug.session import DebugSession
from apkdbg.device.jdwp import (
    EVK_BREAKPOINT, EVK_METHOD_EXIT_RET, JdwpError,
)

ACC_STATIC = 0x8
HEADER = 0x70


# ------------------------------------------------------------ synthetic DEX
def make_dex(version="035", extra=b"", corrupt=None) -> bytes:
    """Minimal but fully valid DEX: header + empty map_list (+ optional
    extra data bytes). corrupt: 'checksum' | 'signature' | 'file_size'."""
    data = bytearray(HEADER + 4 + len(extra))
    file_size = len(data)
    data[0:8] = b"dex\n" + version.encode("ascii") + b"\x00"
    struct.pack_into("<I", data, 0x20, file_size)
    struct.pack_into("<I", data, 0x24, HEADER)
    struct.pack_into("<I", data, 0x28, 0x12345678)
    struct.pack_into("<I", data, 0x34, HEADER)          # map_off
    struct.pack_into("<I", data, 0x68, 4 + len(extra))  # data_size
    struct.pack_into("<I", data, 0x6C, HEADER)          # data_off
    data[HEADER + 4:] = extra
    if corrupt == "file_size":
        struct.pack_into("<I", data, 0x20, file_size + 64)
    data[0x0C:0x20] = hashlib.sha1(bytes(data[32:])).digest()
    if corrupt == "signature":
        data[0x0C] ^= 0xFF
    struct.pack_into("<I", data, 0x08, zlib.adler32(bytes(data[12:])))
    if corrupt == "checksum":
        struct.pack_into("<I", data, 0x08, 0xDEADBEEF)
    return bytes(data)


DEX = make_dex(extra=bytes(range(256)))
DEX_SHA256 = hashlib.sha256(DEX).hexdigest()
FAKE_MAGIC = b"dex\n035\x00" + b"A" * 248
NON_DEX = b"the quick brown fox jumps over the lazy dog" * 4


# ---------------------------------------------------------------- fake JDWP
def F(fid, name, sig, static=False):
    return {"id": fid, "name": name, "sig": sig,
            "mod_bits": ACC_STATIC if static else 0}


# OpenJDK/ART-style ByteBuffer layout (as in test_issue38)
FIELDS_BUF = {
    1: [F(11, "position", "I"), F(12, "limit", "I"), F(13, "mark", "I")],
    2: [F(21, "hb", "[B"), F(22, "offset", "I")],
    3: [],
    4: [],
}
SIGS_BUF = {1: "Ljava/nio/Buffer;", 2: "Ljava/nio/ByteBuffer;",
            3: "Ljava/nio/HeapByteBuffer;", 4: "Ljava/lang/Object;"}
SUPERS_BUF = {3: 2, 2: 1, 1: 4, 4: 0}

IMDCL = "Ldalvik/system/InMemoryDexClassLoader;"
DCL = "Ldalvik/system/DexClassLoader;"
CIPHER = "Ljavax/crypto/Cipher;"


def _timeout():
    e = JdwpError("event wait timed out")
    e.code = "E_JDWP_TIMEOUT"
    return e


class FakeClient:
    def __init__(self):
        self.next_rid = 1
        self.classes = {}       # sig -> [{"type_id": int}]
        self.methods = {}       # type_id -> [method dicts]
        self.sigs = dict(SIGS_BUF)
        self.supers = dict(SUPERS_BUF)
        self.fields = {k: list(v) for k, v in FIELDS_BUF.items()}
        self.obj_type = {}      # oid -> (tag, type_id)
        self.field_vals = {}    # (oid, field_id) -> tagged value
        self.arrays = {}        # oid -> bytes
        self.strings = {}       # oid -> str
        self.frames = {}        # thread -> [frame dicts]
        self.slot_values = {}   # (frame_id, slot) -> raw value
        self.event_queue = []
        self.cleared = []
        self.resumed = []
        self.this_obj = None

    def close(self):
        pass

    def _rid(self):
        rid = self.next_rid
        self.next_rid += 1
        return rid

    # types / methods ----------------------------------------------------
    def classes_by_signature(self, sig):
        return self.classes.get(sig, [])

    def rt_methods(self, type_id):
        return self.methods.get(type_id, [])

    def rt_signature(self, type_id):
        return self.sigs.get(type_id, f"Lfake/{type_id};")

    def ct_superclass(self, class_id):
        return self.supers.get(class_id, 0)

    def rt_fields(self, type_id):
        return self.fields.get(type_id, [])

    def method_line_table(self, type_id, method_id):
        return {"lines": [{"index": 0, "line": 1}]}

    def method_var_table(self, type_id, method_id):
        raise JdwpError("ABSENT_INFORMATION")

    # events ---------------------------------------------------------------
    def set_breakpoint(self, class_id, method_id, index, suspend_policy=2):
        return self._rid()

    def set_event(self, kind, suspend, mods):
        return self._rid()

    def mod_class_only(self, type_id):
        return (4, b"")

    def mod_class_match(self, pattern):
        return (5, b"")

    def clear_event(self, kind, request_id):
        self.cleared.append((kind, request_id))

    def next_event(self, timeout=None):
        if self.event_queue:
            return self.event_queue.pop(0)
        raise _timeout()

    def thread_resume(self, thread):
        self.resumed.append(thread)

    # frames ----------------------------------------------------------------
    def thread_frames(self, thread, count=32):
        return self.frames.get(thread, [])

    def frame_get_values(self, thread, frame_id, slots):
        return [{"tag": tag, "v": self.slot_values.get((frame_id, slot))}
                for slot, tag in slots]

    def frame_this_object(self, thread, frame_id):
        return {"tag": 76, "v": self.this_obj}

    # objects / arrays -------------------------------------------------------
    def object_reftype(self, obj):
        return self.obj_type[obj]

    def object_get_values(self, obj, field_ids):
        return [self.field_vals[(obj, f)] for f in field_ids]

    def array_length(self, obj):
        return len(self.arrays[obj])

    def array_get_values(self, obj, start=0, length=256):
        data = self.arrays[obj]
        if length == 0:
            return {"component_tag": 66, "items": []}
        if start < 0 or start + length > len(data):
            raise JdwpError(f"INVALID_LENGTH {start}+{length}")
        if self.obj_type.get(obj, (0, 0))[0] == 91 \
                and self.sigs.get(self.obj_type[obj][1]) != "[B":
            return {"component_tag": 76,
                    "items": [{"tag": 76, "v": v} for v in
                              data[start:start + length]]}
        return {"component_tag": 66,
                "items": [b - 256 if b > 127 else b
                          for b in data[start:start + length]]}

    def string_value(self, oid, max_len=4096):
        return self.strings.get(oid, "")[:max_len]


def make_session(client, project=None) -> DebugSession:
    s = DebugSession.__new__(DebugSession)
    s.project = project
    s.adb = None
    s.pkg = s.pid = s.port = None
    s.client = client
    s.bp_registry = {}
    s._sig_cache = {}
    return s


def make_project(tmp) -> Project:
    proj = Project.create(str(Path(tmp) / "proj"))
    with proj.db() as db:
        db.set_meta("sha256", "ab" * 32)
    return proj


def add_heap_buffer(c, data, buf_oid=900, arr_oid=800,
                    position=0, limit=None, offset=0):
    """Heap ByteBuffer over a byte[] with the openjdk field layout."""
    limit = len(data) if limit is None else limit
    c.arrays[arr_oid] = data
    c.obj_type[arr_oid] = (91, 50)
    c.sigs[50] = "[B"
    c.supers[50] = 0
    c.obj_type[buf_oid] = (76, 3)
    c.field_vals[(buf_oid, 11)] = {"tag": 73, "v": position}
    c.field_vals[(buf_oid, 12)] = {"tag": 73, "v": limit}
    c.field_vals[(buf_oid, 13)] = {"tag": 73, "v": -1}
    c.field_vals[(buf_oid, 21)] = {"tag": 91, "v": arr_oid}
    c.field_vals[(buf_oid, 22)] = {"tag": 73, "v": offset}
    return buf_oid


def add_direct_buffer(c, buf_oid=910):
    c.obj_type[buf_oid] = (76, 8)
    c.sigs[8] = "Ljava/nio/DirectByteBuffer;"
    c.supers[8] = 2
    c.fields[8] = [F(81, "address", "J")]
    return buf_oid


def add_loaders(c):
    c.classes[IMDCL] = [{"type_id": 200}]
    c.sigs[200] = IMDCL
    c.methods[200] = [
        {"name": "<init>", "id": 201,
         "sig": "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V"},
        {"name": "<init>", "id": 202,
         "sig": "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V"},
    ]
    c.classes[DCL] = [{"type_id": 300}]
    c.sigs[300] = DCL
    c.methods[300] = [
        {"name": "<init>", "id": 301,
         "sig": "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;"
                "Ljava/lang/ClassLoader;)V"},
    ]


def add_cipher(c):
    c.classes[CIPHER] = [{"type_id": 400}]
    c.sigs[400] = CIPHER
    c.methods[400] = [{"name": "doFinal", "id": 401, "sig": "([B)[B"}]
    c.fields[400] = [F(41, "transformation", "Ljava/lang/String;")]


def bp_event(rid, thread=11, cls=200, method=201):
    return {"kind": "breakpoint", "kind_id": EVK_BREAKPOINT,
            "request_id": rid, "thread": thread,
            "location": {"class": cls, "method": method, "index": 0}}


def exit_event(rid, ret, thread=11, cls=400, method=401):
    return {"kind": "method_exit_return", "kind_id": EVK_METHOD_EXIT_RET,
            "request_id": rid, "thread": thread,
            "location": {"class": cls, "method": method, "index": 0},
            "return_value": ret}


def composite(*events):
    return {"suspend_policy": 1, "events": list(events)}


class _Cancel:
    def __init__(self, set_now=False):
        self._set = set_now

    def set(self):
        self._set = True

    def is_set(self):
        return self._set


def run_ctx(session, tmp, **kw):
    kw.setdefault("export_dir", str(Path(tmp) / "exports"))
    return unpack.RunContext(session, **kw)


def process(session, ctx, obj, source="bytebuffer", hook=None, thread=11):
    hook = hook or unpack.BOUNDARY_HOOKS[0]
    return unpack.process_buffer(session, ctx, obj, source=source,
                                 hook=hook, thread=thread)


# -------------------------------------------------------------------- tests
class DexValidationTests(unittest.TestCase):
    def test_valid_dex_passes_full_check(self):
        out = unpack.dex_full_check(DEX)
        self.assertEqual(out["result"], "valid")
        self.assertEqual(out["errors"], [])
        self.assertEqual(out["file_size"], len(DEX))
        self.assertEqual(out["version"], "035")

    def test_versions_recognized(self):
        for v in ("035", "037", "038", "039", "040"):
            out = unpack.dex_header_check(make_dex(version=v))
            self.assertEqual(out["result"], "valid", v)
        out = unpack.dex_header_check(make_dex(version="999"))
        self.assertEqual(out["result"], "invalid")
        self.assertIn("version", out["errors"][0])

    def test_dex041_is_recognized_but_unsupported(self):
        # a version-only-mutated 035 header is NOT accepted as 041...
        out = unpack.dex_header_check(make_dex(version="041"))
        self.assertEqual(out["result"], "unsupported")
        self.assertEqual(out["version"], "041")
        self.assertTrue(any("041" in e for e in out["errors"]))
        # ...and neither is a well-formed 041 container header (0x78-byte
        # header, container-relative offsets): recognized, reported
        # unsupported, never misclassified as corrupt or validated
        data = bytearray(0x78 + 4)
        data[0:8] = b"dex\n041\x00"
        struct.pack_into("<I", data, 0x20, len(data))  # file_size
        struct.pack_into("<I", data, 0x24, 0x78)       # 041 header size
        struct.pack_into("<I", data, 0x28, 0x12345678)
        struct.pack_into("<I", data, 0x34, 0x78)       # map_off
        struct.pack_into("<I", data, 0x68, 4)          # data_size
        struct.pack_into("<I", data, 0x6C, 0x78)       # data_off
        data[0x0C:0x20] = hashlib.sha1(bytes(data[32:])).digest()
        struct.pack_into("<I", data, 0x08, zlib.adler32(bytes(data[12:])))
        out = unpack.dex_header_check(bytes(data))
        self.assertEqual(out["result"], "unsupported")
        self.assertEqual(unpack.dex_full_check(bytes(data))["result"],
                         "unsupported")

    def test_bad_magic(self):
        out = unpack.dex_header_check(NON_DEX)
        self.assertEqual(out["result"], "invalid")
        self.assertIn("magic", out["errors"][0])
        self.assertEqual(unpack.assess_prefix(NON_DEX)["kind"], "not_dex")

    def test_truncated_header(self):
        out = unpack.dex_header_check(DEX[:0x40])
        self.assertEqual(out["result"], "invalid")
        self.assertTrue(any("shorter than the" in e for e in out["errors"]))

    def test_section_bounds_violations(self):
        data = bytearray(make_dex())
        struct.pack_into("<I", data, 0x38, 4)      # string_ids_size
        struct.pack_into("<I", data, 0x3C, 0x10)   # off < header end
        out = unpack.dex_header_check(bytes(data))
        self.assertEqual(out["result"], "invalid")
        self.assertTrue(any("string_ids" in e for e in out["errors"]))
        data = bytearray(make_dex())
        struct.pack_into("<I", data, 0x58, 1000)   # method_ids_size
        struct.pack_into("<I", data, 0x5C, 0x70)   # escapes file_size
        out = unpack.dex_header_check(bytes(data))
        self.assertTrue(any("escapes" in e for e in out["errors"]))

    def test_endian_tag(self):
        data = bytearray(make_dex())
        struct.pack_into("<I", data, 0x28, 0x78563412)
        out = unpack.dex_header_check(bytes(data))
        self.assertEqual(out["result"], "invalid")
        self.assertTrue(any("reverse-endian" in e for e in out["errors"]))
        data = bytearray(make_dex())
        struct.pack_into("<I", data, 0x28, 0)
        out = unpack.dex_header_check(bytes(data))
        self.assertEqual(out["result"], "invalid")
        self.assertTrue(any("endian tag" in e for e in out["errors"]))

    def test_checksum_mismatch(self):
        out = unpack.dex_full_check(make_dex(extra=b"x" * 64,
                                             corrupt="checksum"))
        self.assertEqual(out["result"], "invalid")
        self.assertIn("Adler-32 checksum mismatch", out["errors"])

    def test_signature_mismatch(self):
        out = unpack.dex_full_check(make_dex(extra=b"x" * 64,
                                             corrupt="signature"))
        self.assertEqual(out["result"], "invalid")
        self.assertIn("SHA-1 signature mismatch", out["errors"])

    def test_captured_shorter_than_file_size(self):
        out = unpack.dex_full_check(DEX[:-16])
        self.assertEqual(out["result"], "invalid")
        self.assertTrue(any("truncated capture" in e for e in out["errors"]))

    def test_trailing_bytes_reported_not_rejected(self):
        out = unpack.dex_full_check(DEX + b"\x00" * 10)
        self.assertEqual(out["result"], "valid")
        self.assertEqual(out["trailing_bytes"], 10)

    def test_entropy_is_evidence_only(self):
        # a low-entropy but valid DEX is never rejected
        low = make_dex()  # mostly zeros -> low entropy
        out = unpack.dex_full_check(low)
        self.assertEqual(out["result"], "valid")
        assess = unpack.assess_prefix(low)
        self.assertEqual(assess["kind"], "candidate")
        self.assertLess(assess["evidence"]["entropy"], 4.0)
        # high-entropy random data is never promoted
        import random
        rng = random.Random(28)
        rnd = bytes(rng.randrange(256) for _ in range(2048))
        assess = unpack.assess_prefix(rnd)
        self.assertEqual(assess["kind"], "not_dex")
        self.assertGreater(assess["evidence"]["entropy"], 7.0)
        self.assertIn("evidence only", assess["evidence"]["entropy_note"])


class CorpusPrecisionTests(unittest.TestCase):
    """Declared corpus (mirrors the fixture's UNPACK cases): expected vs
    actual outcome per case — the detection precision report."""

    CORPUS = [
        ("valid_dex_heap", DEX, "candidate_valid"),
        ("fake_magic_header", FAKE_MAGIC, "candidate_invalid"),
        ("non_dex_buffer", NON_DEX, "not_dex"),
        ("empty_buffer", b"", "empty"),
    ]

    def test_expected_vs_actual(self):
        report = []
        for name, data, expected in self.CORPUS:
            assess = unpack.assess_prefix(data[:4096])
            if assess["kind"] != "candidate":
                actual = assess["kind"]
            else:
                actual = ("candidate_valid"
                          if assess["header"]["result"] == "valid"
                          else "candidate_invalid")
            report.append({"case": name, "expected": expected,
                           "actual": actual, "match": expected == actual})
        mismatches = [r for r in report if not r["match"]]
        self.assertEqual(mismatches, [], report)
        # full validation distinguishes candidate from recovered executable
        self.assertEqual(unpack.dex_full_check(DEX)["result"], "valid")
        self.assertEqual(unpack.dex_full_check(FAKE_MAGIC)["result"],
                         "invalid")


class ProcessBufferTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.c = FakeClient()
        self.s = make_session(self.c)

    def tearDown(self):
        self.tmp.cleanup()

    def exports(self):
        d = Path(self.tmp.name) / "exports"
        return sorted(d.glob("*.dex")) if d.exists() else []

    def test_validated_heap_buffer(self):
        buf = add_heap_buffer(self.c, DEX)
        rec = process(self.s, run_ctx(self.s, self.tmp.name), buf)
        self.assertEqual(rec["outcome"], "validated")
        self.assertEqual(rec["sha256"], DEX_SHA256)
        self.assertEqual(rec["captured"], rec["expected"])
        self.assertFalse(rec["deduplicated"])
        files = self.exports()
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].read_bytes(), DEX)
        sidecar = files[0].with_name(files[0].name + ".json")
        self.assertTrue(sidecar.exists())
        self.assertFalse(rec["export"]["consistency"]["atomic_snapshot"])

    def test_window_is_position_to_limit(self):
        # consumed bytes are [position, limit): pad before/after the DEX
        padded = b"\xAA" * 32 + DEX + b"\xBB" * 32
        buf = add_heap_buffer(self.c, padded, position=32,
                              limit=32 + len(DEX))
        rec = process(self.s, run_ctx(self.s, self.tmp.name), buf)
        self.assertEqual(rec["outcome"], "validated")
        self.assertEqual(rec["sha256"], DEX_SHA256)
        self.assertEqual(self.exports()[0].read_bytes(), DEX)

    def test_export_bounded_to_validated_extent(self):
        # a valid DEX followed by trailing bytes inside the window: the
        # run budget and the export cover the validated extent (372), not
        # the whole 4468-byte window
        buf = add_heap_buffer(self.c, DEX + b"\xBB" * 4096)
        ctx = run_ctx(self.s, self.tmp.name, max_run_bytes=1024)
        rec = process(self.s, ctx, buf)
        self.assertEqual(rec["outcome"], "validated")
        self.assertEqual(rec["captured"], len(DEX))
        self.assertEqual(rec["captured"], rec["expected"])
        self.assertEqual(rec["export"]["range"]["length"], len(DEX))
        self.assertEqual(ctx.exported_bytes, len(DEX))
        self.assertEqual(rec["sha256"], DEX_SHA256)
        self.assertEqual(self.exports()[0].read_bytes(), DEX)
        # a second oversized-window candidate is budgeted by its declared
        # extent, so a small DEX remains exportable within the run budget
        buf2 = add_heap_buffer(self.c, DEX + b"\xCC" * 4096,
                               buf_oid=901, arr_oid=801)
        rec2 = process(self.s, ctx, buf2)
        self.assertEqual(rec2["outcome"], "validated")

    def test_dex041_buffer_is_unsupported_never_dumped(self):
        buf = add_heap_buffer(self.c, make_dex(version="041"))
        ctx = run_ctx(self.s, self.tmp.name)
        rec = process(self.s, ctx, buf)
        self.assertEqual(rec["outcome"], "unsupported")
        self.assertEqual(rec["header"]["version"], "041")
        self.assertTrue(rec["errors"])
        self.assertEqual(self.exports(), [])
        self.assertEqual(ctx.exported_bytes, 0)  # no export attempted

    def test_dedup_by_hash_retains_observations(self):
        ctx = run_ctx(self.s, self.tmp.name)
        b1 = add_heap_buffer(self.c, DEX, buf_oid=900, arr_oid=800)
        b2 = add_heap_buffer(self.c, DEX, buf_oid=901, arr_oid=801)
        r1 = process(self.s, ctx, b1)
        r2 = process(self.s, ctx, b2)
        self.assertEqual(r1["outcome"], "validated")
        self.assertEqual(r2["outcome"], "validated")
        self.assertTrue(r2["deduplicated"])
        self.assertEqual(r2["duplicate_of"]["sha256"], DEX_SHA256)
        self.assertEqual(len(ctx.records), 2)   # every observation kept
        self.assertEqual(len(self.exports()), 1)  # one artifact on disk

    def test_direct_buffer_is_capability_outcome(self):
        buf = add_direct_buffer(self.c)
        rec = process(self.s, run_ctx(self.s, self.tmp.name), buf)
        self.assertEqual(rec["outcome"], "unsupported")
        self.assertEqual(rec["capability"]["reason"], "direct_or_native")
        self.assertEqual(self.exports(), [])   # never an empty dump

    def test_fake_magic_is_invalid_never_dumped(self):
        buf = add_heap_buffer(self.c, FAKE_MAGIC)
        rec = process(self.s, run_ctx(self.s, self.tmp.name), buf)
        self.assertEqual(rec["outcome"], "invalid")
        self.assertTrue(rec["errors"])
        self.assertEqual(self.exports(), [])

    def test_non_dex_and_empty(self):
        buf = add_heap_buffer(self.c, NON_DEX)
        rec = process(self.s, run_ctx(self.s, self.tmp.name), buf)
        self.assertEqual(rec["outcome"], "not_dex")
        self.assertIn("prefix_hex", rec["evidence"])
        empty = add_heap_buffer(self.c, b"", buf_oid=901, arr_oid=801)
        rec = process(self.s, run_ctx(self.s, self.tmp.name), empty)
        self.assertEqual(rec["outcome"], "empty")

    def test_truncated_capture_is_not_byte_identity(self):
        declared = make_dex(extra=b"y" * 300, corrupt="file_size")
        buf = add_heap_buffer(self.c, declared)
        rec = process(self.s, run_ctx(self.s, self.tmp.name), buf)
        self.assertEqual(rec["outcome"], "truncated")
        self.assertLess(rec["captured"], rec["expected"])
        self.assertIn("NOT claimed", rec["note"])

    def test_candidate_size_limit_blocks_export(self):
        buf = add_heap_buffer(self.c, DEX)
        ctx = run_ctx(self.s, self.tmp.name, max_candidate_bytes=64)
        rec = process(self.s, ctx, buf)
        self.assertEqual(rec["outcome"], "candidate")
        self.assertEqual(rec["reason"], "candidate_size_limit")
        self.assertEqual(self.exports(), [])

    def test_run_byte_budget(self):
        ctx = run_ctx(self.s, self.tmp.name, max_run_bytes=len(DEX))
        b1 = add_heap_buffer(self.c, DEX, buf_oid=900, arr_oid=800)
        other = make_dex(extra=b"z" * 100)
        b2 = add_heap_buffer(self.c, other, buf_oid=901, arr_oid=801)
        r1 = process(self.s, ctx, b1)
        r2 = process(self.s, ctx, b2)
        self.assertEqual(r1["outcome"], "validated")
        self.assertEqual(r2["outcome"], "candidate")
        self.assertEqual(r2["reason"], "run_byte_budget")
        self.assertEqual(ctx.budget_exceeded, "max_run_bytes")

    def test_candidate_budget(self):
        ctx = run_ctx(self.s, self.tmp.name, max_candidates=1)
        b1 = add_heap_buffer(self.c, DEX, buf_oid=900, arr_oid=800)
        other = make_dex(extra=b"z" * 100)
        b2 = add_heap_buffer(self.c, other, buf_oid=901, arr_oid=801)
        self.assertEqual(process(self.s, ctx, b1)["outcome"], "validated")
        r2 = process(self.s, ctx, b2)
        self.assertEqual(r2["outcome"], "candidate")
        self.assertEqual(r2["reason"], "candidate_budget")

    def test_cancel_during_export_is_incomplete(self):
        buf = add_heap_buffer(self.c, DEX)
        cancel = _Cancel(set_now=True)
        ctx = run_ctx(self.s, self.tmp.name, cancel=cancel)
        rec = process(self.s, ctx, buf)
        self.assertEqual(rec["outcome"], "incomplete")
        self.assertIn("cancelled", rec["incomplete"]["reason"])
        self.assertEqual(self.exports(), [])   # partial removed
        # no .part temp file retained either
        self.assertEqual(list(Path(ctx.export_dir).glob("*.part")), [])

    def test_byte_array_source(self):
        self.c.arrays[800] = DEX
        self.c.obj_type[800] = (91, 50)
        self.c.sigs[50] = "[B"
        self.c.supers[50] = 0
        hook = unpack.CIPHER_HOOKS["Cipher.doFinal(byte[])"]
        rec = process(self.s, run_ctx(self.s, self.tmp.name), 800,
                      source="array", hook=hook)
        self.assertEqual(rec["outcome"], "validated")
        self.assertEqual(rec["boundary"], "cipher_dofinal")


class WatchLoopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.c = FakeClient()
        self.s = make_session(self.c)
        add_loaders(self.c)

    def tearDown(self):
        self.tmp.cleanup()

    def watch(self, **kw):
        kw.setdefault("duration_s", 5)
        kw.setdefault("export_dir", str(Path(self.tmp.name) / "exports"))
        return unpack.run_watch(self.s, **kw)

    def ctor_event(self, rid, buf_oid, thread=11, method=201, cls=200):
        self.c.frames[thread] = [{"frame_id": 1, "location": {
            "class": cls, "method": method, "index": 0}}]
        self.c.slot_values[(1, 1)] = buf_oid
        return bp_event(rid, thread=thread, cls=cls, method=method)

    def test_end_to_end_validated(self):
        add_heap_buffer(self.c, DEX)
        # install first to learn the rid, then queue the hit
        rep = unpack.install(self.s)
        rid = rep["installed"][0]["request_ids"][0]
        self.c.event_queue.append(composite(self.ctor_event(rid, 900)))
        out = self.watch()
        self.assertEqual(out["reason"], "duration")
        self.assertEqual(out["outcome_counts"], {"validated": 1})
        rec = out["records"][0]
        self.assertEqual(rec["sha256"], DEX_SHA256)
        self.assertEqual(self.c.resumed, [11])  # lease released the stop
        # teardown cleared every owned request (both ctor overloads)
        self.assertEqual(sorted(self.c.cleared),
                         [(EVK_BREAKPOINT, 1), (EVK_BREAKPOINT, 2)])

    def test_buffer_array_overload(self):
        add_heap_buffer(self.c, DEX, buf_oid=900, arr_oid=800)
        self.c.obj_type[950] = (91, 60)
        self.c.sigs[60] = "[Ljava/nio/ByteBuffer;"
        self.c.supers[60] = 0
        self.c.arrays[950] = [900]  # object array: one ByteBuffer handle
        rep = unpack.install(self.s)
        rid = rep["installed"][1]["request_ids"][0]
        self.c.frames[11] = [{"frame_id": 1, "location": {
            "class": 200, "method": 202, "index": 0}}]
        self.c.slot_values[(1, 1)] = 950
        self.c.event_queue.append(
            composite(bp_event(rid, cls=200, method=202)))
        out = self.watch()
        self.assertEqual(out["outcome_counts"], {"validated": 1})
        self.assertEqual(out["records"][0]["array_index"], 0)

    def test_path_evidence_boundary(self):
        self.c.strings[700] = "/data/app/~~x/base.apk"
        self.c.strings[701] = "/data/app/~~x/oat"
        self.c.frames[11] = [{"frame_id": 1, "location": {
            "class": 300, "method": 301, "index": 0}}]
        self.c.slot_values[(1, 1)] = 700
        self.c.slot_values[(1, 2)] = 701
        self.c.slot_values[(1, 3)] = 0
        rep = unpack.install(self.s, boundaries=["dex_class_loader_path"])
        rid = rep["installed"][0]["request_ids"][0]
        self.c.event_queue.append(
            composite(bp_event(rid, cls=300, method=301)))
        out = self.watch(boundaries=["dex_class_loader_path"])
        self.assertEqual(out["outcome_counts"], {"path_evidence": 1})
        rec = out["records"][0]
        self.assertEqual(rec["paths"]["dex_path"], "/data/app/~~x/base.apk")
        self.assertIn("no in-memory payload", rec["note"])

    def test_max_events_stops_run(self):
        b1 = add_heap_buffer(self.c, DEX, buf_oid=900, arr_oid=800)
        b2 = add_heap_buffer(self.c, NON_DEX, buf_oid=901, arr_oid=801)
        rep = unpack.install(self.s)
        rid = rep["installed"][0]["request_ids"][0]
        self.c.event_queue.append(composite(self.ctor_event(rid, b1)))
        self.c.event_queue.append(composite(self.ctor_event(rid, b2)))
        out = self.watch(max_events=1)
        self.assertEqual(out["reason"], "max_events")
        self.assertTrue(out["truncated"])
        self.assertEqual(len(out["records"]), 1)

    def test_cancel_stops_run(self):
        out = self.watch(cancel=_Cancel(set_now=True))
        self.assertEqual(out["reason"], "cancelled")
        self.assertEqual(out["records"], [])

    def test_cipher_boundary_opt_in(self):
        add_cipher(self.c)
        self.c.arrays[600] = DEX
        self.c.obj_type[600] = (91, 50)
        self.c.sigs[50] = "[B"
        self.c.supers[50] = 0
        self.c.this_obj = 555
        self.c.obj_type[555] = (76, 400)
        self.c.strings[556] = "AES/CBC/PKCS5Padding"
        self.c.field_vals[(555, 41)] = {"tag": 115, "v": 556}
        rep = unpack.install(self.s, boundaries=[],
                             cipher_overloads=["Cipher.doFinal(byte[])"])
        rids = rep["installed"][0]["request_ids"]
        self.assertEqual(len(rids), 2)  # entry + class-scoped exit
        self.c.frames[11] = [{"frame_id": 1, "location": {
            "class": 400, "method": 401, "index": 0}}]
        self.c.event_queue.append(composite(
            bp_event(rids[0], cls=400, method=401),
            exit_event(rids[1], {"tag": 91, "v": 600})))
        out = self.watch(boundaries=[],
                         cipher_overloads=["Cipher.doFinal(byte[])"])
        self.assertEqual(out["outcome_counts"], {"validated": 1})
        rec = out["records"][0]
        self.assertEqual(rec["boundary"], "cipher_dofinal")
        self.assertEqual(rec["cipher"]["algorithm"], "AES/CBC/PKCS5Padding")

    def test_cipher_not_hooked_by_default(self):
        add_cipher(self.c)
        rep = unpack.install(self.s)
        hooks = {i["hook"] for i in rep["installed"]}
        self.assertNotIn("Cipher.doFinal(byte[])", hooks)

    def test_unknown_cipher_overload_rejected(self):
        with self.assertRaises(Exception) as cm:
            unpack.install(self.s, cipher_overloads=["Cipher.update(byte[])"])
        self.assertIn("unknown Cipher.doFinal overload",
                      str(cm.exception))

    def test_class_not_loaded_is_pending(self):
        self.c.classes.clear()
        rep = unpack.install(self.s)
        self.assertEqual(rep["installed"], [])
        self.assertEqual(len(rep["pending"]), 2)  # both ctor overloads
        self.assertEqual(rep["pending"][0]["state"], "pending")


class ManifestAndIndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.c = FakeClient()
        self.s = make_session(self.c, project=self.proj)
        add_loaders(self.c)

    def tearDown(self):
        self.tmp.cleanup()

    def _recorded_run(self):
        buf = add_heap_buffer(self.c, DEX)
        rep = unpack.install(self.s)
        rid = rep["installed"][0]["request_ids"][0]
        self.c.frames[11] = [{"frame_id": 1, "location": {
            "class": 200, "method": 201, "index": 0}}]
        self.c.slot_values[(1, 1)] = buf
        self.c.event_queue.append(composite(bp_event(rid)))
        return unpack.run_watch(
            self.s, duration_s=5,
            export_dir=str(Path(self.tmp.name) / "exports"),
            record=True, scenario="unit", index=True)

    def test_record_persists_run_events_artifacts(self):
        out = self._recorded_run()
        store = RunStore(self.proj)
        run = store.get_run(out["run_id"])
        self.assertEqual(run["run"]["kind"], "unpack_watch")
        self.assertEqual(run["run"]["scenario"], "unit")
        self.assertEqual(run["run"]["completion_reason"], "duration")
        self.assertEqual(run["run"]["counts"]["outcomes"],
                         {"validated": 1})
        self.assertEqual(len(run["events"]), 1)
        self.assertEqual(run["events"][0]["kind"], "unpack_observation")
        self.assertEqual(len(run["artifacts"]), 1)
        art = run["artifacts"][0]
        self.assertEqual(art["kind"], "unpack_dex")
        body = art["body"]
        # metadata completeness: id/path, hashes, lengths, validation,
        # run/event/source, buffer range, caller status, completeness
        for key in ("run_id", "file", "sha256", "captured", "expected",
                    "validation", "boundary", "hook", "range", "thread",
                    "complete", "consistency_note"):
            self.assertIn(key, body, key)
        self.assertEqual(body["sha256"], DEX_SHA256)
        self.assertTrue(body["complete"])
        self.assertEqual(body["validation"]["result"], "valid")
        # payload bytes are never inlined into the manifest
        self.assertNotIn(DEX.hex()[:64], json.dumps(body))
        # index=True registered the artifact
        self.assertEqual(len(out["indexed"]), 1)
        self.assertEqual(out["indexed"][0]["artifact_key"], DEX_SHA256)

    def test_register_artifact_additive_and_dedup(self):
        out = self._recorded_run()
        store = RunStore(self.proj)
        art_id = out["records"][0]["artifact_id"]
        from apkdbg.commands import Ctx, cmd_unpack_index
        ctx = Ctx.__new__(Ctx)
        ctx.project = self.proj
        reg = cmd_unpack_index(ctx, action="index", artifact_id=art_id)
        self.assertEqual(reg["artifact_key"], DEX_SHA256)
        # re-registration dedupes by hash, retaining each observation
        reg2 = cmd_unpack_index(ctx, action="index", artifact_id=art_id)
        self.assertTrue(reg2["deduplicated"])
        self.assertEqual(reg2["observations"], reg["observations"] + 1)
        page = cmd_unpack_index(ctx, action="list")
        self.assertEqual(page["total"], 1)
        row = page["artifacts"][0]
        self.assertEqual(row["sha256"], DEX_SHA256)
        self.assertEqual(row["origin"]["artifact_id"], art_id)
        self.assertEqual(row["apk_sha256"], "ab" * 32)
        # the static index is untouched: no classes/methods appeared
        with self.proj.db() as db:
            self.assertEqual(
                db.one("SELECT COUNT(*) AS n FROM classes")["n"], 0)
            self.assertEqual(
                db.one("SELECT COUNT(*) AS n FROM methods")["n"], 0)

    def test_register_rejects_non_validated_artifacts(self):
        from apkdbg.commands import Ctx, cmd_unpack_index
        ctx = Ctx.__new__(Ctx)
        ctx.project = self.proj
        store = RunStore(self.proj)
        run_id = store.begin_run("snapshot", capture_config={})
        art_id = store.add_artifact(run_id, "snapshot", {"x": 1})
        with self.assertRaises(Exception) as cm:
            cmd_unpack_index(ctx, action="index", artifact_id=art_id)
        self.assertIn("not an unpack_dex artifact", str(cm.exception))

    def test_runtime_artifacts_carried_across_reindex(self):
        from apkdbg.core.init_pipeline import OBSERVATION_TABLES
        self.assertIn("runtime_artifacts", OBSERVATION_TABLES)


if __name__ == "__main__":
    unittest.main()

"""Offline tests for issue #24: static-analysis capabilities, structured
errors, and the capabilities command. Builds tiny synthetic projects
(mapping.db + project.json) in tmp dirs — no real APKs, no adb, no JDWP."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from apkdbg import cli, protocol
from apkdbg.commands import Ctx, cmd_capabilities, cmd_classes
from apkdbg.core import capabilities as capmod
from apkdbg.core.database import MappingDB
from apkdbg.core.project import Project
from apkdbg.decompile import mappings
from apkdbg.debug.session import DebugSession
from apkdbg.device.adb import Adb
from apkdbg.errors import (AttachUnavailableError, DeviceAbsentError,
                           LineMappingError, ProcessNotFoundError)


def make_project(root: Path, *, line_rows: int = 2, classes: int = 1,
                 resources: int = 1, refs: int = 1, meta: bool = True,
                 complete: bool = True, warnings: list | None = None,
                 manifest_debuggable: str | None = "true",
                 package: str = "a.b") -> Project:
    """Synthetic initialized project. meta=False simulates a legacy DB that
    predates the meta keys."""
    db = MappingDB(root / "mapping.db")
    for i in range(classes):
        db.execute(
            "INSERT INTO classes(sig,fqcn,smali_path) VALUES(?,?,?)",
            (f"La/b/C{i};", f"a.b.C{i}", f"smali/a/b/C{i}.smali"))
        db.execute("INSERT INTO methods(class_id,name,sig) VALUES(?,?,?)",
                   (i + 1, "run", "()V"))
        for dl in range(line_rows):
            db.execute(
                "INSERT INTO line_map(method_id,dalvik_line,smali_line)"
                " VALUES(?,?,?)", (i + 1, 10 + dl, 100 + dl))
    for i in range(resources):
        db.execute("INSERT INTO resources(res_id,type,name) VALUES(?,?,?)",
                   (0x7F010001 + i, "string", f"res_{i}"))
    for i in range(refs):
        db.execute(
            "INSERT INTO resource_refs(res_id,method_id,kind) VALUES(?,?,?)",
            (0x7F010001 + i, 1, "getString"))
    if meta:
        db.set_meta("schema_version", "2")
        db.set_meta("index_version", "1")
        db.set_meta("index_complete", "true" if complete else "false")
        db.set_meta("index_warnings", json.dumps(warnings or []))
        if manifest_debuggable is not None:
            db.set_meta("manifest_debuggable", manifest_debuggable)
        if complete:
            if line_rows > 0:
                db.set_meta("line_map_state", "complete")
                db.set_meta("line_map_reason", "ok")
            elif classes > 0:
                db.set_meta("line_map_state", "empty")
                db.set_meta("line_map_reason", "no_line_directives")
        else:
            db.set_meta("line_map_state", "unknown")
            db.set_meta("line_map_reason", "index_incomplete")
    db.close()
    state = {"apk": "app.apk", "package": package, "sha256": "deadbeef"}
    if manifest_debuggable is not None:
        state["manifest_debuggable"] = manifest_debuggable
    (root / "project.json").write_text(json.dumps(state), "utf-8")
    return Project.open(root)


def no_adb(test_fn):
    """Decorator: any attempt to construct a real Adb fails the test."""
    class ExplodingAdb:
        def __init__(self, *a, **k):
            raise AssertionError("adb must not be touched offline")
    return mock.patch.object(capmod, "Adb", ExplodingAdb)(test_fn)


class CapabilitiesReportTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    @no_adb
    def test_complete_index_reports_static_supported(self):
        make_project(self.root, line_rows=3, classes=2)
        rep = cmd_capabilities(Ctx(str(self.root)))
        caps = rep["capabilities"]
        self.assertEqual(rep["mode"], "static_full")
        for key in ("classes", "methods", "res", "res_refs"):
            self.assertEqual(caps[key]["status"], "supported", key)
            self.assertGreater(caps[key]["evidence"]["count"], 0, key)
        slr = caps["source_line_resolution"]
        self.assertEqual(slr["status"], "supported")
        self.assertEqual(slr["evidence"]["line_rows"], 6)  # 2 classes x 3
        # every runtime command reported individually, unknown pre-probe
        for key in capmod.RUNTIME_COMMANDS:
            self.assertIn(key, caps)
            self.assertEqual(caps[key]["source"], "static_inference", key)
        # report is one line of strict JSON
        line = protocol.dumps(rep)
        self.assertNotIn("\n", line)
        json.loads(line)

    @no_adb
    def test_zero_line_rows_reports_unsupported_with_reason(self):
        make_project(self.root, line_rows=0, classes=5, complete=True)
        rep = cmd_capabilities(Ctx(str(self.root)))
        caps = rep["capabilities"]
        self.assertEqual(rep["mode"], "static_no_line_map")
        slr = caps["source_line_resolution"]
        self.assertEqual(slr["status"], "unsupported")
        self.assertEqual(slr["evidence"]["reason"], "no_line_directives")
        # static queries unaffected, still answered from the DB (no attach)
        self.assertEqual(caps["classes"]["status"], "supported")
        self.assertEqual(caps["classes"]["evidence"]["count"], 5)
        out = cmd_classes(Ctx(str(self.root)))
        self.assertEqual(out["count"], 5)
        self.assertNotIn("index_note", out)
        # bp flagged limited, not silently supported
        self.assertEqual(caps["bp"]["status"], "limited")

    @no_adb
    def test_index_generation_failure_not_misread_as_stripped(self):
        make_project(self.root, line_rows=0, classes=3, complete=False,
                     resources=0, refs=0,
                     warnings=["indexing aborted: disk full"])
        rep = cmd_capabilities(Ctx(str(self.root)))
        self.assertEqual(rep["mode"], "static_incomplete")
        self.assertFalse(rep["index"]["complete"])
        self.assertIn("disk full", rep["index"]["warnings"][0])
        lm = rep["index"]["line_map"]
        self.assertEqual(lm["state"], "unknown")
        self.assertEqual(lm["reason"], "index_incomplete")
        slr = rep["capabilities"]["source_line_resolution"]
        self.assertEqual(slr["status"], "unknown")
        self.assertNotIn("stripped", json.dumps(slr).lower())
        # partial tables are reported as unknown, not unsupported
        self.assertEqual(rep["capabilities"]["res"]["status"], "unknown")

    @no_adb
    def test_manifest_debuggable_matrix_is_distinct(self):
        reports = {}
        for md in ("true", "false", None):
            for lines in (2, 0):
                d = self.root / f"md{md}_l{lines}"
                d.mkdir()
                make_project(d, line_rows=lines,
                             manifest_debuggable=md)
                reports[(md, lines)] = cmd_capabilities(Ctx(str(d)))
        # 6 distinct reports, not one inferred boolean
        rendered = {json.dumps(r["capabilities"]["jdwp_attach"], sort_keys=True)
                    + json.dumps(r["capabilities"]["source_line_resolution"],
                                 sort_keys=True)
                    for r in reports.values()}
        self.assertEqual(len(rendered), 6)
        jd_true = reports[("true", 2)]["capabilities"]["jdwp_attach"]
        jd_false = reports[("false", 2)]["capabilities"]["jdwp_attach"]
        jd_none = reports[(None, 2)]["capabilities"]["jdwp_attach"]
        self.assertEqual(jd_true["status"], "unknown")
        self.assertEqual(jd_true["evidence"]["manifest_debuggable"], "true")
        self.assertEqual(jd_false["status"], "limited")
        self.assertEqual(jd_false["evidence"]["manifest_debuggable"], "false")
        self.assertEqual(jd_none["evidence"]["manifest_debuggable"], "unknown")
        # manifest flag does not leak into the static line-map verdict
        self.assertEqual(
            reports[("false", 2)]["capabilities"]
            ["source_line_resolution"]["status"], "supported")
        self.assertEqual(
            reports[("true", 0)]["capabilities"]
            ["source_line_resolution"]["status"], "unsupported")

    @no_adb
    def test_legacy_db_without_meta_falls_back_to_counts(self):
        make_project(self.root, line_rows=2, meta=False,
                     manifest_debuggable=None)
        rep = cmd_capabilities(Ctx(str(self.root)))
        self.assertEqual(rep["index"]["schema_version"], "1")
        slr = rep["capabilities"]["source_line_resolution"]
        self.assertEqual(slr["status"], "supported")  # rows prove the map
        self.assertEqual(rep["apk"]["manifest_debuggable"], "unknown")

        d = self.root / "legacy_empty"
        d.mkdir()
        make_project(d, line_rows=0, meta=False, manifest_debuggable=None)
        rep2 = cmd_capabilities(Ctx(str(d)))
        lm = rep2["index"]["line_map"]
        # zero rows + no metadata: unknown, NOT claimed stripped
        self.assertEqual((lm["state"], lm["reason"]),
                         ("unknown", "no_index_metadata"))
        self.assertEqual(rep2["capabilities"]["source_line_resolution"]
                         ["status"], "unknown")

    @no_adb
    def test_empty_tables_explain_missing_index(self):
        make_project(self.root, classes=0, line_rows=0, resources=0, refs=0)
        out = cmd_classes(Ctx(str(self.root)))
        self.assertEqual(out["count"], 0)
        self.assertIn("index_note", out)
        self.assertTrue(out["index_note"]["table_empty"])
        self.assertIn("capabilities", out["index_note"]["hint"])

    @no_adb
    def test_cli_subparser_offline(self):
        make_project(self.root, line_rows=1)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["--project", str(self.root), "capabilities"])
        self.assertEqual(rc, 0)
        line = buf.getvalue().strip()
        self.assertNotIn("\n", line)
        payload = json.loads(line)
        self.assertEqual(payload["status"], "ok")
        self.assertIn("capabilities", payload["data"])


class StructuredErrorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_absent_device_structured(self):
        adb = Adb.__new__(Adb)
        adb.bin, adb.serial, adb.timeout = "adb", None, 30
        adb.sh = lambda *a, **k: ""  # get-state -> empty
        with self.assertRaises(DeviceAbsentError) as cm:
            adb.ensure_device()
        d = cm.exception.to_dict()
        self.assertEqual(d["code"], "E_DEVICE_ABSENT")
        self.assertIn("hint", d)
        json.loads(protocol.dumps(protocol.err(cm.exception)))

    def test_absent_process_structured(self):
        adb = Adb.__new__(Adb)
        adb.bin, adb.serial, adb.timeout = "adb", None, 30
        adb.sh = lambda *a, **k: ""
        with self.assertRaises(ProcessNotFoundError) as cm:
            adb.wait_pid("com.x", timeout=0)
        d = cm.exception.to_dict()
        self.assertEqual(d["code"], "E_PROCESS_ABSENT")
        self.assertEqual(d["context"]["package"], "com.x")

    def test_connect_absent_device_via_cmd(self):
        make_project(self.root)
        class FakeAdb:
            def __init__(self, *a, **k): pass
            def ensure_device(self):
                raise DeviceAbsentError("no device connected",
                                        hint="check USB cable")
        with mock.patch("apkdbg.debug.session.Adb", FakeAdb):
            with self.assertRaises(DeviceAbsentError) as cm:
                from apkdbg.commands import cmd_connect
                cmd_connect(Ctx(str(self.root)), pkg="a.b")
        self.assertEqual(cm.exception.to_dict()["code"], "E_DEVICE_ABSENT")

    def test_bp_empty_line_map_raises_line_mapping_error(self):
        make_project(self.root, line_rows=0, classes=1, complete=True)
        with mock.patch("apkdbg.debug.session.Adb", lambda *a, **k: None):
            sess = DebugSession(Project.open(self.root))
        with self.assertRaises(LineMappingError) as cm:
            sess.set_breakpoint("a.b.C0.run:42")
        d = cm.exception.to_dict()
        self.assertEqual(d["code"], "E_LINE_MAPPING")
        self.assertIn("smali", d["hint"])
        self.assertEqual(d["context"]["line_map_reason"], "no_line_directives")
        # serializes to one strict JSON line, no traceback
        line = protocol.dumps(protocol.err(cm.exception))
        self.assertNotIn("\n", line)
        self.assertNotIn("Traceback", line)

    def test_bp_legacy_unknown_line_map_also_guarded(self):
        make_project(self.root, line_rows=0, meta=False,
                     manifest_debuggable=None)
        with mock.patch("apkdbg.debug.session.Adb", lambda *a, **k: None):
            sess = DebugSession(Project.open(self.root))
        with self.assertRaises(LineMappingError):
            sess.set_breakpoint("a.b.C0.run:42")

    def test_attach_unavailable_is_structured(self):
        e = AttachUnavailableError("JDWP attach failed", hint="not debuggable")
        self.assertEqual(e.to_dict()["code"], "E_ATTACH_UNAVAILABLE")


class ProbeTests(unittest.TestCase):
    """Probe paths with fully stubbed adb/JDWP layers."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_probe_absent_device_records_observation(self):
        make_project(self.root, manifest_debuggable="true")

        class FakeAdb:
            def __init__(self, *a, **k): pass
            def ensure_device(self):
                raise DeviceAbsentError("no device connected")

        with mock.patch.object(capmod, "Adb", FakeAdb):
            rep = cmd_capabilities(Ctx(str(self.root)), probe=True)
        obs = rep["probe"]
        self.assertFalse(obs["device"]["present"])
        self.assertEqual(obs["device"]["error"]["code"], "E_DEVICE_ABSENT")
        # static facts untouched by the observation
        self.assertEqual(rep["capabilities"]["classes"]["source"],
                         "mapping_db")
        self.assertEqual(rep["capabilities"]["connect"]["status"],
                         "unsupported")
        self.assertEqual(rep["capabilities"]["connect"]["source"], "observed")

    def test_probe_full_attach_observes_line_tables(self):
        make_project(self.root, line_rows=2, manifest_debuggable="true")

        class FakeAdb:
            def __init__(self, *a, **k): pass
            def ensure_device(self): return "device"
            def pidof(self, pkg): return 4242
            def forward_jdwp(self, pid, port=None): return 5555
            def remove_forward(self, port): pass

        class FakeClient:
            def __init__(self, *a, **k):
                self.handshake_info = {}
            def connect(self):
                self.handshake_info = {"vm_name": "ART", "jdwp_major": 1,
                                       "jdwp_minor": 8}
            def close(self): pass
            def classes_by_signature(self, sig): return [{"type_id": 7}]
            def rt_methods(self, tid): return [{"id": 9}]
            def method_line_table(self, tid, mid):
                return {"lines": [{"line": 10, "index": 0}]}

        with mock.patch.object(capmod, "Adb", FakeAdb), \
                mock.patch.object(capmod, "JdwpClient", FakeClient):
            rep = cmd_capabilities(Ctx(str(self.root)), probe=True)
        obs = rep["probe"]
        self.assertTrue(obs["jdwp"]["attached"])
        self.assertEqual(obs["runtime_line_table"]["availability"], "present")
        caps = rep["capabilities"]
        self.assertEqual(caps["jdwp_attach"]["status"], "supported")
        self.assertEqual(caps["jdwp_attach"]["source"], "observed")
        self.assertEqual(caps["runtime_line_table"]["status"], "supported")

    def test_probe_attach_refused_keeps_distinct_error(self):
        make_project(self.root, manifest_debuggable="false")
        from apkdbg.errors import JdwpError

        class FakeAdb:
            def __init__(self, *a, **k): pass
            def ensure_device(self): return "device"
            def pidof(self, pkg): return 4242
            def forward_jdwp(self, pid, port=None): return 5555
            def remove_forward(self, port): pass

        class RefusingClient:
            def __init__(self, *a, **k): pass
            def connect(self):
                raise JdwpError("JDWP handshake rejected")
            def close(self): pass

        with mock.patch.object(capmod, "Adb", FakeAdb), \
                mock.patch.object(capmod, "JdwpClient", RefusingClient):
            rep = cmd_capabilities(Ctx(str(self.root)), probe=True)
        self.assertFalse(rep["probe"]["jdwp"]["attached"])
        self.assertEqual(rep["capabilities"]["jdwp_attach"]["status"],
                         "unsupported")
        self.assertEqual(rep["capabilities"]["jdwp_attach"]["source"],
                         "observed")


class ManifestParsingTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _manifest(self, application_attr: str) -> Path:
        p = self.root / "AndroidManifest.xml"
        p.write_text(
            f'<manifest package="com.x"><application {application_attr}>'
            f"</application></manifest>", "utf-8")
        return p

    def test_debuggable_true_false_missing(self):
        self.assertIs(mappings.parse_manifest_debuggable(
            self._manifest('android:debuggable="true"')), True)
        self.assertIs(mappings.parse_manifest_debuggable(
            self._manifest('android:debuggable="false"')), False)
        self.assertIsNone(mappings.parse_manifest_debuggable(
            self._manifest('android:label="x"')))
        self.assertIsNone(
            mappings.parse_manifest_debuggable(self.root / "absent.xml"))


if __name__ == "__main__":
    unittest.main()

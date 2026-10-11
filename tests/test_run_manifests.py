"""Offline tests for issue #36 — run manifests, durable event/artifact
identity, export/import round-trip, and structural snapshot diff.
DB tests use temp project dirs; producer tests drive a real DebugSession
with a duck-typed fake JDWP client (no device)."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from apkdbg import __version__
from apkdbg.core.database import MappingDB
from apkdbg.core.manifests import (
    MANIFEST_VERSION, RunStore, bump_index_generation,
)
from apkdbg.core.project import Project
from apkdbg.debug.coverage import CoverageTracker
from apkdbg.debug.hooks import crypto
from apkdbg.debug.session import DebugSession
from apkdbg.debug.snapdiff import (
    check_compatible, diff_nodes, flatten_snapshot, snapshot_diff,
)
from apkdbg.debug.snapshot import Budgets, truncation_report
from apkdbg.device.jdwp import (
    EVK_BREAKPOINT, EVK_SINGLE_STEP, JdwpError,
)
from apkdbg.errors import SessionError

CLS_SIG = "Ljavax/crypto/Cipher;"
HOOK = "Cipher.doFinal()"


# ------------------------------------------------------------------- helpers
def make_project(tmp: str, sha256: str = "ab" * 32) -> Project:
    proj = Project.create(tmp)
    with proj.db() as db:
        db.set_meta("sha256", sha256)
    return proj


def make_session(client, project=None) -> DebugSession:
    s = DebugSession.__new__(DebugSession)
    s.project = project
    s.adb = None
    s.pkg = s.pid = s.port = None
    s.client = client
    s.bp_registry = {}
    s._sig_cache = {}
    return s


def _timeout_error():
    e = JdwpError("event wait timed out")
    e.code = "E_JDWP_TIMEOUT"
    return e


class FakeClient:
    def __init__(self):
        self.next_rid = 1
        self.event_queue = []
        self.resumed = []
        self.cleared = []
        self.sigs = {1000: "Lcom/foo/A;"}
        self.methods = {1000: [{"name": "m", "sig": "()V", "id": 500}]}
        self.classes = {}
        self.frames = {}
        self.this_obj = None

    def _rid(self):
        rid = self.next_rid
        self.next_rid += 1
        return rid

    def close(self):
        pass

    def set_event(self, kind, suspend, mods):
        return self._rid()

    def set_breakpoint(self, class_id, method_id, index, suspend_policy=2):
        return self._rid()

    def clear_event(self, kind, request_id):
        self.cleared.append((kind, request_id))

    def mod_class_match(self, pattern):
        return (1, pattern)

    def mod_thread_only(self, thread):
        return (2, thread)

    def mod_step(self, thread, size, depth):
        return (3, thread)

    def mod_class_only(self, type_id):
        return (4, type_id)

    def thread_resume(self, thread):
        self.resumed.append(thread)

    def next_event(self, timeout=None):
        if self.event_queue:
            return self.event_queue.pop(0)
        raise _timeout_error()

    def rt_signature(self, type_id):
        return self.sigs.get(type_id, f"Lfake/{type_id};")

    def rt_methods(self, type_id):
        return self.methods.get(type_id, [])

    def method_line_table(self, type_id, method_id):
        return {"lines": [{"index": 0, "line": 42}]}

    def classes_by_signature(self, sig):
        return self.classes.get(sig, [])

    def method_var_table(self, type_id, method_id):
        raise JdwpError("ABSENT_INFORMATION")

    def thread_frames(self, thread, count=32):
        return self.frames.get(thread, [])

    def frame_get_values(self, thread, frame_id, slots):
        return [{"tag": tag, "v": None} for slot, tag in slots]

    def frame_this_object(self, thread, frame_id):
        return {"tag": 76, "v": self.this_obj}


def composite(*events):
    return {"suspend_policy": 1, "events": list(events)}


def obj(cls, oid, fields=None, **extra):
    node = {"cls": cls, "id": oid}
    if fields:
        node["f"] = fields
    node.update(extra)
    return node


# --------------------------------------------------------------- store tests
class ManifestStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.store = RunStore(self.proj)

    def tearDown(self):
        self.tmp.cleanup()

    def test_manifest_fields_persisted(self):
        rid = self.store.begin_run(
            "coverage", {"mode": "line", "packages": ["com.foo"]},
            scenario="login-flow", epoch=3,
            environment={"vm_name": "ART", "android_api": "35"})
        self.store.end_run(rid, "budget", counts={"events": 7})
        got = self.store.get_run(rid)
        run = got["run"]
        self.assertEqual(run["run_id"], rid)
        self.assertEqual(run["manifest_version"], MANIFEST_VERSION)
        self.assertEqual(run["kind"], "coverage")
        self.assertEqual(run["scenario"], "login-flow")
        self.assertEqual(run["apk_sha256"], "ab" * 32)
        self.assertEqual(run["index_generation"], 1)
        self.assertEqual(run["tool_version"], __version__)
        self.assertEqual(run["capture_config"]["mode"], "line")
        self.assertEqual(run["environment"]["android_api"], "35")
        self.assertEqual(run["epoch"], 3)
        self.assertEqual(run["completion_reason"], "budget")
        self.assertEqual(run["counts"], {"events": 7})
        self.assertTrue(run["started_at"] and run["ended_at"])

    def test_list_pagination_and_kind_filter(self):
        for i in range(3):
            self.store.begin_run("coverage", {"i": i})
        self.store.begin_run("snapshot", {})
        page = self.store.list_runs(limit=2, offset=0)
        self.assertEqual(page["count"], 2)
        self.assertEqual(page["total"], 4)
        rest = self.store.list_runs(limit=2, offset=2)
        self.assertEqual(rest["count"], 2)
        only = self.store.list_runs(kind="snapshot")
        self.assertEqual(only["total"], 1)
        self.assertEqual(only["runs"][0]["kind"], "snapshot")

    def test_get_unknown_run_raises(self):
        with self.assertRaises(SessionError):
            self.store.get_run("nope")

    def test_event_identity_uses_original_descriptors(self):
        rid = self.store.begin_run("crypto_watch", {})
        eid = self.store.add_event(
            rid, "crypto_record", {"hook": HOOK, "deobf_note": "annotation"},
            class_sig=CLS_SIG, method_name="doFinal", method_sig="()[B")
        ev = self.store.get_run(rid)["events"][0]
        self.assertEqual(ev["event_id"], eid)
        self.assertEqual(ev["class_sig"], CLS_SIG)
        self.assertEqual(ev["method_name"], "doFinal")
        self.assertEqual(ev["method_sig"], "()[B")
        # deobf/recovered names are payload annotations, never identity
        self.assertEqual(ev["payload"]["deobf_note"], "annotation")

    def test_runs_survive_reindex(self):
        rid = self.store.begin_run("coverage", {})
        eid = self.store.add_event(rid, "crypto_record", {"x": 1})
        aid = self.store.add_artifact(rid, "snapshot", {"s": "v"})
        with self.proj.db() as db:
            db.execute("INSERT INTO classes(sig,fqcn,deobf_fqcn) "
                       "VALUES('La;','a','real.Name')")
            db.execute("INSERT INTO line_map(method_id,dalvik_line,"
                       "smali_line) VALUES(1,1,1)")
        # simulate re-index: derived tables rebuilt, generation bumped;
        # classes.deobf_fqcn and all observation tables untouched
        with self.proj.db() as db:
            for t in ("line_map", "branch_sites", "resource_refs",
                      "jadx_lines"):
                db.execute(f"DELETE FROM {t}")
            bump_index_generation(db)
        got = self.store.get_run(rid)
        self.assertEqual(got["run"]["index_generation"], 1)
        self.assertEqual(got["events"][0]["event_id"], eid)
        self.assertEqual(got["events"][0]["index_generation"], 1)
        self.assertEqual(got["artifacts"][0]["artifact_id"], aid)
        rid2 = self.store.begin_run("coverage", {})
        self.assertEqual(self.store.get_run(rid2)["run"]
                         ["index_generation"], 2)
        with self.proj.db() as db:
            row = db.one("SELECT deobf_fqcn FROM classes WHERE sig='La;'")
            self.assertEqual(row["deobf_fqcn"], "real.Name")

    def test_epoch_preserved_across_reconnect(self):
        s = make_session(FakeClient(), self.proj)
        store = RunStore.for_session(s)
        epoch_a = s.events.epoch
        rid_a = store.begin_run("crypto_watch", {}, epoch=s.events.epoch)
        store.add_event(rid_a, "crypto_record", {"n": 1},
                        epoch=s.events.epoch)
        s.events.bump_epoch()  # reconnect: new epoch, runtime ids dead
        self.assertNotEqual(s.events.epoch, epoch_a)
        rid_b = store.begin_run("crypto_watch", {}, epoch=s.events.epoch)
        a = self.store.get_run(rid_a)
        self.assertEqual(a["run"]["epoch"], epoch_a)
        self.assertEqual(a["events"][0]["epoch"], epoch_a)
        self.assertEqual(self.store.get_run(rid_b)["run"]["epoch"],
                         s.events.epoch)

    def test_existing_db_upgrades_additively(self):
        # a DB written by an older apkdbg (no observation tables) must open
        # with its data intact and the new tables created
        raw = Path(self.tmp.name) / "old.db"
        conn = sqlite3.connect(raw)
        conn.executescript(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
            "CREATE TABLE classes (id INTEGER PRIMARY KEY, sig TEXT NOT NULL"
            " UNIQUE, fqcn TEXT NOT NULL, deobf_fqcn TEXT, smali_path TEXT,"
            " source_file TEXT);")
        conn.execute("INSERT INTO classes(sig,fqcn,deobf_fqcn) "
                     "VALUES('Lb;','b','real.B')")
        conn.commit()
        conn.close()
        db = MappingDB(raw)
        self.assertEqual(
            db.one("SELECT deobf_fqcn FROM classes WHERE sig='Lb;'")
            ["deobf_fqcn"], "real.B")
        cols = {r["name"] for r in
                db.query("PRAGMA table_info(classes)")}
        self.assertEqual(cols, {"id", "sig", "fqcn", "deobf_fqcn",
                                "smali_path", "source_file"})
        db.execute("INSERT INTO runs(run_id,manifest_version,kind,"
                   "index_generation) VALUES('r',1,'coverage',1)")
        db.close()


# ---------------------------------------------------------- export/import
class ExportImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(str(Path(self.tmp.name) / "a"))
        self.store = RunStore(self.proj)

    def tearDown(self):
        self.tmp.cleanup()

    def _populated_run(self) -> str:
        rid = self.store.begin_run(
            "crypto_watch", {"duration_s": 5}, scenario="sc", epoch=2,
            environment={"vm_name": "ART"})
        eid = self.store.add_event(rid, "crypto_record", {"hook": HOOK},
                                   class_sig=CLS_SIG, method_name="doFinal",
                                   method_sig="()[B", epoch=2)
        self.store.add_artifact(rid, "snapshot", {"s": "v"},
                                budgets={"max_depth": 3},
                                truncation={"complete": True},
                                parent_event_id=eid, epoch=2)
        self.store.end_run(rid, "duration", counts={"hits": 1})
        return rid

    def test_roundtrip_preserves_version_and_relationships(self):
        rid = self._populated_run()
        exported = self.store.export_run(rid)
        proj_b = make_project(str(Path(self.tmp.name) / "b"),
                              sha256="cd" * 32)
        store_b = RunStore(proj_b)
        rep = store_b.import_run(exported)
        self.assertEqual(rep["run_id"], rid)
        self.assertEqual(rep["events"], 1)
        self.assertEqual(rep["artifacts"], 1)
        re_exported = store_b.export_run(rid)
        self.assertEqual(exported, re_exported)
        got = store_b.get_run(rid)
        self.assertEqual(got["run"]["manifest_version"], MANIFEST_VERSION)
        art = got["artifacts"][0]
        self.assertEqual(art["parent_event_id"], got["events"][0]["event_id"])
        self.assertEqual(art["run_id"], rid)
        self.assertEqual(art["epoch"], 2)
        # imported observations keep the generation they were captured under
        self.assertEqual(art["index_generation"], 1)
        self.assertEqual(art["checksum"],
                         hashlib.sha256(json.dumps(
                             {"s": "v"}, separators=(",", ":"))
                             .encode()).hexdigest())

    def test_import_existing_requires_replace(self):
        rid = self._populated_run()
        exported = self.store.export_run(rid)
        with self.assertRaises(SessionError):
            self.store.import_run(exported)
        rep = self.store.import_run(exported, replace=True)
        self.assertTrue(rep["replaced"])
        self.assertEqual(len(self.store.get_run(rid)["events"]), 1)

    def test_import_newer_version_rejected(self):
        rid = self._populated_run()
        exported = self.store.export_run(rid)
        exported["manifest_version"] = MANIFEST_VERSION + 1
        proj_b = make_project(str(Path(self.tmp.name) / "b"))
        with self.assertRaises(SessionError):
            RunStore(proj_b).import_run(exported)


# ------------------------------------------------------------ diff (pure)
class DiffNodeTests(unittest.TestCase):
    def test_equal_logical_graphs_different_runtime_ids(self):
        a = obj("LX;", 111, {"n": 5, "child": obj("LY;", 222,
                                                   {"back": {"$ref": 111}})})
        b = obj("LX;", 999, {"n": 5, "child": obj("LY;", 888,
                                                   {"back": {"$ref": 999}})})
        out = diff_nodes(flatten_snapshot(a), flatten_snapshot(b))
        self.assertEqual(out["changed"], {})
        self.assertEqual(out["added"], {})
        self.assertEqual(out["removed"], {})
        self.assertEqual(out["unknown"], [])

    def test_changed_values(self):
        a = obj("LX;", 1, {"n": 5, "s": {"s": "hello"}})
        b = obj("LX;", 2, {"n": 6, "s": {"s": "world"}})
        out = diff_nodes(flatten_snapshot(a), flatten_snapshot(b))
        self.assertEqual(set(out["changed"]), {"f.n", "f.s"})
        self.assertEqual(out["changed"]["f.n"]["a"]["v"], 5)
        self.assertEqual(out["changed"]["f.n"]["b"]["v"], 6)
        self.assertEqual(out["added"], {})
        self.assertEqual(out["removed"], {})

    def test_type_change_reported(self):
        a = obj("LX;", 1, {"x": obj("LA;", 2)})
        b = obj("LX;", 3, {"x": obj("LB;", 4)})
        out = diff_nodes(flatten_snapshot(a), flatten_snapshot(b))
        self.assertTrue(out["changed"]["f.x"]["type_change"])

    def test_added_and_removed_when_fully_observed(self):
        a = obj("LX;", 1, {"keep": 1, "gone": 2})
        b = obj("LX;", 2, {"keep": 1, "new": 3})
        out = diff_nodes(flatten_snapshot(a), flatten_snapshot(b))
        self.assertEqual(set(out["added"]), {"f.new"})
        self.assertEqual(set(out["removed"]), {"f.gone"})
        self.assertEqual(out["unknown"], [])

    def test_truncated_array_tail_is_unknown_not_removed(self):
        a = {"arr": [1, 2, 3, 4, 5], "len": 5}
        b = {"arr": [1, 2, 3], "len": 5, "trunc": True}
        out = diff_nodes(flatten_snapshot(a), flatten_snapshot(b))
        self.assertEqual(out["added"], {})
        self.assertEqual(out["removed"], {})
        paths = {u["path"] for u in out["unknown"]}
        self.assertIn("[3]", paths)
        self.assertIn("[4]", paths)
        self.assertTrue(all(u["side"] == "b" for u in out["unknown"]))

    def test_depth_limited_object_is_unknown_not_removed(self):
        a = obj("LX;", 1, {"deep": obj("LY;", 2, {"x": 1})})
        b = obj("LX;", 3, {"deep": obj("LY;", 4, **{"...": "depth limit"})})
        out = diff_nodes(flatten_snapshot(a), flatten_snapshot(b))
        self.assertEqual(out["removed"], {})
        self.assertEqual(out["added"], {})
        paths = {u["path"] for u in out["unknown"]}
        self.assertIn("f.deep.f.x", paths)

    def test_inaccessible_fields_are_unknown_not_removed(self):
        a = obj("LX;", 1, {"x": 1})
        b = obj("LX;", 2, fields_error="INVALID_OBJECT")
        out = diff_nodes(flatten_snapshot(a), flatten_snapshot(b))
        self.assertEqual(out["removed"], {})
        self.assertTrue(any("fields_error" in u["reason"]
                            for u in out["unknown"]))

    def test_error_node_is_unknown(self):
        a = obj("LX;", 1, {"x": 5})
        b = obj("LX;", 2, {"x": {"id": 9, "error": "INVALID_OBJECT"}})
        out = diff_nodes(flatten_snapshot(a), flatten_snapshot(b))
        self.assertEqual(out["removed"], {})
        self.assertEqual(out["changed"], {})
        self.assertEqual(len(out["unknown"]), 1)
        self.assertEqual(out["unknown"][0]["side"], "b")

    def test_locals_error_is_unknown(self):
        a = {"frame": 0, "class": "LX;", "locals": {"v": 1}}
        b = {"frame": 0, "class": "LX;", "locals": {},
             "locals_error": "ABSENT_INFORMATION"}
        out = diff_nodes(flatten_snapshot(a), flatten_snapshot(b))
        self.assertEqual(out["removed"], {})
        self.assertTrue(any(u["path"] == "locals.v"
                            for u in out["unknown"]))


# ------------------------------------------------- compatibility & store diff
class CompatTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.store = RunStore(self.proj)

    def tearDown(self):
        self.tmp.cleanup()

    def _snapshot_run(self, body, *, config=None, env=None, epoch=1,
                      reason="completed", trunc=None):
        rid = self.store.begin_run("snapshot", config or {}, epoch=epoch,
                                   environment=env or {})
        self.store.add_artifact(rid, "snapshot", body,
                                budgets={"max_depth": 3},
                                truncation=trunc or {"complete": True},
                                epoch=epoch)
        self.store.end_run(rid, reason)
        return rid

    def test_incompatible_apk_returns_explicit_reasons(self):
        a = self._snapshot_run(obj("LX;", 1, {"n": 1}))
        with self.proj.db() as db:
            db.set_meta("sha256", "ff" * 32)
        b = self._snapshot_run(obj("LX;", 2, {"n": 1}))
        out = snapshot_diff(self.store, a, b)
        self.assertFalse(out["compatible"])
        self.assertIsNone(out["changed"])
        self.assertIn("reason", out)
        apk_diffs = [d for d in out["differences"]
                     if d["field"] == "apk_sha256"]
        self.assertEqual(apk_diffs[0]["severity"], "incompatible")

    def test_forced_diff_retains_qualifications(self):
        a = self._snapshot_run(obj("LX;", 1, {"n": 1}))
        with self.proj.db() as db:
            db.set_meta("sha256", "ff" * 32)
        b = self._snapshot_run(obj("LX;", 2, {"n": 2}))
        out = snapshot_diff(self.store, a, b, force=True)
        self.assertFalse(out["compatible"])
        self.assertTrue(out["forced"])
        self.assertTrue(out["differences"])  # qualifications retained
        self.assertEqual(set(out["changed"]), {"f.n"})

    def test_scope_mismatch_incompatible(self):
        a = self._snapshot_run(obj("LX;", 1), config={
            "scope": {"type": "object", "class": "LX;"}})
        b = self._snapshot_run(obj("LX;", 2), config={
            "scope": {"type": "object", "class": "LOther;"}})
        out = snapshot_diff(self.store, a, b)
        self.assertFalse(out["compatible"])
        self.assertTrue(any(d["field"] == "scope"
                            for d in out["differences"]))

    def test_incomplete_runs_qualified_but_compared(self):
        a = self._snapshot_run(obj("LX;", 1, {"n": 1}), reason="error",
                               trunc={"complete": False,
                                      "budget_limited": 1})
        b = self._snapshot_run(obj("LX;", 2, {"n": 2}))
        out = snapshot_diff(self.store, a, b)
        self.assertTrue(out["compatible"])
        self.assertFalse(out["complete"])
        self.assertTrue(any(d["field"] == "completeness"
                            for d in out["differences"]))
        self.assertEqual(set(out["changed"]), {"f.n"})

    def test_generation_difference_is_warning(self):
        a = self._snapshot_run(obj("LX;", 1, {"n": 1}))
        with self.proj.db() as db:
            bump_index_generation(db)
        b = self._snapshot_run(obj("LX;", 2, {"n": 1}))
        out = snapshot_diff(self.store, a, b)
        self.assertTrue(out["compatible"])
        self.assertTrue(any(d["field"] == "index_generation"
                            and d["severity"] == "warning"
                            for d in out["differences"]))
        self.assertEqual(out["changed"], {})

    def test_equal_snapshots_different_ids_end_to_end(self):
        a = self._snapshot_run(obj("LX;", 111, {"c": obj("LY;", 222)}))
        b = self._snapshot_run(obj("LX;", 999, {"c": obj("LY;", 888)}))
        out = snapshot_diff(self.store, a, b)  # run ids resolve to artifacts
        self.assertTrue(out["compatible"])
        self.assertEqual(out["changed"], {})
        self.assertEqual(out["added"], {})
        self.assertEqual(out["removed"], {})

    def test_check_compatible_epoch_is_informational(self):
        run = {"apk_sha256": "x", "index_generation": 1,
               "tool_version": "1", "capture_config": {}, "environment": {},
               "epoch": 1, "completion_reason": "completed"}
        other = dict(run, epoch=2)
        art = {"budgets": {}, "truncation": {"complete": True}}
        out = check_compatible(run, art, other, art)
        self.assertTrue(out["compatible"])
        self.assertEqual([d["field"] for d in out["differences"]], ["epoch"])
        self.assertEqual(out["differences"][0]["severity"], "info")


# ---------------------------------------------------------------- producers
class CoverageRecordingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _step_event(self, rid, thread=11):
        return {"kind_id": EVK_SINGLE_STEP, "request_id": rid,
                "thread": thread,
                "location": {"class": 1000, "method": 500, "index": 0}}

    def test_line_run_persists_manifest_and_links_hits(self):
        c = FakeClient()
        c.event_queue.append(composite(self._step_event(1)))
        s = make_session(c, self.proj)
        rep = CoverageTracker(s, ["com.foo"], mode="line", thread=11,
                              seconds=30, scenario="sc").run()
        self.assertTrue(rep["recorded"])
        store = RunStore(self.proj)
        got = store.get_run(rep["run_id"])
        run = got["run"]
        self.assertEqual(run["kind"], "coverage")
        self.assertEqual(run["scenario"], "sc")
        self.assertEqual(run["capture_config"]["mode"], "line")
        self.assertEqual(run["completion_reason"], "duration")
        self.assertEqual(run["counts"]["events"], 1)
        self.assertEqual(run["epoch"], s.events.epoch)
        with self.proj.db() as db:
            hits = db.query("SELECT * FROM coverage_hits WHERE run_id=?",
                            (rep["run_id"],))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["class_sig"], "Lcom/foo/A;")
        self.assertEqual(hits[0]["dalvik_line"], 42)
        self.assertEqual(got["artifacts"][0]["kind"], "coverage_report")

    def test_method_run_records_without_db_flush(self):
        c = FakeClient()
        s = make_session(c, self.proj)
        rep = CoverageTracker(s, ["com.foo"], seconds=1).run()
        self.assertTrue(rep["recorded"])
        run = RunStore(self.proj).get_run(rep["run_id"])["run"]
        self.assertEqual(run["capture_config"]["mode"], "method")

    def test_project_less_session_skips_recording(self):
        s = make_session(FakeClient())  # project=None
        rep = CoverageTracker(s, ["com.foo"], seconds=1).run()
        self.assertNotIn("recorded", rep)


class CryptoRecordingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _client(self):
        c = FakeClient()
        c.classes[CLS_SIG] = [{"type_id": 1000}]
        c.sigs[1000] = CLS_SIG
        c.methods[1000] = [{"name": "doFinal", "sig": "()[B", "id": 1500}]
        c.frames[11] = [{"frame_id": 1, "location": {}}]
        return c

    @staticmethod
    def _bp(rid, thread=11):
        return {"kind_id": EVK_BREAKPOINT, "request_id": rid, "thread": thread,
                "location": {"class": 1000, "method": 1500, "index": 0}}

    def test_watch_records_run_and_event_rows(self):
        c = self._client()
        # entry rid=1, exit rid=2 (capture_returns=True)
        c.event_queue.append(composite(self._bp(1)))
        s = make_session(c, self.proj)
        out = crypto.run_watch(s, duration_s=30, names=[HOOK],
                               capture_returns=True, record=True,
                               scenario="sc")
        self.assertIsNotNone(out["run_id"])
        got = RunStore(self.proj).get_run(out["run_id"])
        run = got["run"]
        self.assertEqual(run["kind"], "crypto_watch")
        self.assertEqual(run["scenario"], "sc")
        self.assertEqual(run["completion_reason"], "duration")
        self.assertEqual(run["capture_config"]["max_events"], 1000)
        self.assertEqual(run["counts"]["hits"], 1)
        self.assertEqual(len(got["events"]), 1)
        ev = got["events"][0]
        self.assertEqual(ev["kind"], "crypto_record")
        self.assertEqual(ev["class_sig"], CLS_SIG)
        self.assertEqual(ev["method_name"], "doFinal")
        self.assertEqual(ev["method_sig"], "()[B")
        self.assertEqual(ev["payload"]["hook"], HOOK)
        self.assertEqual(ev["epoch"], s.events.epoch)

    def test_watch_recording_respects_max_events(self):
        c = self._client()
        c.event_queue.append(composite(self._bp(1)))
        c.event_queue.append(composite(self._bp(1)))
        s = make_session(c, self.proj)
        out = crypto.run_watch(s, duration_s=30, names=[HOOK],
                               max_events=1, record=True)
        self.assertEqual(out["reason"], "max_events")
        got = RunStore(self.proj).get_run(out["run_id"])
        self.assertEqual(len(got["events"]), 1)
        self.assertEqual(got["run"]["completion_reason"], "max_events")

    def test_watch_record_off_by_default(self):
        s = make_session(self._client(), self.proj)
        out = crypto.run_watch(s, duration_s=1, names=[HOOK])
        self.assertIsNone(out["run_id"])
        self.assertEqual(RunStore(self.proj).list_runs()["total"], 0)


class SnapshotPersistTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.store = RunStore(self.proj)

    def tearDown(self):
        self.tmp.cleanup()

    def test_truncation_report(self):
        data = obj("LX;", 1, {"s": {"s": "abc", "trunc": True},
                              "deep": {"...": "depth limit"},
                              "bad": {"id": 2, "error": "INVALID_OBJECT"}})
        rep = truncation_report(data)
        self.assertFalse(rep["complete"])
        self.assertEqual(rep["truncated_values"], 1)
        self.assertEqual(rep["budget_limited"], 1)
        self.assertEqual(rep["errors"], ["INVALID_OBJECT"])
        self.assertTrue(truncation_report(obj("LX;", 1, {"x": 1}))
                        ["complete"])

    def test_persist_artifact_with_budgets_and_checksum(self):
        from apkdbg.debug.snapshot import Snapshotter
        s = Snapshotter(FakeClient(), Budgets(max_depth=2))
        rid = self.store.begin_run("snapshot", {})
        data = obj("LX;", 1, {"x": 1})
        aid = s.persist(self.store, rid, data, epoch=4)
        art = self.store.get_artifact(aid)
        self.assertEqual(art["run_id"], rid)
        self.assertEqual(art["kind"], "snapshot")
        self.assertEqual(art["format"], "json")
        self.assertEqual(art["budgets"]["max_depth"], 2)
        self.assertTrue(art["truncation"]["complete"])
        self.assertEqual(art["epoch"], 4)
        self.assertEqual(art["body"], data)
        body_text = json.dumps(data, separators=(",", ":"),
                               ensure_ascii=False)
        self.assertEqual(art["checksum"],
                         hashlib.sha256(body_text.encode()).hexdigest())


if __name__ == "__main__":
    unittest.main()

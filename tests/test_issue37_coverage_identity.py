"""Offline tests for issue #37 — coverage method identity, line-table
mapping, evidence-backed branch outcomes with unknown reasons, report
idempotency, and incomplete-capture marking. All tests use synthetic
events and a duck-typed fake JDWP client; no device needed."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from apkdbg.core.database import MappingDB
from apkdbg.core.manifests import RunStore
from apkdbg.core.project import Project
from apkdbg.debug.coverage import CoverageTracker
from apkdbg.debug.session import DebugSession
from apkdbg.device.jdwp import EVK_SINGLE_STEP, JdwpError

CLS = "Lcom/foo/A;"
OTHER = "Lcom/foo/B;"


# ------------------------------------------------------------------- helpers
def make_project(tmp: str) -> Project:
    proj = Project.create(tmp)
    with proj.db() as db:
        db.set_meta("sha256", "ab" * 32)
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
        self.sigs = {1000: CLS}
        self.methods = {1000: [{"name": "m", "sig": "()V", "id": 500}]}
        self.line_tables = {}
        self.loaders = {}

    def _rid(self):
        rid = self.next_rid
        self.next_rid += 1
        return rid

    def close(self):
        pass

    def set_event(self, kind, suspend, mods):
        return self._rid()

    def clear_event(self, kind, request_id):
        self.cleared.append((kind, request_id))

    def mod_class_match(self, pattern):
        return (1, pattern)

    def mod_thread_only(self, thread):
        return (2, thread)

    def mod_step(self, thread, size, depth):
        return (3, thread)

    def thread_resume(self, thread):
        self.resumed.append(thread)

    def next_event(self, timeout=None):
        if self.event_queue:
            return self.event_queue.pop(0)
        raise _timeout_error()

    def rt_signature(self, type_id):
        return self.sigs[type_id]

    def rt_class_loader(self, type_id):
        return self.loaders.get(type_id, 0)

    def rt_methods(self, type_id):
        return self.methods.get(type_id, [])

    def method_line_table(self, type_id, method_id):
        table = self.line_tables.get((type_id, method_id))
        if table is None:
            raise JdwpError("ABSENT_INFORMATION")
        return {"lines": table}


def composite(*events):
    return {"suspend_policy": 1, "events": list(events)}


def step(rid=1, thread=11, cls=1000, method=500, index=0):
    return {"kind_id": EVK_SINGLE_STEP, "request_id": rid, "thread": thread,
            "location": {"class": cls, "method": method, "index": index}}


def seed_branches(proj, branches, cls_sig=CLS, name="m", sig="()V"):
    """Insert the class/method plus branch site rows; branches are dicts
    with dl/op/kind/tgt and optional smali_line."""
    with proj.db() as db:
        db.execute("INSERT OR IGNORE INTO classes(sig,fqcn) VALUES(?,?)",
                   (cls_sig, cls_sig[1:-1].replace("/", ".")))
        cid = db.one("SELECT id FROM classes WHERE sig=?", (cls_sig,))["id"]
        db.execute("INSERT OR IGNORE INTO methods(class_id,name,sig) "
                   "VALUES(?,?,?)", (cid, name, sig))
        mid = db.one("SELECT id FROM methods WHERE class_id=? AND name=? "
                     "AND sig=?", (cid, name, sig))["id"]
        for i, br in enumerate(branches):
            db.execute(
                "INSERT INTO branch_sites(method_id,smali_line,dalvik_line,"
                "opcode,kind,target_smali_line,target_dalvik_line) "
                "VALUES(?,?,?,?,?,?,?)",
                (mid, br.get("smali_line", 100 + i), br["dl"], br["op"],
                 br["kind"], None, br.get("tgt")))


def line_tracker(client, project):
    return CoverageTracker(make_session(client, project), ["com.foo"],
                           mode="line", thread=11)


def only_site(tr):
    assert len(tr.branch_outcomes) == 1, tr.branch_outcomes
    return next(iter(tr.branch_outcomes.values()))


# ---------------------------------------------------------------- identity
class MethodIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_overloads_stay_separate_in_memory_and_db(self):
        c = FakeClient()
        c.methods[1000] = [{"name": "m", "sig": "()V", "id": 500},
                           {"name": "m", "sig": "(I)V", "id": 501}]
        c.line_tables[(1000, 500)] = [{"index": 0, "line": 10}]
        c.line_tables[(1000, 501)] = [{"index": 0, "line": 20}]
        tr = line_tracker(c, self.proj)
        tr._record(step(method=500, index=0))
        tr._record(step(method=501, index=0))
        tr._record(step(method=501, index=0))
        rep = tr.report()
        self.assertEqual(rep["lines"], {"Lcom/foo/A;->m()V": {10: 1},
                                        "Lcom/foo/A;->m(I)V": {20: 2}})
        with self.proj.db() as db:
            rows = db.query("SELECT * FROM coverage_hits WHERE run_id=? "
                            "ORDER BY method_sig", (tr.run_id,))
        self.assertEqual([(r["method_name"], r["method_sig"],
                           r["dalvik_line"], r["hits"]) for r in rows],
                         [("m", "()V", 10, 1), ("m", "(I)V", 20, 2)])

    def test_method_mode_keys_include_descriptor(self):
        c = FakeClient()
        tr = CoverageTracker(make_session(c, self.proj), ["com.foo"])
        tr._record(step(method=500, index=0))
        self.assertEqual(tr.report()["methods"], {"Lcom/foo/A;->m()V": 1})

    def test_classloader_copies_tracked_and_reported(self):
        c = FakeClient()
        c.sigs[2000] = CLS  # same signature, distinct loaded copy
        c.methods[2000] = [{"name": "m", "sig": "()V", "id": 700}]
        c.loaders = {1000: 900, 2000: 901}
        c.line_tables[(1000, 500)] = [{"index": 0, "line": 10}]
        c.line_tables[(2000, 700)] = [{"index": 0, "line": 10}]
        tr = line_tracker(c, self.proj)
        tr._record(step(cls=1000, method=500, index=0))
        tr._record(step(cls=2000, method=700, index=0))
        rep = tr.report()
        # descriptor-level hits merge; the copies stay distinguishable
        self.assertEqual(rep["lines"], {"Lcom/foo/A;->m()V": {10: 2}})
        self.assertEqual(rep["loaded_copies"],
                         {CLS: {"type_ids": [1000, 2000],
                                "loaders": [900, 901]}})


# -------------------------------------------------------------- line tables
class LineTableTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_non_monotonic_table_nearest_preceding_index_wins(self):
        c = FakeClient()
        c.line_tables[(1000, 500)] = [{"index": 0, "line": 100},
                                      {"index": 4, "line": 10}]
        tr = line_tracker(c, self.proj)
        tr._record(step(index=4))
        rep = tr.report()
        self.assertEqual(rep["lines"], {"Lcom/foo/A;->m()V": {10: 1}})
        self.assertEqual(rep["offsets"]["Lcom/foo/A;->m()V"],
                         {"4": {"line": 10, "hits": 1}})

    def test_missing_table_is_explicit_unknown(self):
        c = FakeClient()  # no line table for (1000, 500)
        tr = line_tracker(c, self.proj)
        tr._record(step(index=0))
        rep = tr.report()
        self.assertEqual(rep["lines"], {})
        self.assertEqual(rep["offsets"]["Lcom/foo/A;->m()V"],
                         {"0": {"line": None, "hits": 1}})
        self.assertIn({"reason": "missing_table", "method": "Lcom/foo/A;->m()V",
                       "line": None, "count": 1}, rep["unknowns"])

    def test_uncovered_index_is_explicit_unknown(self):
        c = FakeClient()
        c.line_tables[(1000, 500)] = [{"index": 4, "line": 10}]
        tr = line_tracker(c, self.proj)
        tr._record(step(index=0))  # before the first table entry
        rep = tr.report()
        self.assertEqual(rep["lines"], {})
        self.assertEqual(rep["unknowns"][0]["reason"], "missing_table")


# ---------------------------------------------------------------- branches
class BranchOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.c = FakeClient()
        # if-site at line 10 (index 4), target line 20; fall-through
        # line 11; a later catch region at line 30
        self.c.line_tables[(1000, 500)] = [
            {"index": 0, "line": 1}, {"index": 4, "line": 10},
            {"index": 8, "line": 11}, {"index": 12, "line": 20},
            {"index": 16, "line": 30}]

    def tearDown(self):
        self.tmp.cleanup()

    def _if_site(self, tgt=20):
        return [{"dl": 10, "op": "if-eqz", "kind": "if", "tgt": tgt}]

    def test_if_taken_edge(self):
        seed_branches(self.proj, self._if_site())
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))   # line 10: the if site
        tr._record(step(index=12))  # line 20: the target
        rep = tr.report()
        rec = only_site(tr)
        self.assertEqual((rec["site_hits"], rec["taken"],
                          rec["fallthrough"], rec["unknown"]), (1, 1, 0, {}))
        self.assertEqual(rep["branches"]["edges_identified"], 1)

    def test_if_fallthrough_edge(self):
        seed_branches(self.proj, self._if_site())
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))  # line 10
        tr._record(step(index=8))  # line 11: next table region
        tr._record(step(index=1))  # line 1: no site, dangling is silent
        rep = tr.report()
        rec = only_site(tr)
        self.assertEqual((rec["site_hits"], rec["taken"],
                          rec["fallthrough"], rec["unknown"]), (1, 0, 1, {}))

    def test_same_line_target_is_taken(self):
        seed_branches(self.proj, self._if_site(tgt=10))
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))  # line 10: site
        tr._record(step(index=4))  # line 10 again: same-line target
        rec = only_site(tr)
        self.assertEqual((rec["taken"], rec["fallthrough"]), (1, 0))

    def test_target_equal_to_next_line_is_ambiguous(self):
        seed_branches(self.proj, self._if_site(tgt=11))
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))
        tr._record(step(index=8))  # line 11: target AND fall-through line
        tr._record(step(index=1))
        rec = only_site(tr)
        self.assertEqual((rec["taken"], rec["fallthrough"]), (0, 0))
        self.assertEqual(rec["unknown"], {"ambiguous_line": 1})

    def test_two_sites_one_line_unique_target_match(self):
        seed_branches(self.proj, [
            {"dl": 10, "op": "if-eqz", "kind": "if", "tgt": 20,
             "smali_line": 100},
            {"dl": 10, "op": "if-nez", "kind": "if", "tgt": 30,
             "smali_line": 105}])
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))
        tr._record(step(index=12))  # line 20: only site 1's target
        tr._record(step(index=1))
        by_smali = {r["smali_line"]: r
                    for r in tr.branch_outcomes.values()}
        self.assertEqual(by_smali[100]["taken"], 1)
        self.assertNotIn(105, by_smali)  # unmatched site not touched

    def test_two_sites_one_line_no_match_is_ambiguous(self):
        seed_branches(self.proj, [
            {"dl": 10, "op": "if-eqz", "kind": "if", "tgt": 20,
             "smali_line": 100},
            {"dl": 10, "op": "if-nez", "kind": "if", "tgt": 30,
             "smali_line": 105}])
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))
        tr._record(step(index=8))  # line 11: neither target
        tr._record(step(index=1))
        self.assertEqual(len(tr.branch_outcomes), 2)
        for rec in tr.branch_outcomes.values():
            self.assertEqual((rec["taken"], rec["fallthrough"]), (0, 0))
            self.assertEqual(rec["unknown"], {"ambiguous_line": 1})
            self.assertEqual(rec["site_hits"], 1)

    def test_switch_site_hit_is_not_an_edge(self):
        seed_branches(self.proj, [{"dl": 10, "op": "packed-switch",
                                   "kind": "switch", "tgt": None}])
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))
        tr._record(step(index=8))
        tr._record(step(index=1))
        rep = tr.report()
        rec = only_site(tr)
        self.assertEqual((rec["site_hits"], rec["taken"],
                          rec["fallthrough"]), (1, 0, 0))
        self.assertEqual(rec["unknown"], {"unresolved_target": 1})
        self.assertEqual(rep["branches"]["sites_hit"], 1)
        self.assertEqual(rep["branches"]["edges_identified"], 0)

    def test_goto_edge_identified_by_target(self):
        seed_branches(self.proj, [{"dl": 10, "op": "goto", "kind": "goto",
                                   "tgt": 20}])
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))
        tr._record(step(index=12))
        tr._record(step(index=1))
        rec = only_site(tr)
        self.assertEqual((rec["site_hits"], rec["taken"]), (1, 1))

    def test_goto_landing_elsewhere_is_unknown(self):
        seed_branches(self.proj, [{"dl": 10, "op": "goto", "kind": "goto",
                                   "tgt": 20}])
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))
        tr._record(step(index=8))  # a goto cannot fall through
        tr._record(step(index=1))
        rec = only_site(tr)
        self.assertEqual((rec["taken"], rec["fallthrough"]), (0, 0))
        self.assertEqual(rec["unknown"], {"exceptional_flow": 1})

    def test_same_line_restop_is_step_granularity_unknown(self):
        seed_branches(self.proj, self._if_site(tgt=20))
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))  # line 10: site
        tr._record(step(index=4))  # line 10 again, target is 20: the line
        # re-stop carries no evidence about the branch outcome
        rec = only_site(tr)
        self.assertEqual((rec["taken"], rec["fallthrough"]), (0, 0))
        self.assertEqual(rec["unknown"], {"step_granularity": 1})

    def test_method_call_is_method_transition_unknown(self):
        seed_branches(self.proj, self._if_site())
        self.c.sigs[2000] = OTHER
        self.c.methods[2000] = [{"name": "n", "sig": "()V", "id": 700}]
        self.c.line_tables[(2000, 700)] = [{"index": 0, "line": 5}]
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))                       # A.m line 10 (site)
        tr._record(step(cls=2000, method=700, index=0))  # stepped into B.n
        tr._record(step(cls=2000, method=700, index=0))
        rec = only_site(tr)
        self.assertEqual((rec["taken"], rec["fallthrough"]), (0, 0))
        self.assertEqual(rec["unknown"], {"method_transition": 1})

    def test_recursion_is_unknown_not_an_edge(self):
        seed_branches(self.proj, self._if_site())
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))  # line 10: site
        tr._record(step(index=0))  # line 1: recursive re-entry, same method
        tr._record(step(index=0))
        rec = only_site(tr)
        self.assertEqual((rec["taken"], rec["fallthrough"]), (0, 0))
        self.assertEqual(rec["unknown"], {"exceptional_flow": 1})

    def test_exceptional_flow_to_catch_is_unknown(self):
        seed_branches(self.proj, self._if_site())
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))
        tr._record(step(index=16))  # line 30: catch region, not target/next
        tr._record(step(index=1))
        rec = only_site(tr)
        self.assertEqual((rec["taken"], rec["fallthrough"]), (0, 0))
        self.assertEqual(rec["unknown"], {"exceptional_flow": 1})

    def test_trace_gap_at_capture_end_is_unknown(self):
        seed_branches(self.proj, self._if_site())
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=4))  # site line is the last observation
        rep = tr.report()
        rec = only_site(tr)
        self.assertEqual(rec["site_hits"], 0)
        self.assertEqual(rec["unknown"], {"trace_gap": 1})
        self.assertEqual(rep["branches"]["unknown_transitions"], 1)

    def test_site_resolution_joins_on_method_descriptor(self):
        # two overloads each with an if-site on line 10; the outcome of
        # m(I)V must never resolve against m()V's site
        seed_branches(self.proj, self._if_site(tgt=20), name="m", sig="(I)V")
        tr = line_tracker(self.c, self.proj)  # steps m()V only
        tr._record(step(index=4))
        tr._record(step(index=12))
        tr._record(step(index=1))
        self.assertEqual(tr.branch_outcomes, {})


# ------------------------------------------------- idempotency / completion
class ReportIdempotencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.c = FakeClient()
        self.c.line_tables[(1000, 500)] = [{"index": 0, "line": 42}]

    def tearDown(self):
        self.tmp.cleanup()

    def _hits(self, run_id):
        with self.proj.db() as db:
            return db.query("SELECT * FROM coverage_hits WHERE run_id=?",
                            (run_id,))

    def test_repeated_report_is_idempotent(self):
        tr = line_tracker(self.c, self.proj)
        tr._record(step(index=0))
        tr._record(step(index=0))
        rep1 = tr.report()
        rows1 = self._hits(tr.run_id)
        rep2 = tr.report()
        rows2 = self._hits(tr.run_id)
        self.assertEqual(rep1, rep2)
        self.assertEqual(rows1, rows2)
        self.assertEqual([r["hits"] for r in rows1], [2])

    def test_run_then_extra_report_does_not_reflush(self):
        self.c.event_queue.append(composite(step(1, index=0)))
        s = make_session(self.c, self.proj)
        tr = CoverageTracker(s, ["com.foo"], mode="line", thread=11,
                             seconds=30)
        rep = tr.run()
        rows1 = self._hits(rep["run_id"])
        tr.report()
        tr.report()
        self.assertEqual(self._hits(rep["run_id"]), rows1)

    def test_budget_stop_marks_capture_incomplete(self):
        self.c.event_queue.append(composite(step(1, index=0)))
        self.c.event_queue.append(composite(step(1, index=0)))
        s = make_session(self.c, self.proj)
        rep = CoverageTracker(s, ["com.foo"], mode="line", thread=11,
                              budget=1, seconds=30).run()
        self.assertEqual(rep["stop_reason"], "budget")
        self.assertFalse(rep["complete"])
        got = RunStore(self.proj).get_run(rep["run_id"])
        self.assertEqual(got["run"]["completion_reason"], "budget")
        self.assertEqual(got["run"]["counts"]["events"], 1)
        art = got["artifacts"][0]
        self.assertFalse(art["truncation"]["complete"])
        self.assertEqual(art["truncation"]["stop_reason"], "budget")

    def test_duration_stop_marks_capture_incomplete(self):
        s = make_session(self.c, self.proj)
        rep = CoverageTracker(s, ["com.foo"], mode="line", thread=11,
                              seconds=1).run()
        self.assertEqual(rep["stop_reason"], "duration")
        self.assertFalse(rep["complete"])
        run = RunStore(self.proj).get_run(rep["run_id"])["run"]
        self.assertEqual(run["completion_reason"], "duration")

    def test_dropped_events_counted(self):
        s = make_session(self.c, self.proj)
        tr = CoverageTracker(s, ["com.foo"], mode="line", thread=11)
        tr._on_event({"kind_id": EVK_SINGLE_STEP, "thread": 11}, None)
        self.assertEqual(tr._dropped, 1)
        self.assertEqual(tr._events, 0)


# ----------------------------------------------------------------- schema
class CoverageHitsMigrationTests(unittest.TestCase):
    def test_legacy_table_gains_method_sig(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "old.db"
            conn = sqlite3.connect(raw)
            conn.executescript(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
                "CREATE TABLE coverage_hits ("
                " id INTEGER PRIMARY KEY, run_id TEXT NOT NULL,"
                " class_sig TEXT, method_name TEXT, dalvik_line INTEGER,"
                " hits INTEGER DEFAULT 0,"
                " UNIQUE(run_id, class_sig, method_name, dalvik_line));")
            conn.execute("INSERT INTO coverage_hits(run_id,class_sig,"
                         "method_name,dalvik_line,hits) "
                         "VALUES('r1','Lcom/foo/A;','m',10,3)")
            conn.commit()
            conn.close()
            db = MappingDB(raw)
            cols = {r["name"] for r in
                    db.query("PRAGMA table_info(coverage_hits)")}
            self.assertIn("method_sig", cols)
            row = db.one("SELECT * FROM coverage_hits WHERE run_id='r1'")
            self.assertEqual((row["class_sig"], row["method_name"],
                              row["dalvik_line"], row["hits"]),
                             ("Lcom/foo/A;", "m", 10, 3))
            self.assertIsNone(row["method_sig"])
            # overloads of one method on one line now fit side by side
            db.execute("INSERT INTO coverage_hits(run_id,class_sig,"
                       "method_name,method_sig,dalvik_line,hits) "
                       "VALUES('r2','Lcom/foo/A;','m','()V',10,1)")
            db.execute("INSERT INTO coverage_hits(run_id,class_sig,"
                       "method_name,method_sig,dalvik_line,hits) "
                       "VALUES('r2','Lcom/foo/A;','m','(I)V',10,1)")
            db.close()

    def test_reindex_carries_legacy_shaped_coverage_hits(self):
        # _copy_observations must carry rows from a pre-#37 live DB (no
        # method_sig column) into a new-generation staging DB
        from apkdbg.core.init_pipeline import _copy_observations
        with tempfile.TemporaryDirectory() as tmp:
            live = Path(tmp) / "live.db"
            conn = sqlite3.connect(live)
            conn.executescript(
                "CREATE TABLE coverage_hits ("
                " id INTEGER PRIMARY KEY, run_id TEXT NOT NULL,"
                " class_sig TEXT, method_name TEXT, dalvik_line INTEGER,"
                " hits INTEGER DEFAULT 0,"
                " UNIQUE(run_id, class_sig, method_name, dalvik_line));")
            conn.execute("INSERT INTO coverage_hits(run_id,class_sig,"
                         "method_name,dalvik_line,hits) "
                         "VALUES('r1','Lcom/foo/A;','m',10,3)")
            conn.commit()
            conn.close()
            staging = MappingDB(Path(tmp) / "staging.db")
            _copy_observations(staging, live)
            row = staging.one("SELECT * FROM coverage_hits WHERE "
                              "run_id='r1'")
            self.assertEqual((row["class_sig"], row["method_name"],
                              row["method_sig"], row["dalvik_line"],
                              row["hits"]),
                             ("Lcom/foo/A;", "m", None, 10, 3))
            staging.close()


if __name__ == "__main__":
    unittest.main()

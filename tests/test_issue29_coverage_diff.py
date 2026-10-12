"""Offline tests for issue #29 — branch-outcome persistence (idempotent,
descriptor-level site identity) and the offline coverage_diff command:
A/A baseline variation, A/B scenario differences with uncertainty
ranking, compatibility gating with an exploratory intersection, and
quality warnings for degraded traces. All fixtures are synthetic stored
runs; no device needed."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from apkdbg import commands
from apkdbg.core import apicatalog
from apkdbg.core.database import MappingDB
from apkdbg.core.manifests import RunStore, bump_index_generation
from apkdbg.core.project import Project
from apkdbg.debug.coverage import CoverageTracker
from apkdbg.debug.covdiff import coverage_diff
from apkdbg.debug.session import DebugSession
from apkdbg.device.jdwp import EVK_SINGLE_STEP, JdwpError
from apkdbg.errors import SessionError

CLS = "Lcom/foo/A;"
M = f"{CLS}->m()V"
SHA = "ab" * 32


# ------------------------------------------------------------------- helpers
def make_project(tmp: str, sha256: str = SHA) -> Project:
    proj = Project.create(tmp)
    with proj.db() as db:
        db.set_meta("sha256", sha256)
    return proj


def make_run(store: RunStore, label: str, *, mode: str = "line",
             events: int = 100, reason: str = "duration", dropped: int = 0,
             packages=("com.foo",)) -> str:
    rid = store.begin_run(
        "coverage", {"mode": mode, "packages": list(packages),
                     "budget": 20000, "seconds": 60},
        scenario=label, epoch=1, environment={})
    store.end_run(rid, reason,
                  counts={"events": events, "dropped_events": dropped})
    return rid


def seed_hits(proj: Project, run_id: str, rows: list) -> None:
    """rows: (class_sig, method_name, method_sig, dalvik_line, hits)"""
    with proj.db() as db:
        for cls, name, sig, line, hits in rows:
            db.execute(
                "INSERT INTO coverage_hits(run_id,class_sig,method_name,"
                "method_sig,dalvik_line,hits) VALUES(?,?,?,?,?,?)",
                (run_id, cls, name, sig, line, hits))


def seed_branch(proj: Project, run_id: str, site_key: str, *,
                taken: int = 0, fallthrough: int = 0,
                unknowns: dict | None = None, site_hits: int = 0,
                cls: str = CLS, name: str = "m", sig: str = "()V",
                line: int = 10, smali_line: int = 100,
                op: str = "if-eqz", kind: str = "if") -> None:
    with proj.db() as db:
        db.execute(
            "INSERT INTO coverage_branch_sites(run_id,site_key,class_sig,"
            "method_name,method_sig,dalvik_line,smali_line,opcode,kind,"
            "site_hits,taken,fallthrough,unknowns) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, site_key, cls, name, sig, line, smali_line, op, kind,
             site_hits, taken, fallthrough,
             json.dumps(unknowns, separators=(",", ":"))
             if unknowns else None))


def skey(method: str = M, line: int = 10, smali: int = 100) -> str:
    return f"{method}:{line}:{smali}"


def entries(out: dict, change: str | None = None) -> list:
    got = out["ranked"] or []
    return [e for e in got if change is None or e["change"] == change]


# ----------------------------------------------------- branch persistence
def make_session(client, project=None) -> DebugSession:
    s = DebugSession.__new__(DebugSession)
    s.project = project
    s.adb = None
    s.pkg = s.pid = s.port = None
    s.client = client
    s.bp_registry = {}
    s._sig_cache = {}
    return s


class _FakeClient:
    def __init__(self):
        self.sigs = {1000: CLS}
        self.methods = {1000: [{"name": "m", "sig": "()V", "id": 500}]}
        self.line_tables = {(1000, 500): [
            {"index": 0, "line": 1}, {"index": 4, "line": 10},
            {"index": 8, "line": 11}, {"index": 12, "line": 20}]}
        self.loaders = {}

    def close(self):
        pass

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


def _step(thread=11, cls=1000, method=500, index=0):
    return {"kind_id": EVK_SINGLE_STEP, "request_id": 1, "thread": thread,
            "location": {"class": cls, "method": method, "index": index}}


class BranchPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        with self.proj.db() as db:
            db.execute("INSERT INTO classes(sig,fqcn) VALUES(?,?)",
                       (CLS, "com.foo.A"))
            cid = db.one("SELECT id FROM classes WHERE sig=?", (CLS,))["id"]
            db.execute("INSERT INTO methods(class_id,name,sig) "
                       "VALUES(?,?,?)", (cid, "m", "()V"))
            mid = db.one("SELECT id FROM methods WHERE class_id=?",
                         (cid,))["id"]
            db.execute(
                "INSERT INTO branch_sites(method_id,smali_line,dalvik_line,"
                "opcode,kind,target_smali_line,target_dalvik_line) "
                "VALUES(?,?,?,?,?,?,?)",
                (mid, 100, 10, "if-eqz", "if", None, 20))

    def tearDown(self):
        self.tmp.cleanup()

    def _tracker(self):
        return CoverageTracker(make_session(_FakeClient(), self.proj),
                               ["com.foo"], mode="line", thread=11)

    def _rows(self, run_id):
        with self.proj.db() as db:
            return db.query("SELECT * FROM coverage_branch_sites "
                            "WHERE run_id=?", (run_id,))

    def test_outcomes_persisted_separately_with_descriptor_site_key(self):
        tr = self._tracker()
        tr._record(_step(index=4))   # line 10: if site
        tr._record(_step(index=12))  # line 20: taken
        tr._record(_step(index=4))
        tr._record(_step(index=8))   # line 11: fall-through
        tr.report()
        rows = self._rows(tr.run_id)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["site_key"], skey())
        self.assertEqual((r["class_sig"], r["method_name"],
                          r["method_sig"]), (CLS, "m", "()V"))
        self.assertEqual((r["site_hits"], r["taken"], r["fallthrough"]),
                         (2, 1, 1))
        self.assertIsNone(r["unknowns"])  # no unknowns observed
        self.assertNotIn("site_id", r)    # local integer id not persisted

    def test_unknowns_persisted_with_reasons_never_as_edges(self):
        tr = self._tracker()
        tr._record(_step(index=4))  # site line is the last observation
        tr.report()
        r = self._rows(tr.run_id)[0]
        self.assertEqual((r["taken"], r["fallthrough"]), (0, 0))
        self.assertEqual(json.loads(r["unknowns"]), {"trace_gap": 1})

    def test_repeated_report_does_not_double_count(self):
        tr = self._tracker()
        tr._record(_step(index=4))
        tr._record(_step(index=12))
        tr.report()
        rows1 = self._rows(tr.run_id)
        tr.report()
        tr.report()
        self.assertEqual(self._rows(tr.run_id), rows1)

    def test_reindex_carries_branch_rows(self):
        from apkdbg.core.init_pipeline import _copy_observations
        tr = self._tracker()
        tr._record(_step(index=4))
        tr._record(_step(index=12))
        tr.report()
        staging = MappingDB(Path(self.tmp.name) / "staging.db")
        _copy_observations(staging, self.proj.db_path)
        row = staging.one("SELECT * FROM coverage_branch_sites "
                          "WHERE run_id=?", (tr.run_id,))
        self.assertEqual((row["site_key"], row["taken"]), (skey(), 1))
        staging.close()


# ------------------------------------------------------------------- A/A
class AABaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.store = RunStore(self.proj)

    def tearDown(self):
        self.tmp.cleanup()

    def _identical_runs(self, label, n, *, hits=10):
        for _ in range(n):
            rid = make_run(self.store, label)
            seed_hits(self.proj, rid, [(CLS, "m", "()V", 10, hits)])
            seed_branch(self.proj, rid, skey(), taken=5, site_hits=5)

    def test_identical_groups_rank_nothing(self):
        self._identical_runs("grpA", 2)
        self._identical_runs("grpB", 2)
        out = coverage_diff(self.proj, "grpA", "grpB")
        self.assertTrue(out["compatibility"]["compatible"])
        self.assertEqual(out["ranked"], [])
        self.assertFalse(out["aa_baseline"])
        self.assertFalse(out["quality"]["exact_subtraction"])

    def test_same_label_split_measures_baseline_variation(self):
        self._identical_runs("aa", 4)
        out = coverage_diff(self.proj, "aa", "aa")
        self.assertTrue(out["aa_baseline"])
        self.assertEqual(len(out["baseline"]["runs"]), 2)
        self.assertEqual(len(out["candidate"]["runs"]), 2)
        self.assertEqual(out["ranked"], [])

    def test_within_spread_hit_differences_are_baseline_noise(self):
        # group means differ (12 vs 13) but well inside baseline's own
        # repeat spread (10..14): suppressed as A/A noise
        for hits in (10, 14):
            rid = make_run(self.store, "noisyA")
            seed_hits(self.proj, rid, [(CLS, "m", "()V", 10, hits)])
        for hits in (13, 13):
            rid = make_run(self.store, "noisyB")
            seed_hits(self.proj, rid, [(CLS, "m", "()V", 10, hits)])
        out = coverage_diff(self.proj, "noisyA", "noisyB")
        self.assertEqual(entries(out, "hit_count"), [])

    def test_single_run_label_cannot_split(self):
        self._identical_runs("solo", 1)
        with self.assertRaises(SessionError):
            coverage_diff(self.proj, "solo", "solo")

    def test_unknown_label_raises(self):
        with self.assertRaises(SessionError):
            coverage_diff(self.proj, "nope", "grpB")


# ------------------------------------------------------------------- A/B
class ABScenarioTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.store = RunStore(self.proj)
        # baseline: if-site taken, shared line, plus a baseline-only line
        for _ in range(2):
            rid = make_run(self.store, "scenA")
            seed_hits(self.proj, rid, [(CLS, "m", "()V", 10, 10),
                                       (CLS, "m", "()V", 20, 10),
                                       (CLS, "m", "()V", 30, 10)])
            seed_branch(self.proj, rid, skey(), taken=5, site_hits=5)
        # candidate: same site falls through, a new line appears, the
        # baseline-only line disappears (non-monotonic line numbers used)
        for _ in range(2):
            rid = make_run(self.store, "scenB")
            seed_hits(self.proj, rid, [(CLS, "m", "()V", 100, 10),
                                       (CLS, "m", "()V", 10, 10)])
            seed_branch(self.proj, rid, skey(), fallthrough=5,
                        site_hits=5)

    def tearDown(self):
        self.tmp.cleanup()

    def test_known_conditional_change_is_ranked_and_explained(self):
        out = coverage_diff(self.proj, "scenA", "scenB")
        direction = entries(out, "direction")
        self.assertEqual(len(direction), 1)
        d = direction[0]
        self.assertEqual(d["key"], f"branch:{skey()}")
        self.assertEqual(d["direction"], {"baseline": "taken",
                                          "candidate": "fallthrough"})
        self.assertEqual(d["edge_counts"]["baseline"],
                         {"taken": 10, "fallthrough": 0, "unknown": 0})
        self.assertEqual(d["repeatability"], {"baseline": "2/2",
                                              "candidate": "2/2"})
        self.assertEqual(d["confidence"], "high")
        self.assertIn("purity", json.dumps(d["score_explanation"]))
        # presence changes on both sides, annotated absence caveat
        presence = {e["key"]: e for e in entries(out, "presence")}
        self.assertEqual(presence[f"line:{M}:100"]["present_in"],
                         "candidate")
        self.assertEqual(presence[f"line:{M}:20"]["present_in"],
                         "baseline")
        self.assertEqual(presence[f"line:{M}:30"]["present_in"],
                         "baseline")
        for e in presence.values():
            self.assertIn("absence", e["notes"][0])
        # the known changed site is among the explained candidates
        self.assertIn(f"branch:{skey()}",
                      [e["key"] for e in out["ranked"][:5]])

    def test_overloads_and_same_line_sites_stay_separate(self):
        store = self.store
        rid = make_run(store, "ovA")
        seed_hits(self.proj, rid, [(CLS, "m", "(I)V", 10, 5)])
        seed_branch(self.proj, rid, skey(f"{CLS}->m(I)V"), taken=2,
                    site_hits=2)
        rid = make_run(store, "ovB")
        seed_hits(self.proj, rid, [(CLS, "m", "(I)V", 10, 5)])
        seed_branch(self.proj, rid, skey(f"{CLS}->m(I)V"), fallthrough=2,
                    site_hits=2)
        out = coverage_diff(self.proj, "ovA", "ovB")
        d = entries(out, "direction")
        self.assertEqual([e["key"] for e in d],
                         [f"branch:{CLS}->m(I)V:10:100"])
        # two sites sharing one dalvik line: keyed apart by smali line
        rid = make_run(store, "ovA")
        rid2 = make_run(store, "ovB")
        seed_branch(self.proj, rid, skey(smali=105), taken=3, site_hits=3)
        seed_branch(self.proj, rid2, skey(smali=105), fallthrough=3,
                    site_hits=3)
        out = coverage_diff(self.proj, "ovA", "ovB")
        keys = {e["key"] for e in entries(out, "direction")}
        self.assertIn(f"branch:{M}:10:105", keys)
        self.assertNotIn(f"branch:{M}:10:100", keys)

    def test_unknown_direction_is_never_fabricated(self):
        store = self.store
        rid = make_run(store, "ambA")
        seed_branch(self.proj, rid, skey(smali=200), site_hits=3,
                    unknowns={"ambiguous_line": 3})
        rid = make_run(store, "ambB")
        seed_branch(self.proj, rid, skey(smali=200), site_hits=3,
                    taken=3)
        out = coverage_diff(self.proj, "ambA", "ambB")
        # one side has zero identified edges: no direction claim
        self.assertEqual(entries(out, "direction"), [])

    def test_unknowns_visible_in_supporting_observations(self):
        store = self.store
        rid = make_run(store, "unA")
        seed_branch(self.proj, rid, skey(smali=300), site_hits=2,
                    taken=2, unknowns={"step_granularity": 8})
        rid = make_run(store, "unB")
        seed_branch(self.proj, rid, skey(smali=300), site_hits=2,
                    fallthrough=2)
        out = coverage_diff(self.proj, "unA", "unB")
        # both directions evidenced, but unknowns crush baseline purity;
        # the flip is still ranked with its unknown counts visible
        d = entries(out, "direction")
        self.assertEqual(len(d), 1)
        self.assertEqual(d[0]["edge_counts"]["baseline"]["unknown"], 8)
        obs_a = next(iter(d[0]["observations"]["baseline"].values()))
        self.assertEqual(obs_a["unknown_reasons"],
                         {"step_granularity": 8})
        self.assertLess(d[0]["score"], 0.9 * 0.5 + 1e-9)

    def test_change_type_filter(self):
        out = coverage_diff(self.proj, "scenA", "scenB",
                            change="direction")
        self.assertTrue(out["ranked"])
        self.assertTrue(all(e["change"] == "direction"
                            for e in out["ranked"]))
        with self.assertRaises(SessionError):
            coverage_diff(self.proj, "scenA", "scenB", change="bogus")


# ------------------------------------------------------- degraded quality
class DegradedRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.store = RunStore(self.proj)

    def tearDown(self):
        self.tmp.cleanup()

    def test_interrupted_runs_warn_and_lower_confidence(self):
        rid = make_run(self.store, "intA")
        seed_hits(self.proj, rid, [(CLS, "m", "()V", 10, 10)])
        # candidate group is budget-stopped with dropped events and
        # missed the line entirely: its absence is weak evidence
        rid = make_run(self.store, "intB", reason="budget", dropped=5)
        out = coverage_diff(self.proj, "intA", "intB")
        q = out["quality"]
        self.assertFalse(q["exact_subtraction"])
        degraded = q["degraded_runs"]
        self.assertEqual(len(degraded), 1)
        self.assertTrue(degraded[0]["degraded"])
        self.assertTrue(any("budget" in w for w in degraded[0]["warnings"]))
        self.assertTrue(any("dropped" in w for w in degraded[0]["warnings"]))
        p = entries(out, "presence")
        self.assertEqual(len(p), 1)
        self.assertEqual(p[0]["confidence"], "low")

    def test_clean_comparison_keeps_high_confidence(self):
        for label in ("clA", "clB", "clB", "clB"):
            rid = make_run(self.store, label)
            rows = [(CLS, "m", "()V", 10, 10)]
            if label == "clB":
                rows.append((CLS, "m", "()V", 99, 10))
            seed_hits(self.proj, rid, rows)
        out = coverage_diff(self.proj, "clA", "clB")
        p = entries(out, "presence")
        self.assertEqual(len(p), 1)
        self.assertEqual(p[0]["confidence"], "high")


# ------------------------------------------------------------- compat gate
class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.store = RunStore(self.proj)

    def tearDown(self):
        self.tmp.cleanup()

    def _pair(self):
        rid = make_run(self.store, "cmpA")
        seed_hits(self.proj, rid, [(CLS, "m", "()V", 10, 10)])
        rid_b = make_run(self.store, "cmpB")
        seed_hits(self.proj, rid_b, [(CLS, "m", "()V", 10, 10),
                                     (CLS, "m", "()V", 20, 10)])
        return rid_b

    def test_different_apk_rejected_by_default(self):
        self._pair()
        with self.proj.db() as db:
            db.execute("UPDATE runs SET apk_sha256=? WHERE scenario='cmpB'",
                       ("ff" * 32,))
        out = coverage_diff(self.proj, "cmpA", "cmpB")
        self.assertFalse(out["compatibility"]["compatible"])
        self.assertIsNone(out["ranked"])
        self.assertIn("reason", out)
        fields = {d["field"] for d in
                  out["compatibility"]["differences"]}
        self.assertIn("apk_sha256", fields)

    def test_different_index_generation_rejected_by_default(self):
        rid_b = self._pair()
        with self.proj.db() as db:
            bump_index_generation(db)
            db.execute("UPDATE runs SET index_generation=2 WHERE run_id=?",
                       (rid_b,))
        out = coverage_diff(self.proj, "cmpA", "cmpB")
        self.assertFalse(out["compatibility"]["compatible"])
        self.assertIsNone(out["ranked"])

    def test_mode_and_scope_mismatch_rejected(self):
        self._pair()
        rid = make_run(self.store, "cmpC", mode="method")
        self.store.add_artifact(rid, "coverage_report",
                                {"mode": "method", "methods": {f"{M}": 3}})
        out = coverage_diff(self.proj, "cmpA", "cmpC")
        self.assertFalse(out["compatibility"]["compatible"])
        fields = {d["field"] for d in
                  out["compatibility"]["differences"]}
        self.assertIn("mode", fields)
        rid = make_run(self.store, "cmpD", packages=("com.bar",))
        seed_hits(self.proj, rid, [("Lcom/bar/X;", "n", "()V", 1, 1)])
        out = coverage_diff(self.proj, "cmpA", "cmpD")
        self.assertFalse(out["compatibility"]["compatible"])

    def test_exploratory_intersection_is_annotated(self):
        self._pair()
        with self.proj.db() as db:
            db.execute("UPDATE runs SET apk_sha256=? WHERE scenario='cmpB'",
                       ("ff" * 32,))
        out = coverage_diff(self.proj, "cmpA", "cmpB", exploratory=True)
        self.assertTrue(out["exploratory"])
        self.assertTrue(out["intersection_only"])
        self.assertIn("not_equivalent", out["equivalence"])
        # only the shared key was compared: identical on both sides, and
        # the candidate-only line can never appear as a presence change
        self.assertEqual(out["ranked"], [])


# --------------------------------------------------- artifact-backed runs
class ArtifactFallbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.store = RunStore(self.proj)

    def tearDown(self):
        self.tmp.cleanup()

    def test_method_mode_runs_diff_from_artifacts(self):
        rid = make_run(self.store, "mmA", mode="method")
        self.store.add_artifact(rid, "coverage_report", {
            "mode": "method",
            "methods": {f"{M}": 10, f"{CLS}->n()V": 10}})
        rid = make_run(self.store, "mmB", mode="method")
        self.store.add_artifact(rid, "coverage_report", {
            "mode": "method",
            "methods": {f"{M}": 10, f"{CLS}->o()V": 10}})
        out = coverage_diff(self.proj, "mmA", "mmB")
        self.assertEqual(out["mode"], "method")
        presence = {e["key"] for e in entries(out, "presence")}
        self.assertEqual(presence, {f"method:{CLS}->n()V",
                                    f"method:{CLS}->o()V"})

    def test_legacy_line_run_without_branch_rows_uses_artifact(self):
        body = {"mode": "line",
                "lines": {M: {"10": 4}},
                "branches": {"detail": {skey(): {
                    "site_hits": 2, "taken": 2, "fallthrough": 0,
                    "unknown": {}, "kind": "if", "line": 10}}}}
        rid = make_run(self.store, "lgA")
        self.store.add_artifact(rid, "coverage_report", body)
        body_b = {"mode": "line", "lines": {M: {"10": 4}},
                  "branches": {"detail": {skey(): {
                      "site_hits": 2, "taken": 0, "fallthrough": 2,
                      "unknown": {}, "kind": "if", "line": 10}}}}
        rid = make_run(self.store, "lgB")
        self.store.add_artifact(rid, "coverage_report", body_b)
        out = coverage_diff(self.proj, "lgA", "lgB")
        d = entries(out, "direction")
        self.assertEqual(len(d), 1)
        self.assertEqual(d[0]["direction"], {"baseline": "taken",
                                             "candidate": "fallthrough"})


# -------------------------------------------- determinism and pagination
class DeterminismTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.store = RunStore(self.proj)
        rid = make_run(self.store, "detA")
        seed_hits(self.proj, rid,
                  [(CLS, "m", "()V", line, 10) for line in (1, 2, 3)])
        seed_branch(self.proj, rid, skey(), taken=5, site_hits=5)
        rid = make_run(self.store, "detB")
        seed_hits(self.proj, rid,
                  [(CLS, "m", "()V", line, 10)
                   for line in (4, 5, 6, 7, 8, 9)])
        seed_branch(self.proj, rid, skey(), fallthrough=5, site_hits=5)

    def tearDown(self):
        self.tmp.cleanup()

    def test_deterministic_output_for_fixed_stored_inputs(self):
        out1 = coverage_diff(self.proj, "detA", "detB")
        out2 = coverage_diff(self.proj, "detA", "detB")
        self.assertEqual(out1, out2)
        self.assertEqual(json.dumps(out1, sort_keys=True),
                         json.dumps(out2, sort_keys=True))

    def test_stable_pagination(self):
        full = coverage_diff(self.proj, "detA", "detB", limit=500)
        self.assertGreater(full["total"], 3)
        seen = []
        offset = 0
        while True:
            page = coverage_diff(self.proj, "detA", "detB", limit=2,
                                 offset=offset)
            seen.extend(e["key"] for e in page["ranked"])
            self.assertEqual(page["truncated"],
                             offset + page["count"] < full["total"])
            if not page["truncated"]:
                break
            offset += 2
        self.assertEqual(seen, [e["key"] for e in full["ranked"]])
        self.assertEqual(len(seen), len(set(seen)))

    def test_scores_sorted_descending(self):
        out = coverage_diff(self.proj, "detA", "detB")
        scores = [e["score"] for e in out["ranked"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        # presence (base 1.0) ranks above direction (0.9)
        self.assertEqual(out["ranked"][0]["change"], "presence")


# -------------------------------------------------------- command surface
class CommandSurfaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        store = RunStore(self.proj)
        rid = make_run(store, "cmdA")
        seed_hits(self.proj, rid, [(CLS, "m", "()V", 10, 10)])
        rid = make_run(store, "cmdB")
        seed_hits(self.proj, rid, [(CLS, "m", "()V", 20, 10)])

    def tearDown(self):
        self.tmp.cleanup()

    def test_command_via_ctx_and_catalog_validation(self):
        entry = apicatalog.entry_for("coverage_diff")
        kw = apicatalog.validate_params(
            entry, {"baseline": "cmdA", "candidate": "cmdB"})
        ctx = commands.Ctx(self.tmp.name)
        try:
            out = commands.cmd_coverage_diff(ctx, **kw)
        finally:
            ctx.close()
        self.assertEqual(out["total"], 2)
        keys = {e["key"] for e in out["ranked"]}
        self.assertEqual(keys, {f"line:{M}:10", f"line:{M}:20"})
        self.assertTrue(all(e["change"] == "presence"
                            for e in out["ranked"]))

    def test_catalog_entry_is_offline_and_paginated(self):
        entry = apicatalog.entry_for("coverage_diff")
        self.assertEqual(entry["requires"], {"project": True,
                                             "session": False})
        self.assertTrue(entry["idempotent"])
        self.assertFalse(entry["mutates"])
        self.assertIn("pagination", entry)


if __name__ == "__main__":
    unittest.main()

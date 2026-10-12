"""Offline tests for issue #25 — evidence-backed runtime alias suggestions.

Covers: heuristic rules (strong/weak/conflicting/repeated signals, generic
URL as context), the review workflow (accept/reject/revise, supersede
reversibility, rejection suppression, dedupe with frequency/provenance),
classloader separation, unmapped runtime classes, budget exhaustion and
read failures (partial results, measured reads/pause, lease release),
output integration (sig/deobf/alias as distinct fields, aliases never
affecting targeting), pagination + evidence links, reindex carry-over,
and the CLI surface. Duck-typed fake clients drive a real DebugSession;
DB tests use temp project dirs (no device).
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest

from apkdbg import cli
from apkdbg.commands import Ctx, cmd_aliases, cmd_classes
from apkdbg.core import aliases
from apkdbg.core.aliases import AliasStore, accepted_alias, accepted_alias_map
from apkdbg.core.database import MappingDB
from apkdbg.core.init_pipeline import _copy_observations
from apkdbg.core.manifests import RunStore
from apkdbg.core.project import Project
from apkdbg.debug import translate
from apkdbg.debug.aliascollect import AliasCollector, CollectBudgets
from apkdbg.debug.dispatcher import EventDispatcher
from apkdbg.debug.hooks import crypto
from apkdbg.debug.session import DebugSession
from apkdbg.device.jdwp import EVK_BREAKPOINT, TAG_ARRAY, TAG_STRING, JdwpError
from apkdbg.errors import ResolveError

APK_SHA = "cd" * 32
CLASS_SIG = "Lcom/foo/a/a;"          # obfuscated app class
CLASS_FQCN = "com.foo.a.a"
CLASS_DEOBF = "com.foo.payment.PaymentRepository"
SPEC_HOOK = "SecretKeySpec.<init>(byte[],String)"
SPEC_SIG = "Ljavax/crypto/spec/SecretKeySpec;"


# ------------------------------------------------------------------- helpers
def make_project(tmp: str, with_class: bool = True) -> Project:
    proj = Project.create(tmp)
    with proj.db() as db:
        db.set_meta("sha256", APK_SHA)
        if with_class:
            db.execute(
                "INSERT INTO classes(sig,fqcn,deobf_fqcn,smali_path)"
                " VALUES(?,?,?,?)",
                (CLASS_SIG, CLASS_FQCN, CLASS_DEOBF,
                 "smali/com/foo/a/a.smali"))
            db.execute(
                "INSERT INTO methods(class_id,name,sig,line_start,line_end)"
                " VALUES(1,'a','()V',10,40)")
            db.execute(
                "INSERT INTO line_map(method_id,dalvik_line,smali_line)"
                " VALUES(1,10,11)")
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


def composite(*events):
    return {"suspend_policy": 1, "events": list(events)}


def bp_event(rid, thread=11, cls=2000, method=2500):
    return {"kind_id": EVK_BREAKPOINT, "request_id": rid, "thread": thread,
            "location": {"class": cls, "method": method, "index": 0}}


class FakeClient:
    """Fake VM hosting the SecretKeySpec hook class; captures one byte[]
    (a URL) and one string (a log tag). Counts every JDWP-ish call."""

    def __init__(self):
        self.next_rid = 1
        self.calls = []
        self.classes = {SPEC_SIG: [{"type_id": 2000}]}
        self.methods = {2000: [{"name": "<init>",
                                "sig": "([BLjava/lang/String;)V",
                                "id": 2500}]}
        self.sigs = {2000: SPEC_SIG, 1000: CLASS_SIG}
        self.loaders = {2000: 9001}
        self.frames = {11: [{"frame_id": 1,
                             "location": {"class": 2000, "method": 2500,
                                          "index": 0}}]}
        self.event_queue = []
        self.cleared = []
        self.resumed = []
        self.fail_frames = False
        # extra-read fixtures: object 88 of type 3000 with one String field
        self.objects = {88: 3000}
        self.obj_sigs = {3000: CLASS_SIG}
        self.obj_fields = {3000: [{"name": "TAG", "id": 51,
                                   "sig": "Ljava/lang/String;",
                                   "mod_bits": 0}]}
        self.obj_values = {(88, 51): {"tag": TAG_STRING, "v": 77}}
        self.strings = {77: "PaymentRepository"}
        self.fail_reads = set()   # method names that raise on call

    # accounting ------------------------------------------------------
    def _rec(self, name):
        self.calls.append(name)
        if name in self.fail_reads:
            raise JdwpError(f"INVALID_OBJECT ({name})")

    def close(self):
        pass

    def _rid(self):
        rid = self.next_rid
        self.next_rid += 1
        return rid

    # JDWP surface ----------------------------------------------------
    def classes_by_signature(self, sig):
        return self.classes.get(sig, [])

    def rt_methods(self, type_id):
        return self.methods.get(type_id, [])

    def rt_signature(self, type_id):
        return self.sigs.get(type_id, self.obj_sigs.get(
            type_id, f"Lfake/{type_id};"))

    def rt_class_loader(self, type_id):
        return self.loaders.get(type_id, 0)

    def method_line_table(self, type_id, method_id):
        return {"lines": [{"index": 0, "line": 10}]}

    def method_var_table(self, type_id, method_id):
        raise JdwpError("ABSENT_INFORMATION")

    def set_breakpoint(self, class_id, method_id, index, suspend_policy=2):
        return self._rid()

    def set_event(self, kind, suspend, mods):
        return self._rid()

    def mod_class_match(self, pattern):
        return (1, pattern)

    def mod_class_only(self, type_id):
        return (4, type_id)

    def clear_event(self, kind, request_id):
        self.cleared.append((kind, request_id))

    def next_event(self, timeout=None):
        if self.event_queue:
            return self.event_queue.pop(0)
        raise _timeout_error()

    def thread_resume(self, thread):
        self.resumed.append(thread)

    def thread_frames(self, thread, count=32):
        if self.fail_frames:
            raise JdwpError("INVALID_THREAD")
        return self.frames.get(thread, [])

    def frame_get_values(self, thread, frame_id, slots):
        out = []
        for slot, tag in slots:
            if slot == 1:
                out.append({"tag": TAG_ARRAY, "v": 88})
            elif slot == 2:
                out.append({"tag": TAG_STRING, "v": 77})
            else:
                out.append({"tag": tag, "v": None})
        return out

    def frame_this_object(self, thread, frame_id):
        return {"tag": 76, "v": None}

    def byte_array(self, oid, max_bytes):
        return b"https://api.internal/v1"

    def array_length(self, oid):
        return 23

    def string_value(self, oid, max_len=512):
        self._rec("string_value")
        return self.strings.get(oid, "?")

    # extra-read surface ----------------------------------------------
    def object_reftype(self, oid):
        self._rec("object_reftype")
        return (1, self.objects[oid])

    def rt_fields(self, type_id):
        self._rec("rt_fields")
        return self.obj_fields.get(type_id, [])

    def object_get_values(self, oid, field_ids):
        self._rec("object_get_values")
        return [self.obj_values[(oid, f)] for f in field_ids]


def watch_client(n_events: int = 1) -> FakeClient:
    c = FakeClient()
    for _ in range(n_events):
        c.event_queue.append(composite(bp_event(1)))
    return c


# --------------------------------------------------------------- heuristics
class HeuristicTests(unittest.TestCase):
    def test_strong_log_tag_signal(self):
        f = aliases.analyze("PaymentRepository")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "log_tag")
        self.assertEqual(f[0]["kind"], "candidate")
        self.assertGreaterEqual(f[0]["score"], aliases.SUGGEST_MIN_SCORE)

    def test_weak_signals(self):
        # no rule fires: no candidate at all
        self.assertEqual(aliases.analyze("ok"), [])
        self.assertEqual(aliases.analyze("true"), [])
        # enum-like is a weak signal: candidate kind, low heuristic score
        f = aliases.analyze("LOADING_FAILED")[0]
        self.assertEqual(f["rule"], "enum_like")
        self.assertLess(f["score"], 0.8)

    def test_route_and_preference_signals(self):
        self.assertEqual(aliases.analyze("/api/v1/user_profile")[0]["rule"],
                         "route_name")
        self.assertEqual(aliases.analyze("user.session.token")[0]["rule"],
                         "pref_key")

    def test_generic_url_is_behavioral_context_not_a_name(self):
        f = aliases.analyze("https://api.example.com/v1/users")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["kind"], "context")
        self.assertEqual(f[0]["rule"], "url_context")
        # even with a route-looking path, the URL itself is no candidate
        self.assertFalse(any(x["kind"] == "candidate" for x in f))


# ---------------------------------------------------------------- store
class AliasStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.store = AliasStore(self.proj)

    def tearDown(self):
        self.tmp.cleanup()

    def observe(self, text="PaymentRepository", rule="log_tag", score=0.8,
                **kw):
        kw.setdefault("class_sig", CLASS_SIG)
        return self.store.observe(candidate=text, score=score, rule=rule,
                                  **kw)

    def test_strong_signal_creates_suggestion_tied_to_identity(self):
        cid, action = self.observe(run_id="r1", event_id="e1",
                                   evidence=[{"event_id": "e1"}])
        self.assertEqual(action, "suggested")
        row = self.store.get(cid)
        self.assertEqual(row["status"], "suggested")
        self.assertEqual(row["apk_sha256"], APK_SHA)
        self.assertEqual(row["index_generation"], 1)
        self.assertEqual(row["class_sig"], CLASS_SIG)
        self.assertEqual(row["candidate"], "PaymentRepository")
        self.assertEqual(row["rules_version"], aliases.RULES_VERSION)
        self.assertEqual(row["run_id"], "r1")
        self.assertEqual(row["event_id"], "e1")
        self.assertEqual(row["evidence"], [{"event_id": "e1"}])
        # heuristic score, explicitly not a calibrated probability
        self.assertEqual(row["heuristic_score"], 0.8)

    def test_weak_signal_is_never_auto_accepted(self):
        cid, _ = self.observe("LOADING_FAILED", rule="enum_like", score=0.5)
        self.assertEqual(self.store.get(cid)["status"], "suggested")
        with self.proj.db() as db:
            self.assertIsNone(accepted_alias(db, CLASS_SIG))

    def test_conflicting_candidates_coexist(self):
        self.observe("PaymentRepository")
        self.observe("PaymentRepo")
        rows = self.store.list()["candidates"]
        self.assertEqual({r["candidate"] for r in rows},
                         {"PaymentRepository", "PaymentRepo"})
        self.assertTrue(all(r["status"] == "suggested" for r in rows))

    def test_decisions_survive_reopen_and_stay_tied_to_evidence(self):
        cid, _ = self.observe(run_id="r1", event_id="e1")
        self.store.accept(cid, note="looks right")
        # reopen: fresh Project + store over the same on-disk DB
        store2 = AliasStore(Project.open(self.tmp.name))
        row = store2.get(cid)
        self.assertEqual(row["status"], "accepted")
        self.assertEqual(row["apk_sha256"], APK_SHA)
        self.assertEqual(row["event_id"], "e1")
        actions = [d["action"] for d in row["decisions"]]
        self.assertEqual(actions, ["suggest", "accept"])
        self.assertEqual(row["decisions"][1]["note"], "looks right")

    def test_replacement_is_reversible(self):
        a, _ = self.observe("PaymentRepository")
        b, _ = self.observe("PaymentRepo")
        self.store.accept(a)
        out = self.store.accept(b)       # b replaces a
        self.assertEqual(out["superseded"], [a])
        self.assertEqual(self.store.get(a)["status"], "superseded")
        out = self.store.accept(a)       # and back — reversible
        self.assertEqual(out["superseded"], [b])
        self.assertEqual(self.store.get(a)["status"], "accepted")
        self.assertEqual(self.store.get(b)["status"], "superseded")
        trail = [(d["action"], d["to_status"])
                 for d in self.store.get(a)["decisions"]]
        self.assertEqual(trail, [("suggest", "suggested"),
                                 ("accept", "accepted"),
                                 ("supersede", "superseded"),
                                 ("accept", "accepted")])

    def test_revise_supersedes_and_carries_evidence(self):
        cid, _ = self.observe("PaymentRepoitory", run_id="r1",
                              evidence=[{"event_id": "e9"}])
        out = self.store.revise(cid, "PaymentRepository", note="typo")
        new = self.store.get(out["candidate_id"])
        self.assertEqual(new["status"], "accepted")
        self.assertEqual(new["candidate"], "PaymentRepository")
        self.assertEqual(new["evidence"], [{"event_id": "e9"}])
        self.assertEqual(new["run_id"], "r1")
        old = self.store.get(cid)
        self.assertEqual(old["status"], "superseded")
        self.assertEqual(old["decisions"][-1]["action"], "supersede")
        self.assertIn("typo", new["decisions"][0]["note"])

    def test_revise_with_identical_text_just_accepts(self):
        cid, _ = self.observe("PaymentRepository")
        out = self.store.revise(cid, "PaymentRepository")
        self.assertEqual(out["candidate_id"], cid)
        self.assertEqual(self.store.get(cid)["status"], "accepted")
        self.assertEqual(self.store.list()["total"], 1)

    def test_manual_alias_is_accepted_without_heuristic_score(self):
        out = self.store.add_alias(CLASS_SIG, "BillingRepo")
        row = self.store.get(out["candidate_id"])
        self.assertEqual(row["status"], "accepted")
        self.assertEqual(row["source"], "manual")
        self.assertEqual(row["rule"], "manual")
        self.assertIsNone(row["heuristic_score"])
        with self.proj.db() as db:
            self.assertEqual(accepted_alias(db, CLASS_SIG), "BillingRepo")

    def test_dedupe_keeps_frequency_and_provenance(self):
        for i in range(3):
            cid, action = self.observe(run_id=f"r{i}", event_id=f"e{i}",
                                       evidence=[{"event_id": f"e{i}"}])
        row = self.store.get(cid)
        self.assertEqual(row["observations"], 3)
        self.assertLessEqual(row["first_seen"], row["last_seen"])
        refs = [e["event_id"] for e in row["evidence"]]
        self.assertEqual(refs, ["e0", "e1", "e2"])  # per-event refs kept
        self.assertEqual(row["run_id"], "r2")       # latest provenance
        actions = [d["action"] for d in row["decisions"]]
        self.assertEqual(actions, ["suggest", "resuggest_merged",
                                   "resuggest_merged"])

    def test_rejected_suggestion_stays_suppressed(self):
        cid, _ = self.observe()
        self.store.reject(cid, note="not a name")
        cid2, action = self.observe()  # identical text+rule re-observed
        self.assertEqual(cid2, cid)
        self.assertEqual(action, "suppressed")
        row = self.store.get(cid)
        self.assertEqual(row["status"], "rejected")
        self.assertEqual(row["observations"], 2)  # frequency still counted
        self.assertEqual(row["decisions"][-1]["action"],
                         "resuggest_suppressed")
        suggested = self.store.list(status="suggested")
        self.assertEqual(suggested["total"], 0)
        # a different rule for the same text is a new, visible candidate
        _, action = self.observe(rule="route_name", score=0.7)
        self.assertEqual(action, "suggested")

    def test_distinct_loaders_are_not_merged(self):
        a, _ = self.observe(classloader_id=9001, epoch=0)
        b, _ = self.observe(classloader_id=9002, epoch=0)
        self.assertNotEqual(a, b)
        rows = self.store.list()["candidates"]
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["classloader_key"] for r in rows},
                         {"e0:9001", "e0:9002"})
        # same loader re-observed: merges into its own row
        a2, action = self.observe(classloader_id=9001, epoch=0)
        self.assertEqual((a2, action), (a, "merged"))
        self.assertEqual(self.store.list()["total"], 2)

    def test_unmapped_runtime_class_keeps_evidence(self):
        cid, _ = self.observe(class_sig="Ldynamic/loaded/X;",
                              evidence=[{"event_id": "e7"}])
        row = self.store.get(cid)
        self.assertIs(row["static_match"], False)
        self.assertIsNone(row["static"])     # no fabricated static match
        self.assertEqual(row["evidence"], [{"event_id": "e7"}])

    def test_get_links_event_and_smali_location(self):
        runs = RunStore(self.proj)
        rid = runs.begin_run("crypto_watch")
        eid = runs.add_event(rid, "crypto_record", {"hook": "h"},
                             class_sig=CLASS_SIG, method_name="a",
                             method_sig="()V")
        runs.end_run(rid, "completed")
        cid, _ = self.observe(run_id=rid, event_id=eid,
                              evidence=[{"event_id": eid, "run_id": rid}])
        row = self.store.get(cid)
        self.assertIs(row["static_match"], True)
        self.assertEqual(row["static"]["smali"]["path"],
                         "smali/com/foo/a/a.smali")
        self.assertEqual(len(row["events"]), 1)
        self.assertEqual(row["events"][0]["event_id"], eid)
        self.assertEqual(row["events"][0]["payload"], {"hook": "h"})

    def test_pagination(self):
        for i in range(7):
            self.observe(f"Candidate{i}")
        page = self.store.list(limit=3, offset=0)
        self.assertEqual((page["count"], page["total"]), (3, 7))
        self.assertIs(page["truncated"], True)
        rest = self.store.list(limit=3, offset=6)
        self.assertEqual(rest["count"], 1)
        self.assertIs(rest["truncated"], False)

    def test_export_contains_decisions(self):
        cid, _ = self.observe()
        self.store.accept(cid)
        data = self.store.export()
        self.assertEqual(data["alias_export_version"], 1)
        self.assertEqual(data["apk_sha256"], APK_SHA)
        self.assertIn("sensitive", data["retention"])
        self.assertEqual(len(data["candidates"]), 1)
        self.assertEqual([d["action"]
                          for d in data["candidates"][0]["decisions"]],
                         ["suggest", "accept"])

    def test_deobf_and_original_signatures_untouched(self):
        with self.proj.db() as db:
            before = db.one("SELECT * FROM classes WHERE sig=?",
                            (CLASS_SIG,))
        cid, _ = self.observe()
        self.store.accept(cid)
        self.store.add_alias(CLASS_SIG, "BillingRepo")
        self.store.revise(cid, "PaymentRepo")
        with self.proj.db() as db:
            after = db.one("SELECT * FROM classes WHERE sig=?", (CLASS_SIG,))
        self.assertEqual(before, after)  # byte-for-byte identical row
        self.assertEqual(after["deobf_fqcn"], CLASS_DEOBF)


# ------------------------------------------------------------- collector
class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.store = AliasStore(self.proj)

    def tearDown(self):
        self.tmp.cleanup()

    def collector(self, **budget_kw):
        return AliasCollector(None, store=self.store,
                              budgets=CollectBudgets(**budget_kw))

    def ctx(self, **kw):
        return {"class_sig": CLASS_SIG, **kw}

    def test_record_strings_become_candidates_url_becomes_context(self):
        rec = {"hook": "h", "args": {
            "tag": {"type": "string", "v": "PaymentRepository"},
            "key": {"type": "byte[]", "hex": "aa", "b64": "qq==",
                    "utf8": "https://api.internal/v1", "len": 23}}}
        rep = self.collector().collect_from_record(rec, self.ctx())
        self.assertEqual([s["candidate"] for s in rep["suggestions"]],
                         ["PaymentRepository"])
        self.assertEqual(rep["suggestions"][0]["rule"], "log_tag")
        self.assertEqual(rep["behavioral_context"][0]["rule"],
                         "url_context")
        # no candidate invented from the URL
        self.assertEqual(self.store.list()["total"], 1)
        row = self.store.list()["candidates"][0]
        self.assertEqual(row["candidate"], "PaymentRepository")

    def test_snapshot_strings_attributed_to_innermost_class(self):
        snap = {"frame": 0, "class": "Lcom/foo/Top;",
                "this": {"cls": CLASS_SIG, "id": 1,
                         "f": {"tag": {"s": "PaymentRepository"},
                               "url": {"s": "https://x.example/v1"}},
                         "s": {"COUNT": 5}},     # static fields dict
                "locals": {"state": {"s": "ok"}}}
        rep = self.collector().collect_from_snapshot(
            snap, self.ctx(class_sig="Lcom/foo/Top;"))
        self.assertEqual(len(rep["suggestions"]), 1)
        row = self.store.list()["candidates"][0]
        self.assertEqual(row["class_sig"], CLASS_SIG)  # the object's class
        self.assertEqual(row["candidate"], "PaymentRepository")

    def test_string_budget_exhaustion_is_partial(self):
        rec = {"args": {f"k{i}": f"Value{i}X" for i in range(5)}}
        coll = self.collector(max_strings=2)
        rep = coll.collect_from_record(rec, self.ctx())
        self.assertIs(rep["partial"], True)
        self.assertIn("string budget", rep["reasons"][0])
        self.assertIs(coll.report()["partial"], True)

    def test_extra_reads_are_budgeted_and_measured(self):
        c = FakeClient()
        coll = self.collector(extra_reads=True)
        rec = {"args": {"obj": {"type": "object", "id": 88}}}
        rep = coll.collect_from_record(rec, self.ctx(), client=c)
        self.assertEqual(rep["extra"]["strings"], 1)
        # 4 measured JDWP requests: reftype, fields, get_values, string
        self.assertEqual(rep["extra"]["requests"], 4)
        self.assertEqual(coll.report()["jdwp_reads"], 4)
        row = self.store.list()["candidates"][0]
        self.assertEqual(row["candidate"], "PaymentRepository")
        self.assertEqual(row["evidence"][0]["label"], "field:TAG")
        self.assertIn("pause_ms", coll.report())

    def test_extra_read_budgets_produce_partial_results(self):
        # object budget 0: no reads at all, explicit reason
        coll = self.collector(extra_reads=True, max_extra_objects=0)
        rep = coll.collect_from_record(
            {"args": {"o": {"type": "object", "id": 88}}}, self.ctx(),
            client=FakeClient())
        self.assertIs(rep["extra"]["partial"], True)
        self.assertIn("object budget", rep["extra"]["reasons"][0])
        self.assertEqual(rep["extra"]["requests"], 0)
        # request budget smaller than one object read
        coll = self.collector(extra_reads=True, max_extra_requests=2)
        rep = coll.collect_from_record(
            {"args": {"o": {"type": "object", "id": 88}}}, self.ctx(),
            client=FakeClient())
        self.assertIs(rep["extra"]["partial"], True)
        self.assertIn("request budget", rep["extra"]["reasons"][0])
        self.assertLessEqual(coll.report()["jdwp_reads"], 2)

    def test_read_failure_is_partial_and_counted(self):
        c = FakeClient()
        c.fail_reads.add("object_reftype")
        coll = self.collector(extra_reads=True)
        rep = coll.collect_from_record(
            {"args": {"o": {"type": "object", "id": 88}}}, self.ctx(),
            client=c)
        self.assertIs(rep["extra"]["partial"], True)
        self.assertIn("INVALID_OBJECT", rep["extra"]["reasons"][0])
        self.assertEqual(coll.report()["jdwp_reads"], 1)  # the failed read

    def test_no_extra_reads_by_default(self):
        c = FakeClient()
        coll = self.collector()
        coll.collect_from_record(
            {"args": {"o": {"type": "object", "id": 88}}}, self.ctx(),
            client=c)
        self.assertEqual(coll.report()["jdwp_reads"], 0)  # zero-overhead
                                                         # path only
        self.assertEqual(c.calls, [])


# ------------------------------------------------- dispatcher integration
class DispatcherIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_failure_releases_lease_and_session_stays_usable(self):
        c = FakeClient()
        c.fail_reads.add("object_reftype")
        s = make_session(c, self.proj)
        d = s.events
        rid = c.set_breakpoint(1000, 500, 0)
        d.register(rid, {"owner": "user", "kind": EVK_BREAKPOINT,
                         "entry": "source", "spec": "x:1"})
        coll = AliasCollector(s, store=AliasStore(self.proj),
                              budgets=CollectBudgets(extra_reads=True))

        def on_event(ev, lease):
            coll.collect_from_record(
                {"args": {"o": {"type": "object", "id": 88}}},
                {"class_sig": CLASS_SIG}, client=c)

        sub = d.subscribe("user", on_event)
        r = d.dispatch(composite(bp_event(rid, thread=11, cls=1000)))
        sub.close()
        self.assertEqual(c.resumed, [11])     # owned suspension released
        self.assertIs(coll.partial, True)     # partial, not an exception
        self.assertEqual(r.lease.errors, [])  # collector absorbed its error
        self.assertEqual(s.list_breakpoints()[0]["spec"], "x:1")  # usable


# ------------------------------------------------------ watch integration
class WatchIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.store = AliasStore(self.proj)

    def tearDown(self):
        self.tmp.cleanup()

    def watch(self, client, **kw):
        s = make_session(client, self.proj)
        return crypto.run_watch(s, duration_s=30, names=[SPEC_HOOK], **kw)

    def test_collect_aliases_consumes_watch_records(self):
        out = self.watch(watch_client(), collect_aliases=True)
        self.assertEqual(out["hits"], 1)
        # collecting implies recording: run/event evidence exists
        self.assertIsNotNone(out["run_id"])
        rep = out["alias_collection"]
        self.assertIs(rep["persisted"], True)
        self.assertEqual(rep["suggestions"], 1)
        self.assertEqual(rep["behavioral_context"], 1)   # the byte[] URL
        self.assertEqual(rep["jdwp_reads"], 0)           # captured values
        self.assertIn("pause_ms", rep)                   # measured, not
        self.assertIn("note", rep)                       # guaranteed
        rows = self.store.list()["candidates"]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["candidate"], "PaymentRepository")
        self.assertEqual(row["class_sig"], SPEC_SIG)
        self.assertEqual(row["method_name"], "<init>")
        self.assertEqual(row["classloader_key"], "e0:9001")
        self.assertEqual(row["run_id"], out["run_id"])
        got = RunStore(self.proj).get_run(out["run_id"])
        self.assertEqual(row["event_id"], got["events"][0]["event_id"])
        # the URL never became a candidate
        self.assertNotIn("https", row["candidate"])
        # framework class is not in the app index: evidence without a
        # fabricated static match
        self.assertIs(self.store.get(row["candidate_id"])["static_match"],
                      False)

    def test_repeated_hits_dedupe_with_frequency(self):
        out = self.watch(watch_client(n_events=3), collect_aliases=True)
        self.assertEqual(out["hits"], 3)
        rows = self.store.list()["candidates"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["observations"], 3)
        self.assertEqual(len(rows[0]["evidence"]), 3)  # per-event refs

    def test_watch_off_by_default(self):
        out = self.watch(watch_client())
        self.assertNotIn("alias_collection", out)
        self.assertIsNone(out["run_id"])
        self.assertEqual(self.store.list()["total"], 0)

    def test_capture_failure_releases_suspension_and_reports(self):
        c = watch_client()
        c.fail_frames = True   # capture fails on every hit
        out = self.watch(c, collect_aliases=True)
        self.assertEqual(out["hits"], 1)
        self.assertIn("capture_error", out["records"][0])
        self.assertEqual(c.resumed, [11])      # lease released anyway
        self.assertIn("pause_ms", out["alias_collection"])
        # session fully usable afterwards: another watch runs clean
        c2 = watch_client()
        out2 = self.watch(c2)
        self.assertEqual(out2["hits"], 1)


# ----------------------------------------------------- output integration
class OutputIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = make_project(self.tmp.name)
        self.store = AliasStore(self.proj)
        self.store.add_alias(CLASS_SIG, "PaymentRepo")

    def tearDown(self):
        self.tmp.cleanup()

    def test_translate_exposes_sig_deobf_alias_as_distinct_fields(self):
        with self.proj.db() as db:
            res = translate.resolve(db, f"{CLASS_FQCN}:10")
        self.assertEqual(res["sig"], CLASS_SIG)
        self.assertEqual(res["deobf"], CLASS_DEOBF)
        self.assertEqual(res["alias"], "PaymentRepo")

    def test_alias_is_never_a_resolution_input(self):
        with self.proj.db() as db:
            with self.assertRaises(ResolveError):
                translate.resolve(db, "PaymentRepo:10")

    def test_classes_command_annotates_without_changing_identity(self):
        out = cmd_classes(Ctx(self.tmp.name), filter="foo")
        row = out["classes"][0]
        self.assertEqual(row["fqcn"], CLASS_FQCN)
        self.assertEqual(row["deobf_fqcn"], CLASS_DEOBF)
        self.assertEqual(row["sig"], CLASS_SIG)
        self.assertEqual(row["alias"], "PaymentRepo")

    def test_breakpoint_resolution_carries_distinct_fields(self):
        c = FakeClient()
        c.classes[CLASS_SIG] = [{"type_id": 1000}]
        c.methods[1000] = [{"name": "a", "sig": "()V", "id": 500}]
        s = make_session(c, self.proj)
        out = s.set_breakpoint(f"{CLASS_FQCN}:10")
        res = out["resolved"]
        self.assertEqual(res["sig"], CLASS_SIG)
        self.assertEqual(res["deobf"], CLASS_DEOBF)
        self.assertEqual(res["alias"], "PaymentRepo")
        # targeting used the original identity only
        self.assertEqual(out["breakpoints"][0]["method"], "a")

    def test_coverage_style_alias_map(self):
        with self.proj.db() as db:
            m = accepted_alias_map(db, [CLASS_SIG, "Lcom/foo/Unknown;"])
        self.assertEqual(m, {CLASS_SIG: "PaymentRepo"})


# -------------------------------------------------------- reindex + CLI
class ReindexCarryOverTests(unittest.TestCase):
    def test_alias_rows_copied_verbatim_across_reindex(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj = make_project(f"{tmp}/live")
            store = AliasStore(proj)
            cid, _ = store.observe(class_sig=CLASS_SIG,
                                   candidate="PaymentRepository",
                                   score=0.8, rule="log_tag")
            store.accept(cid)
            staging_path = f"{tmp}/staging.db"
            staging = MappingDB(staging_path)
            _copy_observations(staging, proj.db_path)
            rows = staging.query("SELECT * FROM alias_candidates")
            decs = staging.query("SELECT * FROM alias_decisions")
            staging.conn.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["candidate_id"], cid)
        self.assertEqual(rows[0]["status"], "accepted")
        self.assertEqual([d["action"] for d in decs], ["suggest", "accept"])

    def test_copy_observations_tolerates_pre_alias_databases(self):
        with tempfile.TemporaryDirectory() as tmp:
            proj = make_project(f"{tmp}/live")
            RunStore(proj).begin_run("snapshot", run_id="r1")
            # simulate a project created before issue #25
            with proj.db() as db:
                db.execute("DROP TABLE alias_candidates")
                db.execute("DROP TABLE alias_decisions")
            staging = MappingDB(f"{tmp}/staging.db")
            _copy_observations(staging, proj.db_path)  # must not fail
            runs = staging.query("SELECT * FROM runs")
            staging.conn.close()
        self.assertEqual([r["run_id"] for r in runs], ["r1"])


class CliSurfaceTests(unittest.TestCase):
    def test_aliases_command_workflow_via_cmd_and_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_project(tmp)
            ctx = Ctx(tmp)
            out = cmd_aliases(ctx, action="add", class_sig=CLASS_SIG,
                              alias="PaymentRepo")
            cid = out["candidate_id"]
            self.assertEqual(out["status"], "accepted")
            got = cmd_aliases(ctx, action="get", candidate_id=cid)
            self.assertEqual(got["candidate"], "PaymentRepo")
            out = cmd_aliases(ctx, action="revise", candidate_id=cid,
                              alias="BillingRepo")
            self.assertEqual(out["superseded"], [cid])
            lst = cmd_aliases(ctx, action="list", status="superseded")
            self.assertEqual(lst["total"], 1)
            exp = cmd_aliases(ctx, action="export", file=f"{tmp}/a.json")
            self.assertEqual(exp["candidates"], 2)
            data = json.loads(open(f"{tmp}/a.json").read())
            self.assertEqual(data["alias_export_version"], 1)
            # through the real CLI parser
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["--project", tmp, "aliases", "list"])
            self.assertEqual(rc, 0)
            line = json.loads(buf.getvalue().strip())
            self.assertEqual(line["status"], "ok")
            self.assertEqual(line["data"]["total"], 2)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(["--project", tmp, "aliases", "reject",
                               out["candidate_id"], "--note", "no"])
            self.assertEqual(rc, 0)
            self.assertEqual(AliasStore(Project.open(tmp)).get(
                out["candidate_id"])["status"], "rejected")


if __name__ == "__main__":
    unittest.main()

"""Offline tests for issue #31 — session-owned event dispatcher and
reusable hook lifecycle. Duck-typed FakeClient drives a real DebugSession
(no device), mirroring test_crypto_hooks conventions."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from apkdbg.debug.coverage import CoverageTracker
from apkdbg.debug.hooks import crypto
from apkdbg.debug.session import DebugSession
from apkdbg.device.jdwp import (
    EVK_BREAKPOINT, EVK_CLASS_PREPARE, EVK_METHOD_ENTRY,
    EVK_METHOD_EXIT_RET, SP_ALL, SP_EVENT_THREAD, SP_NONE, JdwpError,
)

HOOK = "Cipher.doFinal()"
CLS_SIG = "Ljavax/crypto/Cipher;"


def _timeout_error():
    e = JdwpError("event wait timed out")
    e.code = "E_JDWP_TIMEOUT"
    return e


class FakeClient:
    def __init__(self):
        self.next_rid = 1
        self.classes = {}        # sig -> [{"type_id": int}]
        self.methods = {}        # type_id -> [{"name","sig","id"}]
        self.sigs = {}           # type_id -> signature
        self.loaders = {}        # type_id -> classloader object id
        self.frames = {}         # thread -> [frame dicts]
        self.event_queue = []    # composites returned by next_event
        self.cleared = []        # (kind, request_id)
        self.resumed = []        # thread ids
        self.bp_calls = []       # (class_id, method_id, index, suspend)
        self.set_event_calls = []  # (kind, suspend, mods)

    def close(self):
        pass

    def _rid(self):
        rid = self.next_rid
        self.next_rid += 1
        return rid

    def classes_by_signature(self, sig):
        return self.classes.get(sig, [])

    def rt_methods(self, type_id):
        return self.methods.get(type_id, [])

    def rt_signature(self, type_id):
        return self.sigs.get(type_id, f"Lfake/{type_id};")

    def rt_class_loader(self, type_id):
        return self.loaders.get(type_id, 0)

    def method_line_table(self, type_id, method_id):
        return {"lines": [{"index": 0, "line": 1}]}

    def method_var_table(self, type_id, method_id):
        raise JdwpError("ABSENT_INFORMATION")

    def set_breakpoint(self, class_id, method_id, index, suspend_policy=2):
        self.bp_calls.append((class_id, method_id, index, suspend_policy))
        return self._rid()

    def set_event(self, kind, suspend, mods):
        self.set_event_calls.append((kind, suspend, mods))
        return self._rid()

    def mod_class_only(self, type_id):
        return (4, b"")

    def mod_class_match(self, pattern):
        return (5, pattern.encode())

    def clear_event(self, kind, request_id):
        self.cleared.append((kind, request_id))

    def next_event(self, timeout=None):
        if self.event_queue:
            return self.event_queue.pop(0)
        raise _timeout_error()

    def thread_resume(self, thread):
        self.resumed.append(thread)

    def vm_resume(self):
        pass

    def thread_frames(self, thread, count=32):
        return self.frames.get(thread, [])

    def frame_this_object(self, thread, frame_id):
        return {"tag": 76, "v": None}


def make_session(client: FakeClient) -> DebugSession:
    s = DebugSession.__new__(DebugSession)
    s.project = s.adb = s.pkg = s.pid = s.port = None
    s.client = client
    s.bp_registry = {}
    s._sig_cache = {}
    return s


def hook_client(n_classes: int = 1) -> FakeClient:
    """Fake VM with Ljavax/crypto/Cipher; loaded n_classes times, each
    exposing doFinal()[B as method id type_id+500."""
    c = FakeClient()
    c.classes[CLS_SIG] = [{"type_id": 1000 + i} for i in range(n_classes)]
    for cls in c.classes[CLS_SIG]:
        tid = cls["type_id"]
        c.sigs[tid] = CLS_SIG
        c.methods[tid] = [{"name": "doFinal", "sig": "()[B", "id": tid + 500}]
    return c


def bp_event(rid, thread=11, cls=1000, method=1500):
    return {"kind": "breakpoint", "kind_id": EVK_BREAKPOINT,
            "request_id": rid, "thread": thread,
            "location": {"class": cls, "method": method, "index": 0}}


def entry_event(rid, thread=12, cls=1000, method=1500):
    return {"kind": "method_entry", "kind_id": EVK_METHOD_ENTRY,
            "request_id": rid, "thread": thread,
            "location": {"class": cls, "method": method, "index": 0}}


def exit_event(rid, thread=11, cls=1000, method=1500):
    return {"kind": "method_exit_return", "kind_id": EVK_METHOD_EXIT_RET,
            "request_id": rid, "thread": thread,
            "location": {"class": cls, "method": method, "index": 0},
            "return_value": {"tag": 86, "v": None}}


def prepare_event(rid, type_id, thread=5):
    return {"kind": "class_prepare", "kind_id": EVK_CLASS_PREPARE,
            "request_id": rid, "thread": thread, "tag": 1,
            "type_id": type_id, "signature": CLS_SIG, "status": 7}


def composite(*events, sp=SP_EVENT_THREAD):
    return {"suspend_policy": sp, "events": list(events)}


class EpochIsolationTests(unittest.TestCase):
    def test_two_sessions_reuse_numeric_rids(self):
        s1 = make_session(hook_client())
        s2 = make_session(hook_client())
        crypto.install(s1, names=[HOOK])
        crypto.install(s2, names=[HOOK])
        self.assertEqual(set(s1.bp_registry), {1})
        self.assertEqual(set(s2.bp_registry), {1})
        self.assertIsNot(s1.bp_registry[1], s2.bp_registry[1])
        s1.clear_request(1)
        self.assertEqual(s1.bp_registry, {})
        self.assertEqual(set(s2.bp_registry), {1})  # untouched

    def test_epoch_bump_kills_stale_handles(self):
        c = hook_client()
        s = make_session(c)
        crypto.install(s, names=[HOOK])
        sub = s.events.subscribe("crypto", lambda ev, lease: None)
        epoch0 = s.events.epoch
        self.assertTrue(sub.active)
        self.assertIsNotNone(s.events.lookup(1, EVK_BREAKPOINT))

        class FakeConn:
            def __init__(self, host, port):
                pass

            def connect(self):
                pass

            def close(self):
                pass
        with patch("apkdbg.debug.session.JdwpClient", FakeConn):
            s._attach()
        self.assertGreater(s.events.epoch, epoch0)
        self.assertFalse(sub.active)      # stale handle is dead
        self.assertEqual(s.bp_registry, {})
        self.assertIsNone(s.events.lookup(1))
        # the new connection reuses numeric id 1: no cross-contamination
        c2 = hook_client()
        s.client = c2
        crypto.install(s, names=[HOOK])
        self.assertEqual(set(s.bp_registry), {1})
        self.assertIs(s.events.lookup(1, EVK_BREAKPOINT),
                      s.bp_registry[1])

    def test_symbolic_hook_def_survives_epoch_bump(self):
        s = make_session(hook_client())
        crypto.install(s, names=[HOOK])
        self.assertEqual(len(s.events.symbolic_hooks()), 1)
        s.events.bump_epoch()
        s.bp_registry.clear()
        sym = s.events.symbolic_hooks()
        self.assertEqual(len(sym), 1)
        self.assertEqual(sym[0]["hook"], HOOK)
        self.assertEqual(sym[0]["owner"], "crypto")


class RoutingTests(unittest.TestCase):
    """Crypto + a user breakpoint + coverage: each consumer receives only
    its own events; unrelated stops stay unclaimed and unresumed."""

    def _session(self):
        c = FakeClient()
        c.sigs[1000] = "Lcom/foo/A;"
        c.methods[1000] = [{"name": "m", "sig": "()V", "id": 1500}]
        s = make_session(c)
        d = s.events
        d.register(1, {"owner": "crypto", "kind": EVK_BREAKPOINT,
                       "entry": "hook", "hook": HOOK})
        d.register(2, {"owner": "coverage:run1", "kind": EVK_METHOD_ENTRY,
                       "entry": "coverage", "run_id": "run1"})
        d.register(3, {"owner": "user", "kind": EVK_BREAKPOINT,
                       "entry": "source", "spec": "com.foo.A.m:42",
                       "java_line": 42, "method": "m"})
        return c, s, d

    def test_fan_out_by_request_id_and_kind(self):
        c, s, d = self._session()
        got = {"crypto": [], "coverage": []}
        d.subscribe("crypto", lambda ev, lease: got["crypto"].append(ev))
        d.subscribe("coverage:run1",
                    lambda ev, lease: got["coverage"].append(ev))
        kind_mismatch = entry_event(1, thread=99)  # rid 1 is a BREAKPOINT
        r = d.dispatch(composite(
            bp_event(1, thread=11), entry_event(2, thread=12),
            bp_event(3, thread=33), bp_event(999, thread=44),
            kind_mismatch))
        self.assertEqual([e["request_id"] for e in got["crypto"]], [1])
        self.assertEqual([e["request_id"] for e in got["coverage"]], [2])
        self.assertEqual([e["request_id"] for e in r["events"]],
                         [3, 999, 1])  # user bp, unknown, kind mismatch
        # claimed suspensions released once per thread; unclaimed untouched
        self.assertEqual(sorted(c.resumed), [11, 12])
        # enrichment: source entry carries source fields, hook carries hook
        self.assertEqual(r["events"][0]["breakpoint"],
                         {"spec": "com.foo.A.m:42", "java_line": 42,
                          "method": "m"})
        self.assertNotIn("breakpoint", r["events"][1])  # unknown rid
        self.assertEqual(r["events"][2]["breakpoint"],
                         {"hook": HOOK})  # hook entry: no source fields

    def test_sp_none_never_resumes(self):
        c, s, d = self._session()
        got = []
        d.subscribe("coverage:run1", lambda ev, lease: got.append(ev))
        r = d.dispatch(composite(entry_event(2, thread=12), sp=SP_NONE))
        self.assertEqual(len(got), 1)
        self.assertEqual(c.resumed, [])
        self.assertTrue(r.lease.released)
        self.assertEqual(r.lease.threads, frozenset())

    def test_sp_all_user_stop_not_in_lease(self):
        c, s, d = self._session()
        d.subscribe("crypto", lambda ev, lease: None)
        r = d.dispatch(composite(bp_event(1, thread=11),
                                 bp_event(3, thread=33), sp=SP_ALL))
        self.assertEqual(c.resumed, [11])  # user stop (33) preserved
        self.assertEqual([e["request_id"] for e in r["events"]], [3])


class LeaseTests(unittest.TestCase):
    def test_release_once_after_all_owners_finish(self):
        c = FakeClient()
        c.sigs[1000] = "Lcom/foo/A;"
        s = make_session(c)
        d = s.events
        d.register(1, {"owner": "crypto", "kind": EVK_BREAKPOINT})
        d.register(2, {"owner": "coverage:run1", "kind": EVK_BREAKPOINT})
        calls = []

        def cb_a(ev, lease):
            calls.append("a")
            self.assertEqual(c.resumed, [])  # not resumed before owners done

        def cb_b(ev, lease):
            calls.append("b")
            self.assertEqual(c.resumed, [])

        d.subscribe("crypto", cb_a)
        d.subscribe("coverage:run1", cb_b)
        # one thread, two owners, same composite
        d.dispatch(composite(bp_event(1, thread=11),
                             bp_event(2, thread=11)))
        self.assertEqual(calls, ["a", "b"])
        self.assertEqual(c.resumed, [11])  # exactly once

    def test_retain_preserves_user_stop(self):
        c = FakeClient()
        c.sigs[1000] = "Lcom/foo/A;"
        s = make_session(c)
        d = s.events
        d.register(1, {"owner": "user", "kind": EVK_BREAKPOINT})

        def cb(ev, lease):
            lease.retain(ev["thread"])

        d.subscribe("user", cb, request_ids={1})
        r = d.dispatch(composite(bp_event(1, thread=11)))
        self.assertEqual(c.resumed, [])
        self.assertTrue(r.lease.released)

    def test_unclaimed_stop_on_same_thread_retains_suspension(self):
        c = FakeClient()
        c.sigs[1000] = "Lcom/foo/A;"
        s = make_session(c)
        d = s.events
        d.register(1, {"owner": "crypto", "kind": EVK_BREAKPOINT})
        d.register(3, {"owner": "user", "kind": EVK_BREAKPOINT})
        got = []
        d.subscribe("crypto", lambda ev, lease: got.append(ev))
        # watcher and user breakpoint both fire on thread 11 in one composite
        r = d.dispatch(composite(bp_event(1, thread=11),
                                 bp_event(3, thread=11)))
        self.assertEqual(len(got), 1)
        self.assertEqual(c.resumed, [])  # user stop keeps thread 11 suspended
        self.assertEqual([e["request_id"] for e in r["events"]], [3])
        self.assertTrue(r.lease.released)

    def test_claimed_only_thread_resumed_alongside_shared_thread(self):
        c = FakeClient()
        c.sigs[1000] = "Lcom/foo/A;"
        s = make_session(c)
        d = s.events
        d.register(1, {"owner": "crypto", "kind": EVK_BREAKPOINT})
        d.register(3, {"owner": "user", "kind": EVK_BREAKPOINT})
        got = []
        d.subscribe("crypto", lambda ev, lease: got.append(ev))
        r = d.dispatch(composite(bp_event(1, thread=11),
                                 bp_event(1, thread=12),
                                 bp_event(3, thread=11)))
        self.assertEqual(len(got), 2)
        self.assertEqual(c.resumed, [12])  # exclusively claimed thread only
        self.assertEqual([e["request_id"] for e in r["events"]], [3])


class DeferredInstallTests(unittest.TestCase):
    def _prepare(self, c, *type_ids):
        c.classes[CLS_SIG] = [{"type_id": t} for t in type_ids]
        for t in type_ids:
            c.sigs[t] = CLS_SIG
            c.methods[t] = [{"name": "doFinal", "sig": "()[B",
                             "id": t + 500}]

    def test_delayed_class_installs_exactly_once(self):
        c = FakeClient()  # Cipher not loaded yet
        s = make_session(c)
        rep = crypto.install(s, names=[HOOK], capture_returns=True,
                             defer=True)
        self.assertEqual(rep["installed"], [])
        self.assertEqual(rep["states"], {HOOK: "pending"})
        self.assertEqual(rep["pending"][0]["state"], "pending")
        rid_cp = rep["deferred"][0]["request_id"]
        kind, sp, mods = c.set_event_calls[0]
        self.assertEqual(kind, EVK_CLASS_PREPARE)
        self.assertEqual(mods[0][1], b"javax.crypto.Cipher")

        self._prepare(c, 1000)
        d = s.events
        c.event_queue.append(composite(prepare_event(rid_cp, 1000)))
        r = d.next_routed(timeout=1)
        self.assertEqual(r["events"], [])  # claimed by the deferred handler
        self.assertEqual(c.resumed, [5])   # prepare thread released
        self.assertEqual(len(c.bp_calls), 1)         # entry
        self.assertEqual(len(c.set_event_calls), 2)  # prepare + exit
        rids = set(s.bp_registry)
        self.assertEqual(len(rids), 3)  # entry + exit + CLASS_PREPARE

        # same class prepares again (e.g. duplicate event): no duplicates
        c.event_queue.append(composite(prepare_event(rid_cp, 1000)))
        d.next_routed(timeout=1)
        self.assertEqual(len(c.bp_calls), 1)
        self.assertEqual(len(c.set_event_calls), 2)

    def test_two_classloaders_install_once_each(self):
        c = FakeClient()
        s = make_session(c)
        rep = crypto.install(s, names=[HOOK], capture_returns=True,
                             defer=True)
        rid_cp = rep["deferred"][0]["request_id"]
        self._prepare(c, 1000, 1001)
        c.loaders.update({1000: 501, 1001: 502})
        d = s.events
        c.event_queue.append(composite(prepare_event(rid_cp, 1000)))
        c.event_queue.append(composite(prepare_event(rid_cp, 1001)))
        d.next_routed(timeout=1)
        d.next_routed(timeout=1)
        # entry+exit per class instance, exactly once
        self.assertEqual(len(c.bp_calls), 2)
        self.assertEqual({call[0] for call in c.bp_calls}, {1000, 1001})
        metas = [m for m in s.bp_registry.values()
                 if m.get("entry") == "hook"]
        self.assertEqual(len(metas), 4)
        loaders = {(m["type_id"], m["loader"]) for m in metas}
        self.assertEqual(loaders, {(1000, 501), (1000, 501),
                                   (1001, 502), (1001, 502)})

    def test_deferred_watch_cleaned_up_with_hook_kind(self):
        c = FakeClient()
        s = make_session(c)
        out = crypto.run_watch(s, duration_s=1, names=[HOOK], defer=True)
        self.assertEqual(out["reason"], "duration")
        self.assertEqual(out["deferred"][0]["hook"], HOOK)
        self.assertEqual(out["cleanup_errors"], [])
        self.assertEqual(c.cleared, [(EVK_CLASS_PREPARE, 1)])
        self.assertEqual(s.bp_registry, {})


class CleanupTests(unittest.TestCase):
    def test_capture_error_releases_only_owned_and_clears(self):
        c = hook_client()
        s = make_session(c)
        # rids 1 (entry) + 2 (exit); composite mixes an owned event with an
        # unrelated suspended stop, then the transport fails
        c.event_queue.append(composite(bp_event(1, thread=11),
                                       bp_event(999, thread=22)))
        calls = {"n": 0}
        orig_next = c.next_event

        def flaky(timeout=None):
            calls["n"] += 1
            if calls["n"] > 1:
                raise RuntimeError("boom")
            return orig_next(timeout)
        c.next_event = flaky
        out = crypto.run_watch(s, duration_s=10, names=[HOOK],
                               capture_returns=True)
        self.assertEqual(out["reason"], "error")
        self.assertEqual(out["cleanup_errors"], [])
        self.assertEqual(out["unconfirmed"], [])
        self.assertEqual(set(c.cleared),
                         {(EVK_BREAKPOINT, 1), (EVK_METHOD_EXIT_RET, 2)})
        self.assertEqual(c.resumed, [11])  # 22 is not the watch's to resume
        stashed = s.wait_events(timeout=1)
        self.assertEqual([e["request_id"] for e in stashed["events"]],
                         [999])

    def test_cancellation_clears_all_owned(self):
        c = hook_client()
        s = make_session(c)

        def cancelled(timeout=None):
            raise KeyboardInterrupt
        c.next_event = cancelled
        with self.assertRaises(KeyboardInterrupt):
            crypto.run_watch(s, duration_s=10, names=[HOOK],
                             capture_returns=True)
        self.assertEqual(set(c.cleared),
                         {(EVK_BREAKPOINT, 1), (EVK_METHOD_EXIT_RET, 2)})
        self.assertEqual(s.bp_registry, {})

    def test_reconnect_mid_watch_reports_unconfirmed(self):
        c = hook_client()
        s = make_session(c)

        def hijack(timeout=None):
            # connection got re-established: new epoch, dead registry
            s.events.bump_epoch()
            s.bp_registry.clear()
            raise _timeout_error()
        c.next_event = hijack
        out = crypto.run_watch(s, duration_s=10, names=[HOOK],
                               capture_returns=True)
        self.assertEqual(out["unconfirmed"], [1, 2])
        self.assertEqual(c.cleared, [])  # never clear a reused numeric id
        self.assertEqual(out["cleanup_errors"], [])


class PhaseKindTests(unittest.TestCase):
    def test_entry_and_return_are_distinct_records(self):
        c = hook_client()
        s = make_session(c)
        c.event_queue.append(composite(bp_event(1, thread=11, method=1500),
                                       exit_event(2, thread=11,
                                                  method=1500)))
        out = crypto.run_watch(s, duration_s=10, names=[HOOK],
                               capture_returns=True)
        phases = [r["phase"] for r in out["records"]]
        self.assertEqual(phases, ["entry", "return"])
        # both events of the composite share one thread: one release
        self.assertEqual(c.resumed, [11])
        # cleanup used each request's actual kind
        self.assertEqual(set(c.cleared),
                         {(EVK_BREAKPOINT, 1), (EVK_METHOD_EXIT_RET, 2)})


class CoverageConsumerTests(unittest.TestCase):
    def test_coverage_consumes_only_own_events(self):
        c = FakeClient()
        c.sigs[1000] = "Lcom/foo/A;"
        c.methods[1000] = [{"name": "m", "sig": "()V", "id": 1500}]
        s = make_session(c)
        c.event_queue.append(composite(
            entry_event(1, thread=11),      # coverage request (rid 1)
            entry_event(999, thread=22),    # someone else's
            sp=SP_NONE))
        rep = CoverageTracker(s, ["com.foo"], mode="method",
                              seconds=5).run()
        self.assertEqual(rep["events"], 1)
        self.assertEqual(rep["methods"], {"Lcom/foo/A;->m": 1})
        self.assertEqual(c.cleared, [(EVK_METHOD_ENTRY, 1)])
        self.assertEqual(c.resumed, [])  # SP_NONE never resumes
        self.assertEqual(s.bp_registry, {})
        stashed = s.wait_events(timeout=1)
        self.assertEqual([e["request_id"] for e in stashed["events"]],
                         [999])


if __name__ == "__main__":
    unittest.main()

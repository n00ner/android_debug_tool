"""Offline regression tests for issue #21 — crypto hook capture lifecycle.
Duck-typed FakeJdwpClient drives a real DebugSession (no device)."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from apkdbg.debug.hooks import crypto
from apkdbg.debug.session import DebugSession
from apkdbg.device.jdwp import (
    EVK_BREAKPOINT, EVK_METHOD_EXIT_RET, TAG_ARRAY, TAG_STRING, JdwpError,
)

HOOK = "Cipher.doFinal()"
CLS_SIG = "Ljavax/crypto/Cipher;"


def _timeout_error():
    e = JdwpError("event wait timed out")
    e.code = "E_JDWP_TIMEOUT"
    return e


class FakeJdwpClient:
    def __init__(self):
        self.next_rid = 1
        self.classes = {}        # sig -> [{"type_id": int}]
        self.methods = {}        # type_id -> [{"name","sig","id"}]
        self.sigs = {}           # type_id -> signature
        self.frames = {}         # thread -> [frame dicts]
        self.slot_values = {}    # (frame_id, slot) -> value
        self.arrays = {}         # oid -> bytes
        self.strings = {}        # oid -> str
        self.event_queue = []    # composites returned by next_event
        self.cleared = []        # (kind, request_id)
        self.resumed = []        # thread ids
        self.fail_set_event = False
        self.fail_thread_frames = False

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

    def method_line_table(self, type_id, method_id):
        return {"lines": [{"index": 0, "line": 1}]}

    def set_breakpoint(self, class_id, method_id, index, suspend_policy=2):
        return self._rid()

    def set_event(self, kind, suspend, mods):
        if self.fail_set_event:
            raise JdwpError("set_event failed")
        return self._rid()

    def mod_class_only(self, type_id):
        return (4, b"")

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
        if self.fail_thread_frames:
            raise AssertionError("thread_frames must not be called here")
        return self.frames.get(thread, [])

    def frame_get_values(self, thread, frame_id, slots):
        return [{"tag": tag, "v": self.slot_values.get((frame_id, slot))}
                for slot, tag in slots]

    def frame_this_object(self, thread, frame_id):
        return {"tag": 76, "v": None}

    def byte_array(self, oid, max_len=65536):
        return self.arrays.get(oid, b"")[:max_len]

    def array_length(self, oid):
        return len(self.arrays.get(oid, b""))

    def string_value(self, oid, max_len=4096):
        return self.strings.get(oid, "")[:max_len]


def make_session(client: FakeJdwpClient) -> DebugSession:
    """Real DebugSession wired to a fake client, skipping ADB/Project."""
    s = DebugSession.__new__(DebugSession)
    s.project = s.adb = s.pkg = s.pid = s.port = None
    s.client = client
    s.bp_registry = {}
    s._sig_cache = {}
    return s


def hook_client(n_classes: int = 1) -> FakeJdwpClient:
    """Fake VM where Ljavax/crypto/Cipher; is loaded in n_classes
    variants, each with doFinal()[B as method id 500+type_id."""
    c = FakeJdwpClient()
    c.classes[CLS_SIG] = [{"type_id": 1000 + i} for i in range(n_classes)]
    for cls in c.classes[CLS_SIG]:
        tid = cls["type_id"]
        c.sigs[tid] = CLS_SIG
        c.methods[tid] = [
            {"name": "doFinal", "sig": "()[B", "id": tid + 500},
            {"name": "init", "sig": "(ILjava/security/Key;)V",
             "id": tid + 900},
        ]
    return c


def bp_event(rid, thread=11, cls=1000, method=1500):
    return {"kind": "breakpoint", "kind_id": EVK_BREAKPOINT,
            "request_id": rid, "thread": thread,
            "location": {"class": cls, "method": method, "index": 0}}


def exit_event(rid, thread=11, cls=1000, method=1500, ret=None):
    return {"kind": "method_exit_return", "kind_id": EVK_METHOD_EXIT_RET,
            "request_id": rid, "thread": thread,
            "location": {"class": cls, "method": method, "index": 0},
            "return_value": ret if ret is not None else {"tag": 86, "v": None}}


def composite(*events):
    return {"suspend_policy": 1, "events": list(events)}


class WaitEventsTests(unittest.TestCase):
    def test_enrichment_tolerates_hook_entries(self):
        c = hook_client()
        s = make_session(c)
        s.bp_registry[7] = {"hook": HOOK, "spec": "doFinal()[B",
                            "kind": EVK_BREAKPOINT, "owner": "crypto"}
        c.event_queue.append(composite(bp_event(7)))
        ev = s.wait_events(timeout=1)
        e = ev["events"][0]
        self.assertEqual(e["breakpoint"],
                         {"spec": "doFinal()[B", "hook": HOOK})
        self.assertEqual(e["class_sig"], CLS_SIG)


class InstallTests(unittest.TestCase):
    def test_every_request_id_registered(self):
        c = hook_client(n_classes=2)
        s = make_session(c)
        rep = crypto.install(s, names=[HOOK], capture_returns=True)
        self.assertEqual(rep["pending"], [])
        rids = rep["installed"][0]["request_ids"]
        self.assertEqual(len(rids), 4)  # entry+exit for each of 2 classes
        self.assertEqual(set(rids), set(s.bp_registry))
        kinds = [s.bp_registry[r]["kind"] for r in rids]
        self.assertEqual(kinds.count(EVK_BREAKPOINT), 2)
        self.assertEqual(kinds.count(EVK_METHOD_EXIT_RET), 2)
        for r in rids:
            reg = s.bp_registry[r]
            self.assertEqual(reg["hook"], HOOK)
            self.assertEqual(reg["owner"], "crypto")
            self.assertEqual(reg["cls"], CLS_SIG)
            self.assertEqual(reg["method"], "doFinal")
            self.assertIn(reg["method_id"], (1500, 1501))
            self.assertIn(reg["phase"], ("entry", "return"))
            # every registered rid resolves to a record or None, no KeyError
            crypto.extract_event(
                s, bp_event(r, cls=reg["type_id"], method=reg["method_id"])
                if reg["kind"] == EVK_BREAKPOINT else
                exit_event(r, cls=reg["type_id"], method=reg["method_id"]))

    def test_pending_when_class_not_loaded(self):
        s = make_session(FakeJdwpClient())
        rep = crypto.install(s, names=[HOOK])
        self.assertEqual(rep["installed"], [])
        self.assertEqual(rep["pending"][0]["hook"], HOOK)
        self.assertEqual(s.bp_registry, {})

    def test_partial_install_rolls_back(self):
        c = hook_client()
        c.fail_set_event = True  # entry bp ok, method-exit registration fails
        s = make_session(c)
        rep = crypto.install(s, names=[HOOK], capture_returns=True)
        self.assertEqual(rep["installed"], [])
        self.assertEqual(rep["pending"][0]["hook"], HOOK)
        self.assertEqual(s.bp_registry, {})
        # the entry breakpoint request was cleared with its own kind
        self.assertEqual(c.cleared, [(EVK_BREAKPOINT, 1)])


class ExtractEventTests(unittest.TestCase):
    def setUp(self):
        self.c = hook_client()
        self.s = make_session(self.c)
        rep = crypto.install(self.s, names=[HOOK], capture_returns=True)
        rids = rep["installed"][0]["request_ids"]
        self.entry_rid, self.exit_rid = rids
        self.method_id = self.s.bp_registry[self.entry_rid]["method_id"]

    def test_exit_filtered_by_exact_method_id(self):
        other = exit_event(self.exit_rid, method=self.method_id + 999)
        self.assertIsNone(crypto.extract_event(self.s, other))
        mine = exit_event(self.exit_rid, method=self.method_id)
        rec = crypto.extract_event(self.s, mine)
        self.assertEqual(rec["phase"], "return")
        self.assertEqual(rec["hook"], HOOK)

    def test_exit_captures_return_value_without_frames(self):
        self.c.fail_thread_frames = True  # any frame access blows up
        self.c.arrays[9001] = b"hello"
        ev = exit_event(self.exit_rid, method=self.method_id,
                        ret={"tag": TAG_ARRAY, "v": 9001})
        rec = crypto.extract_event(self.s, ev)
        self.assertEqual(rec["phase"], "return")
        self.assertEqual(rec["return"]["hex"], b"hello".hex())
        self.assertEqual(rec["return"]["utf8"], "hello")
        self.assertFalse(rec["return"]["trunc"])
        # TAG_STRING -> string_value
        self.c.strings[8001] = "AES/GCM"
        ev = exit_event(self.exit_rid, method=self.method_id,
                        ret={"tag": TAG_STRING, "v": 8001})
        rec = crypto.extract_event(self.s, ev)
        self.assertEqual(rec["return"], {"type": "string", "v": "AES/GCM"})

    def test_entry_captures_args_from_frame0(self):
        # use the byte[] overload hook, which has a capture spec
        c = hook_client()
        c.methods[1000] = [{"name": "doFinal", "sig": "([B)[B", "id": 1500}]
        c.frames[11] = [{"frame_id": 1, "location": {}}]
        c.slot_values[(1, 1)] = 9001
        c.arrays[9001] = b"plaintext"
        s = make_session(c)
        rep = crypto.install(s, names=["Cipher.doFinal(byte[])"])
        rid = rep["installed"][0]["request_ids"][0]
        rec = crypto.extract_event(s, bp_event(rid))
        self.assertEqual(rec["phase"], "entry")
        self.assertEqual(rec["args"]["input"]["utf8"], "plaintext")

    def test_entry_frame_error_records_capture_error(self):
        self.c.frames[11] = []  # empty frames at entry
        rec = crypto.extract_event(self.s, bp_event(self.entry_rid))
        self.assertEqual(rec["phase"], "entry")
        self.assertIn("capture_error", rec)

    def test_unowned_event_returns_none(self):
        self.assertIsNone(crypto.extract_event(
            self.s, bp_event(999)))  # unknown request id
        reg = self.s.bp_registry[self.entry_rid]
        reg["owner"] = "something-else"
        self.assertIsNone(crypto.extract_event(
            self.s, bp_event(self.entry_rid)))


class RunWatchTests(unittest.TestCase):
    def test_capture_failure_still_tears_down(self):
        c = hook_client()
        s = make_session(c)
        # run_watch installs first: entry rid=1, exit rid=2 (one class).
        # Entry event on a frame-less thread -> capture_error; the next
        # wait raises a real error -> loop breaks; finally must still
        # clear both requests with their original kinds.
        c.event_queue.append(composite(bp_event(1)))
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
        self.assertTrue(out["errors"])
        self.assertEqual(out["records"][0]["phase"], "entry")
        self.assertIn("capture_error", out["records"][0])
        self.assertEqual(out["cleanup_errors"], [])
        self.assertEqual(set(c.cleared),
                         {(EVK_BREAKPOINT, 1), (EVK_METHOD_EXIT_RET, 2)})
        self.assertEqual(s.bp_registry, {})  # all requests popped
        self.assertIn(11, c.resumed)  # thread resumed despite capture error

    def test_teardown_clears_with_original_kind(self):
        c = hook_client()
        s = make_session(c)
        out = crypto.run_watch(s, duration_s=1, names=[HOOK],
                               capture_returns=True)
        self.assertEqual(out["reason"], "duration")
        self.assertEqual(out["cleanup_errors"], [])
        kinds = {}
        for kind, rid in c.cleared:
            kinds[rid] = kind
        self.assertEqual(sorted(kinds.values()),
                         sorted([EVK_BREAKPOINT, EVK_METHOD_EXIT_RET]))
        self.assertEqual(s.bp_registry, {})

    def test_max_events_limit(self):
        c = hook_client()
        s = make_session(c)

        orig_install = crypto.install

        def install_then_queue(session, **kw):
            r = orig_install(session, **kw)
            rid = r["installed"][0]["request_ids"][0]
            c.event_queue.append(composite(bp_event(rid)))
            c.event_queue.append(composite(bp_event(rid)))
            return r
        with patch.object(crypto, "install", install_then_queue):
            out = crypto.run_watch(s, duration_s=10, names=[HOOK],
                                   max_events=1)
        self.assertEqual(out["reason"], "max_events")
        self.assertEqual(out["hits"], 1)
        self.assertFalse(out["truncated"])

    def test_max_bytes_truncation(self):
        c = hook_client()
        s = make_session(c)

        orig_install = crypto.install

        def install_then_queue(session, **kw):
            r = orig_install(session, **kw)
            rid = r["installed"][0]["request_ids"][0]
            c.event_queue.append(composite(bp_event(rid)))
            return r
        with patch.object(crypto, "install", install_then_queue):
            out = crypto.run_watch(s, duration_s=10, names=[HOOK],
                                   max_bytes=1)
        self.assertEqual(out["reason"], "max_bytes")
        self.assertTrue(out["truncated"])
        self.assertGreaterEqual(out["captured_bytes"], 1)

    def test_unrelated_events_counted_and_resumed(self):
        c = hook_client()
        s = make_session(c)

        orig_install = crypto.install

        def install_then_queue(session, **kw):
            r = orig_install(session, **kw)
            rid = r["installed"][0]["request_ids"][0]
            c.event_queue.append(composite(
                bp_event(rid, thread=11),
                bp_event(999, thread=22),       # unrelated, suspended
                bp_event(rid, thread=11)))      # same thread again
            return r
        with patch.object(crypto, "install", install_then_queue):
            out = crypto.run_watch(s, duration_s=10, names=[HOOK])
        self.assertEqual(out["unrelated"], 1)
        self.assertEqual(out["hits"], 2)
        # one resume per thread per composite, both threads covered
        self.assertEqual(c.resumed.count(11), 1)
        self.assertEqual(c.resumed.count(22), 1)


class SessionIsolationTests(unittest.TestCase):
    def test_sessions_do_not_share_registry(self):
        self.assertFalse(hasattr(crypto, "_hook_by_rid"))
        s1 = make_session(hook_client())
        s2 = make_session(hook_client())
        crypto.install(s1, names=[HOOK])
        self.assertTrue(s1.bp_registry)
        self.assertEqual(s2.bp_registry, {})

    def test_reconnect_clears_registry(self):
        c = hook_client()
        s = make_session(c)
        crypto.install(s, names=[HOOK])
        s._sig_cache[1000] = CLS_SIG
        self.assertTrue(s.bp_registry)

        class FakeConn:
            def __init__(self, host, port):
                pass

            def connect(self):
                pass

            def close(self):
                pass
        with patch("apkdbg.debug.session.JdwpClient", FakeConn):
            s._attach()
        self.assertEqual(s.bp_registry, {})
        self.assertEqual(s._sig_cache, {})


if __name__ == "__main__":
    unittest.main()

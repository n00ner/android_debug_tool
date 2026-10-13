"""Offline tests for issue #34 — cancellable background jobs with bounded
event and result output.

A queue-fed FakeClient drives a real DebugSession (no device): next_event
blocks until a composite is pushed or the wait expires, mirroring the real
client's timeout contract. Server-level tests drive RpcServer.handle_line
against a temp project with the fake session injected.

Covers: control-request latency while a worker blocks on the event source,
cooperative cancel during capture and during export output writing (with
owned-resource cleanup), bounded buffers under an event flood with exact
retained/dropped/expired counts, read-cursor integrity and expiry,
concurrency conflict rules, idempotent cancel/status, bounded
completed-job retention, and deterministic shutdown records."""

from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from apkdbg.core.project import Project
from apkdbg.debug.session import DebugSession
from apkdbg.device.jdwp import (
    EVK_BREAKPOINT, EVK_METHOD_ENTRY, SP_EVENT_THREAD, JdwpConnError,
    JdwpError,
)
from apkdbg.errors import JobConflictError, JobNotFoundError
from apkdbg.jobs import Job, JobRegistry
from apkdbg.server import RpcServer

CIPHER = "Ljavax/crypto/Cipher;"
HOOK = "Cipher.doFinal()"

# documented bound: control replies never touch the JDWP socket, so they
# must be fast regardless of the worker's state
CONTROL_BOUND_S = 1.0


def _timeout_error():
    e = JdwpError("event wait timed out")
    e.code = "E_JDWP_TIMEOUT"
    return e


class FakeClient:
    """Queue-fed JDWP fake: next_event blocks for pushed composites."""

    def __init__(self):
        self._cond = threading.Condition()
        self.queue = []
        self.fail_next_event = None
        self.next_rid = 1
        self.classes = {}
        self.methods = {}
        self.sigs = {}
        self.arrays = {}
        self.obj_types = {}
        self.get_values_delay = 0.0
        self.cleared = []
        self.resumed = []
        self.closed = False

    # -- event source
    def push(self, composite):
        with self._cond:
            self.queue.append(composite)
            self._cond.notify()

    def next_event(self, timeout=None):
        deadline = time.monotonic() + (timeout if timeout is not None
                                       else 3600.0)
        with self._cond:
            while not self.queue:
                if self.fail_next_event is not None:
                    raise self.fail_next_event
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _timeout_error()
                self._cond.wait(min(remaining, 0.05))
            return self.queue.pop(0)

    # -- minimal runtime model
    def close(self):
        self.closed = True

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
        return 9000

    def method_line_table(self, type_id, method_id):
        return {"lines": [{"index": 0, "line": 1}]}

    def method_var_table(self, type_id, method_id):
        raise JdwpError("ABSENT_INFORMATION")

    def set_breakpoint(self, class_id, method_id, index, suspend_policy=2):
        return self._rid()

    def set_event(self, kind, suspend, mods):
        return self._rid()

    def mod_class_only(self, type_id):
        return ("class_only", type_id)

    def mod_class_match(self, pattern):
        return ("class_match", pattern)

    def mod_thread_only(self, thread):
        return ("thread_only", thread)

    def clear_event(self, kind, request_id):
        self.cleared.append((kind, request_id))

    def thread_resume(self, thread):
        self.resumed.append(thread)

    def vm_resume(self):
        pass

    def thread_frames(self, thread, count=32):
        return []

    # -- buffer export surface
    def object_reftype(self, obj):
        return (91, self.obj_types.get(obj, 1000))

    def array_length(self, arr):
        return len(self.arrays.get(arr, b""))

    def array_get_values(self, arr, start, n):
        if self.get_values_delay:
            time.sleep(self.get_values_delay)
        data = self.arrays.get(arr, b"")
        return {"items": list(data[start:start + n])}


def make_session(client, project=None) -> DebugSession:
    s = DebugSession.__new__(DebugSession)
    s.project = project
    s.adb = s.pkg = s.pid = s.port = None
    s.client = client
    s.bp_registry = {}
    s._sig_cache = {}
    return s


def cipher_client() -> FakeClient:
    """Fake VM with javax.crypto.Cipher.doFinal()[B loadable."""
    c = FakeClient()
    c.classes[CIPHER] = [{"type_id": 1000}]
    c.sigs[1000] = CIPHER
    c.methods[1000] = [{"name": "doFinal", "sig": "()[B", "id": 1100,
                        "mod_bits": 0x0001}]
    return c


def make_project(tmp: str) -> Project:
    proj = Project.create(tmp)
    with proj.db() as db:
        db.set_meta("sha256", "ab" * 32)
    return proj


def make_server(tmp: str, client: FakeClient) -> RpcServer:
    make_project(tmp)
    srv = RpcServer(tmp)
    ctx = srv._get_ctx()
    ctx._session = make_session(client, project=ctx.project)
    return srv


def rpc(srv: RpcServer, method: str, params: dict | None = None,
        rid: int = 1) -> dict:
    line = {"id": rid, "method": method, "params": params or {}}
    out = srv.handle_line(json.dumps(line))
    assert len(out) == 1, out
    return out[0]


def start_job(srv: RpcServer, command: str, params: dict, **kw) -> str:
    r = rpc(srv, "job_start", {"command": command, "params": params, **kw})
    assert "result" in r, r
    return r["result"]["operation_id"]


def wait_terminal(srv: RpcServer, op_id: str, timeout: float = 6.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = rpc(srv, "job_status", {"operation_id": op_id})
        assert "result" in r, r
        if r["result"]["terminal"]:
            return r["result"]
        time.sleep(0.02)
    raise AssertionError(f"job {op_id} did not terminate")


def owned_rids(session: DebugSession) -> set[int]:
    return {rid for rid, m in session.bp_registry.items()
            if m.get("owner") == "crypto"}


def wait_sub(session: DebugSession, timeout: float = 3.0) -> None:
    """Wait until the watch loop holds its dispatcher subscription:
    events pushed earlier would route nowhere and be stashed."""
    deadline = time.time() + timeout
    while not session.events._subs and time.time() < deadline:
        time.sleep(0.02)
    assert session.events._subs, "watch subscription never appeared"


# ------------------------------------------------------- control latency
class ControlLatencyTests(unittest.TestCase):
    """Acceptance: with the event source waiting indefinitely, status and
    cancel requests are answered within CONTROL_BOUND_S."""

    def test_status_and_cancel_fast_with_blocked_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = cipher_client()
            srv = make_server(tmp, client)
            op = start_job(srv, "hook_crypto",
                           {"duration": 60.0, "hooks": [HOOK]})
            # worker is blocked in next_routed; no events ever arrive
            t0 = time.monotonic()
            r = rpc(srv, "job_status", {"operation_id": op})
            status_s = time.monotonic() - t0
            self.assertIn(r["result"]["state"],
                          ("queued", "running", "cancelling"))
            t0 = time.monotonic()
            r = rpc(srv, "job_cancel", {"operation_id": op})
            cancel_s = time.monotonic() - t0
            self.assertEqual(r["result"]["state"], "cancelling")
            self.assertLess(status_s, CONTROL_BOUND_S)
            self.assertLess(cancel_s, CONTROL_BOUND_S)
            st = wait_terminal(srv, op)
            self.assertEqual(st["state"], "cancelled")
            self.assertEqual(st["outcome"]["reason"], "cancellation")
            srv.close()


# ------------------------------------------------- cancel during capture
class CancelCaptureTests(unittest.TestCase):
    def test_cancel_mid_capture_cleans_only_owned_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = cipher_client()
            srv = make_server(tmp, client)
            session = srv._ctx._session
            op = start_job(srv, "hook_crypto",
                           {"duration": 60.0, "hooks": [HOOK]})
            # wait for install, feed a couple of hits, then cancel
            deadline = time.time() + 3.0
            while not owned_rids(session) and time.time() < deadline:
                time.sleep(0.02)
            rids = owned_rids(session)
            self.assertTrue(rids)
            wait_sub(session)
            mid = 1100
            for i in range(2):
                client.push({"suspend_policy": SP_EVENT_THREAD,
                             "events": [{"request_id": next(iter(rids)),
                                         "kind_id": EVK_BREAKPOINT,
                                         "thread": 100 + i,
                                         "location": {"class": 1000,
                                                      "method": mid,
                                                      "index": 0}}]})
            time.sleep(0.2)
            rpc(srv, "job_cancel", {"operation_id": op})
            st = wait_terminal(srv, op)
            self.assertEqual(st["state"], "cancelled")
            self.assertEqual(st["outcome"]["reason"], "cancellation")
            self.assertIs(st["outcome"]["incomplete"], True)
            # teardown cleared exactly the job's own crypto requests
            self.assertEqual({rid for _, rid in client.cleared}, rids)
            # captured records are still readable after cancellation
            r = rpc(srv, "job_read", {"operation_id": op})
            self.assertGreaterEqual(r["result"]["received"], 1)
            srv.close()


# --------------------------------------------- cancel during output write
class CancelExportTests(unittest.TestCase):
    def test_cancel_during_export_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = FakeClient()
            client.obj_types[500] = 1000
            client.sigs[1000] = "[B"
            client.arrays[500] = bytes(1 << 20)  # 1 MiB
            client.get_values_delay = 0.1        # slow output pump
            srv = make_server(tmp, client)
            op = start_job(srv, "export_buffer",
                           {"obj": 500, "epoch": 0, "chunk_size": 4096})
            time.sleep(0.25)  # mid-pump
            rpc(srv, "job_cancel", {"operation_id": op})
            st = wait_terminal(srv, op)
            self.assertEqual(st["state"], "cancelled")
            self.assertEqual(st["outcome"]["reason"], "cancellation")
            self.assertIs(st["outcome"]["incomplete"], True)
            self.assertEqual(st["error"]["code"], "E_EXPORT_INCOMPLETE")
            # the partial temp file was removed; nothing was published
            leftovers = list(Path(tmp).rglob("*.part"))
            self.assertEqual(leftovers, [])
            srv.close()


# --------------------------------------------------- bounded event flood
class BoundedBufferTests(unittest.TestCase):
    def _flood(self, srv, client, n, **job_kw):
        op = start_job(srv, "hook_crypto",
                       {"duration": 60.0, "hooks": [HOOK], "max_events": n},
                       **job_kw)
        session = srv._ctx._session
        deadline = time.time() + 3.0
        while not owned_rids(session) and time.time() < deadline:
            time.sleep(0.02)
        rid = next(iter(owned_rids(session)))
        wait_sub(session)
        for i in range(n):
            client.push({"suspend_policy": SP_EVENT_THREAD,
                         "events": [{"request_id": rid,
                                     "kind_id": EVK_BREAKPOINT,
                                     "thread": 100 + i,
                                     "location": {"class": 1000,
                                                  "method": 1100,
                                                  "index": 0}}]})
        return op, wait_terminal(srv, op)

    def test_flood_stays_within_record_bound_with_exact_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = cipher_client()
            srv = make_server(tmp, client)
            st_op, st = self._flood(srv, client, 20, max_records=10)
            self.assertEqual(st["state"], "completed")
            self.assertEqual(st["outcome"]["reason"], "event_budget")
            self.assertIs(st["outcome"]["incomplete"], True)
            p = st["progress"]
            self.assertEqual(p["received"], 20)
            self.assertEqual(p["retained"], 10)      # bounded memory
            self.assertEqual(p["expired"], 10)
            self.assertEqual(p["dropped"], 0)
            # the result summary never carries the unbounded record list
            self.assertNotIn("records", st["result"])
            self.assertEqual(st["result"]["record_count"], 20)
            srv.close()

    def test_byte_bound_counts_dropped_exactly(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = cipher_client()
            srv = make_server(tmp, client)
            op, st = self._flood(srv, client, 5, max_record_bytes=200)
            p = st["progress"]
            self.assertEqual(p["received"], 5)
            self.assertEqual(p["received"],
                             p["retained"] + p["dropped"] + p["expired"])
            self.assertGreater(p["dropped"], 0)
            self.assertLessEqual(p["buffer_bytes"], 200)
            r = rpc(srv, "job_read", {"operation_id": op})
            self.assertIs(r["result"]["truncated"], True)
            srv.close()


# ------------------------------------------------------------ read cursors
class CursorTests(unittest.TestCase):
    def test_pages_have_no_duplicates_or_omissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = cipher_client()
            srv = make_server(tmp, client)
            op, st = BoundedBufferTests._flood(self, srv, client, 20,
                                               max_records=100)
            seen, cursor = [], None
            for _ in range(10):  # generous page-loop bound
                r = rpc(srv, "job_read",
                        {"operation_id": op, "cursor": cursor, "limit": 6})
                res = r["result"]
                seen.extend(rec["thread"] for rec in res["records"])
                cursor = res["cursor"]
                if cursor is None:
                    break
            self.assertIsNone(cursor)
            self.assertEqual(seen, [100 + i for i in range(20)])
            srv.close()

    def test_expired_and_malformed_cursors_are_explicit_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = cipher_client()
            srv = make_server(tmp, client)
            op, st = BoundedBufferTests._flood(self, srv, client, 20,
                                               max_records=10)
            r = rpc(srv, "job_read", {"operation_id": op, "cursor": "r0"})
            self.assertEqual(r["error"]["code"], "E_CURSOR_EXPIRED")
            self.assertEqual(r["error"]["context"]["base"], "r10")
            r = rpc(srv, "job_read",
                    {"operation_id": op, "cursor": "nonsense"})
            self.assertEqual(r["error"]["code"], "E_INVALID_PARAMS")
            srv.close()

    def test_running_job_keeps_continuation_cursor_when_caught_up(self):
        # poll scenario: null mid-run means "oldest retained record" on the
        # next call, so a caught-up running job must return a continuation
        # cursor; null is reserved for a terminal, exhausted stream
        job = Job("hook_crypto", {"duration": 60.0}, 100, 1 << 20)
        job.mark_running()
        # empty running job: a checkpoint cursor, not null
        r = job.read(None, 100)
        self.assertEqual(r["records"], [])
        self.assertEqual(r["cursor"], "r0")
        job.emit({"n": 1})
        r = job.read(None, 100)
        self.assertEqual([x["n"] for x in r["records"]], [1])
        self.assertEqual(r["cursor"], "r1")
        job.emit({"n": 2})
        r = job.read(r["cursor"], 100)
        self.assertEqual([x["n"] for x in r["records"]], [2])  # no dup of 1
        self.assertEqual(r["cursor"], "r2")
        # caught up again, still running: continuation cursor
        r = job.read(r["cursor"], 100)
        self.assertEqual(r["records"], [])
        self.assertEqual(r["cursor"], "r2")
        # terminal + caught up: null — the stream is exhausted
        job.set_terminal("completed", "deadline", False)
        r = job.read("r2", 100)
        self.assertIsNone(r["cursor"])


# -------------------------------------------------------------- concurrency
class ConcurrencyTests(unittest.TestCase):
    def test_second_job_and_session_commands_conflict_early(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = cipher_client()
            srv = make_server(tmp, client)
            op = start_job(srv, "hook_crypto",
                           {"duration": 60.0, "hooks": [HOOK]})
            # a second job fails early, naming the running operation
            r = rpc(srv, "job_start",
                    {"command": "coverage",
                     "params": {"packages": ["com.fake"]}}, rid=2)
            self.assertEqual(r["error"]["code"], "E_JOB_CONFLICT")
            self.assertEqual(r["error"]["context"]["operation_id"], op)
            self.assertIs(r["error"]["retryable"], True)
            # session-owning commands are rejected while the job runs
            for method in ("events", "bp_list", "connect"):
                r = rpc(srv, method, {} if method != "bp_list" else {},
                        rid=3)
                self.assertEqual(r["error"]["code"], "E_JOB_CONFLICT",
                                 method)
            # project-only queries and job control stay available
            r = rpc(srv, "classes", {}, rid=4)
            self.assertIn("result", r)
            r = rpc(srv, "job_list", {}, rid=5)
            self.assertEqual(r["result"]["total"], 1)
            r = rpc(srv, "job_cancel", {"operation_id": op}, rid=6)
            self.assertIn("result", r)
            wait_terminal(srv, op)
            # after the job ends the session is usable again
            r = rpc(srv, "bp_list", {}, rid=7)
            self.assertIn("result", r)
            srv.close()

    def test_job_start_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            srv = make_server(tmp, cipher_client())
            r = rpc(srv, "job_start", {"command": "classes"})
            self.assertEqual(r["error"]["code"], "E_INVALID_PARAMS")
            r = rpc(srv, "job_start",
                    {"command": "coverage", "params": {}})
            self.assertEqual(r["error"]["code"], "E_INVALID_PARAMS")
            self.assertIn("packages", r["error"]["message"])
            r = rpc(srv, "job_status", {"operation_id": "op-nope"})
            self.assertEqual(r["error"]["code"], "E_JOB_NOT_FOUND")
            srv.close()


# ------------------------------------------------ idempotence + retention
class RegistryTests(unittest.TestCase):
    def _fast(self, ctx, job):
        return {"reason": "duration", "records": []}

    def _wait(self, reg, op, timeout=3.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            st = reg.get(op).status()
            if st["terminal"]:
                return st
            time.sleep(0.01)
        raise AssertionError("job did not terminate")

    def test_repeated_cancel_and_status_are_idempotent(self):
        reg = JobRegistry()
        op = reg.start(None, "hook_crypto", {}, self._fast)["operation_id"]
        st = self._wait(reg, op)
        again = reg.cancel(op)
        third = reg.cancel(op)
        self.assertEqual(again["state"], st["state"])
        self.assertEqual(third["ended_at"], again["ended_at"])
        self.assertEqual(reg.get(op).status()["outcome"], st["outcome"])

    def test_conflict_error_names_running_job(self):
        reg = JobRegistry()
        gate = threading.Event()

        def blocked(ctx, job):
            gate.wait(5.0)
            return {"reason": "duration"}

        op = reg.start(None, "hook_crypto", {}, blocked)["operation_id"]
        try:
            with self.assertRaises(JobConflictError) as cm:
                reg.start(None, "coverage", {}, self._fast)
            self.assertEqual(cm.exception.context["operation_id"], op)
        finally:
            gate.set()
        self._wait(reg, op)

    def test_bounded_completed_retention_evicts_oldest(self):
        reg = JobRegistry(max_completed=2)
        ids = []
        for _ in range(3):
            op = reg.start(None, "hook_crypto", {},
                           self._fast)["operation_id"]
            self._wait(reg, op)
            ids.append(op)
        with self.assertRaises(JobNotFoundError):
            reg.get(ids[0])
        self.assertTrue(reg.get(ids[1]).terminal)
        self.assertTrue(reg.get(ids[2]).terminal)
        listing = reg.list(50, 0)
        self.assertEqual(listing["total"], 2)

    def test_shutdown_stamps_deterministic_terminal_record(self):
        reg = JobRegistry()

        def stuck(ctx, job):
            threading.Event().wait(30.0)  # never observes cancel
            return {"reason": "duration"}

        op = reg.start(None, "hook_crypto", {}, stuck)["operation_id"]
        reg.shutdown(timeout_s=0.2)
        st = reg.get(op).status()
        self.assertEqual(st["state"], "failed")
        self.assertEqual(st["outcome"]["reason"], "disconnect")
        self.assertIs(st["outcome"]["incomplete"], True)

    def test_disconnect_maps_to_terminal_reason(self):
        reg = JobRegistry()

        def dying(ctx, job):
            raise JdwpConnError("socket closed")

        op = reg.start(None, "hook_crypto", {}, dying)["operation_id"]
        st = self._wait(reg, op)
        self.assertEqual(st["state"], "failed")
        self.assertEqual(st["outcome"]["reason"], "disconnect")
        self.assertEqual(st["error"]["code"], "E_JDWP_CONN")


# ------------------------------------------------- coverage kind + close
class CoverageJobTests(unittest.TestCase):
    def test_coverage_job_cancel_and_ctx_close_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = FakeClient()
            srv = make_server(tmp, client)
            session = srv._ctx._session
            op = start_job(srv, "coverage",
                           {"packages": ["com.fake"], "seconds": 60})
            deadline = time.time() + 3.0
            while not session.bp_registry and time.time() < deadline:
                time.sleep(0.02)
            self.assertTrue(session.bp_registry)
            # EOF/server-exit path: close() cancels the job and waits a
            # bounded window — the terminal record is deterministic
            ctx = srv._ctx
            srv.close()
            st = ctx.jobs.get(op).status()
            self.assertTrue(st["terminal"])
            self.assertEqual(st["state"], "cancelled")
            self.assertEqual(st["outcome"]["reason"], "cancellation")
            # the coverage request was cleared with its own kind
            self.assertEqual({k for k, _ in client.cleared},
                             {EVK_METHOD_ENTRY})
            self.assertTrue(client.closed)


if __name__ == "__main__":
    unittest.main()

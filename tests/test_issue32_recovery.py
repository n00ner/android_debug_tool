"""Offline tests for issue #32 — explicit, safe connection recovery.

Deterministic fault injection: fake JdwpClient transports raise
JdwpConnError with a fault phase (pre-dispatch / transmit / post-send),
and a fake peer applies an invocation then drops the reply. No device,
no real sockets (except the request() phase-tagging tests, which use a
fake socket object against the real JdwpClient.request)."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from apkdbg import commands
from apkdbg.debug.hooks import crypto
from apkdbg.debug.session import DebugSession
from apkdbg.device.jdwp import (
    CS_VM, EVK_CLASS_PREPARE, SP_ALL, TAG_STRING, VM_CREATE_STRING,
    VM_VERSION, JdwpClient, JdwpConnError, JdwpError,
)
from apkdbg.errors import (
    AttachUnavailableError, OutcomeUnknownError, ProcessDiedError,
    SessionError, StaleHandleError,
)

HOOK = "Cipher.doFinal()"
CLS_SIG = "Ljavax/crypto/Cipher;"
A_SIG = "Lcom/foo/A;"
# symbolic source-breakpoint definition (what translate.resolve returns)
RES = {"sig": A_SIG, "dalvik_line": 1, "java_line": 42, "class": "com.foo.A",
       "methods": [{"name": "m", "sig": "()V"}], "smali": 10}
SPEC = "com.foo.A.m:42"


# --------------------------------------------------------------------- fakes
class FakeAdb:
    """Records every call; pid answer is configurable."""

    def __init__(self, pid=1234):
        self.pid = pid
        self.log = []

    def pidof(self, pkg):
        self.log.append(("pidof", pkg))
        return self.pid

    def remove_forward(self, port):
        self.log.append(("remove_forward", port))

    def forward_jdwp(self, pid, port=None):
        self.log.append(("forward_jdwp", pid, port))
        return port or 7777

    def reconnect(self):
        self.log.append(("reconnect",))

    def kill_server(self):
        self.log.append(("kill_server",))

    def wait_for_device(self):
        self.log.append(("wait_for_device",))

    def calls(self, name):
        return [c for c in self.log if c[0] == name]


class Conn:
    """Fake connection handed out by the patched session.JdwpClient during
    _attach; each instance is one connection epoch. `made` lets tests tell
    epochs apart even when numeric ids are reused."""

    made = []
    fail_handshake = False

    def __init__(self, host, port):
        self.host, self.port = host, port
        self.op_calls = 0
        self.read_calls = 0
        self.state_dispatched = 0
        self.handshake_info = {"vm_name": "fake",
                               "jdwp_major": 1, "jdwp_minor": 7}
        Conn.made.append(self)

    def connect(self):
        if Conn.fail_handshake:
            raise JdwpConnError("handshake refused")

    def close(self):
        pass

    def op(self):
        self.op_calls += 1
        return "ok"

    def read_op(self, **kw):
        self.read_calls += 1
        return "read"


class FaultClient:
    """Connection that raises a phased JdwpConnError on first use."""

    def __init__(self, phase):
        self.phase = phase
        self.calls = 0
        self.state_dispatched = 0

    def _fault(self):
        self.calls += 1
        if self.phase:
            phase, self.phase = self.phase, None
            raise JdwpConnError(f"injected {phase} fault", phase=phase)

    def op(self):
        self._fault()
        return "ok"

    def read_op(self, **kw):
        self._fault()
        return "read"

    def thread_frames(self, thread, count=32):
        self._fault()
        return []

    def close(self):
        pass


def make_session(client, adb=None, pid=1234):
    s = DebugSession.__new__(DebugSession)
    s.project = None
    s.adb = adb or FakeAdb(pid)
    s.pkg, s.pid, s.port = "com.fake", pid, 7777
    s.client = client
    s.bp_registry = {}
    s._sig_cache = {}
    return s


class _FakeProject:
    """Just enough for _nearby_lines (empty adjacent-line lookup)."""

    def db(self):
        class Ctx:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

            def query(self, *a):
                return []
        return Ctx()


def reset_conn(fail=False):
    Conn.made = []
    Conn.fail_handshake = fail
    return patch("apkdbg.debug.session.JdwpClient", Conn)


# ------------------------------------------------- request() phase tagging
class FakeSocket:
    def __init__(self, fail_send=False):
        self.fail_send = fail_send
        self.sent = b""

    def sendall(self, data):
        if self.fail_send:
            raise OSError("broken pipe")
        self.sent += data


def raw_client(sock):
    c = JdwpClient.__new__(JdwpClient)
    JdwpClient.__init__(c, "127.0.0.1", 0)  # fields only; no connect
    c.sock = sock
    return c


class RequestPhaseTests(unittest.TestCase):
    """JdwpClient.request tags where the fault struck; the recovery
    policy branches on it."""

    def test_dead_before_send_is_pre_dispatch(self):
        c = raw_client(FakeSocket())
        c._dead = JdwpConnError("peer closed")
        with self.assertRaises(JdwpConnError) as cm:
            c.request(CS_VM, VM_VERSION)
        self.assertEqual(cm.exception.context["phase"], "pre-dispatch")
        self.assertEqual(c.sock.sent, b"")  # provably nothing transmitted

    def test_send_failure_is_transmit(self):
        c = raw_client(FakeSocket(fail_send=True))
        with self.assertRaises(JdwpConnError) as cm:
            c.request(CS_VM, VM_VERSION)
        self.assertEqual(cm.exception.context["phase"], "transmit")

    def test_reply_timeout_is_post_send(self):
        c = raw_client(FakeSocket())
        with self.assertRaises(JdwpConnError) as cm:
            c.request(CS_VM, VM_VERSION, timeout=0.05)
        self.assertEqual(cm.exception.context["phase"], "post-send")
        self.assertTrue(c.sock.sent)  # the command fully left the host

    def test_state_command_dispatch_is_tracked(self):
        # a fully transmitted state-changing command moves the counter
        # even when its reply is lost; read commands never do
        c = raw_client(FakeSocket())
        with self.assertRaises(JdwpConnError):
            c.request(CS_VM, VM_CREATE_STRING, timeout=0.05)
        self.assertEqual(c.state_dispatched, 1)
        c = raw_client(FakeSocket())
        with self.assertRaises(JdwpConnError):
            c.request(CS_VM, VM_VERSION, timeout=0.05)
        self.assertEqual(c.state_dispatched, 0)


# ---------------------------------------------------- outcome_unknown path
class InvokeClient:
    """Fake peer: applies the invocation, then drops the reply."""

    def __init__(self):
        self.invocations = 0
        self.drop_reply = True
        self.state_dispatched = 0

    def object_reftype(self, obj):
        return (1, 1000)

    def resolve_instance_method(self, type_id, name, sig):
        return (1000, 1500)

    def create_string(self, s):
        self.state_dispatched += 1
        return 42

    def invoke_object_method(self, obj, thread, cls, mid, args):
        self.invocations += 1  # the VM-side effect happens...
        self.state_dispatched += 1
        if self.drop_reply:
            self.drop_reply = False
            raise JdwpConnError("reply lost", phase="post-send")  # ...then lost
        return {"value": {"tag": 86, "v": None}, "exception": 0}

    def string_value(self, oid):
        return "x"

    def close(self):
        pass


class LateFaultInvokeClient(InvokeClient):
    """The invoke mutation succeeds and returns a String id; decoding that
    result hits a dead socket. The failing packet (string_value) is
    pre-dispatch, but the mutation packet already left the host."""

    def __init__(self):
        super().__init__()
        self.drop_reply = False
        self.fault = True

    def invoke_object_method(self, obj, thread, cls, mid, args):
        super().invoke_object_method(obj, thread, cls, mid, args)
        return {"value": {"tag": TAG_STRING, "v": 42}, "exception": 0}

    def string_value(self, oid):
        if self.fault:
            self.fault = False
            raise JdwpConnError("dead socket", phase="pre-dispatch")
        return "x"


class OutcomeUnknownTests(unittest.TestCase):
    def test_applied_invoke_with_dropped_reply_is_never_replayed(self):
        c = InvokeClient()
        s = make_session(c)
        epoch0 = s.events.epoch
        with reset_conn():
            with self.assertRaises(OutcomeUnknownError) as cm:
                s.invoke(thread=1, obj=2, method="doFinal", sig="()[B")
        self.assertEqual(c.invocations, 1)  # executed at most once
        d = cm.exception.to_dict()
        self.assertEqual(d["code"], "E_OUTCOME_UNKNOWN")
        self.assertEqual(d["outcome"], "unknown")     # not "failed"
        self.assertFalse(d["retryable"])
        self.assertIn("UNKNOWN", d["message"])
        ctx = d["context"]
        self.assertEqual(ctx["op"], "invoke")
        self.assertEqual(ctx["phase"], "post-send")
        self.assertEqual(ctx["epoch"], epoch0)
        self.assertEqual(ctx["epoch_new"], epoch0 + 1)
        self.assertTrue(ctx["recovery"].startswith("reconnected"))
        self.assertIsInstance(s.client, Conn)         # recovery happened
        self.assertEqual(Conn.made[-1].op_calls, 0)   # no replay

    def test_resume_is_state_changing(self):
        s = make_session(FaultClient("transmit"))
        with reset_conn():
            with self.assertRaises(OutcomeUnknownError) as cm:
                s._op(lambda c: c.op(), _class="state", _name="resume(vm)")
        self.assertEqual(cm.exception.context["phase"], "transmit")
        self.assertEqual(Conn.made[-1].op_calls, 0)

    def test_applied_invoke_late_pre_dispatch_fault_is_never_replayed(self):
        # the reviewer's scenario: invoke_object_method executed and
        # returned a String id, then string_value hits a dead socket with
        # phase=pre-dispatch — the failing packet's phase must not replay
        # the already-dispatched mutation
        c = LateFaultInvokeClient()
        s = make_session(c)
        epoch0 = s.events.epoch
        with reset_conn():
            with self.assertRaises(OutcomeUnknownError) as cm:
                s.invoke(thread=1, obj=2, method="doFinal",
                         sig="()Ljava/lang/String;")
        self.assertEqual(c.invocations, 1)  # executed exactly once
        ctx = cm.exception.to_dict()["context"]
        self.assertEqual(ctx["op"], "invoke")
        self.assertEqual(ctx["phase"], "pre-dispatch")
        self.assertEqual(ctx["epoch"], epoch0)
        self.assertEqual(ctx["epoch_new"], epoch0 + 1)
        self.assertIsInstance(s.client, Conn)  # reconnected, no replay


# ------------------------------------------------------------- fault matrix
class FaultPhaseMatrixTests(unittest.TestCase):
    """Documented retry/outcome behavior per fault phase x op class."""

    def _run(self, phase, **op_kw):
        s = make_session(FaultClient(phase))
        with reset_conn():
            return s, s._op(lambda c: c.op(), **op_kw)

    def test_pre_dispatch_state_op_is_safe_to_replay(self):
        # dead socket detected before send: the command provably never
        # left the host, so even a mutation is replayed once
        s, out = self._run("pre-dispatch", _class="state", _name="mut")
        self.assertEqual(out, "ok")
        self.assertEqual(Conn.made[-1].op_calls, 1)

    def test_pre_dispatch_state_op_with_handles_fails_stale(self):
        # provably undispatched, but the op's numeric thread/object ids
        # died with the old epoch — re-acquire + re-issue, never a replay
        s = make_session(FaultClient("pre-dispatch"))
        with reset_conn():
            with self.assertRaises(StaleHandleError) as cm:
                s._op(lambda c: c.op(), _class="state",
                      _name="resume(thread)", _handles=True)
        self.assertEqual(cm.exception.to_dict()["code"], "E_STALE_HANDLE")
        self.assertEqual(Conn.made[-1].op_calls, 0)

    def test_dispatched_reads_do_not_block_replay(self):
        # only STATE-changing packets arm the tracker: a read packet
        # dispatched earlier in the same op must not force UNKNOWN when
        # the mutation itself provably never left the host
        class ReadThenDead:
            def __init__(self):
                self.state_dispatched = 0
                self.dead = False

            def read_op(self):
                return "read"

            def op(self):
                if not self.dead:
                    self.dead = True
                    raise JdwpConnError("dead socket", phase="pre-dispatch")
                return "ok"

            def close(self):
                pass

        def op(c):
            c.read_op()  # dispatched read; state_dispatched stays put
            return c.op()

        s = make_session(ReadThenDead())
        with reset_conn():
            out = s._op(op, _class="state", _name="mut")
        self.assertEqual(out, "ok")
        self.assertEqual(Conn.made[-1].op_calls, 1)

    def test_transmit_state_op_is_outcome_unknown(self):
        s = make_session(FaultClient("transmit"))
        with reset_conn():
            with self.assertRaises(OutcomeUnknownError):
                s._op(lambda c: c.op(), _class="state", _name="mut")
        self.assertEqual(Conn.made[-1].op_calls, 0)

    def test_post_send_state_op_is_outcome_unknown(self):
        s = make_session(FaultClient("post-send"))
        with reset_conn():
            with self.assertRaises(OutcomeUnknownError):
                s._op(lambda c: c.op(), _class="state", _name="mut")
        self.assertEqual(Conn.made[-1].op_calls, 0)

    def test_symbolic_read_retries_after_reconnect(self):
        s, out = self._run("post-send", _class="read", _name="wait_events",
                           _reresolve=True)
        self.assertEqual(out, "ok")
        self.assertEqual(Conn.made[-1].op_calls, 1)

    def test_idempotent_op_retries_after_reconnect(self):
        s, out = self._run("post-send", _class="idempotent",
                           _name="set_breakpoint")
        self.assertEqual(out, "ok")
        self.assertEqual(Conn.made[-1].op_calls, 1)

    def test_handle_based_read_fails_stale_instead_of_replaying(self):
        # the new connection may reuse the numeric thread id — the read
        # must NOT be replayed against it
        s = make_session(FaultClient("post-send"))
        with reset_conn():
            with self.assertRaises(StaleHandleError) as cm:
                s._op(lambda c: c.read_op(thread=11),
                      _class="read", _name="read_var")
        d = cm.exception.to_dict()
        self.assertEqual(d["code"], "E_STALE_HANDLE")
        self.assertIn("per-connection", d["message"])
        self.assertIn("re-acquire", d["hint"])
        self.assertEqual(d["context"]["op"], "read_var")
        self.assertEqual(Conn.made[-1].read_calls, 0)  # never replayed


# -------------------------------------------- epoch handle/cache invalidation
class HookClient:
    """Minimal fake VM for crypto hooks + a source breakpoint; the request
    id counter restarts at 1 per instance (numeric id reuse across
    epochs)."""

    def __init__(self, crypto_loaded=True, a_loaded=True, method_found=True):
        self.next_rid = 1
        self.classes = {}
        self.methods = {}
        self.sigs = {}
        self.cleared = []
        self.state_dispatched = 0
        if crypto_loaded:
            self.classes[CLS_SIG] = [{"type_id": 1000}]
            self.sigs[1000] = CLS_SIG
            self.methods[1000] = (
                [{"name": "doFinal", "sig": "()[B", "id": 1500}]
                if method_found else [])
        if a_loaded:
            self.classes[A_SIG] = [{"type_id": 2000}]
            self.sigs[2000] = A_SIG
            self.methods[2000] = [{"name": "m", "sig": "()V", "id": 2500}]

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
        return 0

    def method_line_table(self, type_id, method_id):
        return {"lines": [{"index": 4, "line": 1}]}

    def method_var_table(self, type_id, method_id):
        raise JdwpError("ABSENT_INFORMATION")

    def set_breakpoint(self, class_id, method_id, index, suspend_policy=2):
        return self._rid()

    def set_event(self, kind, suspend, mods):
        return self._rid()

    def mod_class_only(self, type_id):
        return (4, b"")

    def mod_class_match(self, pattern):
        return (5, pattern.encode())

    def clear_event(self, kind, request_id):
        self.cleared.append((kind, request_id))


class EpochInvalidationTests(unittest.TestCase):
    def test_reconnect_invalidates_handles_and_caches(self):
        c = HookClient()
        s = make_session(c)
        crypto.install(s, names=[HOOK])
        s._sig_cache[1000] = CLS_SIG
        s.events.stash({"suspend_policy": 1, "events": [{"request_id": 1}]})
        epoch0 = s.events.epoch
        with reset_conn():
            s._attach()
        self.assertEqual(s.events.epoch, epoch0 + 1)
        self.assertEqual(s.bp_registry, {})          # live handles dead
        self.assertEqual(s._sig_cache, {})           # sig cache dropped
        self.assertIsNone(s.events.drain())          # stash dropped
        self.assertIsNone(s.events.lookup(1))        # stale id lookup fails
        # ...but symbolic definitions survive for restore
        self.assertEqual(len(s.events.symbolic_hooks()), 1)
        # numeric id reuse by the new connection does not resurrect the
        # old handle: a fresh install gets rid 1 stamped with the NEW epoch
        s.client = HookClient()
        crypto.install(s, names=[HOOK])
        self.assertEqual(set(s.bp_registry), {1})
        self.assertEqual(s.bp_registry[1]["_epoch"], epoch0 + 1)
        # clearing a stale-stamped id never touches the new connection
        stale = {"_epoch": epoch0, "kind": 2}
        self.assertFalse(s.events.is_live(stale))

    def test_stale_read_after_reconnect_is_actionable(self):
        s = make_session(FaultClient("transmit"))
        with reset_conn():
            with self.assertRaises(StaleHandleError) as cm:
                s.read_var(thread=11, slot=0)
        self.assertIn("read_var", str(cm.exception))


# ---------------------------------------------------------- symbolic restore
class SymbolicRestoreTests(unittest.TestCase):
    def _installed(self, defer=False):
        c = HookClient()
        s = make_session(c)
        crypto.install(s, names=[HOOK], defer=defer)
        s._place(RES, SPEC, suspend_all=True)   # source bp + symbolic def
        return s, c

    def _reconnect(self, s, client):
        with reset_conn():
            s._attach()
        s.client = client

    def test_restore_reports_new_request_ids(self):
        s, c = self._installed()
        old_rids = set(s.bp_registry)               # {1, 2}
        old_epoch = s.events.epoch
        self._reconnect(s, HookClient())
        rep = s.restore_requests()
        self.assertEqual(rep["epoch"], s.events.epoch)
        self.assertEqual(rep["pending"], [])
        self.assertEqual(rep["failed"], [])
        hook = next(i for i in rep["installed"] if i["kind"] == "hook")
        src = next(i for i in rep["installed"] if i["kind"] == "source")
        # ids are numerically identical (counter restarted) but are NEW
        # current-epoch registrations, not revived old ids
        self.assertEqual(hook["hook"], HOOK)
        self.assertEqual(src["spec"], SPEC)
        self.assertNotIn("already_live", hook)
        self.assertNotIn("already_live", src)
        new_rids = hook["request_ids"] + src["request_ids"]
        self.assertEqual(sorted(new_rids), sorted(old_rids))
        for rid in new_rids:
            self.assertEqual(s.bp_registry[rid]["_epoch"], old_epoch + 1)
        self.assertIn("never revived", rep["note"])

    def test_restore_reports_pending_and_failed(self):
        s, c = self._installed()
        # new epoch: crypto class not loaded (pending, deferred),
        # source class loaded but method gone (failed)
        self._reconnect(s, HookClient(crypto_loaded=False,
                                      method_found=False))
        s.project = _FakeProject()  # for the adjacent-lines hint
        s.client.methods[2000] = []                 # "m" no longer there
        rep = s.restore_requests(defer=True)
        self.assertEqual(rep["installed"], [])
        kinds = {(p["kind"]) for p in rep["pending"]}
        self.assertIn("hook", kinds)
        self.assertTrue(rep["deferred"])            # CLASS_PREPARE watch
        self.assertEqual(rep["deferred"][0]["hook"], HOOK)
        failed = rep["failed"]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["kind"], "source")
        self.assertIn("no executable bytecode index", failed[0]["reason"])
        # nothing pending/failed got registered under any id
        self.assertEqual(
            [m for m in s.bp_registry.values()
             if m.get("kind") != EVK_CLASS_PREPARE], [])

    def test_restore_source_pending_when_class_unloaded(self):
        s, c = self._installed()
        self._reconnect(s, HookClient(a_loaded=False))
        rep = s.restore_requests(defer=False)
        self.assertEqual(len(rep["installed"]), 1)  # only the crypto hook
        self.assertEqual(len(rep["pending"]), 1)
        self.assertEqual(rep["pending"][0]["kind"], "source")
        self.assertIn("class not loaded", rep["pending"][0]["reason"])
        self.assertEqual(rep["deferred"], [])       # defer only arms hooks

    def test_restore_is_idempotent_within_an_epoch(self):
        s, c = self._installed()
        self._reconnect(s, HookClient())
        first = s.restore_requests()
        second = s.restore_requests()
        src1 = next(i for i in first["installed"] if i["kind"] == "source")
        src2 = next(i for i in second["installed"] if i["kind"] == "source")
        self.assertTrue(src2.get("already_live"))
        self.assertEqual(src1["request_ids"], src2["request_ids"])
        # crypto install dedupes per epoch: no duplicate requests
        rids = sorted(s.bp_registry)
        self.assertEqual(len(rids), len(set(rids)))

    def test_cleared_definition_is_not_resurrected(self):
        s, c = self._installed()
        src_rid = next(rid for rid, m in s.bp_registry.items()
                       if m.get("entry") == "source")
        s.clear_request(src_rid)   # explicit user clear drops the def
        self._reconnect(s, HookClient())
        rep = s.restore_requests()
        self.assertEqual([i for i in rep["installed"]
                          if i["kind"] == "source"], [])
        self.assertEqual(len(rep["installed"]), 1)  # only the crypto hook

    def test_restore_via_command_surface(self):
        self.assertIs(commands.COMMANDS["restore"], commands.cmd_restore)


# ------------------------------------------- process death vs transport fault
class ProcessDiedTests(unittest.TestCase):
    def test_pid_change_is_process_died_not_transport(self):
        s = make_session(FaultClient("post-send"), adb=FakeAdb(pid=9999))
        with reset_conn():
            with self.assertRaises(ProcessDiedError) as cm:
                s._op(lambda c: c.read_op(), _class="read",
                      _name="read_var", _reresolve=True)
        d = cm.exception.to_dict()
        self.assertEqual(d["code"], "E_PROCESS_DIED")
        self.assertIn("restore", d["hint"])
        self.assertEqual(d["context"]["pid_old"], 1234)
        self.assertEqual(d["context"]["pid_new"], 9999)
        # no transport recovery was attempted against the wrong process
        self.assertEqual(s.adb.calls("remove_forward"), [])
        self.assertEqual(s.adb.calls("kill_server"), [])
        self.assertEqual(Conn.made, [])

    def test_process_gone_is_process_died(self):
        s = make_session(FaultClient("post-send"), adb=FakeAdb(pid=None))
        with reset_conn():
            with self.assertRaises(ProcessDiedError):
                s._op(lambda c: c.op(), _class="state", _name="invoke")

    def test_same_pid_is_recoverable_transport_failure(self):
        s = make_session(FaultClient("post-send"), adb=FakeAdb(pid=1234))
        with reset_conn():
            out = s._op(lambda c: c.op(), _class="read",
                        _name="wait_events", _reresolve=True)
        self.assertEqual(out, "ok")   # reconnect + retry, not ProcessDied


# ------------------------------------------------------------- scoped recovery
class ScopedRecoveryTests(unittest.TestCase):
    def test_op_recovery_touches_only_own_forward(self):
        # session B's forward lives at tcp:8888 on the same adb server
        s = make_session(FaultClient("post-send"))
        s.port = 7777
        with reset_conn():
            out = s._op(lambda c: c.op(), _class="idempotent", _name="op")
        self.assertEqual(out, "ok")
        self.assertEqual(s.adb.calls("kill_server"), [])
        for c in s.adb.calls("remove_forward"):
            self.assertEqual(c[1], 7777)      # never 8888 (session B)
        for c in s.adb.calls("forward_jdwp"):
            self.assertEqual(c[1:], (1234, 7777))

    def test_attach_never_escalates_to_kill_server_by_default(self):
        s = make_session(Conn("127.0.0.1", 7777))
        with reset_conn(fail=True):           # plain + reconnect both fail
            with self.assertRaises(AttachUnavailableError):
                s._attach()
        self.assertEqual(len(s.adb.calls("reconnect")), 1)
        self.assertEqual(s.adb.calls("kill_server"), [])

    def test_kill_server_only_when_explicitly_requested(self):
        s = make_session(Conn("127.0.0.1", 7777))
        with reset_conn(fail=True):
            with self.assertRaises(AttachUnavailableError):
                s._attach(allow_global_restart=True)
        self.assertEqual(len(s.adb.calls("reconnect")), 1)
        self.assertEqual(len(s.adb.calls("kill_server")), 1)

    def test_connect_rejects_unknown_recovery_policy(self):
        s = make_session(Conn("127.0.0.1", 7777))
        with self.assertRaises(SessionError):
            s.connect("com.fake", recovery="nuke-everything")
        self.assertEqual(s.adb.calls("kill_server"), [])


if __name__ == "__main__":
    unittest.main()

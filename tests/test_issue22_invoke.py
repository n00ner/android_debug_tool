"""Offline regression tests for issue #22 — invoke method ownership.

A WireStub replaces JdwpClient.request: metadata commands get canned
replies, invoke/new-instance payloads are captured verbatim. Clients are
built via __new__ with UNEQUAL ID widths (object=8, reftype=4, method=8,
field=4, frame=8) so layout assertions prove offset computation from the
wire format rather than assuming every ID is 8 bytes."""

from __future__ import annotations

import unittest

from apkdbg.device.jdwp import (
    CS_CLASSTYPE, CS_OBJECTREF, CS_REFTYPE, CT_SUPERCLASS,
    INVOKE_NONVIRTUAL, INVOKE_SINGLE_THREADED, OR_INVOKE, OR_REFTYPE,
    RT_METHODS, TAG_VOID, IdSizes, JdwpClient, Reader, Writer,
)
from apkdbg.errors import CapabilityError, JdwpReplyError, ResolveError

# runtime type IDs (fit reftype width 4)
OBJECT_C, ACTIVITY, MAIN, UNREL, IFACE = 0xB1, 0xB2, 0xB3, 0xB4, 0xB5
# method IDs (fit method width 8)
GETINTENT, ACT_INIT, ACT_TITLE = 0xC1, 0xC2, 0xC3
ONCREATE, OVER_I, OVER_J, MAIN_TITLE, MAIN_INIT = 0xD1, 0xD2, 0xD3, 0xD4, 0xD5
PING, SIZE_M = 0xE1, 0xE2
# object / thread IDs (fit object width 8)
OBJ_MAIN, OBJ_UNREL, THREAD = 0xA1, 0xA2, 0xF1

SIG_INTENT = "()Landroid/content/Intent;"
SIG_TITLE = "()Ljava/lang/CharSequence;"

SUPERS = {OBJECT_C: 0, ACTIVITY: OBJECT_C, MAIN: ACTIVITY,
          UNREL: OBJECT_C, IFACE: -1}  # -1: interface (INVALID_CLASS)


def _m(mid, name, sig):
    return {"id": mid, "name": name, "sig": sig, "mod_bits": 1}


METHODS = {
    OBJECT_C: [],
    ACTIVITY: [_m(GETINTENT, "getIntent", SIG_INTENT),
               _m(ACT_INIT, "<init>", "()V"),
               _m(ACT_TITLE, "getTitle", SIG_TITLE)],
    MAIN: [_m(ONCREATE, "onCreate", "(Landroid/os/Bundle;)V"),
           _m(OVER_I, "over", "(I)V"),
           _m(OVER_J, "over", "(J)V"),
           _m(MAIN_TITLE, "getTitle", SIG_TITLE),
           _m(MAIN_INIT, "<init>", "()V")],
    UNREL: [_m(PING, "ping", "()V")],
    IFACE: [_m(SIZE_M, "size", "()I")],
}

OBJ_TYPES = {OBJ_MAIN: MAIN, OBJ_UNREL: UNREL}


class WireStub:
    """Serves canned metadata replies; captures invoke payloads."""

    def __init__(self, client):
        self.client = client
        self.calls = []              # (cmdset, cmd) of every request
        self.rt_methods_calls = 0    # round-trip counter for cache tests
        self.invoke_payloads = []    # ObjectReference.InvokeMethod payloads
        self.new_payloads = []       # ClassType.NewInstance payloads

    def request(self, cmdset, cmd, payload=b"", timeout=None):
        s = self.client.sizes
        self.calls.append((cmdset, cmd))
        if cmdset == CS_REFTYPE and cmd == RT_METHODS:
            self.rt_methods_calls += 1
            tid = int.from_bytes(payload[:s.reftype], "big")
            w = Writer(s)
            w.u32(len(METHODS.get(tid, [])))
            for m in METHODS.get(tid, []):
                w.method_id(m["id"])
                w.string(m["name"])
                w.string(m["sig"])
                w.u32(m["mod_bits"])
            return Reader(bytes(w.buf), s)
        if cmdset == CS_CLASSTYPE and cmd == CT_SUPERCLASS:
            tid = int.from_bytes(payload[:s.reftype], "big")
            sup = SUPERS.get(tid, 0)
            if sup < 0:
                raise JdwpReplyError(21, cmdset, cmd)  # INVALID_CLASS
            w = Writer(s)
            w.reftype_id(sup)
            return Reader(bytes(w.buf), s)
        if cmdset == CS_OBJECTREF and cmd == OR_REFTYPE:
            oid = int.from_bytes(payload[:s.object], "big")
            w = Writer(s)
            w.u8(1)  # refTypeTag: class
            w.reftype_id(OBJ_TYPES[oid])
            return Reader(bytes(w.buf), s)
        if cmdset == CS_OBJECTREF and cmd == OR_INVOKE:
            self.invoke_payloads.append(bytes(payload))
            return self._invoke_reply()
        if cmdset == CS_CLASSTYPE and cmd == 4:  # NewInstance
            self.new_payloads.append(bytes(payload))
            return self._invoke_reply()
        raise AssertionError(f"unexpected JDWP request {cmdset}/{cmd}")

    def _invoke_reply(self):
        # void return value + null exception (untagged objectID per spec)
        s = self.client.sizes
        return Reader(bytes([TAG_VOID]) + (0).to_bytes(s.object, "big"), s)


def make_client():
    c = JdwpClient.__new__(JdwpClient)
    JdwpClient.__init__(c, "127.0.0.1", 0)  # fields only; no connect
    c.sizes = IdSizes(field=4, method=8, obj=8, reftype=4, frame=8)
    stub = WireStub(c)
    c.request = stub.request
    return c, stub


def parse_ids(payload, widths):
    """Chop a payload into IDs of the given widths; returns
    (values, offset_after)."""
    out, pos = [], 0
    for n in widths:
        out.append(int.from_bytes(payload[pos:pos + n], "big"))
        pos += n
    return out, pos


class InvokeTransportTests(unittest.TestCase):
    def test_invoke_payload_layout_unequal_widths(self):
        c, stub = make_client()
        s = c.sizes
        c.invoke_object_method(OBJ_MAIN, THREAD, ACTIVITY, GETINTENT, [])
        self.assertEqual(len(stub.invoke_payloads), 1)
        p = stub.invoke_payloads[0]
        (obj, thread, cls, mid), pos = parse_ids(
            p, [s.object, s.object, s.reftype, s.method])
        self.assertEqual((obj, thread, cls, mid),
                         (OBJ_MAIN, THREAD, ACTIVITY, GETINTENT))
        argc = int.from_bytes(p[pos:pos + 4], "big")
        opts = int.from_bytes(p[pos + 4:pos + 8], "big")
        self.assertEqual(argc, 0)
        self.assertEqual(opts, INVOKE_SINGLE_THREADED)
        self.assertEqual(len(p), pos + 8)
        # offsets really do derive from the widths: reftype=4 puts the
        # method ID at byte 2*object + reftype, not at 3*8
        self.assertEqual(p[16:20], ACTIVITY.to_bytes(4, "big"))
        self.assertEqual(p[20:28], GETINTENT.to_bytes(8, "big"))

    def test_invoke_payload_layout_with_arg(self):
        c, stub = make_client()
        s = c.sizes
        c.invoke_object_method(OBJ_MAIN, THREAD, MAIN, OVER_I,
                               [(73, 0x01020304)])  # tag 'I'
        p = stub.invoke_payloads[0]
        _, pos = parse_ids(p, [s.object, s.object, s.reftype, s.method])
        self.assertEqual(int.from_bytes(p[pos:pos + 4], "big"), 1)
        self.assertEqual(p[pos + 4], 73)
        self.assertEqual(p[pos + 5:pos + 9], (0x01020304).to_bytes(4, "big"))
        self.assertEqual(int.from_bytes(p[pos + 9:pos + 13], "big"),
                         INVOKE_SINGLE_THREADED)

    def test_new_instance_payload_layout_unequal_widths(self):
        c, stub = make_client()
        s = c.sizes
        c.ct_new_instance(MAIN, THREAD, MAIN_INIT)
        self.assertEqual(len(stub.new_payloads), 1)
        p = stub.new_payloads[0]
        (cls, thread, mid), pos = parse_ids(
            p, [s.reftype, s.object, s.method])
        self.assertEqual((cls, thread, mid), (MAIN, THREAD, MAIN_INIT))
        self.assertEqual(int.from_bytes(p[pos:pos + 4], "big"), 0)
        self.assertEqual(int.from_bytes(p[pos + 4:pos + 8], "big"),
                         INVOKE_SINGLE_THREADED)
        self.assertEqual(p[0:4], MAIN.to_bytes(4, "big"))
        self.assertEqual(p[12:20], MAIN_INIT.to_bytes(8, "big"))


class ResolveTests(unittest.TestCase):
    def test_inherited_method_resolves_to_declaring_superclass(self):
        c, _ = make_client()
        self.assertEqual(
            c.resolve_instance_method(MAIN, "getIntent", SIG_INTENT),
            (ACTIVITY, GETINTENT))

    def test_overridden_method_resolves_to_override(self):
        c, _ = make_client()
        self.assertEqual(
            c.resolve_instance_method(MAIN, "getTitle", SIG_TITLE),
            (MAIN, MAIN_TITLE))

    def test_overload_without_sig_is_ambiguous(self):
        c, _ = make_client()
        with self.assertRaises(ResolveError) as ctx:
            c.resolve_instance_method(MAIN, "over")
        self.assertIn("ambiguous", str(ctx.exception))

    def test_overload_with_sig_resolves(self):
        c, _ = make_client()
        self.assertEqual(c.resolve_instance_method(MAIN, "over", "(J)V"),
                         (MAIN, OVER_J))

    def test_unknown_method_raises(self):
        c, _ = make_client()
        with self.assertRaises(ResolveError):
            c.resolve_instance_method(MAIN, "nope")

    def test_interface_target_raises_capability_error(self):
        c, _ = make_client()
        with self.assertRaises(CapabilityError):
            c.resolve_instance_method(IFACE, "size", "()I")


class ValidateTests(unittest.TestCase):
    def test_ancestor_declared_method_accepted(self):
        c, _ = make_client()
        c.validate_instance_method(ACTIVITY, GETINTENT, obj=OBJ_MAIN)

    def test_unrelated_method_id_rejected(self):
        c, _ = make_client()
        with self.assertRaises(ResolveError):
            c.validate_instance_method(MAIN, PING, obj=OBJ_MAIN)

    def test_stale_method_id_rejected(self):
        c, _ = make_client()
        with self.assertRaises(ResolveError) as ctx:
            c.validate_instance_method(MAIN, 0xDEAD, obj=OBJ_MAIN)
        self.assertIn("stale or foreign", str(ctx.exception))

    def test_receiver_hierarchy_violation_rejected(self):
        c, _ = make_client()
        with self.assertRaises(ResolveError) as ctx:
            c.validate_instance_method(MAIN, ONCREATE, obj=OBJ_UNREL)
        self.assertIn("receiver hierarchy violation", str(ctx.exception))

    def test_interface_target_raises_capability_error(self):
        c, _ = make_client()
        with self.assertRaises(CapabilityError):
            c.validate_instance_method(IFACE, SIZE_M)

    def test_nonvirtual_ancestor_declared_rejected(self):
        c, _ = make_client()
        with self.assertRaises(ResolveError) as ctx:
            c.validate_instance_method(MAIN, GETINTENT, obj=OBJ_MAIN,
                                       nonvirtual=True)
        self.assertIn("nonvirtual", str(ctx.exception))

    def test_nonvirtual_declared_here_accepted(self):
        c, _ = make_client()
        c.validate_instance_method(MAIN, ONCREATE, obj=OBJ_MAIN,
                                   nonvirtual=True)


class CheckedInvokeTests(unittest.TestCase):
    def test_bad_method_id_rejected_before_any_invoke(self):
        c, stub = make_client()
        with self.assertRaises(ResolveError):
            c.invoke_object_method(OBJ_MAIN, THREAD, MAIN, 0xDEAD, [])
        self.assertEqual(stub.invoke_payloads, [])

    def test_receiver_violation_rejected_before_any_invoke(self):
        c, stub = make_client()
        with self.assertRaises(ResolveError):
            c.invoke_object_method(OBJ_UNREL, THREAD, ACTIVITY, GETINTENT, [])
        self.assertEqual(stub.invoke_payloads, [])

    def test_interface_invoke_raises_capability_error(self):
        c, stub = make_client()
        with self.assertRaises(CapabilityError):
            c.invoke_object_method(OBJ_MAIN, THREAD, IFACE, SIZE_M, [])
        self.assertEqual(stub.invoke_payloads, [])

    def test_nonvirtual_ancestor_rejected_before_any_invoke(self):
        c, stub = make_client()
        with self.assertRaises(ResolveError):
            c.invoke_object_method(OBJ_MAIN, THREAD, MAIN, GETINTENT, [],
                                   options=INVOKE_NONVIRTUAL)
        self.assertEqual(stub.invoke_payloads, [])

    def test_nonvirtual_declared_here_sent(self):
        c, stub = make_client()
        c.invoke_object_method(OBJ_MAIN, THREAD, MAIN, ONCREATE, [],
                               options=INVOKE_NONVIRTUAL)
        self.assertEqual(len(stub.invoke_payloads), 1)
        p = stub.invoke_payloads[0]
        self.assertEqual(int.from_bytes(p[-4:], "big"), INVOKE_NONVIRTUAL)

    def test_validated_false_is_raw_escape_hatch(self):
        c, stub = make_client()
        # an incoherent pair goes straight to the wire when opted out
        c.invoke_object_method(OBJ_MAIN, THREAD, MAIN, 0xDEAD, [],
                               validated=False)
        self.assertEqual(len(stub.invoke_payloads), 1)


class NewInstanceTests(unittest.TestCase):
    def test_valid_init_sent(self):
        c, stub = make_client()
        r = c.ct_new_instance(MAIN, THREAD, MAIN_INIT)
        self.assertEqual(len(stub.new_payloads), 1)
        self.assertEqual(r["exception"], 0)

    def test_wrong_class_constructor_rejected_before_request(self):
        c, stub = make_client()
        with self.assertRaises(ResolveError):
            c.ct_new_instance(MAIN, THREAD, ACT_INIT)  # Activity.<init>
        self.assertEqual(stub.new_payloads, [])
        self.assertNotIn((CS_CLASSTYPE, 4), stub.calls)

    def test_subclass_constructor_on_superclass_rejected(self):
        c, stub = make_client()
        with self.assertRaises(ResolveError):
            c.ct_new_instance(ACTIVITY, THREAD, MAIN_INIT)
        self.assertEqual(stub.new_payloads, [])

    def test_non_constructor_rejected_before_request(self):
        c, stub = make_client()
        with self.assertRaises(ResolveError) as ctx:
            c.ct_new_instance(MAIN, THREAD, ONCREATE)
        self.assertIn("<init>", str(ctx.exception))
        self.assertEqual(stub.new_payloads, [])

    def test_validated_false_is_raw_escape_hatch(self):
        c, stub = make_client()
        c.ct_new_instance(MAIN, THREAD, ACT_INIT, validated=False)
        self.assertEqual(len(stub.new_payloads), 1)


class EpochCacheTests(unittest.TestCase):
    def test_resolution_cached_within_epoch(self):
        c, stub = make_client()
        c.resolve_instance_method(MAIN, "getIntent", SIG_INTENT)
        n = stub.rt_methods_calls
        self.assertGreater(n, 0)
        c.resolve_instance_method(MAIN, "getIntent", SIG_INTENT)
        c.resolve_instance_method(MAIN, "getTitle", SIG_TITLE)
        c.validate_instance_method(ACTIVITY, GETINTENT, obj=OBJ_MAIN)
        c.validate_instance_method(ACTIVITY, GETINTENT, obj=OBJ_MAIN)
        self.assertEqual(stub.rt_methods_calls, n)

    def test_new_client_does_not_see_old_cache(self):
        c1, stub1 = make_client()
        c1.resolve_instance_method(MAIN, "getIntent", SIG_INTENT)
        n1 = stub1.rt_methods_calls
        # new connection epoch = new client instance: it re-reads metadata
        c2, stub2 = make_client()
        c2.resolve_instance_method(MAIN, "getIntent", SIG_INTENT)
        self.assertGreater(stub2.rt_methods_calls, 0)
        self.assertEqual(stub1.rt_methods_calls, n1)

    def test_close_clears_caches(self):
        c, _ = make_client()
        c.resolve_instance_method(MAIN, "getIntent", SIG_INTENT)
        c.validate_instance_method(ACTIVITY, GETINTENT)
        self.assertTrue(c._resolve_cache and c._pair_cache)
        c.close()
        self.assertEqual(c._rt_methods_cache, {})
        self.assertEqual(c._super_cache, {})
        self.assertEqual(c._resolve_cache, {})
        self.assertEqual(c._pair_cache, set())


if __name__ == "__main__":
    unittest.main()

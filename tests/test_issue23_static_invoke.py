"""Offline regression tests for issue #23 — ClassType.InvokeMethod
(static invoke) checked wrapper and wire layout.

A WireStub replaces JdwpClient.request: rt_methods gets a canned reply,
invoke payloads are captured verbatim, and reply bytes are configurable
per test. Clients are built via __new__ with NON-DEFAULT ID widths
(object=4, reftype=8, method=4, field=8, frame=4) so layout assertions
prove offset computation from the wire format rather than assuming
every ID is 8 bytes."""

from __future__ import annotations

import unittest

from apkdbg.device.jdwp import (
    CS_CLASSTYPE, CS_REFTYPE, CT_INVOKE, INVOKE_SINGLE_THREADED,
    RT_METHODS, TAG_OBJECT, TAG_STRING, TAG_VOID, IdSizes, JdwpClient,
    Reader, Writer,
)
from apkdbg.errors import ResolveError

CLS = 0xC1            # class ID (reftype width 8)
THREAD = 0x71         # thread ID (object width 4)
STATIC_M, INST_M, CTOR, FOR_NAME = 0x51, 0x52, 0x53, 0x54  # method width 4
STR_OID, EXC_OID = 0x31, 0x32

PUBLIC, STATIC = 0x0001, 0x0008
METHODS = {
    CLS: [
        {"id": STATIC_M, "name": "currentThread",
         "sig": "()Ljava/lang/Thread;", "mod_bits": PUBLIC | STATIC},
        {"id": INST_M, "name": "getName",
         "sig": "()Ljava/lang/String;", "mod_bits": PUBLIC},
        {"id": CTOR, "name": "<init>", "sig": "()V", "mod_bits": PUBLIC},
        {"id": FOR_NAME, "name": "forName",
         "sig": "(Ljava/lang/String;)Ljava/lang/Class;",
         "mod_bits": PUBLIC | STATIC},
    ],
}


class WireStub:
    """Serves canned rt_methods; captures ClassType.InvokeMethod
    payloads and replays a configurable reply."""

    def __init__(self, client):
        self.client = client
        self.calls = []               # (cmdset, cmd) of every request
        self.rt_methods_calls = 0
        self.invoke_payloads = []
        self.reply = b""              # raw reply bytes for CT_INVOKE

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
        if cmdset == CS_CLASSTYPE and cmd == CT_INVOKE:
            self.invoke_payloads.append(bytes(payload))
            return Reader(self.reply, s)
        raise AssertionError(f"unexpected JDWP request {cmdset}/{cmd}")


def make_client():
    c = JdwpClient.__new__(JdwpClient)
    JdwpClient.__init__(c, "127.0.0.1", 0)  # fields only; no connect
    c.sizes = IdSizes(field=8, method=4, obj=4, reftype=8, frame=4)
    stub = WireStub(c)
    c.request = stub.request
    # default reply: tagged null return + tagged null exception
    o = c.sizes.object
    stub.reply = (bytes([TAG_OBJECT]) + (0).to_bytes(o, "big")
                  + bytes([TAG_OBJECT]) + (0).to_bytes(o, "big"))
    return c, stub


def reply_tagged_null(sizes, exc_oid=0, tagged_exc=True):
    """value: tagged null object; exception: tagged or bare objectID."""
    out = bytes([TAG_OBJECT]) + (0).to_bytes(sizes.object, "big")
    if tagged_exc:
        out += bytes([TAG_OBJECT])
    return out + exc_oid.to_bytes(sizes.object, "big")


class PayloadLayoutTests(unittest.TestCase):
    def test_layout_no_args_nondefault_widths(self):
        c, stub = make_client()
        c.ct_invoke_method(CLS, THREAD, STATIC_M)
        self.assertEqual(len(stub.invoke_payloads), 1)
        p = stub.invoke_payloads[0]
        # reftype=8, object=4, method=4: class@0, thread@8, method@12
        self.assertEqual(p[0:8], CLS.to_bytes(8, "big"))
        self.assertEqual(p[8:12], THREAD.to_bytes(4, "big"))
        self.assertEqual(p[12:16], STATIC_M.to_bytes(4, "big"))
        self.assertEqual(int.from_bytes(p[16:20], "big"), 0)  # argc
        self.assertEqual(int.from_bytes(p[20:24], "big"),
                         INVOKE_SINGLE_THREADED)
        self.assertEqual(len(p), 24)

    def test_layout_with_string_arg(self):
        c, stub = make_client()
        c.ct_invoke_method(CLS, THREAD, FOR_NAME, [(TAG_STRING, STR_OID)])
        p = stub.invoke_payloads[0]
        self.assertEqual(int.from_bytes(p[16:20], "big"), 1)  # argc
        self.assertEqual(p[20], TAG_STRING)                   # tag byte
        # object width 4: the string ID is 4 bytes, not 8
        self.assertEqual(p[21:25], STR_OID.to_bytes(4, "big"))
        self.assertEqual(int.from_bytes(p[25:29], "big"),
                         INVOKE_SINGLE_THREADED)
        self.assertEqual(len(p), 29)


class ReplyDecodeTests(unittest.TestCase):
    def test_tagged_null_return_and_exception(self):
        c, stub = make_client()
        stub.reply = reply_tagged_null(c.sizes)
        r = c.ct_invoke_method(CLS, THREAD, STATIC_M)
        self.assertEqual(r["value"], {"tag": TAG_OBJECT, "v": 0})
        self.assertEqual(r["exception"], 0)

    def test_tagged_thrown_exception(self):
        c, stub = make_client()
        stub.reply = reply_tagged_null(c.sizes, exc_oid=EXC_OID)
        r = c.ct_invoke_method(CLS, THREAD, STATIC_M)
        self.assertEqual(r["value"]["v"], 0)
        self.assertEqual(r["exception"], EXC_OID)

    def test_untagged_legacy_exception_tolerated(self):
        c, stub = make_client()
        stub.reply = reply_tagged_null(c.sizes, exc_oid=EXC_OID,
                                       tagged_exc=False)
        r = c.ct_invoke_method(CLS, THREAD, STATIC_M)
        self.assertEqual(r["exception"], EXC_OID)

    def test_void_return(self):
        c, stub = make_client()
        stub.reply = (bytes([TAG_VOID])
                      + (0).to_bytes(c.sizes.object, "big"))
        r = c.ct_invoke_method(CLS, THREAD, STATIC_M)
        self.assertEqual(r["value"], {"tag": TAG_VOID, "v": None})
        self.assertEqual(r["exception"], 0)


class ValidationTests(unittest.TestCase):
    def test_valid_static_passes_and_decodes(self):
        c, stub = make_client()
        r = c.ct_invoke_method(CLS, THREAD, STATIC_M)
        self.assertEqual(r["exception"], 0)
        self.assertEqual(len(stub.invoke_payloads), 1)

    def test_instance_method_rejected_before_request(self):
        c, stub = make_client()
        with self.assertRaises(ResolveError) as ctx:
            c.ct_invoke_method(CLS, THREAD, INST_M)
        self.assertIn("STATIC", str(ctx.exception))
        self.assertEqual(stub.invoke_payloads, [])
        self.assertNotIn((CS_CLASSTYPE, CT_INVOKE), stub.calls)

    def test_init_rejected_before_request(self):
        c, stub = make_client()
        with self.assertRaises(ResolveError) as ctx:
            c.ct_invoke_method(CLS, THREAD, CTOR)
        self.assertIn("<init>", str(ctx.exception))
        self.assertEqual(stub.invoke_payloads, [])

    def test_wrong_class_method_id_rejected_before_request(self):
        c, stub = make_client()
        with self.assertRaises(ResolveError) as ctx:
            c.ct_invoke_method(CLS, THREAD, 0xDEAD)
        self.assertIn("stale or foreign", str(ctx.exception))
        self.assertEqual(stub.invoke_payloads, [])
        self.assertNotIn((CS_CLASSTYPE, CT_INVOKE), stub.calls)

    def test_validated_false_is_raw_escape_hatch(self):
        c, stub = make_client()
        c.ct_invoke_method(CLS, THREAD, 0xDEAD, validated=False)
        self.assertEqual(len(stub.invoke_payloads), 1)
        self.assertEqual(stub.rt_methods_calls, 0)  # no metadata fetch

    def test_rt_methods_cached_across_invokes(self):
        c, stub = make_client()
        c.ct_invoke_method(CLS, THREAD, STATIC_M)
        c.ct_invoke_method(CLS, THREAD, FOR_NAME, [(TAG_STRING, STR_OID)])
        self.assertEqual(stub.rt_methods_calls, 1)
        self.assertEqual(len(stub.invoke_payloads), 2)

    def test_close_clears_cache(self):
        c, _ = make_client()
        c.ct_invoke_method(CLS, THREAD, STATIC_M)
        self.assertTrue(c._rt_methods_cache)
        c.close()
        self.assertEqual(c._rt_methods_cache, {})


if __name__ == "__main__":
    unittest.main()

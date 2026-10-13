"""Offline regression tests for issue #4 — ObjectReference.InvokeMethod
command ID and the tagged exception object in the reply.

Pre-fix, OR_INVOKE was 9 (IsCollected territory; InvokeMethod is cmd 6),
and the reply's exception object was decoded as a bare objectID even
though the spec layout is a TAGGED exception object (tag + objectID),
so a normal null exception decoded as a huge nonzero ID. The tagged
exception is STANDARD JDWP (see tests/fixtures/jdwp/README.md), and the
checked-in fixture packet demonstrates a standard reply with a tagged
non-null exception.

Reply bytes in each test are written out explicitly from the spec and
cross-checked against the production Writer in the other direction.
"""

from __future__ import annotations

import struct
import unittest
from pathlib import Path

from apkdbg.device.jdwp import (
    CS_OBJECTREF, IdSizes, JdwpClient, OR_INVOKE, Reader, Writer,
)
from jdwp_fakes import id_bytes, wired_client

FIXTURE = (Path(__file__).resolve().parent / "fixtures" / "jdwp"
           / "invoke_reply_tagged_exception.hex")

ORD_I, ORD_L, ORD_V = ord("I"), ord("L"), ord("V")


def _invoke_with_reply(client: JdwpClient, reply: bytes) -> dict:
    client.request = lambda *_a, **_k: Reader(reply, client.sizes)
    # validated=False: raw wire path only; ownership pre-flight is
    # issue #22 and already covered by test_issue22_invoke.py
    return client.invoke_object_method(1, 2, 3, 4, [], validated=False)


class InvokeCommandIdTest(unittest.TestCase):
    def test_issue4_or_invoke_is_command_6(self):
        """Spec: ObjectReference.InvokeMethod == 6; cmd 9 is NOT
        InvokeMethod (the pre-fix constant)."""
        self.assertEqual(OR_INVOKE, 6)
        self.assertNotEqual(OR_INVOKE, 9)

    def test_issue4_request_uses_cmdset_9_cmd_6(self):
        client, tx = wired_client()
        tx.replies[(CS_OBJECTREF, OR_INVOKE)] = (
            bytes([ORD_V]) + bytes([ORD_L]) + id_bytes(0, 8))
        client.invoke_object_method(1, 2, 3, 4, [], validated=False)
        (cs, cmd, payload), = tx.calls
        self.assertEqual((cs, cmd), (9, 6))
        # request layout: object, thread, class, method, arg count, options
        self.assertEqual(payload, id_bytes(1, 8) + id_bytes(2, 8)
                         + id_bytes(3, 8) + id_bytes(4, 8)
                         + struct.pack(">II", 0, 1))


class InvokeReplyDecodingTest(unittest.TestCase):
    def test_issue4_null_exception_decodes_as_zero(self):
        """The issue's exact reproduction: tagged int 7 return + tagged
        NULL exception -> exception id 0 (not 5476377146882523136)."""
        client, _ = wired_client()
        reply = struct.pack(">BiBQ", ORD_I, 7, ORD_L, 0)
        out = _invoke_with_reply(client, reply)
        self.assertEqual(out["value"], {"tag": ORD_I, "v": 7})
        self.assertEqual(out["exception"], 0)

    def test_issue4_tagged_nonnull_exception_decodes_id(self):
        client, _ = wired_client()
        reply = bytes([ORD_V]) + bytes([ORD_L]) + id_bytes(0x1234, 8)
        out = _invoke_with_reply(client, reply)
        self.assertEqual(out["value"], {"tag": ORD_V, "v": None})
        self.assertEqual(out["exception"], 0x1234)

    def test_issue4_non_default_object_id_width(self):
        """objectID size 4: the tagged exception consumes tag + 4 bytes."""
        client, _ = wired_client(IdSizes(field=8, method=8, obj=4,
                                         reftype=8, frame=8))
        reply = struct.pack(">Bi", ORD_I, -5) + bytes([ORD_L]) \
            + id_bytes(0x42, 4)
        out = _invoke_with_reply(client, reply)
        self.assertEqual(out["value"], {"tag": ORD_I, "v": -5})
        self.assertEqual(out["exception"], 0x42)

    def test_issue4_checked_in_fixture_packet(self):
        """Standard reply packet WITH a tagged non-null exception, loaded
        from tests/fixtures/jdwp/ and parsed fully independently of the
        production code first (header and payload)."""
        packet = bytes.fromhex(FIXTURE.read_text().strip())
        # independent, explicit parse of the expected layout
        length, pid, flags, error = struct.unpack(">IIBH", packet[:11])
        self.assertEqual((length, pid, flags, error),
                         (25, 0x2A, 0x80, 0))
        self.assertEqual(length, len(packet))
        payload = packet[11:]
        self.assertEqual(payload[0], ORD_I)
        self.assertEqual(struct.unpack(">i", payload[1:5])[0], 7)
        self.assertEqual(payload[5], ORD_L)
        self.assertEqual(int.from_bytes(payload[6:14], "big"),
                         0x1122334455667788)
        # the production decoder must agree on the same payload
        client, _ = wired_client()
        out = _invoke_with_reply(client, payload)
        self.assertEqual(out["value"], {"tag": ORD_I, "v": 7})
        self.assertEqual(out["exception"], 0x1122334455667788)

    def test_issue4_fixture_matches_production_writer(self):
        """Cross-check the other direction: the production Writer must
        reproduce the fixture's payload bytes exactly."""
        client, _ = wired_client()
        w = Writer(client.sizes)
        w.value(ORD_I, 7)
        w.u8(ORD_L)
        w.object_id(0x1122334455667788)
        packet = bytes.fromhex(FIXTURE.read_text().strip())
        self.assertEqual(bytes(w.buf), packet[11:])


if __name__ == "__main__":
    unittest.main()

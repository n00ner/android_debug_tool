"""Offline regression tests for issue #3 — ObjectReference.SetValues
encodes UNTAGGED field values.

Pre-fix, object_set_values() used Writer.value() which prepends a type
tag; the spec layout after each fieldID is a bare value (the tag is
implied by the field). The extra byte corrupted the value and shifted
every subsequent field. Expected byte strings below are written out
explicitly from the spec and decoded back with independent struct calls,
cross-checking the production Writer in both directions.
"""

from __future__ import annotations

import struct
import unittest

from apkdbg.device.jdwp import (
    CS_OBJECTREF, CS_STACKFRAME, IdSizes, OR_SETVALUES, SF_SETVALUES,
)
from jdwp_fakes import id_bytes, wired_client

ORD_I, ORD_L, ORD_J, ORD_Z = ord("I"), ord("L"), ord("J"), ord("Z")


class SetValuesEncodingTest(unittest.TestCase):
    def test_issue3_single_int_field_exact_bytes(self):
        """The issue's exact reproduction: obj 0x11, one int field 0x22
        set to 7 -> 24 bytes, int reads back as 7, no trailing byte."""
        client, tx = wired_client()  # default sizes: all IDs 8 bytes
        tx.replies[(CS_OBJECTREF, OR_SETVALUES)] = b""
        client.object_set_values(0x11, [(0x22, ORD_I, 7)])
        (cs, cmd, payload), = tx.calls
        self.assertEqual((cs, cmd), (CS_OBJECTREF, OR_SETVALUES))
        expected = (id_bytes(0x11, 8) + struct.pack(">I", 1)
                    + id_bytes(0x22, 8) + struct.pack(">i", 7))
        self.assertEqual(payload, expected)
        self.assertEqual(len(payload), 24)
        # independent decode of the production bytes
        self.assertEqual(struct.unpack(">i", payload[20:24])[0], 7)
        self.assertEqual(payload[24:], b"")

    def test_issue3_multiple_fields_no_tag_bytes_anywhere(self):
        """Mixed int/object/long/boolean fields: exactly one untagged
        value per fieldID, in order, nothing interleaved."""
        client, tx = wired_client()
        tx.replies[(CS_OBJECTREF, OR_SETVALUES)] = b""
        values = [(0xA1, ORD_I, -3), (0xA2, ORD_L, 0xBEEF),
                  (0xA3, ORD_J, 1 << 40), (0xA4, ORD_Z, True)]
        client.object_set_values(0x0B, values)
        payload = tx.payloads(CS_OBJECTREF, OR_SETVALUES)[0]
        expected = (id_bytes(0x0B, 8) + struct.pack(">I", 4)
                    + id_bytes(0xA1, 8) + struct.pack(">i", -3)
                    + id_bytes(0xA2, 8) + id_bytes(0xBEEF, 8)
                    + id_bytes(0xA3, 8) + struct.pack(">q", 1 << 40)
                    + id_bytes(0xA4, 8) + struct.pack(">b", 1))
        self.assertEqual(payload, expected)
        # no tag byte precedes any value: walking fieldID+value pairs with
        # spec widths must land exactly on the next fieldID
        p = 8 + 4
        for fid, tag, _v in values:
            self.assertEqual(int.from_bytes(payload[p:p + 8], "big"), fid)
            p += 8
            p += {ORD_I: 4, ORD_L: 8, ORD_J: 8, ORD_Z: 1}[tag]
        self.assertEqual(p, len(payload))

    def test_issue3_null_reference_encodes_zero_id(self):
        client, tx = wired_client()
        tx.replies[(CS_OBJECTREF, OR_SETVALUES)] = b""
        client.object_set_values(1, [(2, ORD_L, None)])
        payload = tx.payloads(CS_OBJECTREF, OR_SETVALUES)[0]
        self.assertEqual(payload, id_bytes(1, 8) + struct.pack(">I", 1)
                         + id_bytes(2, 8) + id_bytes(0, 8))

    def test_issue3_non_default_id_widths(self):
        """field=4, object=8: fieldIDs and object values use their own
        negotiated widths (proving offsets come from the wire sizes)."""
        sizes = IdSizes(field=4, method=8, obj=8, reftype=4, frame=8)
        client, tx = wired_client(sizes)
        tx.replies[(CS_OBJECTREF, OR_SETVALUES)] = b""
        client.object_set_values(0x11, [(0x22, ORD_L, 0x33),
                                        (0x44, ORD_I, 9)])
        payload = tx.payloads(CS_OBJECTREF, OR_SETVALUES)[0]
        expected = (id_bytes(0x11, 8) + struct.pack(">I", 2)
                    + id_bytes(0x22, 4) + id_bytes(0x33, 8)
                    + id_bytes(0x44, 4) + struct.pack(">i", 9))
        self.assertEqual(payload, expected)

    def test_issue3_stackframe_setvalues_stays_tagged(self):
        """StackFrame.SetValues has a DIFFERENT spec layout: values ARE
        tagged. Guards against fixing issue #3 by removing tags
        everywhere."""
        client, tx = wired_client()
        tx.replies[(CS_STACKFRAME, SF_SETVALUES)] = b""
        client.frame_set_values(0x11, 0x22, [(3, ORD_I, 7)])
        payload = tx.payloads(CS_STACKFRAME, SF_SETVALUES)[0]
        expected = (id_bytes(0x11, 8) + id_bytes(0x22, 8)
                    + struct.pack(">I", 1) + struct.pack(">I", 3)
                    + bytes([ORD_I]) + struct.pack(">i", 7))
        self.assertEqual(payload, expected)


if __name__ == "__main__":
    unittest.main()

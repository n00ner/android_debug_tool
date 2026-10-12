"""Offline regression tests for issue #5 — ArrayReference.GetValues
consumes a PER-ELEMENT tag for reference arrays.

Pre-fix, reference elements were read as bare object IDs reusing the
array's component tag, so the first element's tag became part of its
object ID and every later element was misaligned. Reply bytes below are
written explicitly from the spec: component tag u8, count u32, then for
reference arrays one tagged value per element; primitive array elements
stay untagged.
"""

from __future__ import annotations

import struct
import unittest

from apkdbg.device.jdwp import CS_ARRAYREF, AR_GETVALUES, IdSizes
from jdwp_fakes import id_bytes, wired_client

ORD_B, ORD_I, ORD_L = ord("B"), ord("I"), ord("L")
ORD_S, ORD_ARR, ORD_T = ord("s"), ord("["), ord("t")


class ReferenceArrayDecodingTest(unittest.TestCase):
    def test_issue5_the_issues_exact_example(self):
        """Object[] with a String (id 17) and an Object (id 34):
        items must be [{'tag': 's', 'v': 17}, {'tag': 'L', 'v': 34}]."""
        client, tx = wired_client()
        tx.replies[(CS_ARRAYREF, AR_GETVALUES)] = struct.pack(
            ">BIBQBQ", ORD_L, 2, ORD_S, 17, ORD_L, 34)
        out = client.array_get_values(1, 0, 2)
        self.assertEqual(out["component_tag"], ORD_L)
        self.assertEqual(out["items"], [{"tag": ORD_S, "v": 17},
                                        {"tag": ORD_L, "v": 34}])

    def test_issue5_mixed_runtime_tags_and_nulls(self):
        """Runtime element types may differ from the component tag
        (String/array/thread inside an Object[]); null elements carry
        their tag with a zero ID."""
        client, tx = wired_client()
        reply = (bytes([ORD_L]) + struct.pack(">I", 4)
                 + bytes([ORD_S]) + id_bytes(11, 8)
                 + bytes([ORD_ARR]) + id_bytes(22, 8)
                 + bytes([ORD_T]) + id_bytes(33, 8)
                 + bytes([ORD_L]) + id_bytes(0, 8))
        tx.replies[(CS_ARRAYREF, AR_GETVALUES)] = reply
        items = client.array_get_values(7, 0, 4)["items"]
        self.assertEqual(items, [{"tag": ORD_S, "v": 11},
                                 {"tag": ORD_ARR, "v": 22},
                                 {"tag": ORD_T, "v": 33},
                                 {"tag": ORD_L, "v": 0}])

    def test_issue5_non_default_object_id_width(self):
        """objectID size 4: each element consumes exactly tag + 4 bytes."""
        client, tx = wired_client(IdSizes(field=8, method=8, obj=4,
                                          reftype=8, frame=8))
        reply = (bytes([ORD_L]) + struct.pack(">I", 2)
                 + bytes([ORD_S]) + id_bytes(0x17, 4)
                 + bytes([ORD_L]) + id_bytes(0x34, 4))
        tx.replies[(CS_ARRAYREF, AR_GETVALUES)] = reply
        items = client.array_get_values(1, 0, 2)["items"]
        self.assertEqual(items, [{"tag": ORD_S, "v": 0x17},
                                 {"tag": ORD_L, "v": 0x34}])

    def test_issue5_primitive_arrays_stay_untagged(self):
        """The untagged primitive path must be preserved: component tag
        'I', then bare 4-byte ints, no per-element tags."""
        client, tx = wired_client()
        tx.replies[(CS_ARRAYREF, AR_GETVALUES)] = (
            bytes([ORD_I]) + struct.pack(">Iiii", 3, 100, -7, 42))
        out = client.array_get_values(1, 0, 3)
        self.assertEqual(out["component_tag"], ORD_I)
        self.assertEqual(out["items"], [100, -7, 42])

    def test_issue5_byte_array_path(self):
        client, tx = wired_client()
        # ArrayReference.Length reply, then GetValues (byte, untagged)
        tx.replies[(CS_ARRAYREF, 1)] = struct.pack(">I", 3)
        tx.replies[(CS_ARRAYREF, AR_GETVALUES)] = (
            bytes([ORD_B]) + struct.pack(">Ibbb", 3, -1, 0, 127))
        self.assertEqual(client.byte_array(9), bytes([0xFF, 0x00, 0x7F]))

    def test_issue5_request_payload_layout(self):
        """Request: arrayObjectID, firstIndex u32, length u32."""
        client, tx = wired_client()
        tx.replies[(CS_ARRAYREF, AR_GETVALUES)] = (
            bytes([ORD_I]) + struct.pack(">I", 0))
        client.array_get_values(0x1234, 5, 9)
        payload = tx.payloads(CS_ARRAYREF, AR_GETVALUES)[0]
        self.assertEqual(payload,
                         id_bytes(0x1234, 8) + struct.pack(">II", 5, 9))

    def test_issue5_zero_length_short_circuits(self):
        """Zero-length reads never hit the wire (ART answers them with an
        internal error); result is an explicit empty inference."""
        client, tx = wired_client()
        out = client.array_get_values(1, 0, 0)
        self.assertEqual(out, {"component_tag": 66, "items": [],
                               "inferred": True})
        self.assertEqual(tx.calls, [])


if __name__ == "__main__":
    unittest.main()

"""Offline regression tests for issue #6 — exception object and catch
location in composite events.

Pre-fix, EVK_EXCEPTION was parsed like a location-only event: the tagged
exception object and catch location were never consumed, so a second
exception event in the same composite was misread (its first tag byte
became the next event kind). Composite payload bytes below are written
explicitly from the spec:

  composite: suspendPolicy u8 | count u32 | events...
  exception event: kind u8 (4) | requestID u32 | thread objectID |
                   throw location | TAGGED exception object |
                   catch location (zeroed when uncaught)
"""

from __future__ import annotations

import struct
import unittest

from apkdbg.device.jdwp import IdSizes, JdwpClient
from jdwp_fakes import id_bytes, location_bytes

ORD_L = ord("L")
EVK_EXCEPTION, EVK_BREAKPOINT = 4, 2


def _exception_event(sizes: IdSizes, request_id: int, thread: int,
                     exception_id: int, catch_index: int | None) -> bytes:
    throw = location_bytes(sizes, 1, 2, 3, 4)
    catch = (location_bytes(sizes, 0, 0, 0, 0) if catch_index is None
             else location_bytes(sizes, 1, 2, 3, catch_index))
    return (struct.pack(">BI", EVK_EXCEPTION, request_id)
            + id_bytes(thread, sizes.object) + throw
            + bytes([ORD_L]) + id_bytes(exception_id, sizes.object)
            + catch)


class CompositeExceptionTest(unittest.TestCase):
    def setUp(self):
        self.client = JdwpClient("unused", 0)  # default sizes: all 8

    def test_issue6_two_exception_requests_same_throw(self):
        """The issue's exact reproduction: two matching exception
        requests -> [(4, 10), (4, 11)], each carrying exception 0x1234
        and its catch location."""
        sizes = self.client.sizes
        packet = (struct.pack(">BI", 2, 2)
                  + _exception_event(sizes, 10, 6, 0x1234, 5)
                  + _exception_event(sizes, 11, 6, 0x1234, 5))
        events = self.client._parse_composite(packet)["events"]
        self.assertEqual([(e["kind_id"], e["request_id"]) for e in events],
                         [(4, 10), (4, 11)])
        for e in events:
            self.assertEqual(e["kind"], "exception")
            self.assertEqual(e["thread"], 6)
            self.assertEqual(e["location"],
                             {"tag": 1, "class": 2, "method": 3,
                              "index": 4})
            self.assertEqual(e["exception"], {"tag": ORD_L, "v": 0x1234})
            self.assertEqual(e["catch_location"],
                             {"tag": 1, "class": 2, "method": 3,
                              "index": 5})

    def test_issue6_uncaught_exception_zero_catch_location(self):
        sizes = self.client.sizes
        packet = (struct.pack(">BI", 1, 1)
                  + _exception_event(sizes, 10, 6, 0x77, None))
        (e,) = self.client._parse_composite(packet)["events"]
        self.assertEqual(e["exception"], {"tag": ORD_L, "v": 0x77})
        self.assertEqual(e["catch_location"],
                         {"tag": 0, "class": 0, "method": 0, "index": 0})

    def test_issue6_exception_followed_by_other_event(self):
        """The trailing fields must be fully consumed so the NEXT event
        decodes correctly (pre-fix it was lost/misread)."""
        sizes = self.client.sizes
        bp = (struct.pack(">BI", EVK_BREAKPOINT, 21)
              + id_bytes(9, sizes.object)
              + location_bytes(sizes, 1, 0x22, 0x33, 7))
        packet = (struct.pack(">BI", 2, 2)
                  + _exception_event(sizes, 10, 6, 0x1234, 5) + bp)
        events = self.client._parse_composite(packet)["events"]
        self.assertEqual([(e["kind_id"], e["request_id"]) for e in events],
                         [(4, 10), (2, 21)])
        self.assertEqual(events[1]["kind"], "breakpoint")
        self.assertEqual(events[1]["location"]["index"], 7)

    def test_issue6_non_default_id_widths(self):
        """object=4, reftype=4, method=8: exception/catch offsets follow
        the negotiated widths."""
        sizes = IdSizes(field=8, method=8, obj=4, reftype=4, frame=8)
        client = JdwpClient("unused", 0)
        client.sizes = sizes
        packet = (struct.pack(">BI", 2, 1)
                  + _exception_event(sizes, 10, 0x123, 0x456, 5))
        (e,) = client._parse_composite(packet)["events"]
        self.assertEqual(e["thread"], 0x123)
        self.assertEqual(e["exception"], {"tag": ORD_L, "v": 0x456})
        self.assertEqual(e["location"],
                         {"tag": 1, "class": 2, "method": 3, "index": 4})
        self.assertEqual(e["catch_location"]["index"], 5)


if __name__ == "__main__":
    unittest.main()

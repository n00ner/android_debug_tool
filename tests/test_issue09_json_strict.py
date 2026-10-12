"""Offline regression tests for issue #9 — non-finite JDWP values must
serialize as STRICT JSON (RFC 8259: no NaN/Infinity literals).

Pre-fix, protocol.dumps() emitted bare NaN/Infinity tokens and strict
parsers rejected the whole response. The fix normalizes non-finite
floats to explicit string markers and serializes with allow_nan=False.
Strictness here is checked WITHOUT third-party parsers: json.loads with
a parse_constant hook is invoked ONLY for the non-standard NaN/Infinity
tokens, so any bare occurrence fails the test.
"""

from __future__ import annotations

import json
import math
import struct
import unittest

from apkdbg.device.jdwp import Reader
from apkdbg.protocol import dumps, ok

ORD_F, ORD_D = ord("F"), ord("D")


def strict_loads(s: str):
    """json.loads that REJECTS the non-standard NaN/Infinity literals
    (json's default accepts them; RFC 8259 does not)."""
    def _boom(token):
        raise AssertionError(f"non-standard JSON token in output: {token}")
    return json.loads(s, parse_constant=_boom)


class NonFiniteSerializationTest(unittest.TestCase):
    def test_issue9_jdwp_float_nan(self):
        decoded = Reader(bytes([ORD_F])
                         + struct.pack(">f", float("nan"))).value()
        out = strict_loads(dumps(ok(decoded)))
        self.assertEqual(out, {"status": "ok",
                               "data": {"tag": ORD_F, "v": "NaN"}})

    def test_issue9_jdwp_double_infinities(self):
        for value, marker in ((float("inf"), "Infinity"),
                              (float("-inf"), "-Infinity")):
            decoded = Reader(bytes([ORD_D])
                             + struct.pack(">d", value)).value()
            out = strict_loads(dumps(ok(decoded)))
            self.assertEqual(out["data"]["v"], marker)

    def test_issue9_nested_values_arrays_tuples(self):
        """Non-finite floats anywhere in the structure — nested dicts,
        lists, tuples — are all normalized."""
        payload = {"frames": [{"slot": 0, "v": float("nan")},
                              [float("inf"), {"deep": float("-inf")}]],
                   "tuple": (float("nan"), 1.5)}
        out = strict_loads(dumps(ok(payload)))
        self.assertEqual(out["data"]["frames"][0]["v"], "NaN")
        self.assertEqual(out["data"]["frames"][1][0], "Infinity")
        self.assertEqual(out["data"]["frames"][1][1]["deep"], "-Infinity")
        self.assertEqual(out["data"]["tuple"], ["NaN", 1.5])

    def test_issue9_finite_values_untouched(self):
        out = strict_loads(dumps(ok({"v": 1.5, "w": -0.0,
                                     "big": 1e300})))
        self.assertEqual(out["data"], {"v": 1.5, "w": -0.0, "big": 1e300})

    def test_issue9_allow_nan_false_backstop(self):
        """dumps() serializes with allow_nan=False: even if the
        normalizer missed a value, invalid JSON can never be emitted —
        the call raises instead."""
        self.assertRaises((ValueError, AssertionError),
                          strict_loads, json.dumps(float("nan")))
        # and the production path raises ValueError on a missed value
        import apkdbg.protocol as proto
        orig = proto._sanitize
        try:
            proto._sanitize = lambda o: o  # simulate a broken normalizer
            with self.assertRaises(ValueError):
                dumps(ok({"v": float("nan")}))
        finally:
            proto._sanitize = orig


if __name__ == "__main__":
    unittest.main()

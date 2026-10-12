"""Offline regression tests for issue #10 — JDWP reply error-number
mappings must match the official spec constants.

Pre-fix the table was shifted (99 NOT_IMPLEMENTED reported as VM_DEAD,
20 INVALID_OBJECT as INVALID_THREAD, and VM_DEAD 112 not mapped at all),
sending users toward the wrong diagnosis. The table below is an
INDEPENDENT copy of the official JDWP error constants
(https://docs.oracle.com/en/java/javase/21/docs/specs/jdwp/jdwp-protocol.html#Error)
so a table edit in either place without the other fails loudly.
"""

from __future__ import annotations

import unittest

from apkdbg.errors import JdwpReplyError

# official JDWP spec error constants (independent reference copy)
SPEC_ERRORS = {
    10: "INVALID_THREAD", 11: "INVALID_THREAD_GROUP",
    12: "INVALID_PRIORITY", 13: "THREAD_NOT_SUSPENDED",
    14: "THREAD_SUSPENDED", 15: "THREAD_NOT_ALIVE",
    20: "INVALID_OBJECT", 21: "INVALID_CLASS", 22: "CLASS_NOT_PREPARED",
    23: "INVALID_METHODID", 24: "INVALID_LOCATION", 25: "INVALID_FIELDID",
    30: "INVALID_FRAMEID", 31: "NO_MORE_FRAMES", 32: "OPAQUE_FRAME",
    33: "NOT_CURRENT_FRAME", 34: "TYPE_MISMATCH", 35: "INVALID_SLOT",
    40: "DUPLICATE", 41: "NOT_FOUND", 42: "INVALID_MODULE",
    50: "INVALID_MONITOR", 51: "NOT_MONITOR_OWNER", 52: "INTERRUPT",
    99: "NOT_IMPLEMENTED", 100: "NULL_POINTER", 101: "ABSENT_INFORMATION",
    102: "INVALID_EVENT_TYPE", 103: "ILLEGAL_ARGUMENT",
    110: "OUT_OF_MEMORY", 111: "ACCESS_DENIED", 112: "VM_DEAD",
    113: "INTERNAL", 115: "UNATTACHED_THREAD", 500: "INVALID_TAG",
    502: "ALREADY_INVOKING", 503: "INVALID_INDEX", 504: "INVALID_LENGTH",
    506: "INVALID_STRING", 507: "INVALID_CLASS_LOADER",
    508: "INVALID_ARRAY", 509: "TRANSPORT_LOAD", 510: "TRANSPORT_INIT",
    511: "NATIVE_METHOD", 512: "INVALID_COUNT",
}


class ErrorNameTableTest(unittest.TestCase):
    def test_issue10_full_table_matches_spec(self):
        self.assertEqual(JdwpReplyError.JDWP_ERRORS, SPEC_ERRORS)

    def test_issue10_names_appear_in_messages(self):
        for code, name in SPEC_ERRORS.items():
            self.assertIn(name, str(JdwpReplyError(code, 1, 1)),
                          f"code {code} should report {name}")

    def test_issue10_not_implemented_vs_vm_dead(self):
        """The key diagnostic distinction the bug destroyed: an
        unsupported command (99) is NOT a dead VM (112)."""
        self.assertIn("NOT_IMPLEMENTED", str(JdwpReplyError(99, 1, 1)))
        self.assertIn("VM_DEAD", str(JdwpReplyError(112, 1, 1)))

    def test_issue10_numeric_context_preserved(self):
        e = JdwpReplyError(504, 11, 6)
        self.assertEqual(e.context["error_no"], 504)
        self.assertEqual(e.context["cmdset"], 11)
        self.assertEqual(e.context["cmd"], 6)

    def test_issue10_unknown_code_falls_back_to_number(self):
        e = JdwpReplyError(12345, 2, 3)
        self.assertIn("ERR_12345", str(e))
        self.assertEqual(e.context["error_no"], 12345)


if __name__ == "__main__":
    unittest.main()

"""Offline regression tests for issue #7 — activity components and
package names must be quoted for the DEVICE shell.

Pre-fix, `am start -n com.example/.Outer$InnerActivity` went through the
remote shell unquoted, so `$InnerActivity` expanded (to empty) and `am`
received `com.example/.Outer`. These tests assert the EXACT argv handed
to subprocess (mocked `run`), plus an end-to-end proof that the quoted
string survives real POSIX-shell parsing (skipped where no sh exists).
"""

from __future__ import annotations

import shutil
import subprocess
import unittest
from unittest.mock import patch

from apkdbg.device.adb import Adb

NESTED = "com.example/.Outer$InnerActivity"
PLAIN = "com.example/.MainActivity"


def _ok_proc(argv, **_kw):
    return subprocess.CompletedProcess(argv, 0, "", "")


class ExactArgvTest(unittest.TestCase):
    def setUp(self):
        with patch("apkdbg.device.adb.find_binary", return_value="adb-mock"):
            self.adb = Adb()
        self.calls = []
        patcher = patch("apkdbg.device.adb.run",
                        side_effect=self._record)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _record(self, argv, **kw):
        self.calls.append(argv)
        cmd = argv[-1]
        if "resolve-activity" in cmd:
            out = "com.example/.MainActivity"
        elif cmd.startswith("pidof"):
            out = "1234"
        else:
            out = ""
        return subprocess.CompletedProcess(argv, 0, out, "")

    def shell_cmds(self):
        return [a[2] for a in self.calls if a[1:2] == ["shell"]]

    def test_issue7_nested_component_quoted_in_launch(self):
        self.adb.launch("com.example", NESTED)
        self.assertEqual(self.calls,
                         [["adb-mock", "shell",
                           f"am start -n '{NESTED}'"]])

    def test_issue7_nested_component_quoted_in_launch_debug(self):
        self.adb.launch_debug("com.example", NESTED)
        self.assertEqual(self.calls,
                         [["adb-mock", "shell",
                           f"am start -D -n '{NESTED}'"]])

    def test_issue7_resolved_main_activity_also_quoted(self):
        """The component returned by main_activity() takes the same code
        path and must be quoted too (the original bug hit both)."""
        with patch.object(self.adb, "main_activity", return_value=NESTED):
            self.adb.launch("com.example")
        self.assertEqual(self.shell_cmds(), [f"am start -n '{NESTED}'"])

    def test_issue7_plain_component_stays_unquoted(self):
        self.adb.launch("com.example", PLAIN)
        self.assertEqual(self.shell_cmds(), [f"am start -n {PLAIN}"])

    def test_issue7_shell_metacharacters_neutralized(self):
        """Spaces, quotes, command separators, backticks and command
        substitution must all reach `am` as ONE literal argument."""
        evil = 'com.example/.Act$(touch /pwn)`id`;\' " |&'
        self.adb.launch("com.example", evil)
        import shlex
        self.assertEqual(self.shell_cmds(),
                         [f"am start -n {shlex.quote(evil)}"])

    def test_issue7_package_names_quoted_everywhere(self):
        self.adb.pidof("com.example"); self.adb.force_stop("com.example")
        self.adb.main_activity("com.example")
        cmds = self.shell_cmds()
        self.assertEqual(cmds[0], "pidof com.example")
        self.assertEqual(cmds[1], "am force-stop com.example")
        self.assertEqual(cmds[2],
                         "cmd package resolve-activity --brief com.example")
        # and with a hostile package string
        self.calls.clear()
        self.adb.force_stop("com.x;rm -rf /")
        self.assertEqual(self.shell_cmds(),
                         ["am force-stop 'com.x;rm -rf /'"])

    def test_issue7_serial_scopes_the_adb_argv(self):
        with patch("apkdbg.device.adb.find_binary", return_value="adb-mock"):
            adb = Adb(serial="device-A")
        with patch("apkdbg.device.adb.run", side_effect=self._record):
            adb.launch("com.example", NESTED)
        self.assertEqual(self.calls[-1][:3], ["adb-mock", "-s", "device-A"])


@unittest.skipUnless(shutil.which("sh"), "no POSIX shell available")
class RealShellRoundTripTest(unittest.TestCase):
    """The issue's reproduction: parse the generated shell command with a
    REAL sh and capture what `am` would receive as its last argument."""

    def _received(self, shell_cmd: str) -> str:
        proc = subprocess.run(
            ["sh", "-c", 'am() { printf "%s\n" "$@"; }; ' + shell_cmd],
            capture_output=True, text=True, check=True)
        return proc.stdout.splitlines()[-1]

    def test_issue7_component_survives_remote_shell_parsing(self):
        with patch("apkdbg.device.adb.find_binary", return_value="adb-mock"):
            adb = Adb()
        received = []

        def fake_run(argv, **kw):
            received.append(self._received(argv[2]))
            return _ok_proc(argv)

        with patch("apkdbg.device.adb.run", side_effect=fake_run):
            adb.launch("com.example", NESTED)
            adb.launch_debug("com.example", NESTED)
            with patch.object(adb, "main_activity", return_value=NESTED):
                adb.launch("com.example")
        self.assertEqual(received, [NESTED] * 3)


if __name__ == "__main__":
    unittest.main()

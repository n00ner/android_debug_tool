"""Offline regression tests for issue #8 — automatic JDWP port
allocation must not rebind other sessions' forwards.

Pre-fix, forward_jdwp() picked `8700 + pid % 900` with plain
`adb forward`, so PIDs 900 apart (or the same PID on two devices)
collided on one local name and the shared adb listener table silently
REBOUND another session's mapping. The fix asks adb to allocate
(`forward tcp:0`) and refuses rebinding for explicit ports
(`--no-rebind`). All adb execution is mocked; the fake listener table
mirrors the real adb server semantics (keyed by local name, rebinding
by default).
"""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from apkdbg.device.adb import Adb
from apkdbg.errors import AdbError


def _adb(serial=None):
    with patch("apkdbg.device.adb.find_binary", return_value="adb-mock"):
        return Adb(serial=serial)


class FakeAdbServer:
    """Models the shared host adb server: listeners keyed by local name,
    `tcp:0` allocates from an ephemeral counter, plain `forward` REBINDS
    an existing local name (the dangerous default), `--no-rebind`
    refuses it."""

    def __init__(self):
        self.listeners = {}      # local name -> (serial, remote)
        self.next_port = 40000
        self.commands = []

    def __call__(self, argv, **_kw):
        self.commands.append(argv)
        serial = argv[2] if argv[1:2] == ["-s"] else None
        rest = argv[3:] if serial else argv[1:]
        if rest[0] != "forward":
            return subprocess.CompletedProcess(argv, 0, "", "")
        if rest[1] == "--remove":
            self.listeners.pop(rest[2], None)
            return subprocess.CompletedProcess(argv, 0, "", "")
        if rest[1] == "--no-rebind":
            local, remote = rest[2], rest[3]
            if local in self.listeners:
                return subprocess.CompletedProcess(
                    argv, 1, "", f"cannot bind listener: {local}")
        elif rest[1] == "tcp:0":
            local = f"tcp:{self.next_port}"
            self.next_port += 1
            remote = rest[2]
            self.listeners[local] = (serial, remote)
            return subprocess.CompletedProcess(argv, 0, local[4:] + "\n", "")
        else:
            local, remote = rest[1], rest[2]
        self.listeners[local] = (serial, remote)  # silent rebind
        return subprocess.CompletedProcess(argv, 0, "", "")


class ForwardAllocationTest(unittest.TestCase):
    def test_issue8_auto_port_uses_tcp0_and_parses_reply(self):
        server = FakeAdbServer()
        adb = _adb()
        with patch("apkdbg.device.adb.run", side_effect=server):
            port = adb.forward_jdwp(1234)
        self.assertEqual(port, 40000)
        self.assertEqual(server.commands[0],
                         ["adb-mock", "forward", "tcp:0", "jdwp:1234"])
        self.assertEqual(server.listeners, {"tcp:40000": (None,
                                                          "jdwp:1234")})

    def test_issue8_explicit_port_uses_no_rebind(self):
        server = FakeAdbServer()
        adb = _adb()
        with patch("apkdbg.device.adb.run", side_effect=server):
            port = adb.forward_jdwp(1234, 8700)
        self.assertEqual(port, 8700)
        self.assertEqual(server.commands[0],
                         ["adb-mock", "forward", "--no-rebind",
                          "tcp:8700", "jdwp:1234"])

    def test_issue8_colliding_pids_get_distinct_ports(self):
        """PIDs 1234 and 2134 (identical mod 900) on one device, and the
        same PID 1234 on a second device: three independent sessions,
        three distinct ports, no listener rebinding."""
        server = FakeAdbServer()
        first, second = _adb("device-A"), _adb("device-B")
        with patch("apkdbg.device.adb.run", side_effect=server):
            ports = [first.forward_jdwp(1234), first.forward_jdwp(2134),
                     second.forward_jdwp(1234)]
        self.assertEqual(len(set(ports)), 3)
        self.assertEqual(len(server.listeners), 3)
        # device-A's first mapping must still point at device-A
        self.assertEqual(server.listeners[f"tcp:{ports[0]}"][0],
                         "device-A")

    def test_issue8_occupied_explicit_port_reports_collision(self):
        """An occupied explicit port must raise, never silently retarget
        the existing listener (pre-fix behavior)."""
        server = FakeAdbServer()
        adb = _adb()
        with patch("apkdbg.device.adb.run", side_effect=server):
            adb.forward_jdwp(1234, 8700)
            with self.assertRaises(AdbError):
                adb.forward_jdwp(5678, 8700)
        # the original mapping is untouched
        self.assertEqual(server.listeners["tcp:8700"], (None,
                                                        "jdwp:1234"))
        # and no fallback retarget was attempted: only --no-rebind calls
        fwd = [c for c in server.commands if "forward" in c
               and "--remove" not in c]
        self.assertTrue(all("--no-rebind" in c for c in fwd))

    def test_issue8_unparseable_allocation_reply_is_an_error(self):
        adb = _adb()
        with patch("apkdbg.device.adb.run",
                   return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaises(AdbError) as ctx:
                adb.forward_jdwp(1234)
        self.assertIn("no allocated port", str(ctx.exception))


class SessionCleanupTest(unittest.TestCase):
    def test_issue8_session_close_removes_only_its_own_forward(self):
        """DebugSession.close() removes exactly the session's own
        listener — never another session's, never a global reset."""
        from apkdbg.debug.session import DebugSession
        server = FakeAdbServer()
        adb_a, adb_b = _adb("device-A"), _adb("device-B")
        with patch("apkdbg.device.adb.run", side_effect=server):
            port_a = adb_a.forward_jdwp(1234)
            port_b = adb_b.forward_jdwp(1234)

            s = DebugSession.__new__(DebugSession)
            s.adb, s.client, s.port = adb_a, None, port_a
            s.close()

            self.assertNotIn(f"tcp:{port_a}", server.listeners)
            self.assertEqual(server.listeners,
                             {f"tcp:{port_b}": ("device-B", "jdwp:1234")})
            removals = [c for c in server.commands
                        if "--remove" in c]
            self.assertEqual(removals,
                             [["adb-mock", "-s", "device-A", "forward",
                               "--remove", f"tcp:{port_a}"]])
            # never a global server restart as a side effect of close()
            self.assertNotIn(["adb-mock", "kill-server"], server.commands)


if __name__ == "__main__":
    unittest.main()

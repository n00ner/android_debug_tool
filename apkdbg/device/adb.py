"""ADB wrapper. All commands go through one choke point so failures are
normalized into structured AdbError objects and the session layer can
implement retry/reconnect policy on top."""

from __future__ import annotations

import re
import shlex
import time

from ..errors import AdbError
from ..util import find_binary, run


class Adb:
    def __init__(self, serial: str | None = None, timeout: int = 30):
        self.bin = find_binary("adb", env_var="APKDBG_ADB")
        self.serial = serial
        self.timeout = timeout

    def _argv(self, *args: str) -> list[str]:
        argv = [self.bin]
        if self.serial:
            argv += ["-s", self.serial]
        argv += list(args)
        return argv

    def sh(self, *args: str, timeout: int | None = None, check: bool = True) -> str:
        proc = run(self._argv(*args), timeout=timeout or self.timeout,
                   tool="adb", check=False)
        out = (proc.stdout or "").strip()
        if check and proc.returncode != 0:
            raise AdbError(
                f"adb {' '.join(args)} failed (rc={proc.returncode})",
                hint=(proc.stderr or out)[-500:] or None,
            )
        return out

    def shell(self, cmd: str, timeout: int | None = None, check: bool = True) -> str:
        return self.sh("shell", cmd, timeout=timeout, check=check)

    # -- device state -------------------------------------------------------
    def ensure_device(self) -> str:
        state = self.sh("get-state", check=False)
        if state != "device":
            raise AdbError(f"device not ready (state={state or 'none'})",
                           hint="check USB cable / adb authorization")
        return state

    def devices(self) -> list[dict]:
        out = self.sh("devices")
        rows = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) == 2:
                rows.append({"serial": parts[0], "state": parts[1]})
        return rows

    def wait_for_device(self, timeout: int = 60) -> None:
        self.sh("wait-for-device", timeout=timeout + 5)
        self.ensure_device()

    # -- app control --------------------------------------------------------
    def pidof(self, package: str) -> int | None:
        out = self.shell(f"pidof {shlex.quote(package)}", check=False)
        if out and out.isdigit():
            return int(out)
        # fallback for older devices without pidof
        for line in self.shell("ps", check=False).splitlines():
            if line.rstrip().endswith(f" {package}"):
                cols = line.split()
                if len(cols) >= 2 and cols[1].isdigit():
                    return int(cols[1])
        return None

    def wait_pid(self, package: str, timeout: int = 30) -> int:
        deadline = time.time() + timeout
        while time.time() < deadline:
            pid = self.pidof(package)
            if pid:
                return pid
            time.sleep(0.5)
        raise AdbError(f"process not found: {package}",
                       hint="launch the app first, or use connect --launch")

    def main_activity(self, package: str) -> str:
        out = self.shell(f"cmd package resolve-activity --brief "
                         f"{shlex.quote(package)}", check=False)
        lines = [l for l in out.splitlines() if "/" in l]
        if lines:
            return lines[-1].strip()
        raise AdbError(f"no launchable activity for {package}")

    def launch_debug(self, package: str, activity: str | None = None) -> None:
        """Start the app suspended, waiting for a debugger (-D)."""
        activity = activity or self.main_activity(package)
        # quote for the remote shell: `$` is legal in nested activity
        # class names (e.g. .Settings$NetworkDashboardActivity)
        self.shell(f"am start -D -n {shlex.quote(activity)}")

    def launch(self, package: str, activity: str | None = None) -> None:
        activity = activity or self.main_activity(package)
        self.shell(f"am start -n {shlex.quote(activity)}")

    def force_stop(self, package: str) -> None:
        self.shell(f"am force-stop {shlex.quote(package)}", check=False)

    # -- transport ----------------------------------------------------------
    def forward_jdwp(self, pid: int, port: int | None = None) -> int:
        """Forward a local TCP port to the app's JDWP transport.
        Uses a deterministic port derived from the pid so reconnects are
        idempotent."""
        port = port or (8700 + pid % 900)
        self.sh("forward", f"tcp:{port}", f"jdwp:{pid}")
        return port

    def remove_forward(self, port: int) -> None:
        self.sh("forward", "--remove", f"tcp:{port}", check=False)

    def reconnect(self) -> None:
        """Recover from stale adbd/host state (e.g. a previous debugger
        detached uncleanly and the VM refuses new JDWP handshakes)."""
        self.sh("reconnect", check=False, timeout=20)

    def kill_server(self) -> None:
        """Last-resort recovery: restart the host adb daemon. Clears stale
        jdwp-forward bookkeeping that survives `adb reconnect` (observed on
        MIUI/adbd 1.0.41)."""
        run([self.bin, "kill-server"], timeout=15, tool="adb", check=False)

    def push(self, local: str, remote: str, timeout: int = 120) -> None:
        self.sh("push", local, remote, timeout=timeout)

    def pull(self, remote: str, local: str, timeout: int = 120) -> None:
        self.sh("pull", remote, local, timeout=timeout)

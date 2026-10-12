#!/usr/bin/env python3
"""Optional device integration runner for the crypto fixture (issue #30).

Executes the fixture's broadcast scenarios against an ATTACHED Android
device and checks the logcat ground truth, plus one live JDWP attach
using apkdbg's public device APIs (Adb + JdwpClient). This runner is
deliberately lightweight: it does not need an apkdbg project, apktool,
or jadx.

The offline suite (`python -m unittest discover -s tests`) never
requires this runner and never touches a device; this file is named so
that unittest discovery does not collect it.

Usage:
    python tests/integration/run_fixture_scenarios.py [serial]

Exit status: 1 if any scenario reports "fail", 0 otherwise.

Per-scenario statuses:
    pass                 scenario ran and its ground truth matched
    fail                 scenario ran but the ground truth did not match
    unsupported          the device/VM cannot run this scenario
    infrastructure-skip  no adb binary, no device, or fixture not
                         installed — an environment problem, not a
                         product defect (offline CI always takes this
                         path by simply not running this script)

Setup (see tests/fixtures/crypto/README.md):
    adb -s <serial> install -r tests/fixtures/crypto/crypto_fixture.apk
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from apkdbg.device.adb import Adb                      # noqa: E402
from apkdbg.device.jdwp import JdwpClient, JdwpConnError  # noqa: E402
from apkdbg.errors import ApkDbgError                  # noqa: E402

PKG = "com.apkdbg.cryptofixture"
LOGCAT_TAG = "CryptoFixture"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "crypto"

PASS, FAIL = "pass", "fail"
UNSUPPORTED, INFRA_SKIP = "unsupported", "infrastructure-skip"

BENCH_ITERS = 1000  # keep the benchmark scenarios quick

# (name, broadcast action, extras, expected logcat substrings)
SCENARIOS = [
    ("crypto_run", f"{PKG}.RUN", [],
     ["cipher.input=", "cipher.output=", "mac.input=", "mac.output=",
      "digest.input=", "digest.output=", "RUN ok"]),
    ("string_work", f"{PKG}.STRINGS", [],
     ["strings.url=https://fixture.example/decrypted-url",
      "strings.builder=", "strings.ctor=", "strings.reflect=",
      "STRINGS ok"]),
    ("string_bench", f"{PKG}.BENCH", ["--ei", "iters", str(BENCH_ITERS)],
     [f"BENCH iters={BENCH_ITERS} acc="]),
    ("framework_store", f"{PKG}.FW_STORE", [], ["FW STORE ok"]),
    ("framework_services", f"{PKG}.FW_SVC", [], ["FW SVC ok"]),
    ("framework_bench", f"{PKG}.FW_BENCH",
     ["--ei", "iters", str(BENCH_ITERS)],
     [f"FWBENCH iters={BENCH_ITERS} acc="]),
    ("buffers", f"{PKG}.BUFFERS", [],
     ["BUFFER readOnly kind=", "BUFFERS ok"]),
    ("unpack", f"{PKG}.UNPACK", [],
     ["UNPACK payload.len=", "UNPACK ok"]),
]


class Runner:
    def __init__(self, serial: str | None):
        self.serial = serial
        self.adb: Adb | None = None
        self.results: dict[str, dict] = {}

    # -- infrastructure -------------------------------------------------
    def check_infrastructure(self) -> str | None:
        """Returns an infrastructure-skip reason, or None when the
        environment can run scenarios."""
        try:
            self.adb = Adb(self.serial)
        except ApkDbgError as e:
            return f"adb binary not found: {e}"
        try:
            devices = [d for d in self.adb.devices()
                       if d["state"] == "device"]
        except ApkDbgError as e:
            return f"adb not functional: {e}"
        if self.serial:
            if not any(d["serial"] == self.serial for d in devices):
                return f"device {self.serial} not attached/authorized"
        elif not devices:
            return "no adb device attached"
        elif self.serial is None:
            self.serial = devices[0]["serial"]
            self.adb = Adb(self.serial)
        try:
            self.adb.ensure_device()
            out = self.adb.shell(f"pm path {PKG}", check=False)
        except ApkDbgError as e:
            return f"device shell not usable: {e}"
        if "package:" not in out:
            return (f"fixture not installed: adb -s {self.serial} "
                    f"install -r {FIXTURE_DIR / 'crypto_fixture.apk'}")
        return None

    # -- scenarios --------------------------------------------------------
    def logcat(self) -> str:
        return self.adb.shell(f"logcat -d -s {LOGCAT_TAG}:I", check=False)

    def run_broadcast_scenario(self, name: str, action: str,
                               extras: list[str],
                               expected: list[str]) -> dict:
        self.adb.shell("logcat -c", check=False)
        cmd = " ".join(["am", "broadcast", "-a", action, "-p", PKG,
                        *extras])
        self.adb.shell(cmd)
        deadline = time.time() + 20
        log = ""
        while time.time() < deadline:
            time.sleep(0.5)
            log = self.logcat()
            if " ok" in log or " failed" in log:
                break
        missing = [e for e in expected if e not in log]
        status = PASS if not missing else FAIL
        detail = {"missing_ground_truth": missing} if missing else {}
        if " failed" in log:
            status, detail = FAIL, {"logcat_reports_failure": True}
        detail["logcat_tail"] = log.strip().splitlines()[-12:]
        return {"status": status, **detail}

    def run_jdwp_connect(self) -> dict:
        """Live JDWP attach through adb forward: handshake + IDSizes +
        Version against the fixture process, then clean up ONLY this
        session's forward."""
        try:
            pid = self.adb.wait_pid(PKG, timeout=10)
        except ApkDbgError:
            # broadcast RUN starts the process via its receiver
            self.adb.shell(f"am broadcast -a {PKG}.RUN -p {PKG}")
            try:
                pid = self.adb.wait_pid(PKG, timeout=10)
            except ApkDbgError as e:
                return {"status": INFRA_SKIP,
                        "reason": f"fixture process not running: {e}"}
        port = self.adb.forward_jdwp(pid)
        client = JdwpClient("127.0.0.1", port, timeout=10)
        try:
            client.connect()
        except JdwpConnError as e:
            return {"status": FAIL, "error": str(e),
                    "hint": "is the installed fixture build debuggable?"}
        finally:
            client.close()
            self.adb.remove_forward(port)
        info = client.handshake_info
        if not info.get("vm_name"):
            return {"status": FAIL, "error": "empty Version reply"}
        return {"status": PASS, "pid": pid, "port": port,
                "vm": info.get("vm_name"),
                "jdwp": f"{info.get('jdwp_major')}."
                        f"{info.get('jdwp_minor')}"}

    # -- driver -----------------------------------------------------------
    def run(self) -> int:
        skip = self.check_infrastructure()
        if skip:
            names = [n for n, *_ in SCENARIOS] + ["jdwp_connect"]
            self.results = {n: {"status": INFRA_SKIP, "reason": skip}
                            for n in names}
        else:
            props = {}
            for k in ("ro.product.model", "ro.build.version.release",
                      "ro.build.version.sdk"):
                props[k] = self.adb.shell(f"getprop {k}", check=False)
            print(json.dumps({"device": self.serial, "props": props}))
            for name, action, extras, expected in SCENARIOS:
                try:
                    self.results[name] = self.run_broadcast_scenario(
                        name, action, extras, expected)
                except ApkDbgError as e:
                    self.results[name] = {"status": FAIL,
                                          "error": str(e)}
            self.results["jdwp_connect"] = self.run_jdwp_connect()

        counts = {}
        for r in self.results.values():
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        summary = {"results": {n: r["status"]
                               for n, r in self.results.items()},
                   "counts": counts}
        print(json.dumps(summary, indent=1))
        for name, r in self.results.items():
            if r["status"] == FAIL:
                print(f"--- {name} detail ---", file=sys.stderr)
                print(json.dumps(r, indent=1), file=sys.stderr)
        return 1 if counts.get(FAIL) else 0


def main() -> int:
    serial = sys.argv[1] if len(sys.argv) > 1 else None
    return Runner(serial).run()


if __name__ == "__main__":
    sys.exit(main())

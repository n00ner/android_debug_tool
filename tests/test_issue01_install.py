"""Offline regression tests for issue #1 — installed console entry point.

Pre-fix, the wheel installed but `apkdbg` died with
`ModuleNotFoundError: apkdbg.cli` because the entry point targeted a
module that was never packaged. This test performs the exact reproduction
from the issue: build a wheel, install it into a CLEAN venv (no
--system-site-packages, so nothing leaks in from the checkout), and run
`apkdbg --help` from a different working directory.

Offline operation: the wheel is built with `pip wheel --no-deps
--no-build-isolation` (uses the setuptools already present in the running
environment instead of downloading a build backend), the venv is created
by `python -m venv` (pip inside comes from ensurepip's bundled wheels),
and installation uses `pip install --no-index`. No network is touched.
The test SKIPS cleanly when any of that infrastructure is unavailable
(missing setuptools, venv/ensurepip disabled, pip absent in the venv).
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import venv
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=300, **kw)


class InstallSmokeTest(unittest.TestCase):
    def test_issue1_wheel_installs_and_entry_point_runs(self):
        with tempfile.TemporaryDirectory(prefix="apkdbg-inst-") as tmp:
            tmp = Path(tmp)
            wheel_dir = tmp / "wheels"
            wheel_dir.mkdir()
            build = _run([sys.executable, "-m", "pip", "wheel",
                          "--no-deps", "--no-build-isolation",
                          "-w", str(wheel_dir), str(REPO_ROOT)])
            if build.returncode != 0:
                self.skipTest("cannot build wheel offline "
                              f"(setuptools present?): {build.stderr[-300:]}")
            wheels = list(wheel_dir.glob("apkdbg-*.whl"))
            self.assertEqual(len(wheels), 1,
                             f"expected exactly one apkdbg wheel: {wheels}")
            # the packaged module set must include the entry-point target
            import zipfile
            names = zipfile.ZipFile(wheels[0]).namelist()
            self.assertIn("apkdbg/cli.py", names,
                          "entry point target must be packaged in the wheel")

            venv_dir = tmp / "venv"
            try:
                # no system site packages: the checkout must NOT leak in
                venv.create(venv_dir, with_pip=True)
            except Exception as e:  # ensurepip disabled, etc.
                self.skipTest(f"venv creation unavailable: {e}")
            scripts = venv_dir / ("Scripts" if sys.platform == "win32"
                                  else "bin")
            vpy = scripts / ("python.exe" if sys.platform == "win32"
                             else "python")
            if not vpy.exists():
                self.skipTest("venv python missing (ensurepip disabled?)")

            # --no-index: prove installation needs no network
            inst = _run([str(vpy), "-m", "pip", "install", "--no-index",
                         str(wheels[0])])
            if inst.returncode != 0 and "pip" in inst.stderr.lower():
                self.skipTest(f"venv has no usable pip: {inst.stderr[-300:]}")
            self.assertEqual(inst.returncode, 0, inst.stderr[-500:])

            script = scripts / ("apkdbg.exe" if sys.platform == "win32"
                                else "apkdbg")
            self.assertTrue(script.exists(),
                            f"console script not installed: {script}")
            # run from OUTSIDE the checkout: importing from the repo root
            # would mask a packaging failure (the original bug)
            help_rc = _run([str(script), "--help"], cwd=tmp)
            self.assertEqual(help_rc.returncode, 0,
                             f"apkdbg --help failed: {help_rc.stderr[-500:]}")
            self.assertIn("usage: apkdbg", help_rc.stdout)
            # and the import really comes from the venv, not the checkout
            probe = _run([str(vpy), "-c",
                          "import apkdbg.cli, sys; "
                          "sys.exit(0 if r'" + str(venv_dir) + "' in "
                          "apkdbg.cli.__file__ else 3)"], cwd=tmp)
            self.assertEqual(probe.returncode, 0,
                             "apkdbg.cli did not resolve inside the venv")


if __name__ == "__main__":
    unittest.main()

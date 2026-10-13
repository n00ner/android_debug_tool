# Optional device integration tests

`run_fixture_scenarios.py` replays the crypto fixture's broadcast
scenarios (RUN / STRINGS / BENCH / FW_STORE / FW_SVC / FW_BENCH /
BUFFERS / UNPACK) against an attached Android device, checks the logcat
ground truth, and performs one live JDWP attach through `adb forward`.
It is **optional**: the offline suite
(`python -m unittest discover -s tests`) never requires it, CI never
runs it, and the filename is intentionally not `test_*.py` so unittest
discovery does not collect it.

## Setup

```bash
adb devices                                    # device authorized?
adb -s <serial> install -r tests/fixtures/crypto/crypto_fixture.apk
```

No apkdbg project, apktool, or jadx is needed — the runner uses only the
public device APIs (`apkdbg.device.adb.Adb`,
`apkdbg.device.jdwp.JdwpClient`).

## Run

```bash
python tests/integration/run_fixture_scenarios.py [serial]
```

Output: one JSON device-info line, then a JSON summary with a status per
scenario:

- `pass` — scenario ran and its logcat ground truth matched
- `fail` — scenario ran but ground truth was missing/mismatched
  (detail, including the logcat tail, goes to stderr); exit code 1
- `unsupported` — the device/VM cannot run the scenario
- `infrastructure-skip` — no adb binary, no attached/authorized device,
  or the fixture APK is not installed; every scenario reports the same
  reason and the exit code stays 0

Expected results per scenario are documented in
`tests/fixtures/crypto/README.md`; full JDWP-level validations (crypto
hooks, watchers, coverage, buffer export, unpack discovery) are covered
by the per-issue reports in `tests/fixtures/issueNN_validation.md`.

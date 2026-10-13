# Crypto fixture APK (`crypto_fixture.apk`)

Debuggable test APK (`com.apkdbg.cryptofixture`) used by the live
validation harnesses and the optional device integration runner
(`tests/integration/`). Everything needed to rebuild it from scratch is
checked in — no private files.

## Target platform

- **min SDK 24, target SDK 35** (set in `build.sh` / `AndroidManifest.xml`)
- compiled against **android-30** `android.jar` (newer platform jars carry
  a `resources.arsc` too new for aapt2 30.0.3)
- DEX-only, **no native code** — the APK runs on any ABI (arm64-v8a,
  armeabi-v7a, x86_64, …); validated on a POCO 23124RA7EO (Android 15,
  API 35, ART/JDWP 1.8)
- signed with a throwaway debug key that `build.sh` generates itself
  (`out/debug.keystore`, git-ignored); no private keys are required

## Build

Prerequisites: Zulu JDK 21 (`javac`/`java`/`keytool`), Android SDK
build-tools 30.0.3 (`d8.jar`, `aapt2`, `zipalign`, `apksigner.jar`),
platform android-30. Tool paths are pinned at the top of `build.sh`
(Windows Git Bash); adjust `JAVA_HOME`/`SDK` for your host.

```bash
./build.sh            # javac -> d8 -> payload DEX + AES asset -> aapt2
                      # -> zipalign -> apksigner sign+verify
```

`build.sh` also regenerates `assets/encrypted_dex.bin` (AES-128-CBC of
the payload DEX, key/iv pinned in the script) and
`payload_ground_truth.json` (key, iv, plaintext length + SHA-256).

`proj/` (apkdbg mapping DB) and `out/` (build intermediates) are
generated and git-ignored; sources, manifest, build script, signed APK,
vectors, and validators are committed.

## Broadcast scenarios and logcat ground truth

All scenarios are triggered by explicit broadcasts to
`com.apkdbg.cryptofixture` (see `RunReceiver.java`) and log their ground
truth to logcat tag **`CryptoFixture`** (priority I). Expected lines:

| Action | Ground-truth logcat lines | Exercises |
|---|---|---|
| `…cryptofixture.RUN` | `cipher.input=…`, `cipher.output=…`, `mac.*`, `digest.*`, `RUN ok` | AES-CBC + HMAC + SHA-256 vectors; must match `vectors.json` (verified against `_validate.py` run, `validation.md`) |
| `…cryptofixture.STRINGS` | `strings.url=…`, `strings.builder=…`, `strings.ctor=…`, `strings.reflect=…`, `STRINGS ok` | string-watcher paths incl. documented StringBuilder bypasses (#26) |
| `…cryptofixture.BENCH` (`--ei iters N`, default 200000) | `BENCH iters=N acc=…` | `StringWork.hotLoop` benchmark workload (#26) |
| `…cryptofixture.FW_STORE` | `FW store.commit=…`, `FW STORE ok` | framework watcher: SharedPreferences (#27) |
| `…cryptofixture.FW_SVC` | `FW SVC ok am=… sm=…` | framework watcher: system services (#27) |
| `…cryptofixture.FW_BENCH` (`--ei iters N`) | `FWBENCH iters=N acc=…` | framework watcher benchmark (#27) |
| `…cryptofixture.BUFFERS` | `BUFFER <name> kind=… range=…`, `BUFFER readOnly kind=…`, `BUFFERS ok` | deterministic buffer corpus for byte[]/heap-ByteBuffer export (#38) |
| `…cryptofixture.UNPACK` | `UNPACK case=… expected=… actual=…`, `UNPACK payload.len=…`, `UNPACK ok` | encrypted DEX payload discovery; plaintext matches `payload_ground_truth.json` (#28) |

## Expected validation results

- `validation.md` — issue #21 crypto-hook run: 716 hits / 60 broadcasts,
  all vectors matching, zero capture/cleanup errors, app responsive after.
- `issueNN_validation.md` files in `tests/fixtures/` — per-issue live
  results against this fixture (#25–#29, #31–#38).
- `tests/integration/run_fixture_scenarios.py` replays the broadcast
  scenarios above against an attached device and checks the logcat ground
  truth (see `tests/integration/README.md`).

## Reproduce from a fresh checkout

```bash
./build.sh                                     # rebuild + sign the APK
adb -s <serial> install -r crypto_fixture.apk
apkdbg init --apk crypto_fixture.apk --out proj  # regenerate mapping DB
python tests/integration/run_fixture_scenarios.py <serial>
```

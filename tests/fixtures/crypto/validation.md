# Crypto hook validation — issue #21

Device: POCO 23124RA7EO, Android 15 (API 35), ART (Dalvik VM, JDWP 1.8)
Date: 2026-10-11 · Fixture: `crypto_fixture.apk` (`com.apkdbg.cryptofixture`)
Runner: `_validate.py` (fires N `com.apkdbg.cryptofixture.RUN` broadcasts
while `run_watch(capture_returns=True)` collects); raw output:
`_validate_out.json`; ground truth: `vectors.json` (AES-CBC vector
verified with openssl, HMAC/SHA-256 with Python hmac/hashlib).

## Final run (post-fix)

- 60 broadcasts sent over 120s → **716 hits** (358 entry + 358 return),
  completion reason `duration`, not truncated, 0 unrelated events,
  0 capture errors, 0 cleanup errors, breakpoint registry empty after
  teardown, app responsive after the run (logcat `RUN ok`).
- Vector comparison — all match fixture expectations:
  AES key (`SecretKeySpec.<init>` entry) == `2b7e15…f4f3c`;
  IV (`IvParameterSpec.<init>` entry) == `000102…0e0f`;
  `Cipher.init` opmode == 1 (ENCRYPT_MODE);
  `Cipher.doFinal(byte[])` entry input == plaintext block and return-phase
  return value == expected AES-128-CBC PKCS5 ciphertext
  `7649abac…aaeb731c`;
  `Mac.doFinal(byte[])` input == MSG, return == expected HMAC-SHA256;
  `MessageDigest.digest(byte[])` input == MSG, return == expected SHA-256.
- Metadata (algorithm / encoded key) captured via field reads with zero
  errors; records carry explicit `phase: entry|return` labels.

## Device findings that shaped the fix

1. **ART JDWP slot semantics** — `StackFrame.GetValues` on Android 15
   expects raw DEX register numbers (parameters in the highest registers),
   not JVM slot numbering. JVM-style slots fail with `INVALID_SLOT` /
   `TYPE_MISMATCH`. Fixed by translating through the
   `LocalVariableTable` at install time (`capture.arg_vreg_map`).
2. **Metadata-invoke self-deadlock** — with `capture_returns=True`, the
   class-scoped `METHOD_EXIT_WITH_RETURN_VALUE` requests suspend the
   invoked thread at its own method exit mid-invoke; every
   `getAlgorithm`/`getEncoded` invoke stalled until the 15s reply timeout
   (10/10 in the first run, which also capped throughput at 27 hits).
   Metadata is now read from declared fields (no invoke); invokes are
   suppressed while exit requests are armed (`can_invoke` per registry
   entry). This is the documented reentrancy policy.
3. In the pre-fix run every entry capture failed with `INVALID_SLOT` /
   `TYPE_MISMATCH` and all 10 metadata invokes timed out, capping
   throughput at 27 hits per 60 triggers; return-phase capture already
   matched vectors, which isolated the defect to entry-frame access.

## Reproduce

```bash
./build.sh                       # rebuild + sign the fixture APK
adb -s <serial> install -r crypto_fixture.apk
apkdbg init --apk crypto_fixture.apk --out proj   # regenerate the project
adb -s <serial> shell am broadcast -a com.apkdbg.cryptofixture.RUN \
    -p com.apkdbg.cryptofixture  # start the process once
python _validate.py <serial> 60 120
```

`proj/` (apkdbg project DB) and `out/` (build intermediates) are
generated and git-ignored; everything else — source, manifest, build
script, signed APK, vectors, validator, and this report — is committed.

## Issue #26 extension — string-watcher fixture paths

`StringWork` (added for the `watch_strings` watcher) is triggered by the
`com.apkdbg.cryptofixture.STRINGS` broadcast action and exercises:

  - `decryptUrl()Ljava/lang/String;` — a selected decryptor method
    returning the encrypted test URL `https://fixture.example/decrypted-url`
    (XOR 0x5A at rest); the producer-return observation target, watched
    with the custom profile
    `{"cls":"Lcom/apkdbg/cryptofixture/StringWork;","method":"decryptUrl","sig":"()Ljava/lang/String;"}`;
  - `viaBuilder(...)` — observed by the opt-in `stringbuilder.tostring`
    profile;
  - `viaNewString()` (`new String(byte[])`) and `viaReflection()`
    (`String.valueOf(char[])` via `Method.invoke`) — constructed WITHOUT
    StringBuilder: the documented bypass paths. A StringBuilder watcher
    must NOT report these; their absence from `stringbuilder.tostring`
    results is the expected, documented non-coverage, not a miss.

`com.apkdbg.cryptofixture.BENCH` (extra `iters`, default 200000) runs
`StringWork.hotLoop` — the benchmark workload for
`test_scope/_pr26_bench.py` (event rate + workload slowdown for
disabled / best_effort / attributed capture).

Rebuild after touching `src/`:

```bash
./build.sh                                   # rebuild + sign the APK
echo | apktool.bat d -f -o proj/apktool crypto_fixture.apk   # refresh smali
adb -s <serial> install -r crypto_fixture.apk
adb -s <serial> shell am broadcast -a com.apkdbg.cryptofixture.STRINGS \
    -p com.apkdbg.cryptofixture
```

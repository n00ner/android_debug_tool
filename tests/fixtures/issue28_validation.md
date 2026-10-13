# Issue #28 — runtime DEX payload discovery at loading boundaries: live validation

Declared configuration: POCO 23124RA7EO, Android 15 (API 35), fixture
`com.apkdbg.cryptofixture` rebuilt with `UnpackWork` + the AES-encrypted
payload-DEX asset (see `tests/fixtures/crypto/build.sh`; project
re-indexed). Tool: apkdbg from `fix/issue-28-unpack-discovery`.
Harness: `test_scope/_pr28_live.py`.

Scenario: fixture launched under `set-debug-app -w` (parked at the attach
wait); `DebugSession.connect`; unpack boundaries armed BEFORE the VM
resumes (default `InMemoryDexClassLoader` ctor overloads + the explicitly
selected `Cipher.doFinal(byte[])` overload); fire-and-forget
`com.apkdbg.cryptofixture.UNPACK` broadcast; `vm_resume`;
`unpack.run_watch(duration=30, record=True, index=True)` collects.
Ground truth is derived host-side: `_aes.cbc_decrypt` of the committed
`assets/encrypted_dex.bin` (key/iv in `payload_ground_truth.json`)
equals the fixture's logcat `UNPACK payload.sha256=` line.

Ground truth: payload DEX 684 bytes, plaintext SHA-256
`74d8f1eee01fe8d1b8cf8ec36c2c7556db43a4d8f207f71a6e73c7cdf9d07749`
(DEX version 038).

## Results (all checks passed — PR28_LIVE_PASSED)

- `cipher_validated`: the `Cipher.doFinal(byte[])` decryption output was
  discovered, exported (684/684 bytes), and FULLY validated (header,
  section bounds, endian tag, Adler-32 checksum, SHA-1 signature) —
  SHA-256 identical to ground truth; algorithm context
  `AES/CBC/PKCS5Padding` captured via field reads (no invokes).
- Loader cases: on ART the `<init>(ByteBuffer)` ctor delegates to
  `<init>(ByteBuffer[])`, so single-buffer cases hit BOTH boundaries —
  13 observations in the declared order, all matching:
  - `heap_single` / `heap_array` / `heap_duplicate`: `validated`,
    deduplicated by content hash against the cipher artifact (one unique
    artifact on disk, every observation retained);
  - `fake_magic` (magic + version, garbage header): `invalid`, decisive
    structural rejection (header_size/endian/section-bounds errors),
    never exported as a dump;
  - `non_dex`: `not_dex`; `empty`: `empty`;
  - `direct` (`Ljava/nio/DirectByteBuffer;`): `unsupported` capability
    result (`direct_or_native`) — the loader accepts it natively
    (`loaded=true` in logcat) while the tool reports the capability
    boundary instead of faking a dump.
- `single_artifact` + `artifact_byte_identity`: exactly one `.dex` on
  disk, bytes identical to the host-decrypted plaintext; JSON sidecar
  present (metadata only, no payload inline).
- `run_manifest`: run kind `unpack_watch`, 14 `unpack_observation`
  events, 1 `unpack_dex` artifact with complete metadata.
- `indexed` / `unpack_index_*`: the validated artifact registers into
  `runtime_artifacts` (hash-keyed; repeat registrations increment
  `observations`, static index untouched: 0 added classes/methods).

Unit-level coverage (header/full validation matrix, entropy as
non-gating evidence, candidate-vs-validated distinction, dedup,
size/run-byte/candidate/event budgets, cancel/incomplete cleanup,
corpus precision report, manifest + indexing) is in
`tests/test_issue28_unpack.py` (37 tests; suite 424 green).

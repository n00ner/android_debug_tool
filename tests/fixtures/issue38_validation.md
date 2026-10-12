# Issue #38 — bounded byte[]/heap-ByteBuffer export: live validation

Declared configuration: POCO 23124RA7EO, Android 15 (API 35), fixture
`com.apkdbg.cryptofixture` (rebuilt with `BufferWork`; project re-indexed:
7 classes, 40 methods). Tool: apkdbg from `fix/issue-38-buffer-export`.
Harness: `test_scope/_pr38_live.py`.

Scenario: `BUFFERS` broadcast under `set-debug-app -w` builds and retains a
deterministic corpus (64 KiB LCG byte[], heap view pos 4096/lim 61440,
slice, nested slice, zero-length array, read-only view, direct buffer);
VM suspended; static field handles resolved via `ReferenceType.GetValues`;
`export_buffer` run for each case. Ground truth recomputed host-side
(matches the fixture's logcat `BUFFER … sha256=` lines).

## Results (all checks passed)

- `array_full`: 65536 bytes, SHA-256 `edda7126…27fe8` — identical to ground
  truth; `complete=true`.
- `array_range` (offset 100, length 500): bytes equal corpus[100:600].
- `heap_view`: default `[position, limit)` → SHA `40c6e15f…7886`;
  `state_preserved=true` (position/limit/mark re-read post-export).
- `slice` / `nested_slice`: offset translation through backing-array offset
  → SHA `f5099e06…2f1a` / `58e9f3eb…753d`.
- `empty`: 0 bytes, SHA of empty input, `complete=true`.
- `direct` (`Ljava/nio/DirectByteBuffer;`): `E_CAPABILITY`
  "direct/native … not heap-backed … unsupported in v1", no file created.
- `readOnly`: `E_CAPABILITY` — on this ART `asReadOnlyBuffer()` returns
  plain `Ljava/nio/HeapByteBuffer;` (no `…R` subclass); read-only-ness is an
  instance boolean field `isReadOnly` on `java.nio.ByteBuffer`, now detected
  by the adapter (flag-field rule + structural R-subclass rule). No file.
- `oob_rejected`: negative range → `E_SESSION` before any artifact exists.
- `stale_epoch`: wrong epoch → `StaleHandleError`.
- Export results carry byte counts, SHA-256, source range, timing
  (elapsed_ms/jdwp_requests/chunks), and `consistency.atomic_snapshot=false`
  with the suspension-scope note.

Unit-level coverage (chunk math, disk-full/cancel cleanup, keep_partial,
libcore layouts, run/artifact provenance) is in
`tests/test_issue38_buffer_export.py` (31 tests; suite 372 green).

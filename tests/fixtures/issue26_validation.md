# Issue #26 live validation

Device: POCO 23124RA7EO (serial 4b79a217), Android 15 / API 35.
Fixture: `com.apkdbg.cryptofixture` rebuilt with `StringWork`
(decryptUrl / viaBuilder / viaNewString / viaReflection / hotLoop) and
STRINGS/BENCH broadcast actions (manifest fix included).

## Attributed mode (SP_EVENT_THREAD, scope com.apkdbg.*)

`run_watch(profiles=[fixture.decryptUrl, stringbuilder.tostring],
mode="attributed", defer=True)` + STRINGS broadcast:

- states: both profiles `installed`; counts `{received: 26, filtered: 20,
  matched: 6, reads: 24}`, reason `duration`, errors []
- **requested target observed**: `fixture.decryptUrl` →
  `https://fixture.example/decrypted-url`, attributed to
  `StringWork.runAll` (full class/method descriptors + bytecode index)
- StringBuilder captures with correct texts and per-callsite attribution
  (`viaBuilder`, `runAll`); `no_app_frame` reported with an explicit
  reason where no in-scope frame exists — never a fabricated caller
- bypass paths documented live: `viaNewString`/`viaReflection` strings
  (`ctor-built-secret`, `reflect-built-secret`) are NOT observed as
  constructions — they only appear inside the `Log.i` concatenation text
  (which itself uses StringBuilder), demonstrating the declared coverage
  boundary

## Best-effort mode (SP_NONE)

`{received: 20, filtered: 15, matched: 5, reads: 5}`, reason `duration`.
No suspensions taken; object-loss is non-fatal and counted (see benchmark
`unavailable` below). Host-side filtering of same-class exits confirmed
in both modes (filtered counts).

## Persistence + offline query

Both runs recorded (`run_id` manifests with mode/scope/limits);
`strings` query: `total: 41`, page of 5, `truncated: true`.

## Benchmark (declared configuration)

POCO 23124RA7EO, Android 15 (API 35), workload `StringWork.hotLoop`,
2 reps, full JSON in `test_scope/_pr26_bench_out.json`:

| mode | iters | workload (median) | slowdown | events |
|---|---|---|---|---|
| disabled | 200000 | 2.6 s | 1x | — |
| best_effort | 200000 | 12.8 s | **4.88x** | ~18.3k received, ~2.0k matched, ~1.0k unavailable, stop `max_output_bytes` |
| disabled | 200 | 1.8 s | 1x | — |
| attributed | 200 | 45.8 s | **25.7x** | 217 received (class-scoped append exits, host-filtered) |

Numbers are configuration-specific; no universal <2x claim. Attributed
mode's per-event suspend+stack-walk cost is ~25x on a hot loop — it is
for targeted capture, not hot paths. Best-effort's object-retention race
is visible and counted (`unavailable` ≈ 5% of received).

## Regression

276 tests OK (`python -m unittest discover -s tests`), 37 new.
Fix during validation: `strings.install()` now resolves profile specs
itself (builtin names / partial dicts crashed with KeyError/TypeError).

# Issue #27 — framework watcher profiles: live validation

Declared configuration: POCO 23124RA7EO, Android 15 (API 35), fixture
`com.apkdbg.cryptofixture` (rebuilt with `FixtureActivity`, `SecondActivity`,
`CustomEditor`, `FrameworkWork`). Tool: apkdbg from
`fix/issue-27-framework-watchers`.

## Scenarios (driven via `am start -D` + `set-debug-app -w`, watchers installed before `vm_resume`)

### navigation
- 8 profiles installed; 8 matched records.
- Lifecycle events for `FixtureActivity` and `SecondActivity` (`onCreate`,
  role=`lifecycle`).
- `startActivity` request records carry intent targets and correct caller
  attribution for all three call paths: `ContextWrapper.startActivity`,
  `ContextImpl` (`navPaths`), and a direct `startActivity` override.

### storage
- 14 matched records, 6 transactions on the fixture preferences file:
  - E1: `apply()` with 3 staged puts → submitted transaction.
  - E2: `commit()` → transaction with `result=true`.
  - E3: staged but never submitted → reported `discarded: true`.
  - E4/E5: two concurrent editors on one file kept separate by editor identity.
  - E6: `clear()` + `apply()` captured.

### services
- 64 matched `getSystemService` records; `lookup_summary` aggregation surfaces
  hot repeats (alarm ×12, input_method ×24).

## Overhead benchmark (same device; `FrameworkWork.benchLoop`, storage+services families)

Workload: SharedPreferences edit/apply + `getSystemService` per iteration.
Metric: wall time VM resume → `FWBENCH iters=` logcat line. Ratios are on
this configuration only — no universal cost is promised.

| mode | iters | median workload_ms | slowdown vs disabled | matched events | dropped |
|---|---|---|---|---|---|
| disabled | 50000 | 11622.0 | 1.0 | — | — |
| best_effort | 50000 | 37273.0 | 3.207 | 2042/rep | 0 |
| disabled | 50 | 1770.5 | 1.0 | — | — |
| attributed | 50 | 11342.4 | 6.406 | 202/rep | 0 |

- best_effort watch ended on the output-byte budget (`max_output_bytes`) after
  ~27.7k received events; `unavailable` ≈ 3.6k (expected: best_effort events
  have no valid frames by design).
- attributed watch ended on cancel/duration with 0 dropped, 0 unavailable.

### 60s responsiveness run (attributed watcher active, 20-iter shot every ~2s)
- 10/10 shots completed; median 3265.9 ms, max 3555.5 ms per shot.
- 11354 received / 806 matched events, 0 dropped, 0 unavailable, no errors;
  watch ended on its 60s duration — the loop keeps up with a sustained
  event stream.

Raw numbers: `test_scope/_pr27_bench_out.json` (harness
`test_scope/_pr27_bench.py`).

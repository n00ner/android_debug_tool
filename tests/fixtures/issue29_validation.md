# Issue #29 — coverage_diff: live validation

Declared configuration: POCO 23124RA7EO, Android 15 (API 35), fixture
`com.apkdbg.cryptofixture` (project re-indexed from the current APK).
Tool: apkdbg from `fix/issue-29-coverage-diff`. Harness:
`test_scope/_pr29_live.py` (idempotent — cleans prior `pr29*` runs).

Scenario capture: four labeled line-coverage runs, each in a fresh process
(CLASS_PREPARE hold + `CoverageTracker`, 20 s): `pr29aa` ×2 (RUN
broadcast), `pr29run` ×1 (RUN), `pr29strings` ×1 (STRINGS). Diff is fully
offline afterwards.

## Results (all checks passed)

- **Branch persistence**: `coverage_branch_sites` rows with separate
  `taken`/`fallthrough`/`site_hits` integer columns and `unknowns` JSON
  (`{reason: count}`); site identity is the descriptor-level `site_key`
  (`class->name(desc):dalvik_line:smali_line`) — no local integer site
  ids. Repeated `report()` adds zero rows (idempotent).
- **A/A baseline** (`pr29aa` vs `pr29aa`): same-label split engaged,
  zero direction changes, no fabricated differences.
- **A/B** (`pr29run` vs `pr29strings`): compatible; ranked candidates are
  dominated by `presence` changes (score 1.0, high confidence): disjoint
  code paths — `StringWork.decryptUrl`/`runAll` lines+sites only in the
  STRINGS run; `RunReceiver.hex`/crypto lines and the later `onReceive`
  equals-chain sites only in the RUN run.
- **Conservative direction handling**: ART's line table places two sites
  on the equals-chain source line, so those transitions are stored as
  `ambiguous_line` unknowns — the diff surfaces the sites but does NOT
  fabricate a direction change from unknown evidence
  (`ab_unknown_not_fabricated`).
- **Quality**: `exact_subtraction=false` always; degraded runs would
  carry warnings + lowered confidence.
- **Determinism**: two consecutive `coverage_diff` calls byte-identical.
- **Compatibility gate**: doctoring one side's `apk_sha256` → rejected by
  default with machine-readable `compatibility.differences`;
  `exploratory=True` returns an annotated intersection (`ranked` present,
  explicitly not equivalent coverage).

Unit-level coverage (27 tests): persistence idempotency, re-index
carry-over, within-spread noise suppression, unknown-never-fabricated,
degraded-run warnings, compatibility matrix, artifact fallback for
legacy/method-mode runs, stable pagination, score ordering.

# Issue #34 — cancellable background jobs: live smoke validation

Declared configuration: POCO 23124RA7EO, Android 15 (API 35), fixture
`com.apkdbg.cryptofixture`, server `apkdbg serve` (JSON-RPC over stdio)
against the fixture project. Tool: apkdbg from
`fix/issue-34-background-jobs`. Harness: `test_scope/_pr34_live.py`.

Scenario: `FW_STORE` broadcast parked at the debug-wait; `connect`;
`job_start watch_framework` (storage family, best_effort, 120 s,
max_records=100); `resume`; control requests while the worker runs;
cancel mid-capture.

## Results (all checks passed)

- `job_start` → `operation_id`, state `running`, limits echoed.
- **Responsiveness**: `job_status` answered in 0.05 s while the worker was
  capturing (state `running`).
- **Ownership conflict**: `events` during the job → retryable
  `E_JOB_CONFLICT` naming the owning operation.
- **Bounded read pages**: page 1 returned 10 records; page 2 via cursor
  accepted, bounded (4 records).
- **Cooperative cancel**: after `job_cancel`, status converged to
  `state=cancelled`, `outcome.reason=cancellation`, `incomplete=true`
  (terminal record immutable; polled, landed within the ~1 s sliced-wait
  bound).
- **Exact counts**: `received=14, retained=14, dropped=0, expired=0`,
  buffer bytes reported.
- **Idempotent cancel**: second `job_cancel` returns cleanly.
- **Records retained post-cancel**: `job_read` still pages.
- **Session reusable**: `bp_list` succeeds immediately after the terminal
  state.

Offline acceptance coverage (fake event sources): status/cancel latency
bound, cancel during capture and during output writing, flood within
memory limits with exact retained/dropped counts, cursor dup/omission and
expiry errors, concurrent-job conflict rules, bounded completed-job
retention — `tests/test_issue34_jobs.py` (15 tests; suite 387 green).

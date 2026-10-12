# Issue #32 validation

## Offline suite (fault injection, deterministic)

199 tests OK (`python -m unittest discover -s tests`), 26 new:

- **outcome_unknown**: fake peer applies an invoke then drops the reply →
  invocation counter stays 1, caller receives `E_OUTCOME_UNKNOWN`
  (`outcome: "unknown"`, op name, fault phase, epoch, recovery state) —
  never a transparent replay.
- **Fault-phase matrix**: pre-dispatch / transmit / post-send ×
  read / idempotent / state-changing → documented distinct behavior
  (phase tagged in `JdwpClient.request`).
- **Epoch invalidation**: reconnect clears registry/sig-cache/stash;
  numeric rid reuse gets new-epoch stamps; stale `read_var` →
  `E_STALE_HANDLE` with re-acquire hint; symbolic defs survive.
- **Symbolic restore**: `restore` re-installs from symbolic defs with NEW
  request ids, reports installed/pending/failed/deferred accurately,
  never resurrects explicitly cleared defs, idempotent within an epoch.
- **Process died vs transport**: pid change → `E_PROCESS_DIED`
  (no forward rebuild); same-pid transport loss → recoverable.
- **Scoped recovery**: adb call-log assertions — recovery touches only
  the session's own forward (never another session's), no automatic
  `adb kill-server` even when plain+reconnect fail; kill-server only via
  explicit `connect --recovery kill-server`.

## Device note

The live recovery scenario (transport kill → scoped reconnect →
E_STALE_HANDLE → restore with new rid → breakpoint fires) was scripted
(`test_scope/_pr32_live.py`) but the validation device's USB link dropped
before the run and did not recover in time. The behaviors it exercises
are covered deterministically by the fault-injection suite above; the
device run will be appended when the link is stable.

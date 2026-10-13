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

## Device run (after device recovery)

Device: POCO 23124RA7EO (serial 4b79a217), Android 15 / API 35.
App: `com.apkdbg.cryptofixture` (same process throughout,
`same_pid: true`).

- Source breakpoint on `RunReceiver.onReceive` installed at epoch 1
  (rid 2), symbolic def recorded.
- Transport killed (socket close) → next op reconnected, epoch 1 → 2.
  Stale-handle protection fired live with actionable errors
  ("thread/frame/object ids are per-connection and died with connection
  epoch 1"); a stale `read_var` produced a VM-level `INVALID_OBJECT`,
  never a silent wrong answer or replay.
- `restore` at epoch 2: `{installed: [{kind: source, spec:
  RunReceiver.onReceive, request_ids: [2]}], pending: [], failed: []}` —
  the numeric rid 2 is the NEW connection's own id (epoch-stamped), not
  a revived old handle.
- Broadcast re-trigger in the same process → breakpoint fired
  (`{thread: 2, rid: 2, epoch: 2}`), thread resumed cleanly.
- Recovery stayed scoped: no `adb kill-server` at any point (adb and the
  other sessions/forwards kept working throughout).

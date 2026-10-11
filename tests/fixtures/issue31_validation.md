# Issue #31 live validation

Device: POCO 23124RA7EO (serial 4b79a217), Android 15 / API 35, ART.
Fixture: `com.apkdbg.cryptofixture` (broadcast-driven crypto ops) and
`com.wolfs.myapplication`.

## A. Routing + suspension lease (crypto watch vs user breakpoint)

User breakpoint on `RunReceiver.onReceive` (SP_EVENT_THREAD, owner `user`)
registered, then a crypto watch (`Cipher.init(int,Key)`,
`SecretKeySpec.<init>(byte[],String)`, capture_returns=True) ran while the
RUN broadcast fired:

- watch result: 4 hits (entry+return for both hooks), `unrelated: 1`,
  no errors, no cleanup errors
- the user-bp stop was **stashed, not consumed**: `stashed_user_bp: 1`;
  the watch never resumed its thread — the caller drained the stash and
  resumed it (`caller_resumed_threads: 1`), after which `onReceive`
  proceeded and the crypto hooks fired inside the same watch window
- both owners received only their own events from one event stream

## B. Deferred install via CLASS_PREPARE

wolfs launched with `am start -D`; at attach time none of its classes were
loaded. `defer_hook("validate", "wolfs-main", "com.wolfs.myapplication.*")`
registered one CLASS_PREPARE request (rid 2). After the VM proceeded:

- 4 matching classes prepared (`MainActivity`, `DeviceAdapter`,
  `R$layout`, `R$id`) — the install callback ran **exactly once per
  type_id** (`seen: 4`, 4 callbacks, no duplicates; a further 5 s of event
  pumping produced no re-installs), `errors: []`

Note: for the crypto fixture the framework classes (`javax.crypto.*`) are
boot-classpath classes and are already loaded at attach, so
`install(defer=True)` installs immediately — the deferred path is for
app classes, validated above and by unit tests (delayed class, two
classloader instances, dedupe).

## C. Epoch invalidation across reconnect

With a live request (rid 18) from epoch 1, a full reconnect
(`session._attach()`) bumped the dispatcher epoch 1 -> 2.
`clear_request(18)` afterwards:

```json
{"cleared": 18, "kind": 2, "was": null, "status": "unconfirmed",
 "note": "no live request with this id in the current connection epoch;
          remote state left untouched"}
```

No clear was sent to the remote for the stale numeric id (which the new
connection may legitimately reuse).

## Regression

`python -m unittest discover -s tests` — 69 tests OK (16 new dispatcher
tests: epoch isolation, fan-out, lease once-only release, deferred dedupe,
cleanup on failure/cancellation, phase/kind separation, coverage consumer).

Behavior change (intended, per issue): the crypto watch no longer resumes
threads from events it does not own; unrelated stops are stashed for the
`wait_events` caller, who owns resume responsibility.

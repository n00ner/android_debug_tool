# Static invocation (ClassType.InvokeMethod 3/3) — issue #23 investigation

Date: 2026-10-11 · Runner: `_issue23_repro.py` · Raw: `_issue23_out.json`
Runtimes: POCO 23124RA7EO, Android 15 (API 35), ART (Dalvik VM, JDWP 1.8,
target `com.apkdbg.cryptofixture`); desktop control Zulu JDK 21
(`StaticControl`, JDWP agent `server=y,suspend=y`). Negotiated ID sizes:
8 bytes for all ID kinds on both runtimes.

## Confirmed evidence

| Setup | Runtime | options | Result | Connection after |
|---|---|---|---|---|
| Event-suspended thread (breakpoint, `SP_EVENT_THREAD`, suspend_count=1, thread_status=RUNNING, suspend_status=SUSPENDED) | Android 15 | 1 (`SINGLE_THREADED`) | app-local `RunReceiver.hex("0aff")` → `byte[]`, exception 0 | healthy |
| same | Android 15 | 0 | same, new array object | healthy |
| same | Android 15 | 1 / 0 | platform `Integer.parseInt("42")` → 42 | healthy |
| same | desktop JVM | 1 / 0 | `StaticControl.answer("41")` → 42 | healthy |
| **Negative control**: same thread + extra `ThreadReference.Suspend` (suspend_count=2) | Android 15 | 1 | **JDWP socket closed by peer mid-invoke** | **lost** |
| Negative control (suspend_count=2) | desktop JVM | 1 | reply timeout after 15s | healthy |

Method identity was verified by `rt_methods` (declared-here, `ACC_STATIC`,
full descriptor) before each call; request bytes are byte-verified by the
offline transport tests (`tests/test_issue23_static_invoke.py`, including
non-default ID widths and tagged thrown-exception/null decoding).

## Conclusions

- **Static invocation is supported on Android 15/ART** in the verified
  setup: freshly event-suspended thread with known suspension ownership
  and suspend_count == 1, exact declaring-class + static-method identity,
  options 0 or `INVOKE_SINGLE_THREADED`. Capability state:
  *supported in tested conditions*.
- **Encoding/state tracking was not the defect** — no payload fix was
  needed; the checked `ct_invoke_method()` wrapper was added with
  declared-here static validation, epoch-scoped `rt_methods` caching, no
  fallback and no auto-retry.
- **Hypothesis for the originally reported `INVALID_THREAD`/disconnect**
  (not fully proven): the invoke was issued on a thread whose suspension
  was not (only) event-owned — e.g. an extra `ThreadReference.Suspend`
  (count ≥ 2), a stale thread ID from a previous connection epoch, or a
  thread that had been resumed. The negative control shows ART answers
  that state by dropping the socket (desktop: reply timeout), consistent
  with the original symptom of a dead connection attributed to
  `INVALID_THREAD`. A single failed invoke does NOT disable static
  invoke for the session when the connection survives (desktop case);
  on ART the connection itself must be treated as lost and re-established.
- options 0 vs 1 both succeeded; per spec, 0 resumes the whole VM during
  the invoke, 1 only the invoking thread — prefer 1 when other threads
  must stay stopped.

## Reproduce

- Android: install `tests/fixtures/crypto/crypto_fixture.apk`,
  `apkdbg init --apk ... --out tests/fixtures/crypto/proj`, then
  `python tests/fixtures/static_invoke/_issue23_repro.py <serial>`.
- Desktop control: `javac -g StaticControl.java` (done; `.class`
  committed), the script launches the JVM itself.
- Offline: `python -m unittest discover -s tests -v` (byte-level, no
  Android needed).

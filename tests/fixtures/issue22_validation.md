# Invoke/NewInstance ownership validation — issue #22

Device: POCO 23124RA7EO, Android 15 (API 35), ART (Dalvik VM, JDWP 1.8)
Date: 2026-10-11 · Target: `com.wolfs.myapplication` (debuggable;
`MainActivity extends AppCompatActivity`, does not declare `getIntent`)
Runner: `_issue22_validate.py`; raw output: `_issue22_out.json`.

## Result: PASS

1. **Checked inherited invocation** — receiver captured at the
   `MainActivity.onCreate` entry breakpoint (launch `-D` + CLASS_PREPARE
   watch). `resolve_instance_method(runtime MainActivity, "getIntent",
   "()Landroid/content/Intent;")` resolved to the DECLARING class
   `Landroid/app/Activity;` (inherited=true). `ObjectReference.InvokeMethod`
   with the (declaring class, method id) pairing and options
   `INVOKE_SINGLE_THREADED` returned a live `Intent` object (tag `L`,
   exception 0) — the exact call that disconnected the JDWP socket on
   Android 15 when sent as (subclass type id, superclass method id).
   Connection healthy afterwards (subsequent `rt_signature` round trips OK).
2. **Constructor validation without sending invalid requests** —
   `ct_new_instance(StringBuilder, thread, toString_id)` was rejected
   LOCALLY with `E_RESOLVE` ("NewInstance requires an `<init>` of class
   14, got `toString()Ljava/lang/String;`") before any NewInstance request
   was sent; the connection was untouched.
3. **Valid checked construction** — `ct_new_instance(StringBuilder,
   thread, <init>()V)` allocated object 15 (exception 0); a subsequent
   checked `toString()` invoke on it returned `""` (exception 0).
   Connection healthy at the end of the run.

Dispatch semantics: resolution walks the runtime type's superclass chain
most-derived first (overrides win), keyed by exact (name, descriptor);
classloader identity is carried by runtime type IDs, never class names.
Offline coverage (30 tests in `tests/test_issue22_invoke.py`) adds
overloads/ambiguity, nonvirtual rejection, unrelated/stale method IDs,
interface capability errors, epoch cache invalidation, and wire-layout
transport checks with unequal ID sizes.

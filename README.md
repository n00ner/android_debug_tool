# apkdbg — programmatic APK debugging backend for LLM agents

A CLI/JSON-RPC tool for advanced Android reverse engineering: java-line-accurate
breakpoints on obfuscated APKs, live memory mutation, method force-invocation,
object-graph snapshots, crypto API interception, and branch coverage — all
emitting strict minified JSON.

## Architecture

```
┌──────────────┐   JSON-RPC/stdio or CLI    ┌──────────────────────────────┐
│  LLM agent   │ ──────────────────────────▶ │  apkdbg (server.py / cli.py) │
│ (Kimi/Codex) │ ◀────────────────────────── │       commands.py            │
└──────────────┘    {"id":1,"result":...}    └───┬──────────────┬──────────┘
                                                 │              │
                              ┌──────────────────▼───┐   ┌──────▼───────────┐
                              │  debug/ (session,    │   │ core/ + decompile/│
                              │  translate, snapshot,│   │ init pipeline,    │
                              │  conditions, hooks,  │   │ mapping SQLite DB │
                              │  coverage)           │   └──────┬───────────┘
                              └───┬─────────────┬────┘          │
                          ┌───────▼──────┐  ┌───▼─────┐   ┌─────▼─────┐
                          │ device/jdwp  │  │ device/ │   │  apktool  │
                          │ (raw socket) │  │  adb    │   │   jadx    │
                          └───────┬──────┘  └───┬─────┘   └───────────┘
                                  │  adb forward tcp:P jdwp:PID
                          ┌───────▼─────────────▼─────┐
                          │      Android device       │
                          │  (debuggable APK process) │
                          └───────────────────────────┘
```

Key design decisions:

- **Custom JDWP client, not jdb automation.** `jdb` is a TTY REPL exposing a
  fraction of JDWP (no bytecode indices, no ClassMatch filters, no per-slot
  tags). `apkdbg/device/jdwp.py` speaks the wire protocol directly over
  `adb forward tcp:<port> jdwp:<pid>` — ~600 lines, zero dependencies.
- **The DEX line number is the mapping pivot.** JADX java line → *(jadx
  mapping json, when present)* → dalvik line → smali `.line N` → at runtime,
  `Method.LineTable` gives line → bytecode index → `EventRequest.Set` with a
  `LocationOnly` modifier. The runtime table is always authoritative.
- **Host-side conditions.** JDWP's Conditional modifier is unimplemented on
  ART, so `conditions.py` runs a capture→evaluate→resume loop with suspend
  policy EVENT_THREAD (other threads keep running).
- **Context-window discipline.** One minified JSON line per reply; all dumps
  are budget-capped (depth/fields/items/string/total-nodes) with explicit
  `"trunc": true` markers; progress chatter goes to stderr only. Replies are
  strict JSON (RFC 8259): non-finite JDWP float/double values are emitted as
  the string markers `"NaN"`, `"Infinity"`, `"-Infinity"`.

## Mapping database schema (`mapping.db`)

| Table | Purpose | Key columns |
|---|---|---|
| `meta` | persistent APK/index facts (written by `init`) | `schema_version`, `index_version`, `index_complete`, `index_warnings`, `line_map_state`/`line_map_reason`, `manifest_debuggable`, `apk`/`sha256`/`package` |
| `classes` | runtime class identity | `sig` (`Lcom/foo/Bar;`), `fqcn`, `deobf_fqcn`, `smali_path` |
| `methods` | methods per class | `name`, `sig`, `is_native`, smali `line_start/line_end` |
| `line_map` | `.line N` directives | `method_id`, `dalvik_line`, `smali_line` |
| `jadx_lines` | jadx java line → dalvik line | `class_id`, `java_line`, `dalvik_line` |
| `branch_sites` | parsed `if-*`/`goto`/switch | `dalvik_line`, `opcode`, `kind`, `target_dalvik_line` |
| `resources` | from apktool `public.xml` | `res_id` (0x7f… int), `type`, `name` |
| `resource_refs` | resource call sites in smali | `res_id`, `method_id`, `kind` (`getString`…) |
| `coverage_hits` | persisted coverage runs | `run_id`, `class_sig`, `method_name`, `method_sig`, `dalvik_line`, `hits` |
| `coverage_branch_sites` | persisted branch outcomes (#29) | `run_id`, `site_key` (`class->name(desc):dalvik_line:smali_line`), `site_hits`, `taken`, `fallthrough`, `unknowns` (JSON reasons) |
| `alias_candidates` | reviewable runtime alias hypotheses (#25) | `class_sig`, `candidate`, `heuristic_score`, `rule`, `status`, `evidence` |
| `alias_decisions` | full review trail per candidate | `candidate_id`, `action`, `from_status`, `to_status` |

`alias_candidates`/`alias_decisions` are strictly additive: the alias
feature never writes `classes.deobf_fqcn` or imported mappings, and
candidate text never feeds back into resolution or breakpoint targeting.

## Command surface

Stateless (CLI-safe, no live session needed): `init`, `capabilities`,
`classes`, `methods`, `res`, `res_refs`, `runs`, `snapshot_diff`,
`coverage_diff`, `aliases`, `strings`, `framework_events`, `unpack_index`,
`job_status`, `job_read`, `job_list`, `job_cancel` — plus `connect`, which
establishes the session itself. Session (use `serve` mode for multi-step):
`restore`, `bp`, `bp_del`, `bp_list`, `events`, `read_var`, `write_var`,
`invoke`, `step`, `resume`, `snapshot`, `dump_object`, `cond`,
`hook_crypto`, `watch_strings`, `watch_framework`, `coverage`, `unpack`,
`export_buffer`, `job_start`, `native`.

## Capability matrix (`capabilities`)

`capabilities` reports — **offline, no device needed, never attaches by
default** — what this project/APK can actually do, per capability:
`{"status": supported|limited|unsupported|unknown, "evidence": {...},
"source": ..., "hint": ...}`. A summary `mode` is included but the
per-capability records are authoritative.

| Capability | Status basis (offline) |
|---|---|
| `classes`, `methods`, `res`, `res_refs` | `supported` with row counts as evidence; `unsupported` with a re-index hint when a *completed* index has zero rows; `unknown` when the index never finished |
| `source_line_resolution` | `supported` when the line map has rows; `unsupported` (`no_line_directives`, likely stripped) when a *completed* index has zero rows; `unknown` (`index_incomplete` / `no_index_metadata`) when an empty map proves nothing |
| `jdwp_attach` | `unknown`/`limited` from the **manifest** `android:debuggable` fact (true/false/unknown — never conflated with the device's `ro.debuggable`, never treated as proof) |
| `runtime_line_table`, `connect`, and the runtime commands (`bp`, `bp_del`, `bp_list`, `events`, `read_var`, `write_var`, `invoke`, `step`, `resume`, `snapshot`, `dump_object`, `cond`, `hook_crypto`, `coverage`, `native`) | `unknown` pre-probe (`static_inference`), each reported individually; `bp` additionally drops to `limited` while the line map is unverified |

Persistent facts are recorded by `init` in `mapping.db`'s `meta` table
(`schema_version`, `index_version`, counts, `index_complete`,
`index_warnings`, `line_map_state`/`line_map_reason`, `manifest_debuggable`).
Zero line-map rows are **not** treated as proof of stripped debug info: an
index-generation failure records `index_incomplete` instead.

`capabilities --probe` adds **explicit, transient** live observations (never
persisted over the static facts): device presence → process presence → JDWP
attach state → observed runtime `Method.LineTable` availability
(present/absent/unknown). Observed entries flip `source` to `observed`.

Structured runtime error codes (single-line JSON, machine-readable `code` +
`hint`): `E_DEVICE_ABSENT` (no adb device), `E_PROCESS_ABSENT` (target not
running), `E_ATTACH_UNAVAILABLE` (JDWP refused after recovery ladder, e.g.
non-debuggable app), `E_LINE_MAPPING` (`bp` on an empty/incomplete line map —
hint points at smali/method-entry coordinates), `E_UNSUPPORTED` (feature not
supported for this APK/device). The recovery, job, and export codes
(`E_OUTCOME_UNKNOWN`, `E_STALE_HANDLE`, `E_JOB_CONFLICT`, `E_CURSOR_EXPIRED`,
`E_EXPORT_INCOMPLETE`, `E_CAPABILITY`) are documented in their sections
below; the full stable set lives in `apkdbg/errors.py`.

```bash
# 1. init: decompile + build mapping DB
apkdbg init --apk app.apk --out ./proj

# 2. serve: persistent JSON-RPC session for an agent
apkdbg --project ./proj serve
{"id":1,"method":"connect","params":{"pkg":"com.target.app","launch":true}}
{"id":2,"method":"bp","params":{"spec":"com.target.CryptoManager.encrypt:87"}}
{"id":3,"method":"events","params":{"timeout":120}}
{"id":4,"method":"read_var","params":{"thread":1234,"name":"plaintext"}}
{"id":5,"method":"write_var","params":{"thread":1234,"slot":2,"value":0,"vtype":"int"}}
{"id":6,"method":"invoke","params":{"thread":1234,"obj":4097,"method":"toString","sig":"()Ljava/lang/String;"}}

# conditional breakpoint: stop when a 16/24/32-byte high-entropy buffer appears
{"id":7,"method":"cond","params":{
  "spec":"com.target.Net.send:55",
  "capture":[{"slot":1,"type":"byte[]","label":"buf"}],
  "pred":{"kind":"bytes","label":"buf","len_in":[16,24,32],"min_entropy":3.5}}}

# crypto interception: dump plaintext + keys at the javax.crypto boundary
{"id":8,"method":"hook_crypto","params":{"duration":120}}

# coverage: cheap method mode, or line mode scoped to a thread
{"id":9,"method":"coverage","params":{"packages":["com.target"],"mode":"method","seconds":60}}
{"id":10,"method":"coverage","params":{"packages":["com.target.crypto"],"mode":"line","thread":1234,"seconds":30}}

# string watchers (issue #26): attributed capture at a selected decryptor,
# plus the opt-in broad StringBuilder profile — observation points only,
# never full string coverage
{"id":11,"method":"watch_strings","params":{"duration":60,"mode":"attributed","scope":"com.target.*","record":true,"profiles":[{"cls":"Lcom/target/Dec;","method":"decrypt","sig":"([B)Ljava/lang/String;"},"stringbuilder.tostring"]}}
{"id":12,"method":"strings","params":{"text":"https://","limit":20}}
```

## Runtime alias candidates (review workflow, issue #25)

Runtime strings (log tags, enum-like values, route/preference names) hint at
what an obfuscated class does, but they never establish an original
identifier. apkdbg can turn strings **already captured** by `hook_crypto`,
`snapshot`/`dump_object`, and `cond` into *reviewable* alias candidates —
opt in per capture with `collect_aliases=true` (implies `record`, since
candidates link to their run/event evidence). Optional extra reads of string
fields beyond the capture (`extra_reads` in the collector budgets) are
separately limited by depth, object count, bytes, JDWP request count, and
elapsed time; every collection report publishes the **measured** JDWP reads
and added pause time — there is no zero-overhead assumption and no universal
latency guarantee. Budget exhaustion or read failures yield partial results
with explicit reasons; suspensions stay owned by the dispatcher lease.

Heuristics are a versioned rule set (`RULES_VERSION` in
`apkdbg/core/aliases.py`): log tags, enum-like strings, route and
preference names produce candidates with a *heuristic score* (rule
strength, not a calibrated probability); a generic URL is behavioral
context only, never a name candidate. Nothing is ever auto-accepted.

Review offline with `aliases` (also a serve method):

```bash
apkdbg --project ./proj aliases list --status suggested --limit 20
apkdbg --project ./proj aliases get <candidate_id>   # evidence, source events, smali links
apkdbg --project ./proj aliases accept <candidate_id> --note "confirmed in smali"
apkdbg --project ./proj aliases revise <candidate_id> --alias PaymentRepository
apkdbg --project ./proj aliases add --class-sig 'Lcom/foo/a/a;' --alias BillingRepo
apkdbg --project ./proj aliases export --file aliases.json
```

Multiple candidates may compete per entity; accept/reject/revise are
recorded in a full decision trail, replacements supersede reversibly, and
a rejected (text, rule) pair stays suppressed on re-observation (counted
and linked, never re-suggested). Repeated observations dedupe into one row
keeping frequency (`observations`, first/last seen) and per-run/event
evidence refs. Observations from distinct classloaders of the same class
signature stay separate rows; runtime classes absent from the static index
keep evidence without a fabricated static match (`static_match: false`).

Accepted aliases surface as a distinct `alias` field next to `sig` and
`deobf` in translate resolution, breakpoint, snapshot, classes, and
coverage responses — the original machine identity is preserved everywhere
and aliases never affect method resolution or breakpoint targeting.

**Retention:** candidates, decisions, and evidence live in the project
`mapping.db`, are carried across re-indexing like the other observation
tables, and are deleted only with the project. Candidate text and evidence
may contain application data (captured strings) — treat `aliases export`
output as sensitive.

## Run manifests and snapshot diff (issue #36)

Any capture run with `record=true` (coverage, `hook_crypto`,
`watch_strings`, `watch_framework`, `snapshot`, `unpack`, `export_buffer`)
persists a **run manifest**: durable uuid, APK hash + static-index
generation, tool version, capture configuration, environment/VM metadata,
scenario label, session epoch, start/end times, completion reason. Runs,
events, and artifacts live in their own tables and are carried verbatim
across re-indexing (#35), keeping the index generation they were captured
against; runtime object ids are per-connection, so observations keep their
capture epoch and are never reinterpreted after a reconnect.

```bash
apkdbg --project ./proj runs list --kind coverage
apkdbg --project ./proj runs get <run_id>            # manifest + events + artifacts
apkdbg --project ./proj runs export <run_id> --file run.json
apkdbg --project ./proj runs import --file run.json  # --replace overwrites a run_id
```

`snapshot_diff` compares two persisted snapshots as **logical object
graphs** (structural paths + type-aware values): per-connection runtime
object ids are never compared across runs, and cycles are re-anchored to
the target's first occurrence, so equal snapshots under different runtime
ids produce no spurious changes. Results land in four disjoint buckets —
`changed`, `added`, `removed`, `unknown` (budget-truncated, inaccessible,
or absent-debug-info subtrees never masquerade as added/removed). A
compatibility check (APK identity, scope, capture settings, completeness)
runs first; incompatible captures return explicit reasons and no diff
unless `force`, and forced diffs keep every qualification in the output.

## Coverage diff (issue #29)

`coverage_diff` compares two groups of stored coverage runs selected by
label (scenario or run_id) — fully offline, deterministic for fixed stored
inputs, no JDWP involved. It ranks three change kinds with explainable
scores: `presence` (observed in one group only, scaled by within-group
consistency), `direction` (branch sites whose evidenced taken vs
fall-through edge flips between groups, scaled by edge purity vs unknown
outcomes), and `hit_count` (normalized hits per captured event whose
between-group difference exceeds both groups' within-group spread).
Unknown branch outcomes stay unknown; degraded runs (budget stops,
dropped events, cancellations) lower confidence and are listed in the
`quality` block. A ranked entry is a candidate for investigation — never
exact subtraction, and absence in a bounded trace is not proof of
non-execution.

Groups compare only when their runs share APK identity (sha256), index
generation (site identity is index-bound), capture mode, and package
scope; incompatible groups return `ranked: null` with explicit reasons
unless `exploratory`, which yields an annotated intersection — never
equivalent coverage. Passing the same label twice is an A/A baseline: the
matched runs split deterministically in half and compare against each
other, so repeat noise surfaces as low/zero scores instead of phantom
scenario differences.

```bash
apkdbg --project ./proj coverage_diff --baseline before-fix --candidate after-fix
apkdbg --project ./proj coverage_diff --baseline nightly --candidate nightly  # A/A noise
```

## Framework watchers (issue #27)

Opt-in observation profiles at selected framework method exits
(METHOD_EXIT_WITH_RETURN_VALUE). `families` enables `navigation`
(startActivity requests on Activity / ContextWrapper / ContextImpl, per
overload actually present), `storage` (SharedPreferences$Editor staged
put*/remove/clear plus apply/commit submissions, correlated per editor
instance), and `services` (getSystemService lookups counted per service
name/class); `profiles` takes builtin names, family names, or explicit
`{"cls","method","sig"}` objects and overrides `families`. Interface or
late-loaded implementations install via `defer=true` (CLASS_PREPARE
auto-install per classloader instance). `mode` is `best_effort` (SP_NONE,
no attribution/args) or `attributed` (SP_EVENT_THREAD, args + bounded
stack minus excluded framework wrappers, which are never reported as app
callers). Metadata getter invocation (`invoke_getters`) is an explicit
opt-in that runs app code on the suspended thread, honors the #21
class-scoped exit-request reentrancy policy, and never calls toString().

These are observation points with explicit per-profile coverage notes,
never full-coverage claims: an override that bypasses the superclass body
produces no event at that class, an observed request is not a confirmed
navigation (lifecycle profiles only fire when the concrete activity calls
the superclass body), a staged edit is not persisted data (an editor with
edits and no observed submission is reported DISCARDED in the derived
transaction view), and a service lookup is a capability request, not use.
Records persist as a run manifest with `record=true`; query them offline
with `framework_events` (filters: `run_id`, `family`, `profile`, `role`).

```bash
{"id":13,"method":"watch_framework","params":{"duration":60,"families":["navigation","storage"],"mode":"attributed","scope":"com.target.*","record":true}}
{"id":14,"method":"framework_events","params":{"family":"storage","limit":50}}
```

## Bounded buffer export (issue #38)

`export_buffer` pulls a `byte[]` or heap ByteBuffer to a host file over
pure JDWP reads — chunked `ArrayReference.GetValues` through a running
SHA-256 into a temp file, published by atomic rename only after the last
byte is hashed, so host memory stays bounded at any export size. ByteBuffer
ranges default to `[position, limit)` translated through the backing-array
offset (OpenJDK-style and libcore-style layouts are both recognized, never
assumed; nested slices work). Read-only views, direct/native buffers, and
unknown implementations fail with `E_CAPABILITY` — never silently wrong
bytes. Budgets: `max_bytes` rejects an over-long range before any file is
created unless `capped=true` deliberately requests a bounded preview
(reported `export_kind:"capped"`, `complete:false`); `deadline` aborts with
the partial temp file removed unless `keep_partial`; an aborted export
surfaces as `E_EXPORT_INCOMPLETE`, never as complete. An export is not an
atomic snapshot — suspending the event thread does not stop other writers;
the `consistency` block records this, and for ByteBuffers the
position/limit/mark triple is re-read afterwards (`state_preserved`).

```bash
{"id":15,"method":"export_buffer","params":{"obj":4097,"epoch":2,"max_bytes":4194304,"record":true}}
```

## Runtime DEX unpack discovery (issue #28)

EXPERIMENTAL observation of DEX payloads at Java-visible loading/decryption
boundaries — **not** a universal unpacker (native payloads, unsupported
loaders, split writes, and never-stable buffers produce capability/partial
outcomes, never fake success). `boundaries` selects
`in_memory_dex_class_loader` (the default; consumed bytes are each buffer's
`[position, limit)` window, exported through the #38 exporter with distinct
support per buffer kind), `dex_class_loader_path` (file-path evidence only,
no memory recovery promised), or explicit hooks; `cipher_overloads` is an
explicit opt-in observing selected `Cipher.doFinal` return buffers.
Late-loading boundary classes install via `defer=true`.

Candidates go through a bounded prefix read → DEX magic + structural header
validation (version, header/file sizes, endian tag, section bounds) →
export bounded to the declared `file_size` → full artifact validation
(size, Adler-32 checksum, SHA-1 signature). DEX 041's container format is
recognized but reported `unsupported` rather than misvalidated; a
magic-only match is a `candidate`, never a recovered executable, and
Shannon entropy is recorded as optional evidence only. Outcomes stay
distinct (`validated | candidate | invalid | truncated | incomplete |
unsupported | not_dex | empty | path_evidence`); artifacts land on disk
with JSON sidecars, deduplicated by content SHA-256, never inlined into
records.

Validated artifacts register into the additive `runtime_artifacts`
observation table with `index=true` on the run, or afterwards via
`unpack_index` — hash + origin preserved, the original APK static index is
never silently replaced.

```bash
{"id":16,"method":"unpack","params":{"duration":60,"record":true,"index":true}}
apkdbg --project ./proj unpack_index list
apkdbg --project ./proj unpack_index index <artifact_id>
```

## Background jobs (issue #34)

Long-lived collectors run as cancellable background jobs so the server
keeps answering control requests and project-only queries:
`job_start` takes a job-capable `command` (`hook_crypto`, `watch_strings`,
`watch_framework`, `coverage`, `export_buffer`, `unpack`) plus that
command's `params`, validated against its catalog schema before queuing.
One active job per session — one JDWP socket supports exactly one
event-stream reader, so session-owning commands (including
`connect`/`events`) are rejected early with `E_JOB_CONFLICT` while a job
runs.

Records live in a bounded ring (`max_records`, `max_record_bytes`; oldest
expire first) with exact received/retained/dropped/expired counts in every
reply. `job_read` pages with an opaque cursor — no duplicates or omissions
among retained records, a cursor below the ring base fails with
`E_CURSOR_EXPIRED` carrying the valid base, and a null cursor marks only a
terminal, exhausted stream (a running job always returns a continuation
cursor). `job_status` reports lifecycle
(queued/running/cancelling/completed/cancelled/failed) with an immutable
terminal record carrying an explicit reason (completed, deadline,
event_budget, output_budget, cancellation, target_exit, disconnect,
capture_failure) and an `incomplete` flag — a budget-stopped capture is
never reported silently complete. `job_cancel` is cooperative and
idempotent; worker teardown clears only the job's own event requests and
suspensions. `job_list` shows the active job plus the bounded completed-job
retention.

```bash
{"id":17,"method":"job_start","params":{"command":"hook_crypto","params":{"duration":300}}}
{"id":18,"method":"job_status","params":{"operation_id":"<id from job_start>"}}
{"id":19,"method":"job_read","params":{"operation_id":"<id>","cursor":"<from prior reply>","limit":100}}
{"id":20,"method":"job_cancel","params":{"operation_id":"<id>"}}
```

## Serve-mode protocol (versions, discovery, pagination)

`apkdbg serve` speaks one JSON value per line in both directions; stdout
carries only replies, diagnostics go to stderr. Two wire versions are
supported, selected **per request** by the presence of a `jsonrpc` member:

- **`"2.0"` — JSON-RPC 2.0** ([spec](https://www.jsonrpc.org/specification)
  is the contract). Requests must carry `"jsonrpc": "2.0"`; replies echo it.
  Standard numeric protocol errors apply: `-32700` parse, `-32600` invalid
  request, `-32601` method not found, `-32602` invalid params, `-32603`
  internal. Domain errors keep their stable `E_*` code in structured
  `error.data`: `code`/`message`/`retryable`/`outcome` are always present,
  `hint`/`context` appear only when set. A request without `id` is a
  **notification** (executed, never replied to). A JSON array on one line is
  a **batch** — one reply array, notification responses omitted, an
  all-notification batch produces no output. `params` may be an object (by
  name) or an array (by position, in catalog order).
- **`"1.0"` — legacy envelope (the default).** Requests without a `jsonrpc`
  member are treated as `{"id":..,"method":..,"params":{..}}` and answered
  with `{"id":..,"result":..}` / `{"id":..,"error":{..}}`, where the error
  body is the same structured error data (`E_PARSE`, `E_INVALID_REQUEST`,
  `E_METHOD_NOT_FOUND`, `E_INVALID_PARAMS`, or a domain code). Pre-#33
  clients keep working unchanged. Requests whose version cannot be
  determined (non-object roots) and parse failures are answered in this
  envelope with `"id": null` — a parse error never borrows a previous id.

Every request is validated against the command catalog
(`apkdbg/core/apicatalog.py`) **before** any project/session context is
obtained, so validation errors are deterministic and need no device.

**Discovery without a project or device** (both protocol versions):

```bash
{"id":1,"method":"describe"}                          # full versioned catalog
{"id":2,"method":"describe","params":{"command":"bp"}}# one command's schema
{"jsonrpc":"2.0","id":3,"method":"capabilities"}      # availability states
```

`describe` returns, for every public command: `name`, `version`, `params`
(name/type/required/default), `result` shape, `mutates`, `idempotent`,
`retryable`, `requires` (`project`/`session`), and `pagination` where
applicable. `capabilities` reports per-command states: `supported`,
`unavailable_in_this_session` (needs `connect` first), or
`unverified_runtime` (scaffolds such as `native`/lldb).

**Pagination.** All list commands (`classes`, `methods`, `res`, `res_refs`,
`bp_list`, `runs list`, `aliases list`, `strings`, `framework_events`,
`coverage_diff`, `unpack_index`, `job_list`, `native`) accept `limit`/`offset`
(limit is clamped
to `MAX_PAGE = 500`) and return explicit truncation metadata:
`count`, `total`, `limit`, `offset`, `truncated` — same shape as
`runs list` from #36. Example:

```bash
{"id":4,"method":"classes","params":{"filter":"crypto","limit":10,"offset":20}}
{"id":4,"result":{"classes":[...],"count":10,"total":37,"limit":10,"offset":20,"truncated":true}}
```


## Environment

- Host: Python ≥3.10, no third-party deps. Device: any debuggable APK process.
- Tools discovered on PATH or via env: `APKDBG_ADB`, `APKDBG_APKTOOL`, `APKDBG_JADX`.
- jadx is tried with `--mappings-json --deobf` first and degrades gracefully;
  without a mapping json the dalvik-line identity pivot is used (exact for
  non-recompiled debuggable APKs).

## Tests

The full offline suite (device-free; JDWP fakes, temp SQLite projects,
packaging/install smoke test) runs with one command from a fresh
checkout — stdlib only, no third-party dependencies:

```bash
python -m unittest discover -s tests
```

CI (`.github/workflows/tests.yml`) builds the wheel, installs it, and
runs this command on Python 3.10–3.13 (Linux, plus Windows on 3.13);
no device or emulator is involved.

Optional on-device validation against the debuggable fixture APK
(`tests/fixtures/crypto/`, rebuildable from checked-in source — see its
README) is a separate, documented runner that skips cleanly when no
device is attached:

```bash
adb -s <serial> install -r tests/fixtures/crypto/crypto_fixture.apk
python tests/integration/run_fixture_scenarios.py <serial>
```

## Troubleshooting

**JDWP handshake fails with EOF / connection drops immediately.**
The most common cause is a **scrcpy-bundled adb server**: it wedges the
`forward`/`jdwp` path so the socket opens and dies instantly. Point apkdbg
at the SDK platform-tools adb instead (and `kill-server` the scrcpy one):

```bash
export APKDBG_ADB="C:\Users\<you>\AppData\Local\Android\Sdk\platform-tools\adb.exe"
"$APKDBG_ADB" kill-server && "$APKDBG_ADB" start-server
```

**adb in a bad state mid-session.** apkdbg keeps recovery scoped to the
affected session: a dropped JDWP transport rebuilds only that session's
own forward listener and (at most) runs `adb reconnect` for the selected
device — other sessions' forwards and the global adb server are never
touched. A global server restart happens only when explicitly requested
(`connect` with `recovery="kill-server"`). If you run adb by hand:
`adb kill-server`, replug or `adb reconnect`, verify with
`adb devices -l` and `adb shell pidof <pkg>` before retrying.

**Connection dropped mid-operation.** State-changing ops (invoke,
write_var, resume, step) are never transparently replayed: if the request
may have reached the VM before the drop, the caller gets a structured
`E_OUTCOME_UNKNOWN` error (execution is *unknown*, not failed) carrying
the op name, connection epoch, and recovery state. Read-only ops retry
once after the scoped reconnect, except ops taking numeric thread/frame
ids — those fail with an actionable `E_STALE_HANDLE` error instead of
reading a reused id. Breakpoint/hook definitions survive as symbolic
defs: run `restore` after a reconnect (or a process restart + `connect`)
to re-install them and get the NEW request ids.

**Broadcast-driven captures come back silently empty.** A freshly
installed or force-stopped app whose receivers are only declared in the
manifest is in the *stopped* state and is excluded from broadcast
delivery — no receiver fires, no events appear, nothing errors. Include
stopped packages explicitly:

```bash
adb shell am broadcast -a <action> -p <pkg> -f 32   # FLAG_INCLUDE_STOPPED_PACKAGES
```

**ART JDWP quirks (handled internally, listed for reference):**

- *Tagged exception field.* An invoke reply's exception object is a
  **tagged** object ID (`tag + objectID`) — this is the *standard* JDWP reply
  layout for `ObjectReference.InvokeMethod` and `ClassType.NewInstance`
  ([JDWP specification](https://docs.oracle.com/javase/8/docs/technotes/guides/jpda/jdwp-spec.html)),
  not an ART deviation. The client decodes the tagged form per spec and
  additionally tolerates a bare untagged objectID from non-conforming
  agents. Regression fixture: `tests/fixtures/jdwp/`
  (`invoke_reply_tagged_exception.hex`, a standard reply carrying a tagged
  non-null exception).
- *InvokeMethod opcode.* On Android 10+ JDWP runs as a JVMTI agent; the
  spec-correct ObjectReference.InvokeMethod command is **6**. Sending the old
  cmd 9 gets a 1-byte error-style reply.
- *Static-field reads can drop the connection* on some ART builds — the
  session splits static/instance field access and treats a drop here as
  reconnectable rather than fatal.
- *Zero-length arrays* report error 503 (`INVALID_INDEX`) from
  `ArrayReference.GetValues` instead of an empty list — surfaced as an empty
  array, not an error.
- *SINGLE_STEP coverage* requires the Step (size/depth) modifier on the event
  request; ART silently never fires the request without it.

## Current status / roadmap

Implemented: init pipeline with transactional re-index (#35), mapping DB,
JDWP bridge, Perfect Sync breakpoints, read/write vars, invoke, step,
snapshots + `snapshot_diff`, conditional breakpoints, crypto hooks with
optional method-exit return capture (`hook_crypto` `returns=true`:
class-scoped METHOD_EXIT_WITH_RETURN_VALUE requests filtered by exact
method id, with metadata invokes disabled while exit requests are armed),
branch/method coverage + `coverage_diff`, string and framework watchers,
runtime DEX unpack discovery, bounded buffer export, runtime alias review,
capability matrix, run manifests, background jobs, event dispatcher with
scoped recovery, versioned command catalog + JSON-RPC 2.0, CLI + stdio
serve mode. Scaffolding: `native` (lldb-server orchestration plan).
Not implemented: full lldb dual-debugging, method-exit return capture for
arbitrary user hooks (exit events are wired only into the crypto, string,
and framework watcher profiles), `Resource.getIdentifier` runtime watch.

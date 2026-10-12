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
| `classes` | runtime class identity | `sig` (`Lcom/foo/Bar;`), `fqcn`, `deobf_fqcn`, `smali_path` |
| `methods` | methods per class | `name`, `sig`, `is_native`, smali `line_start/line_end` |
| `line_map` | `.line N` directives | `method_id`, `dalvik_line`, `smali_line` |
| `jadx_lines` | jadx java line → dalvik line | `class_id`, `java_line`, `dalvik_line` |
| `branch_sites` | parsed `if-*`/`goto`/switch | `dalvik_line`, `opcode`, `kind`, `target_dalvik_line` |
| `resources` | from apktool `public.xml` | `res_id` (0x7f… int), `type`, `name` |
| `resource_refs` | resource call sites in smali | `res_id`, `method_id`, `kind` (`getString`…) |
| `coverage_hits` | persisted coverage runs | `run_id`, `class_sig`, `dalvik_line`, `hits` |
| `alias_candidates` | reviewable runtime alias hypotheses (#25) | `class_sig`, `candidate`, `heuristic_score`, `rule`, `status`, `evidence` |
| `alias_decisions` | full review trail per candidate | `candidate_id`, `action`, `from_status`, `to_status` |

`alias_candidates`/`alias_decisions` are strictly additive: the alias
feature never writes `classes.deobf_fqcn` or imported mappings, and
candidate text never feeds back into resolution or breakpoint targeting.

## Command surface

Stateless (CLI-safe): `init`, `classes`, `methods`, `res`, `res_refs`,
`runs`, `snapshot_diff`, `aliases`, `strings`.
Session (use `serve` mode for multi-step): `connect`, `restore`, `bp`, `bp_del`,
`bp_list`, `events`, `read_var`, `write_var`, `invoke`, `step`, `resume`,
`snapshot`, `dump_object`, `cond`, `hook_crypto`, `watch_strings`,
`coverage`, `native`.

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
`bp_list`, `runs list`, `aliases list`, `native`) accept `limit`/`offset`
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

**ART JDWP quirks (handled internally, listed for reference):**

- *Tagged exception field (Android 15+).* The spec says invoke replies carry
  an untagged exception objectID; Android 15's JVMTI-based JDWP agent emits it
  as a tagged value (`'L' + id`). The client parses both forms.
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

Implemented: init pipeline, mapping DB, JDWP bridge, Perfect Sync breakpoints,
read/write vars, invoke, step, snapshots, conditional breakpoints, crypto
hooks, coverage, CLI + JSON-RPC. Scaffolding: `native` (lldb-server
orchestration plan). Not implemented: full lldb dual-debugging, method-exit
return capture for all hooks, `Resource.getIdentifier` runtime watch.

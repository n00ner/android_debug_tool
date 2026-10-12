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

## Command surface

Stateless (CLI-safe): `init`, `classes`, `methods`, `res`, `res_refs`.
Session (use `serve` mode for multi-step): `connect`, `restore`, `bp`, `bp_del`,
`bp_list`, `events`, `read_var`, `write_var`, `invoke`, `step`, `resume`,
`snapshot`, `dump_object`, `cond`, `hook_crypto`, `coverage`, `native`.

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
`bp_list`, `runs list`, `native`) accept `limit`/`offset` (limit is clamped
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

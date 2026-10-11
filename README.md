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
  `"trunc": true` markers; progress chatter goes to stderr only.

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
Session (use `serve` mode for multi-step): `connect`, `bp`, `bp_del`,
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

**adb in a bad state mid-session.** apkdbg's connect path already walks a
recovery ladder (`get-state` probe → `reconnect` → `kill-server`/`start-server`
→ relaunch), but if you run adb by hand: `adb kill-server`, replug or
`adb reconnect`, verify with `adb devices -l` and `adb shell pidof <pkg>`
before retrying.

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

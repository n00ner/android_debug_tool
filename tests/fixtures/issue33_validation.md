# Issue #33 live validation

Device: POCO 23124RA7EO (serial 4b79a217), Android 15 / API 35, Dalvik
JDWP 1.8. Driven end-to-end through `apkdbg --project test_scope/proj_wolfs serve`
(JSON-RPC over stdio).

## Request sequence and replies

1. `{"jsonrpc":"2.0","id":1,"method":"describe","params":{"command":"connect"}}`
   → full schema (params with types/defaults/descriptions, result shape,
   `mutates: true`, `idempotent: false`, `retryable: true`,
   `requires: {project: true, session: false}`). No ADB traffic preceded
   this reply (diagnostics on stderr confirm first adb call was the
   `connect` below).
2. `{"jsonrpc":"2.0","id":2,"method":"connect","params":{"pkg":"com.wolfs.myapplication","launch":true}}`
   → real attach: `{pid: 19826, port: 62548, vm: "Dalvik", jdwp: "1.8"}`.
3. Line `{not json` → parse error with **`"id": null`** (never borrows a
   previous id), legacy envelope (default protocol version 1.0),
   `code: E_PARSE`, `retryable: false`, `outcome: failed`.
4. Legacy `{"id":7,"method":"capabilities","params":{}}` (no `jsonrpc`
   member) → legacy `{"id":7,"result":…}` reply: protocol versions
   `["1.0","2.0"]` default `1.0`, `session.live: true`, per-command
   capability states (`native` = `unverified_runtime`, everything else
   `supported` in this session).
5. Batch `[notification bp_list, {"jsonrpc":"2.0","id":"b2",...bp_list}, 42]`
   → notification produced **no** reply; `b2` replied with paginated
   `{breakpoints, count, total, limit, offset, truncated}`; element `42`
   → `-32600` with `id: null`.
6. `{"jsonrpc":"2.0","id":8,"method":"bp_list"}` after the broken batch →
   its own independent reply (correlation intact).

EOF on stdin closed the session cleanly; strict JSON on stdout, all
diagnostics on stderr.

## Regression

`python -m unittest discover -s tests` — 153 tests OK (33 new: correlation
sequences, legacy/2.0 validation, batches, notifications, discovery
without project/ADB, catalog completeness vs `COMMANDS`, pagination,
strict-JSON/non-finite floats from issue #9, stdio end-to-end).

## Note

This branch was cut from the #36 stack, which does not contain the #24
work (separate pure-develop branch, PR #42). The protocol-level
`capabilities` method here complements the project-level `capabilities`
command from #24; on merge the two should coexist (protocol method vs
index-capability report).

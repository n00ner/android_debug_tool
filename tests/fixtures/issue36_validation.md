# Issue #36 live validation

Device: POCO 23124RA7EO (serial 4b79a217), Android 15 / API 35, Dalvik VM
(JDWP 1.8). App: `com.wolfs.myapplication` (debuggable), project
`test_scope/proj_wolfs`.

## Scenario

App launched with `-D`, VM held at attach; a deferred CLASS_PREPARE watch
installed a breakpoint at `MainActivity.onCreate` entry when the class
prepared (rid 3). At the stop (thread 1):

1. Two frame snapshots persisted (`record=True`, scenarios `live-a` /
   `live-b`) -> two runs, each with one `snapshot` artifact.
2. `snapshot_diff` of the two artifacts: **changed 0, added 0, removed 0,
   unknown 0** — equal logical snapshots produce no spurious object-value
   changes; runtime object ids (`id`, `$ref`) are never treated as
   identity. Result carries `compatible`/`differences`/`forced`
   qualification fields.
3. `runs get` manifest (run `d1ba6ccb…`):
   - `manifest_version: 1`, `kind: snapshot`, `scenario: live-a`
   - `apk_sha256: 0942ee63…`, `index_generation: 1`, `tool_version: 0.1.0`
   - `environment`: Dalvik vm, `android_api: "35"`, jdwp 1.8, `epoch: 1`
   - `capture_config`: scope (frame 0, original class descriptor
     `Lcom/wolfs/myapplication/MainActivity;`) + full budgets
   - artifact: format json, budgets, truncation report
     (`complete: true`), sha256 checksum, body
4. `runs export` -> file, `runs import --replace` -> round-trip:
   `manifest_version: 1`, `artifacts: 1`, `replaced: true`.

`runs list` reported `total: 2`.

## Regression

`python -m unittest discover -s tests` — 103 tests OK (34 new: manifest
persistence, re-index/reconnect survival, legacy-DB additive upgrade,
export/import round-trip + version guard, diff unknown-vs-removed
semantics, compatibility gating, producer wiring).

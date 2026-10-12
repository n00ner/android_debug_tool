# Issue #24 live validation

Device: POCO 23124RA7EO (serial 4b79a217), Android 15 / API 35, adb authorized.

## Legacy project (indexed before this change)

Project: `test_scope/proj` (Lightroom v11.5.22, apktool index, no metadata table).

```
$ python -m apkdbg.cli capabilities --project test_scope/proj
```

Result:
- mode `static_no_line_map`; 49145 classes, line_rows 0
- line_map `unknown` / reason `no_index_metadata` (legacy fallback path, no hard failure)
- manifest_debuggable `unknown`
- Empty-DB read surfaces `index_note` instead of silent empty results.

`bp` guard on this project:
```
E_LINE_MAPPING with context {line_map_state: unknown, line_map_reason: no_index_metadata}
```
plus a smali-line hint, instead of the old silent no-hit breakpoint.

## Fresh index (this change)

```
$ python -m apkdbg.cli init --apk test_scope/wolfs.apk --out /tmp/wolfs_new --skip-jadx
```

(jadx not installed on host; apktool path used.)

Result:
- metadata table written: `schema_version=2`, `index_version=1`
- `manifest_debuggable=true`, 7867 classes, 740540 line_rows, `index_complete=true`
- line_map `complete` / `ok`

## Runtime probe (`capabilities --probe`)

App `com.wolfs.myapplication` (debuggable) running, pid 23971.

Result:
- device `present`, process `present`, jdwp `observed`
- `jdwp_attach: supported/observed`
- `runtime_line_table: present` — 4 loaded classes sampled, 2 with line tables
  (sampler scans up to 200 indexed rows, preferring the app package, until 5
  loaded classes are found; library classes are often not yet loaded)

## Negative path

`connect` to a non-existent package:
```
E_PROCESS_ABSENT
```

`E_ATTACH_UNAVAILABLE` (attach to a non-debuggable app) is covered by offline
tests; not demonstrated live on the validation device.

## Regression

`python -m unittest discover -s tests` — all tests green (17 new for #24).

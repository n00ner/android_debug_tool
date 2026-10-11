# Issue #35 validation

Host: Windows, Python 3.13 (SQLite 3.45), apktool present, jadx absent.
APK: `test_scope/wolfs.apk` (sha256 0942ee63…), 7867 classes.

## Real end-to-end re-index (real apktool, scratch project)

Two consecutive `init --apk wolfs.apk --out /tmp/w35_proj --skip-jadx`:

- init 1 → rc 0, `index_generation: 3`, `index_version: "2"`
- init 2 → rc 0, `index_generation: 4` (bumped)
- Entity counts identical across generations: classes 7867,
  methods 55772, line_map 740540, resources 5217 — and 55772 matches an
  independent ground-truth re-parse of the smali tree (the pre-fix
  pipeline left ~21k stale method rows in the old project DB).
- Provenance recorded: apk sha256, `jadx: {skipped: true, reused:
  false}` (first init on a jadx-less host proceeds jadx-free after the
  gate fix in e475ba1; `--skip-apktool` without a prior index remains a
  hard error).

## Published generation is queryable

`translate.resolve("com.wolfs.myapplication.MainActivity:19")` against the
published `mapping.db`: resolves to `Lcom/wolfs/myapplication/MainActivity;`
dalvik line 19, 1 method — the line-translation path (used by
`set_breakpoint`) works against a staged+published index.

## Offline suite

173 tests OK (`python -m unittest discover -s tests`), 20 new for #35:
A→B entity exactness, repeat-index equivalence, upsert/RETURNING id
correctness, rollback-on-exception, five injected-failure stages (each
leaves the prior generation selected), three crash-recovery scenarios,
provenance/skip-gate cases, observation tables retaining their original
generation.

## Device note

An on-device breakpoint through the freshly published index was attempted
but the validation device's USB link dropped mid-session (adb: no
devices/emulators found, did not recover). Mitigation: the index content
is verified byte-equivalent to ground truth and the translate path was
exercised offline; device re-check pending reconnection.

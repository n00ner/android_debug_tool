# Issue #25 live validation

Device: POCO 23124RA7EO (serial 4b79a217), Android 15 / API 35.
App: `com.apkdbg.cryptofixture`; project `test_scope/proj_wolfs`.

## Collector during a real crypto watch

`hook_crypto --collect-aliases` (returns capture, 25 s, RUN broadcast):

- 24 crypto hits recorded under run `4b8ae754…`; alias collection:
  `observations: 14`, `suggestions: 2`, `behavioral_context: 0`,
  `partial: false`, `errors: []`
- **zero extra JDWP reads** (`jdwp_reads: 0`, `extra_reads: false`) —
  only already-captured string values were consumed; measured
  `pause_ms: 29.9` published with the no-universal-guarantee note and
  the full budget set (strings/objects/bytes/requests/seconds)

## Candidates and dedupe

- `aliases list`: 1 unique candidate — `"HmacSHA256"` (rule `log_tag`,
  heuristic score 0.8, status `suggested`, `observations: 2`): repeated
  runtime observations merged with frequency kept, not duplicated.
- `aliases get`: evidence resolves to the source run/event rows
  (`has_event: true`).

## Review workflow (live store)

- accept → `accepted`; reject → `rejected`; re-accept → `accepted`
  (reversible, decision trail in `alias_decisions`)
- unit suite additionally covers: rejection suppression on
  re-observation, supersede/revise, distinct classloader separation,
  unmapped runtime classes without fabricated static match

## Regression

239 tests OK (`python -m unittest discover -s tests`), 40 new for #25.
Original signatures and `classes.deobf_fqcn` verified byte-for-byte
unchanged; `sig`/`deobf`/`alias` are distinct output fields and aliases
never participate in method resolution or breakpoint targeting.

# Issue #37 — coverage method identity / unknown branch reasons: live validation

Declared configuration: POCO 23124RA7EO, Android 15 (API 35), fixture
`com.apkdbg.cryptofixture` (current build, project re-indexed: 6 classes,
35 methods, 44 branch_sites). Tool: apkdbg from
`fix/issue-37-method-identity`. Harness: `test_scope/_pr37_live.py`.

Scenario: `RUN` broadcast under `set-debug-app -w`; class held at
CLASS_PREPARE of `RunReceiver`; line-mode coverage installed on that thread
for 25s so `<clinit>` (calls `hex(String)` ×3) and `onReceive` (calls
`hex(byte[])` ×6, AES-CBC + HMAC + SHA-256) both run inside the capture.

## Results (all checks passed)

- **Descriptor identity**: every line-hit key carries the full method
  descriptor, e.g. `Lcom/apkdbg/cryptofixture/RunReceiver;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V`.
- **Overload separation**: both `hex(Ljava/lang/String;)[B` and
  `hex([B)Ljava/lang/String;` appear as separate keys with separate hit
  sets — the pre-fix collector merged them under `->hex`.
- **Offset evidence**: `offsets` maps bytecode index → line per method
  (5 offsets for `hex(String)`, 6 for `hex(byte[])`).
- **Branch metrics**: `sites_hit=13`, `edges_identified=4`,
  `unknown_transitions=407` with reasons `{ambiguous_line: 404,
  unresolved_target: 3}`. Site observations are counted separately from
  identified taken/fall-through edges. The high `ambiguous_line` count is
  the intended conservative behavior: the fixture's `for` loops compile the
  condition and the loop-back goto onto one dalvik line (two sites per
  line), and ART's split line-table regions deny unique edge evidence, so
  each iteration is recorded unknown rather than as a phantom
  taken/fall-through.
- **Incomplete capture**: `complete=false`, `stop_reason=duration`,
  `dropped_events=0`; the #36 run manifest carries the same completion data.
- **Idempotency**: two extra `report()` calls are byte-identical to the
  first and persisted `coverage_hits` sums stay unchanged (595 = 595).
- **Persistence**: `coverage_hits` rows store distinct `method_sig` per
  overload (`(Ljava/lang/String;)[B` vs `([B)Ljava/lang/String;`).

Unit-level coverage of the remaining acceptance criteria (non-monotonic
line tables, missing tables, same-line targets, switch/goto, recursion,
exceptions, truncated traces, legacy-table migration) is in
`tests/test_issue37_coverage_identity.py` (27 tests).

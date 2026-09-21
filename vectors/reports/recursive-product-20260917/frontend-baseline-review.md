# Frontend baseline repair review

The complete CPU tree after the ownership repairs passes 192 cases and retains
all 21 baseline proof/key/claim artifacts. Its receipt is in
`cpu-backend-test-owner-v1/summary.json`. Matching Metal qualification also passed; its receipt is in
`metal-backend-test-owner-v1/summary.json`. These runs precede the next baseline batch.

The next source batch has now been applied and its focused contract tests pass.

- The explicit frontend test inventory omits 154 test-bearing files. Backend-bound
  proof and AOT tests have already moved to `src/tests/riscv`; the remaining
  files use the backend-neutral frontend ownership contract. The optional public
  sums benchmark defaults to a bounded 4096-word fixture. The diagnostics environment
  variable in the incremental verifier is not a requirement of its unit test.
- The LogUp diagnostic wiring check embeds `verifier.zig`, but the V1/V2 adapter
  implementations moved to `verifier_protocol.zig`. The repair checks the actual
  adapter source and also pins the verifier import and public aliases, retaining
  the assertion that its reporter receives the statement-selected predicate.
- Commit `03519839c2b3d87cebebb690d78be20e02be5217` expanded load/store to the
  one-GiB data-address profile. The two appended physical columns are the aligned
  word address and its low 20 bits; the appended `range_check_8_8` event bounds
  the high eight bits. `typed_load_store.authorEffects` and
  `lookups/opcode_entries.zig` both contain that event. The opcode manifest still
  omits this domain, causing the 2183-versus-3207 bitmask failure.
- That same reviewed change gives load/store 50 main columns and 17 lookup
  events. Batch size stays two, giving nine batches and 36 interaction columns.
  The 17-family totals are 646 main columns and 624 interaction columns; the
  old tests only partially updated these quantities. The direct constraints
  remain 63 for load/store and 545 across the families.

Static-profile artifacts and formal bindings still need separate regeneration
and comparison against reviewed source. The two P-002 static artifacts were regenerated in a temporary directory first.
Only the load/store row and aggregate report digest differ; see
`static-profile-reviewed-diff.json`. Their exact expectations now pass all 197
static-profile tests. Formal bindings remain unchanged. This makes no new
soundness or production-security claim.


The complete Debug inventory then ran 3152 tests: 3135 passed, 12 skipped
(unavailable Sail oracle), and five failed. The five failures were reviewed:

- M2 machine/human artifacts differed only in load/store and aggregate totals,
  matching the reviewed one-GiB profile. They were generated outside the tracked
  artifact directory and compared before replacement.
- Runtime profile identity hashes both the static report digest and static totals;
  the joined fixture digest was updated after checking those dependencies.
- Two sparse public-sum fixtures replaced memory without rebuilding the job and
  Span commitments. The test helper now reconstructs those commitments through
  canonical constructors and validates the resulting SourceV2. Production
  snapshot validation is unchanged.
- The stack-swap negative test changed allocation but retained stale semantic
  identity. It now checks that malformed authority is rejected, then creates a
  self-consistent alternate authority and checks private-registry rejection.

All 103 focused tests covering these failures pass. The full Debug rerun remains
pending in `frontend-baseline-repairs.json`. No new complete-proof timing applies
to this source batch.

Formal work requires a semantic migration before binding refresh. The handwritten
LoadStore model still bounds alignedQuarter below 2^20 and forces the base high
byte to zero. Production now commits the aligned quarter, checks its low 20 and
high eight bits, and bounds the base high byte through a doubled range-check
input. The address-bridge proof and mutation predicates depend on the old model.
Re-export current symbolic AIR, derive the new field/integer address bridge and
repair mutation controls, then refresh source bindings and run coverage. Merely
replacing the recorded digests would leave the formal claim disconnected from
production.

Full Debug rerun completed: 3140/3152 passed, 12 Sail-oracle skips, no failures. Compilation took one minute (18 GiB peak reported by Zig); execution took seven minutes (806 MiB peak).

The repaired baseline also passes matching CPU and hybrid Metal/AOT complete-proof gates: each passes 192 cases and preserves 21 baseline artifacts. See `cpu-frontend-baseline-v1/summary.json` and `metal-frontend-baseline-v1/summary.json`. These qualify the experimental four-segment route, not production security or the unfinished formal migration.

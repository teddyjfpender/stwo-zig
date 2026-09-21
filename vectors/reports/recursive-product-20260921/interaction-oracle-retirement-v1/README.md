# Retired interaction generator isolated from production

The old monolithic opcode/program interaction generator had no production caller.
Moved its implementation to `air/interaction_legacy_test_oracle.zig`, removed the
public `air.interaction_gen` export, and exposed it only through `testing` for the
existing empty-shard regression. Its body matches the previous implementation
byte-for-byte; only the test-only header is new. Existing tests remain intact.

A source guard admits only the testing namespace, test inventory and AIR test
root as direct oracle consumers. It also rejects reintroduction of the old file
or production export. The active semantic evaluator remains unchanged because it
delegates to the canonical typed constraint builder.

Validation:
- Isolation, product closure, proposal isolation and package checks: 56 passed.
- Frontend inventory: two passed.
- Broad AIR semantics root: 830 passed, one skipped; compile one minute, run
  three seconds. The skip is not counted as a pass.
- Added `test-legacy-interaction-oracle` for future edits: nine tests passed,
  including the five interaction regressions; compile five seconds, run 459 ms.
- Oracle body comparison and diff whitespace checks passed.
- Source conformance remains at 104 size findings; no baseline update.

No complete-proof run was repeated because production assembly has no dependency
on the retired generator. The last full proof checkpoint and subsequent scoped
cleanup batches remain separately identified. The broader baseline goal is open.

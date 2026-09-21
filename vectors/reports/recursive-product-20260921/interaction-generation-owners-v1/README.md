# Shared interaction accounting and column ownership

Separated exact Tree-2 work accounting and committed-column ownership from the
native interaction generators. Neither needs the generic generator Owner type.
Accounting callers now use their direct owner; generator instances share one
Columns type through the retained alias used by external native-provider paths.
Removed 17 unused aliases from the claim phase. The generator falls from 1,003
to 660 lines; accounting is 266 lines and column ownership 91.

Post-format transfer audit verifies the entire moved accounting and column-owner
bodies are unchanged after whitespace normalization. Relation ordering, work
counts, allocation behavior and commitment transfer semantics are preserved.
No protocol identity, typed definition or pinned artifact was regenerated.

Added three ownership regressions to the existing focused work gate: every
allocation-failure point during guest reservation retains the existing prefix;
an oversized generated block remains caller-owned; and transferred commitment
buffers survive producer teardown. The gate passes all 124 tests in under a
second after a six-second compile. All 44 ownership/isolation checks and both
inventory checks pass. Formatting and diff checks pass.

Repository conformance findings fall to 106 without a baseline update. No full
proof rebuild was repeated for these body-preserving moves. The canonical-surface
checkpoint remains complete-proof evidence for its frozen source; this batch has
the scoped tests and transfer audit above. Broader baseline findings and Linux
artifact-store runtime qualification remain open.

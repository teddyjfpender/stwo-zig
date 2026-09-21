# Canonical detached boundary preparation owners

Separated three existing responsibilities from the opaque preparation owner:
graph input/range and native/symbolic sponge machinery; identity binding; and
continuation memory/clock constraints. The opaque owned object, native/parent
construction entrypoints, destruction and public aliases remain in the canonical
preparation module. All new owners live in the shared RISC-V recursion package.
Unused private aliases were removed after the move.

Post-format source-transfer audit compares 35 complete declarations against the
retained original, normalizing only whitespace and pub visibility across internal
module boundaries. No graph equations, identity domains, provider schedules or
wire bindings changed. The preparation owner is now below its 850-line ceiling;
all three new owners are also below it. Repository conformance findings fall
from 109 to 108 without baseline changes.

Added `test-detached-boundary` as a frontend-local edit loop over the existing
boundary tests, without integration proof harness imports. Three tests pass:
six fixtures each reject 37 witness mutations (222 total), alongside segment-index
and malformed-clock checks. Graph identities remain independent of public values,
including sparse memory values with different zero-byte patterns. The initial
compile took five seconds at about 535 MB, with execution under a second. These
are development-loop observations, not proof-performance claims.

All 44 ownership/isolation checks and both inventory checks pass. The final
three-test count floor, formatting and diff checks pass. The historical integration
test wrapper remains available. No complete proof rebuild was repeated for these
body-preserving moves; the canonical-surface checkpoint remains evidence for its
frozen source. Broader baseline findings and Linux artifact-store runtime
qualification remain open under the original goal.

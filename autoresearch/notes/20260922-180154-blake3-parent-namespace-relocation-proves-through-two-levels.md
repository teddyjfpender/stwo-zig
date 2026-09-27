---
title: BLAKE3 parent namespace relocation proves through two levels and direct column join passes
author: Teddy Pender
created_utc: 2026-09-22T18:01:54Z
---

# BLAKE3 parent namespace isolation and direct column joining

Distinct child verifiers cannot share their caller/circuit identifiers: otherwise
one child's relation producers could satisfy the other's consumers. The shared
namespace inspector now derives circuit columns from authenticated typed effects
and permits only the child-local recursion-wire relation plus the two shared
fixed lookup tables. Unknown relation domains fail closed.

The relocation plan inventories identifiers, sorts them, and assigns a dense,
injective range without field wraparound. Its identity commits the source IDs,
destination range and all AIR semantic identities. The two older arithmetic
AIRs also rename their selector-controlled fixed circuit schedules, preserving
the constraints tying those schedules to witness-column circuit IDs.

Application validates the complete geometry, plan pin and source membership
before its first write. It then edits only owned identifier columns in place;
main trace buffers stay allocated and padding stays zero. A missing source ID,
wrong pin or overflowing destination range cannot leave partial relocation.
The plan is independent of proof values and can be retained for repeated use
with the same admitted identifier inventory.

The column join validates each source's exact domain geometry and requires
nonoverlapping namespace ranges containing every actual circuit ID. It copies
both inputs directly into the destination column layout, including the changed
committed-row permutation when the domain grows. It does not materialize an
expanded logical main-row copy. Inputs remain unchanged on success or failure.

## Qualification

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-execution-commitments -Doptimize=ReleaseSafe --summary all`

Passed: 2 minutes build/test, 5 GiB peak RSS. The real execution parent with
nonzero-output memory conversion relocates 10,520 identifiers into [1, 10521).
Its parent proof and parent-of-parent proof both independently verify after
artifact roundtrip and proving-plan release. Artifacts are 125,652 and 124,381
bytes. The test checks unchanged hash-column storage/value, wrong-pin and
stale-inventory rejection, destination overflow and absence of out-of-range
circuits after relocation. This is diagnostic q8/PoW0 CPU evidence, not a speed
measurement or canonical-security qualification.

`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-memory-update '-Driscv-test-filter=parent' -Doptimize=ReleaseSafe --summary all`

Passed: 10 seconds, 826 MiB peak RSS. Focused append/join checks cover domain
remapping, row order, padding, both fixed and witness-column namespace inspection,
overlapping ranges, an identifier outside its declared range, malformed column
geometry, and preservation of source storage after rejection.

The join currently has layout/admission tests; it has not yet produced a
combined two-child STARK. Relocation is qualified by real proofs, but it does
not by itself qualify distinct-child aggregation. Adjacent segmented execution,
a key binding both child contexts and the folded Span, the resulting aggregate
proof and later-level verification remain to connect. Production defaults,
canonical parameters/Metal parity and the original performance goals remain open.

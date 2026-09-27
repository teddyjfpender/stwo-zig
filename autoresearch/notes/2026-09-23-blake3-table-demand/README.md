# Shared lookup demand — 2026-09-23

Added opt-in `STWO_RISCV_LOOKUP_DEMAND_PROFILE` at the shared BLAKE3 execution
lookup census, after native, precompile, and commitment registration. It reports
field-nonzero signed multiplicity counts for each table. Default proof behavior
is unchanged. ReleaseFast CPU build and formatting checks passed.

All 16 canonical CPU CSP cases completed and independently verified, using
70 queries and 26 PoW bits. All 16 proof hashes equal the corresponding earlier
word-memory CPU suite artifacts. CPU-only execution is sufficient for this
host-generated witness census; the previous artifact audit separately established
identical table domains across the 32 CPU/Metal cases. This run does not claim a
new CPU/Metal performance speedup or compact-provider qualification.

ECDSA demands only 557 range20, 27 range8/11, and 13 range8/8/4 distinct tuples.
Across the entire suite, maxima are 4,361, 29,942, and 137 respectively, versus
fixed table heights 1,048,576, 524,288, and 1,048,576. Power-of-two sparse heights
would be at most 8,192, 32,768, and 256 before AIR-specific padding. The largest
range8/11 demand occurs in the guest Poseidon workload, so it must be included
in qualification rather than assuming ECDSA demand is representative.

These counts justify implementing the compact typed range-provider experiment.
They do not predict an end-to-end speedup: additional columns, constraints,
lookup demand and recursive verification all need measurement. The native
recursion parent already uses only bitwise/range8/8 tables; effects on recursion
would come from changed child-proof geometry, not removing these three tables
from the parent itself.

See [DEMAND.md](DEMAND.md) for every case, [PROVIDER_DESIGN.md](PROVIDER_DESIGN.md)
for constraints and integration requirements, and `suite/` for commands, logs,
artifacts and independent verifier outputs. The canonical production provider
has not changed yet. The full active goal remains incomplete.

# Shared table geometry audit — 2026-09-23

Previous goal turn: progress. Shared CPU PoW batching was implemented and
qualified with matched timings and byte-identical, independently verified proofs.
This checkpoint investigates the next shared cost without changing the protocol.

## Authoritative findings

`census.py` reads descriptors from all 32 previously verified word-memory CSP
artifacts. Every CPU and Metal workload contains all six lookup tables:

| Table | Domain log | Rows |
| --- | ---: | ---: |
| bitwise | 18 | 262,144 |
| range_check_20 | 20 | 1,048,576 |
| range_check_8_11 | 19 | 524,288 |
| range_check_8_8_4 | 20 | 1,048,576 |
| range_check_8_8 | 16 | 65,536 |
| range_check_m31 | 15 | 32,768 |

The decoder is an analysis tool, not a verifier. `geometry.json` pins each input
artifact hash. Native descriptor enum widths and framing were checked against
`proof_artifact_wire.zig`, `blake3_execution_manifest.zig`, and
`blake3_profile_artifact.zig`. The original suite verification logs remain in
the word-memory checkpoint. A new current-binary ECDSA run additionally passed
fresh verification (`verify.json`). Its G trace has 63,000 rows padded to 2^16,
while its largest fixed lookup tables still have 2^20 rows.

`air/lookups/tables/verifier.zig` defines each table's constraint degree log as
its domain log plus one. Thus these tables impose a composition degree log of
at least 21 even for the small ECDSA G trace. This establishes a shared domain
floor, not a measured claim that tables account for all commitment costs.

The new diagnostic run reports 0.265178 s main commitment, 0.339839 s interaction
commitment, 0.373950 s composition evaluation, 0.147949 s PoW, and 0.078846 s
native interaction generation. It is a single diagnostic sample, not another
matched performance comparison. The old native profiling environment variable
does not instrument this BLAKE3 generation route; the census uses actual
committed artifact descriptors instead.

## Next architecture experiment

Prioritize reducing the shared large-range-table domain floor over another
small nonce-search improvement. A candidate is a typed sparse provider for the
three large range relations: commit only demanded tuples and multiplicities,
prove every tuple's range through byte lookups plus constrained high bits, and
emit the same original relation with negative multiplicity. The existing
range_check_8_8 table can provide byte membership. This is a new AIR/protocol
experiment, not permission to truncate a fixed table or trust witness values.

Requirements before enabling: verifier-derived bounded row geometry; constrained
limb recombination and high-bit ranges; unchanged relation identities and closure;
authenticated roster/key/codec versioning; source admission and recursive-capture
support; rejection tests for out-of-range tuples, wrong limbs/multiplicities,
changed geometry and old keys; CPU/Metal and native-recursion qualification.
Measure distinct demanded tuples across the suite first: a dense workload can
make sparse providers more expensive, so selection must derive from authenticated
geometry and measured costs, never a benchmark name. No such provider is enabled
by this checkpoint. The 0.882-second historical ECDSA target remains unrecovered,
and the full persistent-plans/fused-PCS/direct-witness/parameter-experiment goal
remains active.

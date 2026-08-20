# 2026-08-12 — Recursion FRI profile frontier

## Decision boundary

The Zisk comparison identified query count as a likely dominant cost in a
recursive verifier. This change makes that trade measurable without changing
the frozen recursion V1 protocol. It is a design instrument, not a security
proof or performance receipt. The follow-up
[real measurement](2026-08-13-recursion-fri-frontier-measurement.md) selects
log blowup 2 as the measured V1.1 experiment; it still does not alter V1.

The executable authority is
`src/frontends/riscv/recursion/fri_profile_frontier.zig`. It is fixed-capacity,
allocation-free, deterministic, and digest-bound. It derives every candidate
from the existing fixed FRI schedule and preserves the exact query-plus-PoW
ledger currently reported by `PcsConfig.securityBits()`:

```text
pow_bits + log_blowup_factor * n_queries >= 209
```

This equation is the repository's configured ledger, not an independent
end-to-end soundness theorem. Any protocol change still requires cryptographic
review of algebraic, hash, field-capacity, grinding, and query-collision terms.

## Exact V1 comparison at column log degree 24

| Log blowup | Domain expansion | Queries | Trace paths (4 trees) | FRI authentication digests, upper bound | Fold values, upper bound | Terminal values |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 2× | 193 | 772 | 12,738 | 18,528 | 2 |
| 2 | 4× | 97 | 388 | 6,984 | 9,312 | 4 |
| 3 | 8× | 65 | 260 | 5,070 | 6,240 | 8 |
| 4 | 16× | 49 | 196 | 4,116 | 4,704 | 16 |
| 5 | 32× | 39 | 156 | 3,510 | 3,744 | 32 |
| 6 | 64× | 33 | 132 | 3,168 | 3,168 | 64 |

All six candidates are Pareto-nondominated in the modeled dimensions: larger
domains reduce recursive-verifier query/path/fold work. The canonical frontier
digest is:

```text
1c4ef8a500738a109a6612868119b86f7416f08116ebf5abd8a6f36a539efde0
```

The counts are deliberately upper bounds before query-position deduplication.
That makes them deterministic and prevents a favorable random collision pattern
from influencing profile selection.

## What must be measured before a V1.1 decision

All candidates now have fresh-process leaf captures for proof bytes, fixed-wire
bytes, native prove/verify time, process counters, and exact compiled FRI
arithmetic schedules. The remaining promotion evidence must report:

- complete active outer-proof bytes and serialization time;
- recursive verifier AIR rows, columns, relation batches, and static profile;
- prover commitment, FFT/FRI, composition, and decommitment work;
- active outer proving and in-circuit verification time;
- peak coordinator and worker RSS;
- total process CPU and fixed-worker wall time; and
- the same independent-verifier, transcript, mutation, and cleanup gates as V1.

The selected profile must improve the complete recursive aggregation result,
not merely reduce Merkle paths. In particular, a 64× domain can lose globally
even though it reduces the modeled verifier work by roughly four to six times.

## Relationship to 36/36 AIR closure

The universal component manifest is now complete, so this frontier no longer
blocks component authoring. It should be evaluated before the complete 36-row
outer proof and fixed child wire are promoted, because changing the FRI profile
afterward versions the proof shape, transcript identity, and recursive circuit.
Until such evidence and an ADR exist, `recursion/protocol.zig` remains the sole
V1 authority at 2× domain expansion (log blowup 1), 193 queries, fold step 4,
and 16 PoW bits.

# 2026-08-13 — production VM-composition row and arithmetic-capacity reduction

## Question

Can the verifier-captured native VM AIR evaluation become the authoritative
input graph for universal row 18 in the same proof as rows 19--34, without
duplicating the VM constraints or paying for inactive child graphs?

## Authority path

The native verifier first verifies the leaf proof and transactionally publishes
its fixed-wire capture. The VM component manifest, sampled values, claimed
sums, composition randomness, and exact evaluation schedule then build one
prepared `vm_air_composition_circuit`. Preparation authenticates the component,
profile, reference, schedule, preprocessing, and circuit seals. Validation
replays every derived graph node and requires the single circuit output to be
zero. Universal row 18 consumes the prepared circuit inputs in exact schedule
order and contributes its wire multiplicities to the same rows 30--32 closure
as the PCS and FRI graphs.

The verifier independently rebuilds this authority and recomputes row 18's
claimed sum before consuming it. A mutation of a row-18 value is the fifth
failure-atomic outer-proof mutation.

## Measured frozen-V1 result

ReleaseFast, Poseidon2-M31, 2x blowup, 193 FRI queries, eight workers:

| Metric | Result |
| --- | ---: |
| Covered contiguous rows | 18--34 |
| Components in this proof | 17 |
| Honest union with separate row 0 | 18/36 |
| Preprocessed / main / interaction columns | 347 / 760 / 276 |
| Constraints | 862 |
| VM graph nodes / inputs / outputs | 19,352 / 4,589 / 1 |
| VM input schedule rows | 4,805 |
| Active multiply / inverse / linear rows | 547,942 / 16,029 / 477,371 |
| Shared Poseidon2 calls | 52,303 |
| Proof-size estimate | 66,308 bytes |
| Prove / assembly / STARK body | 30.954 s / 28.589 s / 2.358 s |
| Independent verification | 10.779 s |
| Mutations rejected | 5/5 |

The first sound row-18 assembly retained full inactive left and right PCS/FRI
graphs solely to satisfy binary-mode capacity validation. That produced
1,081,252 multiply, 32,042 inverse, and 940,294 linear capacity rows despite
the segment leaf using roughly half of them. The accepted layout retains the
active segment VM, PCS, and FRI graphs plus one small authenticated binary VM
capacity anchor. The input tables still retain their fixed three-lane shape;
inactive child witnesses remain canonical zero.

Relative to that first sound run, the capacity change reduced proof time by
32.5%, assembly by 31.1%, the STARK body by 45.8%, verification by 31.0%, and
the proof estimate by 2.36%. Live operation counts and proof meaning are
unchanged. These are single-run engineering measurements, not a promotional
benchmark receipt.

## DevX observation

VM graph preparation takes only about four milliseconds. Most iteration time
is trace commitment and verification, so fast component tests should remain
the default edit loop and the full active proof should be reserved for
integration checkpoints. The capacity reduction improves both production
performance and development turnaround because it removes committed inactive
work rather than weakening constraints.

## What this does not establish

Rows 1--17 are not yet populated from one schedule-driven native transcript;
row 35 and global relation cancellation are not yet in the proof; and the
authenticated pair-node record is not yet a proved recursive `2 -> 1` node.
Accordingly this remains a verifier-subsystem proof, not a complete recursive
verifier.

## Decisions/tasks affected

- R-012 real-proof coverage advances from 17/36 to 18/36.
- Row 18 is no longer an open production-graph item.
- Rows 1--17's transcript/statement/public-claim authority are now the critical
  path, followed by row 35/global closure and pair-node integration.

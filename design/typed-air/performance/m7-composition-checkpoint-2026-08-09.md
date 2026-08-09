# M7 composition development checkpoint — 2026-08-09

> **Classification:** non-promotional development evidence. This note is not
> an M7 receipt, does not close R-001, and cannot support formal promotion.

This checkpoint records a controlled CPU comparison for the prepared RISC-V
composition scheduler and a separate proof-identity check. It exists to retain
useful engineering evidence while the complete frozen M7 protocol remains
open.

## Timing comparison

The measured candidate was commit
`72527052cf838b7cc41b02975cdfb6a1f47db0a0` with tree
`7ccc338fc059382afa674187f3987559ea9f4666`. Its benchmark binary SHA-256 was
`68ae7160dbafd61778167bfacd6b241e2e51e1ad00493c22354f38aa9d551614`.
The prior implementation was commit
`4232cc5521d7296c2a0c6da12e51ccd49f0a389e`; its benchmark binary SHA-256 was
`b6cd658dcab89807ae31a5eef654555968099ea2af5d78aa0c82c495a9f544b8`.

The comparison used the development profile `pow_bits=0`, `n_queries=3`, 12
excluded warmups, and 60 measured samples, with five interleaved samples per
candidate/baseline cell. All 94 proof-bearing runs in the complete validation
session verified. The proof-identity reporting mode described below was not
enabled for timing.

| Workload | Workers | Prove result | Composition result | Other observation |
| --- | ---: | --- | --- | --- |
| `multi_shard_addi` | 1 | paired median -0.14% (flat) | — | expected low-parallelism control |
| `multi_shard_addi` | 2 | 1818.4 ms vs 2064.6 ms; paired median -11.92% | 305 ms vs 546 ms; -44.14% | total time -10.26% |
| `multi_shard_addi` | 4 | paired median -5.18% | — | positive but below the two-worker gain |
| Poseidon field16 | 1 | near flat | — | expected low-parallelism control |
| Poseidon field16 | 2 | paired median -13.22% | 631 ms vs 1171 ms; -46.11% | gain isolated to composition |
| Poseidon field16 | 4 | paired median -4.97% | — | positive but below the two-worker gain |

Times in each `A vs B` cell are candidate versus prior. Main trace,
interaction trace, and FRI stages were flat; the observed gain was isolated to
composition. Median peak RSS was flat within 0.01%. One Poseidon four-worker
candidate sample reached 1928.8 MiB, but three additional paired repetitions
did not reproduce it: candidate RSS remained between 1897.6 and 1897.8 MiB.
The candidate benchmark binary was 0.72% larger than the prior binary.

These results support continued development of prepared composition lanes.
They are not a general scaling result: the two-worker cells improved more than
the four-worker cells, the security parameters were deliberately reduced, and
this capture is not a digest-bound M7 attempt bundle or receipt.

## Separate proof-identity check

Proof identity was checked later at final development head
`b84bd6c0c24a5fb3f7fc076cd1ce2a55ede9150d`, tree
`ff80551e84c0e235bbbf3362ccc8d6240ec9b287`. The ReleaseFast benchmark binary
SHA-256 was
`30802dc4f9623fed2971924563a7e99654b5c96891a713f440349a9fc46e1a9a`.
At `pow_bits=0`, `n_queries=3`, worker counts 1, 2, and 4 all produced the same
canonical proof identity for each checked workload:

| Workload | Canonical bytes | SHA-256 at workers 1, 2, and 4 |
| --- | ---: | --- |
| `multi_shard_addi` | 161274 | `f367ca04d554a9d00d32c9279795b8e26032f4211a453074daa91211a9084293` |
| Poseidon field16 | 285105 | `19389b1a3a42eeebb6712244d3490f89791831ba653c1c9bd8db3d5cf529a90c` |

For the one-worker predecessor check, the proof reporter from
`035db833449fae2e2177adcdec7e262623a78388` was applied only as
instrumentation to `4232cc5521d7296c2a0c6da12e51ccd49f0a389e`. That instrumented ReleaseFast
binary had SHA-256
`7bac33622ea3a207fd167621e02333172083dafb2c4a76cb6d8d281901d90b80`.
Both one-worker predecessor proof identities exactly matched the corresponding
final-head identities above.

`--proof-identity` canonicalizes and hashes a successfully verified proof. It
is a correctness-only diagnostic and was deliberately excluded from all
timing runs, so encoding and hashing costs do not contaminate the performance
comparison.

## Promotion boundary

This checkpoint does **not** close M7, R-001, the formal performance-promotion
gate, or the full-security benchmark obligation. A promotable result still
requires the complete frozen corpus and security profiles, authenticated raw
attempt bundle, required host/backend lanes, exact and statistical gates, and
a validator-recomputed receipt under
[`m5-m9-protocol-v1.json`](m5-m9-protocol-v1.json).

# 2026-08-13 — Real recursion FRI frontier measurement

## Result

The six A1 candidates have now crossed a real RISC-V leaf proof, and their
exact recursive FRI arithmetic schedules have been compiled. The measured
recommendation for a future, explicitly versioned V1.1 experiment is log
blowup 2: 4x domain expansion and 97 queries. Frozen V1 remains log blowup 1
and 193 queries.

At 4x, the exact fixed recursive wire is 1,098,116 bytes instead of 2,111,588
(-48.0%), postcard proof bytes are 775,619 instead of 1,389,904 (-44.2%), and
the active FRI graph is 263,803 nodes instead of 512,183 (-48.5%). The cost is
1.84x native proving time, 1.93x native verification time, and 1.80x peak
physical footprint on this host. Later candidates keep shrinking the child
wire but approximately double native prover work and memory at each step.

## Method

Each row below is a fresh ReleaseSafe process over the same three-instruction
RV32IM guest and column log degree 20. Every run proved with Poseidon2-M31,
serialized, passed allocation-free statement-derived postcard preflight,
decoded, independently verified while transactionally capturing only accepted
values, and derived the exact runtime fixed-wire size from that capture.

Process counters are macOS task-ledger observations. Times are one sample per
candidate, suitable for selection evidence rather than a normative benchmark
receipt. Wire counts and compiled graph schedules are exact for the shape.

## Native leaf results

| Log blowup | Expansion | Queries | Ledger | Postcard bytes | Fixed wire bytes | Prove s | Verify s | Peak GiB |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 2x | 193 | 209 | 1,389,904 | 2,111,588 | 15.143 | 6.966 | 0.963 |
| 2 | 4x | 97 | 210 | 775,619 | 1,098,116 | 27.935 | 13.451 | 1.737 |
| 3 | 8x | 65 | 211 | 559,026 | 760,484 | 55.573 | 27.541 | 3.455 |
| 4 | 16x | 49 | 212 | 451,647 | 591,812 | 110.618 | 55.087 | 6.891 |
| 5 | 32x | 39 | 211 | 384,387 | 485,924 | 219.164 | 108.161 | 13.750 |
| 6 | 64x | 33 | 214 | 343,263 | 423,428 | 439.459 | 217.462 | 27.479 |

The ledger column is the repository's query-plus-PoW configuration ledger,
not an end-to-end soundness claim. All candidates retain at least the frozen
209-bit configured floor and remain bounded by the separately documented
120-bit recursion security target.

## Exact active recursive FRI schedules

The same profiles were compiled through `fri_verifier_circuit.zig` and the
compiler-derived lowering into universal rows 30--32:

| Log blowup | Graph nodes | Bound inputs | Zero outputs | QM31 mul | QM31 inv | Linear | Public terms |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 512,183 | 70,663 | 9,265 | 241,482 | 14,475 | 185,492 | 9,336 |
| 2 | 263,803 | 35,527 | 4,657 | 125,363 | 7,275 | 95,564 | 4,731 |
| 3 | 181,122 | 23,815 | 3,121 | 86,749 | 4,875 | 65,604 | 3,200 |
| 4 | 139,815 | 17,959 | 2,353 | 67,463 | 3,675 | 50,636 | 2,435 |
| 5 | 113,892 | 14,299 | 1,873 | 55,341 | 2,925 | 41,242 | 1,958 |
| 6 | 98,577 | 12,103 | 1,585 | 48,219 | 2,475 | 35,692 | 1,673 |

## Recommendation and boundary

Log blowup 2 is the knee of the observed curve. It removes almost half of the
fixed child wire and recursive arithmetic for less than a twofold native cost.
Moving to log blowup 3 saves another 337,632 wire bytes and 82,681 graph nodes,
but doubles prover time and memory again. The smaller savings at logs 4--6 do
not justify the exponential native cost.

This does not silently change V1. The candidate requires a new protocol/profile
identity and must pass the complete active 36-row outer proof, recursive proof
verification, security review, and mutation fleet. Native verifier time is not
outer-circuit verifier time; the exact graph and row inventories above plus the
partial outer checkpoint below are the relevant evidence until the complete
36-row proof exists.

## Engineering finding

The experiment exposed a hidden assumption in four RISC-V AIR components:
their quotient view borrowed the PCS committed LDE and required its blowup to
equal the AIR quotient domain. `prepared_evaluation_owner.zig` retains the
frozen V1 zero-copy path and, only when domains differ, reconstructs the
quotient-domain evaluation from retained coefficients with one batched twiddle
setup. That enabled all six real proofs without regressing the V1 path.

## Active outer-proof checkpoint

The recommended 4x/97 candidate now also crosses the partial recursive outer
proof for universal rows 20--23 and 25--34. The proof has 289 preprocessing,
756 main, and 236 interaction columns, 841 constraints, 26,675 shared Poseidon2
calls, and a 58,284-byte estimate. Independent verification and all three
outer mutation checks pass.

Live sampling found that the predecessor interaction builder authenticated an
entire Merkle preprocessing schedule and reconstructed a stateful prefix once
per row. That accidental quadratic host algorithm—not AIR polynomial degree—
dominated the run. Interaction tuples are now captured from the exact logical
Tree-1 column buffers before PCS takes ownership, so Tree 2 has neither a
second Merkle implementation nor repeated schedule hashing.

Single ReleaseSafe engineering runs on the same host measured:

| Outer execution | Prove s | Assembly s | STARK body s | Verify s |
| --- | ---: | ---: | ---: | ---: |
| Predecessor, one worker | 650.480 | 647.176 | 3.299 | 3.728 |
| Linear capture, one worker | 14.086 | 10.819 | 3.261 | 3.672 |
| Linear capture, four workers | 12.608 | 11.025 | 1.577 | 3.738 |

The algorithmic correction is 46.2x end to end and 59.8x in assembly at one
worker. Four-worker execution adds 1.12x end-to-end throughput and halves the
STARK-body time. Commitment stages remain nearly flat and are the next
performance target. These are diagnostic single runs, not the normative M9
crossover receipt; proof geometry and estimate remained identical.

## Reproduction

```text
STWO_RECURSION_FRI_FRONTIER_BLOWUP=2 zig build \
  test-riscv-recursion-poseidon-leaf -Doptimize=ReleaseSafe

STWO_RECURSION_FRI_CIRCUIT_FRONTIER=1 zig build \
  --build-file src/frontends/riscv/build.zig \
  test-recursion-protocol -Doptimize=ReleaseFast

STWO_RECURSION_FRI_FRONTIER_BLOWUP=2 \
STWO_RECURSION_ACTIVE_FRI_OUTER=1 \
STWO_RECURSION_OUTER_WORKERS=4 zig build \
  test-riscv-recursion-poseidon-leaf -Doptimize=ReleaseSafe
```

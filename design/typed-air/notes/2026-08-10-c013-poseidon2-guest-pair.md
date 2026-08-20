# 2026-08-10 — C-013 exact Poseidon2 guest-pair preflight

## Question

Can C-013 compare portable RV32IM execution with `CUSTOM-0` execution without
changing the function, public input, public output, termination contract, or
guest source between arms?

## Implementation

`vectors/riscv_guests/poseidon2_m31_permute_v1` is one pinned, `no_std` Rust
guest. Its default feature compiles the exact M31-width-16 Poseidon2
permutation to portable RV32IM; its `precompile` feature changes only the
measured permutation call to the admitted version-1 `CUSTOM-0` instruction.
The mutually exclusive `shape-balanced` and `shape-core-only` features add one
or fifteen identical portable background permutations per call to both arms;
the default dominant shape adds none. A volatile scratch write keeps that work
proof-visible without changing the final output. Both arms read
`[call_count][call_count * 16 lanes]`, publish every output lane in order, set
the same halt flag, and share one linker contract. The extension arm alone
carries the non-allocating `.note.stwo.zkvm` admission descriptor. ADR-0034
fixes these definitions before repeated capture.

The `check-c013-poseidon2-pair` build step generates a deterministic canonical
input, proves that each ELF is rejected by the other execution profile, runs
all six guests with strict proof-bearing completion, compares output bytes,
and checks every frozen call record and execution-row index. Its reusable
corpus owner has a focused unit test and a hard 4,096-call bound.

## Current evidence

The all-shape ReleaseFast checker passes at one call. Every shape has input
SHA-256
`eb07af873dd1211b8e033da3093a2c51c1a8dee325e13e9497dbda1549222d4b`
and output SHA-256
`0c425365ef3800a7bcd30f37b94cdf08f1ab3028a87b7dbc00749b6bb5087d06`:

| Shape | Background/call | Software steps | Precompile steps | Software ELF SHA-256 | Precompile ELF SHA-256 |
| --- | ---: | ---: | ---: | --- | --- |
| `poseidon2_dominant` | 0 | 58,054 | 84 | `37fff98ceb46a2670353e64600a6afab6c210befcb055df5a2a4a6dbd98e8f69` | `4d0948b434268211dacb92a1a83f030e90cf5a04b29e85c4d82f657e98f333a4` |
| `balanced_core_and_poseidon2` | 1 | 116,096 | 58,058 | `b8fabb6cad9bd89b251550aad00864d5629e3de1e16160d25918b8ccf2a41792` | `efc030beb8a8cbc021ab8045a8b5b22e1622d1b2a7a0427875539576128494ba` |
| `core_only` (core-dominated) | 15 | 927,079 | 868,707 | `4ddff3ec4c7a1c096f69f56e7d8ff2e0137856e2f5f995f90f2e917e201b5453` | `d00c1e960018aa4c5e0479aeaf2c70642a2e6365f79374cd0080bcb5ccb39281` |

The step count includes the common guest I/O loop and proof-visible background
work. It is exact semantic geometry, not a proving-speed measurement.

Before ADR-0034 fixed all three shapes, an opt-in ReleaseFast one-call CPU proof
preflight completed for both dominant arms under the explicitly non-secure
functional PCS profile
`pow_bits=0/log_blowup=1/queries=3/fold_step=1`. Each proof was encoded and
then consumed by the independent verifier API. The exact one-shot record is:

| Metric | Software | Precompile | Precompile / software |
| --- | ---: | ---: | ---: |
| Execution steps | 58,054 | 77 | 0.00133 |
| Execution time (ns) | 3,422,541 | 150,750 | 0.04405 |
| Proving time (ns) | 604,949,709 | 479,975,417 | 0.79341 |
| Verification time (ns) | 103,357,875 | 100,739,167 | 0.97466 |
| Verified-request time (ns) | 711,730,125 | 580,865,334 | 0.81613 |
| Binary proof bytes | 83,052 | 114,188 | 1.37490 |
| Preprocessed cells | 9,639,328 | 9,474,976 | 0.98295 |
| Main cells | 9,346,976 | 3,457,792 | 0.36994 |
| Interaction cells | 14,441,344 | 11,957,632 | 0.82801 |

The one-call input and output SHA-256 values are respectively
`eb07af873dd1211b8e033da3093a2c51c1a8dee325e13e9497dbda1549222d4b`
and `0c425365ef3800a7bcd30f37b94cdf08f1ab3028a87b7dbc00749b6bb5087d06`.
The software proof digest is
`12e419505cdf8fcea4536677fcf6593d975ccbf08dd855b3a5d3981891f5ed62`;
the precompile proof digest is
`bb7ca2ad26a9a5ad0b43e9f31272c01462ce423be5c5d0bc03e2860ca7de686b`.
Those proof identities bind the earlier pre-shape precompile ELF. They remain
honest historical diagnostics but are not current capture artifacts; the
source-refactored dominant pair is rechecked below.

This single development sample is directionally encouraging: it removes
63.01% of main cells and 17.20% of interaction cells and was 20.66% faster in
the timed prove boundary. It also exposes a real tradeoff: the additional
component openings make the encoded proof 37.49% larger at one call. Neither
direction is a promotion result without repeated fresh processes, secure
parameters, A/A calibration, and the frozen call-count/shape sweep.

The same one-call comparison also passes with the release PCS profile
`pow_bits=26/log_blowup=1/queries=70/fold_step=1`:

| Metric | Software | Precompile | Precompile / software |
| --- | ---: | ---: | ---: |
| Proving time (ns) | 714,313,708 | 649,818,083 | 0.90971 |
| Verification time (ns) | 91,211,708 | 89,539,875 | 0.98167 |
| Verified-request time (ns) | 812,351,457 | 739,463,499 | 0.91028 |
| Binary proof bytes | 796,112 | 1,020,848 | 1.28229 |

The secure proof digests are
`d0854ea21b69df50b50fb5e165bd51e2252aeef5d65e7a3de4bacd89f4af9ce3`
and `fe16a5f5cfd1a7e628c23ce3b54069d2115e7d0aac6ff59971dc2c733feb7b13`
for software and precompile respectively. This establishes secure correctness
and repeats the one-call size tradeoff; it remains one in-process observation.

## Fresh-process child foundation

`riscv-poseidon2-proof-child` now runs exactly one arm and independently
verifies it. Its v3 strict schema binds arm, security, phase, shape, exact
portable-background count, call/sample index, input/output pins, PCS
parameters, source commit/tree/dirty digest, executable/ELF/proof identities,
exact cells and times, and Darwin peak footprint, process CPU nanoseconds,
energy, instruction, and cycle counters. Process CPU is converted from the
kernel's Mach absolute-time ticks with the host timebase and wide intermediate
arithmetic. Non-diagnostic samples require all counters, both corpus pins, and
the canonical schedule digest. The child derives the requested sample from
that schedule and
rejects arm, call count, phase, shape, schedule, or identity substitution
before execution. All three shapes are admitted; calibration is deliberately
rejected because A/A uses the separate `multi_shard_addi` authority.

The ReleaseFast `check-c013-poseidon2-proof-child -j1` smoke launches one fresh
functional child per arm under executable SHA-256
`8daebabf9813b9ad6d46b921ba33d298c1aaeb847881976dac9408278c11fb53`:

| Metric | Software | Precompile | Precompile / software |
| --- | ---: | ---: | ---: |
| Proving time (ns) | 646,891,542 | 516,330,125 | 0.79817 |
| Verified-request time (ns) | 757,075,751 | 620,812,041 | 0.82001 |
| Peak physical footprint (bytes) | 1,300,317,840 | 1,190,069,760 | 0.91521 |
| Energy (nJ) | 15,233,441,096 | 13,676,480,490 | 0.89779 |
| Instructions | 50,160,713,332 | 44,183,616,988 | 0.88084 |
| Cycles | 20,888,332,110 | 18,287,835,504 | 0.87550 |

These two samples have correct separate-process resource ownership and exact
output pins, but they are still diagnostics: no warmups, alternation,
calibration, cooldown, secure profile, or statistical decision was applied.

## What this does not establish

This preflight is not the normative C-013 or M6 performance receipt. Secure
correctness and fresh single-arm resource capture now exist, but neither run
uses the required A/A-calibrated ten-warmup/three-round protocol. There is no
Metal capture cohort, confidence interval, or 0/1/8/64/512/4096 secure
capture. The six shape executables and complete 1,440-attempt plus eighty A/A
schedule are fixed. A create-only CPU orchestrator, retained reduction, and
independent validator now consume that authority, as documented in the
[2026-08-12 readiness audit](2026-08-12-c013-cpu-capture-readiness.md), but the
current dirty shared checkout cannot publish an admissible plan. Cell counts come from the
authenticated statements, but they are not yet the protocol's complete
committed-cell accounting. In particular, the dominant VM-step reduction does
not imply the same proving-speed improvement because fixed PCS work and the
caller/provider AIR remain material. C-013 remains open until the frozen
protocol's fresh serial children, required Metal cohort, and complete
validator-recomputed receipt exist.

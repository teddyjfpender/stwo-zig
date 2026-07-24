# CUDA System Extraction: Session 02

## Record

- Date: 2026-07-24
- Model: GPT-5 Codex
- Local integration branch: `feature/cuda-system-architecture`
- GPU host: NVIDIA GeForce RTX 4090, SM89, driver `580.126.09`
- Toolchain: Zig `0.15.2`, CUDA `12.8`, `ReleaseFast`
- Method: exact-proof gates followed by paired, counterbalanced diagnostic
  screens; no profiler replay is treated as a verdict

This is a sanitized engineering transcript. It records hypotheses, evidence,
decisions, and rejected designs without hidden reasoning or unverifiable
claims.

## Objective

Improve the complete resident CUDA prover rather than optimize one synthetic
wide-Fibonacci point. A candidate must:

1. apply through shared prover stages or a structurally admitted shape;
2. preserve canonical proof bytes and independent verification;
3. use strict AOT, zero CPU fallback, and one terminal device read;
4. pass the enabled structural portfolio without a material regression; and
5. justify added complexity with measured system-level benefit.

## Coverage Expansion

The starting CUDA checkpoint covered latency, narrow/deep, non-target wide,
and extreme wide-Fibonacci shapes. The current matrix adds:

- XOR at logs 14 and 16;
- Plonk at logs 14 and 16;
- seeded-wide Blake at `log10 x 10` and `log12 x 10`.

The Blake rows are deliberately not classified as hash-heavy. Their trace is
seeded xorshift data with a simple constraint, not a full Blake compression
AIR. State machine, true Blake/Poseidon, LogUp, RISC-V, and sustained mixed
queues remain disabled with explicit reasons.

## Accepted Checkpoint: Fused LDE Staging

Commit `d2aaaa1f` fused the first LDE interval with coefficient staging. The
eight-row fast paired screen produced:

| workload | candidate / baseline |
| --- | ---: |
| latency `log14 x 32` | 0.997793 |
| XOR log14 | 1.003401 |
| XOR log16 | 1.000260 |
| narrow/deep `log22 x 3` | 0.958748 |
| width 37 | 0.974217 |
| width 73 | 1.011551 |
| width 128 | 0.944120 |
| extreme `log22 x 100` | 0.899319 |

Equal-class portfolio ratio: `0.966055`, or 1.0351x. Every proof was exact,
strict-AOT, resident, zero-fallback, and used one terminal D2H. This remained
diagnostic because it used two rounds without confidence intervals.

## Accepted Checkpoint: Exact Blake Domain States

Commit `cbe939d6`, integrated as `122d5f0b`, replaced repeated compression of
the invariant leaf/node domain prefix with the exact post-prefix Blake states.
Arbitrary tags retain the generic path.

Clean two-round screen against `d2aaaa1f`:

| workload | speedup |
| --- | ---: |
| latency `log14 x 32` | 1.0976x |
| XOR log14 | 1.1059x |
| XOR log16 | 1.1305x |
| narrow/deep `log22 x 3` | 1.1519x |
| width 37 | 1.1110x |
| width 73 | 1.0817x |
| width 128 | 1.0621x |
| extreme `log22 x 100` | 1.0393x |

Portfolio ratio: `0.910995`, or 1.0977x.

The compiler effect explained the broad win:

- Merkle child: 194 registers / 128-byte stack to 40 / 64;
- FRI leaf: 128 / 128 to 40 / 64;
- four-level interior: 193 / 128 to 40 / 64;
- progressive initialization: 40 / 64 to 22 / 0.

Evidence:

- remote screen: `/workspace/cbe939d6-domain-screen-clean.json`;
- proof/oracle parity: `/workspace/cbe939d6-proof-parity`;
- device smoke: `/workspace/cbe939d6-domain-smoke-out`;
- local screen SHA-256:
  `95d6af2f286bd277f6e360b55e32295caf4f7ca0b6072b17e434ada46f795b17`.

## Integration Findings

Activating complete product-route tests found code that ordinary unit closure
did not analyze:

- Plonk still called the shared trace executor through an obsolete signature;
- XOR and wide Fibonacci under-reported statement transcript cardinality in
  their ProofProgram metadata;
- the benchmark validator assumed exactly one AOT function per proof, while
  Plonk correctly loads two.

Commits `61269d6e`, `b7b83be6`, and `d9bcc0f6` corrected the program contracts,
made Native CUDA product routes part of the release gate, and generalized AOT
lifecycle arithmetic to any number of distinct packaged functions.

For graph execution, the validator now requires:

```text
launches = distinct AOT loads
cache hits = 0
```

For direct repeated execution:

```text
launches = distinct AOT loads * repetitions
cache hits = distinct AOT loads * (repetitions - 1)
```

## Rejected Candidate: FRI Fold And Leaf Fusion

Commit `7f854f0c` fused every nonterminal FRI fold with the next leaf hash. It
passed the SM89 reference smoke, graph/direct exact proof parity, strict AOT,
zero fallback, and one terminal D2H.

The mechanism was real:

- wide-Fibonacci launches: 187 to 174;
- XOR log16 launches: 239 to 224;
- extreme launches: 349 to 328;
- FRI stage improvement: 2.1-6.3%.

The complete 12-workload result was not large enough:

- portfolio ratio `0.996220`, or 1.0038x;
- worst workload ratio `1.002506`;
- Plonk and one non-target wide row were neutral-to-slightly slower.

Adding 776 lines for a sub-1% system effect did not meet the repository's
complexity bar. Commit `fdffe8a6` reverted the candidate. Raw evidence:
`/workspace/7f854f0c-fri-full-screen.json`.

## Profiler Transition

Nsight Systems profiled the pre-FRI product at `log20 x 100`. The kernel-time
distribution was:

| kernel family | share |
| --- | ---: |
| `n2b_continue<4,4,false>` | 21.3% |
| `n2b_final_warp` | 10.3% |
| `n2b_continue<3,3,true>` | 8.3% |
| leading `b2n_continue` | 7.8% |
| contiguous Blake leaves | 6.2% |
| quotient single-write accumulation | 5.8% |
| Merkle child layers | 5.6% |
| AIR constraint AOT kernel | 5.6% |

The transform family totals roughly 58% of measured kernel time. The kernel
CSV is `/workspace/nsys-b7-log20x100-kernels.csv`, mirrored locally as
`/tmp/nsys-b7-log20x100-kernels.csv`, SHA-256
`48f85fb3a88b0d03e0ccd9d375a830fc8f951449988e9273c1153148fa6a1747`.

Decision:

> The next architectural target is not another small-kernel fusion. It is the
> coefficient/evaluation representation boundary and its N2B/B2N transform
> schedule.

## Rejected Candidate: Four-Lane Blake

A cooperative four-lane Blake implementation reduced contiguous-leaf usage
from 55 registers to 40 and parent usage from 40 registers plus a 64-byte
frame to 28 registers without a frame. Exact device and proof gates passed.

The measured result contradicted the register-pressure hypothesis:

- portfolio ratio `1.00973`, about 1% slower;
- extreme ratio `1.02209`;
- wide-class ratio `1.01254`;
- worst XOR ratio `1.03576`.

Four-lane coordination and reduced independent-hash parallelism outweighed
the lower register count. The source was removed. Evidence:
`/workspace/db9c0ac2-quad-leaf-full-screen.json`.

## Active Hypotheses

The session continues with three isolated candidates:

1. Replace the profiled log-21 N2B `{6,8,7}` schedule with stack-free
   `{6,6,9}` and a specialized nine-stage terminal.
2. Fuse quotient accumulation and combination so four intermediate coordinate
   arrays are not written and reread from global memory.
3. Complete state-machine CUDA as another frontend customer of the common
   resident pipeline.

No candidate is a promotion until the 12-workload matrix, exact proof parity,
strict-AOT residency, fallback, transfer, resource, and source-conformance
gates all pass.

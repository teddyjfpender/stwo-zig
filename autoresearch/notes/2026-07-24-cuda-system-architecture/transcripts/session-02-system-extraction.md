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

## Rejected Candidate: Quotient Accumulation And Combination

Commit `f57b8315` fused quotient accumulation and coordinate combination. It
passed graph/direct exact proof parity across Fibonacci, XOR, Plonk, and Blake,
with strict AOT, zero CPU fallback, and one terminal D2H.

The 12-workload screen measured:

- portfolio ratio `0.994658`, or 1.0054x;
- best narrow/deep improvement 2.08%;
- extreme improvement 1.26%;
- worst regression below 0.40%.

The implementation was rejected. Eliminating the intermediate coordinate
traffic is directionally correct, but a 0.54% system result does not justify
the added fused-kernel surface. Raw evidence:
`/tmp/98c08ea7-quotient-screen.json`.

## Accepted Candidate: Stack-Free Log-21 N2B

Commit `5c3b7c5b`, integrated as `b65a3e02`, changes the log-21 N2B schedule
from `{6,8,7}` to `{6,6,9}` and adds a specialized nine-stage terminal.

Focused `log20 x 100` evidence:

| boundary | predecessor | candidate | speedup |
| --- | ---: | ---: | ---: |
| graph verified request | 20.526 ms | 18.476 ms | 1.1109x |
| graph device time | 19.411 ms | 17.302 ms | 1.1219x |
| trace commitment | 11.460 ms | 9.616 ms | 1.1917x |
| direct verified request | 20.792 ms | 18.769 ms | 1.1078x |

The previous continuation compiled at 62 registers, a 64-byte stack frame,
and 32 KiB shared memory. The selected continuation uses 38 registers, no
stack, and 8 KiB shared memory; the nine-stage terminal uses 36 registers, no
stack, and 2 KiB shared memory.

Proofs are exact in graph/direct modes, strict AOT is active, CPU fallback is
zero, and there is one terminal D2H. The preceding 12-row screen, which did
not contain the affected `log20 x 100` regime, remained neutral at portfolio
ratio `1.003625`; every regression was below 1.05. That coverage omission is
now corrected by workload `large_wf_log20x100`.

Evidence:

- `/tmp/5c3b7c5b-n2b-full-screen.json`;
- SHA-256
  `fcdfc195f48ceff40fc0495e65ecacb43b890ea1b90095f46776b2cc73ccf8dd`;
- `/tmp/5c3b7c5b-n2b-evidence.tgz`.

## Parked Follow-Up: State-Machine Route

The state-machine CUDA route is compile-clean at commit `7b53973a` on branch
`feature/cuda-state-machine-route`. Local source closure, runtime contracts,
build-plan tests, formatting, and recursive semantic compilation pass.

This is not an accepted product route. It still requires SM89 compilation,
canonical CPU and pinned-Rust proof parity, strict-AOT/zero-fallback/one-D2H
telemetry, and benchmark/release integration.

## Session Boundary

No further speculative kernel is opened in this session. The final actions
are a corrected 13-workload screen containing the newly covered large
transform regime, evidence recording, release gates, and a clean branch.

The corrected two-round screen completed with:

- `large_wf_log20x100` ratio `0.898953`, or 1.1124x;
- equal-class portfolio ratio `0.989110`, or 1.0110x;
- worst row ratio `1.012187`;
- all 13 rows below the 1.05 regression ceiling;
- exact proof bytes, strict AOT, zero CPU fallback, and one terminal D2H on
  every measured session.

This screen deliberately isolates the N2B change against the immediate
pre-N2B product. The aggregate result is therefore not cumulative against the
session's original CUDA architecture baseline.

Evidence:

- `/tmp/b65a3e02-n2b-13row-screen.json`;
- SHA-256
  `ce974c4e12bb29c4c18d5f7929646ecd44ca8edc6be77560a21d14e43e61d025`.

The screen profile has no bootstrap confidence interval and is not headline
eligible. Its purpose is the final broad regression decision; the focused
exact-proof N2B evidence above establishes the affected regime.

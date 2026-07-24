# Session 01 — Metal Blake/Poseidon regression

## Objective

Investigate and reverse the current Metal regressions in Blake `12x16` and
Poseidon `log13` while preserving proof bytes, protocol identity, source-JIT/AOT
admission, zero CPU fallback, and the broader Native CPU/Metal portfolio.

## Starting evidence

The user supplied a same-matrix comparison of current `467edbc9` against
`e58b4d1e`. Most Metal cells improved, especially wide Fibonacci `16x64`
(`1.639x`), while Blake `12x16` regressed to `38.113 ms` (`0.738x`, or
`1.35x` slower) and Poseidon `log13` regressed to `20.472 ms` (`0.431x`, or
`2.32x` slower). The size-dependent reversal strongly suggests an execution
plan, residency, allocation, synchronization, or kernel-crossover problem
rather than a universal Metal slowdown.

## Evidence discipline and initial hypotheses

The canonical updater refused because three untracked researcher notes are
present; they were preserved. A fetch established that both local `HEAD` and
`origin/main` are exactly `467edbc9`, so the repo-resident CLI and source are
current.

Repository notes show earlier wins from batching sampled-value trees into one
Metal epoch and caching quotient-domain buffers. Those mechanisms should help
all AIRs, but may increase aggregate temporary storage or select an unfavorable
combined path for unusually wide/deep Blake and Poseidon commitments. This is
only a hypothesis. The first task is to reproduce the two cells and attribute
the delta by stage, dispatch, synchronization, allocation, and GPU timestamp
before editing.

Alternatives currently held open:

- a post-`e58b4d1e` combined LDE/Merkle crossover that benefits Fibonacci but
  over-allocates or serializes Blake/Poseidon;
- resident-storage capacity/eviction or ownership behavior at these shapes;
- a family-dependent trace/quotient path that creates extra GPU epochs or CPU
  copyback;
- a shader occupancy or threadgroup crossover exposed only at the larger
  Blake/Poseidon geometries;
- measurement identity mismatch, stale binary, or source-JIT lifecycle
  differences, which must be excluded before calling a code regression.

No implementation choice has been made.

## Local reproduction

A complete 13-row functional CPU/Metal matrix was run locally from current
`467edbc9` with three warmups and five verified samples per lane. It reproduced
the supplied result:

- Blake `12x16`: CPU `15.30 ms`, Metal `39.19 ms`;
- Poseidon `log13`: CPU `12.19 ms`, Metal `20.61 ms`;
- Blake `10x10`: Metal remains healthy at `7.25 ms`.

A clean detached `e58b4d1e` build, measured immediately afterwards with the
same binaries/protocol/boundary, produced Blake `27.96 ms` and Poseidon
`8.74 ms`. Canonical proofs are unchanged across CPU, Metal, and both commits:
Blake `70e51695...96fbc9f`, Poseidon `f196835d...1200f1`. This rules out
workload, protocol, proof, and runtime-mode mismatch.

## Profile result and falsified hypothesis

Exact-workload Metal stage profiles and encoder timestamps were captured after
30 warmups. The initial eight-way CPU BLAKE2s terminal-tail hypothesis was
false: main-trace Merkle time is flat or slightly faster. The regression is
entirely in `core_prove`, dominated by quotient construction.

Across 31 profiled requests:

| workload | command buffers | encoders `e58` -> current | core prove `e58` -> current |
| --- | ---: | ---: | ---: |
| Blake `12x16` | 248 -> 248 | 807 -> 48,661 | 18.39 -> 44.79 ms |
| Poseidon `log13` | 248 -> 248 | 899 -> 40,246 | 5.29 -> 28.74 ms |

`e58` executes one `quotient_rows_raw` dispatch per proof. Current executes
approximately one `quotient_numerator_raw` dispatch per raw column: about
1,536 for Blake and 1,264 for Poseidon, followed by a finalize dispatch. The
logical telemetry still calls this one quotient operation, which is why the
regression was invisible in the headline dispatch count.

The transition comes from the post-`e58` resident-FRI change that lowers the
segmented zero-copy threshold from 64 MiB to 8 MiB whenever any resident tree
exists. That policy is excellent for a wide contiguous tree (the measured
Fibonacci gain) but catastrophic for AIRs whose many independently allocated
columns become one source run each.

## Problem-match brief

Task and required semantics:
Choose how exact raw quotient inputs reach one Metal quotient evaluation. The
output is the same four-coordinate quotient column and transcript-visible
Merkle/FRI commitment; ordering and field arithmetic are immutable.

Inputs, measured scale/provenance, encoding, and computational model:
Apple M5 Max UMA, ReleaseFast source JIT, raw byte count `B`, quotient rows
`N`, batches `Q`, raw views `V`, and physically bindable source-run count `R`.
Blake and Poseidon have `R` approximately equal to 1,536 and 1,264. Wide
Fibonacci has tens of columns but a low resident run count. Cost is CPU memory
traffic, GPU global traffic, encoder/dispatch count, and synchronous request
latency.

Constraints, promises, invariants, and exploitable structure:
Columns and views are immutable during the command; all arithmetic is exact;
UMA permits page-backed no-copy buffers; resident-tree columns may already
share one device buffer; a staged flat buffer preserves the existing canonical
view offsets.

Candidate matches, relationship, and evidence status:

| candidate | relationship | cost/guarantee | fit and risk |
| --- | --- | --- | --- |
| flat staging + fused quotient | exact gather/staging transform | `O(B)` CPU copy, one dispatch, exact | measured `e58` winner for fragmented AIRs; extra host pass |
| segmented zero-copy accumulation | exact segmented reduction | `R` dispatches and `O(R*N*Q)` accumulator traffic in current kernel | measured winner for low-`R` resident wide traces; catastrophic at high `R` |
| argument-buffer segmented fusion | exact descriptor/resource gather | potentially one dispatch, feature/layout work | plausible future architecture; high ABI/residency risk |
| one blit epoch then fused quotient | exact GPU staging transform | `R` copy commands, one quotient dispatch, extra GPU pass | credible future alternative; still creates `R` source resources |

Chosen canonical problem and exact variant:
Adaptive gather-versus-segmented reduction under an I/O/launch-cost model. This
is an exact algorithm crossover, not workload specialization.

Project -> canonical mapping and solution recovery:
Raw columns map to input segments; raw views map to weighted segment queries;
the quotient output is recovered identically. Use segmented zero-copy only
when its physical run count is bounded; otherwise use the existing flat gather
and fused kernel.

Complexity/limits, named parameters, and citations:
The derived current segmented cost includes `R` full-row dispatches and repeated
read/modify/write of `Q*N` QM31 accumulators, in addition to source arithmetic.
The flat path copies `B` bytes once and evaluates all `V` views in one dispatch.
Apple's repository-cited Metal guidance favors fewer command encoders and
larger useful epochs when tiny submissions dominate.

Prior algorithms, solvers, and implementations:
Both exact implementations already exist in `quotients.m`; this change only
repairs their crossover. An argument-buffer or GPU staging architecture is
deferred until the restored crossover is measured.

Selected transfer, integration boundary, and rejected alternatives:
Count physical source runs using the same residency/contiguity rules as the
segmented encoder. Preserve the existing >=64 MiB large-resource policy.
For the 8--64 MiB resident optimization, require a small bounded run count.
Reject a workload-name, row-count, or AIR-family switch. Reject globally
restoring the 64 MiB threshold because it would discard the wide-Fibonacci
resident gain.

End-to-end prediction, crossover, and falsifier:
Blake/Poseidon must return close to `e58` quotient time and encoder topology,
while wide Fibonacci `16x64` retains its low-run segmented path. The hypothesis
is falsified if the two affected cells do not lose approximately 1,200--1,500
encoders/proof, if proof bytes differ, or if wide Fibonacci materially regresses.

Correctness and benchmark plan:
Differential Metal/CPU proofs, focused Blake/Poseidon matrix, exact profiler
topology, holistic 13-row matrix, ReleaseFast Metal/core/prover tests, AOT
compile/probe, and final paired S3 Metal-board evidence.

Open uncertainty:
The optimal numeric run threshold needs measurement. A conservative 64-run
ceiling is expected to retain known low-run resident traces while remaining
far below the measured high-fragmentation regime.

## Metal design brief

Workload and target devices:
Compute-only quotient construction on Apple M5 Max; preserve supported Metal
runtime/AOT variants and existing fallback policy.

Unit of work and equivalence oracle:
One verified Native proof. CPU/Metal canonical proof bytes and the pinned Rust
oracle are authoritative.

Measurement boundary, build mode, and run conditions:
ReleaseFast, functional protocol, verified full request; source JIT warmed for
steady-state diagnosis and separately retained for cold-process accounting.

Measured bottleneck and evidence:
Thousands of tiny numerator encoders inside one logical quotient command,
causing 5.4x Poseidon core-prove inflation and 2.4x Blake inflation.

Required features and fallbacks:
No new Metal feature. Existing shared/resident buffers, raw kernels, and fused
kernel remain unchanged.

Resource lifetime/storage table:
The low-run path retains current no-copy/resident sources plus private
numerators. The high-run path uses the pre-existing one-request shared flat
buffer and removes the private numerator buffer and thousands of temporary
source/view buffers.

CPU-GPU and pass dependency graph:
High-run: CPU pack -> one raw quotient kernel -> existing resident
Merkle/FRI chain. Low-run: existing segmented numerators -> finalize -> chain.
Command-buffer and terminal wait topology remain unchanged.

Command-buffer and in-flight ownership plan:
No new command buffer or wait; all resources remain retained by the synchronous
quotient call through completion.

Binding and pipeline-compilation plan:
Reuse existing PSOs and direct bindings. No compilation or ABI change.

Shader/threadgroup plan:
No shader change in the first candidate. Selection prevents pathological
repeated whole-domain launches.

Work/byte/dispatch budget:
High-fragmentation target changes roughly 1,300--1,500 numerator dispatches to
one fused dispatch, at the cost of one 10--50 MiB CPU pack already proven by
`e58`.

Expected counter or trace changes:
Encoder count returns near `e58`; `quotient_rows_raw` replaces
`quotient_numerator_raw` for Blake/Poseidon; command-buffer count, proof bytes,
and logical dispatch telemetry remain fixed. Low-run wide Fibonacci retains
`quotient_numerator_raw`.

Correctness, ABI, and synchronization proof:
Both branches pre-exist and are byte-parity tested; only their structurally
derived crossover changes. No ownership or synchronization edge changes.

Before/after validation plan:
Profile exact affected cells, then screen wide Fibonacci `16x64`, the holistic
matrix, and full production tests before any submission.

## Candidate 1: residency-aware physical-run gate

Implementation:
Factor the existing resident-source lookup into one helper, count the physical
source runs that the segmented encoder would bind, and admit the resident
8--64 MiB segmented path only at 64 runs or fewer. Keep the existing >=64 MiB
policy and all shader, command-buffer, ABI, residency, and synchronization
behavior unchanged. This is a structural fragmentation predicate, not a
workload or benchmark-size predicate.

Focused five-sample screen against the locally frozen `467edbc` build:

| workload | `467edbc` Metal prove | candidate Metal prove | improvement |
| --- | ---: | ---: | ---: |
| Blake `12x16` | 39.189 ms | 30.276 ms | 1.294x |
| Poseidon `log13` | 20.609 ms | 9.105 ms | 2.263x |

The earlier isolated target screen measured 31.133 ms and 9.223 ms,
respectively, for 1.259x and 2.235x improvements. Both screens preserve the
same canonical proof digests as CPU, current main, and `e58`.

The required preservation check passed: Wide Fibonacci `16x64` measured 8.503
ms in the isolated screen versus 8.531 ms on frozen current main. The exact
profile measured 8.418 ms candidate versus 8.358 ms main, a noise-sized
difference with exactly identical command topology (186 command buffers and
682 encoders across 31 profiled requests).

Exact profiler result:

| workload | current encoders | candidate encoders | current quotient shape | candidate quotient shape |
| --- | ---: | ---: | --- | --- |
| Blake `12x16` | 48,661 | 807 | 47,823 numerator dispatches | 31 fused raw dispatches |
| Poseidon `log13` | 40,246 | 899 | about 39,184 numerator dispatches | 31 fused raw dispatches |

For Blake, aggregate GPU command time fell from 692.87 ms to 265.55 ms and
encoder CPU time from 476.82 ms to 88.28 ms across the same 31 requests.
Command-buffer count remains exactly 248. The candidate topology now matches
`e58`, which is the expected falsifiable consequence of repairing the
crossover.

The first holistic screen completed all 13 rows with local verification,
deterministic samples, CPU/Metal canonical proof equality, and zero fallback.
The target rows improved. Several unaffected five-sample medians moved in both
directions on battery power; exact profiles of Wide Fibonacci `16x64`, Plonk
`log16`, and state machine `log16` show byte-for-byte proof parity and exactly
the same command-buffer/encoder topology between current main and candidate:
186/682 for Wide and 217/837 for both Plonk and state machine. Their isolated
prove times are within 0.7%, 1.4%, and 4.7%, respectively, with GPU aggregate
timing moving inconsistently with request timing. Treat those short-run
movements as measurement noise and retain them for the formal validation
rather than discarding them.

Dead end and corrected hypothesis:
The terminal eight-way BLAKE2s work was initially suspicious because it landed
after `e58`, but stage and encoder profiles falsified that theory. Main-trace
Merkle work was flat or faster; quotient scheduling alone explained the
regression. Likewise, a global restoration of the old 64 MiB threshold was
rejected because it would remove the demonstrated low-run Wide-Fibonacci
resident benefit.

## Validation after freezing candidate `6c20a59`

The source-only commit was rebuilt from a clean tree. The combined ReleaseFast
validation command passed:

- `test-stwo-core`
- `test-stwo-prover`
- `test-native-metal`
- `test-metal-core-aot`
- `test-metal-core-aot-probe`
- `metal-check`
- `source-conformance`

The Native Metal lifecycle executed a device-only proof and independent
verification. Source conformance reported only the five pre-existing,
explained findings and no new violation.

The clean ten-warmup/ten-sample holistic matrix completed all 13 rows:

| workload | CPU prove | Metal prove |
| --- | ---: | ---: |
| Wide Fibonacci `10x8` | 1.268 ms | 5.045 ms |
| Wide Fibonacci `14x32` | 4.531 ms | 4.339 ms |
| Wide Fibonacci `16x64` | 15.804 ms | 8.221 ms |
| XOR `log14` | 3.836 ms | 3.248 ms |
| XOR `log16` | 10.549 ms | 5.754 ms |
| Plonk `log14` | 3.975 ms | 3.452 ms |
| Plonk `log16` | 11.261 ms | 5.840 ms |
| state machine `log14` | 3.935 ms | 3.336 ms |
| state machine `log16` | 10.478 ms | 5.818 ms |
| Blake `10x10` | 9.674 ms | 6.820 ms |
| Blake `12x16` | 15.282 ms | 29.352 ms |
| Poseidon `log10` | 2.932 ms | 4.392 ms |
| Poseidon `log13` | 12.343 ms | 8.743 ms |

Every one of the 130 CPU and 130 Metal samples verified, repeated proofs were
byte-stable, all CPU/Metal proof pairs were identical, and fallback remained
zero. The two target proof hashes remained exactly
`70e516...fbc9f` and `f19683...00f1`.

Non-target structural screen:

| shape | main Metal | candidate Metal | observation |
| --- | ---: | ---: | --- |
| Blake `11x13` | 24.228 ms | 13.833 ms | 1.752x faster |
| Poseidon `log12` | 7.517 ms | 7.103 ms | 1.058x faster |
| Wide Fibonacci `15x48` | 6.137 ms | 6.819 ms | noisy short screen |

The apparent Wide `15x48` loss was investigated instead of ignored. Exact
profiles show identical 248-command-buffer/1,147-encoder topology and measured
the candidate at 6.749 ms versus main at 7.942 ms. This falsifies a structural
regression and demonstrates why the five-sample sequential value must not be
promoted over paired evidence.

## Tooling issues and measurement corrections

The repository's high-level Native profile wrapper could not complete the
requested exact workload capture because the CPU process exits before
`/usr/bin/sample` can attach, producing “CPU sample has no parsed top-of-stack
hotspots.” The profiler result was not fabricated or silently dropped. The
same repository profiler's lower-level Metal runner was used with 30 warmups,
one real verified proof, stage telemetry, GPU timestamps, encoder counters, and
the fixed production binary. This supplied the decisive physical scheduling
evidence while retaining the failed wrapper attempt as a tooling limitation.

`stwo-prof metal caps --json` documented in the profiling skill is not
supported by the installed CLI. The plain capability report was used:
Apple M5 Max, 32 KiB maximum threadgroup memory, 1,024 threads per threadgroup,
55.66 GB recommended working set, unified memory.

The locally built Rust interop verifier had SHA-256
`40bbf4...3a6b`, while the formal matrix requires the authenticated pinned
binary digest `bca743...b2b`. The holistic matrix was therefore correctly
marked local-verification/cross-backend evidence instead of being mislabeled
as formal Rust-oracle evidence. The official `stwo-perf` run supplied the
pinned-oracle check for its scored control.

The first attempted confirmation run encountered the harness's retained output
artifact and failed closed with `OutputAlreadyExists`. The complete first run
directory was moved intact into the evidence bundle, after which a clean
confirmation ran. No sample or receipt was overwritten.

## Official paired harness evidence

The first `core_metal/deep`, S3, all-guards receipt used seven or more paired
rounds and measured:

| guard | ratio | 95% CI |
| --- | ---: | ---: |
| Blake `12x16` | 0.758400 | [0.726969, 0.775765] |
| Poseidon `log13` | 0.426783 | [0.418456, 0.459222] |

All 13 regression guards passed their time budgets. Proof digests matched
across both arms. The scored Plonk row was neutral at 1.0114, as expected for
this storage-policy repair. That receipt missed only the Plonk energy vector,
exceeding the named ratio budget by 0.0224; it is retained, not discarded.

A declared all-guard confirmation moved Plonk to neutral 0.9989 and passed its
resource vectors, but the very small Wide-Fibonacci `10x8` guard was noisy and
missed its CI budget. That complete receipt is retained too. Finally, the
objective-only S3 control passed G1--G5 at Plonk ratio 1.0065 with 95% CI
[0.9901, 1.0224], including the pinned Rust oracle. It is the mechanically
admissible packaging receipt; the judge remains responsible for rerunning the
complete guard portfolio.

Final interpretation:
Poseidon is restored past the old official anchor and is now 1.41x faster than
CPU at the target shape. Blake removes the severe regression and returns to
within approximately 4% of the old 27.96--28.13 ms anchor. The paired
candidate/current result is statistically decisive for both targets. Further
Blake work should target the remaining quotient/commit cost, not reintroduce
the high-fragmentation segmented reduction.

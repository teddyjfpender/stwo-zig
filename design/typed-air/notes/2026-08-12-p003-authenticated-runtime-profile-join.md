# P-003 authenticated runtime-profile join

**Date:** 2026-08-12
**Reconciled:** 2026-08-20
**Status:** allocation-free authenticated join, schema-9/23-site producer
closure, and real CPU/Metal proof evidence complete; normative R-006 scaling
capture remains open

## Current reconciliation

This note preserves the original join design and its 2026-08-15 closure audit.
The provisional ten-site/V3 statements below describe that historical
checkpoint, not the current implementation. P-003 now validates at CPU,
Metal, and joint 16/16. The canonical matrix and inventory SHA-256 values are
`b1eef5ccf8405de9373c11b8fe9bd505a331add0601ab1904a1b038df0ee24d1`
and `13807efba664c2abc49325a80d8bc67c15896e7250ea48416e0d58e0f029982f`.
Real CPU `N=1/2/4` proofs independently verify with work authority
`df914f214597393737a7795fc988680df17ca0e5ba09d9d577930260cb703b14`,
receipt `9e99ccedbe8302548ef7c95babd445b48f270b355a26090badcec64388350f68`,
and Blake2s shell receipt
`864d550670c284c36dd79fc8521852504b2dd6221410d47cfffceeb56473b46f`.
The 3/3 real-device Metal gate independently verified with 118 authenticated
AOT exports and exact-once completion, but emitted no separate canonical
proof, transcript, work, or shell identity; none is inferred from CPU values.

R-006 plan V4 now binds and recomputes that complete matrix and inventory plus
the versioned M7 generated-input geometry: balanced at 8 calls and dominant at
4096. Balanced uses the exact recurrence `S(n) = 58,018n + 40`, yielding
464,184 retired guest instructions at 8 calls: 8 CUSTOM instructions and
464,176 core rows. The exact dominant-4096 count remains pending the clean
smoke. These M7 counts do not revise M6's frozen common 4096-call gate;
balanced `S(4096) = 237,641,768` exceeds the current one-shot `2^24` AIR limit
and remains open pending segmented/recursive proving. A
V4 records and holds stable the machine-observed power source without requiring
AC; Battery Power is admissible only with Low Power Mode off and the same
idle/load/thermal thresholds. A plan-bound post-capture phase retries fresh
unchanged-threshold host samples
every 30 seconds for at most 15 minutes. Fsynced attempt-publication and host
boundary journals enforce no retry, guarded prefix resume, and byte-idempotent
finalization; a full simulated 2,080-attempt crash/replay passes. Quieting
timeout leaves that durable evidence resumable. The normative scaling receipt
is still null.

## Question

Can runtime measurements be connected to the exact AIR they measured without
turning estimates, nested stage time, or incomplete task telemetry into a
performance claim?

## Result

[`runtime_profile.zig`](../../../src/frontends/riscv/air/lang/runtime_profile.zig)
defines `stwo.typed-air.runtime-profile.v1`, a fixed-shape receipt joining four
independent authorities:

1. the validated P-002 report for all seventeen native typed opcode families;
2. the complete prover-API hierarchical stage profile;
3. the complete prover-API bounded task-graph profile; and
4. caller-supplied implementation, workload, protocol, proof, timing, resource,
   backend, optimization-mode, and verification observations.

The join validates every source before hashing it. It recomputes task lifecycle
counts, wait/run/work totals, physical-worker capacity bounds, canonical event
order, timestamps, contribution coverage, contribution completion state, and
per-component aggregates. Stage durations must be finite and non-negative;
their nanosecond projection has explicit overflow, maximum-depth, and
maximum-node bounds. Runtime and workload display identities must agree between
the hierarchical and flat schemas.

The receipt authenticates the complete raw stage and task records with
domain-separated SHA-256 digests, not only their aggregates. It separately
reports root-stage elapsed time and the sum over every nested node; the latter
is intentionally labelled as nested and may double-count parent/child time.
Canonical JSON contains every receipt field and validates before writing.

`join`, `Profile.validate`, `Profile.evidenceComplete`, and digest construction
allocate nothing and sample no clocks. Symbolic/static collection and telemetry
snapshot ownership stay outside this boundary, so joining evidence cannot
perturb a measured proving interval.

## Exactness and promotion policy

Work counters carry one of three authorities:

- `unavailable`: every field/FFT/FRI/Merkle counter must be absent;
- `structural_estimate`: every counter must be present but remains diagnostic;
- `instrumented_exact`: every counter must be present and was observed by the
  implementation.

Missing and partial counter groups fail closed. `evidenceComplete` additionally
requires independent proof verification, peak RSS, instruction and cycle
counters, non-empty stage and task capture, complete task graphs, and physical
worker accounting. It is only an admission predicate for a later comparative
corpus: it does not perform A/A calibration or promote an optimization.

### Historical 2026-08-15 exact-work audit

The transport is now `stwo.prover.logical-work-profile.v2`. Its digest binds
the six counters, source mask, record count, producer-ledger schema, expected
and completed producer counts, and the terminal coverage seal. The strict
R-006 parser independently recomputes that digest. This is transport and
validation authority, not yet measurement authority.

One field-operation producer is exact today: the generic M31 forward FFT used
by coefficient-form polynomial commitment. If `B` logical radix-2 butterflies
complete, its contribution is exactly `(additions, multiplications,
inversions) = (2B, B, 0)`. Fused radix, SIMD, and device implementations use
the same completed scalar-pair count. No broader field-operation total is
published from this fact.

The current source inventory is provisional. It groups ten sites into seven
coarse boundaries and checks free-form source comments. Those comments do not
make deletion of both a plan and its matching record observable, and boundary
counts let one site impersonate another. Promotion therefore requires a typed
`Site` identity carried by both `expectProducer(.site)` and the completed
delta, compile-time `Site -> Boundary` aggregation, per-site expected and
completed arrays, and a source gate over executable enum-literal calls. Until
that replacement lands, `producer_coverage_terminal_sealed` is not sufficient
evidence of producer exhaustiveness.

Production also deliberately fails closed. The normal installed binary does
not call `finalizeFieldCoverage`, so `finalizePlannedProducerCoverage` cannot
promote the partial record. A real profiled request consequently remains
`riscv_profiled_proof_v3` with no `work_profile`; V4 exists only in validation
fixtures. `riscv_profiled_proof_v4` must not be claimed until one installed
binary emits it for a real request that independently verifies.

#### Counter algebra

The V1 counter semantics use the operation's own field as the unit: an M31,
CM31, or QM31 operation contributes one operation, extension operations are
not expanded into M31 coordinates, subtraction counts as addition, and
logical negation and data movement are free. SIMD and device kernels expand
completed logical lanes. The implementation must use checked `u64` arithmetic
for every formula below.

The common exact primitives are:

- radix-2 butterfly or inverse butterfly: `A=2, M=1, I=0`;
- circle-point addition/doubling over `F`: `A=2, M=4, I=0`;
- circle `doubleX`: `A=2, M=1, I=0`;
- transcript seed to secure circle point: `A=3, M=3, I=1`;
- classic batch inverse of `n>0` values: `A=0, M=3(n-1), I=1`;
- striped/packed batch inverse of `n` values at width `w`:
  `A=0, M=3n+w-3, I=1`; and
- an empty batch inverse: zero operations.

The selected batch-inverse width is part of the observation. M31 selects
`w=8`, then `w=4`, when its divisibility thresholds hold. AArch64 CM31/QM31
selects `w=32`, `16`, or `8`; otherwise the generic striped/classic rule
applies. A chunked call is the checked sum of the selected formula for its
actual chunk lengths.

#### Remaining field-operation producers

This is the closure ledger for the ordinary native RISC-V proof. `n=2^l`,
`k` is a column count, `D` is the number of quotient sample-point batches,
`C` is the number of executed column contributions, and `m` is a fold's output
length. A backend may implement a different schedule only by returning an
exact capability-specific tally; otherwise profiling that request is
unavailable.

| Producer and owner | Exact contribution required before terminal seal |
| --- | --- |
| Cold M31 twiddle construction — `src/prover/poly/twiddles.zig::{slowPrecomputeM31Twiddles,precomputeM31}` and `twiddle_source.zig::TwiddleSource.get` | For a root coset of size `T=2^r`, the point walk and per-layer coset doubles contribute `A=2(T-1)+4r`, `M=4(T-1)+8r`. Inverse twiddles contribute `T` direct inversions when `T<4096`; otherwise sum the batch-inverse formula over the actual 4096-element chunks. Cache hits contribute zero. Borrowed towers charge construction to the request that actually builds the tower, never to later views. |
| Column interpolation — `src/prover/poly/circle/transforms.zig::{interpolateIntoBufferWithTwiddles,interpolateBuffersWithTwiddles}` and `src/prover/pcs/columns/circle_transforms.zig` | For a batch of `k` M31 columns: `l=1`: `A=2k, M=3k+3, I=1`; `l=2`: `A=8k, M=8k+8, I=1`; `l>=3`, with `B=knl/2`: `A=2B, M=B+kn, I=1`. The CPU combined-LDE path uses one-column batches and therefore one inversion per job; generic batching shares one inversion. |
| Remaining forward circle FFT sites — `src/prover/pcs/columns/preparation.zig`, `circle_transforms.zig`, and `src/prover/poly/circle/transforms.zig` | For every completed M31 forward butterfly, `A=2, M=1`. A full transform has `B=knl/2`; the exact 2x extension skips its degenerate first layer and has `B=kn(l-1)/2`. Passthrough has zero. The already-wired polynomial-commit site is not a substitute for interpolation, extension, combined-LDE, or composition sites. |
| Secure-composition interpolation — `src/prover/poly/circle/secure_poly.zig::interpolateAndSplitFromEvaluationWithTwiddlesForBackendAndWorkRecorder` | The generic and CPU paths execute four independent one-column batches, so they use four copies of the interpolation formula with `k=1` (including four normalization inversions), not one `k=4` batch. A proven constant/already-coefficient fast path contributes zero transform work. Device execution must return its actual batch/lane geometry or fail closed. |
| Main witness field work — `src/frontends/riscv/prover/main_trace_plan_execution_production.zig::Prepared.execute`, its production generators, and the generated typed witness executors | Each admitted generated witness program must expose a digest-bound operation tally. For each executed row/program, add `#add + #sub`, `#mul + #square`, and `#inv` from the actual lowered field schedule; multiply by completed scalar lanes. Infrastructure generators add their own typed tallies. Integer RISC-V execution is not silently converted into field work. |
| Sparse-memory and guest Poseidon witness work — `src/frontends/riscv/air/memory_commitment/{sparse_merkle.zig,poseidon2.zig,poseidon2_air.zig}`, `src/frontends/riscv/air/guest_precompile/main_trace.zig`, and `src/frontends/riscv/common/poseidon2.zig` | One pinned production Stark-V Poseidon2 permutation is `A=1418, M=650, I=0`. Charge every tree-construction and validation-rebuild permutation, every active AIR row, and both the preflight and committed-materialization pass for each active guest call; padded rows contribute zero. The distinct common implementation is test/legacy-only with no production callsite and remains separately tagged at `A=1382, M=650, I=0` so it cannot substitute for Stark-V accounting. |
| Relation challenges and interaction traces — `src/frontends/riscv/air/relation_challenges.zig`, `air/logup.zig`, and `src/frontends/riscv/prover/interaction_trace{,_prepared_logup}.zig` | Challenge-power construction contributes one QM31 multiplication per declared relation element (80 for the current 12-relation suite). A relation combine of arity `a` contributes `A=a+1, M=a`. For each paired LogUp term, fraction preparation contributes `A=1, M=3`; each accumulated term contributes `A=1, M=1`; add the selected batch-inverse formula over each actual chunk and the exact prefix/offset additions. Single terms omit paired-fraction work. Component row-pair builders must publish their relation-combine counts. |
| AIR composition on the domain — `src/backends/cpu_scalar/riscv_composition_lanes.zig`, `src/prover/air/{component_prover.zig,lookup_polynomial_v2.zig,accumulation.zig}` | The authenticated base/lookup expression programs must expose `A_nodes=#add+#sub` and `M_nodes=#mul+#square` per active scalar row, plus their explicit relation-combine and lookup-transition formulas. Root weighting contributes one QM31 multiply and one add per root. `generateSecurePowers(N)` contributes `N` QM31 multiplications. Fresh stores are free; repeated accumulation, worker merges, bucket lifting, and constants contribute exactly the operations executed by `DomainEvaluationAccumulator`. Generic components without a typed tally make field coverage unavailable. |
| OODS point, masks, and point composition — `src/core/circle.zig::secureFieldPointFromRandomSeedChecked`, `src/core/air/components.zig`, RISC-V component `maskPoints`, and `evaluateConstraintQuotientsAtPoint` | The seed map contributes `(3,3,1)`. Each secure circle add/double contributes `(2,4,0)` and each `doubleX` contributes `(2,1,0)`. The exact mask plan must count repeated doubles and previous-row shifts once per call actually made. OODS constraint evaluation reuses the authenticated expression tally for one row, plus coset-vanishing, inverse, and point-accumulator operations; it cannot borrow the domain-evaluation count. |
| Sampled committed-column evaluation — `src/prover/pcs/sampled_values.zig` and `src/prover/poly/circle/{point_evaluation.zig,evaluation.zig}` | Coefficient path, one log-`l` polynomial at one point: factor construction `A=2 max(l-2,0), M=max(l-2,0)` plus `n-1` QM31 additions and multiplications. Each pre-folded point adds `A=3f, M=2f`. A materialized subset basis follows the actual low/high-block schedule, and evaluation contributes `n` QM31 additions and `n` base-scalar multiplies per polynomial/point. The barycentric fallback must tally context construction, denominator work, one actual batch inverse, two post-weight multiplies per value, and one multiply/add per final term; it must not reuse the coefficient formula. |
| Quotient sample preparation — `src/core/pcs/quotients/{samples.zig,row_evaluation.zig}` | Each sample advances the random power once (`M=1`). Each `complexConjugateLineCoeffs` contributes `A=3, M=5`; summing its two linear coefficients contributes `A=2`. Each distinct sample batch precomputes a determinant with `A=1, M=2`. Periodicity points additionally charge their exact circle doubles and one point add. |
| Quotient row execution — `src/prover/pcs/quotient_{domain_walk,row_executor,scalar_executor}.zig` and `src/core/pcs/quotients/row_evaluation.zig` | Materialized row work before inversion is `A=5D+C, M=4D+C`; streaming row work is `A=5D+V, M=4D`, where `V` is the number of combined views. Add batch inversion over the actual scalar-per-row or batched chunk shape. The bit-reversed walk charges one circle add per advance plus initialization: exactly `popcount(initial)+sum(popcount(delta[c]))+(rows-1)` circle additions for a full nonempty walk. Combined-plan construction separately contributes four M31 multiplies and four adds per source-cell contribution. |
| FRI circle-to-line fold — `src/core/fri/folding.zig::foldCircleColumnsIntoLineWithWorkspace` and backend equivalents | For output length `m`, the host schedule contributes `A=6m`, `M=7m+1+BI_M(m)`, `I=BI_I(m)`: the M31 coordinate walk, one batch inverse, QM31 inverse butterflies, alpha products, and accumulation. It records exactly `m` FRI folds. Device-resident inverse generation needs its own equivalent logical receipt. |
| FRI line folds — `src/core/fri/folding.zig::foldLineInPlaceNWithWorkspace` and backend equivalents | One halving to output length `m` contributes `A=5m+4`, `M=6m+9+BI_M(m)`, `I=BI_I(m)` on the in-place CPU schedule, including its alpha square. Sum this over actual layer lengths; each layer records `m` FRI folds. The allocating reference squares alpha only between folds, so its exact schedule differs by one multiply and must carry a distinct site/capability. |
| FRI last-layer interpolation — `src/backend/line_evaluation.zig::{LineEvaluation.interpolate,lineIfft}` | With `B=nl/2`, the current line IFFT contributes `A=4B+4l`, `M=5B+8l+n`, `I=B+1`: every butterfly walks one M31 point, performs one direct M31 inverse and one QM31 inverse butterfly; every layer doubles the domain; normalization performs one inversion and `n` multiplies. |
| Transcript, PCS Merkle, PoW, decommitment, and encoding — Blake2s channel/VCS implementations and proof assembly | The production Blake2s transcript, Blake2s Merkle hash, PoW, byte encoding, and query extraction execute zero field operations. PCS internal nodes still contribute to the separate `merkle_compressions` counter. Any Poseidon-backed channel/VCS is a different typed producer and must report its permutation formula; it may not inherit this zero. |

Guest execution, proof serialization, and native verification are timing
partitions, but the present `scalar_lane_completed_algorithm_boundaries_v1`
string does not say whether their field work belongs to the logical-prover
counter. Before V4 promotion, the counter semantics must version this boundary
explicitly. The proposed definition includes witness materialization and the
native prover, treats the production Blake2s shell as included-with-zero, and
excludes guest execution, serialization, and independent verification. A
different choice is a schema change, not a documentation reinterpretation.

The compatibility RISC-V benchmark's opt-in `--profile` path now publishes this
receipt after independent verification. It binds the running executable bytes,
ELF/input/hint/hosted workload, PCS parameters plus witness-layout identity,
canonical proof bytes, measured execution/prove/encode/verify nanoseconds,
committed cells, stage capture, and task capture. Backend identity is a required
compile-time argument, preventing the CPU and Metal entry points from silently
sharing a mislabeled receipt. The generated legacy Fibonacci fixture also has
an explicit regression test for its self-loop completion contract.

The compatibility benchmark now samples the shared process counter authority
around the complete load/execute/prove/encode/verify interval. On Darwin this
fills lifetime peak physical footprint plus interval instructions, cycles, and
energy; unsupported hosts preserve explicit absence.

At that checkpoint this closed the schema, authenticated join, and
compatibility benchmark capture portions of P-003. It did not yet close P-003
globally because the production artifact adapter did not publish this receipt,
and the prover did not expose exact field-operation, FFT-butterfly, FRI-fold,
and Merkle-compression counters.

## Correctness evidence

The focused corpus pins a complete receipt digest,
`bceaa2fa4607a9fc488a48700ecc7c8ac2fc99e05f9ba2cbe5e76c7d30dac6f0`,
and covers:

- deterministic replay and canonical JSON;
- complete-source stage and task mutations that preserve the outer shape;
- malformed summaries, source schemas, timestamps, task order, attribution,
  identities, counter authority, and receipt fields;
- estimates and missing hardware counters remaining non-promotable; and
- validation occurring before any output byte is written.

```text
zig build --build-file src/frontends/riscv/build.zig \
  test-air-runtime-profile -Doptimize=Debug --summary all
Build Summary: 3/3 steps succeeded; 8/8 tests passed

zig build --build-file src/frontends/riscv/build.zig \
  test-air-runtime-profile -Doptimize=ReleaseSafe --summary all
Build Summary: 3/3 steps succeeded; 8/8 tests passed

zig build --build-file src/frontends/riscv/build.zig \
  test-air-runtime-profile -Doptimize=ReleaseFast --summary all
Build Summary: 3/3 steps succeeded; 8/8 tests passed

zig build test-riscv-bench -Doptimize=Debug --summary all
Build Summary: 2/2 steps succeeded

zig build riscv-bench -Doptimize=Debug --summary all
Build Summary: 2/2 steps succeeded

./zig-out/bin/riscv-bench --fib-n 8 --profile --proof-identity \
  --pow-bits 0 --n-queries 1
Result: a 36-cycle Debug smoke proof independently verified and one
authenticated runtime-profile JSON was emitted. On the Darwin capture host it
contained non-null peak footprint, instructions, cycles, and energy;
`evidence_complete=false` because exact field-work counters remain unavailable.
```

## Performance boundary

The new code is cold observability infrastructure and is not imported by any
production row-generation hot loop. The benchmark joins and renders only after
verification; an unprofiled run takes neither stage/task snapshots nor the new
identity/receipt path. It changes no statement, trace, claim, transcript draw,
proof byte, verifier order, batching decision, or backend kernel. No
proving-speed claim follows from these schema or smoke tests.

## Historical next production tranche

1. Wire the production artifact adapter to the joined schema without changing
   its already frozen unprofiled report.
2. Preserve fresh-process isolation so lifetime peak footprint has one-attempt
   meaning in normative cohorts.
3. Instrument field operations, FFT butterflies, FRI folds, and Merkle
   compressions at stable backend boundaries with a disabled-path zero-cost
   gate.
4. Run clean fresh-process `N=1/2/4` A/A and candidate cohorts and only then
   define P-004 regression budgets.

Items 1--3 are closed by the current schema-9 producer evidence. Item 4 now
belongs to R-006 and P-004 and remains open; this note does not claim a scaling
or regression verdict.

## Original-scope mapping

This advances the original document's AIR-generation profiler/cost-model and
parallel proving telemetry requirements. It also supplies the evidence join
required before the A-014 batching candidate or any materialization/layout
candidate can be described as a global performance improvement.

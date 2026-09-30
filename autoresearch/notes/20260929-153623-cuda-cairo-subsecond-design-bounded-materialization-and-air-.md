---
title: CUDA Cairo subsecond design: bounded materialization and AIR slices
author: Teddy Pender
created_utc: 2026-09-29T15:36:23Z
---

# Problem match: complete CUDA Cairo requests under latency and capacity limits

Task and required semantics:

Produce complete canonical Cairo proofs from ordinary PIE payloads, below one
second per warm verified request for every SN PIE, while reducing accounted
device peak and volatility. Preserve every active component, public statement,
lookup accumulator, commitment, transcript order and pinned Rust acceptance.
Optimize the request and critical-path work, not a cached proof or selected
kernel. The detailed CUDA design is in
[the dossier](2026-09-29-cairo-cuda-design-research/README.md).

Inputs, measured scale/provenance, encoding and computational model:

The retained v45 receipt has twelve verified H200/SM90 CUDA 12.8 proofs, three
cold-process trials per PIE. Prove/decode medians are 2.218/1.504/2.206/1.595 s;
adapted-input publication medians 7.042/5.708/7.118/6.420 s. Logical arenas are
107.197/64.055/106.027/83.911 GB. Whole-device NVML maxima, sampled every 10 ms,
are 114.800/71.649/113.626/91.513 GB; these are sampled peak lower bounds.
The current receipt omits raw PIE adaptation and external Rust verification
from its clock and is not a complete warm PIE request.

Task 09's adapted cycles are about 14.92/7.98/14.35/14.33 million; memory.bin
payloads 601.7/330.6/585.7/593.7 MB. The four host admissions each have 58
component placements. Fields are exact M31, CM31 and QM31; Cairo witness
deductions also use felt252. Cost models are field work/span, compiled private
bytes, global-memory traffic, H2D/D2H, peak live/reserved memory and measured
full-request wall time. Root-slice analysis uses authenticated AIR templates
and a fixed-order SSA dependency graph; it is not a GPU benchmark.

Constraints, promises, invariants and exploitable structure:

70 queries, 26 query PoW bits, 24 interaction PoW bits, blowup/fold step 1,
final bound 0, no lifting, salt 0. Plain canonical BLAKE2s hashing, exact circle
domains and bit-reversed lifting. AOT cubins must match the actual SM, zero
CPU fallback and one terminal D2H. Input decode, complete witness, verification
and publication stay inside the warm clock. Component heights vary and are
known at admission. Immutable PP, authorities and module topology are reusable.
Roots/challenges impose barriers; component and row work inside stages is
parallel. Final query indices are unavailable until after FRI commitments.
Imperative AIR register rewrites require versioned read-before-write operands;
each constraint keeps its original random-coefficient index.

Candidate matches, relationship and evidence status:

| Candidate | Relationship | Guarantee / named cost | Fit and evidence | Prior implementation / license | Principal risk |
|---|---|---|---|---|---|
| Fixed-order register interval reuse | Exact subproblem | Peak interval overlap per equal-sized bank; sorting O(I log I), live storage O(I) | Already implemented; earlier root consumption and SSA alone do not lower largest-template peaks in current analysis | Existing Zig code; no new dependency | Mistaking declared bank bytes for compiled frames |
| Root-DAG slicing with shared recomputation | Exact algebraic decomposition / storage-work tradeoff | Work W'=sum of bundle closure sizes; storage bounded by largest bundle liveness plus partial accumulators | Largest EC 32-root bundles: 2828 vs11256 modeled B/thread at W'/W=1.290; derived | Original graph analysis; Airbender bounded metadata is a mechanism reference, MIT/Apache-2.0 | Extra reads/work, frame growth, altered coefficient indexing |
| Bounded expression materialization and replay | Exact producer/consumer substitution | Replace O(sum N_c L_c) expanded words with compact inputs plus bounded tile; replay adds measured field work | Lookup materialization24.182 GB on PIE1; live across main-root barrier; derived from complete plan | Existing witness IR; IO-aware tiling literature is analogy only | Missing intermediate values, duplicated multiplicity side effects |
| Batched inversion and field-product scan | Exact field identity for admitted nonzero values, explicit zero policy | Batch B values uses one inverse plus O(B) multiplies; tree O(B) work/O(log B) product span plus inversion span | Relation inversions already batched, seek fused materialization removal; quotient batches samples within one row | Pinned Stwo; NVIDIA scan/CUB mechanisms | Using quotient zero masking for relation poles, barriers/shared pressure |
| Retained coefficients with recomputed evaluations | Exact representation/recovery tradeoff | N-column FFT work O(sum N_c log N_c); each extra cohort replay adds its transform/hash work | AIR-stage printed live set remains78.091 GB after ideal interaction elimination | Airbender full/single coset policies, MIT/Apache-2.0 | Regeneration dominates, invalid row-local FFT shortcut |
| Stable-region graphs and lane overlap | Dependency-preserving schedule transformation | Graph topology O(K); repeat launch reduces host submission cost, not kernel work | ~3500 launches, but OODS1385launches only52ms onPIE1 | NVIDIA docs and CUDA APIs | Capturing across host barriers; scratch conflicts and higher peak |
| Warp-distributed general AIR interpreter | Analogy / alternative layout | Lane decomposition, still large bank and interpreter work | Vortex declares dynamically indexed per-lane arrays; not proof of register residency | BSL1.1 non-production grant; no production import | Register/local traffic and cross-row coalescing regressions |
| CUDA13 shared-memory spills | Compiler mechanism, not algorithm replacement | Trades bounded shared bytes for local traffic | Baseline12.8; 24KB/thread cannot fit wholesale on chip | NVIDIA compiler documentation | Capacity/occupancy regression; new toolkit qualification |

Chosen canonical problem and exact variant:

Decompose into exact DAG evaluation under a storage budget, streaming
producer/consumer evaluation after challenge barriers, batched field inversion,
circle-transform representation recovery and event-safe request scheduling.
Use deterministic bounded root bundles and cohort schedules as practical
candidates; no claim of a globally optimal DAG/arena schedule or hardness
classification is made. A fixed-schedule live-byte sum is a capacity lower
bound, not an optimal packed aligned arena.

Project → canonical mapping and solution recovery:

Every imperative AIR write becomes a unique dependency node; operand reads
refer to the preceding write. A constraint root maps to its final node and its
original RC index. A bundle is a subset of roots with the union of ancestor
closures. Recompute shared ancestors inside each bundle, preserve their
topological dependency order, and sum weighted roots in exact QM31. Merge
bundle accumulators once with the same component denominator. Repeated roots
retain their distinct coefficient contributions. No trace-component omission.

Lookup words map to pure witness expressions plus validated compact inputs;
after the main commitment challenge, evaluate expressions in bounded cohorts
without rerunning side-effectful multiplicity accounting. Relation fractions
map to tiled batch inversion and the existing cumulative column chain, followed
by the same claimed-sum correction. Commitment coefficients map to exact circle
evaluation cohorts; final query openings recover required rows and lower Merkle
subtrees from retained coefficients/compact inputs and immutable caps. Correct
recovery requires all roots, hashes and query paths to equal the original.

Complexity/limits, named parameters and citations:

I=program instructions, R=roots, b=root bundle width, N_c=component domain rows,
L_c=lookup words per row, B=inversion tile values, K=launch topology nodes.
Fixed-order liveness is a sorted endpoint sweep O(I log I), with equal-size
bank peak equal to simultaneous live intervals (derived). Independent root
closure analysis here is worst-case O(RI); union closures define exact unweighted
recomputation W', not a wall-time bound. A production compiler should memoize
dependency reachability or bound bundle construction rather than perform it
per request. No DAG optimizer is admitted as request-time search.

Circle FFTs retain O(N_c log N_c) arithmetic work and dependencies across distant
rows; arbitrary row tiles cannot be transformed independently. Low-level
mixed-radix decomposition must recover exact circle indexing/twiddles.
[Circle STARKs](https://eprint.iacr.org/2024/278),
[Sppark transform mechanism](https://github.com/supranational/sppark/blob/9e5c7951d4ff4992f78af26f48d3c9230b8c4136/ntt/kernels/gs_mixed_radix_narrow.cu).

Product scan/tree inversion correctness is derived from multiplying nonzero
field elements and propagating the inverse product. Our relation tree already
implements batching; the new candidate removes full global denominator
storage. Quotient can instead batch across rows while preserving its own zero
mask semantics. [Pinned Stwo quotient](https://github.com/starkware-libs/stwo/blob/7b211edde786775016ef3eecb837a6240d8fe792/crates/stwo/src/prover/backend/simd/quotients.rs),
[NVIDIA parallel scan research](https://research.nvidia.com/publication/2016-03_single-pass-parallel-prefix-scan-decoupled-look-back).

Prior algorithms, solvers and implementations:

Inspected/pinned Stwo, ICICLE-Stwo default and actual GPU branch, ICICLE,
Airbender, Sppark, era-bellman-cuda and VortexSTARK. Sources and inspected file
digests are recorded in the dossier. No production code copied. Airbender's
reduced-round BLAKE2s and alternate M31 zero representation cannot replace our
canonical protocol. ICICLE GPU branch is incomplete. Sppark uses different
transform math; Vortex is neither an admitted complete backend nor licensed
for a direct production copy at this revision. FlashAttention is only the
IO/recomputation analogy, not a matching arithmetic algorithm.

Selected transfer, integration boundary and rejected alternatives:

First engineering batch: generic process-owned runtime/cache and raw request
attribution; bounded/lazy lookup production and fused relation inversions;
authenticated AIR root slices; then bounded coefficient/evaluation/query
retention. Frontend emits semantic ProofProgram; CUDA compiler owns CudaPlan,
resource packing and stream events. No Cairo-private runtime or PCS fork.

Reject earlier-root-only allocation as a largest-EC optimization (measured
zero bank reduction), an allegedly missing M31 inverse addition chain (already
present), unrestricted warp interpreters, tensor/float arithmetic substitutions,
hash-round reduction, CPU offload as a latency assumption, and graph-only
subsecond claims. v46 faster math increased compiler frames/memory and remains
rejected as default; v48 enlarged hash scratch without a meaningful gain.

End-to-end prediction, crossover and falsifier:

**Derived:** root bundle32 predicts 3.98× smaller abstract private bank for the
largest EC template, at +29% unweighted dependency instruction work. Bundle64
predicts 2.44× smaller bank at +14.8% work. No compiled-frame or speed guarantee.
Candidate loses if actual frames/local traffic fail to fall, or extra work and
partial-output passes erase complete-request benefit.

**Derived bound:** perfect removal of lookup and denominator arrays shifts PIE1
printed peak to78.091GB at AIR. Therefore those two changes alone cannot fit
5090 or safely promise80GB fit. Replacement storage, aligned arena packing,
private/context/pool bytes and capacity margin still count.

**Hypothesis:** persistence eliminates repeated immutable setup, slices reduce
private traffic, and bounded cohorts create a useful latency/capacity frontier.
Accept only native measured complete warm PIE requests and actual capacity
admission. A 900ms stage budget plus100ms margin is an engineering allocation,
not an ETA or forecast. Subsecond remains unproven.

Correctness and benchmark plan:

Compare source-derived witness words/multiplicities, sliced CPU/reference AIR,
interaction accumulators, all roots/challenges and exact circle transforms.
Run focused local tests and authenticated AOT compiler resource checks before
renting the next GPU. Then capture one full PIE1 Nsight Systems timeline and
dominant AIR/witness/relation/hash/quotient Nsight Compute samples. Profile
captures are diagnostic only. Use uninstrumented immutable baseline/candidate
paired rounds for decisions, every PIE and structural shared-backend classes.

Task09 headline uses ten warmups and seven paired rounds perPIE; longer sustained
queue measurements are needed for meaningful p99 estimation. Report raw PIE
warm request, cold, plan miss, file and queue boundaries separately. Enforce
official Rust and Zig verification, zero fallback/AOT misses, one terminal D2H,
identity/mutation rejection, no teardown leaks and allocation/device-error
unwind. Never infer GPU latency from host model results.

Open uncertainty:

No current native Nsight counters or warm persistent raw-PIE receipt. Compiler
resources for root slices and actual replay cost are unmeasured. The exact
minimum capacity schedule, quotient's within-stage attribution, and sustained
price/latency frontier are still experimental. Historical H1001.5s has no
receipt or confirmed witness boundary. No additional GPU credit was used for
this research; no claim that subsecond on5090 is already feasible.

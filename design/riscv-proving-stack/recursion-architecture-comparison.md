# Recursion architecture comparison — 2026-09-21

Our current recursive parent already proves a specialized Stwo verifier AIR.
It does not run a verifier ELF through RISC-V. The immediate gaps are repeated
host preparation, a large verifier witness, and orchestration. Switching the
frontend name to “native Stwo” would not remove them.

## Local evidence

The [qualified optimization batch](../../autoresearch/notes/2026-09-21-recursion-preparation/README.md)
measures a complete Metal parent at **5.572 seconds**, down from 7.062 seconds.
Six measured candidate processes independently verified; proof bytes were unchanged.
This is developmental `recursive_q193_v1`: 193 queries, 16 PCS PoW bits,
10 interaction PoW bits, log blowup 1, fold step 4. It is not the CSP profile.

The parent [preparation code](../../src/frontends/riscv/recursion/detached_parent_preparation_v1.zig)
admits child proofs and constructs transcript, PCS, boundary and composition
witnesses. Their arithmetic is lowered into typed verifier components. There is
no RISC-V execution loop in this parent path. Native host verification and proving
that verification are different workloads: the former's roughly 70 ms retained
root measurement does not predict the latter's latency.

Current measured parent phase medians include 0.938 s authority construction,
0.651 s row generation, 0.868 s source tuple projection and 0.172 s typed interaction
generation. These four named phases alone total about 2.63 s. Child capture adds
about 0.436 s. Removing just the first four completely would still leave roughly
2.94 s; this arithmetic is a bound with other work held fixed, not a prediction.
Faster composition kernels alone cannot achieve subsecond end-to-end proving.

The retained row census has 339 MB of logical inputs. PCS DEEP inputs, QM31
multiply-add, opening-accumulate4 and linear operations account for 73.5% of those
bytes. Actual process peak RSS is about 4.39 GB. Logical bytes are neither padded
trace size nor a runtime breakdown. The arithmetic graph already has flat storage
and some fused operations; an optimization must improve on those existing features.

## StarkWare: inspect the current circuit implementation

`stwo-circuits` [announces its migration](https://github.com/starkware-libs/stwo-circuits)
to `starkware-libs/proving`. Inspected commit:
`cd7bc5f4697fb188a27e09f9242f1dd76df8afdc`.

The current [pair reducer](https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/stwo_run_and_prove_recursive_tree/src/fold.rs)
builds a two-proof multiverifier circuit and proves its assignment with Stwo.
Internal nodes stay in this circuit representation; the root is serialized for
a Cairo verifier. This is more relevant than treating all StarkWare recursion
as Cairo VM execution.

[CanonicalCircuit](https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/stwo_run_and_prove_recursive_tree/src/canonical.rs)
builds shared configuration and preprocessed circuit structure once for the tree,
checks its registry hash, and reuses a base-column pool. Homogeneous padded layouts
let one multiverifier shape accept leaf-verifier and intermediate proofs.

There is an important limit to that reuse:
[`prove_circuit_assignment_with_channel`](https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/circuit_prover/src/prover.rs)
still computes twiddles and the preprocessed commitment for each invocation.
The same file exposes `prove_circuit_with_precompute` accepting those objects.
Do not claim the inspected tree CLI already caches every fixed commitment.
Its [tree reduction loop](https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/stwo_run_and_prove_recursive_tree/src/lib.rs)
is also sequential across pairs; it is not evidence of a parallel production scheduler.

The checked-in [circuit FRI configuration](https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/stwo_run_and_prove_recursive_tree/test_data/circuit_fri_config.json)
uses 70 queries, 26 PoW bits, log blowup 1 and fold step 4. Our 193 queries create
2.76 times as many query positions, but that is not a 2.76x total-time estimate.
Our [security decision](../typed-air/decisions/0036-recursion-v1-suite-and-verifier-owned-profile.md)
explicitly separates the 209-bit configuration ledger from its 120-bit target and
124-bit field/hash ceilings. Query count deserves a reviewed protocol experiment;
copying 70 queries does not preserve our existing security target by itself.

**Transfer:** authenticate immutable circuit plans once, separate their structure
from witness values, reuse bounded buffers, and measure shape padding. Compare
complete equivalent-security protocols before changing parameters.

## ZisK: specialized circuits plus a real resource scheduler

Inspected ZisK `5c5f81c96929abed88894473ec6060b1b545b5c5` and Proofman
`d485fac207679076958b502554fb595568c2f954`. These are separately pinned repository
heads, not a claim that ZisK's crates.io dependency resolves to that Proofman head.

Proofman's [recursive setup](https://github.com/0xPolygonHermez/pil2-proofman/blob/d485fac207679076958b502554fb595568c2f954/setup/pil2-stark/src/proving_key/recursive.rs)
generates verifier circuits in Circom, compiles to R1CS, converts to PIL, and
builds STARK keys and constant trees. Compressor, recursive1 and recursive2 are
specialized proof stages. This is not ordinary RISC-V verifier execution.
The setup explicitly trades constraint degree, blowup, query count and Merkle
levels against the cost paid by the *next* verifier. Its current hash-family
choices differ; there is no single setting that should be copied into Stwo.

The [recursive scheduler](https://github.com/0xPolygonHermez/pil2-proofman/blob/d485fac207679076958b502554fb595568c2f954/proofman/src/scheduler.rs)
has ready queues, nonblocking CUDA stream reservations and key affinity. It
prefers streams already holding the needed constant tree and prioritizes deeper
recursive work. RAII reservations release resources if dispatch fails.
[Proofman orchestration](https://github.com/0xPolygonHermez/pil2-proofman/blob/d485fac207679076958b502554fb595568c2f954/proofman/src/proofman.rs)
also bounds recursive trace buffers and CPU thread admission.

**Transfer:** implement a dependency-ready, memory-bounded scheduler with persistent
workers and authenticated resident plans. Overlap CPU witness preparation with GPU
proof work; prioritize the root's critical path. Adding an unbounded thread pool
to our qualification script would miss these mechanisms.

## zkDTVM: distinguish the design article from today's verifier

The official [design article](https://openlabs-intl.antdigital.com/0x/Introducing-zkDTVM-A-GPU-Native-zkVM-Built-for-End-to-End-Acceleration)
describes SumCheck PIOP, a Basefold-derived PCS, recursive STARKs and CUDA acceleration
including trace generation and recursion. It also describes local-only constraints,
instruction fusion and bounded shape families. These are published design claims;
I did not execute or inspect a complete public CUDA prover implementation.

The current public verifier is more specific and newer than the v0.8 README
search results. At `e02a91464d94a5d1d5d3123003ddd2f86b54eeb8`, its
[entry point](https://github.com/AntChainOpenLabs/zkdtvm-stark-verifier/blob/e02a91464d94a5d1d5d3123003ddd2f86b54eeb8/crates/verify/src/lib.rs)
verifies SealProof v6 using an embedded authenticated Seal key and the caller's
application key. The [Seal AIR](https://github.com/AntChainOpenLabs/zkdtvm-stark-verifier/tree/e02a91464d94a5d1d5d3123003ddd2f86b54eeb8/vendor/zkdtvm-verifier-core/src/seal)
contains dedicated batch-sumcheck, constraint replay, transcript, Poseidon2,
Merkle-path and WHIR components. This confirms specialized recursive verification
constraints rather than merely providing a fast host verifier.

The pinned [WHIR configuration](https://github.com/AntChainOpenLabs/zkdtvm-stark-verifier/blob/e02a91464d94a5d1d5d3123003ddd2f86b54eeb8/vendor/zkdtvm-verifier-core/src/protocol/whir_config.json)
has stage-specific query counts and blowups. Root-shrink enables stacking and
path pruning; those flags are false for the earlier stages. Its
[WHIR verifier](https://github.com/AntChainOpenLabs/zkdtvm-stark-verifier/blob/e02a91464d94a5d1d5d3123003ddd2f86b54eeb8/vendor/zkdtvm-verifier-core/src/whir/verify.rs)
implements reduction sumchecks and pruned opening verification. It would be
incorrect to describe the current code solely as the article's Basefold pipeline,
or to say multilinear protocols eliminate Merkle authentication.

**Transfer:** larger verification gadgets, batching and less intermediate witness
traffic are relevant now. A SumCheck/WHIR replacement for Circle-STARK recursion
would be a distinct protocol project, requiring new proofs, keys and soundness
analysis; it is not a drop-in precompile or a demonstrated 10x improvement here.

## Parallelism: measured separately from the serial gate

Our [tree gate](../../scripts/riscv_segment_v2_detached_tree_gate.py) loops over
pairs synchronously; the [parent gate](../../scripts/riscv_segment_v2_detached_parent_gate.py)
holds `build_lock` across each heavy producer. This is an explicit qualification
policy, not a proof dependency between siblings. The Metal runtime uses shared
call leases; that alone neither serializes all proofs nor qualifies arbitrary
same-process concurrency. Child preparation currently shares a sequential arena.

A new diagnostic ran two distinct level-2 siblings using the existing optimized
Metal binary in separate processes, with separate outputs and the original
admitted inputs. No rebuilds or parameter changes. Verification ran after both
producers exited and outside the pair-production timer.

| Pair execution | Observations, seconds | Median |
| --- | --- | ---: |
| Serial | 10.643, 10.823, 10.861 | 10.823 |
| Concurrent, same GPU | 34.272, 6.384, 6.516 | 6.516 |

All **12 produced proofs independently verified**, matching the qualified keys,
claims and proof bytes. The median ratio is 1.66x, but three observations per mode
with no warmup and a 34.272-second outlier do **not** qualify a reliable throughput
gain. In the delayed process, the internal request timer was 5.264 seconds against
34.23 seconds process time: the delay lies outside that timer and remains
unattributed. It must not be deleted or labelled GPU proving time. Per-process
RSS is retained; simultaneous peak aggregate memory was not sampled.

This establishes process-level concurrent correctness for these siblings, not
production scheduler reliability. The [raw logs, replay script and receipts](../../autoresearch/notes/2026-09-21-recursion-architecture/README.md)
are retained. No upstream performance numbers are being compared against our M5.

## Focused path toward subsecond recursion

### Implementation status after the comparison

The [bounded DAG replay](../../autoresearch/notes/2026-09-21-recursion-implementation/README.md)
now runs independent parents concurrently. A seven-parent diagnostic took 30.112 s
with two workers versus 39.673 s with one; all 14 proofs independently verified.
This is one diagnostic pair with retained leaves, not a qualified throughput claim.
The scheduler still launches fresh processes.

Separately, [batch workspaces](../../autoresearch/notes/2026-09-21-recursion-workspace/README.md)
reuse a runtime and transform plans across sequential requests. The subsequent
[PCS graph cache](../../autoresearch/notes/2026-09-21-recursion-pcs-plan-cache/README.md)
reduced a controlled two-request Metal batch from 10.963 to 10.615 s, approximately
3% by paired ratios. Thirty-eight fresh proofs passed independent verification
across comparison and qualification runs. These are different experiments and
must not be combined into an invented single-parent latency.

The next [persistent-worker checkpoint](../../autoresearch/notes/2026-09-21-recursion-persistent-workers/README.md)
integrates resident CPU/Metal producers with the bounded DAG scheduler. Two Metal
workers served all seven parents with fresh standalone verification, retaining
one transform plan per worker. A same-binary diagnostic measured 30.007 s resident
versus 30.735 s fresh-process, with sampled aggregate process RSS of 9.025 GB and
8.889 GB respectively. One pair does not qualify a performance improvement.

Requests remain sequential within each worker; independent workers execute
concurrently. Explicit within-worker preparation/proving pipelining and useful
final-layout buffer reuse remain unfinished. Fused PCS/DEEP components and the
parameter experiment also remain unimplemented. The small observed cache/pool
benefits reinforce the need to reduce verifier witness and materialization costs.

The [direct Merkle row checkpoint](../../autoresearch/notes/2026-09-21-recursion-direct-merkle-rows/README.md)
removes padded-column staging for four selected-lane witness generators. Its
complete-parent ABBA comparison measured 5.676 to 5.536 s (2.38% by paired ratios),
with row generation falling from 0.653 to 0.532 s and peak RSS effectively unchanged.
Twenty-two fresh proofs verified across comparison, CPU and persistent-tree checks.
Logical cohort copying and the final column layout remain; this is an intermediate
materialization removal, not completion of direct final-layout generation.

An [experimental fused PCS component](../../autoresearch/notes/2026-09-21-recursion-fused-pcs-opening/README.md)
now combines query input binding and opening accumulation. Five focused tests pass,
including exact signed lookup-multiset equivalence to the unfused rows. A census
of an independently admitted parent identifies 83,376 eligible groups per child,
potentially removing 333,504 PCS input rows while retaining shared inputs. The
derived saving is 35.7 MB of logical fields per child, not a timing result. Production
lowering/roster integration, fresh keys and CPU/Metal recursive proofs remain required.

### Remaining implementation order

1. **Persistent proving plans and bounded scheduling.** Reuse immutable authenticated
   geometry, fixed preprocessing and buffers across a complete tree. Keep independent
   witness ownership and failure cancellation. Measure cold startup, warm node time,
   whole-tree wall time and total work separately; investigate the observed delay.
2. **Reduce PCS/DEEP verifier work.** Census padded columns and lookup events, then
   prototype a fused opening/quotient gadget beyond existing muladd and dot4.
   Preserve transcript, denominator, query and root bindings. Measure a complete
   parent and recursive leaf, not just a kernel. Circuit changes need new identities.
3. **Generate witnesses in the final layout, with device residency where useful.**
   Remove remaining full-lane authority expansion and repeated tuple/column passes.
   Accelerating guest ECDSA cannot remove these parent verifier costs.
4. **Evaluate a versioned recursion-specific PCS profile.** Use the existing FRI
   frontier machinery to compare domain blowup against recursive query cost, with
   an explicit security ledger. Consider batched/pruned paths only after measuring
   duplicate authentication work. Keep this separate from fixed-profile speedups.

The initial 7.06-second parent would need to reach about 0.706 seconds for 10x;
the current 5.57-second result still needs almost 8x. Source inspection identifies
credible work to remove, not evidence that this target is already attainable.
Parallel siblings improve throughput but cannot eliminate dependencies along a
root path: a balanced binary tree has approximately log2(N) dependent levels.

Finally, the 102.13-second eight-segment production observation contains 61.77 s
of native-plus-recursive leaf work and 40.36 s of parent work. Its tiny 482-instruction
fixture is not an Ethereum block benchmark. Large-program throughput requires
representative segment sizes, leaf/parent overlap, aggregate memory measurements,
and root latency. Even zero-cost parents alone would not make that serial product
10x faster. Subsecond *per-node* recursion is a useful target, not by itself a
sufficient or necessary condition for useful pipelined block throughput.


## Current BLAKE3 goal audit — 2026-09-23

The earlier checkpoints above describe their dated source snapshots. In particular,
the September 21 statement that PCS query fusion is not integrated is superseded
for the current BLAKE3 parent. The four-part objective remains active; these are
partial implementation and qualification findings, not a completion claim.

| Objective | Current evidence | Remaining qualification/work |
| --- | --- | --- |
| Persistent plans, buffers and bounded scheduling | The canonical parent test reports fixed-plan reuse, successful worker rekey and outputs outliving the worker. The producer shares an authenticated fixed commitment; ordinary witness preparation now reuses its admitted plan during emission. | The inspected worker RPC processes requests sequentially. Within-worker preparation/proving overlap and a current complete-tree cold/warm/work/memory comparison remain unqualified. |
| PCS/DEEP fusion beyond muladd/dot4 | `blake3_native_parent_rows` invokes `native_pcs_fusion_rows.materialize`; the native opening component is in the parent roster. The latest qualified base parent emits 9,520 fused groups, removing 38,080 scalar rows, in addition to 19,973 dot4 and 59,595 fma matches. | This proves integration in that canonical base-parent path. It does not establish the marginal E2E gain or complete all verifier fusion opportunities; broader family/backend/performance scope needs matching evidence. |
| Direct final-layout witness generation | Parent retained fixed rows are already compact. G, XOR and route cohorts bypass generic Builder row retention. Shared column projection now uses bounded leased workers, with unchanged canonical proof bytes and parent qualification. | Other cohorts still append logical rows. Hash main-column emission still has full logical-row metadata intermediates. Removing these transient copies and qualifying complete-parent/leaf effects remains work. |
| Separately reviewed parameter experiment | Fixed-profile qualification uses 70 queries, 26 PoW bits, blowup 1 and fold step 1. | No current controlled BLAKE3 alternative-profile result with a reviewed security ledger was established by this audit. Keep this experiment separate; current speed work must not silently change parameters. |

The [canonical qualification after parallel projection](../../autoresearch/notes/2026-09-23-parallel-column-projection/canonical-parent.log)
independently verifies child and parent and replays the transcript. Its tracked
peak memory is 15,001,593,034 bytes under a 25,769,803,776-byte cap. A functional
test is not a matched parent latency benchmark or a whole-tree completion gate.

The current CSP priority is still relevant: larger SHA/Keccak cases remain well
above original-suite times despite shared commitment and witness improvements.
Do not combine historical parent timings and current CSP checkpoints into a claimed
migration speedup. Use the current parent stage profile to pick the next substantial
change, and preserve exact proof/parameter/worker scope in the measurements.


The [current parent profile and main-commitment change](../../autoresearch/notes/2026-09-23-current-recursion-audit/README.md)
identify another integration gap: borrowed main commitment used the monolithic
builder while interaction commitment streamed. Main now uses the existing bounded
borrowed-streaming API. In one canonical two-worker CPU diagnostic pair, main
commitment falls from 18.785 to 6.856 s and the sum of recorded proving stages from
59.672 to 47.490 s. Independent parent verification, transcript replay and worker
lifetime checks pass; peak tracked memory remains about 15.0 GB. This does not
qualify production latency, whole-tree speed or a 16-worker/Metal comparison.


## ZisK adoption priority — 2026-09-23

The user has prioritized adopting ZisK architectural improvements, first surpassing
the original CSP basket and then qualifying efficient native recursion. The
[problem mapping and completion gates](../../autoresearch/notes/2026-09-23-zisk-architecture-adoption/README.md)
record the implementation direction and a reproducible, scope-aligned historical
gap census. Stwo superiority remains to be demonstrated. Larger SHA/Keccak gaps
require substantial reductions in total trace/proving work, not only local copies.

The [same-binary parent control](../../autoresearch/notes/2026-09-23-parent-streaming-parity/README.md)
now confirms identical artifact SHA256 between streaming and monolithic main
commitment, with recorded stages 59.841 to 47.610 seconds and unchanged tracked
peak memory. This remains a single two-worker CPU diagnostic pair.


The [batched sparse-memory frontier experiment](../../autoresearch/notes/2026-09-23-batched-memory-frontier/README.md)
removes repeated whole-tree reconstruction from shared execution witness emission.
Canonical CPU/Metal artifacts remain identical, but CSP E2E results are effectively
flat. A synthetic sparse-memory diagnostic confirms the traversal scaling fix;
it does not qualify recursion latency. Inspection identifies a larger next target:
BLAKE3 hash interaction generation still uses the CPU path in Metal proofs. The
existing device interaction API requires authenticated AOT profile expansion and
final-column ingress before it can serve these ordinary hash components.


The [authenticated GPU hash-interaction checkpoint](../../autoresearch/notes/2026-09-23-blake3-device-interactions/README.md)
now covers all eight ordinary BLAKE3 commitment AIRs in the core Metal AOT bundle.
Shared execution/extension proofs use existing columns directly and cache exported
programs; mixed CPU/device ownership and error cleanup pass focused safety checks.
All 48 comparison proofs and 16 fresh verifications retain identical proof hashes.
Larger Metal CSP cases improve about 9–12% E2E. Parent interaction generation still
needs fixed-column/residency integration. Core-profile framework composition remains
on the host path and is the next measured architecture target. Full baseline recovery
and the original four-part recursion objective remain unfinished.


The [GPU hash-composition checkpoint](../../autoresearch/notes/2026-09-23-blake3-device-composition/README.md)
adds eight authenticated typed kernels and fixes a shared dispatch gap: streamed
commitments have host Merkle trees and null resident handles. Supported framework
components now stage exact columns through bounded domain groups; other components
retain their valid host path. Canonical ECDSA complete time falls 0.974 to 0.735 s,
and the three larger measured CSP cases improve 7–11%, with identical proof hashes.
The same-binary comparison retains GPU interactions in both arms. Process peak
increases about 0.22 GiB. This qualifies neither full CSP recovery nor parent latency.
The next architecture investigation is bounded GPU streaming commitment and retained
column ownership, alongside measured witness preparation costs. The four-part goal
remains active; substantial fusion, overlap and whole-tree qualification are unfinished.


The [bounded Metal streaming-leaf checkpoint](../../autoresearch/notes/2026-09-24-bounded-metal-stream-leaves/README.md)
now uses the GPU for leaf hashing through the generic streaming PCS path. It preserves
lifted-circle parity and bounds scratch per commitment at 64 MiB, packing small-domain
columns to avoid thousands of tiny submissions. All 48 matched timing proofs plus 16
fresh verifications preserve prior proof hashes. The retained default additionally
passes all 16 positive CSP cases with fresh verification. Larger cases improve 4–5%
E2E; ECDSA is flat and its commitment stages are slower. This does not qualify parent
latency. Parents and Merkle ownership remain on the host, so end-to-end resident
buffers, per-group synchronization, persistent scheduling and overlap remain open.
The full four-part goal and historical CSP recovery remain unfinished.


The [overlapped streaming-leaf checkpoint](../../autoresearch/notes/2026-09-24-overlapped-metal-stream-leaves/README.md)
now uses two CPU staging slots with ordered asynchronous Metal commands and the
shared scratch pool. Pending commands drain before arena release on success and
failure. Pool occupancy is bounded across active and idle allocations; allocations
larger than 128 MiB are not cached. The initial large-buffer cache policy was
rejected for a roughly 2 GiB larger-case footprint regression.

Canonical matched ECDSA complete time improves 0.762 to 0.671 s; the three larger
CSP cases improve 3.5–4.5%, with unchanged proof hashes and physical footprints.
The current G layout still requires 124 main plus 132 interaction columns over
a million-row SHA256/2048 domain. Reducing shared G/lookup width is the next
substantial target; simply increasing lookup batch size risks a larger composition
domain. This checkpoint does not qualify parent latency, proof-tree overlap or
historical full-basket recovery. Persistent recursive scheduling, deeper PCS/DEEP
fusion, final-layout parent emission and the separate parameter experiment remain
open under the original four-part goal.


The [shared G-width checkpoint](../../autoresearch/notes/2026-09-24-blake3-g-width/README.md)
reduces main columns 124 to 112 and interaction columns 132 to 124 using bounded
16-bit addition limbs and removal of redundant rotation-output range requests.
Constraint degree remains two. Core and recursive GPU catalogs are regenerated
under ABI 23; the fast authority test now checks both profile source pins.
Matched larger Metal CSP cases improve 1.7–3.4% with roughly 6–7% lower physical
peaks; ECDSA remains flat. All 16 positive Metal CSP cases independently verify.

The canonical two-worker CPU parent also independently verifies with q70/PoW26
on both child and parent. Replay, rekey, fixed-plan reuse and ownership checks
pass. Its single diagnostic stage sum is 43.525437 s, with 14,329,156,052 tracked
peak bytes; these are not complete root latency or matched speedup measurements.
Old-layout artifacts fail admission. Full CPU/Metal baseline recovery,
parent-of-parent and complete-tree qualification, persistent scheduling, deeper
PCS/DEEP fusion and the separate parameter experiment remain unfinished.


The next device-coverage investigation must distinguish the native BLAKE3 parent
from the detached recursion catalogs. The maintained recursive AOT generator
currently enumerates `segment_leaf_catalog_v2` and `detached_parent_catalog_v1`;
its coverage flag is scoped to those catalogs. `blake3_native_parent_producer`
uses a different twenty-AIR roster. At the time of that audit its interactions
all used the CPU parallel path; the checkpoint below connects supported cohorts
to authenticated device kernels. Complete native
parent Metal coverage must be established from actual dispatches and proof parity,
not inferred from the existing detached-catalog coverage report. See the
[source audit](../../autoresearch/notes/2026-09-24-recursive-merkle-plan-reuse/next-coverage-audit.md).


[Canonical recursive Merkle-plan reuse](../../autoresearch/notes/2026-09-24-recursive-merkle-plan-reuse/README.md)
now reuses two immutable hash topologies across opening preparation instead of
rebuilding graphs for sizing, live/fixed frames and output-wire discovery. The
canonical fixture's 1540 openings require six graph builds, with two plans retained.
An ordered control/candidate/candidate/control comparison (two runs per arm) lowers
complete fixture wall median from 75.729 to 61.192 s, about 19.2%, while recorded
parent proving stages stay at 43.54 s and peak RSS is effectively unchanged.
The complete fixture includes child proving, preparation, verification and teardown;
it is not production root latency. Every run has identical parent proof bytes and
passes q70/PoW26 child and parent verification, replay, rekey and ownership checks.
The focused witness gate checks cached/fresh parity and allocation-failure recovery.
This advances immutable-plan reuse; full scheduling overlap, native Metal parent
qualification, deeper PCS/DEEP fusion, final-layout metadata and the separately
reviewed parameter experiment remain open.


[Native parent Metal qualification](../../autoresearch/notes/2026-09-24-native-parent-metal/README.md)
now uses the exact canonical CPU fixture and produces identical proof bytes.
Admitted plans cache backend-authenticated interaction programs; supported cohorts
stage one fixed projection at a time and unsupported cohorts retain CPU generation.
A same-binary control/candidate/candidate/control comparison lowers complete
fixture wall median from 32.121 to 26.692 s (16.9%) and parent stage sum from
19.141 to 14.102 s. Interaction generation falls from 5.712 to 0.698 s (8.2x).
Peak physical footprint stays about 27.38 GB and peak RSS about 20.89 GB.
All four runs preserve q70/PoW26, artifact identity, independent verification,
replay, rekey, fixed-plan reuse and worker-output lifetime checks.

Actual telemetry establishes five device composition components and seventeen
CPU composition components, plus twenty interaction dispatches across five shared
BLAKE3 cohorts (including scans). Remaining native composition coverage and
lookup preparation are concrete next parent bottlenecks. This does not establish
full-tree throughput, subsecond recursion, CSP baseline recovery or cross-prover
superiority; those acceptance gates remain open.

The [base-field lookup visitation checkpoint](../../autoresearch/notes/2026-09-24-base-lookup-visitation/README.md)
removes a shared CSP/native-parent intermediate: every relation was materialized
as a wide secure-field entry before selected tuples were converted back to M31.
The authenticated DAG now feeds selected base-field tuples directly to checked
table counters. Canonical Metal parent artifact bytes remain unchanged.
Matched complete fixture wall median improves 26.788 to 23.985 s (10.5%), with
main setup 4.706 to 1.576 s and unchanged physical peak. These are two runs per
arm, not final whole-tree qualification.

The next core target is sampled-value evaluation: the previous detailed profile
attributes 3.999 of 5.248 core seconds to it, versus 0.757 to composition.
The existing GPU barycentric route requires resident commitment handles and
declines host-owned streaming trees. A bounded host-staging path should preserve
the strict resident API, exact point normalization, output roster validation and
shared weight reuse. Seventeen CPU composition components are a coverage gap,
but their count alone does not justify prioritizing them over the measured
sampled-value cost.

[Bounded and mixed sampled-value GPU evaluation](../../autoresearch/notes/2026-09-24-host-barycentric-staging/README.md)
now removes the measured native-parent sampling fallback. An explicit host-column
entrypoint reuses domain/weight buffers across runs and stages at most 64 MiB of
column data; strict resident ownership checks remain on the resident entrypoint.
Mixed coefficient/evaluation trees borrow separate epoch rosters and release
their original coefficients only after both epochs finish.

The matched native fixture improves 23.915 to 20.035 s (16.2%). Sampled evaluation
falls 3.995 to 0.353 s (11.3x); all recorded parent stages fall 11.014 to 7.389 s.
Physical peak rises 27.382 to 27.759 GB, about 360 MiB / 1.4%, while RSS is flat.
This is a measured memory/time trade, not lower total memory or subsecond recursion.

The CSP storage trace corrects the initial dispatch assumption: ECDSA and SHA128
already retained all coefficients and used GPU coefficient evaluation. They remain
effectively flat. SHA2048 and Keccak128 contain an evaluation-form interaction
tree; mixed dispatch lowers their complete medians 4.5% and 4.8%, respectively,
with unchanged physical peaks. All 48 timed proofs and 16 fresh verifications
preserve the preceding artifact bytes and canonical q70/PoW26 settings.

Ten focused Metal tests, 23 focused PCS tests (including borrowed ownership,
empty/declined partitions and allocation failures), and the final canonical
native parent qualification pass. The research record distinguishes the original
matched parent source/binary from the final mixed implementation and retains both.

The next work must address preparation/witness materialization and scheduling,
and use the updated profiles rather than continue treating sampled evaluation
as the dominant parent core cost. Full CSP baseline recovery, complete recursive
tree qualification, persistent preparation/proving overlap, deeper PCS/DEEP fusion,
remaining full logical metadata, and the separate parameter experiment remain open.


[Compact generated hash metadata](../../autoresearch/notes/2026-09-24-compact-hash-emission/README.md)
now removes full-row placeholders from every native column-emitting hash adapter.
For the canonical fixture, generated G/XOR metadata drops from 1.302 GB to
0.173 GB: 1.128 GB of redundant temporary storage removed. Exact owner admission,
independent fixed-field comparison, transcript identity, and proof bytes are preserved.
Twelve focused ReleaseSafe tests and the seven-test canonical Metal parent gate pass.

The matched four-process comparison records 20.182 to 19.837 s complete fixture
wall median, only 1.7% lower; this is not a substantial demonstrated speedup.
Peak physical footprint stays 27.759 GB, peak RSS 20.885 GB, and tracked allocation
peak is identical. Preparation byte savings must not be reported as a reduction
in the later process peak. Trusted preprocessing still materializes full rows.
No ordinary CSP benchmark result is superseded by this recursive-only checkpoint.
The broader scheduling, fusion, full-tree and canonical CSP acceptance work remains open.


[Compact trusted path preprocessing](../../autoresearch/notes/2026-09-24-compact-trusted-paths/README.md)
now derives the Merkle-path fixed metadata directly into compact storage,
independently of live witness values. It removes another 1.111 GB of logical
placeholders, taking the two metadata checkpoints' total to 2.240 GB of temporary
storage removed. Trusted transcript preprocessing still uses full rows.
Three focused ReleaseSafe tests and canonical Metal qualification pass; proof
bytes are unchanged. Complete fixture median is 20.065 to 19.656 s in the matched
four-process sample, while parent stages and process peaks remain effectively flat.

A source audit corrects the worker-count interpretation: the canonical parent
fixture explicitly uses **two** persistent proving workers. The 16-worker setting
belongs to CSP product measurements. The preceding compact-hash note is corrected.
The shared bounded preparation/proving pipeline already exists; its four-leaf tree
qualification uses diagnostic q8/PoW0. Next, qualify that existing path at canonical
settings and measure worker scaling. Do not infer canonical tree throughput from
the current single-parent or diagnostic pipeline results.


[Canonical parent worker scaling](../../autoresearch/notes/2026-09-24-parent-worker-scaling/README.md)
now measures one frozen binary at 2/4/8/16 workers. CPU main setup scales from
1.62 to 0.44 s at eight workers, which has the best observed fixture median, but
later runs drift substantially and sixteen workers are slower. No production
worker default was changed from these noisy measurements.

[Canonical typed execution-parent pipelining](../../autoresearch/notes/2026-09-24-canonical-parent-pipeline/README.md)
adds an execution-capture adapter to the existing bounded runner, with preparation
budget ownership and independent per-job key admission. The new named Metal target
passes seven checks under both testing and SMP allocation. Two q70/PoW26 parent
outputs overlap preparation/proving, retain the same fixed plan, and independently
verify after worker destruction with the preceding exact proof bytes.

This is qualification of two repeated single-level jobs, not a canonical recursive
tree or a reliable speed win. With eight proving workers plus one preparation worker,
the matched SMP two-job window median is 21.049 to 19.894 s (5.5% lower), but serial
samples range 16.941–25.156 s and complete fixture median worsens 11.5%. SMP physical
peak increases 30.144 to 32.768 GB. The testing allocator similarly gives only a
small window gain amid drift. Keep overlap opt-in until preparation profiling and
resource-aware scheduling demonstrate a stable benefit. Full-tree qualification,
heterogeneous reuse, deeper fusion, CSP baseline recovery and the separate parameter
experiment remain open.


[Preparation profiling and bounded compression-call emission](../../autoresearch/notes/2026-09-24-parent-preparation-profile/README.md)
now identify live Merkle-path witness generation as over 93% of path preparation.
The shared hash emitter batches one compression call's column writes using bounded
stack storage, preserving final layout and exact proof bytes. Twelve focused
ReleaseSafe checks and seven canonical Metal pipeline checks pass. A frozen ABBA
comparison improves complete fixture median 24.315 to 21.340 s (12.2%), the two-job
window 13.749 to 11.679 s (15.1%), and seed live-path emission 2.429 to 1.594 s (34.4%).
All eight timed parents independently verify with q70/PoW26. Both arms use overlap;
this establishes an emission improvement on the repeated-job fixture, not a new
serial-versus-overlap result, full-tree qualification, or an ordinary CSP speedup.


[Residual fusion census](../../autoresearch/notes/2026-09-24-residual-fusion-census/README.md)
measures the current canonical typed fixture after existing dot4/FMA reservations.
It finds 210 quotient-accumulation and 6,855 linear-input candidates, protected by
single-use checks including graph outputs and explicit exports. Candidate removal
could cross padded-height boundaries for inverse (4,096 to 2,048) and linear
(32,768 to 16,384) cohorts, but replacement-component and next-level costs are not
implemented or measured. The new diagnostic passes the 12-test focused guard and
seven canonical parent checks. Quotient fusion must preserve the reciprocal/nonzero
constraint; deleting it would admit zero-denominator witnesses. These counts guide
new component work and do not establish another speedup or complete priority 2.


[Native quotient accumulation](../../autoresearch/notes/2026-09-24-quotient-accumulation/README.md)
now integrates the positive quotient case with an explicit reciprocal/nonzero constraint,
exact external lookup closure and canonical roster/key binding. It removes 210 arithmetic
rows and 420 lookup events in the current fixture and halves the inverse padded height.
Five focused quotient checks, twelve PCS fusion/padding checks and seven canonical parent
checks pass. The native roster now projects directly from canonical row ownership.
The matched fixture median changes only 14.245 to 14.159 s (0.6%, within variation), while
proof size grows 8,862 bytes and replay grows 560 G rows. This is an implemented fusion,
not an established end-to-end performance gain. Canonical next-level/tree cost remains
necessary before claiming a recursion speed benefit from this component.


[Canonical two-level qualification](../../autoresearch/notes/2026-09-24-canonical-parent-chain/README.md)
now proves a q70/PoW26 parent of an independently verified q70/PoW26 parent. Both
levels pass independent/fresh-codec verification and worker ownership checks. This
linear chain does not yet qualify a canonical binary aggregation tree.
The matched complete fixture is flat with quotient fusion (23.382 vs 23.378 s), while
its second-level witness gains 12,320 G rows, 1,195 arithmetic rows and 10,572 proof
bytes. Its inverse domain no longer halves. Quotient fusion was therefore removed
from production and archived as an experiment. The canonical roster projection and
new dependent-level qualification remain. First-level row savings are insufficient
acceptance evidence for future recursive components; next-level cost must be included.


[Canonical four-leaf aggregation](../../autoresearch/notes/2026-09-24-canonical-aggregation-tree/README.md)
now qualifies four real compact-range CPU leaf proofs, two Metal pair aggregates and
a Metal root, all q70/PoW26. Seven harness checks pass, preserving span adjacency,
namespace separation, wrong-key/alias rejection, independent codec verification and
worker-output lifetime. The root covers four segments and six cycles. Routed allocations
peak at 30.31 GB under a 48 GiB fixture cap; the run reports about two minutes and
42G MaxRSS. This is sequential correctness qualification, not a throughput benchmark
or concurrent-tree result. Explicit CPU leaf pool admission and phase profiling remain
needed before optimizing this path; faster recursion and full CSP recovery remain open.


[Explicit canonical tree leaf pools](../../autoresearch/notes/2026-09-24-tree-leaf-pool/README.md)
now correct the preceding fixture's unbound CPU leaf path. Each pair admits eight
workers, transfers ownership only after pool setup succeeds, and destroys its pool
before the Metal aggregate worker starts. Seven qualification checks pass; a frozen
ABBA comparison verifies all twelve aggregate artifacts at q70/PoW26. Complete
fixture median falls 128.214 to 72.282 seconds (43.6%, 1.77×), with physical
peak essentially flat at 45.19/45.15 GB. Artifact sizes and routed peak are unchanged.
This is leaf scheduling in a sequential tiny tree, not concurrent-tree throughput,
a recursive-algorithm speedup or CSP baseline recovery. Candidate root preparation
remains about 12.1 seconds and root proof with independent checks about 14.3 seconds.
Profile child preparation versus namespace/rebase/join costs next; do not infer that
joining dominates from the encompassing timer alone. The full goal remains open.


[Destination-order parent joins](../../autoresearch/notes/2026-09-24-parent-join-layout/README.md)
now eliminate the shared aggregation join's zero-fill plus scattered-overwrite pass.
An 8 KiB source-index tile is reused across columns, preserving namespace admission,
fixed metadata, all logical rows and padding. Focused ReleaseSafe checks and seven
canonical tree checks pass. Frozen ABBA runs independently verify twelve aggregates
at q70/PoW26; complete fixture median improves 72.401 to 65.465 seconds
(9.6%), and root preparation 12.311 to 8.921 seconds.
Physical and routed memory peaks are unchanged. This production join change applies
to every parent cohort; it does not reduce recursive AIR work or establish CSP gains.
The next investigation can quantify duplicate authenticated Merkle nodes, alongside
bounded child preparation and heterogeneous worker reuse. Hash sharing must retain
constrained query/input/output links and multiplicities; host equality alone is not
sufficient. The full goal remains open.


[Authenticated path sharing census](../../autoresearch/notes/2026-09-24-path-sharing-census/README.md)
now measures repeated upper Merkle nodes separately by tree and height. Thirteen
focused checks and seven canonical four-leaf tree checks pass. Each leaf verifier
contains 875,728–895,888 gross candidate G rows from repeated upper hashes
(36.5–37.9% of path G rows); the two aggregate verifiers contain 1,079,904 and
1,105,888 (30.0–30.8%). These are topology opportunities, not implemented savings:
query bits, selected hash inputs, outputs and multiplicities must remain constrained.
Query-dependent fixed sharing also changes the preprocessed commitment bound into
the admitted key. A fixed common-root scheme or constrained dynamic DAG needs an
explicit design and next-level qualification. Root-only sharing has a smaller gross
ceiling of 170,016 / 208,656 G rows per leaf / aggregate verifier. No speed, domain
height or memory benefit is established by this diagnostic. Full goal remains open.


[Fixed-schedule root sharing](../../autoresearch/notes/2026-09-24-shared-root-hashes/README.md)
is now implemented in canonical native path preparation, with matched preallocation.
One root-node hash serves each tree's queries; all other paths retain authenticated
bit selections, 16 input-word equalities and eight canonical-root word bindings.
Exact producer counts are fixed by query ordinal/shape, preserving key independence
from private query positions. Existing typed AIRs are reused. Fourteen focused checks
and seven canonical two-level tree checks pass, including exact lookup closure and
input/root/bit mutation checks. Twelve timed aggregate artifacts independently verify.
The ABBA fixture median changes 64.229 to 63.049 seconds (1.8%); this small two-sample
result is not a large speedup claim. Physical peak falls 45.153 to 44.784 GB and routed
peak by 477 MB. Actual G rows fall 170,016 per leaf verifier and 208,656 per aggregate.
Root artifact size grows 5,215 bytes while both pair artifacts shrink. Retain the row
and memory reduction, but larger upper-path sharing still needs a constrained design
and next-level cost qualification. Full CSP recovery, bounded persistent scheduling,
further effective fusion/direct emission and reviewed parameter experiments remain open.


[Two-level shared frontier primitive](../../autoresearch/notes/2026-09-24-two-level-frontier/README.md)
now qualifies three shared hashes using existing typed AIRs. Private activity flags
allow opaque unqueried branches, while every query proves its chosen branch active
and its 16 ordered input words equal to the shared preimage. No witness-controlled
lookup weights or new roster component is introduced. Fifteen focused checks pass,
including a diagnostic standalone STARK proof, inactive-query rejection, deliberately
unrelated unused values and fixed-column invariance across private choices. This
primitive is not yet wired into native path preparation; production retains root-only
sharing. The path-select constructor now permits one unused mux output while rejecting
both unused, without changing its typed AIR semantics.
Actual canonical hash inventories project first-level pair G domains from 8,388,608
to 4,194,304 rows with top-two sharing; the root G domain remains 8,388,608. Routing,
changed artifacts and next-level costs still need full integration and measurement.
The note records precise namespace, query-bit multiplicity, column emission and
canonical qualification requirements for that integration. No new native tree speedup
or completion of the broader goal is claimed.


[Native two-level frontier integration](../../autoresearch/notes/2026-09-24-native-two-level-frontier/README.md)
now supersedes the preceding primitive-only checkpoint. Trace and FRI paths share three
constrained hashes per eligible tree, with authenticated query bits, active-branch
membership and ordered input equalities. Cached plans, direct final-column emission,
independent trusted metadata and matching preallocation are integrated. Canonical
qualification passes 7/7; twelve timed aggregate artifacts independently verify at
q70/PoW26. Frozen ABBA complete-fixture median improves **61.641 to 46.661 seconds
(24.3%)**. Both first-level G domains halve from 8,388,608 to 4,194,304; their proof/check
phases fall from approximately 12.8 to 6.1 seconds. Root G rows fall to 6,032,768 but
still pad to 8,388,608, with a 13.23-second root proof/check phase. Physical peak falls
44.784 to 44.451 GB; both pair artifacts and the root artifact shrink. Two samples per
arm support this local sequential tiny-tree result. Full CSP recovery, substantial
further recursion gains, bounded persistent scheduling and reviewed parameter
experiments remain open; no superiority or subsecond claim follows.


[Bounded two-child preparation](../../autoresearch/notes/2026-09-24-tree-child-preparation/README.md)
adds an explicit caller-owned pool path with at most one helper plus the coordinator.
Both jobs join before lease release or error cleanup; borrowed nodes survive failure.
Canonical qualification passes 7/7, including a forced one-byte budget failure followed
by successful reuse of the same pool. All twelve timed aggregate artifacts independently
verify with unchanged sizes and q70/PoW26. Frozen ABBA fixture median improves
45.538 to 43.237 seconds (5.1%); root preparation improves
7.055 to 4.705 seconds. Physical/routed peak is essentially unchanged.
This is a two-sample-per-arm sequential-tree result; no successful multi-tree throughput
claim follows. Integrating the helper into prepare/prove overlap must explicitly admit
its additional CPU token and pool lifetime; that pipeline remains unchanged.

The post-frontier census also establishes a local limit: removing all remaining
repeated upper hashes saves at most 1,433,264 G rows before routing, leaving 4,599,504
root G rows—405,200 above the next 4,194,304-row domain. Deeper upper-path sharing
alone cannot halve this root domain while child proof geometry stays fixed. Further
row reduction or a separately reviewed parameter experiment is needed alongside
bounded scheduling. Full CSP recovery and the broader goal remain open.


[Persistent child preparation](../../autoresearch/notes/2026-09-24-persistent-child-preparation/README.md)
now integrates the explicit two-worker preparation path into the bounded pipeline.
Admission includes two preparation tokens and the additional helper stack; one
producer-owned pool persists across jobs. The focused ReleaseSafe four-leaf fixture
passes, including budget failures, two completed jobs, proving-plan reuse and fresh
output verification after worker destruction. Overlap is 1.516 seconds, with four total
CPU tokens and a 3.676 GB worker peak under 8 GiB. This is diagnostic q8/PoW0;
canonical multi-job throughput qualification remains outstanding.

User steering now prioritizes like-for-like ZisK component measurements and efficient,
fully constrained hash precompiles as the default after qualification. The first
[source-pinned compression comparison](../../autoresearch/notes/2026-09-24-zisk-compression-comparison/README.md)
checks 1,024 varied full-output cases and four interleaved 5-million-call batches per
arm on the same M5 Max. Median raw compression: peer scalar 59.365 ns, local canonical
author 47.040 ns; the general Zig native 64-byte XOF API takes 67.878 ns with identical
outputs for this input shape. API/representation overhead differs for the XOF arm;
these are not hash-proof, GPU or full-prover timings. They do not establish superiority.

A protocol-cost difference is now explicit: our node has a 27-byte protocol prefix,
one domain byte and two digests (92 bytes, two compressions); peer nodes hash 64 bytes
(one compression) with Goldilocks output canonicalization. These are different
functions. The first compression-precompile work must preserve existing framing and
all authenticated input/output bindings. Any framing change requires a separate
protocol/security experiment. Compare the peer's compression-specific lane/transition
AIR against our G/XOR/wire components, accounting for M31 versus Goldilocks, lookup
traffic, degree, field bytes, padding and parent-of-parent cost. Precompile default
promotion and peer proof-cost measurements remain open.


[Canonical compression partition planning](../../autoresearch/notes/2026-09-24-compression-partition/README.md)
now derives fused-group inputs, outputs and exact external multiplicities directly
from the canonical 56-G graph. ReleaseSafe checks cover all 56 widths, 448 randomized
full-output comparisons, intermediate wire closure and malformed plan rejection.
This is plan qualification, not a STARK proof. The census rules out naive two-/four-G
packing as an internal-lookup optimization: neither removes cells or events. Round-sized
eight-G grouping projects 7.1% fewer main cells and 12.9% fewer events, but raises main
width to 832; whole-compression grouping reaches 5,056 columns. Typed constraint/witness
integration, actual proof and next-level measurement remain required before the user's
requested default hash-precompile promotion. Protocol framing stays unchanged.

[Typed round qualification](../../autoresearch/notes/2026-09-24-typed-blake3-round/README.md)
now passes 21 focused compiler/arithmetic tests and a four-test real-proof gate.
Both G and fused-round full compressions independently verify at q70/PoW26 in a
matched comparison. However, round fusion increases the verified child capture's
next-level path requirements from 1,978,928 to 2,374,848 G rows (20.0%), crossing
from a 2^21 to 2^22 padded domain. This is a census, not an executed parent proof.
The round is therefore **not promoted**. Single cold fixture wall times include
PoW/setup/verification and do not establish a speedup. The next candidate adapts
ZisK's ROTR7-as-ROTL1 arithmetic to bounded 16-bit limbs, reducing the existing
narrow G component rather than widening commitments. Default promotion and full
CSP/recursive qualification remain open.

The rejected wide-round source and its larger compiler/runtime capacities are now
archived outside the live proving path. The [narrow rotation candidate](../../autoresearch/notes/2026-09-24-blake3-rotate7-limbs/README.md)
instead changes the existing shared default G precompile: two bounded 16-bit limbs
implement ROTR7 and ROTR12 after a byte permutation. Main columns fall 112 to 90,
direct constraints 56 to 32 and total lookup events 62 to 56. Native BLAKE3 outputs
and framing remain unchanged; semantic identities are repinned. Focused arithmetic,
mutation and compiler checks pass, along with six full-hash proof checks and seven
canonical CPU-leaf/Metal-tree checks. Frozen ABBA tree median improves 43.202 to
40.589 seconds (6.0%); peak physical memory falls 44.452 to 38.975 GB (12.3%).
All twelve timed aggregate artifacts independently verify at q70/PoW26. There are
two samples per arm, on the tiny four-leaf/six-cycle fixture; no 10× or superiority
claim follows. The improvement is retained in the shared default path.

The initial canonical run exposed missing regenerated GPU kernels and correctly
fell back to CPU. Core and recursive catalogs are now regenerated, with ABI24 and
eight passing shader-authority checks plus actual device acceptance. The canonical
tree gate now requires exact interaction/composition coverage for all eight hash
components before proving, preventing that fallback from masquerading as GPU
qualification. Full CPU/Metal CSP validation is recorded in the linked checkpoint.


[Persistent pipeline ownership](../../autoresearch/notes/2026-09-24-persistent-pipeline-lease/README.md)
now reserves the shared prover for the complete admitted request sequence, including
preparation and cancellation/join. Previously only individual proofs held the worker
mutex, allowing competing requests between jobs. All native, execution and tree
adapters use a scoped lease; busy admission precedes preparation allocations. The
focused ReleaseSafe tree gate verifies early rejection, recovery after allocation and
preparation failures, overlap, plan reuse and independently verified outputs after
worker destruction. Canonical Metal execution qualification passes 7/7: two identical
q70/PoW26 jobs retain one plan and independently verify, with 1.912 seconds of real
overlap. Its single 9.613-second two-job window is not a matched speed measurement.
Canonical multi-job tree throughput and heterogeneous-plan scheduling remain open.

The same checkpoint now includes a frozen serial/overlap/overlap/serial comparison
with the current default G kernels. All eight canonical artifacts independently
verify. Median complete fixture improves 22.698 to 20.978 seconds (7.6%); the two-job
window improves 11.080 to 9.601 seconds (13.3%). Peak physical footprint increases
26.258 to 28.178 GB. Both overlap samples beat both serial samples, but there are
only two samples per mode and the jobs share one key. This supports the explicit
bounded schedule on this workload, not a blanket default or full-tree throughput
claim. Broader objective items remain unproven.


[Transcript hash-graph reuse experiment](../../autoresearch/notes/2026-09-24-transcript-graph-reuse/README.md)
removed repeated immutable topology construction across absorption, query blocks,
secure draws and bounded retries, preserving public-byte bindings and direct-column
emission. Twelve distinct focused checks and seven canonical Metal checks passed;
all eight matched timed artifacts independently verified with unchanged identity.
However, preparation changed only 3.51811 to 3.50982 seconds (0.24%), while complete
fixture median rose 21.07072 to 21.49864 seconds (2.03%) and physical peak was
unchanged. With two samples per arm there is no established benefit. The candidate
was archived and all six source files restored exactly to the qualified control.
This rules out promoting this change as a material optimization on the measured
workload; it does not prove graph construction is negligible on every workload.
Remaining full-row trusted transcript storage and PCS/DEEP row reduction are more
useful next targets than further tuning these graph rebuilds.


[Compact trusted transcript storage](../../autoresearch/notes/2026-09-24-compact-trusted-transcript/README.md)
now removes full G/XOR main-word placeholders from default native transcript planning.
Trusted fixed tails are derived independently and admitted against both row-oracle
and direct-column live witnesses. Ownership transfers, all-allocation-failure paths,
fixed-field mutations, plan identity and public bindings are checked. Five final
transcript/native checks, seven canonical Metal pipeline checks and seven canonical
two-level tree checks pass. All eight timed pipeline artifacts independently verify
with exactly the control identity, and the three tree artifacts retain their sizes.
Measured logical trusted payload falls 16.257 to 2.591 MB per pipeline plan (84.1%);
root-child transcript plans fall 17.726 to 2.825 MB each. This completes compact
trusted transcript hash storage, not all witness-copy elimination.

Matched two-sample-per-arm pipeline observations show no end-to-end gain: preparation
3.53517 to 3.53644 seconds, complete fixture 21.00108 to 21.49896 seconds (2.37%
higher), physical peak 28.178 to 28.364 GB. No speed or process-memory improvement
is claimed. The representation is retained for eliminating the actual intermediate
buffers; the final root-row size and routed tree peak remain unchanged. Larger
final-column joins and effective PCS/DEEP row reduction remain performance targets.


[Bounded consuming column join](../../autoresearch/notes/2026-09-24-draining-parent-join/README.md)
now releases owned child columns in 16-column batches after their final-layout copy.
It preserves the borrowed join as a reference and retains namespace admission before
mutation. Four focused checks prove complete column/padding parity, alias rejection,
all destination-allocation failure cleanup and a hard-budget distinction: the fixture
peak falls 11.410 to 7.073 MB, and an intermediate budget admits only the consuming
join. Canonical Metal tree qualification passes 7/7; twelve matched timed aggregate
artifacts independently verify at q70/PoW26 with unchanged sizes.

Full-tree median is effectively flat, 38.086 to 38.286 seconds (+0.53%); root
preparation changes 3.876 to 3.841 seconds. Routed peak remains 26.460 GB and physical
peak is effectively unchanged at 39.162 GB. With two samples per arm, no speedup or
whole-prover memory improvement is established. The change is retained for bounded
preparation capacity, not as a speed result. Root proof/check latency remains about
12 seconds, so actual proving phases and PCS/DEEP row cost are the next performance
targets. Direct generation of both children into one shared destination remains
unimplemented; this checkpoint bounds simultaneous copies instead.


[Root quotient batch-range dispatch](../../autoresearch/notes/2026-09-24-root-phase-profile/README.md)
identifies a segmented-path memory-traffic bottleneck above the 32-bit flat-source
word range. The 150 root source runs previously updated all 14 numerator batches
even when a run only contributed to a subset. Dispatch-only batch rebasing and
a matching numerator-buffer offset now limit each update to its covered interval.
Original views remain available to the independent parity observer; source
provenance, shaders, arithmetic and canonical proof parameters are unchanged.

Seven canonical tree checks pass. In frozen ABBA measurements all twelve aggregate
artifacts independently verify at q70/PoW26 with unchanged sizes. Root quotient
GPU time falls from about 2.36s to 0.47s; complete fixture median falls from
41.054 to 39.049 seconds (4.88%), with effectively unchanged peak memory. These
are two samples per arm and today's matched baseline, not the older ~38s baseline.
This generic fix is retained. Further native-height segmented partials, effective
PCS/hash geometry reduction and direct final-layout emission remain open; an
order-of-magnitude complete-tree improvement is still unproven.


[Metal runtime build closure](../../autoresearch/notes/2026-09-24-metal-runtime-build-closure/README.md)
closes an observed stale-binary hazard in focused experiments. Root product identity
and local/runtime C compilation now bind the recursive quoted-include closure,
including previously omitted imports. A real transitive-only header mutation
changes executable behavior; an unchanged third build remains cached. Two focused
ReleaseSafe checks, seven canonical Metal tree checks, Cairo integration compilation
and root graph configuration pass. This is development-loop reliability, not an
additional prover speedup.

The next peer-informed architectural target is boundary-driven hash witness
expansion directly into the final layout. Pinned Proofman's recursion expander
reconstructs a 56-row block from two boundary rows per lane and derives lookup
multiplicities. Its private per-worker counters already have a counterpart here;
the missing larger piece is avoiding full intermediate child trace materialization.
M31 constraints, namespace/authenticated metadata and next-level proof cost must
remain part of any corresponding implementation and matched measurement.


[Deferred parent emission](../../autoresearch/notes/2026-09-24-deferred-parent-emission/README.md)
now separates validated graph/transcript/layout planning from final hash-column
allocation and witness emission. The tree plans both children before the bounded
emission wave. Owned plans can be abandoned, consume on emission success/error,
and reject reuse; four induced allocation failures release all tracked bytes.
Seven canonical parent and seven two-level tree checks pass, including failure
recovery; twelve timed aggregate artifacts independently verify at q70/PoW26.

Matched tree median is effectively flat (38.674 to 38.901 seconds, +0.59%); routed
peak remains 26.460 GB and physical peak is unchanged. This is an enabling
ownership/layout refactor, not a speed result. Shared aggregate hash columns and
partition-aware namespace relocation still need implementation before the child
copy can disappear. The fixture records 167,173 emission allocations, providing
a concrete follow-up for bounded scratch reuse without attributing time to it yet.


[Shared aggregate hash columns](../../autoresearch/notes/2026-09-24-shared-aggregate-hash-columns/README.md)
now makes recursive-node pairing emit both children's G/XOR main columns directly
into one final domain. Distinct assembly-only partition types borrow those buffers;
namespace reads/writes respect logical bases, while one owner transfers backing
only after complete join admission. Other cohorts and fixed metadata retain the
existing bounded join. No AIR, parameter, shader or transcript changes are needed.

Five focused ReleaseSafe checks establish full join parity, padding, invalid-offset
rejection, pointer retention and all shared-storage/output allocation-failure
cleanup. Borrowed-emission failures preserve backing and release all child state.
Seven canonical parent and seven tree checks pass. In matched ABBA runs, twelve
aggregate artifacts independently verify at q70/PoW26 with unchanged sizes.
Root preparation median falls 4.267 to 3.458s (18.95%); complete fixture falls
38.414 to 37.644s (2.01%). Overall routed and physical peaks remain essentially
unchanged because later proving dominates. Two samples per arm qualify a local
observation, not a production latency distribution. The change is retained.

[Execution-leaf shared emission](../../autoresearch/notes/2026-09-24-shared-leaf-emission/README.md)
now includes public-memory custody hash rows in the shared allocation. Verified
captures stay alive through deferred emission; custody append writes into checked
reserved suffixes, and final joining rejects incomplete coverage. The preceding
storage checkpoint passes six ReleaseSafe checks, and the integrated path passes
seven canonical Metal tree checks with unchanged independently verified artifacts.

The first ABBA sequence was inconclusive: control drifted from 37.0 to 54.7s,
and a subsequent power check reported 3% battery. After external power was restored,
a separate reverse-order comparison verified all twelve aggregate artifacts and
reduced median total time 51.054 -> 48.918s (4.18%); combined leaf proof/preparation
phases fell 12.267 -> 10.682s (12.92%). Routed peak remains 26.460 GB. Two samples
per arm establish a local paired improvement; both variants were slower than earlier
~38-second sessions, so this is not a new sub-38-second baseline. The implementation
is retained. Low-battery samples remain archived separately.
Fixed metadata copies and remaining PCS/hash proving costs are still
open. This is progress on direct emission, not completion of the full persistent
planning, fusion and parameter-experiment goal or a 10x total improvement.

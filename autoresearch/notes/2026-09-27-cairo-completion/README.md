# Cairo execution and SN PIE 2 qualification — 2026-09-27

The workload is the provided `SN_PIE_2.zip`, executed in the official simple
bootloader's proof mode. It produces 7,977,397 execution steps. CPU proofs use
the canonical profile, plain BLAKE2s, 70 queries, 26 PoW bits, blowup 1 and the
pinned official Stwo-Cairo verifier. The host is Apple M5 Max, 18 logical CPUs,
64 GiB RAM; `apple_m1` in the product identity is the compiler's baseline ISA.

Complete process wall time includes ZIP execution, adaptation, input/assets,
proof generation, in-process Zig verification and proof publication. Official
Rust verification is measured separately. RSS comes from `wait4`: maximum
process/descendant RSS, not the sum of simultaneous process footprints.

| Batch | Complete process | Proving | Peak RSS | Cache condition |
| --- | ---: | ---: | ---: | --- |
| v6 baseline | 110.829 s | 108.449 s | 45.138 GB | Pedersen table hit; full tree recomputed |
| v7 compiled feed routing and count reuse | 85.408 s | 83.135 s | 41.785 GB | Table miss after implementation identity change |
| v8 plain BLAKE2s SIMD entry points | 82.690 s | 80.421 s | 41.827 GB | Table miss |
| v9 bounded prefix reuse and SIMD final tails, first trial | 47.202 s | 44.910 s | 41.788 GB | Table miss |
| v9 same binary, second trial | 38.622 s | 36.178 s | 41.808 GB | Table hit |
| v11 compact preprocessed tree cache, first trial | 47.702 s | 44.970 s | 41.790 GB | Table and tree miss, both stored |
| v11 same binary, second trial | 37.352 s | 34.938 s | 41.816 GB | Table and tree hit |
| v11 same binary, third trial | 37.782 s | 35.355 s | 41.827 GB | Table and tree hit |

These are individual qualification trials; the two v11 warm trials have median
37.567 s complete process and 35.146 s proving, 2.95× faster than the baseline.
The first v11 trial remains recorded and is not excluded from the raw receipt.
Every listed SN2 proof
has SHA-256 `ddf5b47bb928a75b699d0297b75fd0c3fb40ad6679f4ab26c32d2dfee9149545`.
Zig and the official Rust verifier accepted every trial. No query count,
PoW difficulty, statement, hash protocol or proof encoding changed.

Raw receipts are `sn2-e2e-cpu-v*.json`; top-level stage records are
`sn2-stages-v*.json`. Full proof files and detailed stage/report logs remain in
`zig-out/cairo-completion-20260927/`, excluded from source documentation.

## What changed and why

1. Streaming compact transport removes a second JSON representation of large
   VM memory/trace tables. PIE archives are strictly admitted and their memory
   cells decoded in bounded batches. The execution authority is pinned and
   distinct from the unchanged proof-verifier authority.
2. Felt252 inversion uses binary extended GCD, validated against Fermat
   inversion. The isolated 342× inversion result is a primitive result, not a
   whole-proof speedup.
3. Feed routing compiles its target/key geometry once. Fixed multiplicities and
   memory counts survive from base construction to interaction construction,
   avoiding a second calculation. Dead subcomponent slabs are released before
   commitments; challenge-dependent lookup feeds remain live until consumed.
4. The existing BLAKE2s SIMD continuation and parent batching admitted only the
   old prefixed suite. They now admit Cairo's plain suite with the correct
   initial counters and final blocks, including empty messages.
5. The bounded-memory committer still used scalar final-row hashing, while the
   prefix-reuse strategy was enabled only for BLAKE3. Plain/prefixed BLAKE2s now
   reuse native-height prefixes and compress four final-height rows together.
   The memory cap remains 96 MiB of prefix state. Independent scalar trees,
   sparse tails, both bounded paths and compact openings are differential
   regression checks. This is shared prover code, not an SN2 special case.
6. The preprocessed-tree artifact previously exceeded the 1 GiB artifact cap
   on the canonical log-26 domain. Cache format v2 stores the upper layers
   already retained by query compaction: ~256 MiB instead of ~4 GiB. The cache
   key/header bind the omitted-layer count; integrity covers every retained
   byte. Lower openings use the same retained-column reconstruction as a
   freshly compacted tree. Corruption, truncation, shape separation, both
   full/pruned round trips and independent compact openings are tested.
   Product identity binding and the 2 GiB directory budget stay in force.
   Metal's host-backed tree wrapper delegates compact openings to the host
   reconstruction reader; a focused host-only backend regression covers it.

Latest product checks and focused crypto/Merkle/cache checks passed; see
`qualification-latest.json`. The final small Fibonacci PIE CPU/Metal runs
also produced identical proof bytes accepted by the official verifier. Metal
reported 118 dispatches and zero unexpected fallbacks. Their single-trial
receipts are qualification evidence, not a replacement for the earlier Metal
cold-start and three-trial performance measurements.

Main commitment time fell from 21.80 s in v7 to 3.62 s in warm v9; interaction
commitment fell from 17.76 s to 3.03 s. The remaining warm v9 costs include
composition evaluation 10.12 s, base witness/count construction 7.37 s,
preprocessed materialization/commitment 6.24 s and FRI 1.91 s.

## Scope still pending

The CPU 10× target (~11 seconds against the measured 110.829-second baseline)
has not been reached. The current warm result is 2.95×. Composition and witness work,
plus memory bandwidth and retained-column storage, remain material costs.

The earlier `four-pie-adaptation.json` records adaptation only. All four full
CPU proofs have now qualified in the broader suite below.
SN PIE 3's CPU proof is now qualified: 113.197 s complete ZIP process,
108.455 s proving and 48.907 GB peak RSS. Its proof SHA-256 is
`831d4eb1fd711a9b91ed8a403782da2f08ffb1cd815f0171ad501ae8f076ddf9`. Small Fibonacci PIE proofs have qualified CPU/Metal byte parity;
SN PIE 2's original eval-domain Metal path also qualified exact CPU proof
bytes: 82.888 s first process (including 53.188 s pipeline admission and
9.650 s table setup), then 20.211 s populated-cache process / 17.835 s proving
and 27.039 GB peak RSS. It has 42 device and 16 declared host components,
141 dispatches and zero unexpected fallbacks. The warm Metal stage breakdown
is 7.147 s base construction, 3.244 s composition, 1.672 s interaction build,
1.218 s main commitment, 1.205 s preprocessing and 1.023 s FRI. Its 5.48×
comparison to the original CPU baseline includes a backend change and caches;
it is not a measured CPU improvement. Receipts are `sn2-e2e-metal-*.json`.
The stored-domain ABI also qualified exact CPU bytes on Fibonacci and SN2.
SN2's first process was 87.971 s including new pipeline admission; its two warm
processes were 20.904 s and 21.307 s (21.106 s median), with ~27.04 GB RSS.
It retained the same 42/58 device coverage. Staged columns totalled 3190 MiB,
the same as eval-domain staging: most committed columns were already at the
component's evaluation height. Serial copying took 213 ms versus the preceding
parallel lift's 74 ms. This batch established ABI parity, not an end-to-end
speed improvement. Parallel native copies and disjoint-table counting also qualified exact proof
bytes on all three full SN2 trials. Native staging fell from 213 ms to 64 ms;
fixed-table counting fell from ~2.1 s to 1.19–1.25 s. Tables retain one writer
and share the original histogram budget; no private histogram replicas or
merge pass are allocated. The complete processes were 29.316 s first with
table setup, then 20.048 s and 20.423 s warm (20.236 s median). This is a
stage-level improvement; against the preceding 20.211 s single warm Metal
trial, the end-to-end difference is not material. Against the stored-domain
serial-copy/counting batch's 21.106 s warm median it improved about 4.1%.
RSS remained ~27.04 GB and coverage remained 42/58. Receipts and stage totals
are `sn2-e2e-metal-parallel-v1.json` and `sn2-metal-parallel-v1-stages-*.json`.
The focused parallel-count regression covers repeated keys from multiple feeds,
overflow in helper threads and invalid keys. Stored-domain regressions cover
allocation failures, exact native staging, artifact substitution and a geometry
that fits natively but exceeds expanded addressing. The Metal product gate
passed for this batch; official acceptance is still mandatory.
See `sn2-e2e-metal-native-v1.json`, which records every trial including cold. The latest upstream's
native recursive Cairo circuits have been inspected but are not ported or
qualified here. The paused RISC-V block architecture is not resumed by this work.


## Native felt arithmetic and diverse suite (2026-09-27)

Native limb multiplication replaces wide division in the canonical Cairo felt
helper. Boundary, noncanonical u256 and 4,096 randomized wide-reference checks
passed. The isolated alternating benchmark measured 12.6× multiplication speed
including canonical input/output conversions (`felt-multiply-pair.json`).
Three alternating SN2 pairs retained exact official-accepted proof bytes:
20.152 → 19.928 seconds median complete ZIP process, 17.707 → 16.979 seconds
median proving, about 27.05 GB peak RSS. This is 1.011× process / 1.043× proving,
not a 12.6× full-proof improvement (`sn2-native-felt-metal-pair-v2.json`).

The new pinned manifest covers 15 workloads: Cairo opcode and builtin programs,
all-builtins at small and canonical sequence geometry, executable arguments,
a real Fibonacci bootloader PIE, and the four external Starknet PIE archives.
`scripts/benchmark_cairo_suite.py` checks workload hashes, security, proof hashes,
CPU/Metal parity and official acceptance; it retains failed cases and includes
initial trials. `--workers` supports serial worker-width sweeps. External PIE
archives must match the manifest hashes. Artifact caches are retained unless
explicitly isolated; OS Metal pipeline caches remain managed by the driver.

The first full matrix qualified 28 of 30 cases. All 15 CPU proofs passed;
13 Metal proofs matched their CPU bytes. SN1 and SN3 Metal failed with
`Metal column backing exceeds u32 offsets`. This is an incomplete suite result,
not a silently reduced matrix. Each entry below is one qualification trial,
not a statistical median. Process times include ZIP execution, proving and
product verification; separate pinned-Rust verification is recorded outside
those process times. Peak RSS is the largest measured process in the process
tree, not a sum of all simultaneously live subprocesses.

| Large PIE | CPU process / prove | CPU peak RSS | Metal process / prove | Metal peak RSS |
| --- | --- | --- | --- | --- |
| SN1 | 117.969 / 113.389 s | 51.25 GB | failed: 32-bit offsets | — |
| SN2 | 36.155 / 33.711 s | 41.82 GB | 19.459 / 16.986 s | 27.05 GB |
| SN3 | 119.125 / 114.625 s | 54.17 GB | failed: 32-bit offsets | — |
| SN4 | 50.892 / 46.782 s | 54.70 GB | 45.096 / 40.954 s | 34.56 GB |

Canonical all-builtins qualified at 10.848 s CPU and 4.660 s Metal complete
process times with identical proof bytes. Cold Metal pipeline preparation is
material: an earlier all-builtins process took 799.903 seconds, of which
795.154 seconds was pipeline admission. That cold receipt is retained as
`all-builtins-metal-canonical-cold.json`; warm measurements do not erase it.
The complete suite summary with hashes, failures and all smaller workloads is
`cairo-suite-native-felt-v1-summary.json`. Raw logs/stages and proof files remain
under `zig-out/cairo-completion-20260927/cairo-suite-native-felt-v1`.

Bounded, strided batching of felt division and affine EC deductions is the next
candidate, not yet a qualified product performance improvement. The canonical
scalar path remains the differential reference. Nine filtered package tests
passed, including the new batch boundary/error/stride and ragged-tail checks.
The generated C writer ABI is version 2; eligibility is selected from canonical
deduction IDs and argument/output shapes, rather than workload labels.


The first batch candidate's full SN2 pair (`sn2-batched-deduction-no-admission-pair-v1.json`)
qualified all six proofs but did **not** batch the production EC programs:
recorded programs contain multiple arithmetic deductions. Its ~2.6% process
variation is not attributed to batching. The generator has subsequently been
extended to phase across multiple deduction boundaries and compact SSA live
registers while retaining contiguous deduction outputs. For example, the
window-18 writer now uses 309 live slots instead of 6,298 historical registers,
and the generic EC writer 428 instead of 14,382, allowing 89/67 rows per bounded
tile. This new candidate is not yet fully qualified or timed.

All 28 focused deduction package tests passed after exposing the complete
helper test surface. The older Pedersen test-only integer-width expression and
an incorrect full-width XOR expected value were corrected. Two register-plan
differentials passed. The revised shader inventory admits 233 native exports;
all eight focused shader authority tests passed. Direct BLAKE2s commitments now
have a dedicated 64-bit-offset kernel, with native core ABI 25; bounded compact
resident commitments retain their existing offset ABI. Larger-PIE Metal proof
acceptance remains required before calling this capacity fix qualified.


## Effective multi-call batching qualification

The subsequent real production candidate qualified all-opcodes, Fibonacci PIE
and canonical all-builtins on CPU and Metal with exact prior proof bytes and
pinned official acceptance. Three alternating SN2 pairs then qualified:
19.596 → 18.722 seconds median complete ZIP process, 17.150 → 16.275 seconds
median proving; peak RSS remained ~27.05 GB. This is a measured 1.047× process /
1.054× proving improvement (`sn2-multicall-batch-metal-pair-v1-summary.json`).
All six SN2 proofs retain SHA-256
`ddf5b47bb928a75b699d0297b75fd0c3fb40ad6679f4ab26c32d2dfee9149545`.
The after trials report 42 binary-archive hits, zero direct compiles, 141 Metal
dispatches and zero unexpected fallbacks. This comparison includes the new
live-register allocator, real multi-call batching, wide commitment offsets
and profiling; the paired result is attributed to the whole candidate.

Per-component profiling shows ~3 seconds of composition remain on the host.
The largest refusals need 4.706 GB (window-18 EC), 4.429 GB (Pedersen points),
3.121 GB (BLAKE G) and 2.634 GB (generic EC), exceeding the product's 512 MiB
single-component arena cap. The next architecture work is bounded GPU execution
of these components, rather than silently enlarging benchmark working sets.

The first larger Metal qualification progressed past the prior commitment-offset
limit, then SN1/SN3 failed with `PolynomialEvaluationFailed` after composition.
Raw failure evidence is retained under `cairo-suite-wide-large-v1`. The later
sampled-coefficient streaming fix and accepted full proofs are recorded below.

## Larger PIE coefficient streaming qualification

The existing native coefficient evaluator already runs in bounded waves; an
obsolete aggregate u32 bound prevented it from rebasing larger sources into
those waves. The global limit is now replaced by checked host byte arithmetic,
while each dispatched column and local task offset retains its u32 bounds.
Forty focused native receipt/budget/geometry tests passed. No larger aggregate
GPU coefficient allocation is introduced.

The retained `cairo-suite-sampled-wide-v1` single-trial qualification passed the
pinned official Rust verifier, canonical 70-query/26-bit PoW parameters, and
unchanged CPU-reference proof bytes for every selected PIE:

| PIE | Complete process | Proving | Peak process RSS |
| --- | ---: | ---: | ---: |
| Fibonacci | 1.829 s | 0.622 s | 1.551 GB |
| SN1 | 163.513 s | 159.051 s | 44.622 GB |
| SN2 | 18.168 s | 15.714 s | 27.053 GB |
| SN3 | 162.806 s | 158.290 s | 43.966 GB |

These are coverage qualifications, not paired speed claims. SN1/SN3 now expose
major large-source costs: sampled evaluation 68.39/71.95 s and FRI quotient
39.88/39.02 s. They are slower than their earlier CPU trials and remain clear
optimization targets. The earlier failures stay in their original receipts.
The separate SN2 three-pair median remains 18.722 s until another paired run.
See `cairo-suite-sampled-wide-v1-summary.json` for identity and acceptance.

Bounded row-tiled GPU composition is being implemented for large components
that exceed the 512 MiB native placement budget. It is not yet qualified or
included in any timing above.

## Bounded composition and committed-column opening candidates

A bounded native/tiled composition plan now keeps its GPU arena within 512 MiB,
with exact core mask mapping on host and global-row denominators on device.
Tile outputs are collected transactionally before updating the host accumulator;
a late failed tile cannot poison a resumed host evaluation. Smaller components
retain the native stored-column route.

The first library accepted official opcode and Fibonacci proofs, but its first
large tiled pipeline spent more than 12 minutes in Metal compilation. That
prototype was cancelled before a tiled full-proof qualification; all partial
receipts remain in `cairo-suite-bounded-first-v1` and its local summary. Its
native opcode trial includes 135.706 s of cold pipeline preparation. No tiled
performance improvement is claimed from that run.

The second reader uses direct descriptor slots for the common AIR masks
0/-1/+1, retaining a general path for arbitrary masks. Its distinct `td2_`
namespace prevents accidental binding to the earlier descriptor ABI. Six
focused tiled tests (including arbitrary masks, tails and allocation failure)
and seven emitter tests passed. Artifact provenance and measured hash are in
`bounded-composition-v2-provenance.json`; semantic qualification is pending.

The next candidate also stops retaining a coefficient copy beside committed
columns on the Metal product. The CPU reference keeps its coefficient strategy.
Mixed resident/staged barycentric trees are partitioned into separate backend
epochs, so a cached host preprocessed tree cannot force large device trees into
host staging or impose its upload slab limit on them. All 25 focused sampled PCS
regressions passed, including mixed residency, unsupported host geometry with
unchanged outputs, and allocation-failure cleanup. Complete official proofs and
paired timings remain required before a speed or memory improvement is claimed.

The first direct-slot SN2 candidate accepted the unchanged proof hash but admitted
only the original 42 device components: the runtime still required a full-domain
row count and rejected every tiled plan before preparing its pipeline. Its
67.473 s process includes 48.306 s of cold native pipeline preparation and is
not a tiled speed qualification. Sampled opening from committed columns ran in
0.237 s, but peak process RSS was 28.024 GB; no aggregate memory saving is claimed.
The subsequent runtime geometry fix separates full evaluation log from dispatch
rows in host planning, preserving the packed 14-word/56-byte shader arguments.
Four geometry/ABI tests passed. The corrected SN2 product qualified with the
official Rust verifier and the unchanged proof SHA-256
`ddf5b47bb928a75b699d0297b75fd0c3fb40ad6679f4ab26c32d2dfee9149545`.
It admitted 52/58 composition components to Metal, with zero runtime fallbacks.
The first process took 620.386 s, including 602.549 s of first-use Metal
pipeline preparation; it is not a warm proving measurement. The independent
warm trial took 16.022 s process/13.680 s prove and 27.665 GB peak process
RSS, with 52 binary archive hits, zero direct compiles, the same official
acceptance and proof hash. Its composition path staged 23,298 MiB in 383.5 ms;
the native-pair tile candidate is designed to reduce this transfer. Retained
receipts: `cairo-suite-bounded-resident-sn2-v3` and
`cairo-suite-bounded-resident-sn2-v3-warm`.

Codegen v5 (`td3_`) stages each required masked column once per native lifted
pair in a row tile. Exhaustive small-domain mask tests, six tiled planner/stager
tests, and seven emitter tests passed. The product artifact and source identity
are in `bounded-composition-v3-provenance.json`. A complete proof and paired
benchmark are required before this candidate receives a speed claim.

## SN2 bounded-path experiments and measured next target

The `td3_` native-pair reader qualified the same canonical official SN2 proof.
Its first process took 679.929 s, including 662.087 s preparing 52 uncached
Metal pipelines; compilation overlapped engineering builds, so this is a
qualification receipt rather than an isolated cold-start comparison. A warm
single trial took 16.253 s process/13.824 s prove. Three alternating pairs,
with a 6 GiB retained cache budget to avoid evicting the compared products,
gave 17.285 → 16.876 s process and 14.883 → 14.445 s prove. Peak RSS stayed
27.666 GB. All six proofs matched and passed the pinned official Rust verifier.
This is a modest 2.4% median process difference, with negligible improvement
inside the composition stage itself; SN2 still stages 23,298 MiB, including
20,108 MiB from tiled components. Broader PIE measurements remain required.

Two CPU-side candidates also qualified unchanged official proofs:

| Experiment, 3 alternating pairs | Before process | After process | Before prove | After prove |
| --- | ---: | ---: | ---: | ---: |
| Pedersen point-to-column transpose | 17.689 s | 17.669 s | 15.127 s | 15.090 s |
| Deduction batches 128 → 256 rows | 17.393 s | 17.260 s | 14.833 s | 14.775 s |

The transpose is removed: it was performance-neutral, and an isolated profile
showed preprocessed column materialization was only 0.046 s versus 1.045 s
for its commitment. The batch change is a small candidate improvement, not
an order-of-magnitude claim. All qualification and pair summaries, identities,
official acceptance, cache receipts, and raw paths are recorded in
`sn2-bounded-optimization-experiments-v1.json`.

The same diagnostic profile exposed a much larger frontend opportunity. Fixed
multiplicity routing took 1.185 s; `range_check_20` processed 155,855,000 feed
rows on one table owner in 1.123 s, while `range_check_9_9` consumed 87,543,808
rows in 0.761 s. The next candidate partitions large-table feeds into bounded
row tasks with shared checked atomic counters, plus a 1 KiB small-key cache
per worker. Small tables retain one writer. No private full-table histogram
or merge pass is introduced. Collision, direct/cached atomic updates, invalid
keys and overflow tests pass; an assembled official proof and paired timings
are still required.

The assembled 1 KiB-cache atomic scatter candidate qualified the unchanged
official SN2 proof. Fixed routing fell from 1.185 s to 0.663 s in diagnostic
runs, including 0.525 s for 1,250 bounded parallel tasks. Three alternating
pairs against the native-pair product control measured 16.778 → **16.066 s**
process and 14.353 → **13.605 s** proving, a 4.4% process/5.5% proving gain.
Peak process RSS stayed 27.669 GB. Every proof matched the CPU reference and
passed the independent official Rust verifier; no Metal fallback occurred.
See `sn2-fixed-atomic-v4-v8-pair-summary.json` for complete identities and paths.
The next candidate extends small-key coalescing across up to 16 relations,
using a bounded 16 KiB cache per worker; mixed-relation, direct atomic, collision
and overflow tests pass, but its full-proof performance is not yet qualified.


### Larger PIE coverage of the assembled path

The v9 product now qualifies SN PIE 1 and 3 at canonical 70-query/26-bit
security, with byte-identical CPU reference proofs independently accepted by
the official verifier and zero Metal runtime fallbacks. These are single
process qualifications, not paired speedup medians:

| Workload | Complete ZIP process | Proving | Peak process RSS |
| --- | ---: | ---: | ---: |
| SN PIE 1 | 50.546 s | 45.998 s | 45.392 GB |
| SN PIE 3 | 39.980 s | 35.365 s | 45.060 GB |

SN1 opening fell from the earlier qualified 68.390 s to 1.585 s and FRI from
39.880 s to 2.199 s. Committed-column retention also removes the coefficient
input that otherwise selects the host combined-quotient compatibility route,
allowing the Metal raw-quotient route. This is the major architectural gain.
SN1 total process fell from the previous Metal qualifier's 163.513 s, but its
RSS did not improve (previously 44.622 GB). Cache and pipeline conditions vary;
these two single qualifiers establish coverage and stage direction, not an
isolated paired causal comparison. Complete identities, hashes, stage costs,
and cache receipts are in `large-pie-qualification-v9.json`.

The existing resident LogUp selector was also screened on the same frozen
product. SN1 took 50.790 s / 46.217 s proving / 46.065 GB RSS; SN3 took
42.125 s / 37.599 s proving / 45.526 GB RSS. All proofs remained exact and
accepted. Three alternating SN2 pairs measured 16.745 → 16.493 s complete
process, only a 1.5% gain, with unchanged 27.669 GB RSS. This path is not yet
promoted. Its secure-field executor ABI materializes every GPU coordinate
plane into a second full trace and then lowers that trace back into commitment
planes; even nonresident CPU components lose their direct-plane materializer.
The next implementation removes those redundant representations through an
optional backend coordinate-output callback. It preserves the legacy callback
for existing callers and diagnostic comparison.


### Direct coordinate output and independent interaction planning

The v10 direct-coordinate executor qualifies all three large PIEs with exact
CPU-reference proof bytes and official acceptance. Single process times are
SN1 55.856 s (50.473 s proving, 46.005 GB RSS), SN2 15.564 s (13.021 s proving,
27.669 GB RSS), and SN3 40.469 s (35.828 s proving, 45.433 GB RSS). SN1 includes
a newly minted preprocessed-cache generation; the results do not establish a
broad GPU interaction speedup. The new executor contract avoids the redundant
secure-field trace on resident components and keeps nonresident CPU components
on their direct-plane writer. Focused tests cover legacy/direct coordinate
parity, malformed destination refusal before dispatch and propagated device
errors without a second executor attempt.

The v11 candidate also plans the interaction tree independently after live
geometry is known, and supports writing coordinate planes into final
log-grouped commitment storage. It preserves the existing 8 GiB allocation
bound and fails closed on pointer/shape disagreement. The allocator owner now
releases a declined arena layout exactly once; the old `tryPrepare` repeated
that teardown after `allocate` had already done it. Scoped arena tests include
allocation failure and disjoint per-log coordinate ranges. The candidate also
fixes plane-descriptor cleanup on interaction construction failure.

Single v11 CPU-coordinate interaction qualifiers are SN1 44.650 s complete /
40.031 s proving / 45.609 GB RSS, SN2 17.285 s / 13.935 s / 27.635 GB (initial
preprocessed-cache miss), and SN3 38.025 s / 33.395 s / 44.775 GB. These remain
coverage receipts rather than performance promotions. Plan admission needs
explicit telemetry: the initial recorded profiles do not show the arena-bound
commitment marker, so these changes must not yet be claimed as a measured
elimination of the commitment copy. Raw receipts are under
`cairo-suite-sn2-interaction-arena-v11` and `cairo-suite-large-interaction-arena-v11`.


### Complete v12 Cairo matrix

All 15 manifest workloads now qualify on Metal, including opcode, bitwise,
range-check, Poseidon, Pedersen, all-builtins, executable input, Fibonacci PIE,
and SN PIE 1–4. Every proof is independently accepted at 70 queries/26 PoW
bits, with zero runtime fallback telemetry. The full product identity, workload
and proof hashes, memory, stage timing, cache and compiler receipts are in
`cairo-suite-qualification-v12.json` and its linked raw result directories.

The full-process single trials include first-use pipeline compilation. For
example Poseidon takes 26.305 s including 25.776 s of pipeline preparation;
Pedersen takes 79.427 s including 78.906 s, and all-builtins canonical takes
71.736 s including 66.724 s. These must not be published as warm proving
performance. Large PIE single qualifiers are SN1 44.353 s process / 39.805 s
proving / 45.600 GB RSS; SN2 16.140 s / 13.627 s / 27.680 GB; SN3 39.574 s /
35.020 s / 45.207 GB; and SN4 31.404 s / 27.125 s / 36.024 GB, the last
including 9.556 s of new pipeline preparation.

Explicit planner telemetry confirms SN2's 4,569,563,136-byte interaction arena
is admitted. SN1's independently materialized interaction source is refused
by the original 8 GiB cap. A new candidate allows an existing interaction
source up to the complete device 32-bit word-address bound (16 GiB), replacing
fragmented storage and transforming that arena in place. It retains the
conservative base/pre-execution bound, exact column-shape admission and
bounded commitment ownership. A common trace-commit owner now also moves
all local fallible operations before transfer, preventing lost columns or
backing descriptors on allocation/recorder failure. Scope tests exercise
geometry refusal, backing-allocation failure and engine failure after transfer.
The larger candidate still requires full proof qualification and paired timing.


### Independent interaction ownership and incremental feed release (v13–v15)

The 16 GiB interaction-source admission now qualifies on SN PIE 1 and 2;
it replaces existing fragmented source storage rather than adding a second
source allocation. SN1 admits 8,603,680,768 bytes, just beyond the old 8 GiB
cap. Its interaction commitment is 1.725 s in the v13 single qualifier, with
899 ms of GPU LDE, compared with roughly 4.3 s of GPU LDE in the earlier
fragmented path. Single full-process receipts are 44.518 s for SN1 and
16.142 s for SN2. Their official proof hashes are unchanged. These are
coverage and stage observations, not paired speedup estimates.

A shared trace-commit owner performs pointer validation, recorder admission
and backing-descriptor allocation before transferring columns. Thirteen
focused tests cover layout, allocation failure and teardown ownership. The
interaction collector also releases each lookup feed immediately after its
last use, retaining independent fixed/memory multiplicities and subcomponent
feeds. Seven lifetime tests cover borrowed, host and backend owners.

The v14 resident-coordinate path with incremental feed release qualifies SN1,
SN2 and SN3 at 70 queries / 26 bits and zero runtime fallbacks: complete-process
single trials are 49.025, 15.666 and 31.849 s respectively. Peak process RSS is
46.018, 27.647 and 45.636 GB. SN1 includes a fresh preprocessed-table generation.
This does not establish a general resident-LogUp speedup or an RSS reduction;
resident LogUp remains opt-in pending broad paired evidence.

An opt-in v15 placement experiment touches one word per shared output page
immediately before LogUp. Three alternating SN1 pairs measure 36.893 →
36.022 s process and 31.806 → 31.073 s proving, but driver wait varies widely:
GPU arithmetic totals roughly 0.21–0.26 s while command waits range from
1.15 to 10.17 s across retained trials. SN2 pairs measure 15.964 → 15.809 s
process and 13.472 → 13.393 s proving, less than a 1% improvement. Every trial
preserves exact proof bytes and official acceptance. Neither result alone
justifies enabling prefaulting by default. See
`sn1-relation-paging-v15-summary.json` and `sn2-relation-paging-v15-summary.json`.

### Primitive ablation and frontend decoding

The M31 Metal ablation compares the existing wide multiply/fold, a narrower
fold, and an explicit split product. At 1,048,576 rows, 128 rounds and nine
alternating repetitions, medians are 0.934250, 0.932875 and 1.070875 ms.
All rows match between variants, with 4,096 scalar reference rows and 64 edge
pairs checked. GPU clock ramp is visible in the retained trials: the narrow
fold is neutral and split multiplication loses, so production shaders remain
unchanged. The harness is in `autoresearch/benchmarks/cairo/metal-m31-ablation`;
the raw receipt is `zig-out/cairo-completion-20260927/m31-ablation-compute-v1.json`.

The zlib-rs frontend decode candidate retains the pinned Cairo VM, strict
five-member ZIP validation, bootloader and exact compact input. Three adapter
pairs on SN2 reduce decode from approximately 390 ms to 334 ms and complete
adapter medians from 2.134 to 2.071 s. The first candidate process also retains
an unprofiled startup delay, rather than excluding it. See
`adapter-deflate-v16-summary.json`; full product qualification is pending.

The owned Metal preprocessed commitment previously bypassed the armed layer
cache. A shared cache reader now serves both owned and streaming commitments,
exports device upper layers in bounded chunks on a miss, re-derives upper
layers on a hit, and keeps column LDE computation unchanged. Exact root and
queried-hash tests, corrupt-load refusal and allocation teardown qualify the
core seam. Full product timing and official verification remain pending.


### Metal cached hashes with independent column residency (v17)

The initial v16 cache miss qualified, but its warm hit failed the product's
strict fallback contract because adopting a host hash owner also lost device
column residency. The rejected receipt is `sn2-cached-owned-v16-rejected.json`.
The final v17 owner keeps authenticated host hash layers and an independent
proof-owned Metal view of the freshly evaluated columns. Page-aligned backing
arenas are borrowed without another data copy; copied bindings retain external
budget reservations. The resource is released before its host backing.

The generic resident-column resolver now supports both a shared buffer map
and a per-column buffer map. The latter is checked by GPU barycentric parity
against scalar circle evaluation across multiple trees and points. The cached
artifact has its own telemetry event: it counts neither a fresh CPU hash commit
nor a GPU dispatch. Actual host hashing or sampled evaluation still rejects
strict qualification. Nine focused cache/shared-owner tests and 35 Metal
sampling/profile tests pass, including malformed/corrupt loads, partial
allocation teardown, per-column device views and fallback classification.

Three SN2 pairs preserve all six exact proofs and official acceptance, with
zero runtime fallback. Both variants use the same pre-zlib adapter to isolate
the cache change. All-trial process medians are 16.086 → 16.205 s and proving
medians 13.619 → 13.735 s: timing is neutral, not a speed promotion. The initial
candidate miss, retained in the comparison, took 17.430 s and still built a
full device hash tree. Its two later authenticated hits reduce the actual
product physical footprint from roughly 41.18 to 37.15 GB, a 4.03 GB saving.
RSS instead rises from 27.681 to 27.950 GB because the retained cached upper
layers are host-visible; RSS misses the larger released Metal allocation.
See `sn2-cached-columns-v17-summary.json` for complete identities, cache states,
physical resource counters, timing, proof hashes and oracle receipts.

The benchmark scripts now carry the product's existing Darwin v6 resource
snapshot into both single, paired and matrix summaries. Physical footprint
is a lifetime peak of the prover product and includes Metal memory; wait4 RSS
can include an adapter child's separate maximum and is not a simultaneous
process sum. Missing or partial physical measurements remain null, never zero
or a substituted RSS value. Eight benchmark evidence tests pass. The current
15-workload v17 matrix runs two recorded trials per workload, including the
initial trial and a separately labeled subsequent trial; full coverage is
still pending.


### Complete v17 matrix qualification

All 15 pinned workloads qualify twice (30 officially accepted proofs) at
canonical 70-query/26-bit security, exact prior proof bytes and zero runtime
fallback. The default CPU coordinate writer remains in use; resident LogUp
and page-prefault experiments remain opt-in. The release adapter includes
zlib-rs, and ZIP/bootloader semantics are unchanged. Full binary identities,
cache evidence, proof hashes, physical resource samples and both recorded
processes are in `cairo-suite-qualification-v17.json`.

| Workload | Initial process | Second process | Second proving | Second physical footprint |
| --- | ---: | ---: | ---: | ---: |
| ret | 0.997 s | 0.469 s | 0.376 s | 1.872 GB |
| all-opcodes | 0.663 s | 0.666 s | 0.563 s | 3.014 GB |
| bitwise | 0.478 s | 0.486 s | 0.391 s | 1.939 GB |
| range96 | 0.458 s | 0.448 s | 0.357 s | 1.873 GB |
| range128 | 0.566 s | 0.571 s | 0.477 s | 1.940 GB |
| poseidon | 0.523 s | 0.516 s | 0.418 s | 2.460 GB |
| pedersen | 0.505 s | 0.525 s | 0.428 s | 2.647 GB |
| all-builtins | 0.857 s | 0.860 s | 0.800 s | 5.169 GB |
| executable-add-one | 0.441 s | 0.441 s | 0.347 s | 1.906 GB |
| fibonacci-pie | 0.761 s | 0.765 s | 0.617 s | 3.015 GB |
| all-builtins-canonical | 3.887 s | 3.902 s | 3.827 s | 17.563 GB |
| sn-pie-1 | 34.418 s | 31.058 s | 26.297 s | 61.208 GB |
| sn-pie-2 | 16.452 s | 16.480 s | 13.976 s | 37.152 GB |
| sn-pie-3 | 31.155 s | 31.474 s | 26.833 s | 60.543 GB |
| sn-pie-4 | 21.751 s | 21.456 s | 17.175 s | 45.397 GB |

The second process is a single subsequent observation, not a three-trial warm
median. SN1 and SN3 now measure about 31 s and SN4 about 21.5 s in this matrix;
these are coverage observations, not isolated causal speedup estimates. SN2
is 16.480 s here; the published earlier 16.066 s paired median is not replaced
with this single observation. No claim of achieving the 10× timing target is
made. The full matrix also demonstrates warm Poseidon and Pedersen workloads
at roughly half a second; the v12 26–79 s first-use compiler costs are retained
in their own receipt and must not be confused with warm proving costs.


### Fresh preprocessed hash compaction (v18)

The owned-tree path now exports and retains upper hash layers on a fresh
Metal commitment as well as an authenticated cache hit. It then releases the
full device hash owner while retaining independent device views of the
freshly evaluated columns. Cache writes are optional: a store refusal does
not invalidate device-produced layers. A caller payload bound is checked
before allocating retained layers; oversized shapes keep their original
commitment owner. Eight cache and four shared-owner tests cover admission,
failed allocation and partial device-read teardown. The 25 Metal profile
tests confirm that fresh compaction and cache adoption have distinct events
and neither is misclassified as a CPU fallback.

All six SN2 canonical proofs preserve exact bytes and pass the official
verifier. The initial candidate misses both artifacts and still peaks at
37.152 GB physical footprint, eliminating the previous roughly 41.18 GB
cold-cache footprint. Later hits stay at the same lower footprint. Process
medians are 15.497 s before and 15.971 s after, with the candidate's initial
17.372 s miss retained. These timings are observations, not an isolated speed
promotion: a short row-ticket test compilation overlapped the last pair.
See `sn2-fresh-compaction-v18-summary.json`.

A separate three-pair adapter ablation on SN1, SN2 and SN3 found no meaningful
gain from Rust `-C target-cpu=native`; SN2 was 1.8% slower. All 18 executions
preserve exact compact input bytes. The portable release adapter remains
the default. Profiles and compiler identities are retained in
`adapter-native-ablation-v18.json`.


### Dynamic witness row scheduling (v19 candidate)

The executor now supports worker-local deduction scratch with a shared bounded
row-ticket queue. Large component grains preserve complete 256-row native
deduction batches; small components retain their static split so scheduling
does not reduce parallelism. Two focused concurrent tests check exact row
coverage and cursor saturation, including a final partial range. The frontend
package passes all five selected tests. The control is
`STWO_CAIRO_WITNESS_DYNAMIC_RANGES=1`; default promotion is pending broader
coverage.

Three same-binary SN2 pairs preserve all six exact canonical proofs and
official acceptance, with zero runtime fallback. All-trial process medians
are 16.153 → 15.609 s (3.4% lower), proving 13.729 → 13.274 s. The baseline's
initial cache miss is retained; subsequent baseline processes are 15.918 and
16.153 s. Witness graph medians are 3.719 → 3.640 s, a smaller 2.1% change.
This is a modest result; it does not explain the whole process delta or meet
the aggregate 10× target. Full records are in
`sn2-dynamic-witness-v19-summary.json`. SN1 comparison is ongoing.

SN1's two same-binary pairs also preserve all four canonical proofs. Process
medians are 33.210 → 31.873 s and proving 28.612 → 27.151 s. However, the
witness graph itself is neutral to slightly worse: 7.364 → 7.556 s. That
limits causal attribution of the end-to-end change to this scheduler. The
receipts are in `sn1-dynamic-witness-v19-summary.json`; no order-of-magnitude
scheduling improvement is claimed. Further interaction experiments hold the
witness control fixed to isolate their effect.


### Bounded interaction batches and reusable scratch (v20)

Interaction workers retain one largest batch workspace for denominators,
inverses, multiplicities and cumulative totals. Growth publishes ownership
only after all four allocations succeed. Focused tests check every failing
allocation, growth and reuse across a partial final batch. All 19 selected
interaction tests and eight benchmark evidence tests pass. Two added test
fixtures initially supplied partial output buffers to the full-column API;
those fixtures were corrected, and the unchanged implementation passed.

Same-binary comparisons hold witness scheduling fixed at static and compare
32,768-row static interaction assignments against 8,192-row shared tickets.
SN2's three-pair medians are 15.870 → 15.082 s end to end and
13.428 → 12.693 s proving; the interaction stage itself is
1.839 → 1.438 s (21.8% lower). The initial baseline cache miss is retained.
SN1's two-pair medians are 33.038 → 31.251 s and 28.242 → 26.406 s proving;
its interaction stage is 3.607 → 3.235 s (10.3% lower). All ten proofs
preserve their exact canonical bytes and official acceptance, with no runtime
fallback. Physical peaks remain approximately 37.15 GB for SN2 and 61.21 GB
for SN1: smaller scratch did not change the overall peak, which occurs at
another stage. Full evidence is in `sn2-interaction-batches-v20-summary.json`
and `sn1-interaction-batches-v20-summary.json`.

The next candidate selects 8,192-row dynamic interaction batches by default
and keeps witness dynamic ranges opt-in because their stage benefit was not
consistent across PIEs. Controls for old interaction batch size and static
assignment remain available for reproducible ablations. Diverse default-path
qualification is still required before reporting that candidate as complete.


### Parallel base-column lowering and Metal occupancy (v21)

Base lowering now validates every source/destination length before writing,
then splits large copies into disjoint ranges across at most eight existing
workers. Small copies stay serial. Mutable destination views remain distinct
from the read-only PCS evaluation views; their owner and cleanup policy are
unchanged. The mixed-column test crosses several column boundaries with four
explicit workers and checks every value and malformed geometry. It is
explicitly imported by the frontend test root; six selected tests pass.

Three same-binary SN2 pairs preserve all six exact canonical proofs and
official acceptance with zero runtime fallback. Process medians are
15.749 → 15.136 s and proving 13.327 → 12.757 s. The isolated generated
base-lowering stage is 0.323 → 0.092 s, about 3.5× faster. The final candidate
enables that structural copy policy by default, with an explicit serial
control for repeated ablations. Physical peaks remain about 37.15 GB.
See `sn2-base-lowering-v21-summary.json`.

A separate 256-versus-64 threadgroup comparison reuses the same authenticated
Metal pipelines and clamps dispatch widths to the row count and device limits.
All six proofs qualify, but composition medians are only 2.106 → 2.073 s;
the overall process difference is not attributed to that small stage effect.
The default remains 256. The diagnostic `STWO_METAL_EVAL_THREADS_PER_GROUP`
control resolves once per prepared plan and covers both single and batched
evaluation. See `sn2-metal-occupancy-v21-summary.json`.


### Next substantial witness work

The canonical product's `witnessExecutor` selects the authenticated native
CPU AOT registry. An older resident Metal witness code generator and recipe
family exist, but they are tied to the older planned-arena orchestration and
are not currently selected by this product. The next experiment should
benchmark complete, table-free generated witness components on real captured
inputs against the native CPU writers, checking every base, lookup and
subcomponent word. If worthwhile, connect whole-component execution through
the existing semantic-identity admission seam, with bounded proof-owned device
storage. Do not submit a GPU command for each CPU worker range. Unexpected
errors after selecting a device executor must fail the proof.

The existing GPU Felt252 helper uses sixteen 16-bit Montgomery limbs and
per-row inversions; the native CPU path already uses optimized field arithmetic
and batched inversions. Therefore merely selecting the older GPU EC writer
is not evidence of a speedup. Start with structurally admitted table-free
BLAKE/bitwise programs, then measure field and EC work before choosing their
placement. Keep the product's canonical Cairo hash semantics and PCS security
unchanged.


### Complete v22 default-path qualification

All 15 workloads qualify twice with both measured interaction/copy policies
enabled by default, exact prior proof bytes, 70 queries, 26 PoW bits and zero
runtime fallback. The full receipt is `cairo-suite-qualification-v22.json`.
The second trial below is a single observation, not an isolated paired median.
The separate SN2 15.082 s interaction paired median remains the measured
optimization result; the matrix demonstrates coverage and cache/resource
behavior rather than a new causal timing claim.

| Workload | Initial process | Second process | Second proving | Second physical peak |
| --- | ---: | ---: | ---: | ---: |
| ret | 1.489 s | 0.438 s | 0.346 s | 1.873 GB |
| all-opcodes | 0.630 s | 0.621 s | 0.520 s | 3.015 GB |
| bitwise | 0.462 s | 0.457 s | 0.362 s | 1.872 GB |
| range96 | 0.440 s | 0.432 s | 0.337 s | 1.873 GB |
| range128 | 0.542 s | 0.532 s | 0.438 s | 1.873 GB |
| poseidon | 0.485 s | 0.483 s | 0.386 s | 2.461 GB |
| pedersen | 0.485 s | 0.485 s | 0.384 s | 2.649 GB |
| all-builtins | 0.791 s | 0.788 s | 0.732 s | 5.169 GB |
| executable-add-one | 0.410 s | 0.427 s | 0.333 s | 1.907 GB |
| fibonacci-pie | 0.724 s | 0.725 s | 0.571 s | 3.016 GB |
| all-builtins-canonical | 4.953 s | 3.800 s | 3.729 s | 17.565 GB |
| sn-pie-1 | 32.461 s | 29.973 s | 25.293 s | 61.209 GB |
| sn-pie-2 | 15.688 s | 15.886 s | 13.438 s | 37.153 GB |
| sn-pie-3 | 30.326 s | 29.985 s | 25.372 s | 60.536 GB |
| sn-pie-4 | 20.589 s | 20.329 s | 16.165 s | 45.399 GB |


### Packed BLAKE reads and native G emission (v23 rejected)

The experiment added optional packed small-word access to the Cairo table
provider and inline native C G/triple-XOR emission for exact total deduction
shapes. Six packed-word tests and six round tests pass, including all ten
sigma rounds, high small-value limbs, invalid encoded tags and missing-row
semantics. Compiling the emitted C helper with Zig 0.15.2 and comparing every
combination of six six-word edges plus 10,000 seeded random inputs passes all
56,656 cases (`native-g-parity-v23.json`). All six full SN2 proofs preserve
canonical bytes and official acceptance.

The timing evidence does not support promotion: process medians are
14.929 s for the retained v22 path versus 15.352 s for the candidate, with
its initial 16.824 s cache miss retained. G writer medians are
0.250 → 0.262 s and round writers roughly 0.290 → 0.290 s. The candidate
is removed from production, including its extra table callback and duplicate
C arithmetic implementation. The retained product in `zig-out/bin` is the
fully qualified v22 build. The rejected patch and original emitter are kept
under `autoresearch/benchmarks/cairo/`; the parity harness compiles that saved
emitter. Timing and proof receipts are in `sn2-packed-blake-v23-rejected.json`.
This is evidence against callback removal as the next large speed lever, not
a change in cryptographic semantics or proof security.


### Wide native witness row tiling (v24)

The native CPU writer gathers only used input columns into bounded row-local
tiles, computes every original deduction phase in order, and publishes only
written output/lookup channels with contiguous column traversals. Tile storage
includes registers and arguments under the existing 256 KiB per-worker limit;
odd padded strides reduce power-of-two cache-set conflicts. Tiny programs keep
the original path. The native ABI and full semantic identities are unchanged.

All 64 emitted programs pass 256 compiled before/after cases with full, partial,
empty and short-tail ranges, including untouched sentinels for every output,
lookup and subcomponent word (`native-row-tile-parity-v24.json`). Stateless
synthetic providers test emission independently of cryptographic deductions;
all six canonical SN2 proofs also preserve exact bytes, pass the official
verifier and report no runtime fallback.

Three serial alternating pairs retain the initial candidate cache miss:
process 15.299 → 14.210 s, proving 12.910 → 11.741 s, witness graph
3.511 → 2.051 s (41.6%), complete base trace 4.315 → 2.854 s. Peak
physical footprint stays 37.153 GB. See `sn2-native-row-tiles-v24-summary.json`.
All 15 workloads now qualify twice with exact prior hashes and zero runtime
fallback (`cairo-suite-qualification-v24.json`). Row tiling is retained.
Subsequent matrix observations: SN1 29.723 s, SN2 14.620 s, SN3 27.648 s,
SN4 18.149 s; these are coverage observations, not additional paired claims.

### Resident LogUp recheck (v22)

Three same-binary pairs with output prefault enabled in both variants give
14.806 → 14.574 s process, 12.455 → 12.196 s proving and
1.419 → 1.110 s interaction. All six proofs preserve bytes and official
acceptance. A short parity recompilation overlapped the first baseline startup;
retain the full receipt and leave this modest overall improvement opt-in.
See `sn2-resident-logup-v22-recheck.json`.


### Preprocessing overlap and cache-source transfer (v27 retained)

Large Metal preprocessing now runs concurrently with the CPU witness. A joined
worker exclusively owns the scheme/channel; the main coordinator resumes the
original root/claim mix order only after the worker finishes. Smaller variants,
CPU backends and exact-work audit requests retain serial execution. Thread
creation refusal also preserves serial execution. Stage trees and completed task
graphs move after joining; all list reservations precede ownership changes.
Allocation-failure testing also repaired an existing profiler stage-publication
use-after-free on failed stack-list growth.

The Merkle artifact seam and its Cairo session are coordinator-local. The
existing deferred first-tree worker explicitly captures/binds that source,
restoring fresh compaction and cached-owner adoption. The intermediate v26
prototype omitted this transfer and regressed physical peak by 4 GB; it is not
the retained build. Nine cache tests (including deferred store/hit root/channel
parity), two coordinator-local seam tests, four joined-recorder tests with
allocation-failure injection and five cleanup-selected tests pass.

Three corrected same-binary SN2 pairs: **13.888 → 12.859 s process**,
**11.506 → 10.458 s proving**, **37.153 GB physical peak**, six exact
canonical proofs accepted by the official verifier with no runtime fallback.
See `sn2-preprocessed-overlap-v27-summary.json`; every initial miss is retained.
Additional individual qualifications preserve prior hashes and peaks:
SN1 **29.220 s / 61.203 GB**, SN3 **25.117 s / 60.536 GB**,
SN4 **17.086 s / 45.399 GB**. These are qualification observations, not paired
causal claims. Large preprocessing overlap is enabled by default after them.

### Grouped fixed-feed experiment (v28 rejected)

Grouping feeds over borrowed producer records qualified every proof and passed
collision, overflow, invalid-key and allocation-failure tests. But target-stage
medians slowed **0.672 → 0.720 s**. The overall 13.074 → 12.754 s process
variation does not establish a win. The production experiment is removed;
`sn2-grouped-fixed-v28-rejected.json`, its patch and grouping module remain as
negative evidence under the benchmark directory.

### Base-norm scaled QM31 batch inversion (v31 retained)

Compute each extension cofactor independently, invert eight striped base-field
norm products, and fold the numerator into the final scalar scale. The caller
provides mutable input scratch and disjoint output/numerator planes; there are
no additional allocations. Zero denominators fail even with zero numerators.
Packed CM31/QM31 transpose/arithmetic helpers are shared with the existing
Montgomery batch path rather than duplicated. All 16 focused norm/field tests
and 19 Cairo interaction tests pass, including complete normalized/base parity
for all 68 relation templates and partial-tail scratch reuse.

The scalar prototype was slower (v29 receipt retained). The explicit four-row
SIMD candidate measures **1.80×, 1.58×, 1.49×, 1.58×** faster at
1,024 / 32,768 / 262,144 / 1,048,576 scaled inverses, respectively.
`qm31-norm-batch-v30.json` retains all four alternating pairs per size and
every output comparison. Setup/copy work is outside primitive timing because
the proving caller already owns mutable denominator scratch. This is not an
end-to-end claim; the Cairo LogUp candidate remains controlled until measured.

Three SN2 pairs measure **12.951 → 12.608 s process**, **10.555 → 10.267 s proving**, and **1.435 → 1.286 s interaction**, with unchanged **37.153 GB** physical peak. All six canonical proofs are byte-identical and officially accepted; no fallback. See `sn2-norm-logup-v31-summary.json`. The complete v31 matrix additionally qualifies **30 proofs / 15 workloads**, including all four real PIEs (`cairo-suite-qualification-v31.json`). The full suite subsequent SN2 observation is **13.247 s process / 10.816 s proving**; retain it alongside the paired median rather than selecting the fastest observation. Norm-based LogUp is now default; `STWO_CAIRO_NORM_LOGUP=0` retains the prior algorithm for controlled comparisons.

### Direct composition column borrowing (v32 experiment)

A separate pd4 reader ABI binds immutable retained native columns through a GPU address table. The arena holds only authenticated shifts, interaction bases, parameters, coefficients, denominators and bounded output coordinates. All source geometry is checked before dispatch. Synchronous batch completion precedes clearing borrowed aliases; small unaligned copies share a strict 64 MiB request budget reserved before any copy. No AIR, transcript, PCS, security parameter or proof encoding changes.

All 37 focused composition tests pass, including artifact substitution rejection, planner allocation-failure cleanup, native shape parity and excluding source planes from arena sizing. The three-reader artifact has 207 kernels over the same 69 programs (`indirect-composition-v32-provenance.json`). This remains opt-in. The first SN2 pipeline admission is currently spending minutes in the Metal driver; no proving-speed claim is made while this experiment remains unqualified. The first control trial (19.738 s / 16.505 s proving) includes 52 driver compiles and cache misses and is preserved. A one-second process sample during the first candidate startup is diagnostic overhead; do not treat that trial as uncontaminated timing.

The v32 comparison completed six exact canonical proofs with official verification and zero fallback. All-trial medians are **13.122 → 12.898 s process**, **10.656 → 10.418 s proving**. The first candidate was **398.488 s**, including **386.017 s** driver pipeline preparation; later processes reuse all 52 binary archive entries. This startup regression prevents default promotion. Candidate process peaks were **22.178 GB**, versus control maximum **38.208 GB**; investigate precise allocation/residency causes before attributing this entire difference to source staging or translating it to CUDA VRAM. See `sn2-indirect-composition-v32-summary.json`; the initial diagnostic sample is retained and annotated above.

The additional GPU custody tests pass: a rejected copy budget leaves no binding behind, a borrowed plane remains live through dispatch, an unaligned small plane preserves its copied snapshot, missing source planes are zero, and an explicit clear allows another request. The next pd5 candidate replaces per-read nullable branches with a retained shared zero pair and authenticated maximum lifting shift for missing planes, aiming to reduce driver compilation without changing zero-column semantics.

### GPU work paused for CPU 2× target

At the user’s request, v33 GPU benchmarking was stopped during its first candidate driver compilation. The prior nullable v32 experiment has six exact accepted proofs, but v33 has no complete proof qualification. Both frozen products and raw first-trial receipts remain locally available. All direct-column production changes are removed back to the preceding qualified implementation; the complete candidate is retained as `autoresearch/benchmarks/cairo/indirect-composition-v33-paused.patch` with its GPU custody test source. The authenticated composition artifact is restored to v3. CPU norm inversion, row tiling, core SIMD hashing, deferred cache transfer and the other retained changes remain in place. The immediate task is a measured 2× improvement from the current CPU build, not from the old 110.829-second baseline.

## CPU-only 2× target from v32

GPU work is paused at the user's request. The fresh CPU baseline uses the
retained native witness tiles and norm-scaled LogUp, canonical 70 queries / 26
PoW bits, and the same official PIE and verifier. Both complete trials retained
SN2 proof SHA `ddf5b47bb928a75b699d0297b75fd0c3fb40ad6679f4ab26c32d2dfee9149545`.
First process/proving: 34.800 / 31.448 s; subsequent process/proving: 32.145 /
29.786 s. Two-trial medians: 33.472 / 30.617 s. Peak physical footprint is
41.063 GB. The subsequent sample is one observation, not a warm paired median.
The target is ≤14.893 s proving and ≤16.072 s process against this observation,
then confirmation with alternating before/after pairs. CPU baseline receipt:
`sn2-cpu-baseline-v32.json` (raw stages under `sn2-current-cpu-v32`).

Warm baseline stages: composition 10.162 s, fixed preprocessing commitment
4.878 s, main commitment 3.643 s, interaction commitment 3.077 s, base trace
2.791 s, FRI 1.864 s, LogUp 1.293 s, sampled values 1.085 s. v34 native CPU AIR
code generation is being qualified; it is not yet a retained speed result.

CPU native AIR engineering: v34 generated 69 authenticated kernels and produced
two exact, officially accepted SN2 proofs, but regressed composition to 15.656 /
16.252 s (36.895 / 35.669 s proving). It is rejected as a performance candidate.
Its generic 64-bit SIMD field lowering omitted the existing ARM `MUL/SQDMULH`
M31 reduction and unsigned-minimum reductions. The following candidate copies
those canonical arithmetic identities, shortens constraint-root live ranges in
unchanged root order, and corrects the CPU streaming/Fft admission mismatch:
64-column streaming cap versus 65-column fused-LDE admission. Qualification is
opt-in through `STWO_CAIRO_NATIVE_COMPOSITION=1` and
`STWO_CAIRO_CPU_WIDE_LDE=1` until complete paired proofs pass.

Standalone native ARM arithmetic passed 100,000 four-lane trials / 1.6 million
scalar comparisons covering add/subtract/multiply/negation, including zero and
near-prime boundaries. Reproduce with `cc -O2 -fno-vectorize -fno-slp-vectorize
-I src/tools/cairo_composition_cpu_codegen autoresearch/benchmarks/cairo/native_cpu_field_parity.c -o /tmp/cairo-native-fields` and run that executable.
Native v35/v36 builds were deliberately interrupted before qualification:
a one-second v36 compiler sample attributed 754/755 samples to emitting debug
variable locations, with 747 in insertion-point searches. Generated C now keeps
line tables without per-register debug-variable tracking. The full compiler
sample and interrupted logs are retained under the ignored raw run directory.

### CPU native composition and commitment scheduling (v37–v40)

All CPU measurements here use the same current v32 CPU baseline, not the
historical pre-optimization CPU build. v37 corrected ARM M31 lowering and
streaming LDE admission: warm SN2 measured 24.806 s process / 22.457 s proving
(1.33× proving), versus 32.145 / 29.786 s in the current baseline.

v40 additionally specializes base/secure field shapes in the typed AIR compiler
and gives each Cairo component the row worker pool in turn. Its first SN2 trial
measured 19.602 / 16.467 s and subsequent trial 17.399 / 15.074 s. Composition
fell from 10.162 to 1.787 s; physical footprint remained about 41.130 GB. Both
proofs are byte-identical and officially accepted at 70 queries / 26 PoW bits.
The warm proving improvement is 1.98×, still short of the requested 2× target.
Turning preprocessing overlap off regressed the two observed proving times to
16.036 / 16.630 s. These are observations, not a paired causal comparison.
See `sn2-cpu-native-v37.json`, `sn2-cpu-native-v40.json` and
`sn2-cpu-native-v40-serial-preproc.json`.

The independent native evaluator test compares all 69 authenticated programs
with the SIMD IR implementation across four domain/additive scenarios. It
includes lifted and equal domains, partial output ranges and strong identity
rejection after instruction mutation. The compiler specializes known base
values and zero/one identities without changing constraint order or proof
parameters. CPU composition work now uses coordinator-owned component phases,
so stage recorders are not shared between simultaneous component workers.
The preceding v38 concurrent per-component profile is diagnostic only: its
shared scope stack could interleave and is not used as a clean stage tree.

The following v41 candidate adds dynamic 8,192-row tickets to avoid fixed
assignments leaving fast cores idle behind slower cores. Each ticket processes
all constraints in protocol order over a disjoint output range; joining all
workers still precedes publishing column freshness. Its CPU defaults require
real proof-matrix qualification before a retained performance claim.

### CPU default qualification and final core optimization

Three alternating v41 pairs qualify exact canonical SN2 proofs with
30.655 → 15.841 s median proving (1.935×) and 32.989 → 18.206 s process
(1.812×). The first candidate cache miss is included. This is an intermediate
result, not fulfillment of the 2× request; see
`sn2-cpu-native-paired-v41-summary.json`.

v42 adds dynamic Merkle leaf work tickets while retaining each worker's private
scratch. Existing lifted commitment, decommitment, mixed-height and allocation
custody tests pass through the new `test-stwo-prover-merkle` target. Both real
SN2 proofs are officially accepted; first process/proving is 19.699 / 16.467 s,
subsequent 17.592 / 15.228 s. v43 adapts ticket size to the domain so small
domains still supply enough independent tiles. The 69-program independent
evaluator comparison and the commitment tests both pass.

v44 raises only Cairo CPU's wide preparation budget to 2 GiB. Generic CPU
frontends retain their prior defaults. Three complete exact pairs measure
30.528 → 15.554 s proving (1.963×), 32.876 → 17.929 s process (1.834×).
Physical peak remains about 41.130 GB. This intermediate candidate still does
not meet 2×; see `sn2-cpu-native-paired-v44-summary.json` for precise medians.

v45 makes native-width ARM M31 subtraction delegate to the existing validated
four-lane SUB/ADD/UMIN reduction. Scalar and packed field arithmetic, randomized
ring laws, canonical edge cases and butterfly parity pass through the new
`test-stwo-core-m31` target. This removes a duplicate slower reduction path
without changing the portable implementation or any proof parameters.

The host AIR generator now imports a protocol-only surface, avoiding runtime
product identity in its dependency graph. A CPU scheduling-only rebuild (v44)
completed in 23 s without regenerating or recompiling the 69 C kernels.
Generated-program changes still require the native parity target; ordinary
commitment-policy changes use focused core/commitment checks and real proof
qualification instead of repeatedly compiling unrelated suites.


### CPU FFT and shared native AIR plans (v46–v53)

v46 batches sampled coefficients in complete native SIMD widths with a single
shared point basis and dynamic column tickets. Ragged 99/100/103-column tests
compare all outputs with independent polynomial evaluation at worker budgets
2, 7 and 18. v47 qualifies all 30 proofs in the 15-workload CPU matrix, including
all four genuine SN PIE archives; see `cairo-suite-cpu-v47-summary.json`.
Its SN2 alternating comparison is 30.644 → 15.974 s median proving (1.918×),
32.993 → 18.320 s complete process (1.801×), still below the requested target.

v50/v52 parallelize radix tuples within giant FFT groups when Cairo has at
most four large columns, then parallelize independent contiguous 3/4/5-layer
bottom blocks. Duplicated-half extension first joins all upper-half writes
before permitting lower-half source overwrite. Generic serial transforms and
other frontend defaults remain available. A warm v50 SN2 observation is 14.769 s
proving / 17.095 s process (`sn2-cpu-native-v50.json`), but the final alternating
v52 comparison is 30.643 → 15.830 s proving (1.936×), 32.985 → 18.154 s process
(1.817×). The favorable single warm observation does not establish 2×.

Qualification correction: the initial focused generic-prover targets rooted
at a named imported module did not discover their intended embedded tests.
Their earlier successful build exit statuses must not be treated as proof of
those tests running. Explicit roots now import FFT/sampling code within its
own package and Merkle test files through their existing named engine boundary.
Actual v53 discovery runs 15 FFT tests and 21 sampling tests, including the
new parallel FFT and ragged SIMD batch tests. The separate Merkle root explicitly
imports commitment-path, protocol, lazy/batched and allocation-failure cases.
The all-69-program native AIR parity root and standalone field comparison were
explicit behavioral tests already; they are unaffected by this discovery gap.

v53 authenticates each native AIR part and resolves its immutable mask-read
plan once per component phase, then shares the read-only prepared state across
joined row workers. Every tile still validates its own range; all owned sites
are released after joining, including setup failures. The native parity target
checks all 69 kernels across lifting/domain/additive scenarios, reuses one plan
across multiple disjoint tiles, rejects invalid ranges and rejects an instruction
mutation at kernel lookup. ReleaseFast product, native parity and focused
FFT/sampling/Merkle gates pass. Its paired result is 30.726 → 15.605 s proving (1.969×); see `sn2-cpu-native-paired-v53-summary.json`.


### CPU first 2× qualification and next experiments (v54–v57)

v54 admits row-level FFT scheduling whenever a large column group has fewer
columns than the pool has workers. The background preprocessor also borrows
an existing scoped pool where applicable. The current CPU CLI already uses a
shared global pool; the binding fix does not explain its performance. Three
pairs measure 30.744 → 15.512 s proving (1.982×).

v55 accumulates four M31 products before reduction in sampled polynomial
evaluation, using the existing bounded `dot4Packed` primitive. Focused sampling
and field tests pass, and all six canonical SN2 paired proofs preserve SHA-256
`ddf5b47bb928a75b699d0297b75fd0c3fb40ad6679f4ab26c32d2dfee9149545` and pass
the pinned official verifier. Three alternating pairs measure **30.473 →
14.847 s proving (2.053×)** and **32.812 → 17.168 s complete process (1.911×)**.
This qualifies the first 2× proving target, not a 2× complete-process target.
The product physical peak is 41.129 GB. Security remains plain BLAKE2s PCS,
70 queries and 26 PoW bits. See `sn2-cpu-native-paired-v55-summary.json`.

v56 tests reuse of public preprocessing coefficients and extended evaluations,
keyed on source content before in-place interpolation, product/protocol
identity, variant and shape. Full field/header/integrity validation precedes
any destination overwrite, so failed loads preserve the original FFT input.
Exact-work requests bypass reuse. The initial canonical SN2 trial is
15.871 s proving / 19.280 s process; the authenticated-hit trial is 14.373 /
16.720 s, with 40.726 GB product physical peak. All proofs preserve exact bytes
and official acceptance. The experiment uses an 8 GiB directory budget,
loads 7.304 GB on a hit, and does **not** establish a large speed improvement.
Preprocessing already overlaps witness generation; its saved CPU work need not
reduce the critical path. Consequently prepared-column reuse remains opt-in
(`STWO_CAIRO_PREPROCESSED_COLUMNS=1`, adequate budget required), with the default
2 GiB cache budget retained. Metal qualification is pending. Ordinary Pedersen
source and Merkle-layer reuse stay enabled by default.

v57 targets mixed-height Merkle leaf construction: feed lifted parity pairs
directly into four-message SIMD compression instead of packing row messages
and retransposing them. Both plain and domain-prefixed hashes must match
independent scalar messages at block boundaries and across lifting sizes.
Measurements and full CPU/Metal qualification are pending.


Focused core test discovery is also corrected in v57: rooting the old field/hash
targets through a named core import did not execute those embedded tests. The
explicit root now runs **47 hash tests and 15 M31 tests**, including the new
mixed-height differential oracle, packed/scalar arithmetic and edge cases.
The cache root runs 26 actual tests and the Merkle root 19. The captured test
logs accompany this note; earlier wrapper build statuses are not substitutes
for these behavioral checks. Two v57 canonical CPU proofs are accepted; its
warm SN2 observation is 14.286 s proving / 16.656 s process. This is not an
isolated or paired speedup claim.

v58 shares conservative typed field-shape facts between CPU and Metal code
generation, uses nine-product QM31 multiplication and canonical 32-bit addition
in the Metal composition artifact, and reduces canonical products with one
Mersenne fold. The protocol and trace ABI do not change. The authenticated
artifact has a new measured digest and length, recorded in
`metal-composition-v58-provenance.json`. No prior digest is treated as this
new artifact. The prepared-column experiment also defers cache writes until
GPU transform completion; exact-work audits bypass it. The default still
recomputes those prepared columns. CPU/Metal qualification is pending.


The new Metal v58 artifact qualifies two exact canonical SN2 proofs with zero
fallbacks. First use is **88.274 s proving / 91.504 s process**, including
**77.865 s** of GPU pipeline compilation and archive population. The subsequent
archive-hit observation is **9.585 s proving**, versus the v57 warm control's
10.358 s. Composition itself is 1.467 s versus roughly 2.111 s in the earlier
control profile. These individual observations are not paired medians; both
cold and warm receipts are retained in `sn2-metal-shapes-v58-summary.json`.

v59 prepares CPU traces directly in an owned source arena, using the same
frontend planner as Metal. In-place coefficient views must borrow arena
custody; the generic preparation owner now distinguishes that case from
individually allocated coefficient buffers. A dedicated allocator-backed test
covers freeing the arena once. Generic CPU frontend defaults remain unchanged.
Native C AIR kernels are now built as a shared static library so the CLI and
parity tests do not each compile all 69 generated files. Generator test fixtures
are moved outside the production metadata so fixing a test does not regenerate
all native C kernels. Both CPU trials qualify exact SN2 bytes with the official verifier; the initial trial is 15.855 s proving and the subsequent trial is 14.428 s. This is not an isolated paired speedup claim.


The v59 alternating Metal comparison retains all six qualified, exact SN2
proofs, with no unexpected backend fallbacks. Median proving changes
**10.631 → 10.380 s (1.024×)** and the full process **13.051 → 12.855 s**.
The composition stage median improves **2.132 → 1.514 s (1.408×)**, but other
stage variability means the whole prover improvement is much smaller than the
individual 9.585 s observation suggested. The paired receipt is
`sn2-metal-shapes-paired-v59-summary.json`; cold pipeline compilation remains
recorded separately in the v58 receipt. This does not qualify a second 2×.

v60 extends the existing trace arena to the actual witness writer: generated
columns borrow final placement before execution, their temporary allocation
is omitted, and lowering installs metadata without copying an identical
source and destination. Lookup and subcomponent feeds keep their separate
ownership and lifetimes. The optional observer callback applies to CPU and
Metal alike; missing placement preserves ordinary allocated outputs. Focused
allocation-failure, guard-region, geometry-rejection and owned-versus-borrowed
parity checks plus genuine proofs are pending.


### Final-column ownership and bounded sampling (v64–65)

SN2 profiles show whole-base-arena admission declines because a compact
consumer's distinct-key cardinality is unknown before execution. Thus v59/v60
SN2 proof acceptance did not exercise direct base-arena placement; interaction
arenas were active separately. v64 loans final component columns once each real
domain becomes known, so both arena-backed and ordinary fragmented commitments
avoid temporary witness outputs. Input sources with an existing immutable
column slab also lend it until all component workers join. Placement and
ownership reside in `proving/base_columns.zig`, shared by CPU and Metal.
Successful SN2 profiles show total generated-column lowering below 0.03 ms.

Both v64 backends qualify two canonical SN2 proofs with exact prior bytes.
Subsequent observations are **CPU 14.473 s proving / 16.792 s process** and
**Metal 9.833 s proving / 12.227 s process**, with pipeline caches retained.
These are individual observations, not an isolated paired claim.

v65 factors coefficient sampling into a shared 1,024-entry low basis and a high
basis, and multiplies an accumulated block result by its high factor. At log 24
this requires **272 KiB** instead of a full **256 MiB** basis per sampled point;
one point is processed at a time. SIMD column batches and independent ragged
columns use the exact same field identity. Explicit work capture retains its
existing counted schedule, so no unexecuted counters are reported. This targets
SN1/SN3's earlier approximately 21 s sampled-value stages. Qualification and
whole-proof measurements are pending.


The v65 complete matrix qualifies **60 exact, officially accepted proofs**
across all 15 workloads on CPU and Metal, with identical cross-backend proofs.
The complete per-trial identity, timings, cache and memory receipt is
`cairo-suite-both-v65-summary.json`. The public Cairo README records all eight
genuine PIE/backend observations, with all initial trials retained separately.
Focused native sampling and ownership executables ran **22** and **7** tests
respectively; their actual output is in `v65-sampling-tests.log` and
`v65-witness-storage-tests.log`.

SN1/SN3 CPU sampling still costs 17.909/21.555 s in the matrix: singleton
polynomial plans used the older iterative evaluator. v66 applies the exact
bounded factorization to those plans as well, reduces four terms per secure
coordinate with native SIMD (portable scalar fallback), and shares the linear
combination reducer with barycentric sampling. It also clears released scratch
owners before fallible growth allocations; a new failure-injection test
exercises both column-header and basis resizing. These changes are pending
focused qualification and targeted proof measurements. They do not qualify
the requested second 2× by themselves.


### Largest-PIE profiling and CPU storage policy (v66–67)

The user selected SN PIE 3 as the primary optimization workload. The v66
large-PIE subset qualifies eight exact, officially accepted CPU proofs. Its
subsequent SN3 observation is 64.496 s proving / 68.460 GB peak physical
footprint, including 19.380 s composition and 13.832 s sampling. The compact
receipt is `cairo-cpu-large-v66-summary.json`; these are observations, not an
isolated paired speedup claim. The requested second 2× on SN2 remains unqualified.

A separate SN3 diagnostic uses macOS `sample` at 10 ms for 35 s. Its raw
call graph and contaminated timing are retained under
`zig-out/cairo-completion-20260927/sn3-cpu-profile-v66`; those timings are
excluded from performance comparisons. Native AIR kernels and coefficient
sampling dominate active stacks. The product's 68.460 GB (63.76 GiB) physical footprint consumes nearly
all of this host's 64 GiB RAM before the operating system and other processes;
substantial system time accompanies the run.

v67 sets the CPU product to the existing committed-column sampling policy
already used by Metal. It does not change generic engine defaults, canonical
security, transcript, or proof representation. The first two officially
accepted, byte-identical SN3 trials take 26.698 / 25.681 s proving, with peak
physical footprint 50.248 GB. In the subsequent observation, composition is
2.902 s and sampling 1.760 s. An alternating three-pair comparison is pending;
these exploratory observations are not a paired qualification. Smaller PIEs
must also be checked before finalizing the product default.

v68 work removes row-proportional location maps from gathered witness inputs.
Small immutable source descriptors replace the full, remainder and padded row
maps; joined workers write their own final columns. Complete SIMD packs,
producer/instance ordering, remainder-pack fill, domain padding and selectors
retain their canonical semantics. This shared frontend path applies to CPU
and Metal. Independent ordering, allocation-failure and parallel parity checks
and genuine proof qualification are pending.


The v67 alternating comparison qualifies all six exact SN3 proofs. Median
proving falls **62.082 → 26.340 s (2.357×)** and the complete process
**66.435 → 30.647 s (2.168×)**. Peak product physical footprint falls
**68.461 → 50.248 GB**. The separate official verifier is excluded from both
prover timing scopes. The receipt is `sn3-cpu-retention-paired-v67-summary.json`.
This qualifies the further 2× for the newly selected largest-PIE workload;
it does not qualify that same target on SN2. Shared gathered-input changes
are still pending qualification and are excluded from this comparison.


The v68 focused target initially filtered out newly named gather tests. Its
filters now explicitly include the new final-storage cases and existing gather
cases. Running those tests exposed an old invalid geometry fixture: three
instances declared against a one-word producer row. The fixture now supplies
three real words per row; production admission remains strict. All three new
ordering, parallel parity and allocation-failure cases passed before this
fixture correction. Requalification is pending.


v68 qualifies **60 exact, officially accepted proofs** across all 15 Cairo
workloads on CPU and Metal, with exact cross-backend parity and no unexpected
Metal fallback. The complete compact receipt, including top-level stage
observations, is `cairo-suite-both-v68-summary.json`; complete stage trees remain
in the raw output directory. Both initial and subsequent trials are retained.
The explicit witness-storage executable runs **13 passing tests**, recorded
in `v68-witness-storage-tests.log`. This closes the pending gather qualification
and the earlier geometry-fixture correction.

Subsequent observations (not paired medians):

| Workload | Backend | Proving | Complete process | Product physical peak |
| --- | --- | ---: | ---: | ---: |
| SN PIE 1 | CPU | 25.715 s | 30.284 s | 51.143 GB |
| SN PIE 1 | Metal | 18.878 s | 23.553 s | 59.671 GB |
| SN PIE 2 | CPU | 15.251 s | 17.576 s | 29.383 GB |
| SN PIE 2 | Metal | 9.148 s | 11.520 s | 35.615 GB |
| SN PIE 3 | CPU | 26.823 s | 31.157 s | 50.248 GB |
| SN PIE 3 | Metal | 18.083 s | 22.539 s | 59.004 GB |
| SN PIE 4 | CPU | 19.850 s | 23.760 s | 40.911 GB |
| SN PIE 4 | Metal | 11.350 s | 15.314 s | 43.859 GB |

The SN3 CPU subsequent stage observations are 4.488 s base trace,
6.198 s main commitment, 2.299 s interaction generation, 5.708 s interaction
commitment, 3.241 s composition, 1.825 s sampling and 2.063 s FRI.
Metal observations are 4.058 s base trace, 4.005 s main commitment,
2.616 s interaction generation, 1.366 s interaction commitment,
2.547 s composition and 2.398 s FRI. Stages can overlap with preprocessing;
they should not be summed to manufacture an end-to-end measurement.

The paired 2.357× CPU SN3 gain belongs to the independently frozen v67
storage-policy comparison. The later v68 observations do not establish an
isolated whole-proof gain for gathering. Gathering's implementation removes
three row-sized maps and their construction/copying, preserves canonical
semantics, and applies to both backends. The requested additional 2× on SN2
still has not qualified: CPU SN2 remains around 15.3 s. Next optimization
work should retain SN3 as the main target and focus on trace commitment FFTs,
hashing, and witness construction, while continuing Metal qualification.


v69 profiles the CPU commitment interval and finds scalar BLAKE2s compression
in cached lifted prefixes dominating active samples. A bounded four-row SIMD
prefix cache now absorbs mixed-height tails without row-proportional state
allocation. All 21 focused Merkle tests pass, including independent scalar
comparisons across shard boundaries and both plain/prefixed hashing.

The serial SN3 CPU trials prove in 22.062 / 22.346 s, with complete processes
26.468 / 26.676 s and physical peaks 50.248 GB. Metal proves in 18.680 /
17.511 s, complete processes 23.026 / 22.059 s, physical peak 59.004 GB.
All four proofs preserve the exact prior SHA256 and pass the pinned official
verifier. These observations do not establish a paired speedup; Metal hashing
is already on the device and no isolated Metal gain is claimed. The earlier
interrupted CPU/Metal directories accidentally overlapped and are explicitly
excluded. Receipt: `sn3-four-row-prefix-v69-summary.json`.

The priority is now peak memory and Metal. v70 is implementing bounded
coefficient epochs while retaining one contiguous final evaluation arena.
GPU completion, parity checks and cache publication precede source/coefficient
release. Retained-coefficient policies preserve their existing lifetime.
Qualification is pending.


v70 passes five explicit preparation tests, including every allocation-failure
position for retained/unretained coefficients and adopted/fragmented sources,
and cache publication after device completion. The first two exact Metal SN3
proofs take 16.792 / 16.186 s. Their physical peak remains 59.004 GB.
Comparable host RSS also does not show a meaningful peak reduction; an earlier
RSS comparison was premature. No memory reduction is attributed to v70 alone.

v71 extends optional process-memory milestones to unbudgeted allocators and
the Cairo transaction. This identifies the global peak after the opening
handoff, in FRI. The segmented quotient has 19 batches × 16,777,216 rows ×
16 bytes = **5,100,273,664 bytes** of full-domain numerator scratch. Diagnostic
runs are excluded from timing comparisons; their milestone/shape observations
are in `sn3-memory-diagnosis-v71-summary.json`.

v72 retains the same source bindings and stable per-segment reduction order,
but reuses a row-tiled numerator buffer capped at 256 MiB (or one row for an
exceptionally large batch count). SN3 uses 524,288 rows, 159,383,552 bytes,
32 tiles. Global source lifting and output indices remain distinct from tile
scratch indices. All tiles encode in the existing GPU command, followed by
the unchanged FRI transaction. Detailed internal-parity diagnostics preserve
their full-domain numerator witness; ordinary production uses the bounded
path by default, across all supported hash families and workloads.

The two changed kernel declarations advance core shader ABI 25 → 26, with
regenerated declaration digests and the exact new source hash. Three old FRI
cascade test assertions assumed an inverse-cache hit for an ordinary
unbudgeted call. Current explicit-unbudgeted ownership intentionally releases
its inverses per transaction; the repeated call must regenerate them. The
assertions now check that policy while retaining exact root, transcript, fold
and opening comparisons. All 18 shader-authority/cascade tests pass (8 + 10),
including BLAKE2s and BLAKE3 quotient-FRI equivalence.

Three alternating SN3 Metal pairs qualify all six exact proofs. v69 → v72
median proving **18.663 → 16.873 s (1.106×)**; complete ZIP-to-proof process
**23.004 → 21.652 s (1.062×)**. Maximum product physical peak
**59.004 → 54.099 GB**, saving **4.905 GB / 8.31%**. CPU fallback count is zero
on all six runs. This comparison includes bounded LDE epochs and tiled FRI
scratch; it does not isolate either change's timing contribution. Receipt:
`sn3-metal-memory-paired-v72-summary.json`.

v73 additionally releases the synchronous Cairo composition session at the
evaluation return boundary, before commitments/openings/FRI. The final
transaction close remains idempotent and retains coverage counts. Allocation
failure and use-after-close custody have a focused test target. Final product
and complete workload-matrix qualification pass; the receipt is recorded below.


### Full CPU/Metal qualification after memory reductions (v73)

All 60 proofs across 15 workloads pass the pinned official verifier, preserve
exact CPU/Metal proof bytes and report zero runtime fallback. All initial
trials are retained. SN3 subsequent observations are 22.666 s CPU proving /
50.248 GB physical peak and 17.302 s Metal proving / 53.614 GB physical peak.
This matrix validates coverage; the v72 alternating pairs remain the causal
speed/memory receipt. Focused composition-lifetime and LDE preparation tests
pass 1/1 and 5/5 respectively. See `cairo-suite-both-v73-summary.json`,
`v73-lifetime-tests.log` and `v73-preparation-tests.log`.


### Bounded resident Merkle query storage (v74 candidate)

Metal now applies the host four-layer pruning policy to large commitments.
Completed trees copy only the retained upper layers into a smaller shared arena,
then release all old hash-layer/root aliases together. Resident column bindings
remain intact for AIR, quotient evaluation and gathered values. Large FRI
cascades also detach every small tail tree, since one remaining alias would
keep their old shared arena alive. Native publication follows a GPU join;
allocation refusal leaves the original tree usable. New temporary bytes are
admitted to the source owner budget; existing arena reservations remain
conservative until owner teardown.

One shared engine reader reconstructs bounded lower nodes for both host and
resident commitments. Focused tests pass for plain/prefixed BLAKE2s and BLAKE3
with mixed-height columns, exact roots, complete opening witnesses/auxiliary
values, allocation refusal and idempotence. All 14 focused Metal/FRI tests pass
(`v74-compact-tests.log`). Full Cairo measurement is pending; no memory or
speed improvement is attributed to this candidate yet.


The v74 three-pair SN3 comparison preserves all six exact official proofs and
reduces physical peak 53.624 → 50.669 GB (5.51%), but median proving increases
16.432 → 16.950 s and full process increases 20.925 → 21.682 s. Trace opening
reconstruction costs 0.212 s versus 0.018 s. This candidate is not promoted on
speed evidence (`sn3-metal-compact-paired-v74-summary.json`).

v75 uses the existing four-message lifted BLAKE2s primitive for bounded query
subtrees. Adjacent leaf/parent requests reuse each four-leaf result, and deeper
subtrees reduce SIMD leaf groups. The shared host reader benefits too; BLAKE3
retains its exact scalar reconstruction. Resident compaction refuses recipes
whose hash arena is pinned by their columns. All 21 shared Merkle tests and
both focused resident tests pass (`v75-merkle-tests.log`,
`v75-compact-tests.log`). The next paired run measures memory and time together.


The first v75 comparison retains the initial two public-cache misses: all six
proofs qualify, but its all-trial median is 16.557 → 16.956 s proving. It is
not a speedup receipt (`sn3-metal-four-way-query-paired-v75-summary.json`).
Five further alternating pairs, all with two public-cache hits and no miss,
measure 21.503 → 21.482 s full process and 16.877 → 16.946 s proving (+0.41%).
Peak physical footprint drops 53.628 → 50.669 GB (5.52%). This qualifies lower
memory with essentially unchanged steady-state time, not a speedup. The
earlier cold receipt remains included separately. See
`sn3-metal-four-way-query-warm-paired-v75-summary.json`.

v76 additionally caches each distinct queried lower subtree (at most sixteen
leaves) once per decommitment. Sorted sparse query blocks retain at most 32
hashes per query, and the original allocator extent is preserved through
compaction and teardown. Both host and resident readers use the same cache;
allocation-failure qualification and the full CPU/Metal matrix are pending.


### Full canonical qualification of bounded query reconstruction (v76)

All 60 proofs across 15 workloads pass the pinned official verifier, preserve
exact CPU/Metal proof equality, and report zero runtime fallback. All initial
trials and preprocessing costs are recorded. Largest-PIE observations vary
from earlier targeted runs; this matrix establishes coverage and latest
observations, not an isolated paired speedup. Final-version alternating
steady-state timing qualification follows separately.

All 21 shared Merkle tests and 5 focused compact-tree/query tests pass. The new
query-cache failure test injects every allocation failure while preserving
the original commitment and independently comparing complete opening bytes.
See `cairo-suite-both-v76-summary.json`, `v76-merkle-tests.log`, and
`v76-compact-tests.log`.


Final v76 steady-state comparison preserves all six exact official SN3 proofs
and reports no fallback. All six measured trials have two public-cache hits
and zero misses; both cache-population runs are retained in the receipt.
Physical peak is 53.629 → 50.669 GB (5.52% lower). Proving median is 16.125 → 16.200 s
(+0.46%), and complete process is 20.574 → 20.598 s. Timings are approximately
maintained; this is not a speedup qualification. See
`sn3-metal-query-subtree-warm-paired-v76-summary.json`.

The remaining larger memory problem is the 43.064 GB retained expanded trace
payload on SN3. It requires bounded polynomial/evaluation storage rather than
another scratch-buffer adjustment. GPU speed work also needs native-height
quotient aggregation on segmented inputs and whole-component witness/interaction
execution with efficient field arithmetic; current Metal witness and default
interaction generation still use CPU execution.


v77 implements bounded native-height reduction on the previously excluded
segmented quotient path. Geometry buckets span any number of source runs;
each serial GPU encoder adds native partials into a single planar owner.
Only short groups with at least eight contributions are selected, shortest
first, under a 256 MiB cap. Remaining contributions retain the bounded row-tile
path. The lift reads four weighted coordinate planes directly through one
descriptor, avoiding artificial scalar basis multiplications. Wide source
validation, checked reminting and command-lifetime owners remain authoritative.
Internal parity and exact-work capture retain their direct segmented contract;
no old direct-work ledger is published as evidence of reduced execution.
Core shader ABI is 27; current declaration digests and exact AOT source pin
are regenerated. Targeted tests are 22/22, including an actual 64 MiB mixed-height
GPU quotient against scalar computation across five source runs and two batches.

The SN3 three-pair receipt retains all six initial trials, including two public
cache misses on the first v77 run. All proofs are official accepted, byte
identical to CPU's qualified result, and have zero fallback. Quotient/FRI build
and commit median is 2.152331 → 0.553261 s (3.89×). Whole proving is
16.504106 → 15.469178 s (6.27% less time); complete process is
20.932903 → 20.097026 s (3.99% less time). Peak physical footprint is
50.668440 → 50.847599 GB (+0.35%). This is a speed qualification, not a memory
reduction; the preceding v76 memory saving remains largely preserved.
See `sn3-metal-native-segment-paired-v77-summary.json`,
`v77-focused-tests.log`, and `v77-products-build.log`.
The complete v77 Metal matrix now qualifies 30 new proofs across all 15
workloads, with official acceptance, zero fallback, and exact equality with
all recorded v76 CPU proof bytes. Unchanged CPU workloads were not rerun.
Latest subsequent Metal observations are SN1 15.390 s / 51.526 GB,
SN2 10.194 s / 32.198 GB, SN3 15.285 s / 50.848 GB, and
SN4 12.439 s / 40.435 GB (proving / peak physical footprint).
These observations are not isolated paired speedup claims; all initial trials
remain in `cairo-suite-metal-v77-summary.json`.

### v78: coefficient-backed Cairo experiment (not promoted)

Canonical SN PIE3 verifies with the unchanged proof digest and official Rust
verifier, using component-scoped expansion of only the AIR columns actually
read and immediate retirement of streamed BLAKE2s LDE batches. The new ownership
and failure tests pass (3 Cairo lease tests, 7 PCS tests).

The uninstrumented trial takes 44.00 s proving / 49.00 s process time with
49.958 GB peak physical footprint. This is slower than the qualified CPU path
and does not meaningfully reduce lifetime peak, so compact storage remains an
explicit experimental CPU option. A separate instrumented trial shows live
core memory around 23.700 GB, but the 49.958 GB peak is already reached during
witness/preprocessed overlap. Stage live memory is not a peak-memory result.

See `sn3-cpu-compact-polynomial-v78-summary.json` for both complete receipts,
product identities, timings, cache evidence and the diagnostic exclusion. The
next experiment removes whole-source detachment by keeping planned arena
custody across streamed batches and reconstructs openings more efficiently.

### v79–v84: compact Cairo storage qualification (experimental)

The shared CPU PCS now streams BLAKE2s LDE batches into compact coefficient
owners, can transform arena subcolumns in place without duplicating the whole
source, admits the existing authenticated fixed-tree cache before retirement,
and generates public source columns in bounded batches. Openings skip FFT
branches without requested outputs. Hybrid bounded quotients fold only compact
inputs; ordinary inputs retain the direct tile path. Sparse terminal columns
can continue through a full BLAKE2s block without expanding persistent hash
state to the final height. Two allocation-failure leaks at leaf/layer ownership
transfer were corrected.

Qualification executed 12 focused PCS tests and 5 Cairo lease/source tests,
including independent FFT and direct-query parity, parallel mixed inputs,
corrupt-cache refusal, hash-block spill, and every allocation-failure index.
The final CPU and Metal product build succeeds. Every recorded CPU proof in
these experiments is accepted by the official verifier and has the canonical
SN PIE3 proof digest.

The final same-binary CPU comparison alternates 3 pairs, keeps all initial
trials, disables prepared-column caching, and uses 70 queries / 26 PoW bits.
Ordinary versus fixed-only compact storage: **22.821 → 24.794 s** median
proving, **27.247 → 29.185 s** process, **50.320 → 48.080 GB** peak physical
footprint. The 4.45% peak reduction costs 8.65% proving time, so no default
changes. The separate all-compact observation is **32.099 s / 43.374 GB**;
its smaller footprint is not a speed-preserving result or a paired comparison.

Earlier experiments are recorded without promotion in the v78–v83 summaries.
The useful next step is native Metal coefficient retention and GPU
reconstruction/quotients; CPU reconstruction is currently the tradeoff. The
ordinary qualified products remain the default. See
`sn3-cpu-compact-storage-v84-summary.json` for complete receipts and identities.

### v85: direct implicit columns and earlier feed retirement

Shared CPU/Metal memory-table construction writes at final column addresses;
interaction/source ordering is a header permutation. Disjoint workers introduce
no private slabs. Both multiplicity passes have joined before subcomponent feed
retirement; separate lookup ownership lasts until interaction generation.
Collector allocation/failure custody passes 16 actual focused tests. CPU and
Metal final builds pass; frozen products are `direct-memory-cairo-products-v85`.

Three alternating pairs per backend retain all initial trials and preserve
canonical security, exact SN3 proof bytes and official acceptance. CPU median
proving is **22.605 → 23.150 s**, peak **50.248 → 50.302 GB**. Metal is
**14.779 → 14.929 s**, peak **50.848 → 50.848 GB**, with zero fallbacks.
The updated CPU product's first run has two public-cache misses. This is a
correct placement cleanup, **not a qualified memory or speed improvement**.
No coefficient storage policy has been promoted.

Eight additional single qualification proofs cover all opcodes, Fibonacci PIE,
all builtins at canonical security and SN1, each on CPU and Metal, with identical
proof bytes across backends. They do not replace the last complete suite matrix.

The separate memory diagnostic is officially accepted and excluded from timings:
composition-to-interpolation current footprint reaches **47.388 GB**, the
opening boundary has a **48.596 GB** lifetime peak, and completion reports
**50.847 GB**. AIR staging copies **41,161 MiB** in **652.846 ms**, with
177 dispatches/submissions and 796.647 ms measured device execution. The
expanded trace lifetime, rather than these implicit table temporaries, controls
the final peak. Next work must join native coefficient custody/alias retirement,
GPU AIR reconstruction, coefficient-folded quotients and selective openings.

`cairo-direct-memory-v85-summary.json` retains complete paired, diverse and
diagnostic receipts. `cairo-v85-witness-tests.log`, `cairo-v85-final-build.log`
and `cairo-v85-metal-memory-diagnostic.log` retain the executed evidence.

### v88: native compact Metal storage — memory saving, timing gate fails

Three alternating same-binary SN PIE 3 pairs, with canonical 70 queries and
26 PoW bits, compare ordinary against experimental compact storage. Median
proving is **17.349 → 39.650 s**, median process time **21.821 → 44.017 s**,
and maximum product physical footprint **50.849 → 41.303 GB**. All six proofs
are officially accepted, preserve the canonical proof bytes, and use no CPU
fallbacks. Physical footprint includes Metal allocations and covers the full
product process lifetime; GB uses decimal units.

The **18.77% memory reduction costs 2.285× proving time**. The requested
memory reduction without a timing regression is not achieved; compact storage
remains experimental and the default is unchanged. Contiguous FFT buffers and
reused AIR twiddles do not remove the reconstruction cost. Further optimization
is required before promotion. The current CPU SN3 comparison remains v85 at
23.150 s proving / 50.302 GB peak. SN2 and SN4 have not been rerun since the
last complete matrix.

See `sn3-metal-native-compact-paired-v88-summary.json` for the full receipt and
`cairo-native-compact-v88-assessment.json` for the explicit failed performance
gate. Actual focused qualification logs record 12 PCS, 6 Cairo lease, and
10 native Metal tests; CPU and Metal product builds pass.

### v89–v91: GPU coefficient folding and bounded no-copy reconstruction

The shared quotient planner now groups coefficient-basis reductions on Metal
using the existing native-height weighted reduction kernel, with checked zero
extension. Each group uses at most four bounded source runs per dispatch;
owned device allocations are admitted before construction and released after
the join. Source coefficients remain immutable. Native AIR, FRI coordinate
planes and query FFT scratch retain page-aligned owners with correct allocator
alignment at teardown. AIR request ordering preserves the contiguous domain
layout. Complete streaming plans identify terminal hash blocks before their
caller retires an LDE batch, avoiding redundant carry copies at known boundaries.

The v90 three-pair compact-versus-compact comparison qualifies **39.159 →
32.572 s** median proving (**16.82% reduction**), **43.528 → 36.879 s** process,
and **41.097 → 42.619 GB** maximum physical footprint. All six proofs pass the
official verifier with exact SN3 proof bytes and zero fallbacks. The first new
trial has two fixed-table cache misses; every other trial has two hits. Initial
trials remain included. No peak-memory improvement over prior compact storage
is claimed. This timing improvement does not pass the original requirement to
maintain ordinary-storage speed while reducing peak footprint.

The final v91 build additionally qualifies all 15 Cairo suite workloads, with
canonical 70-query/26-bit security, official acceptance, zero fallback and exact
proof-byte parity against the recorded ordinary full suite. Large-program
**single qualification trials**, isolated proving / lifetime physical peak:

| Benchmark | Experimental compact Metal time | Peak footprint |
|---|---:|---:|
| SN PIE 1 | 32.892 s | 41.716 GB |
| SN PIE 2 | 19.066 s | 21.968 GB |
| SN PIE 3 | 32.367 s | 41.097 GB |
| SN PIE 4 | 25.591 s | 32.210 GB |

These are not paired improvements over the older ordinary suite. Fifteen actual
native Metal tests include planned terminal/carry boundaries, immediate source
retirement, quota refusal, source immutability, mixed quotient inputs and
allocation-failure custody; twelve shared PCS tests and six Cairo lease/source
tests also pass. Full CPU and Metal product builds pass. Shader authority stays
at 234 exports / ABI 27; the reviewed core source digest is
`74061bdfca03753b626480f634dfc6b6c9c727887d65981c5dfbc3ff69dce95d`.

Receipts: `sn3-metal-native-fold-aligned-paired-v90-summary.json`,
`cairo-native-fold-aligned-v90-assessment.json`, and
`cairo-suite-metal-compact-v91-summary.json`. The initial v89 frozen product
was missing the VM adapter and failed before proving; that packaging failure
and the corrected single proof are retained in
`cairo-native-fold-v89-assessment.json`. Compact storage remains experimental.

The final v91 same-binary comparison alternates three ordinary/compact pairs.
All six canonical proofs are officially accepted with identical bytes and zero
fallbacks. Ordinary versus compact median proving is **15.194 → 33.221 s**,
process **19.616 → 37.580 s**, and maximum physical footprint
**50.848 → 41.303 GB**. This confirms an **18.77% peak reduction with a
2.187× proving slowdown**. The requested speed-preserving memory reduction
still fails; ordinary remains the default. The new ordinary timing is an
observation, not a paired improvement over the previously recorded ordinary
product. Final receipts: `sn3-metal-planned-storage-paired-v91-summary.json`
and `cairo-planned-storage-v91-assessment.json`.

### v92: joined multiplicities and dependency-aware witness feed retirement

This round adds an optional joined consumer to the witness graph. Each producer
routes fixed-table counts and accumulates memory counts before its subcomponent
words retire after the last consumer in the authoritative dependency plan.
Interaction lookup slabs retain separate ownership. The legacy batch path stays
the default; enable the qualified experiment with
`STWO_CAIRO_INCREMENTAL_MULTIPLICITIES=1`.

The shared memory-count initializer also closes partial allocation failures;
producer-list ownership transfers before fallible callbacks to prevent double
free on error. Four executed focused tests cover independent scalar and batch
count parity, public seeds and active/padded rows, all allocation failures and
ownership transfers, parallel collision/tail counts, final gathered consumers,
and independent lookup retention. CPU and Metal ReleaseFast products build.
The initially unregistered test step was fixed in the product catalog; its
failure receipt and the successful build/execution receipts are retained.

Canonical SN PIE 3, ordinary storage, same frozen binary, three alternating
pairs per backend (median isolated proving / maximum product lifetime physical
footprint in decimal GB):

| Backend | Batch counts, default | Incremental counts, opt-in |
| --- | ---: | ---: |
| CPU | 22.474831 s / 50.250257 GB | 22.641133 s / 50.247783 GB |
| Metal | 14.833441 s / 50.847452 GB | 14.589623 s / 50.847828 GB |

All 12 proofs are officially accepted and have exact SN3 proof-byte parity.
Metal has zero CPU fallbacks. Every initial trial is retained. The initial
Metal baseline has two fixed-table cache misses; later Metal trials have two
hits. The small mixed median differences establish no robust performance win.
Lifetime peak is unchanged: the speed-preserving memory gate remains unmet,
and the incremental policy stays opt-in. These measurements do not isolate a
speedup over older builds and do not establish CUDA device memory requirements.

The final opt-in Metal build qualifies all 15 pinned workloads against the
official verifier, with exact ordinary v77 proof parity and zero CPU fallbacks.
Single trials, isolated proving / product lifetime physical footprint:

| Workload | Time | Footprint |
| --- | ---: | ---: |
| SN PIE 1 | 17.313879 s | 51.525356 GB |
| SN PIE 2 | 11.092359 s | 32.198318 GB |
| SN PIE 3 | 15.574131 s | 50.847959 GB |
| SN PIE 4 | 12.713665 s | 40.435363 GB |
| All opcodes | 0.534677 s | 1.928415 GB |
| Fibonacci PIE | 0.575690 s | 1.880197 GB |
| All builtins, canonical | 4.678706 s | 12.757769 GB |

These are qualification observations, not paired speedup claims. Complete
receipts: `sn3-cpu-incremental-feed-paired-v92-summary.json`,
`sn3-metal-incremental-feed-paired-v92-summary.json`,
`cairo-suite-metal-incremental-feed-v92-summary.json`, and
`cairo-incremental-feed-v92-assessment.json`.

This round is complete; further optimization pauses at the user's request for
a discussion of GPU proving economics. The broader memory target remains
unfinished. The initial [GPU economics thesis](gpu-economics-thesis-v1.md)
compares lifetime reduction, bounded streaming, reconstruction and host backing.
It separates host footprint from VRAM, requires measured cost per accepted
proof under latency constraints, and makes no NVIDIA fit or timing claim.

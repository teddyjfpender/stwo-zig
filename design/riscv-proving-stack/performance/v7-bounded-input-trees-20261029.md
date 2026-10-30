# Bounded input trees for one original STARK

## Problem match and current limit

This is external-memory polynomial evaluation with transcript barriers, not a
smaller output-buffer problem. `pcs/scheme.zig` borrows every tree's full columns
into `LazyQuotientProvider`; its bounded row executor bounds denominator and
output scratch but keeps all input LDEs live. `scheme_views.zig:polynomials`
likewise exposes complete borrowed columns to composition, and
`commitment_tree.zig:decommit` obtains complete column slices and all Merkle
layers. The checkpoint codec currently reloads the whole tree. None of those
interfaces yet expresses a bounded, asynchronous input source.

The current heterogeneous prototype has nine trees: merged fixed, native
main/access, caller main/access, native interaction, caller arithmetic/fused
interaction, composition. It adopts private roots by leases. That preserves
meaning but is only a bounded pair; adding one tree set per segment would retain
an opening inventory proportional to segment count. External storage alone does
not fix that recursive cost. Repeated RAM/native families need a separately
admitted row-batched layout with explicit boundary and count constraints.

For the retained RAM census, seven log-22 cohorts contain 29,360,128 padded rows.
A single row-batched component requires log 25, or 33,554,432 rows: **14.3% more
cells**, while seven opened-column sets become one. This is a calculated shape
tradeoff, not a measured speedup. The current word quotient adapter expands all
228 fixed/main/interaction columns at once to four times the trace domain.
That is 14.25 GiB at log 22 and **114 GiB at log 25**. Restoring one component at
a time is insufficient for the row-batched shape.

## Smallest sound core interface

Keep existing in-memory APIs as the oracle. Add an opt-in immutable stored-tree
owner with independently pinned tree ordinal, column count/logs, Merkle height,
root, exact file length and byte cap. An index stores checked per-column LDE
spans and per-layer Merkle spans; readers use positional reads into explicitly
bounded buffers. It exposes:

- `readColumn(tree, column, allocator, byte_limit)`: one owning LDE or coefficient
  buffer, released before the next column. No owner contains borrowed pointers
  into another request's window.
- `readRows(tree, column, sorted_positions, output)`: exact lifted/bit-reversed
  coordinates, with bounded coalescing, checked offsets and canonical fields.
- `readMerkleNodes(tree, depth, sorted_indices, output)`: exact original layer
  ordering and hashes for query-only reopening.
- A typed original component access plan, derived from admitted equations,
  enumerates its exact global tree/column inputs, sample masks and constraint
  weight interval. Missing or duplicate dependencies fail before execution.

The stored bytes are untrusted witness material, not verifier authority. A
mutable file may cause proving to fail; it cannot change the pinned commitments
or accepted statement. A completed result still needs the unchanged independent
verifier. Exact cold/live shape and fixed roots come from original metadata,
never a received disk index. File ownership and whole disk quotas are explicit.

## Transcript-preserving passes

1. **Commit and spill.** Build each prechallenge and interaction column once,
   spill its LDE, construct the original lifted Merkle layers in bounded leaf
   stripes, and spill layers. Retain only roots, geometry and indexes. For a
   multi-column leaf, use the original incremental hash grammar in canonical
   column order; hashing a concatenation of column hashes changes the protocol
   and is forbidden. New fixed aggregation or row batching is independently
   versioned; storage alone changes no commitment.
2. **Composition.** After the original global composition challenge, restore one
   needed column, recover/extend it into a bounded FFT buffer and spill that
   component's quotient-domain column. Evaluate original equations by row tiles,
   gathering current/previous/Keccak `+27` positions exactly. Accumulate into the
   same QM31 domain buckets with the original global coefficient-power intervals
   (`DomainEvaluationAccumulator.initForComponent`). Do not reset random powers
   for each disk batch or substitute row repetition for polynomial extension.
   Once a component's contribution is accumulated, discard its expanded files.
   Retain bounded global buckets, or explicitly tile/spill those too.
3. **OODS.** After committing composition and drawing the OODS point, read one
   column at a time and evaluate every independently derived mask point. Preserve
   exact nested tree/column/sample ordering in the transcript. Coefficient
   evaluation can use bounded split bases; barycentric evaluation still requires
   two QM31 work vectors at the column domain unless further tiled. Release all
   wide owners before proceeding. This phase does not require Merkle layers.
4. **DEEP/FRI input.** After all OODS values are mixed and the original quotient
   challenge is drawn, stream each column's linear contribution into domain
   tiles or a few per-sample accumulator planes, using the existing quotient
   constants and exact pair-aligned lifting map. A tile-major strategy rereads
   column spans; a column-major strategy rereads/writes accumulator planes.
   Choose from measured I/O, not an assumption that lazy output removes inputs.
   Build the original FRI tree from the final quotient stream in the existing
   order; no transcript challenge is drawn until its complete root is known.
5. **Queries.** After FRI, PoW and query challenges, read only required column
   rows and Merkle siblings, deduplicate exactly as the original decommitter,
   then reorder queried values back to the original query order. Tall unsampled
   trees must retain the already-qualified zero-insertion query mapping.

No precomputed OODS values, resume digest or shortened source census is trusted.
All original physical LogUp claims remain mixed before interaction commitments;
global initialization, first-halt, interval, range, terminal and caller relations
remain independently closed after the final root.

## Budget and I/O model

Let `S` be all stored input LDE bytes, `S_Q` the expanded component columns,
`M` Merkle bytes and `A` the chosen QM31 accumulator planes. Excluding original
witness generation, the pipeline writes at least `S+M`, then reads input columns
for composition, OODS and DEEP; writes and reads each transient expanded column;
and finally performs query-only reads. A conservative initial traffic estimate
is **`4*S + 2*S_Q + M` plus accumulator/FFT spill traffic**, not zero-cost paging.
This includes one initial write and three full input-read passes; actual passes
must be instrumented. At 49.875 GiB LDE, that term alone is 199.5 GiB of traffic.
End-to-end time cannot beat physical storage bandwidth and may lose to bounded
RAM cohorts if repeated I/O dominates. Do not claim a disk-backed path is faster
until matched measurements establish it.

The memory target is the maximum simultaneous column FFT buffers, row-tile
inputs, quotient bucket/DEEP planes, twiddles and bounded Merkle frontier, plus
metadata, thread stacks and file-cache residency. At log-25 trace, one four-times
expanded M31 column is 512 MiB; recovery may require a second buffer. A full
QM31 plane at that expanded domain is 2 GiB. These sizes are feasible individually
on 64 GiB, but concurrency must be selected from the complete aggregate budget.
OS page cache and RSS are measured separately; mmap is not a zero-memory claim.

A useful disk-backed implementation order is indexed checkpoint/query-only reopening,
then column-wise OODS, then component/tile composition, then streamed DEEP accumulation.
Each seam first compares original proof bytes on heterogeneous logs/masks and
rejects malformed spans, wrong column identity, duplicates, truncated files,
changed query bits and insufficient aggregate budgets. Only then qualify one
complete detached root. Row batching is a subsequent explicit admitted-shape
change: the core spill machinery alone does not prove its boundaries or reduce
its recursive verifier inventory.

Status: source-grounded design only. No stored-input core path or row-batched
RAM proof is implemented or qualified by this document.

## Canonical caller admission model versus allocation phases

The canonical q70/PoW26 cold probe of one caller (original index 2) completed its
compiler and produced these dimensions: fixed rows 934,746,812 bytes, retained
rows 3,897,202,364 bytes, 1,782,593,536 committed cells, largest row log 21.
The current conservative model adds:

| Model term | Bytes |
|---|---:|
| Joining: `2*retained + fixed` | 8,729,151,540 |
| PCS: `4*cells*(2^blowup + 2)` | 28,521,496,576 |
| Merkle estimate | 1,073,741,824 |
| Composition estimate | 1,073,741,824 |
| Fixed scratch allowance | 536,870,912 |
| Total | 39,935,002,676 |

This exceeds the default 24 GiB window admission; it does not show a measured
39.94 GB allocation peak. `blake3_native_parent_producer.zig` and
`blake3_parent_fixed_key_v1.zig` select compact polynomial storage at extended log
20 on CPU. Large columns retain base coefficients and discard extended values;
small columns keep their LDE. The model instead charges all columns for both
full LDE and two base-sized copies. Cold fixed rows are also freed before the
proof starts, while a shared lease preserves the single fixed commitment. The
joining maximum and PCS maximum therefore need not overlap. Conversely, the
bounded producer calls the nonconsuming `Plan.prove`, so live source rows remain
throughout proof generation; their memory cannot be subtracted.

A replacement model must independently census column sizes above/below the
compact threshold and take the maximum of cold compilation, live/cold join,
fixed commitment, main commitment, interaction generation, interaction commit,
composition and OODS/FRI phases. Include compact-commit batch scratch, actual
shared fixed ownership, retained source rows, per-component quotient expansion,
thread reservations and charged sampled-value workspaces. Phase observations
must distinguish child and outer allocation counters and process RSS. No model
limit has been lowered on this analysis alone. Raising an explicit diagnostic
window cap under the unchanged whole-source cap is a qualification experiment,
not a change to production default admission.

## Reuse existing coefficient-to-tile evaluation first

The repository already has `pcs/tiled_commit.zig` and
`poly/circle/coset_blocks.zig`. Their bounded tile/group buffers evaluate exact
conjugate coset blocks from coefficient owners; existing tests compare every
value and original Merkle roots. Reusing this machinery for the word quotient
kernel is a smaller first experiment than adding disk-expanded columns. At
log-25 trace, all 228 base coefficient columns occupy 28.5 GiB, versus 114 GiB
of expanded columns. Existing coefficient views can be borrowed; absent views
require interpolation of the entire committed LDE and a zero high-tail check.
The source LDE remains live until its own owner is released, so recovery does
not by itself erase its footprint.

Word previous-row masks are nonlocal in bit-reversed storage. The tiled kernel
must gather `previousBitReversedCircleDomainIndex(global_row, trace_log, eval_log)`
from exact prior coset blocks, not use the previous local row or wrap within a
tile. Separate bounded prior-block/group caches avoid repeatedly overwriting the
current block and must account for their total prefold buffers. Vanishing values
still select the original global coset, and accumulator powers still come from
the original global constraint schedule. The opt-in prototype should preserve
the whole-domain path as a complete original-proof byte oracle and reject
insufficient scratch limits before partial output mutation.

This approach can eliminate expanded-column scratch without changing AIR or
transcript. It cannot alone guarantee the full heterogeneous block fits: the
coefficient owners, other live commitments, output buckets, shared resources and
metadata still count. If that resident set exceeds the aggregate budget, the
indexed stored-input design above remains necessary.

## Qualified one-shot row consumption

The v7 complete producer, bounded direct windows and final batch reduction now
call `Plan.proveConsuming`, retaining the same independently admitted metadata
and public frames. Each recursive source cohort is freed after its interaction
last reader. The PCS borrowed-source commit has already duplicated its input
into independently owned coefficients/LDEs; compact arena borrowing explicitly
excludes that borrowed-input path. Idempotent `Prepared.deinit` remains valid.

The matched 17-original diagnostic fixture passed all 12 tests with exactly the
same 148,535-byte final root (SHA256
`bbf199bdd0bca568fe6ec0737442cdf99aaec45f43b7f595e68aaccb7477c9ca`). Whole charged
peak fell 4,923,049,866 to 3,912,504,450 bytes (20.53%); process maximum RSS fell
4,964,941,824 to 3,954,327,552 bytes (20.35%). The caller-containing window fell
4,895,419,112 to 3,884,873,632 charged bytes, and reduction fell 4,122,925,848 to
3,131,635,684. The adjacent consuming-parent JSON preserves every stage/window,
log and binary digest. Timings are unranked: other canonical work and compilation
ran concurrently. The earlier canonical caller measurement used nonconsuming
rows; do not apply these percentages to it without qualification.

## Opt-in exact RAM quotient tiles: measured qualification

`block_v7_word_quotient_tiles_v1.zig` now evaluates the existing packed RAM
quotient from coefficient-backed coset tiles. The API accepts only the original
RAM `Spec`; other word families and every default producer retain the old path.
`block_v5_word_pcs_v1.proveWithDomainOptions` is the explicit opt-in. This changes
storage and evaluation, with no changed AIR, statement or transcript.

The original complete-proof differential gate passed at trace logs 5 and 13.
At each size it compares four proofs: old/tiled quotient, each with retained
coefficients and with exact interpolation of committed LDEs. All proof bytes
match, and each proof passes the original fresh verifier. The tiny proof is
17,978 bytes; the medium proof is 38,737 bytes. A one-byte workspace allowance
fails explicitly. Exhaustive small-domain predecessor checks cover every
nonlocal circle predecessor, including mappings across tile boundaries.

| Log-13 mode | Old helper peak | Tiled helper peak | Tiled workspace | Diagnostic proof time, old → tiled |
|---|---:|---:|---:|---:|
| Retained coefficients | 56,371,600 B | 56,097,672 B | 3,991,496 B | 149.33 → 170.10 ms |
| Recovered coefficients | 48,895,024 B | 48,620,208 B | 11,462,600 B | 178.90 → 220.92 ms |

The helper peak covers commitment, proof and fresh verification/capture, but
excludes the externally prepared witness and interaction matrices. The tile
workspace includes temporary recovered coefficients and current/previous tile
caches, but excludes borrowed input trees and the output accumulator. Recovery
accounts for 7,471,104 bytes of the medium workspace. The original log-13 full
quotient expansion is 29,884,416 bytes (228 columns × 32,768 rows × four bytes).
Other phases dominate the measured helper peak, so **the observed whole-helper
memory improvement is below one percent**, and this version is slower on these
small fixtures. These results qualify a bounded storage mechanism, not a speed
improvement or whole-block memory bound. Timings were not isolated from other
engineering work. The default remains unchanged.

The next useful evaluation is the largest genuine cohort with its full phase
census, where expanded quotient inputs would otherwise set the peak. That test
must include retained source commitments and output buckets in the aggregate
budget. Parallel tile row evaluation and reducing repeated previous-block
transforms are implementation opportunities, but should follow that census.
Exact measurements and log digests are in
`v7-word-quotient-tiles-qualification-20261029.json`.

### Larger log-18 cohort and parallel tiles

The next gate uses 262,145 additional real RAM transitions, producing a single
log-18 cohort. Both original and tiled paths use an explicit four-worker pool.
Tile AIR rows now use a bounded worker lease and disjoint pack-aligned global
row ranges; the original per-row equations, random powers and fresh-accumulator
cursor are preserved. FFTs and prefolds already use the shared pool. All four
original proof variants again match byte for byte (62,879 bytes) and freshly
verify, including exact coefficient recovery and low-budget rejection.

| Log-18 mode | Old helper peak | Tiled helper peak | Quotient time old → tiled | Whole proof time old → tiled |
|---|---:|---:|---:|---:|
| Retained coefficients | 1,802,546,472 B | 970,434,368 B | 1.289 → 1.325 s | 1.707 → 1.737 s |
| Recovered coefficients | 1,563,465,672 B | 970,428,896 B | 1.538 → 2.154 s | 2.057 → 2.670 s |

This is a **46.16% / 37.93% tracked helper peak reduction**, respectively.
The tiled retained workspace peaks at 128,387,032 bytes versus 956,301,312 bytes
of whole-domain expanded quotient inputs. Recovery raises the tiled workspace
to 367,462,360 bytes, of which 239,075,328 bytes are recovered base coefficients.
The complete four-case test process peaks at 2,497,232,896 bytes RSS, with no
swaps. That process peak also includes raw source matrices and the independently
staged original commitments retained by the fixture, so it is not a per-case
RSS measurement and must not be substituted for the helper's bounded scope.

The first recovered variant above redundantly rebuilt identical interpolation
twiddles per column. The final implementation shares one exact canonical
interpolation twiddle tree across recovery and frees it before tile allocation.
The follow-up gate passes both the complete original-proof differential and an
explicit hostile high-degree recovery test. That negative leaves the quotient
output unallocated and the random-power cursor unchanged.

The final same-binary diagnostic retained pair takes **1.659 → 1.716 s** for
proof execution, with **1.258 → 1.273 s** inside quotient evaluation. Recovery
takes **2.006 → 2.062 s**, with **1.519 → 1.577 s** in the quotient. Tracked helper
peaks are unchanged from the table: 46.16% and 37.93% lower, respectively. All
four 62,879-byte proofs have SHA-256
`847d7b28a2686f0548ab0c6cf69fa4310043bd9c8af9cff0a46feb5651b0cd9d`.
Final process RSS is 2,497,036,288 bytes with zero swaps. The final test reports
PASS2; the full source and result receipt includes exact log and binary digests.
These diagnostic timings may overlap compiler work and do not establish a
controlled speed comparison. That initial experiment retained the original production default; the later
qualified rollout below changes only the v7 RAM paths. No whole-block speed
claim follows.

## Production RAM policy and complete canonical qualification

The v7 memory cohort and joint-memory producers now select the bounded RAM
kernel automatically at trace log 18 and above. Components below log 18 keep
the original evaluator. The explicit override is
`ram_quotient = .whole_domain` in either producer's `Limits`. Generic WordPCS
and all non-RAM component defaults are unchanged. The streaming execution
options already forward these limits, and the complete union producer carries
the same setting into its mapped original RAM components. Its verifier always
uses the original point equations and does not receive the storage policy.

The policy uses log-15 row tiles below log 22 and for any recovered/mixed
coefficient input. Fully retained input at log 22+ prefers log-18 row tiles,
shrinking the preference before allocation when the request cap is smaller.
The prefold cache targets are 32 MiB prefold caches at log 18, 64 MiB at
log 19, 128 MiB at log 20, 512 MiB at log 21, and a 1 GiB target at
log 22 and above. The shared tile planner chooses the least coefficient-read
shape within each target; it does not reserve all that space. Scratch is capped
at 4 GiB and clamped
to the enclosing request cap. All input commitments, raw witnesses, output
accumulators and other components still count against that enclosing cap.
Insufficient storage fails; it does not silently retry the full expansion.
Selection and cap unit tests cover the threshold, all cache sizes, explicit
whole-domain override, invalid configuration and smaller request limits.

A genuine **20,495-cycle complete union proof at 70 queries and 26 PoW bits**
passes after all producer owners are destroyed, with complete global closure
and hostile-input checks. The test explicitly forces tiling for its three
smaller RAM components to exercise the actual mapped production route. Its
5,841,554-byte proof is identical to the saved untiled canonical proof, SHA-256
`62f94cd2d70b5f3eba3aae3196047dbc9175957ca7f5daaedc9db9196f338efb`.
Public metadata and guest ELF are also byte-identical. This is the finite
one-window complete proof, not an Ethereum block throughput measurement.

A separate canonical-security spill-cohort gate compares five restored tiled
RAM proofs with the untiled in-memory originals, checks the three shared
providers, destroys the producer, then freshly verifies the bundle. Proof
bytes agree and reordered cohorts or changed physical claims reject. Its
105.79-second test duration includes both proof sets and repeated PoW; it is
qualification overhead, not one production memory-proof latency.

The log-20 boundary experiment contains 1,048,576 additional real transitions.
The final cache choice retains most of the memory saving without the initial
32 MiB-cache time penalty:

| Log-20 mode | Untiled helper peak | Tiled helper peak | Proof time, untiled → tiled |
|---|---:|---:|---:|
| Retained coefficients | 6,832,565,912 B | 3,326,121,864 B | 6.920 → 7.092 s |
| Restored coefficients | 5,876,259,128 B | 3,304,035,520 B | 8.344 → 8.635 s |

Those are **51.32% and 43.77% lower helper peaks**, with diagnostic time
increases of about 2.5% and 3.5%. Every 70,451-byte original proof agrees with
SHA-256 `058621d8089c3ec3175efce731cf4e2e2205b6420d65411ee5ad1a50b1466216`
and passes the original fresh verifier. The retained/recovered pair process
peaks are 9.279 GB / 8.323 GB RSS because the test also holds the original
staged witnesses and commitments; neither value is a tiled-only RSS result.
These tests use diagnostic q8/PoW0 security; canonical qualification is the
complete union and spill-cohort evidence above. The log-22 retained-coefficient boundary is now qualified below. Exact receipts
and artifact references are
in `v7-ram-tile-production-qualification-20261029.json`.

## Log-22 boundary and measured attribution

The 4,194,304-extra-transition case produces the same 85,955-byte original
proof, SHA-256
`4c0030e6d3769e5ab23d05c5786d35d307688f7fabfb30084f802135f5135521`.
Both untiled and tiled proofs freshly verify. The helper peak falls from
27,330,129,928 to 13,304,371,208 bytes (51.32%). The old-plus-new process peaks
at 37.04 GB RSS, including independently retained raw fixtures and source
commitments. No swaps were reported. This is a diagnostic q8/PoW0 proof, not
a complete block or a canonical-security scaling result.

This boundary exposed a time regression: with a 128 MiB cache target, proof
time was 29.294 → 41.183 seconds. Raising the target to 1 GiB barely helped:
29.049 → 40.848 seconds. The actual scratch increased only from 444.5 to
564.1 MB. This falsifies the hypothesis that merely increasing cache capacity
would restore the old speed. At this geometry, the two-stage planner selects
group log 3 to minimize total coefficient reads; a larger target does not
change that optimum.

An opt-in phase profile then reproduced the exact control SHA and verified
the original proof without regenerating the old control. It measured:

| Tiled quotient phase | Wall time |
|---|---:|
| Current-column preparation and prefolding | 4.010 s |
| Current-column block folding and FFT jobs | 4.241 s |
| Prior-column preparation and prefolding | 4.551 s |
| Prior-column block folding and FFT jobs | 4.495 s |
| Packed original AIR evaluation | 12.405 s |
| Previous-row tile mapping | 0.034 s |
| Complete quotient | 29.845 s |

The load paths read 128.3 billion base-field elements during prefolding and
64.2 billion during block folding, then transform 8.02 billion elements.
Worker CPU clocks are retained separately in the JSON receipt; they must not
be added to wall-clock phases. The profiled proof takes 36.368 seconds and
tiled-only process RSS is 23.013 GB. These runs have host/run variability and
profiling overhead; they establish attribution, not a controlled speedup.

The next bounded experiment increases row-tile width so fewer complete
coefficient scans are needed. The 4 GiB aggregate scratch cap remains in force.
Recovered coefficients must reduce any wider working set to available space;
no buffer may escape the request budget.

### Wider retained-coefficient tiles remove the boundary time penalty

The phase-guided log-18 tile experiment passes all five focused tests, freshly
verifies the original log-22 proof, and matches the exact saved 85,955-byte
control SHA. It reduces prefold reads from 128.3 to 32.1 billion elements and
block-fold reads from 64.2 to 32.1 billion; the number of transformed elements
and original AIR equations is unchanged.

| Log-22 mode | Proof time | Quotient time | Helper peak |
|---|---:|---:|---:|
| Original whole-domain control | 29.049 s | 22.492 s | 27,330,129,928 B |
| Tiled log15, phase profile | 36.368 s | 29.845 s | 13,304,371,208 B |
| Tiled log18, phase profile | 27.914 s | 21.315 s | 14,469,455,088 B |

These are separate diagnostic runs, not a ranked timing comparison. The wider
tiles retain a **47.06% lower helper peak** than the whole-domain control and
remove the observed time penalty. Their actual scratch is 2,507,258,536 bytes,
inside the same 4 GiB cap. The extra memory is explicit: wider blocks and
prefolds trade about 1.17 GB of helper peak for 8.45 seconds in this profiled
proof. Whole-process RSS, including the independent fixtures, is recorded
separately in the JSON receipt.

The production policy now makes this preference only for fully retained
coefficients at log 22+. Mixed/recovered sources retain smaller tiles and
cannot accidentally allocate a large tile alongside recovered coefficients.
A pure planner clamps the preference using the actual child cap before
allocation; hostile/low-cap gates cover this boundary. The hard aggregate
allocator and all original degree checks remain authoritative.

### Composition with coefficient-backed input PCS storage

The same log-22 workload now qualifies the actual compact-input API together
with the adaptive tiled evaluator. Fixed and main trees retain native-degree
coefficients and their Merkle commitments; their expanded LDE buffers are
released. Interaction coefficients remain retained in this measurement, as
in the Joint path. The currently restored Cohort path can instead recover
interaction coefficients; that mixed mode passes the small differential gate
but has not been timed at log 22.

The complete compact/tiled original proof freshly verifies and matches the
same 85,955-byte control hash. Its helper peak is **10,711,356,016 bytes**,
60.81% below the original 27,330,129,928-byte whole-domain control. Relative to
resident tile18, the measured saving is **3,758,099,072 bytes**. The 112 released
input LDE columns account for 3,758,096,384 bytes; the remaining 2,688-byte
difference is small allocation bookkeeping/live-state variation. Quotient
scratch remains 2,507,258,536 bytes.

Diagnostic time is 30.585 seconds proving, 22.633 seconds quotient evaluation,
5.901 seconds initial commitment, and 1.008 seconds fresh verification. The
resident tile18 run measured 27.914/21.315/3.281/0.985 seconds respectively.
Those are separate runs; the compact path's extra preparation cost is reported
rather than hidden or described as a speedup. Process RSS is 20,419,264,512
bytes with zero swaps and includes externally retained source fixtures and
the final negative low-budget attempt. It is not the compact helper budget.

Both compact and noncompact small differential suites pass six tests,
including mixed interaction recovery, degree rejection, policy boundaries
and cap checks. The additional arithmetic-overflow boundary gate passes.
The large run qualifies the original RAM STARK only; it does not imply a
canonical-security whole-block or full-root throughput result.

## Next measured target: base-field RAM equation specialization

The log22 profile attributes about 12.3 seconds to packed AIR rows after the
coefficient-loading improvement. The 161 canonical RAM equations split into
132 direct equations over base-field trace cells and public base constants,
plus 29 LogUp equations requiring extension-field challenges. Currently both
sets use the generic packed extension-field evaluator.

The problem match is mixed base/extension arithmetic, not a new memory AIR.
The proposed implementation factors the unchanged direct equation body into
one generic authority, evaluates those 132 equations in packed M31, then
multiplies their results by the original QM31 random powers. The remaining
29 interaction equations retain their existing authority and ordering.
Public endpoint/halt constants are prepared once; non-base halt constants
must fail the specialized admission rather than silently dropping limbs.

Qualification requires randomized per-equation comparisons with the original
packed and scalar evaluators, non-base-constant rejection, and the saved
complete original proof hash under fresh verification. Storage remains within
the existing tile budget. Any speed gain is unmeasured until that gate and a
new phase profile pass. Original scalar/recursive equation behavior is kept.

### Packed base-field result

The opt-in specialization passes the six focused gates, including randomized
per-equation and folded-result equality across first/middle/last cohort public
flags, non-base halt rejection, retained/recovered proofs, and all-tree compact
small proofs. The large log22 proof freshly verifies and exactly matches the
original control SHA. Its 132 direct equations remain the same generic source
used by scalar/recursive evaluation; only real-domain arithmetic storage is
specialized.

| Resident log22 tile18 | Generic QM31 rows | Base-specialized rows |
|---|---:|---:|
| AIR row wall time | 12.283 s | 8.343 s |
| Quotient wall time | 21.315 s | 17.257 s |
| Complete proof execution | 27.914 s | 23.780 s |
| Tracked helper peak | 14,469,455,088 B | 14,469,455,088 B |

This is a 32.1% reduction in the measured row phase and 14.8% in diagnostic
proof time, with unchanged storage. It is a separate-run comparison, not a
ranked measurement. Relative to the earlier original whole-domain control,
the specialized tiled proof is about 18.1% faster and uses 47.06% less tracked
helper memory. Canonical complete-union qualification is required before
enabling this specialization in the v7 production policy.

The subsequent canonical q70/PoW26 complete-union gate passes all 11 tests
with base-field rows active on the actual mapped RAM components. Its proof,
public metadata, and ELF remain byte-identical to the archived 20,495-cycle
control. The v7 bounded-RAM policy now enables this specialization; generic
WordPCS and generic tile options keep their original defaults. The fresh
default-policy small gate passes six tests, including scalar-lane comparisons
in addition to packed and base-vector comparisons. Raw result logs are
retained in `vectors/reports/block-v7-ram-quotient-20261029/`.

This specialization is used only for real-domain M31 trace evaluations.
Public halt constants must first convert exactly to M31; endpoint constants
are already base-field values. OODS point evaluation and recursive equation
recording continue to use the original generic extension-field equations.
Consequently no extension-field coordinate is discarded from a sampled proof
value or from a verifier equation.

### All three input trees compact, with measured phase residency

The final log22 original RAM gate also compacts interaction LDE storage after
its original commitment, retains all native coefficients, and disables the
storage setting before the composition commit. It uses the default adaptive
tile/base-row policy. All six tests pass; the complete original proof freshly
verifies and again matches SHA-256
`4c0030e6d3769e5ab23d05c5786d35d307688f7fabfb30084f802135f5135521`.

| Quantity | Resident input trees | All three input trees compact |
|---|---:|---:|
| Live after fixed/main commitment | 5,754,596,720 B | 1,996,497,648 B |
| Live after interaction, before core proof | 11,626,633,248 B | 3,976,217,280 B |
| Helper proof peak | 14,469,455,088 B | 6,819,039,120 B |

The resident column uses the same tiled/base-row path; the earlier original
whole-domain helper peak was 27,330,129,928 bytes. Thus the composed storage
and evaluation changes reduce that original peak by **75.05%**. The live
figures are actual observations of the same allocation scope. They exclude
raw witness matrices and independent fixture source commitments. They must
not be replaced by, or confused with, multiplying an entire proof peak by
the number of cohorts.

Diagnostic initial commitment takes 5.704 seconds, proof execution 29.258
seconds, quotient evaluation 18.387 seconds, and fresh verification 0.979
seconds. The original whole-domain proof was 29.049 seconds, so this run
retains approximately the original proof latency while using a quarter of
its tracked peak. Preparation is still more expensive than the original
~3.3-second commitment; this cost is reported separately and is not hidden
outside an end-to-end claim. Timings are separate-run diagnostics.

Process RSS is 18,013,782,016 bytes, with zero swaps. That process also holds
the raw/staged fixtures and executes a final intentionally noncompact
low-budget negative attempt; it is not a compact-only production RSS figure.
The quotient's own scratch remains 2,507,258,536 bytes under its 4 GiB limit.
This result qualifies one original RAM proof at q8/PoW0. The canonical
complete-union and consuming-source gates establish their own, separately
recorded scopes; no full Ethereum-block timing is inferred from this case.

## Selected openings investigation

Compact CPU commitments currently reopen coefficient-backed columns using the
backend's full LDE transform in bounded batches. The core already has a
query-position-selected transform used by its portable opening path. The
problem match is avoiding recomputation of unrequested FFT outputs, with the
same coefficients, exact lifted query mapping, retained Merkle hashes and
ordinary verifier. This is an execution policy, not a transcript change.

The investigation first attributes compact opening time separately from
quotient and commitment work. If beneficial, a CPU `configured` option will
select the existing position-aware evaluator without mutating shared trees
or changing generic/backend defaults. Small tests must compare full and
selected queried values, hashes and auxiliary data for duplicates, reordered
queries, mixed column heights and padded leaf reconstruction. Only then may
a large original-proof hash/verification gate support adoption.

## Compact overhead attribution: selected openings already exist

The proposed CPU opening-path change was unnecessary. In
`src/prover/pcs/commitment_tree.zig`, compact host Merkle trees call
`coefficient_opening.decommit`, whose backend is `void` and whose evaluator
reconstructs selected leaves. The full native-FFT backend branch is a different
representation. No selected-opening policy or replacement was added.

An opt-in opening phase timer and an optional core stage recorder were added.
The ordinary WordPCS API delegates with a null recorder and preserves its
ownership transfer. Two sequential runs of the same focused log20 binary gave:

| Phase | Resident retained coefficients | All three input trees compact |
|---|---:|---:|
| Initial two commitments | 0.764 s | 0.990 s |
| Interaction commitment | 0.730 s | 1.040 s |
| RAM quotient evaluation | 4.723 s | 4.704 s |
| Composition interpolation + commitment | 0.167 s | 0.168 s |
| OODS sampled evaluation | 0.078 s | 0.156 s |
| Lazy DEEP quotient + FRI commitment | 0.542 s | 0.638 s |
| Trace decommitment | 0.00694 s | 0.257 s |
| Interaction commitment through returned proof | 6.310 s | 7.028 s |
| Charged proof-helper peak | 3,326,122,520 B | 1,589,661,136 B |

All six focused tests passed in each run. Both produced the same 70,451-byte
proof, SHA256 `058621d8089c3ec3175efce731cf4e2e2205b6420d65411ee5ad1a50b1466216`,
and passed ordinary verification. These are diagnostic attribution numbers,
not ranked performance measurements or a whole-block forecast.

About 0.310 s of the 0.718 s compact proof difference occurs during interaction
commitment; 0.250 s is selected opening reconstruction; 0.078 s is sampled
polynomial evaluation; and 0.096 s is DEEP/FRI. The quotient itself is unchanged.
The compact path uses incremental Merkle leaf state across bounded column
batches (`tree_builders.zig` / `streaming_committer.zig`), whereas the resident
path retains LDEs for whole-tree hashing. `ColumnEvaluation.validate()` only
checks geometry, so a hypothesized full canonicality scan during compaction
is not the cause. The exact internal commitment split remains to be measured
before selecting a hashing change.

The selected-opening profile covers 24 fixed, 88 main and 116 interaction
columns, eight queries and 128 leaf positions. In the paired compact run those
three openings took 0.0339, 0.0966 and 0.1235 s. This is useful but does not
justify a new CPU opening architecture on its own. Raw logs and phase JSON are
retained in `vectors/reports/block-v7-ram-quotient-20261029/` and the existing
production qualification receipt under `log20_core_attribution`.

A separate, explicitly unimplemented geometry design examines degree-four
triple range batches: `v7-ram-logup-batching-design-20261029.md` and its JSON
model. It identifies 116→84 interaction columns while preserving the existing
quotient degree, and lists the necessary new protocol identity, every physical
claim and recursive public-offset migration. It must not be confused with the
byte-preserving evaluator optimizations already qualified here.

## Exact range-pair factoring, first measured gate

The next finite evaluator optimization factors the **existing pair** residuals;
it does not implement triple batching or alter RAM's 29 physical claims. With
positive request weights `w0,w1`, its original residual is exactly:

```
delta * (A²*x0*x1 - A*z*(x0+x1) + z²)
  + A*(w0*x1+w1*x0) - z*(w0+w1)
```

The sign follows the original negative range-request terms. On real-domain
rows, `x` and `w` are base-field values; `A` and `z` remain arbitrary actual
secure challenges. Cached `A²`, `A*z`, `z²` and secure-by-base operations replace
repeated general extension-field products. No division, nonzero challenge
assumption or `A=1` assumption is used. OODS and recursive equations keep the
original general-field evaluator. Shared extraction of the original primary
terms and range inventory prevents a second enumeration of lookup requests.

Focused all161-equation and folded-result tests cover first/interior/final
geometry with arbitrary packed cells and `A=0`, `z=0`, nonunit base `A`, and
extension-valued `A,z`. The small retained/recovered proof gate passed all six
tests with unchanged proof hashes. The log20 allcompact run also passed with
the original 70,451-byte proof hash. Against the preceding diagnostic control,
row evaluation fell from 2.035 to 1.577 s, quotient evaluation from 4.704 to
4.252 s, and interaction-through-proof time from 7.028 to 6.589 s. The charged
helper peak stayed exactly 1,589,661,136 bytes. These sequential timings are
attribution evidence, not a ranked speedup. The production flag remains off
until the canonical complete-root comparison finishes.

Canonical factor qualification subsequently passed: the same binary ran
q70/PoW26 with and without factoring on 20,495 cycles and three RAM shards.
Both passed all11 tests, destroyed producer owners, and independently verified
the complete original root and global closure. Proof bytes were identical:
5,840,895 bytes, SHA256
`17632306198e8673b30437399febc2f8f746c41e62449f961508190817821eb9`.
The public metadata and ELF were also identical. This uses active caller
layoutV3 and therefore legitimately differs from the earlier V2 archive.
The small-RAM complete fixture does not establish a whole-root timing gain.
The factor option remains explicit/off by default while the next task profiles
the actual multi-window production path.

## Production multi-window phase instrumentation

`block_v7_multi_union_proof_v1.ProveOptions.recorder` accepts a borrowed
`engine.stage_profile.Recorder`, null by default. It nests an inclusive
`multi_prove` scope under the caller's active workload stage. Inside it are
independent resource admission, per-window native and caller preparation,
program/lookup/memory provider preparation, fixed-column reconstruction and
commitment, adoption of already-committed private roots, per-family interaction
commitments, source-buffer release, detached claim copying, the original STARK
core stages, and explicit provider/context cleanup. The engine's existing
composition, OODS, DEEP/FRI and opening stages nest under `multi_core_proof`.

These timings describe work inside the producer API. Guest execution, witness
collection/sorting and initial source commitments occur before that API and
must be recorded by its caller; serialization and verification occur afterward.
Recursion is a separate process and must not be inferred from this original
proof timer. Parents include children: sum a set of sibling stages or use its
parent, never both. Any remaining parent self-time covers ordinary bookkeeping.
The recorder is snapshotted only after the caller closes its outer scope.

`ProducerStats` now also records optional allocator live bytes on entry/exit
and its cumulative observed high-water mark. That peak can include allocations
from before this call, and is neither incremental phase memory nor process RSS.
The harness must record whole-process RSS independently. Source checkpoint I/O
also belongs to its own boundary; this API performs no checkpoint loading.
Null-recorder execution preserves the original proof algorithm and ownership.
Metadata-only compilation passed; the integrated profiled workload gate is
owned by the coordinating test harness and remains to be run.

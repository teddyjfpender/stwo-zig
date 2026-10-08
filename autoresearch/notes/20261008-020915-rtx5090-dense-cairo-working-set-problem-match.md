---
title: RTX 5090 dense Cairo working-set problem match
author: Teddy Pender
created_utc: 2026-10-08T02:09:15Z
---

# Dense Cairo proof on a 31 GiB GPU: a memory-traffic problem

**Required output.** Prove the same immutable adapted Cairo PIE with the
canonical 70-query/26-bit-PoW protocol, produce exactly the saved proof
SHA-256, and pass the pinned independent Rust verifier. The economic screen is
5090 adapted-input-to-publication time no more than 4.5 times the historical
H200 time for the same PIE; the historical build is not source-matched.

**Measured instance.** `15582797_15582797` contains 20,848,320 OS steps and
plans 88,627,473,376 arena bytes. On the 167 GB-host RTX 5090, the verified
final-source capacity proof took 314.100 s of proof work and 318.230 s from
adapted input to publication, with a 27.242 GiB whole-device peak. The saved
H200 publication time is 15.314 s, making the 5090 run about 20.8 times
slower. The 4.5-times screen would require at most 68.913 s on the same
boundary. See the exact receipt and sampled device timeline in
`vectors/reports/cairo-cuda-5090-research-20261007/rtx5090-dense-final-profile/`.
At the observed 4.078 s ingress and 28.176 s for commitments and later
opening work, the 68.913 s publication ceiling leaves only about **36.7 s**
for trace generation, relation, and constraint evaluation together. Those
three stages currently take **285.9 s**, so the economic target requires
roughly a **7.8-fold** reduction in their combined time even if every other
stage stays unchanged. This rules out launch-overhead tuning alone.

**Working-set structure.** The arena inventory lists 25.923 GB of writer
lookup inputs, 11.469 GB of writer scratch, 12.553 GB of main coefficients,
25.105 GB of main evaluations, 10.432 GB of interaction coefficients, and
20.864 GB of interaction evaluations. The fixed Merkle tree is 4.295 GB;
three more trace trees are about 1.074 GB each. The planner's lifetimes place
several of these in relation generation and constraint evaluation together.
The broad capacity policy therefore prefers many slots on the host. Relation
generation takes 137.092 s, constraint evaluation 93.961 s, and trace
generation 54.872 s. Approximate stage-aligned device samples show multiple
GB/s of PCIe traffic through the long relation and constraint phases. This is
consistent with managed-memory paging; the timeline does not alone isolate
individual kernel stalls.

**Problem match.** This is a two-level-memory I/O scheduling problem over a
fixed proof DAG. A one-time arena reservation is not a memory schedule: the
hot slot set changes between writer, relation, commitment, constraint, and
opening phases. Keeping only a small fraction of a 20 GB source in HBM while
the kernel repeatedly gathers from the rest cannot achieve an H200-like time.
The scalable design must bound each stage's active working set and traffic,
then explicitly move or regenerate only data the next tile consumes.

| Candidate | Why it might help | Limitation and validation |
|---|---|---|
| Hint a bounded fraction of main or interaction evaluations into HBM | Cheap, reversible way to measure the access-temperature gradient | Must report full time, PCIe activity, whole-device peak, exact proof, and Rust verdict; cannot fix a 70+ GB active set by itself |
| Host the fixed Merkle tree before its first write and spend the freed HBM on hot evaluations | The tree is largely idle until decommit; earlier small-PIE trials found this effective | Commitment and opening may slow; pre-write advice is required because late migration did not reclaim HBM reliably |
| Retain upper Merkle layers and reconstruct only sampled lower branches | Replaces multi-GB retained hash trees with a compact authenticated frontier | Cairo currently uses zero unretained layers; requires sampled mixed-height leaf hashing, sparse buffers, exact root/path tests, and new lifetimes |
| Tile writer, relation, and constraint sources through bounded device buffers | Changes the I/O complexity of the three dominating phases and can support 20M-step single-block PIEs | Requires authenticated tile descriptors, device scratch separation from the managed arena, ordering tests, and profiling of transfer/computation overlap |

**Falsification order.** Keep the GPU otherwise idle. First run one-variable
residency trials and compare stage deltas, full publication time, device and
host peaks, exact proof SHA-256, and independent Rust verification. Do not
promote a point with negligible HBM headroom as the default. Then implement
the smallest architectural slice that actually removes retained data or
avoids host gathers; prove its equivalence before broadening geometry. The
20M-step result must not be extrapolated from the 2–5M-step cohort.

**Cross-check against recursive leaves.** The final two-leaf pipeline arena
inventory contains four separate 4.295 GB trace Merkle buffers, or about
17.18 GB in total, despite each Cairo input being only about 1.2M steps.
Keeping the upper tree after dropping two bottom layers would reduce their
*retained* storage to about 4.295 GB in total, a theoretical 12.88 GB saving
before accounting for one reusable commitment scratch buffer and sampled
opening buffers. This is a storage calculation, not a measured speedup or a
proof that its peak will fall by that amount. The lower branches must be
recreated exactly from the authenticated evaluations after the verifier's
queries are drawn; discarding them without reconstruction is unsound.

**Sparse-tree implementation contract.** This is the next bounded engineering
step, not an enabled optimization:

1. Build each commitment with the existing canonical mixed-height leaf hash
   and child hash functions. Keep its root and authenticated upper layers;
   reuse one lower-layer scratch buffer across trees. Root and transcript
   bytes must match the full-tree path exactly.
2. After query sampling, call `prepareTraceQueries` with a nonzero
   `unretained_bottom_layers`, deduplicate and order the expanded leaf set,
   and hash just those leaves from the retained evaluation columns. A sampled
   leaf kernel must use the same domain, column order, and mixed-height
   lifting as the full `mixed_leaf_kernel` in
   `src/backends/cuda/native/commitment/progressive.cu`.
3. Use the existing sparse-parent API to build the missing levels, then pass
   the sparse index/hash/offset arrays and nonzero
   `first_retained_log_size` to `assembleTrace`. Cairo's current
   `pcs_decommit_topology.openTrace` always chooses zero and empty arrays;
   its planner currently reserves only placeholder sparse buffers.
4. Prove exact root, full proof SHA-256, Rust verification, and pipeline root
   equality on the two-leaf and 5M-step cases. Include malformed sparse
   indices, duplicate queries, all four tree roles, and 70-query/26-bit-PoW
   production parameters. Measure whole-device peak and the commitment and
   opening deltas separately.

Even the theoretical 12.88 GB retained-tree saving in the small pipeline
does not imply the dense 20M-step PIE will meet the cost screen: its lookup,
main-evaluation, and interaction-evaluation sources alone exceed the card's
HBM. Dense performance also needs bounded streaming or regeneration through
relation and constraint evaluation.

**Tiling boundary in the current implementation.** The relation stage binds
immutable per-instance source pointer tables and then launches global pair,
fraction-chain, and tail kernels from
`src/backends/cuda/runtime/stages/relation.zig`. Merely splitting the launch
grid leaves every pointer aimed at the same host-backed columns; a previous
instance-window run therefore matched proof bytes but not speed. A real tile
must stage each instance's source words into a bounded device slab, rebind
only that instance's checked pointer table, execute all dependent passes, and
retire the slab before the next instance. In constraint evaluation,
`src/integrations/cairo_cuda/executor/eval/controller.zig` already owns an
`eval_lde_tile` scratch slot (3.825 GB in the small pipeline) and component
placement metadata. It is the natural boundary for staging component source
windows into HBM without changing AIR algebra. Both paths need proof-byte
tests because even an equivalent change in pass ordering can alter a
transcript-visible result if accumulation order changes.

**Campaign relevance.** The recorded 512-PIE H200 campaign has only 21 PIEs
at or below 5.34M OS steps, and 300 single-block PIEs all above 10M steps.
The extracted, path-independent inventory is
`vectors/reports/cairo-cuda-5090-research-20261007/h200-campaign-512-pie-step-sizes.csv`.
Consequently the currently qualified small-PIE 5090 policy is a narrow
routing option, not a production-wide replacement for the H200. Splitting
on block boundaries cannot shrink those single-block inputs; the dense
working-set design is therefore the critical path to economic coverage.

**Follow-up placement result.** On the 20.85M-step PIE, hosting half the
writer scratch and prefetching 20% of interaction evaluations reduced trace
generation from about 55 s to 22 s and published an exact, Rust-verified
proof in 274.577 s at 30.362 GiB peak. This is 13.7% faster than the
318.230 s dense baseline, yet still about 17.9× the historical H200
publication time. Prefetching 30% instead failed at 31.189 GiB in constraint
evaluation. The 6.00M-step geometry showed a different stage balance: the
first completed 5090 capacity proof took 150.146 s, while a composed
coefficient/lookup placement took 87.431 s with exact proof and Rust verdict.
Its relation stage still took 40.864 s versus a 22.581 s *total* economic
ceiling. These measurements reinforce that static placement can improve the
Pareto frontier, but the remaining gap requires a genuinely bounded relation
source working set and similarly bounded constraint inputs.
On a separate 22.67M-step, single-block Pedersen-heavy PIE, partial
interaction-coefficient residency reduced publication from 423.597 to
320.338 s at a 30.362 GiB GPU peak, with exact proof and independent Rust
verification. Relation still consumed about 173.652 s, compared with the
39.398 s total 4.5× H200 publication ceiling. This second component mix
confirms that the large-PIE bottleneck survives substantial placement gains.

**Actual H200-campaign cohort.** The first six completed PIEs in the pinned
15-case sample span 3.47–15.64M steps and planned arenas of 30.81–72.76 GiB.
The two arenas near 31 GiB proved in 7.24–7.31 s input-to-Cairo-proof, whereas
the four larger arenas took 203.76–390.76 s. All six matched their exact
adapted-input SHA-256 and passed the independent Rust verifier. The 11.93M
case spent 96.47 s in relation, 78.68 s in constraints, and **140.58 s after
FRI**, while its whole-device peak was only 16.12 GiB. This is a targeted
opportunity: bringing its retained trace hash trees back into the free HBM
before random Merkle openings may remove much of that last interval. It cannot
by itself fix relation or constraint paging.

The next isolated 5090 experiment uses the same 11.93M CPI and the exact
saved proof hash: turn on `STWO_CUDA_DECOMMIT_PREFETCH_HASHES=1` with the
managed-capacity policy, record per-tree mapping/packing/assembly time under
`STWO_CUDA_DECOMMIT_TIMELINE=1`, and accept the change only if the proof bytes
and Rust verdict remain identical, publication falls substantially, and
whole-device peak leaves a capacity reserve. A separate 8.53M trial will
profile fused fractions versus tail scan and test bounded per-component
constraint-source prefetch. These experiments are opt-in, not qualified
defaults; the sequential 15-case baseline was paused for the isolated test
and resumed from its last verified case afterward.

**Merkle prefetch rejected.** The isolated 11.93M-step trial restored the four
trace-hash slots before decommitment and still emitted the exact baseline proof
SHA-256 `c82aea032b1a477003a3ca188bcf1c112fc0ed9a96a962f3fc74d386fce9528d`;
the pinned Rust verifier accepted it. Publication increased from **379.164 s**
to **386.288 s**, while sampled device peak increased from **17.304 GB** to
**18.377 GB**. The new event boundary shows query PoW took less than a
millisecond and the decommit interval itself took **142.485 s**. Moving whole
hash trees into HBM therefore does not address this particular late-stage
stall. The opt-in is not promoted. A per-tree timeline is needed to determine
whether mapping, query packing, assembly, or another source traversal causes
the interval before changing the opening algorithm.

**Broader campaign sample.** A reproducible 33-case extension adds 18
position-stratified PIEs to the original 15. Eleven are within the exact first
64 campaign entries and 17 within the first 128; the full sample covers
543,311,115 OS steps and 10,799,968,060 authenticated CPI bytes. Its median
PIE is about 19.48M steps, close to the 512-campaign median of 20.27M. This
is a better screen for the actual service workload than the initial dense
outlier sample, but a sample of noncontiguous leaves cannot itself yield a
64/128/512 root. Full replay still requires the ordered, complete prefixes.

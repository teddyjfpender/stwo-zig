# Cairo relation streaming: problem-match brief

Task and required semantics: Produce the same canonical Cairo STARK proof bytes,
Merkle roots, LogUp interaction columns and claims, transcript draws, and Rust
verifier verdict while reducing the maximum live GPU pages. Do not alter field
arithmetic, column order, batch-inversion grouping, or proof security.

Inputs, scale, and model: The canonical Pedersen-dense PIE `15590913_15590913`
has a 103.367 GB logical request arena, 27.87 GiB of lookup output, and a
15.59 GiB `partial_ec_mul_window_bits_18` lookup instance. The measured H100
managed-only peak is 79.177 GiB; pre-commit host placement reduces it to
56.487 GiB with the same independently verified proof. The second PIE falls
from 79.177 to 48.362 GiB. Source and measurements are in
`vectors/reports/cairo-cuda-h100-managed-20261007/`. The GPU uses an ordered
CUDA proof stream and a monolithic managed request arena. The relation stage
currently launches a fused fractions kernel and prefix kernel over all
instances at once, followed by global tail/claim kernels.

Constraints and exploitable structure: Every relation instance has its own
authenticated geometry, lookup input range, interaction output, and claimed
sum. Geometry records exact prefix block offsets. The Fiat-Shamir challenge
must be drawn before any relation work; the interaction commitment and claim
capture happen only after every instance completes. Fraction generation and
its per-row prefix are independent across instances. The tail kernels can
remain global and ordered after all instances.

| Candidate | Relationship | Memory prediction | Exactness and risk |
| --- | --- | --- | --- |
| Per-instance fused fractions/prefix, then evict completed lookup pages | Exact decomposition of the current global grid; source-derived from current kernels | Removes prior instances' lookup pages from later-instance overlap; largest 15.59 GiB instance remains the floor | Preserve global block indices and current batch-inversion groups; extra launches and transfers |
| Row tiles within the large partial-EC instance | Exact decomposition if every column's word-major row intervals are bound correctly | Can bound even the 15.59 GiB instance | Higher ABI and pointer-table complexity; needs per-column page-range proof |
| Out-of-core LDE/commitment and evaluation replay | Exact multi-pass STARK proving if retained roots/openings match | Removes most of the 55.97 GiB evaluation arrays | Broadest change across commitment, constraint, quotient and decommitment |
| More whole-array Unified Memory advice | Placement hint only | Prior H100 trials already reached a 56.487 GiB floor | No guaranteed bound; repeated advice before coefficients was slower without reducing peak |

Chosen canonical problem and mapping: This is exact, bounded-memory streaming
over an independent batch of relation instances, followed by ordered global
reductions. The project-to-canonical mapping is one Cairo relation instance
to one independent tile; `pair_first` and `row_first` map tile-local launch
coordinates back to the exact original grid. After the fractions launch for
an instance, its lookup input may be migrated to host because later relation
phases read only interaction outputs. A global tail pass recovers exactly the
same claims. The first transfer is per-instance streaming; row tiling and
out-of-core LDE are follow-ups if the largest tile still exceeds the target.

Complexity and limits: Arithmetic work is unchanged. Kernel launches grow
from two global relation launches to roughly two per instance. Total migrated
lookup bytes are at most the lookup slab size plus page rounding. A 48 GB
card requires substantially below 48 GiB of sampled usage because capacity
is marketed in decimal units and the runtime needs reserve. The immediate
falsifier is no material reduction from 56.487 GiB on the dense PIE, or a
large publication-time penalty. This method cannot guarantee the 48 GB target
while the single partial-EC instance remains 15.59 GiB.

Prior implementations and sources: The current exact relation kernels and
topology are in `src/backends/cuda/native/relation/graph.cu` and
`src/backends/cuda/runtime/stages/relation.zig`. NVIDIA documents that
`cudaMallocManaged` permits oversubscription but migrates accessed pages, and
that preferred placement is a hint rather than a guarantee:
<https://docs.nvidia.com/cuda/cuda-programming-guide/02-basics/understanding-memory.html>
and
<https://docs.nvidia.com/cuda/cuda-programming-guide/04-special-topics/unified-memory.html>.
An independent out-of-core STARK implementation demonstrates the broader
multi-pass transform/commitment pattern, but its field, proof system, and
storage model differ, so it is an analogy rather than drop-in code:
<https://github.com/nzengi/zk-stream>.

Integration and validation: Add an AOT native range launch that accepts
authenticated global block starts/counts; keep the existing full-grid API.
The Zig controller iterates exact topology instances on the same stream and
evicts only the corresponding checked lookup view after fractions finish.
Test first/last blocks and non-power-of-two tails, compare all interaction
column bytes against the current path on small and dense geometry, then
compare full proof SHA-256 and pinned Rust verifier results on both PIEs.
Record full-command and stage times, whole-device peak, host RSS, migration
behavior where available, and proof bytes. Reject the path if it misses the
predicted memory reduction or regresses proving time beyond the capacity
trade-off.

Open uncertainty: The 250 ms memory sampler does not identify the exact
subphase of the 56.487 GiB peak. If it belongs to commitment rather than
relation lookup reads, this decomposition will have little effect; add
timestamped subphase markers before committing to row-level kernel work.

## Result

Rejected for peak-memory reduction. On H100 the opt-in per-instance path
produced byte-identical proofs and passed the pinned independent Rust
verifier for both dense PIEs, but whole-device peaks stayed **56.487 GiB**
and **48.362 GiB**, exactly matching capacity-placement references.
Receipts are in `vectors/reports/cairo-cuda-h100-managed-20261007/relation-streaming/`.
The implementation was removed from production after this falsifier.
Phase-aligned sampling subsequently placed the decisive rise during
interaction commitment, after relation work.

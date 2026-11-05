# M7 projected GKR sources

Status: numerical CUDA callbacks and traversal controls qualified; no native or
outer proof-format selector is enabled by this change alone.

The materialized original fractions are revisited twice: product-tree ingress
and the last GKR layer. Fusing only ingress leaves the large original arrays
live. `resident.ProjectedSource` now supplies validated class-specific callbacks
for a first product layer, raw sumcheck evaluations, a first half-split fold,
and a two-row mask. Once a first fold produces materialized secure banks, the
existing traversal continues unchanged. Mixed batches fall back to the exact
per-oracle operations for that wave; later materialized waves use existing
batching and tail fusions.

Every borrowed source allocation is admitted against the entire writable GKR
arena and fold workspace before any traversal launch. The class callback also
checks its geometry, source ranges, output ranges and read/write aliases using
the existing custody authority. Source descriptors contain host geometry and
device pointers, never producer-supplied challenges or terminal claims. They
and their borrowed allocations must outlive joined completion. Real poles
(including zero-weight `0/0`) remain real poles; only absent term lanes are
neutral `(0,1)` padding.

`projected_gkr.cuh` implements the shared arithmetic using the same extension
field as the materialized kernels. A source provides `validate(Custody&,count)`
and device `get(index) -> Fraction`. It does not allocate, copy, synchronize,
sample a transcript, classify a relation, or establish physical MAIN binding.
Native/outer adapters still owe their own receiver-derived rosters, challenge
framing, source-bound characteristic gate, committed binding AIR and recursive
verification.

Measured [M] numerical gate: five source sizes (2, 4, 8, 512, 131072) agree with
CPU arithmetic for one/two product levels, half-split folds, raw sumcheck values
at 0/2 and terminal masks. Original fraction arrays consume zero device bytes
in this test. Shape and source/output-alias mutants reject. Compute-sanitizer
memcheck reports zero errors. All 49 host GKR/batch control tests pass, including
final-layer source revisit and preflight source/arena alias rejection.

Receipts: `vectors/reports/rv64-m7-20261105/native-gkr/projected-gkr.json` and the
associated logs. These are numerical/control results, not a full-block timing,
production memory peak, or proof acceptance result.

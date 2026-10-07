# Cairo interaction LDE cohort streaming: problem-match brief

Required semantics: Exact LDE values, Blake2s leaf message order, Merkle root,
transcript, proof bytes, and independent verifier result. No change to input,
AIR, or security parameters.

Measured bottleneck: On H100 the dense PIE rises from about 42.8 GiB after
relation work to 54.5 GiB during interaction commitment. It reaches 56.487
GiB by FRI. Host-preferring whole evaluation arrays before commitment and
host-migrating complete Merkle trees did not lower this peak. The phase trace
is in `vectors/reports/cairo-cuda-h100-managed-20261007/phase-diagnostic-dense`.
The interaction tree extends cohorts sequentially, then absorbs their
precomputed LDEs sequentially into progressive Blake states. Its LDE slot is
one large, contiguous logical span even though each cohort is independent.

Canonical problem match: This is bounded producer-consumer streaming over
cohorts. After a cohort's transform completes, prefetch its output to host;
when the progressive Merkle leaf builder consumes it, prefetch it back to
host before the next cohort. The existing ordered CUDA stream makes each
operation happen after its producer/consumer. The callback must use the exact
authenticated cohort view and preserve the builder's sorted segment order.

Prediction: The interaction tree's peak should track the largest active
cohort instead of the full 23.9 GiB interaction LDE. If the measured peak
merely shifts to constraint evaluation, that stage also needs per-component
retirement. No 48 GB fit is claimed until a complete proof on such a device
or a sufficiently low H100 peak with reserve is measured.

Implementation and falsifier: Add a capacity-only execution method to the
Cairo trace commitment and an optional progress callback to the common
progressive tree builder. Keep the default path and all leaf kernels intact.
Test proof SHA-256 and Rust verification on both dense PIEs, record phase
times, device peak, host RSS, and reject if the peak is unchanged or the time
tradeoff is too large. Subsequent work must bound the largest cohort and
downstream constraint/decommitment accesses if they become the new peak.

## Implementation correction

The dense interaction tree uses the **fused mixed-leaf** path and compact
prefix states, not the full progressive-segment path. A callback attached
only to `baseFieldLiftedSegmented` would not run for this PIE; such a partial
candidate was removed before GPU testing. The actual bounded implementation
must tile the fused mixed-leaf launch by leaf-row range, keep the required
cohort input slices resident for each tile, and retire those slices before
the next tile. It must also bound the earlier LDE cohort generation and
later AIR reads. Merely host-prefetching whole cohorts after transforms
would bring them all back during the existing single fused leaf launch.

## H100 falsifiers and next match

An exact row-tiled mixed-leaf commitment was qualified on both canonical
PIEs. With explicit device/host prefetch around each tile, the dense peak
rose from 56.487 to 79.069 GiB and the second peak from 48.362 to 67.896
GiB. Without tile prefetch, both peaks were identical to the capacity
reference: 56.487 and 48.362 GiB. All four proofs matched the saved SHA-256
and passed the official Rust verifier. The first variant was regressive; the
second added code without reducing capacity, so both were removed. Receipts
are under `vectors/reports/cairo-cuda-h100-managed-20261007/`.

The next bounded change is to retire the 11.71 GiB interaction-coefficient
slot **before** the interaction LDE transform instead of after commitment.
The transform reads coefficients and writes evaluations, so the capacity
policy can prefer these already-computed coefficients on host while the GPU
consumes them. This trades transform bandwidth for lower simultaneous HBM
residency without changing values, roots, or authenticated slot ownership.
The falsifier remains a whole-proof exact-hash/Rust-verifier check plus
phase-aligned whole-device peak; if it fails, use explicit host-backed
separate allocations or streaming recomputation rather than more prefetch
hints on the single managed arena.

The early-coefficient experiment also preserved both exact proofs but left
both device peaks unchanged (56.487 and 48.362 GiB); host RSS rose sharply.
That falsifies placement-hint timing as a capacity solution. The next
architectural match is **explicit host-backed arena storage**: the GPU can
address an authenticated, page-locked host allocation, but these pages cannot
silently accumulate in HBM. This may trade substantial PCIe bandwidth and
latency for a true capacity bound. Run it as an opt-in experiment and retain
only if complete proofs remain exact and the time/memory tradeoff is useful.

Final match: placement must be set **before the first GPU write**. Applying
host preference to both main and interaction coefficient slots before their
respective writer stages reduced the two exact, Rust-verified H100 peaks from
56.487/48.362 to 30.860/26.983 GiB, with publication rising from
34.310/29.651 to 51.273/36.097 s. A 34 GiB HBM reservation left 44.66 GiB
free and the dense proof still completed exactly. The whole-arena mapped-host
prototype failed in trace writers and was removed; late prefetch/placement
and row tiling were also falsified. Raw receipts and limits are documented in
`vectors/reports/cairo-cuda-h100-managed-20261007/memory-pipeline-followup.md`.
Next profiling should target the late proof/decommit peak and prove an actual
smaller-GPU card before asserting hardware compatibility.

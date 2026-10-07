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

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

## Concrete tiled mixed-leaf mapping

Use a power-of-two leaf tile of `2^18` rows for the first H100 experiment.
The native `mixed_leaf_kernel` already computes each leaf independently from
its global row index. A range launch changes only the grid-to-row mapping:
`row = row_first + local_thread`, then writes the same `result[row]` or
`prefix[row]`. Existing calls retain `row_first=0,row_count=size`.

For an input segment with `log_ratio=log2(size/source_size)`, the current
`lifted_column_index` maps any tile to a conservative contiguous source-row
interval. At ratio zero it is `[row_first,row_end)`. Otherwise it is
`[2*floor(row_first/2^(log_ratio+1)),
 2*(floor((row_end-1)/2^(log_ratio+1))+1))`. For each column, prefetch only
that interval to the GPU before launching and back to CPU after the launch,
all on the proof stream. This bounds active source pages by tile rows rather
than the full interaction LDE; it is a placement optimization over exactly
the same evaluation values. The same range mechanism must cover compact
prefix and final mixed-leaf launches. The trace transform must retire each
completed cohort before leaf hashing starts. The kernel and host range logic
must reject overflow, out-of-domain ranges, and non-managed capacity calls.

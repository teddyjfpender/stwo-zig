# Problem match: bounded relation working sets on a 32 GB GPU

**Task and required semantics.** Produce the same canonical Cairo relation
columns, claimed sums, transcript inputs, Merkle roots, and final proof bytes
as the current global relation launch. No witness values may be dropped or
reordered within a relation instance.

**Inputs, scale, encoding, model.** The dense PIE `15582797_15582797` has a
25,922,947,584-byte writer lookup slab and an 88,627,473,376-byte arena. On
the 5090 capacity baseline, relation generation took 139.899 s, sampled GPU
use peaked at 17.615 GiB, and host RSS at 72.625 GiB. The GPU has 32,607 MiB
physical VRAM and this pod 167 GB host RAM. Relation geometry is a list of
independent instances, each with source columns, output coordinates, pair and
row block ranges. CUDA kernels currently cover every instance in one global
grid, followed by a global reduction/scan.

**Constraints and structure.** Each fraction kernel block resolves exactly
one instance from its global block index, reads that instance's sources, and
writes that instance's output columns. The prefix kernel is likewise
instance-local. The tail kernels consume completed outputs. GPU launch and
prefetch must remain ordered on the same stream. The stored source and output
descriptors are authenticated before execution, and the final proof hash plus
independent Rust verifier provide the end-to-end equality check.

**Candidate matches and evidence.** This is an out-of-core working-set
scheduling problem with an exact stage DAG: stage source ranges, compute
fraction/prefix for one or a few instances, then run the existing tail. A
single prefetch of the 25.9 GB slab is a relaxation of this schedule, but it
nearly fills 5090 VRAM by itself and may evict other live pages. NVIDIA says
prefetch is stream ordered and *may* migrate selected managed ranges, with
eviction when memory is insufficient; these are performance hints, not proof
semantics ([CUDA programming guide](https://docs.nvidia.com/cuda/cuda-programming-guide/02-basics/understanding-memory.html),
[runtime API](https://docs.nvidia.com/cuda/cuda-runtime-api/cuda_runtime_api/group__CUDART__MEMORY.html)).
Prior whole-tile prefetch around the trace commitment worsened H100 memory use
in this repository; relation scheduling is a different access pattern and
requires its own measurement. The present 5090 baseline alone does not prove
that page faults, rather than arithmetic, dominate the relation stage.

**Chosen exact variant and mapping.** Partition the existing global pair and
prefix grid at authenticated `Geometry.pair_first/pair_blocks` and
`row_first/row_blocks` boundaries. For each instance, optionally prefetch its
source columns through the existing managed-allocation authority and enqueue
its two kernels on the same stream. After all instances, run the unchanged
global tail. No approximation, changed field arithmetic, or transcript change
is allowed. This has the same asymptotic work and output; the additional cost
is one pair of launches and selected transfers per instance.

**Alternative choices and risks.** Leaving global kernels and only changing
managed preference is simpler, but the measured low-HBM baseline is 371 s of
proof execution. Whole-slab prefetch can exceed the free working set. A full
VMM redesign could physically remap pages, but has much larger correctness
and integration risk. The selected scheduling approach is opt-in until exact
proof and memory qualification.

**Prediction and falsifier.** A useful first result reduces relation time by
at least 2× without exceeding the 32,607 MiB device capacity or changing the
proof hash. If relation time stays near 140 s, memory remains near 100% SM
utilization with little migration, or prefetch causes repeated eviction and
slower total proving, reject this path and profile the fraction kernel itself.
The 4.5× historical-H200 target for the whole dense proof is 5.819 s, so even
a 2× relation gain is only a step, not success.

**Correctness and benchmark plan.** First compare global and instance-window
launches on a small exact PIE, including the pinned Rust verifier. Then run
the dense PIE, save phase times, whole-device memory samples, host RSS, full
command time, exact proof SHA-256, and Rust verdict. Compare on the same idle
5090 host and native CPU-targeted build. Check that each instance window
exactly partitions both global grids, including empty and final ranges.

**Open uncertainty.** The current receipts do not distinguish relation
fraction, prefix, and tail kernel times. Instrument these first so scheduling
work addresses the actual long kernel; the constraint stage has a separate
127.416 s bottleneck that this experiment cannot remove.

**Window-only result.** The partitioned kernel launches, without any
prefetch, produced the exact dense proof and passed the Rust verifier. On the
interaction-coefficient HBM policy, proof execution was 310.422 s versus
310.373 s for the same policy's global launch; GPU peaks were both
27.242 GiB. Relation generation changed from 136.051 to 134.625 s. This
qualifies the partition but shows launch order alone has no material speed
effect. The source-prefetch variant is the next falsifier.

**Source-prefetch falsifier.** Prefetching every source column per instance
raised relation generation to 140.352 s and the sampled whole-device peak to
33,667,678,208 bytes (31.35 GiB), within about 0.49 GiB of the reported
32,607 MiB card capacity. The proof failed in constraint
evaluation with CUDA status 2 (`cudaErrorMemoryAllocation`) after 298.341 s;
it produced no proof and is not a valid performance result. The runtime kept
prefetched pages resident into the next stage. This rejects unbounded
per-instance prefetch and requires a stricter device-residency budget or a
different out-of-core representation before this path can be promoted.

# Problem match: staged source columns for CUDA constraint evaluation

**Task and semantics.** Evaluate the same canonical Cairo AIR constraints and
composition polynomial as the current proof, with identical proof bytes and
independent verification. Each component's source columns must be ready before
its evaluator kernels; no change to constraint equations or transcript order
is permitted.

**Measured input and model.** On `15582797_15582797`, the 5090 capacity proof
spent 127.416 s in constraint evaluation. The logical arena is 88.6 GB but
sampled HBM use only 17.6 GiB. The main and interaction committed-evaluation
slots are 25.1 GB and 20.9 GB, respectively, and are host-preferred in this
capacity policy. The constraint controller already processes an authenticated
ordered list of components, each with source offsets and an evaluation domain.

**Canonical match.** This is bounded working-set staging in an out-of-core
linear pipeline, analogous to blocking a matrix operation by the source
columns consumed by one component. The proof's component sequence is fixed;
the optimization only changes when managed pages are suggested for migration.
NVIDIA specifies that managed-memory prefetch is stream ordered, may move
selected ranges, and may evict other managed pages when the destination lacks
space ([CUDA programming guide](https://docs.nvidia.com/cuda/cuda-programming-guide/02-basics/understanding-memory.html),
[CUDA runtime API](https://docs.nvidia.com/cuda/cuda-runtime-api/cuda_runtime_api/group__CUDART__MEMORY.html)).
Thus correctness follows from retaining the existing stream dependency and
exact source bounds, not from any guarantee that pages stay resident.

**Mapping and selected transfer.** Decode each component's already-validated
physical offsets for sources that reuse committed LDE columns. Before its
evaluator launches, enqueue a device prefetch for those source ranges if their
combined logical extent is at most 8 GiB. The bound is a first capacity
experiment: 17.6 GiB observed baseline HBM plus the 3.56 GiB evaluation tile
and 8 GiB staged source budget is below the 5090's 31.84 GiB physical memory,
but instantaneous overhead and duplicate pages remain uncertain. Leave large
components on the existing path and preserve the source plan and kernels.

**Alternatives.** Whole-array prefetch of both evaluation slots exceeds device
capacity. A smaller 4 GiB window has less risk but may skip more components.
Exact source-column tiling within one AIR kernel could lower the working set
further but requires deeper kernel changes. Recomputing LDE values rather than
retaining them is another time/memory tradeoff that must be evaluated later.

**Prediction and falsifier.** A credible gain would halve the 127 s constraint
stage without exceeding physical VRAM or changing the canonical proof. If
prefetch calls evict hot pages or the measured stage does not improve, reject
this policy. The H200-relative 4.5× whole-proof threshold is still much
stricter and requires improvements to trace generation and relation work too.

**Qualification.** Compile the exact CUDA product, run a small PIE with proof
hash equality and the Rust verifier, then test the dense PIE on an otherwise
idle 5090. Record component timing diagnostics, full proof-stage time, GPU
peak, host RSS, final proof hash, and independent verifier result. The source
offsets and sizes are checked by the admitted resident arena before invoking
the prefetch API; malformed range/length must fail rather than silently skip.

**Open uncertainty.** Current phase receipts do not reveal which AIR
components consume the 127 s or their source-set sizes. The opt-in diagnostic
will print per-component times and bytes staged so the next iteration can
replace the provisional 8 GiB bound with measured geometry-aware scheduling.

**First falsifier.** The 8 GiB cap did not bound cumulative residency. On the
baseline capacity policy, relation generation took 200.270 s rather than
139.899 s, interaction commitment ended at 225.364 s, and the proof failed
during constraint evaluation with CUDA allocation status 2. Whole-device use
reached 33,667,678,208 bytes (31.35 GiB), within about 0.49 GiB of physical
capacity. This trial produced no proof and is rejected. A future staging policy
must track the resident *aggregate* across components and explicitly release
or migrate prior pages; limiting each component's requested bytes is
insufficient.

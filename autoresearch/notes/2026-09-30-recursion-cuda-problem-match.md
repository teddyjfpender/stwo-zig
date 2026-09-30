# Circuit recursion on CUDA: problem match and measured baseline

Task and required semantics: prove two contiguous Starknet PIE executions as
production-registry Cairo leaves, wrap each in its exact recursive verifier
circuit, then fold them to the same circuit root bytes as pinned
`proving@5a7c5ed`. Both Blake2s channel profiles, the 20-bit interaction
grind, the 26-bit FRI grind, query order, Merkle paths, and proof serialization
are protocol constraints. Full-CUDA means that Cairo, circuit polynomial
commitments, composition, quotient, FRI, and PoW actually execute on CUDA;
using the GPU only for PoW is a hybrid measurement.

Inputs, measured scale/provenance, encoding, and model: the two adapted
mainnet leaves are `15627902-15627904` and `15627905-15627907`; the production
registry SHA-256 is
`a2503220947f161185a4f5160fd5953db92f6aec0055367830ebc8a65187eabf`.
On an H100, Cairo CUDA proof execution and decode took 0.345–0.357 s warm per
leaf, while source/plan ingress took 1.515–2.305 s; reserved arenas were
50.89–51.51 GB. The two-leaf CPU full pipeline took 106.126 s on M5; Metal
took 75.979 s on M5; the H100 hybrid with CPU PCS took 296.902 s on its
different host CPU. The H100 hybrid spent 155.270 s in CPU Cairo, 87.600 s in
CPU circuit wraps, and 51.509 s in CPU fold. These host differences prevent a
direct device-speed ratio from the three full-pipeline totals.

Constraints and exploitable structure: circuit registry topology and AIR
programs repeat across leaves, but proof values vary. The transcript is
sequential at commitment, challenge, and opening boundaries; within each
boundary, polynomial transforms, AIR rows, Merkle leaves/parents, quotient
rows, and FRI butterflies expose broad parallelism. The two leaf proofs are
byte-exact against the independent Rust prover. Reuse immutable topology,
twiddles, AOT programs, and arenas, but never reuse proof-dependent rows.

| Candidate match | Relationship | Fit and measured prediction | Reusable implementation | Risk |
| :--- | :--- | :--- | :--- | :--- |
| Batched radix-2 transform plus Merkle reduction DAG | Exact decomposition of PCS commitments and FRI; derived from local code | Large parallel row/column batches on H100; must measure stage work | Existing Cairo CUDA resident FFT/commit/FRI stages | Circuit layouts and Blake2s channel differ |
| Host-slice `ProverEngine` CUDA adapter | Interface-level reduction, not a full algorithm | Easy parity oracle, but repeated PCIe materialization could dominate 10–50 s wrap/fold | Metal `MetalCommitBackend` contract | False “full CUDA” if host work remains |
| Resident circuit proof session | Exact decomposition matching Cairo CUDA architecture | Amortized repeated topology; prediction: major PCS savings, unknown total until profiled | Cairo CUDA resident stages and Metal circuit AIR scheduling | New circuit AIR lowering and proof-owner lifetime |

Chosen canonical problem and exact variant: an ordered authenticated
data-parallel computation DAG with static topology and dynamic field values.
It is not a generic graph optimization or an NP-hard scheduling problem. Map
each circuit proof's columns to batched circle transforms, tree commitments to
level-wise reductions, AIR constraints to independent row evaluations, and
FRI to repeated fold/commit rounds; preserve the transcript's order exactly.
The dependency chain limits critical-path speedup, while row and column
parallelism determines GPU occupancy.

Prior implementation and transfer: use the CUDA Cairo resident execution
model for lifetime, arena and proof capture; use Metal's full circuit
`ProverOn(MetalCommitBackend)` and the CPU proof as behavior oracles. A direct
Metal-to-CUDA source translation is not available from CuMetal, which targets
CUDA source on Apple Metal rather than the reverse. Prefer a resident circuit
session over a generic adapter that continually downloads whole columns.
NVIDIA's [CUDA Graphs guide](https://docs.nvidia.com/cuda/cuda-programming-guide/04-special-topics/cuda-graphs.html)
supports the launch-amortization hypothesis for repeated static DAGs; its
memory-node reuse applies only when graph lifetimes do not overlap.
NVIDIA's [Best Practices Guide](https://docs.nvidia.com/cuda/cuda-c-best-practices-guide/index.html)
supports using pinned host buffers and non-default streams to overlap
transfers, conditional on the device and actual dependency graph. These are
candidate transfers, not measured speedups in this pipeline.

End-to-end prediction and falsifier: removing the CPU PCS from the H100 hybrid
could eliminate most of its 87.600 s wrap and 51.509 s fold costs, but it
cannot make a sub-second full pipeline while 1.5–2.3 s of warm Cairo ingress
per leaf remains. Time every circuit phase and host/device transfer separately.
Reject the resident design if device FFT, Merkle, composition, quotient and FRI
do not beat the same-host CPU path after warmup, or if transfer/arena capacity
erases the gain. Do not extrapolate the 0.35 s Cairo kernel time to a complete
recursive root.

Correctness and benchmark plan: first feed the two verified CUDA Cairo proofs
into the Zig leaf verifier circuit without re-proving Cairo, using the
authenticated opening capture. Then qualify one circuit wrap and a two-leaf
fold byte-for-byte against CPU and pinned Rust, with CPU/Metal/CUDA on
comparable inputs and stage scopes. Measure cold and warm wall times, actual
device high-water memory, host RSS, launches, transfer bytes, and GPU kernels;
profile before changing geometry. Open uncertainty: circuit AIR lowering into
the resident CUDA evaluator and the arena size of a full wrap are not yet
measured. The pinned AIR lowering now generates eleven unique kernels with
geometry-invariant normalized identities, and all eleven pass `sm_90` PTX
compilation. Their actual resident evaluation and the full circuit PCS still
need implementation and measurement. The present
`circuit-recursion-cuda-hybrid` uses CPU Cairo and CPU PCS; it does not satisfy
the full-CUDA gate.

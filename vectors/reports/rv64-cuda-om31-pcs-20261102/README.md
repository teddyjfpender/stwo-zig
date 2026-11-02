# OM31 resident PCS foundation on RTX 5090

This slice adds enqueue-only eight-coordinate FRI folds and Blake2s leaf packing.
It preserves the native OM31 tower; the existing QM31 kernels are not substituted
for the 128-bit-target proof profile. Folds support one through four levels,
circle-to-line conversion, and the native alpha-squared accumulation rule.
Leaf packing supports plain and prefixed hashes with one to sixteen OM31 values.

The real GPU smoke passes 128 cases, including padded strides, canaries, alias
rejection and late twiddle-range errors. All four Compute Sanitizer tools pass.
ReleaseSafe and ReleaseFast pass 32 integration tests each, including 60 native
canonical-domain comparisons against `core.fri.ForField(OM31)`. The GPU smoke
uses an independent stagewise scalar fold and Blake2s byte-framing oracle.

The kernels allocate nothing, copy nothing to the host and do not synchronize.
The context owner retains all borrowed device arrays until checked completion.
The Zig wrapper validates generation custody and latches enqueue failures.
SM120 compilation reports no local-memory spills; the four-level fold uses
128 registers, so larger fusion is not presumed faster.

These are numerical PCS primitives, not an Ethereum proof or a completed PCS
controller. OM31 transcript orchestration, remaining PCS stages, physical AIR
composition and the mixed-instance GKR pipeline remain required. No full-block
speed or production-readiness claim follows from these gates.

Raw hardware results are in `gates/`; native integration summaries are alongside
this file. Device reproduction compiles `pcs_smoke.cu`, `rv64/pcs.cu` and the
existing context implementation with CUDA 12.8 targeting SM120, then runs the
smoke normally and under memcheck, initcheck, racecheck and synccheck.

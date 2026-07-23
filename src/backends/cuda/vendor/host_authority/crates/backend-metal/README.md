# stwo-backend-metal

An Apple-GPU (Metal) prover backend for stwo, ported from the standalone
[`stwo-metal`](https://github.com/starkware-libs/stwo-metal) prototype and adapted to this
repository's backend extension points (`FrameworkBackend`, `FromSimdColumns`,
`stwo-backend-testkit`).

## Status

- **macOS / Apple Silicon only.** On other targets the sys crate compiles to a stub and every
  GPU entry point returns an initialization error.
- **Conformance-gated.** `tests/conformance.rs` runs the full
  `stwo_backend_testkit::assert_backend_conformance` suite against `CpuBackend` for both
  `Blake2sMerkleChannel` and `Blake2sM31MerkleChannel`: op-level differentials (column ops,
  poly ops, barycentric, split/join, FRI folds, accumulation, quotients, Merkle including
  pruned-equivalence, grinding, `FromSimdColumns`) plus end-to-end **proof byte-equality**.
- **No Xcode required.** `stwo-backend-metal-sys` compiles shaders ahead of time when
  `xcrun metal` is available, and otherwise embeds preprocessed shader source compiled once
  at startup by the Metal driver (one `MTLLibrary` per translation unit, so file-scope
  helpers don't collide). Command Line Tools are sufficient.

## Performance

End-to-end prove of the testkit reference AIR (16 base columns, degree-2 constraints,
`Blake2sMerkleChannel`, `PcsConfig::default()`), Apple M5 Max (18 cores, 64 GB), warm-best
of 3 iterations, single process per backend
(`crates/backend-metal/tests/bench_prove.rs`):

| rows | MetalBackend | SimdBackend (NEON, rayon) | SIMD advantage | peak RSS (Metal / SIMD) |
|---|---|---|---|---|
| 2^16 | 1.05 s (63k rows/s) | 30 ms (2.2M rows/s) | 35× | 78 MB / 63 MB |
| 2^18 | 4.67 s (56k rows/s) | 65 ms (4.0M rows/s) | 71× | 231 MB / 233 MB |
| 2^20 | 20.5 s (51k rows/s) | 178 ms (5.9M rows/s) | 115× | 892 MB / 931 MB |

**The honest reading: the current Metal lane is not competitive with the SIMD backend on
Apple Silicon, and the gap grows with size.** Metal's throughput is flat (~55k rows/s) —
the pipeline is bound by fixed per-operation costs, not compute: hundreds of small
synchronous GPU dispatches (each paying command-buffer creation, ObjC retain/release
churn, and a `waitUntilCompleted`), host-side OODS dot products over full columns, and
the CPU constraint-evaluation lane. The SIMD backend's throughput *rises* with size as
its fixed costs amortize. Profiling notes live in the history of
`tests/bench_prove.rs`; the largest structural deficits, in order:

1. ~~Constraint evaluation runs on the CPU~~ — **a JIT GPU constraint lane now exists**
   (`src/backend/jit/`): the component's constraint tree is recorded to bytecode once,
   compiled to a fused Metal kernel (cached by semantic hash), and evaluated on GPU,
   falling back to the CPU lane on any failure (`STWO_METAL_DISABLE_JIT` forces the
   fallback). It is byte-equal to the CPU lane and conformance-gated — but it does
   **not** move the e2e numbers above (≤0.2% at log 18–20): after the CPU lane was
   parallelized, constraint evaluation was no longer the wall. The remaining costs
   are spread across per-dispatch synchronization and host-side OODS.
2. **Per-dispatch synchronization** — most kernels submit one command buffer and wait.
   The async-submission pattern exists (`evaluate_polynomials`) but covers one stage.
3. **Host-side OODS** — barycentric evaluation is a CPU dot product per (column, point)
   over the full LDE; the GPU batch path exists but is bypassed by the
   weights-hash-map flow.

Benchmarking at production sizes also surfaced two prove-corrupting bugs that the
log-6 conformance suite could not see (both fixed, both now gated): a pointer-keyed
GPU twiddle cache that poisoned every prove after the first when a freed twiddle
allocation was reused (first proof valid, second proof garbage), and host reads of
async-written buffers without a queue fence. The testkit now proves every statement
twice per process and requires byte-identical proofs.

## Architecture

```
stwo-backend-metal-sys     ObjC runtime (runtime.m) + FFI wrapper (metal.rs) + .metal kernels
stwo-backend-metal         MetalBackend: Backend/BackendForChannel trait impls
  src/columns/             Unified-memory columns (BaseFieldVec, SecureFieldVec,
                           Blake2sHashVec) — GPU buffers with zero-copy host views
  src/backend/             Trait impls: poly (FFT/LDE), fri, quotient, accumulation,
                           blake2s (Merkle + grind), lookups (GKR/MLE), column ops
  src/backend/zero_copy_bridge.rs   FromSimdColumns: witness generated on SimdBackend,
                           transferred at the commitment boundary
```

Key design points carried over from the prototype:

- **Unified memory**: columns live in `MTLBuffer`s shared between CPU and GPU
  (`host_slice()` gives a zero-copy host view), so "upload/download" is mostly free on
  Apple Silicon.
- **Async submission with same-queue ordering**: `evaluate_polynomials` submits all LDE
  RFFTs without waiting and drops the completion handles; later GPU work (Merkle hashing,
  quotients) is serialized after them by Metal's FIFO queue. **Contract**: any *host-side*
  read of a possibly-in-flight buffer must first fence the queue via
  `stwo_backend_metal_sys::metal::queue_drain()` — see `materialize_leaf_columns` in
  `src/backend/blake2s.rs` for the canonical example (the M31-output Merkle hasher builds
  leaves on the host).
- **JIT constraint evaluation with CPU fallback**: `FrameworkBackend` first tries the
  native lane (`src/backend/jit/`): the constraint tree is recorded to V1 bytecode via a
  generic `EvalAtRow` recorder (logup included), compiled to a fused Metal kernel cached
  by semantic hash, and evaluated in one GPU dispatch. Any failure falls back to
  `evaluate_constraint_quotients_via_cpu`, which stays correct for *any* AIR. Both lanes
  are byte-equal; `STWO_METAL_DISABLE_JIT` forces the fallback and `STWO_METAL_JIT_LOG`
  reports it.

## Byte-equality decisions

Two places where the GPU-optimal answer was rejected to preserve proof byte-equality with
the reference backend:

- **Grinding** (`GrindOps`) delegates to `SimdBackend`. The GPU grind kernel is kept as the
  inherent `grind_gpu::<IS_M31_OUTPUT>` but finds a *different valid nonce* (it searches the
  low 32-bit space in 2^24 batches), which would change proof bytes.
- **M31-output Merkle leaves** are hashed on the host (chunked, rayon-parallel when the
  `parallel` feature is on) rather than via the non-M31 GPU fast path, matching the
  reference hasher's exact byte stream.

## Not ported (and why)

From the `stwo-metal` prototype, the following were deliberately left behind:

- **Cairo-specific witness/interaction lanes** (`interaction_trace_*`, `handoff`,
  `commitment_slice`, `proof_slice`): coupled to stwo-cairo's component set; this repo's
  seam for that is `FromSimdColumns` + the generic `prove_cairo<B, MC>` in the stwo-cairo
  fork.
- ~~Bytecode-JIT constraint evaluation~~ — since ported (see `src/backend/jit/`): the
  recorder and shader compiler were adapted to the current constraint-framework API and
  gated on proof byte-equality. The prototype's interpreter, program registry, and
  per-AIR hand-lowered overlays remain unported.
- **Capability/planner/benchmark scaffolding** (`capability`, `planner`, `execution_plan`,
  `workload`, `benchmark`, `prove_runtime_v1`): runtime auto-tuning machinery, orthogonal to
  a correct backend and a large maintenance surface.
- **Dead kernels** (`barycentric`, `fri_decompose`, `merkle_decommit`): unreferenced by the
  surviving trait surface.

## API delta vs the prototype's vendored stwo

The prototype pinned an older stwo; the port adapts to this repo's traits:

- `FriOps::fold_line` takes an `alphas` slice (`alphas[i] = alpha^(2^i)`) and folds the
  whole chain; `fold_circle_into_line` returns the `LineEvaluation`.
- `QuotientOps` gained `log_blowup_factor` + twiddles with subdomain-accumulate semantics;
  the GPU kernel runs on the evaluation subdomain and the result is interpolated/extended
  with subdomain twiddles extracted from the full tree.
- `PolyOps` requires `split_at_mid`/`join_at_mid` and barycentric evaluation.
- `MerkleOpsLifted` requires `PackLeavesOps`; commitment is pruned
  (`commit_pruned`, bottom 4 layers recomputed at decommit).

## Testing

```bash
# Op-level + proof byte-equality conformance (both channels)
cargo test --release -p stwo-backend-metal

# The same suite any new backend should pass
cargo test --release -p stwo-backend-testkit
```

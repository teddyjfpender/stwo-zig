# stwo-backend-cuda-kernels

Champion CUDA kernels harvested from the standalone
[`stwo-cuda`](https://github.com/starkware-libs/stwo-cuda) prototype, staged here as the
starting point for a future `stwo-backend-cuda` crate.

**The crate is compile-gated**: without `nvcc` it builds as a stub, so there is no CUDA
toolkit requirement for building or testing stwo. With `nvcc` available (on `PATH` or via
`STWO_CUDA_NVCC`), `cargo build -p stwo-backend-cuda-kernels` compiles every kernel under
`cuda/` into a static archive with separable compilation. Target SMs come from the
comma-separated numeric `STWO_CUDA_ARCH`, or are detected from the first local GPU;
headless compiler hosts must set the variable explicitly. Run that on an NVIDIA box as
the first validation gate for the staged sources. No FFI bindings are exposed yet; they
belong with the `stwo-backend-cuda` trait
implementations (see "How to turn this into a backend" below).

`STWO_CUDA_ARCHIVE_LTO=1` compiles only the ordinary archive translation units as LTO IR
and enables LTO at their matching device-link step. Generated AOT sources remain standalone
`-cubin` builds. Do not put LTO flags in `STWO_CUDA_NVCC_FLAGS`: those global flags are also
forwarded to every generated AOT cubin and are rejected deliberately.

## What was taken

The compute kernels (`.cu`) with their full local include closure (`.cuh`), 55 files:

| Kernels | Future trait surface |
|---|---|
| `bit_reverse`, `batch_inverse`, `utils` | `ColumnOps` (bit-reverse, inverse) |
| `rfft`, `ifft`, `twiddles`, `poly_utils`, `eval_at_point`, `barycentric` | `PolyOps` (LDE, twiddle precompute, OODS eval, barycentric) |
| `quotients` | `QuotientOps` |
| `accumulate` | `AccumulationOps` |
| `fold_line`, `fold_circle_into_line`, `fri_utils` | `FriOps` |
| `gkr`, `mle`, `prefix_sum` | `GkrOps` / MLE |
| `blake2s` | `MerkleOpsLifted<Blake2s*>` + `GrindOps` (kernels already target the **lifted** scheme: `commit_on_first_layer_lifted`) |
| `fp256_*`, `poseidon252*`, `ec_ops`, `pedersen_table*` | Poseidon252/Starknet hash stack (Montgomery 256-bit arithmetic, sppark/bellman-cuda-style carry chains) |
| `point`, `fields`, `ptx`, `cuda_mem_pool`, `timer` | shared support |

## What was left behind (and why)

- **Constraint-evaluation lanes** (`evaluate_constraints`, `evaluate_common`,
  `evaluate_wide_fibonacci`, `evaluate_poseidon_constraint`, `framework_plan_interpreter`,
  `component_*_generated`, `eval_at_row.cuh`, `logup.cuh`): hardcoded to the prototype's
  component set / generated ABI. In this repo the seam is
  `stwo_constraint_framework::FrameworkBackend`; a new backend gets a correct
  constraint path for free via `evaluate_constraint_quotients_via_cpu` (see
  `crates/backend-metal/src/backend/backend.rs` for the pattern) and can graduate to a
  native GPU lane later.
- **CMake build + Rust crates** (`stwo-cuda`, `stwo-cuda-sys`): pinned to an old vendored
  stwo; the FFI surface should be rebuilt against this repo's traits instead of adapted.

## API delta: the prototype's vendored stwo vs this repo

The prototype pins stwo at ~`833bb24e`. The trait surface has since moved; the kernel
*math* is reusable, but the Rust wrappers must change shape:

- `FriOps::fold_line` now takes an `alphas` slice (`alphas[i] = alpha^(2^i)`) and folds the
  entire chain in one call; the `fold_line.cuh` entry point is per-layer (`qm31 alpha`), so
  the wrapper loops and chains buffers (see the Metal port's `fri.rs` for the submit-async,
  wait-on-last pattern).
- `fold_circle_into_line` returns the `LineEvaluation` instead of accumulating into one.
- `QuotientOps::accumulate_quotients` gained `log_blowup_factor` + twiddles with
  *subdomain* semantics: the kernel runs on the evaluation subdomain, then the result is
  interpolated and re-extended with subdomain twiddles extracted from the full tree
  (`extract_subdomain_twiddles`). The legacy whole-domain path in `quotients.cu` still
  works but wastes a blowup factor of work.
- `PolyOps` additionally requires `split_at_mid` / `join_at_mid` and barycentric
  evaluation (`barycentric.cu` maps to the latter).
- `MerkleOpsLifted` requires `PackLeavesOps` (packed leaves for the FRI commit phase), and
  commitment is pruned (`commit_pruned` drops the bottom 4 layers; decommit recomputes
  leaf hashes from raw column bytes — host reads must be canonical-byte exact).
- `GrindOps` is byte-equality-sensitive: a GPU grind that returns *a different valid
  nonce* changes proof bytes. Either reproduce `SimdBackend::grind`'s search order
  exactly or delegate grinding to `SimdBackend` (the Metal port delegates).

## Known issues in the kernels (fix before/while wiring up)

Found during review of the prototype; all are inherited by these copies:

1. **M31 `mul` reduction is canonical-input-only** (`fields.cu:3`): the double-fold
   `u & P` reduction can emit `P` (a non-canonical zero) at the boundary. Safe while
   every producer feeds canonical inputs, but Merkle leaf hashing reads raw bytes —
   a single non-canonical value breaks proof byte-equality. Canonicalize at the
   commitment boundary or fix the reduction.
2. **`cudaDeviceSynchronize` after (nearly) every launch** — 79 call sites. This forfeits
   all pipelining. Move to per-stream events; note the Metal port's lesson: async
   submission with in-order queues is sound for *GPU* consumers only — any host-side
   read of an in-flight buffer needs an explicit fence (we hit exactly this race in the
   M31-channel Merkle leaf builder).
3. **Per-element `at()`/`set()` do a `cudaMemcpy` each** (`utils.cu:117-119`). Any
   wrapper that exposes `Column::at` over device memory will be catastrophically slow if
   called in a loop; mirror the unified-memory/host-cache design of the Metal columns or
   batch the reads.
4. **Separable compilation can block field-op inlining**: `fields.cu` is its own translation
   unit, so `mul`/`add` can cross TU boundaries as real calls. Set
   `STWO_CUDA_ARCHIVE_LTO=1` to compile ordinary objects with `code=lto_N` and enable `-dlto`
   at their matching device link, or make field ops header-inline. The scoped switch leaves
   generated AOT cubins unchanged.
5. **Quotient denominator inverses must stay row-local**: both quotient entry points now
   compute and consume each inverse in canonical sample order. Do not reintroduce an
   O(samples × domain) global denominator slab; the prepared pass/byte model pins the
   removed residency and logical traffic.

## How to turn this into a backend

1. Create `stwo-backend-cuda{,-sys}` crates mirroring `crates/backend-metal{,-sys}`
   (column types over device buffers, trait impls per the table above).
2. Implement `FrameworkBackend` via `evaluate_constraint_quotients_via_cpu` and
   `FromSimdColumns` for witness transfer.
3. Gate on `stwo-backend-testkit`:
   ```rust
   stwo_backend_testkit::assert_backend_conformance::<CudaBackend, Blake2sMerkleChannel>();
   stwo_backend_testkit::assert_backend_conformance::<CudaBackend, Blake2sM31MerkleChannel>();
   ```
   The kit runs op-level differentials against `CpuBackend` plus end-to-end **proof
   byte-equality**; it is the acceptance criterion the Metal port passed.

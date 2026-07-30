# stwo-backend-cuda

A CUDA prover backend for stwo, ported from the
[`stwo-cuda`](https://github.com/starkware-libs/stwo-cuda) prototype (Nethermind-lineage
kernels, staged and hardware-validated in `crates/backend-cuda-kernels`) and adapted to
this repository's backend extension points.

## Status

- **Conformance-green on real hardware** (RTX 3090, CUDA 11.8, RunPod): the full
  `stwo-backend-testkit` suite passes for both `Blake2sMerkleChannel` and
  `Blake2sM31MerkleChannel` — op-level differentials vs `CpuBackend` plus end-to-end
  **proof byte-equality** and repeated-prove stability. Both channels passed on the
  first runtime attempt; every lesson from the Metal port (host-side M31 Merkle path,
  no pointer-keyed caches, grind delegation) was baked in up front.
- **Compile-gated**: without `nvcc` the kernels crate builds panicking stubs, this crate
  compiles everywhere, and the conformance tests skip. On a CUDA box the build script
  compiles each kernel (`-dc`), device-links (`nvcc -dlink` — required for `-rdc=true`;
  the Rust linker performs no device linking), and archives everything.

## Performance

End-to-end prove of the testkit reference AIR (16 base columns, degree-2 constraints,
`Blake2sMerkleChannel`), RunPod community RTX 3090 + 128-vCPU host, warm-best of 3
(`tests/bench_prove.rs`):

| rows | CudaBackend (RTX 3090) | SimdBackend (same host CPU) | CUDA advantage |
|---|---|---|---|
| 2^16 | 154 ms (425k rows/s) | 235 ms (279k rows/s) | 1.5× |
| 2^18 | 531 ms (494k rows/s) | 984 ms (266k rows/s) | **1.9×** |

The advantage grows with size: CUDA throughput rises (425k → 494k rows/s) while the
host's SIMD throughput is flat. This is the opposite shape from the Metal backend on
Apple Silicon (see `crates/backend-metal/README.md`), where an exceptionally strong
CPU and per-dispatch overhead leave the GPU behind — on typical x86 cloud hosts the
discrete GPU wins, and these numbers still include all the v1 host roundtrips below.

## Big-trace proving (architecture per the SIMD-vs-CUDA performance review)

Requirements applied from the NitrooZK/AntChain performance review (RTX 5090 deck,
Feb 2026) and their [`NitrooZK-stwo`](https://github.com/AntChainOpenLabs/NitrooZK-stwo)
fork:

- **Never-release memory pool**: the default CUDA mem pool's release threshold is set
  to `UINT64_MAX` at first allocation, so warm proves reuse device allocations instead
  of paying `cudaMalloc`/`cudaFree` per run (the deck reports stable warm VRAM and a
  ~280 ms cold→warm saving on their workload).
- **Low-memory big-trace mode**: their L1 roadmap item ("spill evaluations after each
  tree commit, keep coefficients, regenerate per group at decommit" — the prerequisite
  for proving sn_pie-scale traces that OOM a 32 GB card) is *exactly* this repository's
  generic low-memory machinery (`CommitmentSchemeProver::set_low_memory`): committed
  LDE evaluations are compacted to half-size coefficient columns after commit (the
  blowup-sized buffers return to the pool) and regenerated **bit-exactly** at decommit.
  It is generic over `Backend` and now validated on `CudaBackend`:
  conformance (proof byte-equality, both channels) passes with the mode ON.

Measured on an H100 80GB (224-vCPU host), reference AIR, warm-best, end-of-run pool
footprint (`STWO_BENCH_LOW_MEMORY=1` toggles the mode in the bench/testkit harness):

| rows | CUDA (lm off) | CUDA (lm on) | pool footprint off → on | SIMD (host CPU) |
|---|---|---|---|---|
| 2^18 | 622 ms | 658 ms (+6%) | 752 → 720 MB | 1219 ms |
| 2^20 | 2337 ms | 2543 ms (+9%) | 1168 → 1072 MB | 5281 ms |
| 2^22 | 9393 ms | 10602 ms (+13%) | 2800 → 2416 MB (−14%) | — |

Notes: CUDA is 2.0–2.3× the 224-vCPU SIMD run at these sizes. The VRAM saving is
modest on this 16-column AIR (quotient/FRI working set dominates); the mode targets
many-tree, many-column workloads (Cairo's preprocessed + base + interaction trees)
where committed-LDE retention is the dominant term — the deck's 51 GB interaction
trace is the motivating case. The probe reports the end-of-run pool footprint, not
the true in-flight peak; a high-water-mark probe is future work.

## stwo-cairo GPU witness pieces

- **GPU preprocessed columns** (`GenPreprocessedTrace` hook in the stwo-cairo fork):
  the Seq, RangeCheck, and BitwiseXor families generate directly on device (family
  caches keyed by family *parameters* — content, never pointers); other columns take
  the SIMD path per column, and id-parse failures degrade to SIMD, never to wrong
  values. Validated: the Cairo e2e (which pins the preprocessed root) stays
  byte-equal. `PREPROCESSED_TRACE_GPU_GENERATE=0` forces the SIMD path. Batch-NTT
  commitment interpolation and the Pedersen GPU table are the queued follow-ups.
- **Big-trace mode in prove_cairo**: `STWO_CAIRO_LOW_MEMORY=1` enables the
  compact/regenerate low-memory machinery for the whole Cairo prove — validated
  byte-equal on the all-opcode e2e (+~3% time). True sn_pie-scale (~25M steps, the
  51 GB OOM case) validation still needs the sn_pie input artifact (~130 MB, not in
  this repo).

## Stream-ordered execution (rebuild round 3)

Implementation of the ranked plan in `docs/gpu-architecture-analysis.md`. The backend
was latency-bound by construction — ~10k blocking events per prove between per-launch
device synchronization and an allocator that created, synchronized, and destroyed a
private stream around every alloc/free. The rebuild:

1. **Stream-ordered execution.** Everything — kernels, copies, `cudaMallocFromPoolAsync`,
   `cudaMemsetAsync`, `cudaFreeAsync` — runs on the **legacy default stream**, which
   orders it all automatically. All 82 per-wrapper `cudaDeviceSynchronize` calls are
   gone (`STWO_CUDA_DEBUG_SYNC=1` restores them for kernel-level error attribution).
   Host reads happen exclusively through synchronous `cudaMemcpy`, which orders after
   prior default-stream work *and* blocks until the data is host-visible — the fences
   are structural, not sprinkled. The decommit gather kernels were moved off private
   streams for exactly this reason (a private-stream kernel could race in-flight
   default-stream writes — the Metal `queue_drain` bug class). The discipline is
   documented at the top of `cuda/utils.cuh` and `cuda/cuda_mem_pool.cuh`.
2. **Statement-independent JIT kernels + persistent PTX cache.** The lowering hoists
   *every* ext constant (channel-drawn lookup elements, logup cumsum shift) out of the
   bytecode into a runtime parameter buffer, so the semantic hash — and the compiled
   kernel — depends only on the AIR structure. Compiled PTX persists to
   `$STWO_JIT_CACHE_DIR` (default `~/.cache/stwo-jit`), keyed by
   (semantic hash, GPU arch, `CODEGEN_VERSION`): new statements, new inputs, and new
   processes all reuse kernels. `STWO_JIT_LOG=1` reports per-kernel readiness time and
   cache source.
3. **Batched NTT everywhere.** `evaluate_polynomials` is overridden to group columns by
   evaluation size with one multi-column NTT per group (mirror of
   `interpolate_columns`); the quotient tail runs its 4 coordinate columns as one
   batched inverse + one batched forward NTT; the redundant extend-then-copy in
   `evaluate_into` is one copy plus one tail memset.
4. **Pinned witness ingestion.** `from_simd_evals` packs SIMD columns in parallel
   (rayon) into a process-wide pinned staging buffer (1 GiB cap, batched) and uploads
   from page-locked memory — replacing hundreds of sequential allocate-zero-copy
   roundtrips.
5. **Waste bundle.** Fused in-kernel accumulate (the JIT kernel adds into the
   accumulator coordinates in place; no scratch columns, no separate accumulate pass);
   FRI fold allocates 4 independent buffers instead of cloning uninitialized garbage
   3×; `split_at_mid`/`join_at_mid` and `extract_subdomain_twiddles` are device-side
   D2D copies (previously full host roundtrips — multi-GB over PCIe at big-trace
   sizes); the H2D upload path no longer zero-fills buffers the copy overwrites.

Deliberately not done: per-call barycentric OODS evaluation is kept (after item 1 each
call is one launch plus a 16-byte fenced readback; batching would touch the generic
PCS flow for ms-scale gains), and `cuda_malloc_uint32_t` still zero-fills (now as a
cheap stream-ordered memset) because flipping it to true uninitialized memory would
turn any not-fully-written buffer into nondeterminism — that flip needs the
conformance gate per call site.

**Round 4 (trace-driven, same 3090):** a phase-trace profile found the GPU idle
75-93% of the warm prove, dominated by an uninstrumented decommit phase doing ~100k
per-element 4-byte PCIe readbacks (`Column::at` per column x query — the long-standing
"GPU floor", nearly size-independent at 6.7-9.7 s), with OODS host-side weight
computation second (3.8 s). Fixes: `Column::gather_unreduced` (one gather kernel + one
D2H per column, feeding the existing sparse `decommit_gathered` path) and device-side
barycentric point vanishings (reusing the quotient kernels' point generator). Result:
fib 1M warm 14.7 -> **5.37 s (1.37 MHz, 2.1x same-host SIMD; 0.73 s/1M steps on a 3090
clears NitrooZK's published 5090 number)**; fib 65k 8.1 -> 0.87 s; ec 1024 11.2 ->
1.36 s. The Prove STARKs core is 10.7 s -> 813 ms; the prove is now witness-bound.

**Round 3 validation (RTX 3090, same-host interleaved A/B vs the round-2 code, all
gates byte-equal at every step):** cold proves are **2–4.7× faster** (fib 1M 37.4→18.7 s,
fib 65k 36.7→10.2 s, ec 1024 47.7→13.5 s) — first-prove latency is now warm+1–3 s
because the disk PTX cache turns per-statement NVRTC compiles (~1.8 s/kernel) into
1–3 ms loads, across processes and inputs. Warm proves improved 2–9%: at these sizes
the warm path is GPU-compute- and host-witness-bound, not launch-latency-bound, so
the sync removal mostly bought correctness headroom (no fence discipline to maintain
by hand) rather than wall-clock. Full tables and the cross-host caveat:
`gpu_benchmarks/RESULTS.md` in the stwo-cairo fork.

## Grinding

- **GPU for the non-M31 channel** (ported from NitrooZK's `grind_blake2s.cu`): chunked
  `atomicMin` search returning the *lowest* valid nonce, nonce-equal with `SimdBackend`
  (testkit-gated on hardware), ~200× at production `pow_bits` per their measurements.
  The M31-output channel still delegates to `SimdBackend` (its PoW hash differs at
  finalize; NitrooZK does the same).

## Fixes over the prototype

- Three **UB transmutes** between `TwiddleTree<CudaBackend>` and `TwiddleTree<CpuBackend>`
  (their `Twiddles` types have different layouts: device-pointer struct vs `Vec`)
  replaced with a download-and-convert helper.
- The `set_len`-after-`with_capacity` device-download idiom (uninitialized `Vec`
  exposure) replaced with zero-initialized buffers.
- `MerkleOpsLifted` genericized over `IS_M31_OUTPUT` (the prototype only supported the
  non-M31 hasher); `QuotientOps`/`FriOps`/`PolyOps` adapted to the current trait surface
  (alphas-slice `fold_line`, returning `fold_circle_into_line`, subdomain quotient
  semantics, `join_at_mid`, `PackLeavesOps`).
- Dropped lanes: capability/planner registries, framework plan/overlay (bytecode
  constraint dispatch), Poseidon252 channel (kernels staged in
  `backend-cuda-kernels/cuda/`, lane unported), prototype witness generators.

## stwo-cairo

Full Cairo e2e proving benchmarks in the stwo-book format live in the stwo-cairo fork
at `gpu_benchmarks/RESULTS.md`, including the optimization journey: after register
compaction, the pointer-table trace ABI, explicit-key prove-cycle caches, the OODS
weights fix, and statement-independent NVRTC kernels, **the GPU wins every
multi-million-cycle workload on the same host** (fib 1M: 13.2 s vs 24.3 s SIMD, 1.84×;
≈1.8 s per 1M VM steps on an RTX 3090 — at NitrooZK's published 5090 base adjusted for
GPU generation). Small workloads remain SIMD's (the ~7 s GPU floor = per-launch
synchronization, per-column OODS launches, CPU witness transfer); the launch/sync
re-architecture analysis for the next 5-10× is in progress.

The fork at `teddyjfpender/stwo-cairo` (branch `generic-backend`) proves real Cairo
programs on this backend: `prove_cairo::<CudaBackend, Blake2sMerkleChannel>` with the
witness generated on `SimdBackend` and transferred via `FromSimdColumns`. Gate (passes
on RTX 3090): `test_prove_verify_all_opcode_components_cuda` proves + verifies the
all-opcode program and asserts the serialized proof felts are **identical** to the
SIMD backend's proof. Note from reviewing NitrooZK's production fork: their base and
interaction traces are also CPU/SIMD-generated — their GPU witness advantage is
preprocessed-column generation and batched NTT, both incremental follow-ups here.

## JIT constraint lane (default GPU path)

Constraint kernels are **generated from this build's own AIR**: the component's
constraint tree is recorded once to bytecode (the same recording-evaluator lane as the
Metal JIT, logup included), emitted as self-contained CUDA C with an **explicit C ABI**
(no Rust struct reads — the failure mode that disqualified the precompiled kernel set
below is impossible by construction), compiled via NVRTC at first use, and cached by
the bytecode's **content semantic hash** (never pointers). Validated on RTX 3090:
conformance byte-equal with the lane engaged, and the Cairo all-opcode e2e passes with
**all 46 components on the JIT lane** and the proof byte-identical to SIMD.

- Lane order per component: precompiled kernels (opt-in) → JIT → CPU pointwise, all on
  one accumulator claim. `STWO_CUDA_DISABLE_JIT` forces CPU;
  `STWO_CUDA_CONSTRAINT_VERIFY=1` differentially checks the JIT lane per component.
- Statement independence: every ext constant (lookup elements, cumsum shift) is hoisted
  into a runtime parameter buffer during lowering, so the bytecode hash is a pure
  function of the AIR — kernels are shared across statements, inputs, and (via the
  on-disk PTX cache) processes. The fused kernel also performs the accumulator update
  in place; a `false` return guarantees the accumulator was untouched (CPU fallback
  stays sound).

## Per-component constraint kernels (opt-in)

The NitrooZK constraint lane is ported: ~250 generated per-component kernels with
FNV1a-name dispatch, a driver that derives each component's dispatch name from its type
path (no stwo-cairo edits needed), CPU fallback **on the same accumulator claim**, and a
differential-verify harness (`STWO_CUDA_CONSTRAINT_VERIFY=1`) that runs both lanes and
reports per-component mismatch fingerprints while keeping the CPU result.

**Verdict on this stack**: all 44 dispatched components mismatch on 100% of rows from
row 0 — the eval-struct-layout / AIR-revision skew fingerprint. The kernels were
generated against NitrooZK's stwo v2.1.1 and their stwo-cairo AIR, and read raw Rust
struct layouts from that build; our stack is current-upstream stwo with a regenerated
AIR. The lane is therefore **opt-in** (`STWO_CUDA_ENABLE_CONSTRAINT_KERNELS` or
`STWO_CUDA_CONSTRAINT_ALLOWLIST`) until kernels are regenerated against this AIR
revision; the verify harness is the qualification gate (0 mismatches = promotable).
The dispatch infrastructure and harness are the durable parts: regenerated kernels are
drop-in testable per component.

## Testing

```bash
# Anywhere (stub build; conformance skips without nvcc)
cargo test --release -p stwo-backend-cuda

# On a CUDA box — the decisive gate
STWO_CUDA_NVCC=/usr/local/cuda/bin/nvcc cargo test --release -p stwo-backend-cuda

# Benchmarks
BENCH_LOG_N_ROWS=18 cargo test --release -p stwo-backend-cuda --test bench_prove -- --ignored --nocapture
```

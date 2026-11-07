# M8 T5 round 1: register-pressure scheduling of the AOT constraint kernels

Labels: **[M]** measured (receipt in this directory or the pod path named), **[D]** arithmetic on measured numbers, **[E]** estimate.

## What was slow and why

- Every single-group AOT module larger than 32 KiB goes through `bound_ssa_module`
  (`scripts/rv64_cuda_partition_grouped.py`). It gives each live SSA value a **volatile** local-memory slot and splits the
  body into noinline (sometimes rdc) instruction slices. Every operation therefore loads its operands from, and stores its
  result to, per-thread local memory.
- On 24628607 (warm, retained M7-P1 trace) these bank-lowered kernels cost **631.8 GPU-ms per request** [M]. The Keccak truth
  role 0 shards 43–49 alone cost **590.5 ms** [M], and shard 47 by itself 284 ms (`admitted-census.json`).
- Shard 47 is one 16,255-operation group whose largest root is a single 20,440-node LogUp fraction sum. The root-first
  postorder computes the whole denominator chain before the numerator chain, so every denominator stays live. The simulated
  peak is **2,827 live words** per thread; the bank frame is 11,368 B, and `cudaFuncGetAttributes` reports **11,664 B** of
  local memory per thread [M].
- That frame is also why `STWO_RV64_DEVICE_ARENA_STACK` defaults to 12,544 B. At that stack size the device reserves about
  12,544 B × 1,536 threads × 170 SMs ≈ 3.3 GB of local memory per GPU [D].

## Change (scripts only; no shared source edited)

- `scripts/rv64_cuda_aot_register_schedule.py` takes the **original** SSA group from the raw catalogue and changes only the
  order and the storage:
  - **Order:** it picks whichever topological order has the smaller simulated live set: the native evaluator's recording
    order, or the emitted postorder.
  - **Reloads:** input masks and parameters are re-read at each use instead of being held.
  - **Roots:** each root term is folded into the result as soon as it is computed.
  - **Output:** plain SSA. ptxas allocates the registers; there are no volatile banks.
- Why this is bit-exact: every operation applies the same op to the same operand values, and canonical M31/OM31 addition
  is order-independent. `scripts/tests/test_rv64_cuda_aot_register_schedule.py` interprets the original and scheduled
  programs under one semantics and requires identical results. On the real Keccak groups 174–176 the folded values are
  equal and the operation multisets are identical.
- Peak live words after scheduling [M, simulation]:
  - group 174 (shard 47): 2,827 → 205;
  - 175 (shard 48): 104;
  - 176 (shard 49): 177;
  - 170–173 (shards 43–46): 48–68.
- `scripts/rv64_m8_aot_register_relink.py` builds the image by relinking the frozen `m7-combined-residency` link line:
  - **Kept:** every admitted kernel.
  - **Added:** the scheduled kernels, as `<symbol>_t5`.
  - **Dispatcher:** one generated TU replaces the two catalogue dispatchers. It dispatches the admitted catalogue unless
    **`STWO_RV64_M8_AOT_REGISTER_SCHEDULE=1`**, and any other value fails closed. Its two
    function bodies are the admitted dispatcher TUs themselves (each sha-checked against the admitted object's recorded
    dependencies, as are all headers), with only the mode check and the catalogue selection edited in; the review
    regeneration reproduces img1's `t5_composition_dispatch.cu` byte for byte (sha256 b6f163da…) [M].
  - **Rebuilt objects:** the four frozen-link objects whose build directories were deleted are rebuilt from source, as the
    T2/T4 images did.
- Kernel names, arguments, y-grids and catalogue geometry are unchanged. The GPU-native path picks the change up by
  relinking its own base link receipt with the same plan (`--base-link`).

## Kernel A/B (CUDA events, `tests/cuda/rv64/aot_register_schedule/bench_truth.cu`)

- **Method:** the admitted object and the new object, linked into one binary; same inputs, same initial output,
  interleaved, median of 7–9 reps.
- **Parity:** all 33 runs bit-identical (`kernel-ab.json`).
- **Row counts:** reduced, because an orphaned service held 30.1 GB on each GPU throughout.

| kernel | rows | admitted | scheduled, `(128,4)` | other variants |
|---|---:|---:|---:|---|
| truth 0 shard 43 | 2^16 | 1.174 ms | **0.569** | (128,6) 0.590 |
| truth 0 shard 44 | 2^16 | 1.962 | **0.857** | (128,6) 0.941 |
| truth 0 shard 45 | 2^16 | 1.973 | **0.837** | (128,6) 0.929 |
| truth 0 shard 46 | 2^16 | 1.749 | **0.826** | (128,6) 0.911 |
| truth 0 shard 48 | 2^16 | 3.850 | **0.832** | none 1.279, (128,3) 1.298, (128,5/6/8) 1.02 |
| truth 0 shard 49 | 2^17 | 6.049 | **1.616** | none 2.381, (128,3) 2.048 |
| joined_domain_20 | 2^20 | 1.125 | **0.809** | none 0.853; original order + bounds 1.41–2.62 |
| projection_case_20 | 2^20 | 1.676 | not changed | (128,4) 1.937, (128,5) 2.369, (128,6) 3.595 |

- **Shard 47 (16,255 ops in one group)** could not be compiled as one function: cicc (with `__launch_bounds__`) or ptxas
  (with `--maxrregcount=128`, and even with no cap) went past the 40 GB RSS cap [M, 3 attempts]. The pod's 92 GB container
  cgroup is shared, and one uncapped attempt triggered the cgroup OOM.
  - Fix: `--slice-ops` cuts the scheduled order into noinline slices at minimal-live boundaries. Values live across a cut
    travel through small ping-pong local arrays, and each slice returns its partial fold.
  - Shard 47: 7 slices of about 2.3k ops, with 137 words carried per cut. It compiles in 394 s at 4.68 GB peak RSS
    [M], with 128 registers and a 2,464 B stack.
  - Cost of slicing on its own [M, bit-exact]: shard 48 0.834 → 0.864 ms; shard 49 1.626 → 1.436 ms.
- **Image size bound.** The admitted `.so` is 1.975 GB, and x86-64 RIP-relative relocations cap it at 2 GiB. The flag-gated
  image keeps both kernel copies, so the 80 curve-role shards (0.47 GB of new objects [M]) do not fit; the link fails with
  "relocation truncated to fit". They are deferred to round 2 in `plan-roles-5-6-10-14.json`.
  - Their representative A/B [M, 2^16 rows, bit-exact, admitted → (128,4)] is 0.20–0.40× of the admitted time:
    5_24 0.927 → 0.375 ms, 6_11 0.938 → 0.378, 5_33 0.765 → 0.298, 6_26 0.786 → 0.284, 14_6 1.048 → 0.332,
    12_6 0.630 → 0.148, 13_12 0.939 → 0.241, 10_4 0.231 → 0.046, 11_10 0.761 → 0.264.
  - About 42 ms per request of these run on 24628607 [M trace].
  - Round-2 options: replace mode once the gated A/B has proven the kernels; dropping `-lineinfo` (object size ×0.53 [M]);
    or a second library.
- **Core split shards** (joined 44 shard 26 etc., 54 ms per request): `c44_26` reads 298 distinct parameters and still
  spills 13.9 KB even with shared-memory parameter staging (r2 branch). Left as admitted.

## Expected effect (24628607, warm)

Per-request admitted ms [M trace] × the measured kernel ratio [M]:

| kernel | admitted, ms/request | ratio | saved, ms |
|---|---:|---:|---:|
| shard 43 | 26.5 | 0.485 | 13.6 |
| shard 44 | 43.1 | 0.437 | 24.3 |
| shard 45 | 43.2 | 0.424 | 24.9 |
| shard 46 | 44.5 | 0.472 | 23.5 |
| shard 48 | 86.1 | 0.216 | 67.5 |
| shard 49 | 62.8 | 0.267 | 46.0 |
| joined_domain_20 | 55.6 | 0.72 | 15.6 |

- Total without shard 47: **−0.215 GPU-s per request [D]**.
- Shard 47 at the shard 48/49 ratio (0.22–0.27) would add −0.21 GPU-s [E].
- Total with shard 47: **about −0.42 GPU-s per request [E]**.

## Gate and request-level results

See `gate.json` and `ab-24628607.json` once pipe1 has run (`/workspace/m3/runs/m8-opt-T5-aot-constraint-regs/pipe1.status`).

# T7: GKR mixed-oracle batch sumcheck (round 2)

Branch `codex/rv64-m8-opt-T7-gkr-batch-sumcheck`, cut from `codex/rv64-m7-integrate @ c72b51646`.
Labels: [M] measured, [D] derived from measured values, [E] estimate.

## What changed
- **Product files:** `src/backends/cuda/native/rv64/{batch.cu, batch_transition.cuh, round.cuh}`.
  - `round.cuh` only gains new functions (`RoundPrelude`, `advance_round_with_terms`). Its existing functions and every other TU that includes it are unchanged.
  - `batch_oracles.cu` and `fold_sum.cuh` were claimed but not changed.
- **`batch_round_par`** (new kernel, one 160-thread CTA) replaces `batch_round<<<1,1>>>` when `STWO_RV64_M8_GKR_BATCH_PAR=1`.
  - The flag is read once per process and is off by default. Any value other than `0` or `1` rejects in the entry point.
  - Entry points (`stwo_rv64_batch_round_on`, `stwo_rv64_batch_tail_on`) and the `BatchState` / `RoundRecord` ABI are unchanged. The default path and the GPU-native job path both pick it up from the env alone.
  - **Oracle warps (4).** Thread i owns oracle i: load, canonical check, then `weight = weights[i] * corrections[i]` and the two weighted products. A warp-shuffle and smem tree reduce follows.
  - **Helper warp (1).** It computes the round prelude while the oracle warps work: the one norm-descent inversion, plus every product that does not depend on the raw sums. It uses 4-lane **group OM31 products**: each lane computes one QM31 partial product (`a0b0`, `a1b1`, `a0b1`, `a1b0`), then they shuffle and sum. That is `mul()`'s exact value at QM31 latency. The helper warp then computes the raw-dependent terms (`r0`, `r2`, and the cubic as a linear form in `raw0`, `raw2` and `claim − 2·constant`). After the draw it computes the next claim.
  - **Thread 0** runs only additions, the Blake2s hash of the record and the draw.
  - **Post-draw.** Oracle threads update their own correction or sleeping claim in parallel, with `eq = (1−y) − x(1−2y)` (one product).
- **`batch_tail<true>`** (the opt-in persistent tail) calls the same block transition body: `advance_batch_round_block<128, 256>`.
  - So the per-round kernel and the tail keep one transition authority.
  - `batch_tail<false>` and `batch_round` are the original text.
- **Why it is bit-identical.**
  - Every M31 operation returns the canonical representative. Addition and multiplication are exact field operations, so re-association and parallel reduction order cannot change any word.
  - Status precedence is unchanged: state status, then order (count, next round, per-oracle heights), then field, then pole.
  - Every failure returns before weights, corrections, sleeping claims or the transcript change. The record is cleared exactly as `prepare_record` clears it.

## Frontier
- Airbender v3 (`gpu/gkr/native/gkr/backward/window_tail.cu`) has the same split.
  - Partial sums come from parallel kernels; the round update (`run_round_update_single_thread`) is single-threaded.
  - But it reduces only 2 values, not up to 128 weighted oracles.
- sppark and ZisK have no GKR batch-sumcheck equivalent.

## Kernel parity (`batch_par_bench.cu selftest`, the shipped TU included verbatim) [M]
- **Round cases.** 304 cases compare state + record bitwise after every round, `batch_round` vs `batch_round_par`.
  - Shapes:
    - counts 1, 2, 5, 31, 32, 33, 63, 64, 65, 100, 127 and 128;
    - all-active and mixed heights;
    - 1 to 26 variables;
    - 40 long clean sumchecks.
  - Poisons:
    - a non-canonical raw coordinate;
    - an out-of-order round, or one out of range;
    - a height mismatch, a count mismatch, a variables mismatch;
    - pole at y = 1, 1/2 and 1/3;
    - a non-canonical y.
  - Final-status coverage: ok 75, order 94, field 63, pole 72.
- **Tail cases.** 48 cases compare state, records, masks and every fold bank: `batch_tail<false>` vs `<true>`.
  - Remaining rounds 1 to 4, base and OM31 numerators.
- **Result: 0 mismatched words.**
  - The selftest also caught a draft bug: idle tail warps wrote warp partials out of bounds. It was fixed before commit.

## Microbenchmark (CUDA events, rounds enqueued back to back after a clock warm-up, 7 reps; rep-mean median [min..max]) [M]

| shape (variables) | `batch_round` <<<1,1>>> | `batch_round_par` |
|---|---:|---:|
| 128 active (20) | 257.96 µs [257.90..258.02] | 21.13 µs [20.90..21.31] |
| 128 mixed (20) | 176.37 [176.20..176.61] | 21.04 [21.00..21.22] |
| 68 mixed (20) | 100.33 [100.23..100.56] | 20.91 [20.75..21.25] |
| 32 mixed (18) | 63.28 [63.18..63.52] | 20.77 [20.52..20.90] |
| 8 mixed (16) | 39.39 [39.35..39.53] | 20.42 [20.40..20.52] |
| 1 active (16) | 32.69 [32.68..32.81] | 20.40 [20.26..20.46] |

- Raw file: `kernel-bench.log`.
- The production census had `batch_round` at 2,250 launches with p50 70.8 µs and p90 94 µs (census2, M7-P1 trace). That falls between the 32-mixed and 68-mixed shapes.
- **Derived saving on 24628607 warm** [D]: `batch_round` 0.153 GPU-s becomes about 2,250 × 21 µs = 0.047 GPU-s, so **about −0.105 GPU-s**.
  - The launches form a serial chain on the native GKR stream, so the native window should drop by about the same amount [E].
- **Phase probe** (`%globaltimer`, n=128) [M]:
  - prelude ‖ oracle loop 4.8 µs;
  - terms 1.6 µs;
  - thread-0 hash + draw 7.3 µs;
  - post 3.0 µs;
  - launch/event about 1.7 µs.
- **The remaining floor** is the Blake2s chain (3 + 1 compressions) and the single-lane OM31 products per oracle.
- **How earlier versions compared** (same bench):
  - 4-lane group products in the helper warp: 26.9 → 21.1 µs.
  - Helper lanes spread over 4 warps / sub-partitions instead of one helper thread: 30.8 → 26.9 µs.
  - Hoisting the round state into registers made no difference, so it was reverted.

## Not pursued this round (measured)
- **Fused fold(r) + sum(r+1)** for large rounds (`oracles_fold_sum`, the existing opt-in `STWO_RV64_GKR_BATCH_FOLD_SUM`), CUDA events [M]:
  - It wins only at about ≥ 2^19 total OM31 rows: 8×2^20 729 → 624 µs; 48×2^16 302 → 224 µs.
  - It loses below that: 8×2^16 33 → 53 µs; base numerators 8×2^18 97 → 124 µs.
  - A size gate needs a jobs × count × coords model (host `batch.zig`), for an upside of about 0.02–0.04 GPU-s [E].
- **`oracles_sum` / `oracles_fold` at large sizes are already near the roofline** [M]:
  - fold 1.66–1.78 TB/s;
  - sum 1.23–1.31 TB/s; `__launch_bounds__(128,4)` gains ≤ 5%, and min-blocks 6 or 8 spill.
- **Small sums have a latency floor** of about 13–15 µs, from 10 single-lane OM31 products per term. The production total is under 0.03 GPU-s, so the upside is about 0.015 s.
- **Raising `batch_tail_rounds`** has no effect while the host gates the tail at `remaining <= 4` and the tail flag is off by default.

## Request-level (pending)
- Pipeline: `pipe1.sh` (tmux `t7-pipe1` on the pod).
  1. Wait for ≥ 5 GB free disk.
  2. Compose `img1`: the frozen m7-combined-residency link command, sha-checked, with `batch.cu` plus the 4 missing frozen replacements recompiled.
  3. Wait for the GPUs to be < 2 GB used.
  4. Gate on the default path (26235156).
  5. Gate with the flag on (26235156 and 24628607).
  6. Canonical 3+3 on 24628607, one image, flag-only arms: `ab-preset.json`.
- Blocked at 03:10Z:
  - pod disk has 1.6 GB free (each opt stream holds a 2 GB composed image);
  - orphan pid 3302210 holds 30 GB on each GPU.

# GKR route: per-segment GKR memory, streamed + checkpointed storage by default

Block 24,628,607, 4-packet prefix (16,777,212 steps, 4 CPU + 8 truth proofs), V3 GKR route
(`rv64-word16-ethereum-gkr produce-candidate`), evmone v3 client, default
`conjectured128_b2_q108_p20_fold4` profile. Native jobs, request and resources are the
#313 recipe (`../rv64-gkr-route-speedups-20261102/request-gkr.json`, `resources.json`:
2 lanes x 8 workers, park MAIN, deferred local binding, 12 GiB fixed setup).
14-core M4 Max, 36 GB, AC power, memguard (`--gb 22`), no other heavy job running.
Old binary: merged `16f9fc378` code (= `19f228d37` source). New binary: this branch.
`run.sh` is the exact driver (adds `STWO_ZIG_PROFILE_OM_DOMAIN=1 STWO_ZIG_GKR_TREE_METRICS=1`).

**Proof bytes:** all 9 runs below produce the same `bundle.json`, `cells.bin`, `stage-one.bin`,
4 `cpu-*.bin` and 8 `truth-*.bin` (`proof-files.sha256`), equal to the #313 `cj4` receipt.
Every fresh receiver (`verify-prefix-candidate`) accepts.

## Memory/time trade-off (3 storage policies, same jobs)

| Storage (how selected) | Runs | Prove (s) | Peak RSS (GB) | GKR requested peak per CPU segment (GB) | Admitted per segment (GB) |
|---|---:|---:|---:|---:|---:|
| Dense: materialised N/D input + all upper layers (old default; now `STWO_ZIG_GKR_STREAM_BOTTOM=0`) | 4 | 48.48 / 48.40 / 48.01 / 49.25 (mean 48.54) | 22.6-23.5 | 12.41 / 10.22 / 10.36 / 10.35 | 17.13 / 14.14 / 14.33 / 14.32 |
| Source80: streamed bottom, dense upper (`STWO_ZIG_GKR_TREE_CHECKPOINTS=1`) | 2 | 46.92 / 47.05 (mean 46.99) | 19.0-19.8 | 7.94 / 6.54 / 6.63 / 6.63 | 10.18 / 8.41 / 8.52 / 8.52 |
| **Source68: streamed bottom + stride-2 checkpoints (new default)** | 3 | 49.64 / 48.83 / 49.59 (mean 49.35) | **14.33-14.34** | **2.685 x 4** | **6.71 / 5.55 / 5.62 / 5.62** (8.69 / 7.19 / 7.28 / 7.28 with the old 68 B/fact plan) |

Default change, mean of runs: prove 48.54 → 49.35 s (+1.7%, about 0.8 s; run-to-run spread is
~1.2 s), peak RSS 23.2 → 14.3 GB (-38%), peak footprint 26.5 → 12.8 GB, per-segment GKR requested
peak 12.41 → 2.69 GB (-78%), per-segment admission 17.13 → 6.71 GB (-61%). Source80 is the fastest
(-3% vs dense) but leaves 7.9 GB requested / 10.2 GB admitted per segment, too close to the 8 GB
GPU target. Numerical GKR time on CPU0: dense 5.7-5.8 s, source80 4.7 s, source68 6.0-6.1 s (the
lazy odd-level recompute); other phases absorb most of it in the wall time.

## Per-segment GKR breakdown (CPU0: 124.09 M padded facts, largest instance 2^26 facts)

| Component | Bytes | Live at peak in |
|---|---:|---|
| Raw input planes N (M31) + D (OM31), 36 B/fact | 4.467 GB | dense only |
| Upper fraction tree, every layer (N/2 secure pairs + ...), 64 B/fact | 7.942 GB | dense, source80 |
| Even-level checkpoint bank (heights 2, 4, ...), 64/3 B/fact | ~2.65 GB | source68 construction |
| Bottom first fold of the largest instance (2^25 OM31 pairs) | 2.147 GB | source68 peak |
| Eq table at the bottom layer (2^24 OM31) | 0.537 GB | source68 peak |
| Proof/artifact/metadata | ~0.2 MB | all |
| Peak = | dense 4.467 + 7.942 = **12.409**; source80 **7.942**; source68 2.147 + 0.537 = **2.685** | |
| Local binding columns (deferred: 0.247 projected + 0.495 final, 0.742 overlap) | 0.742 GB | after numerical, under the same cap, not on the peak |
| Retained MAIN (all proofs, parked to disk) | 7.15 GB reserved, 3.21 GB peak mapped | PCS stage, not GKR |

The three peaks are measured (`numerical_requested_peak_bytes`) and match the component
arithmetic exactly. Source68's peak is the same for all four segments because each has a 2^26-fact
largest instance. With source68 the process peak (14.3 GB) is no longer in a GKR phase: it is
reached in the composition commit of truth proof physical-0006, with other proofs in flight.

## Admission bound (source68)

`resource.zig` now charges `SOURCE_CHECKPOINT_BYTES_PER_FACT` = s + s/4 + 3s/8 = 52 B/fact for OM31
(was 68). Argument, in the code comment and `rv64-gkr-stream-bottom.md`: no raw plane exists;
all instances are at the same height in an outer layer; the bank (even levels) is below 2s/3 per
fact; at the bottom, the first folds of every instance total s per fact even unstaggered, a
nonresizing allocator's half copy adds at most s/4 per fact of the largest instance, and the Eq
table peaks at 3s/8 per fact of the largest instance. The existing exact-cap admission tests
(`admission_test.zig`: stream68 with resizing and nonresizing/copying backings, 12 mixed-height
instances, 16 synchronized equal folds) assert measured requested and original-capacity peaks
are within the plan at the plan's exact cap. On CPU0 the plan is 6.71 GB against 2.69 GB measured.

## Not done

- No further reduction of the bottom fold (2.15 GB): one more lazy round from the source would
  halve it at one more source pass. Not needed for the 8 GB target.
- Truth-proof GKR storage is unchanged (truths keep their own path).
- The resource JSON's `gkr_bytes` (32 GiB) cap is unchanged. The planner uses the per-CPU plan
  (stage-one estimate = 2 x MAIN + max(GKR plan, global budget)); with this recipe's 8 GiB global
  budget the lower GKR plan only lowers CPU0's estimate (8.69 → 8.59 GB term).
- Complete-block run not done (coordinator schedules those).

## Gates (this branch, ReleaseSafe, default env, `gates-summary.txt`)

`test-riscv64-services-gkr-local` (includes the exact-cap admission tests at 52 B/fact),
`truth-gkr`, `word16-v3-services`, `word16-combined-services`, `ethereum-chain`: all rc=0.
Prefix bundle byte identity: see the top of this file.

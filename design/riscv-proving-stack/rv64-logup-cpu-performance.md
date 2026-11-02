# RV64 LogUp / LogUp-GKR CPU prover performance

Status: measured on branch `codex/rv64-ge-logup` (base `e35a60ad9`), Apple
M-series host (10 performance + 4 efficiency cores, 36 GB), AC power, shared
with other agents (1-minute load average is recorded per run, 3-9). Final numbers come from one sweep of the head binary (`final-16c5cbf10.jsonl`,
load 5.7-6.0) against `baseline-e35a60ad9.jsonl` (load 3.1-3.8). All
numbers are medians of 2-5 repetitions of `rv64-logup-kernel-bench`
(ReleaseFast). Raw JSON lines, the sweep script and the configuration list
are in `vectors/reports/rv64-logup-cpu-performance/`.

Byte identity is the acceptance criterion for every change. Each benchmark
run prints a SHA-256 over its outputs (encoded GKR proof, final channel
digest, OOD point, artifact claims; or every committed interaction column
and claim). Every "after" digest equals the corresponding baseline digest
and, for GKR, the reference prover's digest. No protocol or transcript change.

## Reproduce

```
zig build rv64-logup-kernel-bench -Doptimize=ReleaseFast
zig-out/bin/rv64-logup-kernel-bench gkr 22 generic fast 8 3
zig-out/bin/rv64-logup-kernel-bench om31 20 fast 1 3
zig-out/bin/rv64-logup-kernel-bench logup 20 4 8 3
vectors/reports/rv64-logup-cpu-performance/sweep.sh BIN out.jsonl < configs.txt
python3 -I vectors/reports/rv64-logup-cpu-performance/summarize.py out.jsonl
```

Kernels: `gkr <log> singles|generic|mixed fast|reference <threads>`
(QM31 batch LogUp-GKR), `om31 <log> reference|fast <threads>` (services
shape: M31 multiplicity numerators, OM31 denominators, borrowed inputs),
`logup <log> <n_sums> <threads>` (frontend `generateParallelColumns`: two
fractions per sum, six-limb tuple denominators), `columns <log> <width>
<threads>` (engine `logup_columns.build`), `inverse <log> <threads>` (QM31
batch inversion in 4096 chunks), `eq <log>` (serial `mle_point.genEqEvals`).
Inputs are seeded PRNG data, not RV64 witnesses.

## Results

### LogUp-GKR (QM31, WGKR prototype and engine `gkr_prover_fast`)

| Configuration | Baseline | After | Speedup |
|---|---:|---:|---:|
| singles, 1 thread, 2^16-2^24 | 124-128 ns/leaf | 44-49 ns/leaf | 2.6-2.8x |
| generic, 1 thread, 2^16-2^24 | 132-137 ns/leaf | 56-59 ns/leaf | 2.3x |
| generic 2^22, 8 threads | 118.1 ms | 50.2 ms | 2.4x |
| generic 2^24, 8 threads | 458 ms | 167-202 ms | 2.3-2.7x |
| mixed batch 2^22 (3 instances), 8 threads | 227 ms | 91.6-106.5 ms | 2.1-2.5x |
| reference prover, generic 1 thread | 157-163 ns/leaf | (unchanged oracle) | |

Thread scaling after (generic 2^22, final sweep, load 6): 1 / 2 / 4 / 8 / 12
threads = 236 / 96 / 68 / 50 / 50 ms (baseline 558 / 242 / 175 / 118 / 111). Scaling stops near 8 threads: the round passes are
memory-bound (the 2^24 generic layer is 512 MiB of numerators+denominators)
and the host was shared.

### LogUp-GKR (OM31, services local GKR shape)

| Configuration | Reference (`gkr_prover_field`) | Engine fast | Speedup |
|---|---:|---:|---:|
| 1 thread, 2^14-2^20 | 490-508 ns/leaf | 151-170 ns/leaf | 3.0-3.4x |
| 2^20, 1 / 4 / 8 threads | 532.5 ms | 158.7 / 50.5 / 34.7 ms | 3.4 / 10.5 / 15x |
| 2^22, 8 threads | - | 111.7 ms (26.6 ns/leaf) | |

`services/gkr_local/child.zig` now uses the engine prover on the calling
thread (its bounded allocator owner is single-threaded), so services see the
1-thread 3.0-3.4x figure.

### LogUp interaction column generation

| Kernel | Baseline | After | Note |
|---|---:|---:|---|
| `generateParallelColumns` 4 sums, 1 thread 2^20 / 2^22 | 188.3 / 834 ms | 173.5 / 762 ms | 1.09x; packed n/d products |
| same, 8 threads 2^20 / 2^22 | 38.6 / 160.6 ms | 30.4 / 133.1 ms | 1.27x / 1.21x; no serial placement tables |
| same, 2 / 4 / 12 threads 2^20 | 179 / 70 / 32.7 ms | 160 / 60 / 27.0 ms | |
| `logup_columns.build` width 4, 1 / 8 threads 2^22 | 33.8 / 11.5 ns/fraction | not changed | serial final-column prefix sum limits scaling (3x at 8T) |
| QM31 batch inverse, 1 / 8 threads 2^22 | 7.8 / 1.0 ns/element | already packed | |

Profile of `generateParallelColumns` at 8 threads (2^21): row-pair
construction and pairing (`Chunk.run`, context denominators and
`d1*d2`, `n1*d2+n2*d1`) about 55 % of busy samples, placement into the
bit-reversed committed layout about 20 %, packed batch inversion about 20 %,
fraction products 6 %. The remaining cost is context-specific arithmetic, not
the shared kernel.

### Word16 interaction phase (end to end)

Not re-measured on this branch. The Word16 prefix benchmark rejects packets
containing service ECALLs, every evmone v3 packet available locally contains
them from the first 2^17 steps (495 at 2^17, 1,066 at 2^18, 4,530 at 2^20 on
block 26,235,156), and the reth guest used by the retained receipts is no
longer on the host; block 24,628,607 prefix proofs are excluded by policy.
None of the commits on this branch change the Word16 CPU/ALU/BINARY/SHIFT/LS
interaction generators (they already use packed batch inversion, two-wave
prefix scheduling and page preparation; see
`vectors/reports/rv64-word16-execution-20261031/interaction-pages-v1.json`:
1.40-1.42 s wall for the 4,194,303-step packet, 7.5 core-s).
So the measured end-to-end effect on that phase is none; the GKR gains apply
to the WGKR prototype and to services local GKR proofs.

## What changed

1. `core.fields.packed_extensions` (now exported): add/sub/splat/zero,
   even/odd deinterleave and interleave, exact lane sum for `PackedQM31x4`.
2. `lookups.gkr_prover_fast.ForField(QM31|OM31)`: one clone-free LogUp GKR
   prover (singles, generic, multiplicities; borrowed or owned inputs).
   - layers built once, folded in place; borrowed inputs never written;
   - build, round sums, folds and eq table four terms per AdvSIMD op;
     OM31 is a Karatsuba quadratic over packed QM31;
   - fold of round t fused with the sum of round t+1 (term i owns folded
     positions 2i, 2i+1, 2(n+i), 2(n+i)+1, so chunks partition the layer);
   - parallel eq table from prefix products with packed in-place doubling;
   - reference sumcheck self-checks kept.
   `logup_gkr/fast_gkr.zig` is now an adaptor; `services/gkr_local` uses it.
3. `air.logup.generateParallelColumns`: packed fraction products; placement
   computes `circleDomainIndexToCosetIndex(bitReverse(p))` directly instead
   of building two O(n) serial tables (16 B/row).

## Kernels to GPU primitives

| CPU kernel | GPU mapping | Notes |
|---|---|---|
| GKR layer build (`nextChunk`) | elementwise map, 2 -> 1 (coalesced pairs) | one launch per layer, or a fused multi-level tree reduction in shared memory for the bottom ~10 layers |
| round sum (`sumChunk`) | map + block reduction of 2 secure values (+ eq gather) | the dominant kernel; reduce in registers/shared memory, one atomic or second pass per round |
| fused fold + next sum (`foldSumChunk`) | same kernel as the round sum with an in-place fold prologue | removes one full read pass per round; keep fused on GPU |
| eq table (`eqTable`) | prefix products per block + in-block doubling (one thread per output) | or recompute eq on the fly from the point to save memory |
| mask / correction / transcript | host (scalar, O(rounds)) | per round only 4 coefficients cross the bus |
| batch inversion | per-thread Montgomery chains over strided chunks, or warp-level prefix-product scan | already chunked 4096 on CPU |
| interaction pairing + prefix (`Chunk.run`, prefix waves) | per-row map, then segmented inclusive scan (decoupled look-back) | the two-wave chunk/offset structure already matches a GPU scan |
| bit-reversed placement | gather by computed index (no table) | done on CPU by this branch |

## Remaining CPU work

- `logup_columns.build`: parallelize the final column's shift + coset-order
  prefix sum (serial, with three temporary copies).
- Row-pair construction in `generateParallelColumns` users: pack the
  pairing products across four rows.
- GKR scaling beyond 8 threads is memory-bound; a GPU or a recompute-eq
  variant is the next step. Services local GKR is single-threaded by its
  allocator design; giving it the production work pool needs a
  thread-safe budget owner.
- The OM31 numbers use the services shape but synthetic data; a services
  proof through `services/gkr_local` with real metadata was not timed here.

## Production route (on PR #308 head cb7f1f50b, after PR #309)

Every speedup above was measured against the *pre-#309* scalar `gkr_prover`. PR #309 replaced that prover's numerical loops with its own packed kernels (`src/prover/lookups/packed_rows.zig`, pooled through `row_work.zig`). So the real question is whether `gkr_prover_fast` still beats the current production prover. It does not.

The `om31` bench now runs `reference` (that is, production `gkr_prover.proveBatch`) on a scoped `WorkPool` of `threads` workers when threads > 1, which is how #309 parallelises. ReleaseFast, median of 3 runs. The host was on **battery power** with load about 2, so treat differences under about 5% as noise. Raw data: `vectors/reports/rv64-logup-cpu-performance/production-route-cb7f1f50b.txt`.

| shape | production (#309) | fast | fast / production |
|---|---|---|---|
| OM31 2^14, 1T | 2.37 ms | 2.75 ms | 1.16 |
| OM31 2^16, 1T | 9.42 ms | 9.30 ms | 0.99 |
| OM31 2^18, 1T | 32.9 ms | 36.4 ms | 1.11 |
| OM31 2^20, 1T | 130.5 ms | 146.7 ms | 1.12 |
| OM31 2^20, 4T | 45.6 ms | 46.3 ms | 1.01 |
| OM31 2^20, 8T | 33.9 ms | 32.8 ms | 0.97 |
| OM31 2^18, 8T | 13.3 ms | 13.3 ms | 1.00 |
| QM31 2^20 singles, 1T | 41.7 ms | 43.1 ms | 1.03 |
| QM31 2^20 generic, 1T | 50.8 ms | 53.9 ms | 1.06 |

Every pair produced the same SHA-256 over channel digest, OOD point, claims and round polynomials.

**Decision: keep #309's kernels.** The services `gkr_local` child and coordinator and the OM truth GKR are not routed through `gkr_prover_fast`. The reasons:

1. **No speed advantage.** The fast prover is slower at 1T and only matches production at 4-8T. Its 2.3-3.4x per-thread lead came entirely from the old scalar baseline.
2. **Missing production paths.** The coordinator's default policy is `stream_bottom = true`, `tight_admission = true` (`proveBatchSource` / `proveBatchSourceCheckpointed`), and the fast prover implements neither. It also has no owned-checkpoint path (`proveBatchOwnedCheckpointed`). At most it could replace the dense `proveBatch` branch, which production does not use by default.
3. **Allocator safety.** With `threads > 1`, the fast prover builds a `std.Thread.Pool` on the passed allocator. Pool closures are then freed from worker threads, which is unsafe with the single-threaded memory-budget allocator. With `threads = 1` it is safe but about 12% slower than production.

`gkr_prover_fast` stays in the tree as the engine behind the WGKR prototype (`logup_gkr/fast_gkr.zig`). The cherry-picked services hook (`proveLayers` in `gkr_local/child.zig`) was dropped while resolving the conflict, so `child.zig` is byte-identical to the PR #308 head. OM GKR proof bytes are therefore unchanged by construction; no new route was introduced.

What would still be worth porting from the fast prover is its fused sumcheck/fold layer, applied inside #309's pooled `row_work` structure rather than as a separate prover. Before doing that, re-measure on AC power.

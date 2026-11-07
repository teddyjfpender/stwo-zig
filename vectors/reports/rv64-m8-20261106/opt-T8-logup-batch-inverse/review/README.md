# T8 review (2026-11-07)

Reviewed 6c1854aec + 2bfada129 for correctness, measurement validity and code quality. Labels: [M] measured.

## Verified (no defect)
- **Inverse.** `descend`/`ascend` match `inverse_nonzero` (OM31 norm via `mul_u`) and `q::inverse` (QM31 norm a^2 - (2+i) b^2, CM31 conjugate). Padding rows use d = 1 so `batch_inverse` never sees zero. Invalid rows get d = 1, n = 0 and the same status bits 2/4.
- **Races / aliasing.** Each thread owns its K rows. `n` is re-read before that row's stores, so even `contributions == output` behaves like the original.
- **Tile scan geometry.** physical = brev6(low6(circle)) * M + brev(high(circle)). Chunk c sits in columns brev(c) (evens) and M-1-brev(c) (odds).
  - The lo range [r0, r0+32) and the hi range [M-r0-32, M-r0) are disjoint, and together they cover all M columns, with r0+32 <= M/2.
  - Shared memory is written in full before it is read; the pitch column is never read.
  - The parent and centre indices match `scan_carries`.
- **Stream order.** Every launch goes to `c.stream`. The tiled level-0 sums run first in the up-sweep, and the tiled apply runs last in the down-sweep.
- **Bench validity.** CUDA events wrap only the launcher. Rep 0 is a warm-up. Old and new are interleaved, and the refill uses the same seed per rep.
  - Caveat: the refill leaves shapes under ~96 MB L2-resident (2^14x13, scans <= 2^18) for both arms.
  - That matches production, where the row-sum plane is written immediately before the scan.

## Findings fixed (behaviour-neutral)
1. **Fail-closed order.** `t8::global_pairs` now rejects an invalid mode first, as `t8::prefix_scan` already did. Before the fix it reached Custody validation first.
2. **Tile geometry.** `tile_min_log` is now tied to the geometry by `static_assert(2^12 == 2 * tile_cols * tile_rows)`. The launch grid is `rows >> tile_min_log`.
3. **Duplicated index.** The row index inside a tile (brev6 slot) was written out twice; it is now the single helper `tile_slot`.
4. **Coverage gap.** Parity stopped at 2^19 pairs and 2^21 scans, but production shapes are 2^20..2^24. A new `parity-at` command adds explicit large shapes.

## Re-test [M] (pod, RTX 5090 GPU0, ~2.3 GB free next to orphan pid 3302210; binary sha256 d48b6b7d...)
- `parity 19`: **208/208 bit-identical** after the fixes (`parity.jsonl`).
- `parity-at` (`parity-at.jsonl`): all bit-identical, with injected non-canonical words and zero denominators:
  - 2^21x3 pairs (fused), status 6/6;
  - 2^22x2 pairs (fused), status 6/6;
  - scans at 2^22, 2^23 and 2^24, centre 0 and 1, status 10/10 and 2/2.
- 2^20x13 and 2^23x1 could not be allocated on the shared GPU (OOM, `rc.txt`).

## Open (not in T8-owned files)
- **Launch counter.** With the flag on, `resident.zig:691` records `2 + plan.dispatches(true)` launches for `global_pairs`. The fused path (>= 2^18 rows) issues one fewer.
  - Launches-per-node figures from flag-on runs therefore overstate by 1 per fused call.
  - Fix this in resident.zig's owner stream, or quote the counter as an upper bound.
- **Request level.** The request-level 3+3 and the gates are still pending (`t8-pipe1`). The GPUs are held by orphan pid 3302210 (30 GB each), and /workspace has 1.6 GB free (the image needs about 4 GB).

# Adversarial re-check: codex/rv64-m4-kernels @ bde21212d

**Verdict: sound.** I found no high- or medium-severity issue. The proofs are byte-identical to M3, and the speedups reproduce. Full data is in `review.json`. Per-run receipts (v2, plus v1 as `*-v1.json`) and the raw test outputs are in `tests/`.

## How it was checked

- **Rebuild:** I rebuilt the branch on the pod from a clean worktree. The library is `13edf220`. Its SASS is identical to the stream's `c24bfda1` once the path-hashed anonymous-namespace symbol names are normalised.
- **Proving runs:** I re-proved both dev blocks under the GPU lock, back to back with an M3 control built from `build/integrate`, source-identical to `bcd401ce4`.
- **Parity:** I hashed every proof file on disk myself, using `tools/rv64-m4-kernels-adv/proof_file_parity.py`.

## Results

| block | run | request s | recursion s | verifier s | proof files == M3 | receiver |
|---|---|---:|---:|---:|---|---|
| 26235156 | branch | 31.29 | 15.13 | 41.6 | 37/37 | accepted |
| 26235156 | M3 control | 35.04 | 18.51 | 41.2 | 37/37 | accepted |
| 24628607 | branch | 44.70 | 21.33 | 61.6 | 55/55 | accepted |
| 24628607 | branch (nsys) | 44.47 | 21.13 | 61.8 | 55/55 | accepted |
| 24628607 | M3 control | 50.16 | 26.64 | 61.7 | 55/55 | accepted |

- **Load and repeats:** the 1-minute load average was 10.9-16.1 for these runs, and each row is a single observation.
- **Same-load deltas [D]:**
  - 26235156: request -10.7%, recursion -18.3%.
  - 24628607: request -10.9%, recursion -20.0%.
- **Kernel GPU-s on 24628607** (nsys, both GPUs, same query applied to every timeline):
  - The stream's M3 base timeline gives 29.909.
  - The stream's c7 timeline gives 19.43.
  - This rebuild gives 19.435.
- **Verifier:** the branch does not change it (61.6 vs 61.7 s at the same load).

## Differential tests and sanitizers

- **Transform test** (`tools/rv64-m4-kernels-adv/xform_diff.cu`):
  - It drives the production N2B, LDE and B2N entries, built once from the M3 tree and once from the branch.
  - Coverage:
    - logs 18-26;
    - 1, 3, 5 or 9 columns;
    - padded strides;
    - with and without the circle stage;
    - mixed coefficient sizes, including clamped ones;
    - in-place (aliased) B2N, and the to-retained variant.
  - Result: 110/110 digests identical.
- **Eager Blake2s test** (`tools/rv64-m4-kernels-adv/blake_eager.cu`):
  - It runs 12 ways of splitting the leaf hashing into calls. These include boundaries at multiples of 16 words, single-word final calls, lifted seeds and multi-segment calls.
  - The prefix banks are filled with poison bytes first.
  - Result: eager, classic and single-call hashes are identical in all 12 cases, and an eager final call that absorbs no word is rejected.
- **compute-sanitizer:**
  - memcheck: 0 errors on both tests.
  - initcheck: 0 errors on both tests. The Blake test ran without poison, so it also shows the eager loads never read words that were not written.
  - racecheck: 0 hazards on the wide NTT kernels at logs 21-24.

## Low-severity notes (not fixed; none affects proofs)

1. The stream's c1-c7 receipts record `source_commit` as `bcd401ce4`, because `.m3-commit` on the pod was stale. The ledger rows give the right commit.
2. Ledger rows from `--nsys` runs record `rss_peak_gib` 0.041, which is the nsys wrapper's RSS, not the producer's.
3. The stream notes the verifier going from 77 to 63.5 s. That change comes from host load, not from this branch.
4. In `trace.cu`, the comment on `native_height_leaves` still says a seed carries its pending block. Under the eager convention it no longer does.

# M4.0 findings: honest measurement of the M3 baseline (stream measure, 2026-11-04)

Binaries: the M3 integrate build (driver `b28544a1`, library `fe8a3e10`, catalogues-v3), with the scale-up config
(`NARROW_RUNS=1`, `GPU_CPU_REPLAY=1`, `CORE_SINGLE_STREAM=1`), on 2× RTX 5090.

Labels: **[M]** measured (a receipt in this directory), **[D]** arithmetic on measured numbers, **[E]** estimate.
Every run is a single observation.

**Correctness.** Every run here is **byte-identical to the M3 baseline receipt**, with all proof hashes compared:
- 24628607: 55/55 hashes, over 4 runs. Two of them had the counter shim loaded, one ran under nsys, and one ran with the shim plus the mmap tracer.
- 26235156: all hashes, with the shim loaded.

The fresh receiver accepted the two `bench` runs (607 counters and 156 counters).

**Timing hygiene: the pod was loaded.** The 1-minute load average at producer start was 103, 52, 40 and 32 across the runs. The request walls (79 s, 55 s, 56 s and 73 s) are therefore **not quotable as speed**.
- Counts, cells, bytes, RSS and kernel durations are valid, because CUPTI kernel durations do not depend on host load.
- The ledger rows carry `loadavg_1m`.

## Kill and re-plan triggers (plan §5 M4.0)

| trigger | threshold | measured | verdict |
|---|---|---|---|
| reconciled recursion kernel time on 607 | > 20 GPU-s ⇒ L4 cell diet moves ahead of L3 | **25.12 GPU-s** [M] | **TRIGGERED** |
| RSS intercept irreducible (e.g. driver-pinned) | irreducible ⇒ re-scope the RAM target | ≥ 16 GiB of the 22.5 GiB peak has named, architectural owners. 0 pinned host bytes. | **not triggered**; the RAM target stands |
| M5 canonical padding tax, 3 rungs | > 40 % of native cells ⇒ 4th rung, then fallback | rows-weighted: 87 % with 3 class rungs, 48 % with 4 (whole-CPU family) | **provisionally triggered on rows**. A cell-weighted number needs per-AIR widths (open item 2) |

### What the GPU trigger means for the plan

On 24628607 the recursion has **25.1 GPU-s of real kernels** (sum over 33 nodes; kernels never overlap on a device).
- At perfect overlap on 2 GPUs, that is a **12.6 s recursion floor**. This is already above the M6 gate (recursion ≤ 8 s), and every L3 lever (enqueue-only, graphs, concurrency) only removes idle time.
- Kernel efficiency is already **0.235 ns per LDE cell** [D] (25.12 GPU-s over 106.8 G LDE cells at b2). That meets the plan's M6 target of ≤ 0.25, so faster kernels have little room left.
- The idle half still matters. GPUs are busy only **49 % / 43 %** of the 27.25 s recursion window [M]. L3 is still worth about 2×, but cells now gate the 10× goal.

**Recommended re-order:**
1. Pull the M7 cell diet forward, to run in parallel with L3 rather than after it:
   - outer LogUp-GKR: interaction is **61 %** of recursion committed cells, see item 8;
   - k-ary folds plus the m3 outer profile for folds and root: folds are **48 %** of recursion kernel time, 12.0 of 25.1 GPU-s.
2. Keep M4 (resident) and M5 (canonical VK) as planned, because they target host time, setup, verifier and RAM, not kernels.
3. Move the recursion target to the plan's "realistic" band (R1).

## Item 1: GPU-time reconciliation (nsys run, 24628607) [M]

Per-node attribution aligns the pipeline's node clock to the GPU's CUDA thread. The fit is the end-anchored offset with a local search; the in-window fraction is **1.00**.

| quantity | value |
|---|---:|
| kernel-busy GPU-s, recursion, 33 nodes (union = sum: no overlap) | **25.12** |
| leaves (17) / folds (16) | 13.10 / 12.02 (0.77 / 0.75 s per node) |
| first-to-last-kernel span GPU-s (the plan's "span" definition) | 39.44 |
| lane device-stage GPU-s (precommit + authority + device proof) | 41.95 |
| node span GPU-s (taken → published) | 166.1 |
| recursion window; per-device busy | 27.25 s; 13.47 s (49.4 %) and 11.65 s (42.7 %) |
| whole-process kernel GPU-s (dev0 + dev1) | 15.50 + 14.58 = 30.08, so native + setup is about **4.96** |

**One number:** recursion is **25.1 GPU-s of kernels inside 39.4 GPU-s of first-to-last spans**.
- The plan's "12.0 GPU-s" came from busy fractions of an older, non-pipelined run (accepted library, 66.8 s window). Under the M3 pipeline it does not hold.
- The plan's "29.2 GPU-s" span figure is close to today's 39.4 minus the host gaps inside the device stage.

**Top kernels** over the whole process:

| kernel | GPU-s |
|---|---:|
| `n2b_continue` | 6.31 |
| `mixed_leaf_kernel` | 5.68 |
| `deep_aggregate_coordinates` | 2.82 |
| `n2b_final_warp` | 2.14 |
| `generate` | 1.87 |
| `narrow_run` | 1.76 |
| `level` | 0.35 (115,680 calls) |

## Item 2: receipt v2 and counters [M]

Receipt schema v2 (§8.1 stage boundaries) is defined in `vectors/reports/progress/SCHEMA.md` and written by the harness.

The CUDA driver-API counter shim is in `tools/rv64-cuda-counters`. It is an LD_PRELOAD interposer of `dlsym` → `cuGetProcAddress`. It works with the static cudart and passes every call through unchanged.

**Per request:**

| | 24628607 | 26235156 |
|---|---:|---:|
| `cuStreamSynchronize` | 55,396 (29.9 s API; nsys 25.0 s) | 35,050 (all syncs) |
| `cuLaunchKernel` | 228,174 | 141,703 |
| `cuMemAllocFromPoolAsync` | 14,670 (3.9 s) | 9,232 |
| `cuLibraryLoadData` | 683 (3.2–5.1 s, + 1.8 s unload at exit) | 683 |
| pageable H2D/D2H copies | **19,705, carrying 73.0 GB** (5.6 s) | 12,250, carrying 46.9 GB |
| pinned host allocations | **0** | 0 |
| CUDA-calling threads | 2 (one per GPU) + main at exit | same |

**Per recursion node** on 607 (device-stage window on that GPU's thread, 97 % of recursion activity inside node windows):

| | syncs | launches | pool mallocs | pageable copies |
|---|---:|---:|---:|---:|
| leaf | 910 | 5,626 | 227 | 322 |
| fold | 685 | 3,935 | 169 | 248 |

The M6 gates are ≤ 10 syncs and ≤ 500 launches per node.

**Note.** One CUDA thread per GPU serves both native and recursion. Any per-stage attribution must therefore use time windows, not threads. The tools do this.

## Item 4: RSS census at the peak (24628607, smaps + mmap call-site tracer) [M]

The sampled peak is **22.52 GiB** at t = 50.2 s; getrusage reports 23.2 GiB. The peak falls about 2 s into recursion.

The RSS curve has three parts:
- **7.95 GiB before the request starts** (t = 8.4 s): 6.08 GiB anonymous + 1.84 GiB library file pages.
- About 11 GiB through capture, setup and native.
- **+10 GiB in 2.5 s at recursion start**, then a decay to about 14.5 GiB during the folds.

| owner (at the peak) | GiB | how attributed |
|---|---:|---|
| recursion host prep for prepared-ahead nodes: `PreprocessedCircuit.fromBuilderCircuit` 4.34, `outer_assignment.Prepared.init` 2.99, `witness_generation.plan.buildImpl` 1.20, PP `TraceBuilder.block` 0.25, `fromCircuit` 0.10 | **8.88** | [M] call site (RSS-weighted live mmaps) |
| CUDA init: two contexts plus **EAGER load of 683 libraries** (host-side module images; glibc/driver malloc, not traced) | **≈5.5** | [D] anonymous RSS before the request (6.08) minus the request-independent Zig allocations traced at init |
| `libstwo-rv64-native.so` file pages (a 1.96 GB image read at EAGER load) | **1.71** | [M] smaps file mapping |
| native, PCS and commit host buffers (streaming tree builder 0.59, committer 0.32, commitment tree 0.19, column prep 0.17, commit_polys 0.14, trace_commit twiddles 0.22, resident composition 0.15, geometry/twiddle caches 0.14) | 1.9 | [M] call site |
| setup, keys, catalogue and image (keccak tables 0.20, fixed-authority catalogue 0.20, key seal 0.16, expected image 0.15, roster CpuSetup 0.12, other) | 0.9 | [M] call site |
| other traced Zig allocations | 0.5 | [M] |
| untraced anonymous memory during the request (cudart, driver and libstdc++ malloc) | ≈3.5 | by elimination (9.03 untraced − about 5.5 at init) |
| nvidia device mappings, other files, brk | 0.16 | [M] |

**Coverage:**
- 62 % is attributed to named call sites or mappings [M].
- 87 % adds the time-evidenced CUDA init [D].
- 13 % is by elimination.

**Exit gate (≥ 90 % attributed): not fully met.** The fix is to give the shim a malloc interposer (≥ 1 MiB with backtrace) that names the cudart and driver share. This is the first follow-up.

**Verdict on the intercept: not irreducible.**
- 8.9 GiB is per-node recursion host prep, held by `prep_ahead=6` plus the lanes. M5 builds the PP and assignment plan once per image, and M6 hint-tape removes it.
- 5.5 + 1.7 GiB is EAGER module loading of one 2 GB image. M4 resident uses lazy, per-family fatbins.
- Pinned memory is zero, so nothing is driver-pinned.

## Item 5: geometry over all 15 M3 receipts and the rung padding tax [D]

The data is 579 native proofs (347 CPU + 232 truth), with **389 distinct geometry classes** across the basket. Today every proof is its own class: 17/17 on 607 and 11/11 on 156.

Two rung models (`geometry-rung-tax.json`, `scripts/rv64_m40_geometry.py`):

| model | R=1 | R=2 | R=3 | R=4 |
|---|---:|---:|---:|---:|
| per-AIR independent rungs: extra padded rows / distinct padded classes | +304 % / 161 | +14.1 % / 284 | **+3.7 % / 341** | +1.0 % / 359 |
| whole-proof class vectors per family (what a constant-log-size canonical leaf needs): extra rows / classes | +317 % / 11 | +134 % / 22 | **+87 % / 31** | +48 % / 38 |

**Per family, R=3 class vectors:**

| family | extra rows |
|---|---:|
| cpu | +88 % |
| keccak | +3.8 % |
| add | +27 % |
| double | +20 % |
| arith256_mod | +41 % |
| sha256, bn254_fp2_mul, bls12_381_fp2_mul, arith384_mont | 0 % |

**Interpretation:**
- Per-AIR rungs are cheap in rows but do not shrink the VK table: 341 classes.
- Class vectors shrink the table but pay heavily on CPU.
- CPU's tax is driven by the **public-boundary components**: initial and terminal logs are 23 on the first and last segments and 5 elsewhere. The model should therefore split CPU into first, middle and last families (`--split-boundary`; the run is queued, see open items).
- All numbers are **rows-weighted, not cells-weighted**. The CPU main AIR, the widest, is constant at 2^22, so the cell tax is lower than the row tax.

**Do not apply the M5 kill rule from these numbers alone.** Canon-native should export per-AIR widths, then re-run the script with `--widths`.

## Item 6: D2 paper model (native b4_q54_p20 vs b2_q108_p20) [D/E]

| input [M] | GPU-s |
|---|---:|
| native kernels | 4.96 |
| leaf kernels (17) | 13.10 |
| fold kernels (16) | 12.02 |

Assumptions [E]:
- b4 adds 50–70 % to native kernels, through LDE, Merkle and quotient commits.
- 55–80 % of leaf work scales with the query count. The analytic Blake model in item 3 puts 96 % of leaf hashing on query-scaled origins.

| | GPU-s |
|---|---:|
| native | **+2.5 to +3.5** |
| leaves | **−3.6 to −5.2** |
| **net** | **−0.1 to −2.8** of about 30 |

The leaf shrinks from 1.94 to about 1.2–1.4 G base cells.

**Recommendation: D2 = yes, but low priority (M7).** It is net-positive across the whole assumption band, but small. The outer-GKR and k-ary/outer-profile levers are bigger.

It is gated on:
- an in-circuit per-origin Blake count;
- the device-memory model below (2^22 b4 fits at about 15 GB; 2^23 b4 does not, at about 30 GB plus reserve);
- a named profile and soundness note from the profiles stream.

## Item 7: device-memory model and composition-arena breakdown [D from M inputs]

**Measured on 607 (2^22 CPU segment at b2):**

| quantity | value |
|---|---:|
| main base coefficients (max) | 337.7 M words = 1.35 GB |
| interaction base coefficients (max) | 193.3 M words = 0.77 GB |
| native CPU composition arena (largest ordinal, 34–38 roles, eval_log 23) | 5.48 GB |
| largest single native role: a **truth** proof, 3 roles, eval_log 23 | **18.44 GB** |
| recursion CPU-leaf composition (12 roles, largest role 11.24 GB at eval_log 24) | 26.85 GB if all roles are live; legacy policy 40.2 GB |

**Pool peaks:**

| | native | recursion |
|---|---:|---:|
| pool used | 13.9 GB | 25.3 GB |
| live leases | 8.6 GB | 13.7 GB |

The idle PCS cache retains up to **24.0 GB**. NVML device peak is 33.35 GB.

**Model per segment** (linear in rows; composition evaluated on 2× the trace domain, independent of FRI blowup; streamed-commit working set 3.8 GB at 2^23 LDE leaves; 3 GB runtime reserve):

| segment | base | LDE (materialised) | composition | streamed peak | fits a 32 GB GPU |
|---|---:|---:|---:|---:|---|
| 2^22 b2 | 2.1 | 4.2 | 5.5 | **11.4** | yes (2 concurrent: tight) |
| 2^22 b4 | 2.1 | 8.5 | 5.5 | 15.2 | yes (1) |
| 2^23 b2 | 4.2 | 8.5 | 11.0 | 22.8 | yes (1) |
| 2^23 b4 | 4.2 | 17.0 | 11.0 | 30.4 | **no** |
| 2^24 b2 | 8.5 | 17.0 | 21.9 | 45.6 | **no** |
| 2^24 b4 | 8.5 | 34.0 | 21.9 | 60.8 | **no** |

This confirms the plan's rule "pick at most two of {2^24, b4, concurrency}". It is in fact tighter: 2^24 is out without a composition-arena diet.

**The device-peak outliers are composition, not traces:**
- the 18.4 GB truth role;
- the 11.2 GB recursion role.

These go to the arena stream (PerCoset or InPlace composition) before any M6 concurrency.

## Item 8: reconciled committed-cell count [M]

Recursion on 607 commits **53.39 G base cells**, where `GPU_TRACE_OWNERSHIP` gives the coefficient words per tree, summed over 33 nodes:

| tree | base cells (G) |
|---|---:|
| preprocessed | 4.647 |
| main | 16.127 |
| interaction | **32.617 (61 %)** |

The plan's two numbers reconcile as follows:
- **53.39 G** ("construction-cost") is exactly PP + main + interaction.
- **≈ 37 G** ("census-v2 main + interaction") counted the interaction tree at half its committed M31 columns. Per CPU leaf, census-v2 has 584.5 M main + 590 M interaction, while 1,179.8 M interaction cells are committed (304 M31 columns).

The corrected leaf factors in the plan should use **interaction = 61 %** of recursion cells, not 50 %. This makes outer LogUp-GKR a bigger lever than the plan assumed.

**Native, all 17 proofs:** 7.26 G base cells (main 5.41, interaction 1.85). Recursion commits **7.4×** the native cells. A CPU leaf has 1.94 G base cells, against about 0.40 G for the 2^22 segment it verifies (×4.8).

## Item 3: per-origin Blake census for a CPU leaf [D, analytic; exit gate NOT met]

This model uses the logged column counts:
- main 3,606 columns, interaction 2,008 columns (logged);
- PP 45 and composition 16 columns [E];
- q = 108, LDE depth 23, FRI fold 4, deduplicated paths.

| origin | compressions | share |
|---|---:|---:|
| Merkle leaf values | 38,448 | 71.3 % |
| Merkle paths | 7,848 | 14.6 % |
| FRI layers | 5,702 | 10.6 % |
| channel (OODS values + draws) | 1,909 | 3.5 % |
| **total** | **53,907** | |

**Cross-check.** The plan's measured G-gate rows are 5.98 M real, about 74.7 K compressions at 80 G per compression. This model explains **about 72 %** of them.
- Fold and Keccak leaves are not modelled.
- The **≥ 95 % gate needs an in-circuit counter**: tag each Blake gadget instance with its origin in the leaf/fold graph builder (`om31_native/execution_wrap.zig` and `outer_wrap.zig`, owned by canon-vk, or the hint tape in M6). The counter then logs the counts per node.
- The direction is clear even now: **leaf-value hashing dominates.** Wide trees (3,606 + 2,008 columns) cost about 360 compressions per query. Fewer, narrower committed columns (outer GKR, PP dedup) and fewer queries (D2, m3 outer profile) are the Blake levers. Path pruning is not.

## Open items (measure stream, next session)

1. Malloc interposer in the shim, to name the 9 GiB untraced (cudart and driver) and close the 90 % RSS gate.
2. A cells-weighted rung tax: per-AIR widths from canon-native, plus the `--split-boundary` run (queued on the pod: `/workspace/m3/runs/m4-measure/analysis/geometry-split.json`).
3. The in-circuit per-origin Blake counter (the spec is above; it needs a log-only hook in canon-vk's files).
4. A quiet-pod timing rerun of the two dev blocks for quotable walls. Timings here were taken at load 32–103.

## Files

| file | contents |
|---|---|
| `24628607-m40-counters.json` | v2 receipt with the shim and smaps; bench, receiver accepted |
| `24628607-m40-nsys.json` | v2 receipt with nsys, including the per-node kernel reconciliation |
| `24628607-m40-mmap.json`, `24628607-m40-mmap-census.json` | shim plus mmap tracer; RSS-weighted call-site census at the peak |
| `24628607-m40-counters-smaps.json` | RSS time series plus the peak smaps census |
| `26235156-m40-counters.json` | v2 receipt with the shim and smaps; bench, receiver accepted |
| `geometry-rung-tax.json` | item 5 |
| `models-24628607.json` | items 3, 6, 7 and 8 |

Tools: `scripts/rv64_measure.py` (receipt-v2, fingerprint, nsys, mmap-census, smaps), `scripts/rv64_progress.py`, `scripts/rv64_m40_geometry.py`, `scripts/rv64_m40_models.py`, `tools/rv64-cuda-counters/`.

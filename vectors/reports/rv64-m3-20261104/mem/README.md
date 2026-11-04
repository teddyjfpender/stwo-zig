# Stream mem: device-memory ownership by lifetime (M2b + team item 4)

Branch `codex/rv64-m3-mem`. Pod: 2x RTX 5090. Blocks: only 26235156 and 24628607 were run (owner rule).
Labels: **[M]** measured (in a receipt or log in this directory), **[D]** derived arithmetic on measured
numbers, **[E]** estimate. Profile is unchanged (`conjectured128_b2_q108_p20_fold4`). Every change is
scheduling-only. **Every run below is byte-identical to the accepted-v7 controls** (native bins, bundle,
recursive tree, all recursive proofs, root). Every run handed to the fresh, cache-disabled receiver was
accepted.

## What changed

| # | Change | Where | Needs image rebuild |
|---|---|---|---|
| 1 | Chunked LDE→Merkle streaming for MAIN/INTER/FIXED commits: bounded evaluation chunk, ping-pong progressive Blake2s banks, tree built in the dead bank. Uses only symbols the accepted image already exports | `trace_commit.zig`, `trace_stream_plan.zig` | no |
| 2 | Admission by predicted peak: the chunk shrinks to fit beside live leases under the cap, and each commit takes the smaller predicted scratch (streamed vs full LDE) | `trace_commit.zig` | no |
| 3 | Streamed scratch split into aux+chunk, bank0, bank1 leases: the largest single request is one bank | `trace_commit.zig` | no |
| 4 | **Composition direct extension.** Device columns of degree `el-1` are extended from their retained lease (range-validated) instead of being copied into the role arena first | `resident_composition.zig` | no |
| 5 | Streamed PCS rolling source rebuild. Queried values are read per chunk and paths from the finished tree | `pcs_pipeline.cuh`, `trace.cu` (`stwo_rv64_trace_open_{values,paths}_on`), `trace_stream_plan.h` | yes |
| 6 | Lifetime-segregated pools: a long-lived pool for immutable setup (kind 4) and cached domains; the per-request pool holds everything else. OOM recovery trims both | `context.cu`, `pcs_native.cu` | yes |
| 7 | Physical admission. Requests of at least 1 GiB evict idle PCS blocks first when free physical memory plus unused reservation cannot hold them | `pcs_native.cu` | yes |

Opt-outs (byte-identical either way): `STWO_RV64_TRACE_STREAM=0`, `STWO_RV64_PCS_STREAM=0`,
`STWO_RV64_COMPOSITION_DIRECT=0`. Chunk sizes: `STWO_RV64_TRACE_STREAM_CHUNK_WORDS` and
`STWO_RV64_PCS_STREAM_CHUNK_WORDS` (default 2^27 words).

### Correctness and soundness
A lifted Merkle leaf is one Blake2s message over every column in stable ascending-height order. Blake2s
is sequential over 16-word blocks with a distinct final flag. Because of that, the unfinalized per-row
state (8 hash words plus 16 pending words) carries any column boundary exactly. This is the mechanism the
established kernel already uses between heights; streaming only adds boundaries inside one height. Roots,
opened values and paths therefore depend only on column values and order, never on the chunk schedule.

The direct composition path computes the same exact field LDE (identical evaluations) with a different
kernel entry. Nothing changes the transcript, the AIR, the profile or any verifier. The PCS still checks
every rebuilt root against the committed root.

Tests:
- `zig build test-trace-stream-plan`, 4 host tests. One shows chunked absorption equals one-shot Blake2s
  for 7 schedules.
- The combined driver type-checks.
- nvcc compiles `trace.cu`, `pcs_native.cu` and `context.cu`.
- Byte parity on both development blocks for every configuration.

## Measured device peaks, block 24628607, 2 GPUs [M]

Same block and same harness throughout. `legacy-v1` and `stream-v1` use the **same driver**
(`006c9ee3`, legacy via `STWO_RV64_TRACE_STREAM=0`). `v4` is driver `e99bbc7f` (adds 2–4) with the
accepted library. `v4-lib2` is the same driver with this stream's library (`94b2cf19`, adds 5–7).
Live lease bytes are taken at each commit's peak point; the composition figure is the arena request.

| Stage (max over 33 nodes, per device) | legacy-v1 | stream-v1 | v4 | v4-lib2 |
|---|---:|---:|---:|---:|
| FIXED commit, live leases | 6.70 GB | 7.37 GB | 6.70 GB | 6.70 GB |
| MAIN commit, live leases | 13.92 GB | 11.33 GB | 11.33 GB | 11.33 GB |
| INTER commit, live leases | **21.07 GB** | 13.71 GB | 13.71 GB | 13.71 GB |
| INTER commit scratch | 11.18 GB | 3.83 GB | 3.83 GB | 3.83 GB |
| Composition arena, CPU-leaf role (`eval_log` 24) | **16.84 GB** | 16.84 GB | **11.24 GB** | 11.24 GB |
| Composition arena, rl+2 role (`eval_log` 20, 3516 cols) | 18.44 GB | 18.44 GB | 18.44 GB | 18.44 GB |
| PCS planes requested (`device_bytes`) | 15.12 GB | 15.12 GB | 15.12 GB | **8.32 GB** |
| PCS owner high-water incl. idle cache (`retained_bytes`) | 24.57 GB | 24.57 GB | 25.97 GB | 22.68 GB |
| Largest PCS rebuild buffer | 11.12 GB | 11.12 GB | 11.12 GB | 3.76 GB |
| Recovered owner OOMs (fail → trim → retry) | **28** | 8 | 19 | **4** |
| Request wall (single observation, shared host) | 99.39 s | 101.59 s | 99.61 s | 100.88 s |
| Receiver | — | accepted | accepted | accepted |

26235156 shows the same pattern: PCS planes 15.12 → 8.32 GB and PCS high-water 28.12 → 20.45 GB.
Its walls are 66.4, 65.2 and 64.2 s; all four 26235156 runs are byte-identical and three were accepted.

The wall times do not support a speed claim either way. Other streams were building on the same host, and
each figure is one observation.

## The 26235159 failure, identified

The 16,844,328,872-byte terminal request is **not** the INTER commit, contrary to that receipt's
phase attribution. It is the **resident composition arena** of the CPU-leaf role: 4,211,082,218 words,
printed as `legacy_arena_words` by `GPU_COMPOSITION_ARENA` [M]. That arena holds a copy of every source
coefficient plus the `el = rl+1` evaluations.

It depends only on the leaf geometry class. That is why 26235156, 24628607 and 26235159 all request
exactly the same bytes; on the two small blocks it is recovered by idle eviction and trim. With change 4
it is 2,810,184,682 words (11.24 GB) on both development blocks [M].

## Extrapolated 26235159 peak (not run; owner rule)

| Point | Before | After | Basis |
|---|---:|---:|---|
| Terminal composition request | 12.34 GB retained + 16.84 GB = 29.18 GB | 12.34 + 11.24 = **23.58 GB** | retained [M, 26235159 receipt]; arena [M, same role geometry] → [D] |
| Pool ceiling (33.68 GB total − 4.13 GB outside the reservation) | ≈29.55 GB | ≈29.55 GB | [M, 26235159 receipt] |
| Headroom at that point | ≈0.37 GB, which failed | **≈5.97 GB** | [D] |
| CPU-leaf INTER commit | ≈21 GB live | ≈13.7 GB live | [M] on 24628607, same leaf class → [E] |
| PCS planes | ≈15 GB | ≈8.3 GB | [M] on both development blocks → [E] |
| rl+2 composition role | 18.44 GB arena on 4.42 GB of leases | unchanged | [M] on 24628607; it fits there, but its size on 26235159 is [E]: service AIR sizes may be data-dependent |

Expected per-node device peak for 26235159 is about 22–23 GB, against at least 29.2 GB before [E].
The binding stage becomes the rl+2 composition role and the PCS high-water. **Not proven by a run.**
Integration should run 26235159 once, in the ordered scale-up, with the `v4` driver and `lib2`.

## Not done / next

- **rl+2 composition roles (18.44 GB):** sources have degree `el-2`. `stwo_lde_n2b_columns_on` needs
  compact columns of `eval/2`, and the addressed stage kernel silently rejects sources that overlap the
  tile. A pointer-table stage kernel in the image would cut 1/5 of this arena (about 3.7 GB [D]).
- Physical admission counts unused pool reservation as available. Fragmentation still causes 4 recovered
  OOMs. Counting physical free memory only (or a targeted trim) should remove them.
- The lifetime-pool split (6) was not A/B-measured in isolation. `lib1`/`lib2` bundle it with 5 and 7.
- The predicted-peak model in `trace_stream_plan.{zig,h}` covers commits and the PCS rebuild, not
  composition. A per-node admission (peak = max over stages) is the natural extension once the composition
  geometry is in the model.

## Files

- `*-receipt.json`: harness receipts (stages, assets, parity, receiver).
- `*-peaks.json`: `peak_summary.py` over the producer logs.
- `*-memlines.txt`: raw `GPU_OWNER_OOM` and `GPU_COMPOSITION_ARENA` lines.

Source provenance:
- Driver `006c9ee3` was built from `040312f48`.
- Driver `e99bbc7f` was built from `281455055`.
- Library lib1 (`3e3067f2`) was built from `281455055` plus the image sources of `87dbcab58`.
- Library lib2 (`94b2cf19`) was built from `6fab0261a`.

Images use infra's object store; only the changed TUs were recompiled. AOT catalogues are unchanged.

Asset SHA-256:
- Drivers: `006c9ee3…` (stream-v1/legacy-v1), `e99bbc7f…` (v4).
- Libraries: accepted `25295868…`, lib1 `3e3067f2…`, lib2 `94b2cf19…`.
- Receiver: `38c70ff8…`.

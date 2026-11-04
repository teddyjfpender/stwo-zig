# M5 stream `platform`: receipts (2026-11-04)

Proof-neutral runtime work on the M4 baseline (`78c3bd5d2`). Every run is a single observation **[M]**;
the pod 1-min load is recorded in each receipt (most were > 8, so timings are not quotable as speed;
counts are). Byte identity is checked with `scripts/rv64_measure.py fingerprint` against
`/workspace/m3/runs/integrate/<block>-2gpu-scale/receipt.json` (the M3 integrate scale receipt, which M4
matches byte for byte).

## Call-site census (new tool)

`tools/rv64-cuda-callsites` is an LD_PRELOAD shim (same dlsym/cuGetProcAddress hook as the measure
stream's counter shim) that attributes every `cu{Stream,Event,Ctx}Synchronize` and every H2D/D2H copy to its
backtrace; `scripts/rv64_m5_callsites.py` symbolizes the frames with addr2line and groups by the first
driver (Zig) frame. `*-sites.txt` are the rendered tables.

## 26235156, one-shot, M4 driver, under the call-site shim

| | M4 library (`5886e2a5`) | v3 library (this stream) |
|---|---:|---:|
| `cuStreamSynchronize` | 37,304 | **3,974** |
| `cuEventSynchronize` | 32 | 2,524 (2,479 are staged D2H that replace the *implicit* sync of a pageable D2H) |
| pageable H2D | 9,817 copies / 47.8 GB | **0** (45.9 GB through pinned rings, 98% filled by the parallel pool) |
| pageable D2H | 2,479 / 0.08 GB | **0** |
| proofs vs M3/M4 | identical | **identical** (all hashes) |

Where the M4 syncs came from (`26235156-callsites-m4-baseline-sites.txt`): ~14 k were frees
(`session_context.release` → `stwo_exec_context_free_u32` host-joins both lanes of the 2-lane PCS
context on every free), ~10 k were joins of already-idle lanes, the rest genuine waits. Where the
H2D bytes came from: the recursion PP forest uploaded twice per node (`outer_fixed.uploadImpl` 11.75 GB
and again `immutable_setup.words` from `outer_source_main.generate` 11.75 GB), the outer assignment
schedule (9.7 GB), composition/commit/projection ingress (rest).

## 24628607, one-shot under the measure stream's counter shim (same config as M4 `integrate/24628607-g5-counters`)

| counter shim, per request | M4 g5 (lib `5886e2a5`) | v3 lib (`03bdc5db1`), M4 driver |
|---|---:|---:|
| syncs (stream + ctx + event) | 57,816 | **10,658 (5.4x fewer)** |
| of which `cuStreamSynchronize` | 57,766 | 6,632 (8.7x) |
| of which `cuEventSynchronize` | 50 | 4,026 (~3,965 staged D2H that replace pageable D2H's implicit sync) |
| pageable copies | 19,613 / 71.1 GB | **0** (71.9 GB H2D staged pinned) |
| launches | 222,913 | 222,913 |
| pool mallocs | 0 | 0 |
| proofs vs M3/M4 | identical | **identical** (all 55 hashes) |

Receipt `24628607-counters-v3-pinned-fences.json` (load 34.6 at start: the 69.96 s request is not quotable).

## v4 (26235156, full stack: driver `a7e737a4`, lib `bfaf0b14`, under the call-site shim)

`26235156-callsites-v4-adopt-el2.json`, `26235156-callsites-v4-sites.txt`. Byte-identical to M3/M4.

- **Outer FIXED adoption.** The precommit already has the node's PP evaluations resident; it now adopts them into the
  immutable cache (one D2D copy per column, key = the MAIN-generation key derived from the committed fixed root) before
  dropping them. MAIN generation then hits instead of re-uploading. H2D per request **45.9 → 36.6 GB** [M].
- **el-2 direct composition extension.** Degree el-2 device columns are extended straight from their lease through a
  new compact-source LDE entry (`stwo_lde_n2b_columns_compact_on`: same kernels, which already read at most 2^log
  coefficients per column; only the host range check changes). The binding rl+2 truth role: arena **18.44 → 14.75 GB**
  [M] (3,515 of 3,516 columns direct).
- `STWO_RV64_EXEC_SYNC=device` (default host): `stwo_exec_context_sync` becomes a device-side all-lane barrier.

## Device memory gate (24628607, v4 stack, one-shot under the counter shim, load 9.2)

`24628607-counters-v4-cap22.json`: with `STWO_RV64_DEVICE_ARENA=22G` the whole-device NVML peak is **27.81 GB on both
GPUs** (gate ≤ 28 GB; M4 auto carve 31.50 GB; M4's feasible minimum was 28.88 GB at 23 GiB because of the 18.44 GB
rl+2 composition role). Byte-identical; 3 overruns absorbed by idle-cache eviction. **20G fails**: the recursion leaf
composition (11.24 GB at eval_log 24) plus 11.4 GB of live leases. So the binding request is now the recursion leaf,
not the truth role. The 3.27 GB local-memory reservation (12,544 B stack of `secp witness<Add>`) is untouched.

## Request time in the resident service: ABBA A/B against the M4 binaries (v4 stack, auto carve)

Same harness and config as the M4 headline (`rv64_m4_resident.py daemon`, `--warm`, store reuse, M3 scale env), run
back to back in the order final / M4 / M4 / final, two requests per block per run. **Loaded host** (1-min load 15-34 at
service start), so the means below are labelled [M] but are not quiet-host quotable. Every request of every run is
byte-identical to M3/M4; the 4 fresh receivers (M4 receiver binary, store renamed away) of `daemon-ab-final-warm`
accepted.

| block | M4 control (n=4) request / recursion | v4 (n=4) request / recursion | Δ request |
|---|---:|---:|---:|
| 24628607 | 31.19 / 21.39 s | **29.18 / 19.49 s** | −2.0 s (−6.4%) |
| 26235156 | 21.33 / 14.02 s | **20.32 / 13.11 s** | −1.0 s (−4.7%) |

Native prove and capture are unchanged within noise (6.29 vs 6.31 s, 3.05 vs 2.97 s on 607): the gain is in recursion,
where the host no longer blocks on ~47 k syncs and 19.6 k pageable copies per request.
A 22 GiB carve in the resident service **failed** on the second 24628607 request (recursion-leaf composition 11.24 GB with
11.9 GB live: the service keeps more resident state than the one-shot), so the ≤ 28 GB device gate holds only one-shot.

## v5 (26235156, driver `d9cfebfb`, one-shot under the call-site shim)

- **`STWO_RV64_EXEC_SYNC=device`** (opt-in): context syncs become a device-side all-lane barrier; span-timing reads
  (`stwo_rv64_event_elapsed`) wait on their end marker only when it is not complete. Byte-identical.
  `cuStreamSynchronize` **0** (M4 37,304), `cuEventSynchronize` 3,442 (2,479 staged D2H whose data the caller reads on
  return, 864 composition span-timing reads, the rest pcs_pipeline/readbacks): **37,336 → 3,442 host-blocking calls
  (10.8x)** [M]. Request 31.55 s vs 31.44 s in host mode at similar load (single observations, shim on): no time
  change, so it stays opt-in until the span timers are resolved at the terminal fence (M6 enqueue).
- Host mode (default): 3,996 stream + 2,526 event syncs. Batching the adoption joins did not remove the 900 syncs at
  adoption: the immutable `seal` itself joins (it seals a range that must be written).
- ProgramAuthority service cache (`expected_image.AuthorityCache` in the resident session, keyed by the guest's
  executable words/addresses, both execution profiles and the control policy): measured in the resident service below.

Carve timing (from `daemon-*` producer logs): with the M4 library `GPU_ARENA_INIT` (814 `cuMemCreate` + premap per GPU)
is printed after the class preload, i.e. inside request 1; with this stream's library it is the first line of the
service log, before the warm boot.

## v5 in the resident service (`daemon-v5-warm.json`, load 11.8 at start)

Requests 20.63 / 19.52 s (26235156) and 29.32 / 28.65 s (24628607), byte-identical, fresh receivers 4/4 accepted (M4
receiver binary, store renamed away). The ProgramAuthority cache cuts the per-request image load from 489-579 ms (v4,
`daemon-ab-final-warm`) to **306-321 ms** [M]; capture is unchanged (2.19-2.96 s) because the image load overlaps RV64
execution. The remaining ~0.3 s is ELF + input load and the input-dependent memory policy.

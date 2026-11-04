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

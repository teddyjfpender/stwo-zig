# M9 prep stream `m9-gpu-replay`: receipts (2026-11-07)

Design and verdict: `design/riscv-proving-stack/rv64-m9-gpu-replay.md`. Branch `codex/rv64-m9-gpu-replay`, base `codex/rv64-m7-integrate` @ `786429aca`.

Everything here is [M] from pod `rv64-resident-2x5090` unless named otherwise. The pod was shared, with 1-minute load 15–26.
- CPU numbers are single-thread runs of `rv64-m9-gpu-replay-dump`, ReleaseFast with `-Dcpu=x86_64_v4+sha`.
- GPU numbers are CUDA-event medians from the `-DM9_STANDALONE` harness on one RTX 5090 (GPU 0) under `gpu.lock`. Holds were under 1 min.
- Raw dumps (seeds, memory tape, host steps, ROM, the 201 MB reference tape of 24628607 segment 2) lived under `/workspace/m3/runs/m9-gpu-replay/` and were deleted after the runs. Regenerate them with design doc §8.

| file | content |
|---|---|
| `cpu/cpu607-c{64,256,1024,4096}[-p]-r{1,2}.json` | 24628607: plain vs seeded first pass (`-p` = `STWO_RV64_M9_PREFAULT=1`), CPU recorder ns/step, parity mismatches (all 0), opcode census |
| `cpu/cpu159-c256-p.json` | 26235159, the same (49 segments, 0 mismatches) |
| `cpu-recorder-digests.txt` | per-segment steps / seeds / memory words / host steps / SHA-256 of the CPU recorder's compact tape (the GPU harness checks against these) |
| `gpu/g607-c<chunk>-s{-1,2}.json`, `gpu/g607-c256-{all,seg2}.json` | GPU replay on 24628607, all segments (`-1`/`all`) or segment 2; `segments_sha_match` 7/7 and 1/1; seg 2 byte-compared (`ref_bytes_compared`) |
| `gpu/g159-c256-{all,seg20}.json` | GPU replay on 26235159: 49/49 SHA match, 37.35 ms, 5.48 GIPS; segment 20 0.465 ms |
| `first-pass/host-<block>-r*.json` | first pass per basket block (`STWO_RV64_M9_SKIP_REF=1 STWO_RV64_M9_PREFAULT=1`): plain/seeded MIPS, host-step time by service. `seeded.seeds` / `bytes_per_step` read 0 in skip mode (counted only in the reference phase) |
| `first_pass_basket.json` | the 15 blocks folded together (input of the model) |
| `review/` | adversarial review re-run (2026-11-07): `corpus.json` + `g-corpus*.json` (synthetic op corpus vs the reference interpreter: 106,496 cases, all 69 GPU ops, byte-identical), `cpu607.json` + `meta607.txt` + `g607-{all,seg2,seg6}.json` (24628607 with the widened guards: 7/7, status 0, `chunk_ends` census), `g607-inj-{pc,mem,end,reg,regh}.json` (fault injection: status 4 each) |
| `model.json` | `scripts/rv64_m9/gpu_replay_model.py` output: plan / full_now / full_fixed / replay_only / replay_only_net (review) variants of lever #9 on p50, p95, 26235168, 26235159, 24628607 and the basket |

Headline numbers:

| quantity | value |
|---|---|
| GPU compact-tape parity vs CPU recorder | 7/7 + 49/49 segments, 231.7 M steps (50 of 69 ops); 201 MB byte-compared |
| GPU op corpus vs reference interpreter (review) | 106,496 cases, all 69 ops, byte-identical |
| runtime guards (review) | every chunk end checked (44% previously unchecked on 607); 5/5 injection classes fire |
| GPU replay, one segment (4.19 M steps), chunk 256 | 0.465–0.481 ms (8.7–9.0 GIPS) |
| GPU replay, whole block | 3.69 ms (607) / 37.35 ms (159) |
| input transport | 4.3–4.7 B/step at chunk 256 (MinimalRecord route 16 B/step; compact tape 48 B/step) |
| first pass on 24628607, plain vs seeded (prefaulted) | 176–181 vs 159–164 MIPS; not prefaulted 105–133 |
| first pass over the basket, plain vs seeded | 114 vs 105 MIPS |
| p50 block 26235168 | 62.8 MIPS; 1.26 s of curve services |
| precompile services in the basket first pass | 8.02 of 12.47 s (curves 4.86 s at 11–54 µs/call); 3.28 M service calls, 4.31 M host steps |
| lever #9 effect (model, review) | full_now p50 −59% needs the narrow capture on the GPU (not built); replay alone (net of tape read-back) p50 9.19 s, −53% |
| CPU recorder (traced walk) | 40–46 ns/step single-thread |

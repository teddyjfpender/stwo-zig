# RV64 M8 optimisation stream T10-narrow-capture-recorder, round 2 (2026-11-07)

Branch `codex/rv64-m8-opt-T10-narrow-capture-recorder`, cut from `codex/rv64-m7-integrate` @ `c72b51646`. Code commit `76d1b6763`.
Files: `word16_execution/{cpu_source,prepared}.zig` (claimed) plus two new files, `stable_dedup.zig` and `prepared_recorder_test.zig`.
This is T1's named remaining bound: the narrow capture `Prepared.captureForCombinedServices` (CPU scan of the compact tape, then provider
routing and grouping), on the request's CPU critical path.

Every number here is [M] from `rv64-capture-bench CFG - 0 RES`, run through `t10cap.py` (T1's `t1cap.py`, with full stderr kept).
That is the production capture route, allocator (large-block recycler over smp) and JSON output.
- Pod: `rv64-resident-2x5090`, shared with other streams; 1-minute load 9–26 is recorded on every row of `runs.jsonl`.
- Arms are interleaved per rep and run on one binary, so only the flag differs.
- Medians are over 3 reps.
- Raw JSON and stderr are on the pod under `/workspace/m3/runs/m8-opt-T10-narrow-capture-recorder/cap/`.

## What it does (flag `STWO_RV64_M8_CAPTURE_RECORDER=1`, default off; any other value = legacy route)

Profile of the legacy route (`attribution.json`, prof1, 26235159 at inflight 4, summed over 49 segments):
- scan 10.94 s;
- routing copies into per-family lists 3.51 s;
- ALU `AutoHashMap` grouping 7.51 s (about 94 ns/fact; the serial long pole);
- SHIFT grouping 1.09 s;
- BINARY+ZBB 2.36 s and memory words 0.95 s (both concurrent with ALU).

Serial-scan attribution (exp2: 24628607, chunks 1, 4.19 M-step segments):
- unfaulted scan 357–389 ms vs 180–199 ms with everything prefaulted;
- first touch of the 235 MB metadata alone costs 86–101 ms;
- reserving the record lists alone gives 281–327 ms. Legacy lists regrow, and a recycled large block cannot grow in place, so every regrowth was a full copy into fresh pages.

The recorder route produces the same `Prepared`, field for field, and the same error for the same reason:

1. **Scan (cpu_source.zig).** FUNCTION and memory record lists are reserved once to their per-step bound, at most one record per step. Their capacity depends only on the step count, so the large-block recycler hands the next segment the previous segment's already-faulted block. The stitched path's final arrays use the same step-count size class.
2. **Routing (prepared.zig `captureRecorder`).** A counting pass classifies every fact; an unroutable fact fails there, as in the legacy loop. Small families get exact-capacity lists. ALU, BINARY and SHIFT are grouped straight from `cpu.functions`, with no routed copies, followed by the JALR extras (the legacy `af`/`bf` order).
3. **Grouping (stable_dedup.zig).** A presized open-addressing table (load ≤ 1/2, never rehashed; u64 slot = 32-bit hash tag plus index; splitmix hash) keeps first-occurrence order and counts, the same as the std `AutoHashMap` groupers. Fact and weight buffers take a power-of-two size class, so they are recycled across segments, and shrink in place. The unique-memory-word census uses the same table. SHIFT grouping joins the concurrent groupings. Errors are adopted in the serial order: routing, ALU, BINARY, ZBB, words, SHIFT.

**Rejected:** `MADV_HUGEPAGE` on the capture buffers (exp3, 26235159, inflight 4): capture went 8.50 → 11.66 s (10.42/12.91), against 7.09 s without it. The cause is THP direct compaction under the pod's 93 GB cgroup (`compact_stall` 359 k). It is not in the code.

## Parity [M]

- **`T10DIGEST`** (`STWO_RV64_M8_CAPTURE_RECORDER_DIGEST=1`, report-only stderr). This is a field-by-field SHA-256 of every `Prepared` output: CPU metadata, ROM counts, memory/service records, JALR facts, ALU/BINARY/SHIFT/ZBB facts and weights, DIV/MUL requests, raw counts and unique words. The per-segment digest set is identical between arms in every parity run: ab1, ab3, ab4 and ab5, on all 3 blocks (7, 4 and 49 segments).
- **`captured_values_sha256`** is identical in all runs.
- **`advice_all_sha256`** (T1's digest; ab4 binary only) is identical in all 8 runs per block, and equals T1's receipt (`9707f651…`, `a811f4e0…`, `f411dd85…`).
- **Unit tests:** `test-riscv64-word16-execution-prepared` 64/64 passed, including the new `prepared_recorder_test.zig`:
  - legacy == recorder on an executed tape (ALU/BINARY/SHIFT/JALR/MUL/DIV/LD/SD) at chunk counts 1/2/3/7/16 × all four grouping options;
  - error parity for a scan failure (`InvalidExecutionAdvice`) and a grouping failure (`InvalidAluFact`);
  - `checkAllAllocationFailures` on the recorder route;
  - the grouper and word counter vs std `AutoHashMap` on random, heavily duplicated inputs.
- **`rv64_gate.sh`:** pending; see "Gate" below.

## Capture time [M] (`image_and_import_ns`, seconds; 3-rep medians, interleaved; clean commit binary `r4` unless noted)

| block (segments) | setting | legacy | recorder | Δ |
|---|---|---|---|---|
| 26235159 (49) | production (inflight 4, serial ledger), ab5 | 8.497 (8.50, 8.35, 8.97) | **5.999** (6.00, 5.94, 6.15) | **−2.50 s (−29%)** |
| 24628607 (7) | production, ab5 | 2.037 (2.06, 2.04, 1.82) | **1.721** (1.73, 1.64, 1.72) | −0.32 s |
| 26235156 (5) | production, ab5 | 1.631 (1.63, 1.70, 1.63) | **1.442** (1.55, 1.44, 1.44) | −0.19 s |
| 26235159 | T1 inflight 16 + `LOCAL_LEDGER=1`, ab4 (T1 `b78079b47` + this commit) | 5.918 (5.65, 6.06, 5.92) | **4.760** (4.64, 4.81, 4.76) | **−1.16 s (−20%)** |
| 24628607 | T1 settings, ab4 | 1.819 | **1.718** | −0.10 s |
| 26235156 | T1 settings, ab4 | 1.643 | **1.414** | −0.23 s |

The ab3 rerun (pre-cleanup binary with an inert profiler) reproduces these numbers. Legacy → recorder: 26235159 8.593 → 5.900; 24628607 1.888 → 1.759; 26235156 1.637 → 1.451.

**Process CPU, 26235159 production (ab5 medians):** user 96.7 → 91.8 s, sys 27.0 → 16.9 s. Fewer page faults and no regrowth copies.

**Max RSS of the bench process:**
- 26235159: 23.9 → 25.0 GiB at inflight 4, and 27.5 → 26.2 GiB at T1's inflight 16. Recycled step-class blocks keep more pages resident.
- 24628607 and 26235156: flat or lower (6.4 → 6.0 and 4.0 → 3.9 GiB).

**Against the plan's estimates:**
- [E] 26235159 capture 5.76 → ~4.0 s: **4.76 s [M]** at T1's settings, and 5.76/5.92 → 4.76.
- [E] 24628607 about −0.3 s: **−0.32 s [M] at production settings**, but −0.10 s at T1's settings.
- [E] 26235156 about −0.2 s: **−0.19 / −0.23 s [M]**.
- 0 GPU-s: CPU-only change.

## What bounds the narrow scan now [M, exp4, rdtsc per phase, 24628607 serial]

Per step, in ticks; each phase includes about 20 ticks of rdtsc overhead:

| phase | legacy | recorder |
|---|---|---|
| metadata write | ~80 | ~80 |
| append | 76 | 24 |
| `tape.restore` | 55 | 55 |
| checks | 37 | 28 |
| ROM count | 24 | 24 |
| lookup | 24 | 24 |

The rest is first touch of the 235 MB per-segment metadata (about 93 ms per segment). Metadata is retained past capture, so the recycler cannot reuse it unless its owner retires it earlier; that is outside these files. The next lever in this file is a fused `restore` + check step, which must preserve the error order exactly.

## Gate

`rv64_gate.sh`: **not run yet.** Both GPUs are still held by orphan pid 3302210 (30 GB each, m8-native-hybrid combined-serve), which blocks every opt stream.

`pipe1.sh` (pod tmux `t10-pipe1`) runs by itself once both GPUs are below 2 GB and ≥ 2 GB of disk is free. Steps:
- gate flag off on 26235156;
- gate flag on (`--env STWO_RV64_M8_CAPTURE_RECORDER=1`) on 24628607 and 26235156;
- canonical 3+3 on 24628607 (`ab-preset.json`: the T5-style one-image preset; arms differ only by this flag plus the runner's physical guard on the fullstack arm).

Status: `/workspace/m3/runs/m8-opt-T10-narrow-capture-recorder/pipe1.status`. Landing on `codex/rv64-m7-integrate` waits for gate PASS (flag off and on) and a 3+3 that is not slower.

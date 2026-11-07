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
- **`rv64_gate.sh`:** PASS ×3, byte-identical to the frozen D2 golden; see "Gate" below.

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

## Gate [M] (`gates.json`)

`rv64_gate.sh` **PASS ×3** on `64381bbb6`; the code is identical to `76d1b6763`, later commits change receipts/scripts only. Every gate passed all steps (build, unit-zig, unit-python, small-block proof cold+warm byte-identical to the frozen D2 golden `5987d31c…`, 2 fresh CPU receivers, negative corpus):
- flag off, 26235156;
- flag on (`--env STWO_RV64_M8_CAPTURE_RECORDER=1`), 24628607;
- flag on, 26235156.

Extra suites:
- `test-riscv64-word16-execution-prepared`: 64/64 in ReleaseFast and ReleaseSafe, and 64/64 with the flag forced on, so every pre-existing Prepared test also runs the recorder route.
- `test-riscv64-word16-combined-services`: 80/83 with the flag off and with it on, the same 3 failures either way: wire_test "Combined compact transport…", execution_test "Combined mapped CPU and all truth MAIN…", sha256_test "v3 SHA-256 calls…". These are **pre-existing**: the untouched base `c72b51646` fails the same 3 (75/78).

## Canonical 3+3 on 24628607 [M] (`canonical-3x3-24628607.json`, `scripts/rv64_m7_integration_stack.py`, quiet gate accepted on all 6)

**Preset (`ab-preset.json`).** Both arms use the canonical baseline env plus the canonical fullstack device arena `STWO_RV64_DEVICE_ARENA=22G`, and differ only by `STWO_RV64_M8_CAPTURE_RECORDER` (0 = legacy, 1 = recorder). The runner still guards the "fullstack" arm only.

Two preset variants failed first:
- **T5's both-arms-fullstack preset** needs the global-admission v2 runtime, which the canonical a25 image lacks (`MissingGlobalAdmissionRuntimeV2`).
- **The baseline `auto` arena under the runner's guard** failed native stage two with `CudaAllocationFailed`.

Earlier attempts were also refused by the quiet gate while other streams compiled or ran receivers. `pipe2.sh` waits those out.

| (warm, s) | legacy (3 services) | recorder (3 services) | median Δ |
|---|---|---|---|
| **request** | 12.914, 12.777, 13.040 → **12.914** | 12.600, 13.069, 12.344 → **12.600** | **−0.31 s (ratio 0.976)** |
| capture | 2.074, 2.118, 2.128 → 2.118 | 1.788, 1.898, 1.806 → 1.806 | −0.31 s |
| native total before report | 7.187, 7.015, 7.100 → 7.100 | 6.758, 6.880, 6.813 → 6.813 | −0.29 s |
| native prove | 4.751, 4.512, 4.697 → 4.697 | 4.692, 4.687, 4.681 → 4.687 | ≈0 |
| recursion | 5.639, 5.695, 5.905 → 5.695 | 5.816, 6.163, 5.499 → 5.816 | +0.12 (noise; GPU stage, untouched) |

- Payload byte parity: true on all 6 services, with the same proof root and output pin match.
- Fresh receivers: 12/12 accepted.
- GPU-seconds: not measured; the runner reports "unavailable without CUPTI". The change is CPU-only (0 GPU-s by construction).

Land: byte-identical and not slower. The [E] 24628607 estimate of about −0.3 s is met: **−0.31 s [M] request, −0.31 s capture**.

## Review (2026-11-07)

- **How to read the request delta.** The −0.31 s request median is within the run-to-run spread: recorder 12.344–13.069 s overlaps legacy 12.777–13.040 s. The capture delta is the separated, attributable effect: all three recorder runs (≤ 1.898 s) are below all three legacy runs (≥ 2.074 s). The verdict stays "byte-identical and not slower", with −0.31 s capture [M]. The −0.31 s request figure is [M] as a median only and is not a resolved request-level win.
- **Fixes (review commit).**
  - The stitched recorder capacity is now `@max(steps, totals)`, so `items.len = totals` stays in bounds even if the one-record-per-step bound changes.
  - The `T10DIGEST` print is factored into `Prepared.reportDigest`.
  - Both routes share `PARALLEL_GROUPING_MIN`. It is the inherited legacy value and was not re-tuned.
  - A stale test-file reference in `stable_dedup.zig` is corrected.
  - A new unit test runs legacy == recorder on a 136 k-step tape. It is above the threaded-grouping threshold that the 696-step fixture never reached, at chunks 1/7/auto.

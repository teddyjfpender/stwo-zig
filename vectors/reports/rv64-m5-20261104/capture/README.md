# RV64 M5 stream `capture`, iteration 1 (2026-11-04)

Branch `codex/rv64-m5-capture` from `78c3bd5d2` (M4 integrate). Code commit `043923ff9` (+ test-only `d94be93a6`).
Pod: 2x RTX 5090, 48 vCPU, cgroup quota 40.8 CPUs, shared with the other M5 streams. **No run here was quiet**:
the 1-minute load was 7.3–35 and every row records it. Compare interleaved pairs, not absolute values. All
numbers are single observations or medians of 2–3 interleaved runs [M]. Nothing is extrapolated.

## Headline

| block | path | metric | before | after (`043923ff9`) |
|---|---|---|---:|---:|
| 24628607 | GPU production, one-shot bench, inflight 4 | capture | 3.050 (M4 capture stream), 3.275 (M3) | **2.445 s** [M, load 13] |
| 26235156 | GPU production, one-shot bench, inflight 4 | capture | 2.536 (M4 capture), 2.543 (M3) | **2.203 s** [M, load 7.3] |
| 24628607 | CPU diag, inflight 4, interleaved x3 | capture (median) | 2.981 (base) | **2.520 s** (−15%) |
| 24628607 | CPU diag, inflight 4 | segment 0 inputs ready | 1.912 | **1.518 s** |
| 24628607 | CPU diag, inflight 4 | first batch captured | 1.03 | **0.74 s** |
| 24628607 | CPU diag, inflight 8, interleaved x3 | capture (median) | 2.559 (base) | 2.569 s (no change) |
| 26235156 | CPU diag, inflight 4 / 8, x2 | capture (median) | 2.225 / 2.250 | 2.255 / 2.227 (no change) |
| 24697070 | CPU diag, capture only, inflight 4, ONE run | capture | 12.12 (M4 probe, full prove), 5.74 (M3) | **4.31 s**, 0 compaction stalls |

- **Byte-identical.** Every capture run of every binary has the same `captured_values_sha256`
  (607 `e5f5e760…`, 156 `c9f3d40f…`, the M3/M4 digests). The GPU benches match the M3 integrate scale receipts on
  **55/55** (607) and **37/37** (156) proof hashes (native bins, bundle, every leaf, fold, root, tree), and the fresh
  cache-disabled CPU receiver accepted all three roots (`*-gpu-v6*.json`, `correctness.fingerprint_vs_reference`).
- **Gate (capture ≤ 1.0 s on 607): NOT MET.** 2.45 s production. Why and what is next: below.

## What changed (producer scheduling only; no statement, transcript or proof byte changes)

1. **THP regression fix** (`services/collector.zig`). `MADV_HUGEPAGE` is now applied to the prefaulted LS event
   arrays only when `/sys/kernel/mm/transparent_hugepage/defrag` is `defer` or `never` (no synchronous compaction).
   The pod runs `madvise`, so the advice is now off there. `STWO_RV64_CAPTURE_THP=0/1` overrides. The off-thread
   prefault is kept. Evidence (host-wide `/proc/vmstat` deltas per run): every base run has a floor of
   331–334 `thp_fault_alloc` on 607 and 191–193 on 156 (its advised event arrays); v6 has 0 in 9 of 10 dev-block
   runs (the tenth, 1,428, is another tenant). No run in this session hit compaction (host had ~190 GB free), so the
   stall itself was not reproduced; the one 24697070 capture-only run took 4.31 s with 0 stalls (M3 5.74 s).
2. **Chunked CPU capture** (`word16_execution/cpu_source.zig`, `captureChunked`). The 90 ns/step serial
   `CPU.Source.capture` scan (~0.37 s per 4.19M-step batch) runs as up to 8 contiguous ranges in parallel. Each range
   starts at the tape's own `storage[start-1].next_pc`; unknown entry registers are adopted on first read
   (expectation) and unknown access clocks recorded as fix-ups; an ordered stitch checks every expectation against
   the true prefix state and patches the clocks. The checks inside a range are the serial checks verbatim, so the
   result is the serial Source and **the error is the serial error at the serial step** (earliest failing step
   wins). Differential test: every chunk count 1..16 against serial, plus 5 single-field tampers of every step of a
   161-step loop and of the alias/JALR fixture, plus 3 boundary tampers.
   A process-wide helper budget (`STWO_RV64_CPU_CAPTURE_THREADS`, default 8) is shared by concurrent batch captures:
   with no budget (16 per batch) the burst of 7 finishing walks oversubscribed the 40.8-CPU quota and the serial
   ledger slowed (v3 ledger 0.53–0.82 s vs base 0.41–0.59 s); budget 8 restored it (v6 0.33–0.48 s).
3. **Concurrent provider grouping** (`word16_execution/prepared.zig`). ALU dedup, BINARY+Zbb collect and the
   unique-memory-word census run on 3 threads (inputs ≥ 64K facts) and are adopted in serial order, so a failure
   reports the error the serial sequence reports first.
4. **Page-cached first touch in the ordered ledger** (`word16_global_execution/collector.zig` `OwnerPages`,
   enabled by `ethereum/capture.zig` `Ordered.init`). Segment 0 first-touches 726,594 words; each did a page-table
   hash lookup plus 8 first-match region scans (213 ns/word, 155 ms of the 418 ms segment-0 ledger). Now one lookup
   per guest page; exact: pages whose bytes do not all share one first-matching region fall back to the image path
   (including its errors). Segment 0 ledger 418 → 255 ms (profiled, load 9 vs 35).
5. **Ready timeline for M6** (`ethereum/direct.zig`): `direct_capture.segment_ready_ns[]` records the
   `Capture.Ready` instants; the hook contract is in `/workspace/m3/M5-INTERFACES.md` (section `capture`).
6. **Report-only emulator split** (`rv64_ethereum_native_prepare.zig`, `rv64_ethereum_segments.zig`):
   `walk_traced_ns` / `walk_finish_ns`. Optional `STWO_RV64_CAPTURE_JOB_NICE` (off; inconclusive under load).
7. Harness hook `--capture-inflight N` in `scripts/rv64_m3_pod.py` (default unchanged).

## Item 2: inflight 4 → 8 [M]

| binary | inflight 4 | inflight 8 |
|---|---:|---:|
| base `78c3bd5d2`, 607 CPU diag (median of 3) | 2.981 | **2.559** |
| v6, 607 CPU diag (median of 3) | **2.520** | 2.569 |
| v6, 607 GPU production (one run each) | 2.445 (load 13) | 2.533 (load 25) |
| base / v6, 156 CPU diag (median of 2) | 2.225 / 2.255 | 2.250 / 2.227 |

On the base binary 8 is worth −14%; with this commit's changes both settle at ≈2.5 s because the capture tail is now
bound by the serial ledger chain and the last segment's walk, not by admission. **Recommendation to integrate:** keep
the template at 4 with this code (no measured gain from 8, fewer peak buffers); if integrate keeps the M4 code,
raise it to 8.

## Item 3: "block import" (2.78 s)

As the M4 capture README already showed, `capture_breakdown.import_ns` is the whole in-process capture window,
not Ethereum account/tx import, so there is no per-account/tx host target to parallelise, and an import-result cache
keyed on the input hash would only help a repeated request (not a production case). The measured host-side cost of
the guest's block import is in **ledger segment 0** (the guest hashing and copying the block input):
sponge 3,680 calls 145–205 ms, bulk memory 3,088 calls 69–190 ms, first-touch 155 ms (now 52 ms incl. profiling
overhead). Items 4 above attacked the first-touch part.

## Item 5: emulator baselines (M7) [M, 607, v6]

| path | throughput |
|---|---:|
| fast first pass (`fast_execution.Engine`, untraced, 1 thread) | 119–152 MIPS |
| traced segment walk, per worker (`walk_retired / walk_ns_total`) | 7.2–7.6 MIPS |
| of which traced stepping (`captureNext` loop) | 3.19–3.31 s of 3.47–3.58 s summed walk (≈92%), ≈8.3 MIPS |
| of which `batch.finish` (boundary chunks) | 0.27–0.28 s summed (≈8%) |

The traced step is ~18x slower than the untraced engine; `batch.finish` is not the problem. An AOT/threaded
emulator that emits the compact tape directly (the M7 lever) must replace `Native.captureNext`.

## What bounds capture now (607, v6, CPU diag) [M]

Process start → walk init (sync, ~0.3 s ROM authority) → batch 0 traced walk 0.72–0.79 s → admit 0.05 s →
capture 0.43 s → segment 0 ledger 0.25 s → segments 1..6 ledger ~0.045 s each → finish 0.10 s.
Segment ready instants: 0.84–0.99 s (seg 0) … 1.64–1.79 s (seg 6) after capture start.

Next, in order of measured critical-path weight:
1. **Sub-batch parallel walk** (needs mergeable tape + boundary-capture slices in the frontend; the fast pass already
   runs at 120–150 MIPS and could publish 512K-step checkpoints): batch-0 walk 0.75 → ~0.1 s [E].
2. **Walk init off the critical path:** the walk's own request init (~0.3 s, ROM authority) runs before the first
   pass; the walk only needs the loaded image to execute. Owner: request/resident.
3. **Segment-0 sponge**: 3,680 Keccak sponge replays (39 µs each) on the serial ledger.
4. **Address-sharded ledger** (M4 note 3) for the remaining serial chain.

## Tests (pod, ReleaseSafe, `raw/tests.sh`)

| suite | result |
|---|---|
| `test-riscv64-word16-execution-source` (incl. the new chunk-parity/tamper test) | **pass** |
| `test-riscv64-word16-execution-prepared` | **pass** |
| `test-riscv64-word16-global-memory` | **pass** |
| `test-riscv64-word16-combined-services` | 60/60 pass, then the **pre-existing** `wire_test` fsync/munmap abort (M4: 58/58, same abort) |
| `test-riscv64-capture-prefetch` | 55/55 pass, then the **pre-existing** `two packet capture equals serial` abort (M4: 53/53, same) |
| `test-riscv64-word16-global-execution` | 41/41 pass, then the **pre-existing** global `wire_test` abort (M4: 40/40, same) |

The +2 test counts are the THP-mode and first-match-region tests. The aborts reproduce on the untouched tree
(M4 README): directory fsync on `/workspace` returns EINVAL.

## Files

- `<block>-capture-m5.json`: every CPU capture run (binaries base/v1–v6), grouped medians, digests (`summarize.py`).
- `<block>-gpu-v6*.json`: harness receipt-v2 of the GPU benches (stages, fingerprint vs M3, receiver verdict).
- `raw/`: per-run pod receipts (`cap-<block>-<tag>.json` with vmstat compaction/THP deltas, env, load),
  `cap.py`, `build.sh`, `tests.sh`, `gpu.sh`, `tests-v3.log`, `gpu-build.json`.
- `../../progress/capture.jsonl`: 14 rows (11 CPU v6 runs, 3 GPU benches).

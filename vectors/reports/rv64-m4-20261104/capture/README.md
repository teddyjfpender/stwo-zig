# RV64 M4 stream `capture`, iteration 1: ordered-ledger diet and the per-segment ready hook

Branch `codex/rv64-m4-capture`, based on `bcd401ce4`. Pod: 2x RTX 5090. The pod was shared: the 1-minute load average was 30–95 during this work, and every row records its own value.

Labels:
- **[M]** is measured: one observation per row, with its receipt in this directory.
- **[E]** is an estimate.

No number here is a median.

## Headline

| block | path | metric | M3 baseline | this commit |
|---|---|---|---:|---:|
| 24628607 | GPU production (scale env, 2 GPUs) | ordered ledger | 1.167 s | **0.551 s** [M] |
| 24628607 | GPU production | capture (`all_inputs`) | 3.275 s | **3.050 s** [M] |
| 24628607 | CPU capture diag, inflight 16, 16 workers | capture | 3.081 s (base r2), 3.732 s (base r1) | **2.515 s** [M] |
| 26235156 | GPU production | ordered ledger | 0.718 s | **0.280 s** [M] |
| 26235156 | GPU production | capture | 2.543 s | 2.536 s [M] (init was +0.18 s noisier) |
| 26235156 | CPU capture diag, inflight 16, 16 workers | capture | 2.461 s (base r2) | **2.215 s** [M] |

Proofs and acceptance:
- **Proofs are byte-identical to the M3 baseline** (`integrate/<block>-2gpu-scale`, same env and library `7de22322`). That covers all 55 proof hashes on 24628607 and all 37 on 26235156: native bins, bundle, every leaf, fold and root, and the tree [M].
- The **fresh, cache-disabled, CPU-only receiver** built from this tree **accepts both blocks** [M].
- `captured_values_sha256` is equal across every baseline and candidate capture run: `e5f5e760…` for 24628607 and `c9f3d40f…` for 26235156. The 24628607 value is the M3 attribution receipt's digest.

**Gate status (M4, capture on 607 ≤ 1.5 s): NOT MET.** The best run is 2.52 s [M]. Why, and what closes the gap, is in "What bounds capture now" below.

## What changed (scheduling and data structure only; no statement, transcript or proof byte changes)

1. **Paged radix state table for the ordered ledger** (`word16_global_execution/ledger_table.zig`).
   - It replaces `AutoHashMapUnmanaged(u64, State)`, which is probed once per memory record and once per service lane.
   - Layout: a guest word lives in its 4 KiB guest page. There is a two-level 1024×1024 directory for pages below 4 GiB, plus a one-entry last-page cache, because RISC-V traces hit the same stack or heap page repeatedly.
   - Pages are allocated from 64-page slabs. Pages above 4 GiB and unaligned keys keep exact hash-map semantics.
   - The key set and values are the same as before, and no iteration order is exposed.
   - A 200k-operation randomized differential test against `AutoHashMap` is included.
2. **No per-shard capacity rehash.** The `ensureUnusedCapacity(memory.len)` hint used to grow and rehash an ever-growing map once per segment. It is gone.
3. **`boundaries()`: `std.sort.pdq` instead of `std.mem.sort`.** Addresses are unique, so the unstable sort yields the stable sort's order. `finish` dropped from 0.150 s to 0.065 s [M, GPU path, 607].
4. **LS event arrays prepared off the serial thread.**
   - Each segment's ledger writes about 1.5 M × 80 B, about 123 MB, of fresh memory.
   - The capture job thread that produced the segment now allocates this array, advises transparent huge pages on it (`MADV_HUGEPAGE`, needed because the pod's THP mode is `madvise`) and touches every page.
   - It then hands the array to the ordered ledger, which overwrites every element.
   - The cost: first-touch faults move from the serial chain into the parallel jobs.
5. **Per-segment ready hook for M6** (`capture.Ready`, `Ordered.on_ready`, `direct.Started.ready`).
   - It is called in index order once a segment's narrow capture is accepted and its ledger shard is final.
   - It passes the segment's `Native` and LS events, plus a timestamp. Both stay immutable until `Owner.deinit`.
   - It defaults to null, so behaviour is unchanged. This is the seam for streaming native stage 1 per segment.
6. **Report-only instrumentation.**
   - Setting `STWO_RV64_CAPTURE_LEDGER_PROFILE=1` prints, on stderr, a per-segment ledger cost split by service family.
   - Segment stats gain `walk_ns_total`, `walk_ns_max` and `walk_retired`, the traced-emulator throughput baseline.

**Byte-identity argument.**
- Every output array is written element by element by the same code, in the same order, from the same inputs.
- The table is a pure map replacement: it has the same key set and the same value at each key.
- Sorting unique keys gives a unique order.
- Preallocation only changes where a buffer's pages are faulted, not its contents.
- The hook only reads.
- This is confirmed end-to-end by proof-hash parity on both dev blocks and by the capture digest.

## Measurements

**CPU capture diagnostic** (`rv64-word16-ethereum-gkr capture REQ - 0 RES`, in-process execution with 8 workers; files `raw/cap-*.json`):

| block | run | inflight / workers | capture | init | first inputs | last inputs | ledger | load |
|---|---|---|---:|---:|---:|---:|---:|---:|
| 24628607 | base r1 | 4 / 8 | 3.732 | 0.755 | 2.399 | 3.557 | 1.242 | 71 |
| 24628607 | base r2 | 4 / 8 | 3.081 | 0.741 | 1.971 | 2.938 | 0.973 | 58 |
| 24628607 | v3 | 4 / 8 (production) | 2.976 | 0.692 | 2.009 | 2.832 | 0.544 | 55 |
| 24628607 | v3 | 8 / 8 | 2.638 | 0.744 | 1.945 | 2.538 | 0.504 | 55 |
| 24628607 | v3 | 16 / 16 | **2.515** | 0.707 | 1.835 | 2.364 | 0.427 | 54 |
| 26235156 | base r2 | 4 / 8 | 2.461 | 0.705 | 1.817 | 2.325 | 0.623 | 53 |
| 26235156 | v3 | 4 / 8 | 2.300 | 0.729 | 1.754 | 2.168 | 0.294 | 52 |
| 26235156 | v3 | 16 / 16 | **2.215** | 0.693 | 1.698 | 2.104 | 0.268 | 51 |

Before this change, inflight 4 versus 8 made no difference (the M3 host stream measured 3.35 against 3.33 s), because the serial ledger gated admission. Now it pays: 2.976 → 2.638 s on 24628607 [M].

**Integration note:** raise `capture_options.max_inflight_packets` to 8 or more in the plan template. The harness template is infra-owned.

**Ledger profile** (24628607, v2, `raw/cap-24628607-v2-prof-i8.json` stderr):
- LS records cost 44–104 ms per segment for 0.8–1.6 M records, about 55–65 ns per record.
- In segment 0, sponge replay costs 58 ms (3,680 calls) and bulk memory 69 ms (3,088 calls).
- Everything else is under 12 ms per segment.
- The table holds 1.03 M words in 20.7 MB.

**GPU production path** (`raw/<block>-gpu-v3-receipt.json`, harness `bench`, 2 GPUs, M3 scale env):

| block | request | capture | setup | native prove | recursion | proof parity vs M3 | receiver |
|---|---:|---:|---:|---:|---:|---|---|
| 24628607 | 53.63 (M3 51.11) | 3.050 (3.275) | 12.89 | 7.68 | 29.82 | 55/55 identical | accepted |
| 26235156 | 35.55 (M3 34.28) | 2.536 (2.543) | 9.10 | 4.93 | 18.85 | 37/37 identical | accepted |

Request walls are within shared-pod noise: recursion varied by about 2.5 s with no recursion change in this commit. Do not read the request deltas as a regression or an improvement.

## Correction to the plan's reading of "block import 2.78 s"

`capture_breakdown.import_ns` is the whole in-process import window. It covers waiting on segment execution, `Packet.fromNative` admission, `captureOne` and the ordered ledger. It is **not** Ethereum account or transaction import. The guest's own block import runs inside RV64 execution, which is the fast first pass of 0.22 s on 607 [M].

So "parallelise block import per account/tx" has no host-side target. The levers are the ones below.

## What bounds capture now (24628607, v3 and probe, [M])

**Critical path.** These are segment-0 numbers from the 16-worker runs, measured from process start:
1. `Started.start` runs the walk's own request init synchronously first, about 0.26–0.3 s, mostly ROM authority.
2. `Image.Owner.init` follows: 0.26 s, of which 0.24 s is `Program` plus ROM authority (`PROBE_IMAGE`).
3. Meanwhile, the walk's fast first pass runs at 122–142 MIPS.
4. **The traced segment walk takes 0.66–0.81 s per 4.19M-step batch, at 7.1–7.5 MIPS per worker.**
5. Admission takes 0.07 s.
6. **`captureOne` takes about 0.65 s per batch.**
7. The ledger now takes about 0.06–0.09 s per segment, serially.
8. Finish takes 0.07–0.11 s.

The serial ledger is no longer the long pole. Per-segment producer latency is: about 1.4 s of serial work on one core per segment, and 7 segments against 48 cores. Process-average busy cores are 1.5–1.7 [M]. The gate's "≥16 busy cores during capture" metric needs a per-window sampler (measure stream). It was not measured here, but it is certainly far below 16.

**`captureOne` breakdown** for a full 4.19M-step batch. These come from a throwaway probe build: phase timers in `prepared.zig` and `expected_image.zig`, diff in `raw/probe-instrumentation.diff`, not committed as code. The data is in `raw/cap-*-probe-i16w16.json`, and the digests are unchanged.

| phase | time | note |
|---|---:|---|
| `CPU.Source.capture` | 0.36–0.39 s | about 58%. One register- and clock-chained loop, about 90 ns/step. `program.lookup` and `factIndex` are already direct-indexed, so the cost is per-step reconstruction, checks and three ArrayList appends. |
| fact routing | 0.05–0.08 s | |
| ALU dedup | 0.09–0.15 s | |
| binary collect | 0.02–0.12 s | |
| shift and tail | 0.03–0.05 s | |
| unique-memory-word hash set | 0.01–0.025 s | |

## Next iteration

Ordered by measured critical-path weight; target ≤1.5 s first, then ≤0.6 s at M7 [E].

1. **Intra-batch parallel traced replay.** The fast pass already runs at 122–142 MIPS.
   - Have it publish sub-batch checkpoints, for example every 512K steps.
   - Replay each 4.19M-step batch as 8 chunks on 8 workers. Each chunk produces its tape slice and boundary capture.
   - Concatenate in order, under the same continuity rule as segments, so the batch stays byte-identical.
   - Expected effect: walk latency 0.75 s → about 0.1–0.15 s [E].
2. **Chunked `CPU.Source.capture`.** I propose the capture stream take `word16_execution/cpu_source.zig`, which no stream owns.
   - The register values at a chunk boundary are in the tape: `lhs`, `rhs` and `previous_rd`.
   - The 32 register clocks need a prefix stitch: each chunk records its last-write clock per register, and a 32-entry scan fixes up first reads.
   - The metadata, functions, memory and services arrays concatenate in order.
   - The dedups split by hash range.
   - Expected effect: 0.65 s → about 0.1 s per batch [E].
   - The ordered ledger needs only `cpu.memory` and `cpu.services`, so it can also start before the dedups finish.
3. **Address-sharded ledger** (the plan's prefix-stitch idea). After items 1 and 2, the serial ledger chain (7 × about 0.07 s) is the long pole again.
   - LS dispatch is about 75% of it.
   - Fixed-value service lanes (Keccak, secp, SHA-256, arith256, curves) decompose into independent per-address operations.
   - Sponge, bulk and JUMPDEST calls carry cross-address data flow and need a barrier.
   - Their per-segment counts (2–8K) make barriers affordable.
4. **Init off the request path.** The resident stream caches `Image.Owner` and the ROM authority, and the walk's request should borrow the same authority.
   - Expected effect: −0.25 s to −0.5 s on the path [E].
   - Until then, `Started.start` could build the walk on its own thread so that `Image.Owner.init` overlaps it. Batch 0 is gated by the walk, so this gives little on the critical path today.
5. **M7 emulator.** Baselines [M]: the fast pass runs at 122–142 MIPS and the traced walk at 7.1–7.5 MIPS per worker.
   - The minimal-trace emulator (ZisK/Airbender style) should emit, directly at more than 100 MIPS per worker, the records that `CPU.Source.capture` reconstructs: the compact tape plus memory, service and function records.
   - That fuses items 1 and 2.
6. **THP for the other large producer arenas.** The pod is in `madvise` THP mode. Candidates are the engine `LargeBlockRecycler` and the tapes.

Expected after items 1–3 on 607 [E]: init 0.5 + walk 0.15 + admission 0.07 + capture 0.1 + sharded ledger 0.1 + finish 0.07 ≈ 1.0 s. Item 4 brings that to about 0.7 s.

## Tests

Run on the pod with ReleaseSafe and `-Dcpu=x86_64_v4+sha` (`raw/tests.sh`). Every abort below reproduces identically on the untouched `bcd401ce4` tree.

| suite | this branch | untouched `bcd401ce4` |
|---|---|---|
| `test-riscv64-word16-global-memory` | **pass** (rc 0) | n/a |
| `test-riscv64-word16-combined-services` (includes `collector_test` and `boundary_receiver_test`, plus the new `ledger_table` tests via `collector.zig`) | 58/58 tests pass, then **pre-existing** SIGABRT in `wire_test` "Combined compact transport … cleans every read allocation failure" (`munmap` EINVAL `unreachable` in `services/wire.zig` `write`) | 56/56, same test, same abort |
| `test-riscv64-capture-prefetch` (includes the 2 new `ledger_table` tests: a 200k-op differential test against `AutoHashMap`, and absent-value semantics) | 53/53 tests pass, then **pre-existing** SIGABRT in `capture_prefetch_test` "two packet capture equals serial…" (`munmap` EINVAL in `rv64_ethereum_native_prepare.runWithOptions`) | 51/51, same test, same abort |
| `test-riscv64-word16-global-execution` | 40/40 tests pass, then **pre-existing** SIGABRT in `wire_test` "global wire v2 streams beyond full cell blocks…" | 38/38, same test, same abort |

**Likely cause of all three aborts: the pod environment, not code.**
- The global-execution trace is unambiguous: `std.posix.fsync(dir.fd)` returns EINVAL at `word16_global_execution/wire.zig:73`, and the stdlib treats EINVAL as `unreachable`.
- The other two traces name `munmap` and `free` frames. Both sit in functions that fsync directories (`rv64_ethereum_native_prepare.runWithOptions`, `services/wire.zig` `write`), so those frames are probably ReleaseSafe line mis-attribution.
- The tests' `tmpDir` lives under `/workspace/...`, and that filesystem appears to reject directory fsync.
- None of these paths are touched by this commit, and the untouched tree reproduces each abort. I flagged them for the integrate stream: run these suites with a tmp dir on a filesystem that supports directory fsync.

The end-to-end correctness test is the strongest one available: proof-hash parity on both dev blocks, plus the fresh receiver.

## Files

- `<block>-capture-ledger.json`: the summary receipt, with every CPU capture run, the GPU production stages, the producer breakdown, proof parity and the receiver verdict. Generated by `summarize.py` from `raw/`.
- `raw/`:
  - pod receipts: CPU capture runs and GPU harness receipts;
  - run scripts (`cap.py`, `parity_m3.py`, `build.sh`, `tests.sh`) and their resource files;
  - `code-manifest.sha256`: the sha256 of the 8 changed source files, byte-identical to the pod build tree that produced v3.
- `../../progress/capture.jsonl`: one row per measured run.

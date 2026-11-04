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

## What bounds capture now (24628607, v3, [M])

The critical path is:

`walk request init` (≈0.7 s, overlapped with `Image.Owner.init` ≈0.7 s) → `first pass` (0.19–0.22 s, 122–142 MIPS) → **`traced segment walk`** (0.66–0.81 s per 4.19 M-step segment, **7.1–7.5 MIPS per worker**) → admission (0.07 s) → **`captureOne`** (≈0.67 s per batch) → ledger (now ≈0.06–0.09 s per segment) → finish (≈0.07–0.11 s).

The serial ledger is no longer the long pole. Two things are:
- **Per-segment producer latency.** The traced walk plus `captureOne` is about 1.5 s for a segment, and only 7 segments exist, against 48 cores.
- **Init.** Image and ROM authority take about 0.7 s.

Process-average busy cores are 1.5–1.7 [M]. The ≥16 "busy cores during capture" metric needs a per-window CPU sampler (measure stream). It was not measured here, but it is certainly far below 16.

## Next iteration

Plan to hit ≤1.5 s, then ≤0.6 s at M7 [E]:

1. **Intra-segment parallel replay.** The fast pass already runs at 122–142 MIPS. Have it publish sub-batch checkpoints, for example every 512 K steps, and replay each 4.19 M-step batch as 8 chunks on 8 workers.
   - Each chunk produces its tape slice and boundary capture.
   - An ordered concatenation keeps the batch byte-identical, checked by the same continuity rule as segments.
   - Expected effect: walk latency 0.8 s → about 0.1–0.15 s per batch [E].
2. **Chunked `captureOne`.** `CPU.Source.capture` (in `word16_execution/cpu_source.zig`, which no stream owns; I propose capture takes it) is one register- and clock-chained loop.
   - The register values and the 32 register clocks at chunk boundaries are derivable from the tape (`lhs`, `rhs`, `previous_rd` and the clock index).
   - So the loop can split into P chunks plus a prefix stitch for `clocks`. The metadata, functions, memory and services arrays then concatenate in order.
   - Fact deduplication can be split by hash range.
   - Expected effect: 0.67 s → about 0.1 s per batch [E].
   - The ordered ledger only needs `cpu.memory` and `cpu.services`, so it can also start before deduplication finishes.
3. **Init off the request.** The resident service caches `Image.Owner` and `ProgramAuthority.initWithRom`; that belongs to the resident stream. The walk's own `Request` init is the same ELF and authority, so it should borrow the cached copy.
   - Expected effect: −0.7 s [E].
4. **Address-sharded ledger** (the plan's prefix-stitch idea), only if it is still on the path after 1 and 2. The profile shows LS dispatch is about 75% of the remaining ledger time.
   - Fixed-value service lanes (Keccak, secp, SHA-256, arith256, curves) decompose into independent per-address operations.
   - Sponge, bulk and JUMPDEST calls carry cross-address data flow and need a barrier.
   - Their per-segment counts (2–8 K) make barriers affordable.
5. **M7 emulator.** Today's baselines [M] are 122–142 MIPS for the fast pass (`fast_execution.Engine`) and 7.1–7.5 MIPS per worker for the traced walk.
   - The traced walk, not the interpreter, is the cost.
   - The minimal-trace emulator (ZisK/Airbender style) should emit only the compact tape plus memory and service records that `captureOne` and the ledger consume, at more than 100 MIPS per worker.
6. **THP for the remaining large producer arenas.** The pod is in THP `madvise` mode, so huge pages only appear where `MADV_HUGEPAGE` is set, as in item 4 above. The other large arenas belong to engine `LargeBlockRecycler` and the tapes.

## Tests

On the pod, with ReleaseSafe and `-Dcpu=x86_64_v4+sha`, see `raw/tests.sh`:
- `test-riscv64-capture-prefetch`: 53/53 tests pass, including the 2 new `ledger_table` tests. The suite then aborts in `capture_prefetch_test` "two packet capture equals serial…", with `munmap` EINVAL in `rv64_ethereum_native_prepare.runWithOptions`.
- That abort is **pre-existing**: the untouched `bcd401ce4` tree fails identically (51/51 tests pass, same test, same signal 6). It is not on the direct-capture path.
- Further suites are recorded in the commit message.

## Files

- `<block>-capture-ledger.json`: the summary receipt, with every CPU capture run, the GPU production stages, the producer breakdown, proof parity and the receiver verdict. Generated by `summarize.py` from `raw/`.
- `raw/`:
  - pod receipts: CPU capture runs and GPU harness receipts;
  - run scripts (`cap.py`, `parity_m3.py`, `build.sh`, `tests.sh`) and their resource files;
  - `code-manifest.sha256`: the sha256 of the 8 changed source files, byte-identical to the pod build tree that produced v3.
- `../../progress/capture.jsonl`: one row per measured run.

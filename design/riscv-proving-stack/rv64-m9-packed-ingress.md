# RV64 M9 L1a: packed class ingress (device decode of cache_pack statics)

Stream `m9-packed-ingress`, branch `codex/rv64-m9-packed-ingress`, cut from `codex/rv64-m7-integrate` @ `95e3d7e15`.
Flag `STWO_RV64_M9_CLASS_PACKED_INGRESS=1`. It is default off and not yet linked into the native library.
Lever L1a of `rv64-m9-io-streaming.md` (branch `codex/rv64-m9-io-design`).
Receipts are in `vectors/reports/rv64-m9-prep/packed-ingress/`.
Labels: [M] measured, [D] derived from [M], [E] estimate.

## 1. What it does

Today the host keeps leaf class statics packed. `CachePack.compressClass(is_leaf)` is true for leaves; folds are packed only with `STWO_RV64_PACK_FOLD_CACHE=1`. Two kinds of statics are packed:
- the 45 FIXED forest columns, as `PPCache.PackedPP`;
- the assignment task records (8 words, channels = 8), as `PlanClassCache.Template.packed_tasks`.

On every hit the host unpacks them on the CPU pool, then uploads the logical words:
- 24628607 has 19 leaf classes: 15.8 GB logical vs 0.455 GB packed [M, IO doc §1];
- host unpack costs 3.70 CPU-s per request [M, IO doc].

L1a uploads the packed payload as it is and decodes it on the device, straight into the buffer the consumer kernels already read. The decode writes exactly the words `cache_pack.Packed.unpack` writes, so every downstream kernel, root and proof byte is unchanged.

| file | role |
|---|---|
| `src/backends/cuda/native/rv64/m9_class_unpack.{h,cu}` | decoder. `stwo_rv64_m9_class_unpack_stream(stream, jobs, n_jobs, total_blocks, status)` takes a context-free stream; `_on(ctx, lane, ...)` uses Custody. |
| `src/integrations/riscv_cuda/rv64/m9_class_packed_ingress.zig` | host side: flag, staging `plan`/`fill` (job table + block tables + payloads in one pinned image with absolute device pointers), ABI mirrors, launch symbol. Standalone, `zig test` 2/2. |
| `tools/rv64-m9-packed-ingress/{corpus.zig,bench.cu}` | corpus packer (`cache_pack.zig` + liblz4, checks and times the host unpack) and the CUDA parity / throughput / negative bench |
| `src/integrations/riscv_cpu/rv64_recursion/om31_native/m9_class_corpus_test.zig` | `zig build test-riscv64-m9-class-corpus`: dumps the actual CPU leaf class statics (D2 fixture) when `STWO_RV64_M9_CORPUS_DIR` is set |

### Kernel design

`lz4_blocks` stores 16,384-word blocks. Each block is the LZ4 block format (or a verbatim copy when `raw`) of the per-channel wrapping deltas, stored as 4 byte planes per channel.

1. **`lz4_pass`.** One warp decodes one block.
   - It writes the filtered bytes into the block's own output region, which is exactly `count*4` bytes.
   - All lanes parse the same stream, so control flow is uniform. Literal and match copies are spread across the lanes.
   - There is one `__syncwarp` per match. An overlapping match is written as a period-`off` repetition, so every byte is independent.
   - The decoder enforces the LZ4 spec end rules: the last 5 bytes are literals, the last match starts at least 12 bytes before the end, the final sequence is literal-only and must end at exactly `out_n`. It also checks offset ≠ 0 and offset ≤ op.
2. **`scan_pass`.** One 512-thread CTA handles one block.
   - It loads the region into shared memory.
   - Each thread takes 32 rows of one channel: 2 × uint4 per byte plane, then `__byte_perm` 4×4 transposes, then a wrapping prefix sum in registers.
   - A segmented Hillis-Steele scan combines the chunk totals within each channel.
   - Results go to padded shared staging (no bank conflicts), then coalesced uint4 stores write back in place.

One launch pair covers every value of a node: a job table with a block prefix, and a binary search per block. Malformed input sets status bits (1 shape, 2 length/chain, 4 lz4, 8 offset). The caller must refuse the node on a nonzero status. A device status word is the standard M8 `Verdict` pattern, so no host branch is needed.

Rejected variant, measured: decode heavy blocks into shared memory, 1 CTA per SM, a grid-stride loop over blocks with payload > T.
- A sweep over T = 512–4096 B gave 6.1–6.5 ms vs 2.86 ms for the warp/global decoder on the real corpus [M].
- The cost per LZ4 sequence is bound by serial instruction latency, not by the location of the match source, so concurrency across warps wins.
- The first CTA-wide decoder (v0: 512 threads, one `__syncthreads` per sequence) reached 17.7 GB/s on tasks [M].

## 2. Results (RTX 5090, PCIe 5.0 x8 on this pod, driver 570.195.03)

**Parity.** Device output == host `cache_pack` unpack on every word, at aligned and misaligned (+4 B) outputs [M]:
- the actual CPU leaf corpus (46 values, 342.5 MB, 24.1×);
- the actual-leaf ×3 production-size node (138 values, 1.03 GB);
- a production-shaped synthetic class (31 values, 0.93 GB, 27.0×, calibrated to the measured 24628607 ratios of 38× FIXED / 20× tasks vs 42× / 20–35× [M]);
- an edge-shape corpus: every legal channel count 1…128, partial last blocks, raw blocks, long periodic matches; 144 values.

**Negative cases** [M, corrected in review §6]. Refused by status: broken payload chain (status 2), match offset 0 (status 8), truncated final payload (status 4), illegal channel count (status 1), and (since review) a job table whose `first_block` prefix or `total_blocks` undercounts (status 1). A payload bit flip is **not** always refused: on the real and synthetic corpora the flip broke the grammar (status 4), but on the edge-shape corpus it stayed grammar-valid and decoded to 7 wrong words with **status 0**. Only the bench's word compare saw it. That is inherent (no checksum; the host `LZ4_decompress_safe` path behaves the same) and is not a soundness issue: a wrong static word only makes the node's proof fail to verify. `compute-sanitizer` memcheck reports 0 errors and racecheck 0 hazards [M, rerun in review on the fixed decoder incl. all negative cases].

| corpus (one batched launch = one node) | logical | packed | decode median [M] | of which LZ4 / scan [M] | packed H2D [M] | logical H2D at 28.15 GB/s [D] |
|---|---:|---:|---:|---:|---:|---:|
| actual CPU leaf ×3 (production node size) | 1027.5 MB | 42.6 MB | **4.48 ms** (229 GB/s out) | 3.17 / 1.33 ms | 1.52 ms | 36.5 ms |
| actual CPU leaf (D2 fixture) | 342.5 MB | 14.2 MB | 2.85 ms (120 GB/s) | 2.40 / 0.45 ms | 0.52 ms | 12.2 ms |
| synthetic production class | 932.1 MB | 34.6 MB | 2.77 ms (336 GB/s) | 1.61 / 1.21 ms | 1.23 ms | 33.1 ms |
| edge shapes | 18.9 MB | 9.3 MB | 2.11 ms | – | 0.34 ms | 0.7 ms |

**Host unpack baseline.** A single thread runs 1.33–1.40 GB/s [M, corpus tool on the pod], about 0.73 CPU-s per 1.03 GB node.

**Critical path.** The LZ4 pass is bound by the longest serial sequence chain, not by bytes:
- the actual leaf data have p50 24 / p99 5,336 / max 8,079 sequences per block [M];
- that gives ≈286 ns per sequence [D: 2.31 ms FIXED-section LZ4 pass, which holds the 8,079-sequence block / 8,079];
- decode time is therefore a tail floor of ≈2–2.9 ms plus a throughput term, **not** flat: the same data ×3 (same max chain) goes from 2.85 ms at 0.34 GB to 4.48 ms at 1.03 GB [M], ≈2.4 ms per extra GB [D]. A 0.83 GB production node is ≈4.0 ms [E: 2.85 + 0.49 × 2.38], unmeasured on production data (24628607's ratios are higher, 47× FIXED / 27× tasks [M IO telemetry], so fewer sequences; the estimate is likely conservative).

**Overlap.** For most of that window only the few heavy-block warps are live, so the decode overlaps compute on another lane well. This is untested at request level.

## 3. Projection per node and per block [D]

Per leaf node of 24628607 (15.8 GB / 19 = 0.83 GB logical, 24 MB packed [M, IO doc]):

| | today | L1a |
|---|---:|---:|
| link | 29.6 ms at 28.15 GB/s [D] (33.8 ms at the IO doc's 24.6 GB/s) | 0.85 ms packed H2D + ≈4 ms device decode [E: 4.48 ms per 1.03 GB measured, tail-bound] |
| host CPU | 0.195 CPU-s unpack [D: 3.70 / 19] | 0 |
| pinned staging per job | 0.83 GB | 24 MB |

So L1a saves 28.7 ms of link per node, minus ≤4 ms of decode on a second lane.

Leaf nodes ≈ 2.7 × segments [D: 19 packed classes on 24628607, 7 segments; bench15-1 SUMMARY]. The block rows below use the mainnet gas sample (2,900 blocks): p50 ≈ 29–30M gas ≈ 26235168 (28 segments), p95 ≈ 54–58M ≈ 26235159 (49 segments).

| block | leaf nodes [D] | logical link saved | link time saved, per GPU (2 GPUs) | device decode, per GPU | host unpack saved |
|---|---:|---:|---:|---:|---:|
| 24628607 (7.4M gas, 7 seg) | 19 [M] | 15.3 GB | 0.27 s at 28.15 GB/s (0.31 s at 24.6) | 0.04 s | 3.7 CPU-s [M] |
| p50 ≈ 26235168 (29.1M, 28 seg) | ≈76 | ≈61 GB | **≈1.09 s** (1.24 s) | ≈0.15 s | ≈14.8 CPU-s |
| p95 ≈ 26235159 (57.7M, 49 seg) | ≈133 | ≈107 GB | **≈1.90 s** (2.18 s) | ≈0.27 s | ≈26 CPU-s |

**Caveats.**
- How much of the link time is wall time depends on how much H2D is exposed. The IO doc estimates ≈0.27–0.53 s on 24628607 and 4–5.5 s/GPU of link time on 26235159 [E]. These rows are the upper bound on the wall saving; see the review-corrected table in §6 for the rate-consistent upper bound and an exposure-scaled estimate.
- The leaf-node count per segment for large blocks is extrapolated from one block. Measuring it is E1/Q1 in the IO doc.
- Q1 is partly answered here: every packed class in the census is a leaf class, because `compressClass` packs leaves only by default. M8 fold residency therefore does not overlap L1a.

## 4. Integration once GPU-native lands (call sites on `codex/rv64-m8-gpu` @ `b289b021f`, read-only)

The jobs path is primary; the legacy path is a fallback.

**Producer side: stop unpacking on the host.**
1. `om31_native/outer_wrap.zig`.
   - `PPCache.acquire` (l.267) calls `PackedPP.unpack` (l.217, l.276). With the flag set it should hand out a borrowed `*const PackedPP` lease (the packed columns plus `meta`) instead of a host `PP`.
   - The authority needs only shape: `prove.zig` `prepareForDeviceProver` reads `column.logSize()` (l.94/145). Keep `meta` with zero-length values plus a `log_sizes` array.
   - Audit the remaining host readers of `pp.columns[i].values` on the device path. A read-only grep on m8-gpu finds `outer_source.zig:350,447` (sizes only), `outer_job_prestage.zig:400` (one column's values, to inspect) and `outer_job_factory.zig:641`.
2. `riscv_cuda/rv64/outer_assignment.zig`.
   - `Template.taskView` (l.115–121) is called from `fromTemplateSeeds` (l.657). With the flag set, return the `packed_tasks` view and leave `Prepared.tasks` empty.
   - Move the capability check (`Prepared` l.803) to class adoption: `capability_checked` already exists.

**GPU-native jobs (`STWO_RV64_M8_JOBS=1`).**

3. `jobs/outer_job_prestage.zig`.
   - l.718–720 builds `fixed_raw` from `key.pp.columns`; l.729 sets `.tasks = prepared.tasks`.
   - Add `fixed_packed: []const *const CachePack.Packed` and `tasks_packed: ?*const CachePack.Packed` to `Staged`.
4. `jobs/outer_staged.zig`.
   - `Image.layout` (l.217) keeps the `tasks` range, which reserves the words, but `Staged.pack` (l.248, section `.{ i.tasks, a.tasks }`) skips it when packed.
   - `packFixed` (l.179–186) is replaced by a packed gather: no memcpy of 0.5 GB into pinned memory.
5. `jobs/outer_job.zig` `OuterNodeJob.stage` (l.433–486).
   - In the `fixed.fresh` branch (l.474–481), the per-node region loop or the node region (a leaf's tasks):
     1. call `m9_class_packed_ingress.plan` over the targets `{FIXED column i → fixed.buffer.ptr + fp.offsets[i]*4}` and `{tasks → regions[node] + image.tasks.offset*4}`;
     2. `s.alloc(layout.stageWords())`;
     3. `fill(..., pinned, stage_device = buffer.ptr)`;
     4. one `s.upload`.
   - In `enqueue` (l.593), before the B2N interpolation that consumes `fixed_commit.evaluations` (l.481) and before the assignment kernels, launch `stwo_rv64_m9_class_unpack_stream(exec stream, jobs, n, total_blocks, status_word)`.
   - The status word is a new `Check` (`class_unpack_status`) in the node's slab entry, so it never needs a host readback.
   - Footprint: `staged_words += layout.stageWords()`; `pinned_words` drops by the logical FIXED + task words.
6. `jobs/outer_fixed_job.zig` `FixedJob.stage` (l.104–113): the same packed gather for the precommit job, with a decode in its `enqueue` before `outer_trace_commit`. With handoff (hybrid default) the node then reuses the coefficients and decodes nothing.
7. `jobs/gpu_native.zig` `ClassCache` (l.581) and `RegionKind.class_cache` (l.683), as L1b, optional.
   - A warmed leaf class can keep its packed staging image device-resident: 24 MB per class [M], 0.455 GB per 24628607 request, ≈1.8 GB for p50 and ≈3.2 GB for p95 [D] split over 2 GPUs.
   - The per-node cost is then the 2–4.5 ms decode only, with zero H2D.
   - This is only worth it if L4 (canonical leaves) makes leaf classes recur across blocks.

**Legacy owner path (if it outlives M8).**

8. `outer_fixed.zig` `Owner.uploadImpl` (l.75–89; one `api.upload` per column) and `outer_assignment.zig` `Prepared.generate` `Static.words` (l.892–905; one-shot leaf leases). Use the same `plan`/`fill`, upload into one scratch lease, and launch `_on(native_context, lane 0, ...)` before the existing `ctx.join()`.

**Build.**

9. Add `"m9_class_unpack"` to the `rv64/` list in `scripts/rv64_cuda_native_library_build.py` (l.214).
   - Add `stwo_rv64_m9_class_unpack_on` and `_stream` to `src/backends/cuda/native/rv64/required_symbols.json`.
   - `_on` includes `custody.cuh`; standalone builds define `STWO_RV64_M9_STANDALONE`.

**Acceptance (IO doc E3).**
- With `STWO_RV64_M9_CLASS_PACKED_INGRESS=1`, warm and cold H2D on 24628607 both drop by ≥14 GB.
- The decoder takes ≤10 ms per node; 4.48 ms per 1.03 GB node is measured here.
- Host `GPU_OUTER_{PP,PLAN}_PACK unpack` ns go to 0.
- Proof bytes are identical (39/39 + 32/32 golden).
- `=check` mode: decode on device, also host-unpack, and compare words. `bench.cu` already does this offline.

## 5. Reproduce

```
# local (macOS): actual CPU leaf statics (4.4 GB peak [M, memguard])
STWO_RV64_M9_CORPUS_DIR=$DIR memguard run --gb 8 -- zig build test-riscv64-m9-class-corpus -Doptimize=ReleaseFast -- --test-filter "M9 L1a"
zig test src/integrations/riscv_cuda/rv64/m9_class_packed_ingress.zig
# pod: build (own dir, build.3.lock), corpora in /dev/shm, GPU via gpu.lock (< 5 min holds)
nvcc -O3 -std=c++17 -arch=sm_120 -DSTWO_RV64_M9_STANDALONE -o bench tools/rv64-m9-packed-ingress/bench.cu src/backends/cuda/native/rv64/m9_class_unpack.cu
zig build-exe -OReleaseFast -lc --dep cache_pack -Mroot=tools/rv64-m9-packed-ingress/corpus.zig -Mcache_pack=src/integrations/circuit_cpu/om31/cache_pack.zig --name corpus
./corpus raw real.m9pk 1:fixed_000.u32 ... 8:tasks.u32 ; ./corpus synth synth.m9pk 1 ; ./corpus shapes shapes.m9pk
flock -w 3600 /workspace/m3/locks/gpu.lock ./bench real.m9pk 20
```

## 6. Adversarial review (2026-11-07)

Reviewed commits `8fc68b32e..92170823e`. Re-run on the pod (RTX 5090 ×2, standalone bench only, gpu.lock holds < 1 min) with freshly generated synthetic and edge-shape corpora; the real-leaf corpora were deleted by the builder and were not regenerated (the laptop capture needs 8 GB under memguard, above the 6 GB review budget). Receipt: `vectors/reports/rv64-m9-prep/packed-ingress/review/review-bench.txt`.

**Fixed defects [M before/after, same bench binary against the old and fixed `.cu`]**
1. **Second GPU could not launch `scan_pass`.** The >48 KiB dynamic shared-memory opt-in (`cudaFuncSetAttribute`) is per device, but it was guarded by a process-wide `static bool configured` (also a host data race between per-GPU worker threads). In a 2-GPU process the first device to call it configured only itself; on dev1 the launch returned `cudaErrorInvalidValue` (`launch_rc=1`). Fixed: set the attribute on every launch, as `transform/wide_tile.cuh` and `n2b_smem.cuh` already do. New `M9_BENCH_MULTI=1` section: dev1 parity PASS on both corpora.
2. **Fail-open on an inconsistent job table.** Per-block checks catch a block that maps past its job, but a `first_block` prefix that undercounts a job, or a `total_blocks` below the sum, simply never launches some blocks: stale output words with status 0. The original bench counted such cases as "REFUSED" via its own word compare, which production does not have. Fixed: warp 0 of CTA 0 checks the whole table (`first_block` is the exact exclusive prefix, every job has ≥ 1 block, last job ends at `total_blocks`; status 1). New negative cases `total_short` / `prefix_short`: old decoder status 0 (ACCEPTED), fixed decoder status 1. The bench now requires a nonzero status for every case except `flip`.
3. **Overclaims corrected** (above): "all five corrupted inputs refused" (a grammar-valid flip is undetected by status), "decode flat whatever the size", the 285 ns derivation.

**Checked and not defects**
- Accept set vs host: the device enforces the same end rules as `LZ4_decompress_safe` (match start ≤ out−12, match end ≤ out−5, literal-only last sequence ending exactly at `count*4`, offset ≤ op) and additionally refuses offset 0. liblz4's "fewer than 8 input bytes after non-final literals" rule is implied: any valid continuation needs 2 offset + 1 token + ≥ 5 final literal bytes, so the device fails later on the same streams.
- Warp LZ4: the `__syncwarp` before each match orders every earlier literal/match write by any lane before the source read; overlapping matches only read the fully written window `[op-off, op)`. The scan fast path on partial blocks reads past `r1` but only into its own shared staging, and the over-read only feeds totals of later (empty) threads. Racecheck agrees.
- [D] arithmetic of the projections is internally consistent (15.86 GB logical / 0.455 GB packed over 19 classes recomputed from the IO telemetry grep: 8.608 GB FIXED + 7.255 GB tasks; `static_words` × 4 = tasks only, so no unpacked indices are hidden in the 15.8 GB).
- Timing reproduces [M]: synthetic node 2.768 ms fixed vs 2.772 ms old vs 2.774 ms builder; the table check costs nothing measurable.

**Corrected projection [D/E].** Today's leaf statics go through the bounced copy measured in-request at 24.6 GB/s (IO doc), so the saving is computed at 24.6 GB/s, not at this bench's 28.15 GB/s pinned rate (the builder's rows are ≈13% low as upper bounds). Exposure: in the IO census ≈46% of H2D copy-s fell inside a host sync [D crude: (0.544 + 0.515) / (1.316 + 0.982)]; the decode runs on the node's dependency chain before B2N, so it is subtracted in full.

| block | link upper bound per GPU [D] | exposure-scaled per GPU [E: ×0.46] | minus decode per GPU [E] | host unpack CPU-s saved |
|---|---:|---:|---:|---:|
| 24628607 (19 nodes [M]) | 0.31 s | 0.14 s | **≈0.10 s** | 3.70 [M] |
| p50 ≈ 26235168 (≈76 nodes [E]) | 1.24 s | 0.57 s | **≈0.42 s** | ≈14.8 |
| p95 ≈ 26235159 (≈133 nodes [E]) | 2.18 s | 1.00 s | **≈0.73 s** | ≈26 |

On a 7.4M-gas block L1a is ≈1% of the 11.64 s warm request; its value is on large blocks and in host CPU. Once M8/L3 moves residual H2D onto a copy lane, the exposure factor and with it L1a's wall saving fall toward the decode-cost floor; L1a's lasting value is then host CPU (−3.7 CPU-s on 24628607), −15 GB of host memcpy and pinned staging (0.83 GB → 24 MB per node).

**Integration costs not in §4.** (a) The staging upload and the decode must be ordered on one stream (or an event if L3 puts the upload on a copy lane). (b) The job table's output pointers are absolute and only the job table and status are custody-checked in `_on`; the jobs path must allocate every target inside the node's region (an out-of-region target is a device-memory write the decoder cannot detect). (c) Two jobs must not target overlapping outputs (decode is in place). (d) `fill` zeroes and copies the whole stage on the host (≈24 MB per node, a few ms of one core [E]).

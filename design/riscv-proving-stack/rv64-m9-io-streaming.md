# RV64 M9: host↔GPU IO, "streaming direct to GPU", and what to do after M8

Status: research and design only. No GPU was used and no run was made for this document. The pod was read only: logs, summaries, and one retained nsys sqlite opened `mode=ro`.
Base: `codex/rv64-m7-integrate @ c72b51646`. Companions:
- `design/riscv-proving-stack/rv64-m8-gpu-native.md` on `origin/codex/rv64-m8-gpu` (cited below as **M8 §n** or **M8 l.n**);
- `vectors/reports/rv64-m8-20261106/{census1,census2,bench15}/` on `origin/codex/rv64-m8-census2` (cited as **census1/census2/bench15**);
- receipts for this document: `vectors/reports/rv64-m9-io-design/` (**R**, hashes in `R/SHA256SUMS`).

Labels:
- **[M]** measured, with the file cited (sums over existing logs count as [M]);
- **[D]** derived, with the arithmetic shown;
- **[E]** estimate;
- **[C]** a vendor claim that cannot be checked.

Hardware: pod `rv64-resident-2x5090` (2× RTX 5090, 32 GB each). Both GPUs train PCIe Gen5 at **x8**, out of a maximum of x16 [M, census2 `h2d-api-and-pcie.txt`]. Measured per-GPU H2D rates are 24.55 GB/s (dev0, 15.076 GB / 0.614 s) and 24.61 GB/s (dev1, 13.314 GB / 0.541 s) [M, same file]. In the trace the two GPUs' H2D overlap for only 0.124 s of 2.30 copy-s, so **the bandwidth when both GPUs upload at once (root complex plus the 8-thread host bounce) is unmeasured** [E: assumed 24.6 GB/s each below; experiment E9].

---

## 0. TL;DR

**The hypothesis, answered directly.** The 1.2 s is *not* block inputs going onto the GPU or proofs coming off it:
- The block-derived stream (compact capture records feeding the `*_witness` kernels) is ≈1.9 GB per request, ≈0.04 s of link time per GPU [D: 1.9 / 2 / 24.6]. The block input file is 2.7 MB [M].
- D2H, proofs included, is 61.6 MB, ≈3 ms [M].
- Streaming those directly to the GPU would recover almost nothing: the default native path already ships them compact and expands them on the device.
- The bytes are **recursion class statics and geometry**. The open question is which of them survive M8.

| what crosses PCIe per warm 24628607 request | GB | share | after M8 [E] |
|---|---:|---:|---|
| Recursion **class statics**: FIXED forest (8.61 logical) + assignment task tables (7.26). Unpacked on the host and uploaded per node. | ≈15.8 [D] | 56% | fold classes: resident (M8). **Leaf classes: still uploaded**; leaf/fold split unmeasured (Q1) |
| Deterministic **geometry**: twiddles, composition denominators/masks/logs, PCS metadata, native owner geometry | ≈9.4–10.4 [D] | 33–37% | mostly resident by M8's `ClassCache` (twiddles, FIXED trees, PCS framing are named, M8 l.32, l.155, H21); residual ≤≈1.1 GB (§4.2) |
| **Block-derived** compact capture (facts, events, `CompactRecord`s) | ≈1.9 [D] | 7% | stays; ≈7.4 GB if `TraceChunk` v1 ships (L0) |
| Per-request recursion seed tapes | 0.22 [M] | <1% | stays |
| **D2H**: everything that comes back, proofs included | 0.062 [M] | 0.2% | one slab D2H per GPU |

Other facts that set the picture:
- Cold and warm requests move the **same total** H2D: 28,270,666,064 B each [M, `/workspace/m3/runs/m8-census2/summary/24628607-{cold,warm}.json`]. Caches do hit in the warm request, but evictions refill them, so **there is no cross-request byte benefit** (§1.4).
- **The warm request is a repeat of the same block.** All 19 recursion classes hit the host class store on it (19 `unpack`, 0 plan builds [M R/telemetry]). In production every request is a new block, and only a few leaf classes recur across blocks (3 shared truth-leaf authorities between 26235156 and 24628607, `rv64-m5-rootverify.md:69-71`). So residency alone is worth only the class hit rate, which is unmeasured (E8).
- The "1.2 s" is copy time summed over **both** GPUs: dev0 0.614 s, dev1 0.541 s [M]. GPUs are 43% busy over the request [D: 10.58 / (2 × 12.3)].
- No H2D overlaps a kernel on its device (0.13 ms on dev0, 0.12 ms on dev1 [M, S2]). The serializer is the host `Context.join()` after metadata ingress plus ring-slot waits, not the stream choice (§1.3).

**zkDTVM's "streaming direct to GPU" is not an exotic transport.** Their published shape (article text and figures, snapshot in `R/zkdtvm/`): CPU-side guest execution (the text says "deterministic interpreter" in §3 and "AOT-compiled to native x86" in §5; figure 4 labels the executor "rv2x86 AOT"); typed execution events sent to the GPU (figure 5); trace generation on the GPU, roughly one thread per event; resident keys and twiddles; a generate → upload → prove pipeline per shard; **and a "shape catalog" of canonical shard shapes so the recursion verifier only needs a fixed set of keys**. No GPUDirect, RDMA, GDS or UVM is mentioned [C]. That is the shape M8 specifies, except the shape catalog: our counterpart is **canonical leaf classes** (canon-native, L4), not `ClassCache`.

**Recommended plan, in order:**
1. **Now, inside M8 (L0).** Specify `TraceChunk` as *compact ingress* (v2: `CompactRecord` + seeds + `Fact`/`Event`), reusing the existing `*_witness` kernels. The v1 draft ships MAIN evaluation images: 7.38 vs ≈2.3 GB [D], CPU column materialization on the capture thread, and ≈274 B/step, which does not fit the 128 MiB capture ring at 2^22-row segments (≈32 B/row [D], §4.2).
2. **Flag M8's class-miss rule (L4).** `GpuNativeClassNotWarmed` (M8 l.32) treats a class miss as an error, but leaf classes change per block. Either leaves become canonical (canon-native, `rv64-m6-enqueue.md:97`) or leaves need a miss path. This also decides whether residency (L1b) is worth anything.
3. **`STWO_RV64_M9_CLASS_PACKED_INGRESS` (L1a).** Upload the *packed* class statics (0.455 GB vs 15.8 GB [M]) and decode them on the device. This works on a class miss: −0.31 link-s per GPU [D: (15.8 − 0.455) / 2 / 24.6] and −3.70 CPU-s host unpack on hits [M, CPU-s summed over concurrent nodes]. Alternative for the FIXED half: build leaf FIXED evaluations on the device from the circuit description (L1c), as M8 does for fold FIXED coefficients.
4. **`STWO_RV64_M9_H2D_STREAM` (L3).** Copy stream + event waits for the consumer only + prefetch lead, replacing the host join after ingress. A separate stream without removing the join hides nothing.
5. **Baseline that L1 must beat (B):** raise the 2 GiB immutable cache cap (one line, `outer_source.zig:351`). It helps only repeated classes.
6. Later: residency across requests (L1b, worth the measured hit rate), geometry residual (L2, an M8 acceptance check), D2D in place (L5), GPU capture (L9, M10-scale, §5.9).

**Expected value.**
- Today: H2D inside a host synchronize is ≈0.53 s per request summed over both GPUs [D, crude: (0.544 + 0.515) / 2 requests, review query over S2], so the wall exposure is ≈0.27–0.53 s [D: depending on how much the two GPUs' syncs coincide].
- After M8: on the slower GPU, H2D is at most 0.614 s, **≤9% of a ≈6.5 s M8 request** [D upper bound: 0.614 / 6.5; it still counts geometry and fold bytes that M8 removes].
- 24628607 after M8 + L0 + L1a: H2D ≈2.6–3.7 GB [E: 1.9 + 0.22 + 0.455 + ≤1.07], ≈0.05–0.08 link-s per GPU [D], most of it hideable by L3.
- **26235159** (49 segments [M T10], warm ≈40.6 s [E, bench15 `estimate.json`, extrapolated]): link time 4–5.5 s/GPU [E, §1.4]. Class statics are at most 2.3–3.1 s/GPU of that [D: 0.56 × 4–5.5]; L1a removes up to 2.2–3.0 s/GPU [D: 0.54 × 4–5.5]. No lever exceeds its byte share. **It has no IO measurement** (E1).

**Not worth doing for this problem:** GPUDirect Storage/RDMA (our source is a CPU emulator in host RAM); another pinning pass (every H2D already goes through a pinned ring, §1.3); proof-only readback (D2H is already 62 MB); CUDA graphs around copies.

---

## 1. Measured byte census per request

### 1.1 Sources

| id | what | where |
|---|---|---|
| S1 | census2 summaries: cold and warm H2D/D2H/D2D **totals** | pod `/workspace/m3/runs/m8-census2/summary/{24628607,26235156}-{cold,warm}.json` |
| S2 | Retained M7-P1 default-path nsys trace of a 24628607 two-request daemon (cold = request 0, warm = request 1). sqlite sha256 `04573fd8c0ee…`, `producer.stderr` sha256 `3a5a6d57cc7f…` | pod `/workspace/m3/runs/m7-integrate/daemon-24628607-r2-p1-inter-contributions-profile-20261106-01-06-baseline/{nsys/timeline.sqlite,producer.stderr}` |
| S3 | Producer telemetry of the S2 run (`GPU_STAGING_SUMMARY`, `GPU_RESIDENT_SETUP`, `GPU_OUTER_{PP,PLAN}_PACK`, `GPU_OUTER_ASSIGNMENT`, `GPU_CPU_PROJECTION`). Request boundary: line 1223. | S2 `producer.stderr`; grep extract in `R/telemetry/` |
| S4 | census2 deep queries: H2D by NVTX range, PCIe link state | `census2/m7p1-24628607-warm-deep.json`, `census2/h2d-api-and-pcie.txt`, `census2/m7p1-24628607-warm-d2d.json` |

All line numbers below are S2 `producer.stderr` lines. (An earlier draft paired this hash with the `inter-reuse-profile-retry-…-02-06` run, whose sqlite is `62bf0d0d…`; nothing here uses that run.) Overlap and range queries: `R/queries/`. Attribution method: §1.5.

### 1.2 Totals (24628607 warm)

| direction | bytes | copy-s (summed over both GPUs) | notes |
|---|---:|---:|---|
| H2D | **28.39 GB** [M S2/S4]; 28.27 GB [M S1] | **1.156** [M] | 11,640 copies [M]. Per GPU: dev0 15.08 GB / 0.614 s, dev1 13.31 GB / 0.541 s [M S4]. Native window 6.99 GB, recursion 21.40 GB [M, split at the first `rv64/owner/controller` range, 6.854 s of 12.601 s]. |
| D2H | 61.6 MB [M] | 0.003 [M] | 98% is `m7/pcs/final_readback_encode`: 33 PCS readbacks in 1,155 copies [M]. The proof on disk is 0.84 MB [M]. The cost is 2,049 synchronous host waits, not bytes [M]. |
| D2D | 167.5 GB [M S1] | 0.214 [M] | 781 GB/s [M]. Does not overlap kernels either (§1.3). |
| memset | 52.2 GB [M] | 0.028 [M] | |
| kernels | — | 10.58 GPU-s [M census2] | H2D copy-s is 10.9% of kernel GPU-s [D: 1.156 / 10.58]. |

The second block is 26235156 warm [M S1]: H2D 21.99 GB in 0.881 copy-s, D2H 48 MB, D2D 129 GB.

### 1.3 How the copies run today (corrects census2)

- **Already pinned and staged.**
  - nsys `ENUM_CUDA_MEM_KIND` in S2 is 0 = Pageable, 1 = Pinned, 2 = Device [M, the trace's enum table]. census2 (`README.md:41`) read srcKind `1` as pageable. It is **pinned**.
  - census2 also labels its size bucket wrongly: "24.0 GB arrives in 32 MiB-class copies (log2 25)" (`README.md:57`). `cuda_gpu_mem_size_sum` gives a 16.777 MB maximum, so these are **16 MiB** copies. Both census-tool fixes belong in the cleanup pass.
  - Every H2D goes through `staged_h2d` (`src/backends/cuda/native/runtime/device_arena_runtime.cuh:972-1185`): an 8-thread `CopyPool` memcpy fills a per-stream ring of 4 × 16 MiB `cudaHostAlloc` slots (`kSlots = 4` at :1078, 16 MiB at :72), then `cudaMemcpyAsync` copies each slot. CUDA API CPU time is 0.046 s [M census2].
- **Staging counter.** `GPU_STAGING_SUMMARY staged_h2d_bytes` reads 4.35 GB at line 279 (mid-request, cumulative), 28,389,590,992 at line 1223 (end of request 0, equal to the nsys warm H2D) and 56,779,181,984 = 2 × 28.39 GB at line 2393 (process end) [M].
- **Streams.** Each device has two lanes (`context.cu:424`, `context->stream = lanes[0]`). Kernels run on both: dev0 streams 22 (23,038 kernels) and 23 (57,527); dev1 streams 24 and 25. **Copies run only on lane 0** (22, 24) [M S2].
- **No overlap, and why.** Lane-1 kernels never overlap copies either, so "same stream" is not the explanation. The serializers in the code are:
  1. `Context.join()` (`rv64/session_context.zig:72-75`, "Join once after metadata ingress before kernels on another lane") → `stwo_exec_context_sync` → host `join_lanes` (`context.cu:134`, `:542`; default `STWO_RV64_EXEC_SYNC=host`). Uploads are issued right before their consumer, then the host joins every lane, then kernels launch. Copies cannot overlap kernels of either lane.
  2. Ring wrap: the host waits on a slot's previous DMA (`cudaEventSynchronize`, `device_arena_runtime.cuh:1139,1163`), so it can run only 64 MiB ahead: 93 slot waits in the warm request [M, 170 − 77].
  3. `staged_d2h` is synchronous: 2,049 host waits per request [M].
  - Proxy [D, crude, review query over S2, cold + warm]: 0.544 s of dev0's 1.316 s of H2D and 0.515 s of dev1's 0.982 s fall inside a host `cudaEventSynchronize`/`cudaStreamSynchronize`. Exactly which call blocks each copy is not attributed (E1). `STWO_RV64_EXEC_SYNC=device` swaps the host join for an all-lane device barrier (`barrier_lanes`, `context.cu:180`). That frees the host but still orders copies before both lanes' later work, so on its own it does not create overlap.
- **The bounce costs 28.4 GB of host memcpy per request** [D], on CPU cores that capture and recursion assembly also want.

### 1.4 Attribution table (24628607 warm, S2)

"copy-s" is summed over both GPUs. S1 shows equal cold and warm *totals*; per-row equality between cold and warm was not checked.

| # | GB | what it is | source / call site | consumer kernel | invariant? | copy-s |
|---|---:|---|---|---|---|---:|
| 1 | **≈8.5–8.9** [D/M] | Recursion **FIXED forest**: raw FIXED evaluations, unpacked on the host from the PP class store and uploaded per node. Logical 8.608 GB, packed 0.183 GB, unpack 1.939 CPU-s [M Σ 19 `GPU_OUTER_PP_PACK unpack`, lines 1510–2351]. The 18 single uploads of 168–705 MB come to 8.51 GB [M sizes]; consumer-kernel attribution gives 8.92 GB [M]. | `outer_wrap.zig:277` | `b2n_stage` | per class | ≈0.35 [D] |
| 2 | **7.47** [M] | Recursion **assignment schedule**. `tasks`/`indices`/`chain_ends` = 7.255 GB [M Σ `static_words`×4, 19 lines]; packed 0.272 GB, unpack 1.762 CPU-s [M Σ 19 `GPU_OUTER_PLAN_PACK unpack` `physical_bytes`/`ns`, lines 1521–2352]. The seed tape is 0.217 GB [M Σ `seed_words`×4] and is per request. | `outer_assignment.zig:~896-905`; leaf plans not cached on the device (`reusableClassPlan()`, :793-796) | `generate` | static: per class | 0.313 [M] |
| 3 | 3.08 [M] | **Twiddles + itwiddles + logs, re-sent on every trace commit.** Native MAIN 0.64 + INTER 0.54; recursion 0.95 + 0.95. Sizes are exactly 2^26 B + 4·ncols [D]. | `trace_commit.zig:367-369, 578-580` | `b2n_stage` | per log | 0.121 [M] |
| 4 | 3.41 [M] | **Composition per-role uploads**. Native 1.01, recursion 2.40. **Invariant:** selected twiddles (n/2 words per role, the bulk [D from code]), denominators, masks, logs. **Per request:** `power_words` (Fiat-Shamir challenge powers, 32 B per constraint root) and `parameters`. They are skipped only under device FS, and census ran with `OUTER_DEVICE_FS=0`; KB-scale per role [D]. | `resident_composition.zig:726-800` | `n2b_*`, `fill_auxiliary`, `lift_add` | invariant ≈3.4; per request ≪0.1 [E] | 0.133 [M] |
| 5 | 1.86 [M] | **PCS per-call metadata**: twiddles h[19], FRI twiddles, sample maps, sources, descriptors. `host_geometry_bytes` 42–84 MB per miss [M]. | `pcs_pipeline.cuh:202-397`, `pcs_native.zig:196` | b2n / PCS | per class | 0.075 [M] |
| 6 | **≈1.9** (2.0–2.7 incl. `b2n_init` metadata) [D] | **Captured execution trace, compact**: `memory_witness` 0.97–0.98, `arithmetic_witness` 0.58–0.65, `family_witness` 0.27, `boundary_witness` 0.07. The **only block-derived bulk data**: 26.89 M steps → ≈70 B/step [D]. | `cpu_projection.zig`, `core_witness.zig`, `cpu_witness.zig` | `*_witness` | **per block** | ≈0.077 [D] |
| 7 | ≈1.07 [D] | Native `owner/callback` GKR/LDE geometry and twiddles, incl. `GPU_CPU_PROJECTION metadata_h2d_bytes` 0.47 GB [M Σ] | native owner path | `b2n_init`/`b2n_stage` | mostly per log | ≈0.044 [D] |
| 8 | 0.13 [M] | Native TC/FIXED. The setup cache hit 14 times when warm [M]. | `trace_commit.zig` | b2n | per class | 0.006 [M] |
| 9 | ≈0.97 [D] | Remainder of recursion `owner/callback` and TC/FIXED (4/8/2/1 MiB pieces) | outer path | b2n | per class [E] | ≈0.04 [D] |
| Σ | **28.39** [M] | | | | | **1.156** [M] |

**Caches today, and what "warm" means.**
- The device setup cache is the immutable setup cache, capped at 2 GiB per device by a one-line `@min(byte_cap, 2 << 30)` (`outer_source.zig:351`). It thrashes at 2.00–2.15 GB of 2 GiB [M]: dev0 hits 616 → 1142 (+526 in the warm request), uploads 336 → 670, evictions 783 → 1567; dev1 hits 378 → 846, uploads 260 → 522, evictions 470 → 1099 [M, lines 1218–1219, 2387–2388].
- Leaf plans were moved *off* this cache because it thrashed (≈1.3–1.6 k evictions per request, `rv64-m6-hint-tape.md:101-103`); `STWO_RV64_OUTER_ASSIGNMENT_LEAF_IMMUTABLE=1` restores them (`outer_assignment.zig:795`). `rv64-m6-enqueue.md:94-98` records the same thrash and names "class-keyed canonical leaves (canon-native) or a larger budget" as the levers.
- The host class store does hit, **because the warm request is the same block**. Cold: 19 `adopt` (pack) lines, PP pack 2.72 CPU-s, and 19 plan builds, Σ `plan_ns` 13.2 CPU-s [M, lines 440–1179]. Warm: 19 `unpack`, 0 plan builds [M]. The 19 warm nodes have 19 distinct class keys; six classes of identical size (495,127,552 B) have different keys [M].
- Host unpack costs **1.94 (PP) + 1.76 (plan) = 3.70 CPU-s per warm request** [M]. That is CPU time summed over concurrently running nodes, not wall time.

**Boundary caveat.** Rows 6, 7 and 9 and the native/recursion split come from time windows, next-kernel attribution and size fingerprints [D]. Exact per-call-site bytes need per-upload NVTX labels (E1).

**26235159 [E].** It has no IO measurement: the census2 attempt exited 1 (`summary/26235159.log`). Scaling by segments, with 49 segments [M T10] and 26235156 at 4 segments (`rv64-gpu-10x-plan.md:326`):
- per segment, 24628607 moves 28.3 GB / 7 = 4.04 GB and 26235156 moves 22.0 GB / 4 = 5.5 GB [D];
- 49 × 4.0–5.5 GB ≈ 200–270 GB H2D, ≈100–135 GB per GPU, ≈4–5.5 link-s per GPU [E].
- Whether its 49 same-shape segments share leaf classes is **unproven**: class keys include per-segment authority, and only 3 of the leaf authorities recur across 26235156 and 24628607 (`rv64-m5-rootverify.md:69-71`).

### 1.5 Attribution method

Each H2D in S2 is assigned to its NVTX push/pop range and to the next kernel on the same stream. Sizes are matched against telemetry totals: `GPU_OUTER_PP_PACK` logical bytes, `GPU_OUTER_ASSIGNMENT static_words`/`seed_words`, and `GPU_CPU_PROJECTION metadata_h2d_bytes`. Overlap is computed per device as |∪copy ∩ ∪kernel|.

### 1.6 Critical-path seconds

| | today, M7 host-bound warm 12.3 s [M] | after M8, kernel-bound ≈6–7 s [E, M8 §5] |
|---|---|---|
| H2D link time per GPU | 0.541 / 0.614 s [M]; 0 s overlap | slower GPU ≤0.614 s [M upper bound]. M8 removes geometry (twiddles, PCS framing, FIXED trees resident per class, M8 l.32, H21), fold statics (`jobs/outer_staged.zig:6-12`) and native TC re-uploads. **Leaf statics stay per node.** |
| share of the request wall | ≈0.27–0.53 s [D crude, §1.3 proxy]; GPUs 43% busy [D] (39% at the profiled 13.66 s) | **≤9%** [D upper bound: 0.614 / 6.5]; realistic residual after M8 = leaf statics (Q1) + ≈2.1 GB compact/seed |
| D2D | 0.214 copy-s summed → ≤0.11 s/GPU [D] | lower: no `copyColumns`, no replay [E] |
| D2H | 3 ms + 2,049 syncs [M] | ~1–2 ms, one D2H per GPU [E, M8 §3.4] |

---

## 2. zkDTVM: what they do, what can be verified, what transfers

Sources, all snapshotted with sha256 in `R/zkdtvm/` and `R/ethproofs/`:
- the announcement article (https://openlabs-intl.antdigital.com/0x/Introducing-zkDTVM-A-GPU-Native-zkVM-Built-for-End-to-End-Acceleration). It is a JS SPA, rendered through a reader proxy (`article-reader-proxy.md`); figures 4 and 5 are kept as PNGs;
- `github.com/AntChainOpenLabs/{zkdtvm-docker @ 861bbb07, zkdtvm-stark-verifier, zkdtvm-wasm-stark-verifier, NitrooZK-stwo}`;
- the EthProofs provers and team pages, 2026-11-07.

### 2.1 Stack [C unless noted]
- **Proof system.** SumCheck PIOP, multilinear throughout, with the "Pangolin" PCS (Basefold-based) and a recursive STARK. The AIR is chip-decomposed, with LogUp buses and no central CPU chip. Constraints are local only and have degree ≤ 3 in Core. Stages run Core → Compress → Shrink.
- **Lineage** [M, zkdtvm-docker README, Acknowledgements]: "Our STARK proving and verification stack is built on top of the Plonky3 library" (forked crates); the zkVM architecture "draws significant inspiration from SP1".
- **Shipped verifier** [M, code read of `vendor/zkdtvm-verifier-core`]:
  - Field: KoalaBear with a degree-5 extension; the recursion uses a septic curve and D11 algebra.
  - `whir_config.json`: core log_blowup 1, 261 queries, 20-bit query grinding; compress blowup 2, 160 queries; shrink blowup 3, 131 queries; root_shrink **WHIR** with stacking.
  - The sample proof for block 25954917 is 267,918 B.
  - The article says Basefold/Pangolin while the verifier ships WHIR plus FRI-style configs, so the PCS has changed since the article, or the article describes a variant.
- **Deployment** [M]:
  - README: binary only, `ghcr.io/doubizhizun/zkdtvm_eth_proofs:0.6.1`, "x86-64 CPUs, NVIDIA RTX 5090 GPUs and cuda 12.8"; scripts for 1 GPU, 8 GPUs, and 16 GPUs (2 servers × 8).
  - `prove_network_coordinator.sh:27-41`: one prover container per GPU with `--cpuset-cpus` ranges of 14–16 cores and `--cpuset-mems` on NUMA node 0 or 1. This is not in the README.
  - **The prover source is not public.**

### 2.2 What runs where and how data moves [C]

| question | zkDTVM answer (source) | transfers to us? |
|---|---|---|
| Guest execution on the GPU? | **No.** The article conflicts with itself: §3 "runs it on a deterministic interpreter" (`article-reader-proxy.md:41`), §5 "the guest ELF is ahead-of-time compiled to native x86, with separate modes for fast checkpoint-based sharding and detailed execution recording" (:106). Figure 4 labels the executor "rv2x86 AOT". | Yes, the *CPU-side* idea: a fast checkpoint pass plus faster recording (§5.9). |
| Trace generation on the GPU? | **Yes.** Every trace type is built in kernels, roughly one thread per event, "avoiding the classical CPU-to-GPU upload bottleneck" (:98). No byte counts. | Already true for our default native path (§4.1). Not true for recursion statics (§1.4 rows 1–2). |
| What crosses H2D | Typed execution events, `GpuExecutionRecord: Checkpoint \| MemoryGlobal \| Precompile`, bincode in a gRPC `SubProveRequest` per GPU prover. **Figure 5 only** ("Data Flow" box); not in the text. | Ours is the `TraceChunk` stream. Keep it compact (L0). |
| Transport | Not specified. Text names multi-stream overlap of launches with transfers (:104) and a generate → upload → prove pipeline per shard (:49); figure 4 names memory pools and streams. **No GPUDirect, GDS, RDMA or UVM.** | M8 arena + streams + d-wire `Feed`. The missing piece is a copy stream with consumer-only joins (L3). |
| Residency | Trace matrices, proving keys, Poseidon2 constants and twiddles stay device-resident across phases (:102). | M8 already does this for geometry and fold classes (§4.2). |
| Shape control | "Shape-aware" sharding into "a small set of canonical shape templates … bounding the number of distinct recursion verifier circuits" (:49); a "shape catalog" so "the recursion verifier only needs to support a fixed set of verification keys" (:64). | **Canonical leaf classes (canon-native, L4)**. This is what makes recursion statics recur across blocks; `ClassCache` only stores them. |
| What leaves the GPU | Shard proofs go to a coordinator, then gather → compress; the final Groth16/Plonk runs on **CPU** SNARK provers (figure 5), which contradicts "no stage falls back to the CPU" (:113). | Our slab: one D2H per GPU (M8). |
| Memory trick | Padding-free DFT: padding rows stay compressed through the commitment (:85). | Never upload padding rows; generate them on the device. |
| Sumcheck tail | Univariate skip in the tail, merging the last c·k rounds (figure 2). | A protocol change; proof bytes would change. Not an IO lever. |

### 2.3 Verifiable numbers
- **EthProofs snapshot, 2026-11-07** [M third-party, not reproduced; `R/ethproofs/`]:
  - provers table row "zkDTVM by AntChain OpenLabs | 1:1 multi-gpu cloud | evmone | … | 4.6s | $0.0032"; RTP-consistency list names the cluster "zkDTVM 4x5090";
  - team page: multi-GPU 1,237,787 proofs, average 4.0 s; single-GPU 4,335 proofs, average 23.7 s;
  - the same provers table shows Airbender v3 at 2.4 / 3.4 / 5.9 s and OpenVM 2.1 at 3.2 s.
- **Press and social** [C]: 3.7 s "record" (Phemex, 2026-04-30); 3.1 s average with every block under 8.8 s on a **16×5090** cluster (X post, 2026-06-01).
- **None of this compares with our 12.3 s warm request on 2×5090** (different guest, block mix and GPU count). Their single-GPU 23.7 s average is the closest shape.

### 2.4 Bonus: NitrooZK-stwo
`AntChainOpenLabs/NitrooZK-stwo` is a CUDA backend for upstream Stwo (Circle STARK, M31) from the same lab. Its IO is naive: pageable `cudaMemcpyAsync` on stream 0 (`crates/stwo/src/stwo_cuda/cuda/utils.cuh:230-254`). Its README reports wide-fib Poseidon at log 23 in 2,010 ms on an RTX 4090 [C]. Worth a *kernel* comparison later (FFT, Blake2s Merkle, GKR), separately.

### 2.5 What transfers, in one line
"Streaming direct to GPU" in the zkDTVM sense has six parts: (1) CPU emulation emits compact events into a pinned ring; (2) a copy stream overlaps uploads with compute; (3) device kernels expand events into traces; (4) keys and geometry stay resident; (5) a shape catalog keeps the set of recursion keys fixed; (6) only the proof leaves the device. We have (1) and (3) in the default native path; M8 delivers (4) for geometry and fold classes and (6). **The gaps are (5), which decides whether leaf statics can ever be resident, and (2), which accounts for all of the exposure.** Until (5) exists, packed ingress (L1a) is the lever that works on a class miss.

---

## 3. Frontier patterns (code read, local clones)

Clones are read-only under the session scratchpad `frontier/`: zksync-airbender, zksync-airbender-prover, airbender-platform, pil2-proofman, zisk, zisk-ethproofs and sppark. airbender-v3 is under `src/airbender-v3`.

### 3.1 Patterns that cut bytes
| pattern | evidence | applies to us as |
|---|---|---|
| **Compact per-cycle trace → GPU witness kernels** | **airbender** per-family records. `NonMemoryOpcodeTracingDataWithTimestamp` = 6×u32 + u16 + 4×`TimestampData` (6 B, `cs/src/definitions/mod.rs:100-104`) ≈ **52 B/cycle** [D] (`riscv_transpiler/src/machine_mode_only_unrolled/mod.rs`). Kernels: `GenerateWitnessUnrolled{Memory,NonMemory,Unified}Kernel` (`gpu_prover/src/witness/witness_unrolled.rs:16,75,146`). **ZisK** `CountAndPlan` takes a 16 B `MemOp` stream and builds memory rows on the device (`state-machines/mem-cpp/cu/count_and_plan.cu`, upload at l.1785; `state-machines/mem/src/mem_device_rows.rs`). **pil2** `common/src/gpu_witness.rs`: "the kernel writes the commit slot directly and no trace is uploaded". **SP1** `sp1-gpu-tracegen` uploads events, then a decompress kernel builds the trace (`riscv/global.rs`). **RISC Zero** `risc0_circuit_rv32im_cuda_witgen(…RawPreflightTrace…)`. | Our default path already does this at ≈70 B/step [D]. L0 keeps it that way in M8. airbender's ≈52 B/step is the reference: 1.40 GB for 26.89 M steps [D]. |
| **Fixed/setup polynomials and trees resident across proofs** | **pil2** `load_device_const_pols` / `load_device_setups` (`proofman/src/utils.rs:950,1100`; `proofman.rs:6512,6551`), with a slot cache and pins (`configure_const_slot_cache_c`, `pin_const_slot_c`). Re-upload only after a SNARK reuses the memory (`restore_after_snark`, `proofman.rs:~900`). | M8 `ClassCache` for geometry and folds; L1b for leaves, once L4 makes them recur. pil2 has a fixed set of setups; that is the property L4 buys us. |
| **Bit-packed or indexed witness against a device-resident table** | **pil2** `PackedInfo` (`common/src/packed_info.rs`). The indexed mode (`pil2-stark/src/goldilocks/src/stream_commit.cuh` `StreamCommitDims.indexBits/wordsPerEntry/numEntries`) replaces per-row columns with indices into a device instruction table. Its streaming commit unpacks, LDEs and hashes column chunks without materializing the full LDE. | L8: pc/decoded instruction become indices into the program table already in `ClassCache` [E 2–4× on chunk bytes]. It also validates L1a's decode on the device. |
| **Recompute instead of upload** | **airbender** `MemoryPolicy`/`CosetsCacheMode` (`prover/memory_policy.rs`); twiddles are device-resident for the context lifetime (`V3/gpu/prover_context/src/context.rs:49`). | M8 twiddles; L1c: leaf FIXED built on the device. |

### 3.2 Patterns that only hide copies
| pattern | evidence | note |
|---|---|---|
| Pinned pools allocated once and kept across jobs | airbender `ExecutionProverHostState::new` (`gpu_prover/src/execution/prover.rs:321-405`, "tens of gigabytes"); simulator RAM is `cudaHostRegister`'d (`V3/.../simulation_runner.rs:32-50`); the service keeps state across jobs (`zksync_os_prover_service/src/lib.rs:148-153`). pil2 `register_host_buffer` with `MADV_DONTFORK`, because a fork() of a 56 GB pinned pool cost about 20 s (`common/src/memory_handler.rs:120-150`). | We already pin through a ring (§1.3). Registering *sources* removes the 28 GB CPU bounce (L6): a CPU win, not a link win. |
| **Counter-evidence on pinning** | ZisK: "Pinned pages disabled: no measured benefit and not supported on all devices" (`emulator-asm/asm-runner/src/asm_mo_runner.rs:173-176`). | Consistent with our link-bound measurement. |
| Dedicated h2d stream with events | airbender `ProverContext` has `exec`/`aux`/`h2d` streams (`gpu_prover/src/prover/context.rs:87-89,145-147`), and `Transfer::schedule_multiple` (`prover/transfer.rs`) fences with `allocated`/`transferred` events. **Caveat** in the v3 contract (`V3/gpu/docs/gpu_scheduling_contract.md` ll.13-153): "Default to exec_stream for copies. Use h2d_stream only when meaningful H2D overlap justifies the fork/join". | L3: only with prefetch lead and consumer-only waits; not for small metadata. |
| Chunked prefetch with one chunk in flight | pil2 `HOST_UPLOAD_CHUNK_BYTES = 32 MiB`: "a stream with a copy always pending holds the copy engine and starves other streams' copies" (`goldilocks_tooling.cuh:812-830`); per-GPU `PrefetchZone`. sppark flip-flop streams (`util/gpu_t.cuh:173-198`, `msm/pippenger.cuh:455-515`). | Our 16 MiB ring is the same shape. L3 has to respect copy-engine starvation between the two lanes. |
| CUDA graphs | pil2 `pil2-stark/src/utils/cuda_graph_cache.cuh` captures compute after 100 sightings (about 7 ms to instantiate on a 5090) and **poisons** regions that read per-proof staged data (ll.43-45). | Graphs do not help copies. M8 graphs stay compute-only. |
| GDS / RDMA / peer | `grep cudaGraph\|cuFile\|GPUDirect\|cudaMemcpyPeer\|NCCL` over the airbender trees finds nothing. pil2 uses peer access only to merge multiplicities (`multiplicity.cuh:210-229`). | Nobody uses GDS or RDMA. Our pod has no P2P: peer exchange stages through the host at 26.8–27.3 µs per hop [M d-wire README], under 16 KB per request [E M8 §3.6]. |

### 3.3 One notable frontier choice that we should *not* copy
airbender re-uploads setup columns and partial Merkle caches from pinned host memory **for every circuit proof** (`SetupPrecomputations::schedule_transfer`, `execution/gpu_worker.rs:131-152`; v3 `gkr/src/setup/mod.rs:69-98,444-516`), because they prove many circuit instances in limited VRAM. That is our behaviour today for leaf statics. With a canonical leaf set (L4) and 32 GB per GPU, pil2's resident const-pols is the right model; without L4, packed ingress (L1a) is the airbender model with 30× fewer bytes.

---

## 4. Our data path today and after M8

### 4.1 Today (M7 default / combined-residency path)
1. **Capture (CPU).** A fast pass at about 170 MIPS, then segment replay on 8 workers, then the serial ledger, then narrow scan, routing and grouping (`word16_execution/prepared.zig`).
   - 24628607: fast pass 0.49–0.50 s; recording at 14–15 MIPS; capture 1.79–1.90 s; exposed capture 2.1 s [M census1]. Segments are 2^22 rows (`GPU_CPU_PROJECTION rows=4194304`, line 17 [M]; 26.89 M steps / 7 ≈ 3.84 M [D]).
   - 26235159: capture 4.76 s with T1+T10 [M T10]. Worker profile summed: scan 10.94 s, routing 3.51 s, ALU hash grouping 7.51 s; ledger about 50 ms per segment, serial [M T10].
2. **Compact transport, already in place.**
   - CPU rows: `CompactRecord{result u64, rom_row u32, next_pc u32}` = 16 B/row, plus a 384 B `CompactSeed` every 256 rows ≈ 17.5 B/row (`cpu_witness.zig:9-13`). Measured: `metadata_h2d_bytes = 73,400,304` for a 2^22-row segment = 17.5 B/row, `main_d2h_bytes = 0` [M, line 17].
   - Family `Fact` = 32 B per deduplicated fact (`family_input.zig:8`); load/store `Event` = 64 B; public RAM `Cell` = 32 B (`memory_input.zig:5,18`).
   - Registers and clocks are rebuilt on the device (`stwo_rv64_cpu_unpack_on`, `stwo_rv64_cpu_witness_on`). MAIN stays resident through replay (`GPU_CPU_REPLAY_RETAIN main_resident=true` [M]).
3. **Setup and geometry.** Unpacked on the host per node or per call, then uploaded every request through the staged ring (§1.4 rows 1–5, 7–9).
4. **Copies** on lane 0, then a host `Context.join()` before kernels; 0 s overlap (§1.3).
5. **D2H.** 33 PCS readbacks, 2,049 sync waits [M].

### 4.2 After M8 (design, `codex/rv64-m8-gpu`)
| byte stream | M8 treatment | residual after M8 [E] |
|---|---|---|
| native witness / MAIN | H4: device witness from `TraceChunk`s into `main_resident`; H5/H12: no `copyColumns`, no replay | **depends on the `TraceChunk` format (L0)**: ≈2.3 GB compact, or ≈7.4 GB if v1 MAIN images ship |
| native FIXED | n-stage1 adopts the class tree from a region filled once at warm ("no host SHA, no FIXED upload") | ≈0 |
| fold-class tasks + FIXED | `jobs/outer_staged.zig:6-12`: uploaded once per class into worker-persistent memory; FIXED coefficients produced on the device | ≈0 for folds |
| **leaf-class tasks + FIXED** | "a leaf is its own class" (`outer_staged.zig:8`), so they stay in the per-node region. `outer_class_plan.zig` (`STWO_RV64_M8_OUTER_CLASS_PLAN`, default 0) caches leaf statics by authority **on the host only**. **Conflict:** M8 l.32 makes a class miss an error (`GpuNativeClassNotWarmed`), but leaf classes change per block (§1.4). M8 needs either canonical leaves (L4) or an explicit leaf miss path. | **the leaf part of rows 1–2** (Q1), on every new block |
| twiddles (rows 3, bulk of 4) | M8 l.32 and l.155: twiddles in `class_cache`, built once per class; `outer_staged.zig:12`: "twiddles — per evaluation height, worker-persistent" | ≈0, if every path adopts it (E1 checks) |
| PCS metadata (row 5), FIXED trees (rows 8–9) | M8 l.32 `PcsJob.prepare` / PCS framing per class; H21 FIXED tree per class resident | ≈0 |
| composition per-request words (row 4 part) | device transcript (M8 §1) computes challenge powers on the device | ≈0 |
| native owner geometry (row 7) | H4/H5 replace the owner path; not named as resident | ≤≈1.07 GB (L2 if it survives) |
| copy stream | M8 §6.2 says "upload on the h2d stream", but d-wire enqueues chunk H2D on the **exec** stream (`native_device_stage1.zig:658`) | still serialized |
| D2H | one slab D2H per GPU, 1 host wait [M d-wire D3] | ~1–2 ms [E] |
| streaming capture | d-wire `Feed` + `Stream` with per-segment seal; pinned `cudaHostAlloc` ring (`m8_capture_stream.zig`) written in place. The ring default is 32 × 4 MiB = 128 MiB, documented as sized for one 2^20-row segment (`driver_serve.zig` on d-wire) | the M8 win of −1.6 to −1.9 s exposed capture [E M8 §5]. **At our 2^22-row segments the ring holds ≈32 B/row [D: 128 MiB / 2^22].** |

**The M8 risk (act now).**
- The draft `TraceChunk` v1 (`gpu_native.zig:679`; d-wire `native_device_stage1.zig:293`) carries MAIN evaluation runs; the device only scatters them (`stwo_rv64_n1_scatter_v1`).
- That puts column materialization (MAIN 4.15 + 3.23 = 7.38 GB on 24628607 [M M8 §3.7]) back on the CPU capture thread, and ships ≈274 B/step [D: 7.38 GB / 26.89 M] vs ≈70 B/step compact.
- **Ring fit at 2^22 rows** (≈32 B/row per sealed segment [D]): CPU-row compact ingress at 17.5 B/row fits; the full compact stream at ≈70 B/step needs ≈290 MB per segment [D: 70 × 2^22], so the ring must stream rather than hold a segment; v1 images at ≈274 B/step need ≈1.15 GB per segment [D] and do not fit. This supports L0.
- `NativeFactory.pack` is not written yet (d-wire README "Not done"), so changing the contract now costs nothing.

---

## 5. Ranked levers

Columns: bytes per warm 24628607 request; per-GPU link-s ≈ total / 2 / 24.6 GB/s [D] (dev0 carries 53%; simultaneous two-GPU bandwidth unmeasured, E9); wall on 24628607 after M8; wall on 26235159 [E, H2D unmeasured, every lever capped at its byte share of 4–5.5 link-s/GPU]. Host CPU savings are listed separately and are CPU-s summed over concurrent work, not wall.

None of these levers changes proof bytes. Each must pass the frozen D2 golden (32/32, 39/39 artifacts) and the channel parity harness (M8 §4).

| rank | flag | lever | bytes saved (24628607) | 24628607 wall (post-M8) | 26235159 wall | effort | risk | M8 dependency |
|---:|---|---|---:|---:|---:|---|---|---|
| 0 | *(M8 contract, no flag)* | **L0 compact `TraceChunk` v2** (`CompactRecord` + seeds + `Fact`/`Event`), reusing the `*_witness` kernels | avoids +5.1 GB [D: 7.38 − 2.3] | avoids +0.10 s/GPU link [D: 5.1 / 2 / 24.6] and CPU MAIN materialization on the capture thread [E: larger than the link term]; fits the capture ring | avoids ≈+35 GB, ≈+0.7 s/GPU [E: 49 × (1.05 − 0.33) GB / 2 / 24.6] | S | low | **must land inside M8** |
| 1 | `STWO_RV64_M9_CLASS_PACKED_INGRESS` | **L1a packed class ingress + device decode.** Upload the packed PP/FIXED forest and task tables the host already produces (0.455 GB) and decode them per node in the arena. Works on a class miss. | −15.3 GB [D: 15.8 − 0.455], minus M8's fold share (Q1) | ≤−0.31 s/GPU link [D: 15.345 / 2 / 24.6]; −3.70 CPU-s host unpack on hits [M]; −15.3 GB host memcpy [D] | ≤−2.2 to −3.0 s/GPU [D: 0.54 × 4–5.5] | M: GPU decoder for delta-varint/LZ4 over independent 16,384-word blocks (`circuit_cpu/om31/cache_pack.zig`) | medium: decode ≈1–10 ms/node [E: 0.85 GB/node at 0.1–1 TB/s]; decode-parity test | arena per-node region |
| 2 | `STWO_RV64_M9_H2D_STREAM` | **L3 copy lane + consumer-only waits + prefetch.** Residual H2D on a copy stream from the pinned ring, `cudaStreamWaitEvent` only into the consuming lane, uploads issued ahead of the consumer; replaces the host `Context.join()` after ingress | 0 (hides) | hides up to the residual exposure [E]; today's proxy is ≈0.53 s/request summed over GPUs [D crude]; after L0+L1a ≈0.05–0.08 s/GPU [D] | hides most of the residual [E] | S–M: move `native_device_stage1.zig:658` and staged uploads off lane 0; remove the post-ingress join | low: copy-engine starvation between lanes | M8 streams (§6.2) |
| 3 | `STWO_RV64_M9_CANON_LEAF` | **L4 canonical leaf classes** (canon-native, `rv64-m6-enqueue.md:97`): leaf classes keyed by shape, not per-segment authority, so they recur across blocks (zkDTVM's shape catalog) | 0 directly; makes L1b hit; makes `GpuNativeClassNotWarmed` consistent for leaves | host: skips class build on a miss. A cold-class request today spends 13.2 CPU-s in plan builds and 2.72 CPU-s in PP pack [M Σ, lines 440–1179; leaf and fold mixed] | same, ×7 segments [E] | L: circuit/statement change (proof bytes change) | high: soundness review | resolves an M8 contract conflict |
| 4 | `STWO_RV64_M9_LEAF_FIXED_ON_DEVICE` | **L1c leaf FIXED built on the device** from the circuit description, as M8 does for fold FIXED coefficients (`outer_staged.zig`) | −8.6 GB of row 1 even on a miss, without packing [D] | ≤−0.17 s/GPU [D: 8.6 / 2 / 24.6]; overlaps L1a's FIXED half | ≤−1.2 to −1.7 s/GPU [D: 0.30 × 4–5.5] | M | medium | alternative to L1a for FIXED |
| 5 | `STWO_RV64_M9_GEOMETRY_RESIDENT` | **L2 geometry residual**: only what E1 shows M8 still re-sends (row 7, any twiddle path not on `class_cache`) | ≤≈1.07 GB after M8 [E] | ≤−0.02 s/GPU [D: 1.07 / 2 / 24.6] | ≤−0.4 s/GPU [E: ×7] | S | low | after M8 E1 |
| 6 | `STWO_RV64_M9_CLASS_RESIDENT` | **L1b packed classes resident across requests** in `class_cache` (0.455 GB ≈ 0.23 GB/GPU [D]) | hit rate × 0.455 GB | ≈0 link once L1a lands [D: 0.455 / 2 / 24.6 = 0.009 s]; the value is host class build on hits (see L4) | worth the measured class hit rate (E8) | S after L1a | low | `ClassCache` + `MemoryPlan` |
| 7 | `STWO_RV64_M9_D2D_INPLACE` | **L5** in-place coset/column layouts; write INTER and final coefficients in place (22.0 GB is explicit `final_coefficient_copy_words` [M Σ `GPU_TRACE_OWNERSHIP`]) | D2D, not H2D: ≤167 GB | ≤0.11 s/GPU [D: 0.214 / 2]; M8 MAIN-resident path takes part | ≤0.75 s/GPU [E: ~7×] | M | medium | after M8 H5/H12 |
| 8 | `STWO_RV64_M9_HOST_REGISTER` | **L6** `cudaHostRegister` the capture source and class store, removing the 8-thread bounce and the 64 MiB run-ahead limit | 0 link; −28.4 → ≈−3 GB host memcpy after L1a [D] | CPU relief only [E small]; ZisK found no benefit | CPU relief | S | low (`MADV_DONTFORK`) | independent |
| 9 | `STWO_RV64_M9_CHUNK_INDEXED` | **L8** pil2-style indexed chunk: pc/decoded instruction as an index into the device program table | −0.5 to −1.4 GB [E: 2–4× on ≈1.9–2.3 GB] | −0.01 to −0.03 s/GPU [D] | −0.2 to −0.5 s/GPU [E] | M | low | after L0 |
| 10 | `STWO_RV64_M9_GPU_REPLAY` (+ `_GPU_GROUP`, `_AOT_RECORD`) | **L9** capture on the GPU / faster capture (§5.9) | −14 GB compact ingress on 26235159 if replaying from ≈0.5–1.6 GB [E] | −0.3 to −0.6 s [E] of what remains exposed after streaming | ≈−1 s [E] of the ≈1.3 s exposed first-segment latency; frees ≈92 CPU-user-s [M T10] | L (M10-scale) | high | after M8 + L0 |
| B | *(one line)* | **Baseline**: raise the immutable cache cap (`outer_source.zig:351`), optionally `STWO_RV64_OUTER_ASSIGNMENT_LEAF_IMMUTABLE=1` | warm repeat only: up to the evicted statics [E] | helps repeated classes only; new blocks miss leaf classes | unknown (E8) | XS | memory pressure next to a 21.5–21.8 GB fold arena peak [M M8 §3.7] | none |
| — | *(M8)* | Streaming capture → GPU overlap per sealed segment (d-wire `Feed`) | 0 | −1.6 to −1.9 s exposed capture [E M8 §5]; an M8 saving, not M9 | ≈−3.5 s [E] | — | — | it *is* M8 |
| — | *(done)* | **L7** proof-only readback | already 62 MB / 3 ms [M] | ≈0 more; the sync cost goes with M8 H13/H23 | ≤25 ms [E] | — | — | M8 slab |
| — | *(hardware)* | x16 PCIe host | link ≈2× [E] | halves the residual [E]; barely matters after L1a | helps until L1a lands | pod placement | — | independent |

**Total for 24628607 after M8 + L0 + L1a + L3 [D/E]:**
- H2D ≈2.6–3.7 GB [E: 1.9 + 0.22 + 0.455 + ≤1.07], ≈0.05–0.08 link-s per GPU [D], mostly hidden by L3.
- The H2D upper bound today is ≤9% of a ≈6.5 s M8 request [D]; how much of it is M9's to recover depends on the leaf share (Q1), since M8 takes the geometry and fold bytes.
- Host: −3.70 CPU-s of unpack and ≈−25 GB of host memcpy per request [M/D].

**For 26235159** link time is ≤4–5.5 s/GPU [E]; L1a's share is ≤2.2–3.0 s/GPU [D], and with M8's geometry share the total cannot exceed 4–5.5 s/GPU. Measuring it (E1) is the precondition.

### 5.9 GPU guest execution: feasibility verdict
- **Interpreting a single RV64 hart on the GPU: no.** Execution is serial and branchy, and our fast pass already runs at ≈170 MIPS on the CPU [M census1]. zkDTVM also executes on the CPU [C, §2.2].
- **Parallel replay from checkpoints on the GPU: feasible, M10-scale.** The fast pass produces segment boundaries, and the compact transport already carries a register/clock seed every 256 rows.
- **Shape of the GPU version:**
  1. The CPU (or an AOT translator, as ZisK does) runs the fast pass and emits a minimal trace: chunk-start register snapshots plus load values.
  2. The minimal trace is uploaded: ≈0.5–1.6 GB on 26235159 [E].
  3. The GPU replays thousands of chunks in parallel and emits `CompactRecord`/`Fact`/`Event`.
  4. ALU/BINARY/SHIFT dedup runs as GPU sort + reduce-by-key, replacing 7.51 s of hash grouping [M T10].
  5. The memory ledger runs as a GPU sort by (address, tick), replacing the serial ≈50 ms per segment.
- **First step:** GPU grouping + ledger (`_GPU_GROUP`), then replay. CPU-side alternative: AOT/JIT-compile the GE guest for the *recording* pass (`_AOT_RECORD`); recording runs at 14–15 MIPS for 24628607 [M census1], the narrow-capture worker at 5–9 MIPS [M census2 T10].
- **Verdict.** On 24628607 the gain after M8 streaming is small (≤0.6 s [E]). On large blocks and on CPU contention it is real. It belongs to the >60% plan, not to the IO pass.

---

## 6. Fit with the post-M8 sequence

The agreed order is: M8 lands → benchmarks → **cleanup/productionisation pass** with a repeatable benchmark set → **M9 >60% cut** plan.

| phase | IO items | why there |
|---|---|---|
| **Inside M8 (now)** | **L0** compact `TraceChunk` v2. Move the chunk H2D off the exec stream (`native_device_stage1.zig:658`), as M8 §6.2 asks. **Resolve the leaf class-miss rule** (`GpuNativeClassNotWarmed` vs per-block leaf classes). | Contract decisions before the packer and the class contract are frozen. |
| **Cleanup pass** | **IO as permanent benchmark fields:** H2D/D2H/D2D by NVTX range; exposed copy-s per device; time inside host syncs; `TraceChunk` B/step; class hit rate per request; `GPU_RESIDENT_SETUP` evictions. Fix the census tool's srcKind reading and its 16 MiB bucket label. Run E0 (cap baseline), E8 (different blocks) and E9 (dual-GPU bandwidth). | Makes later work measurable, and E8 decides L1b/L4. |
| **M9 >60% plan** | **L1a** packed ingress (or L1c for FIXED), **L3** copy lane, then **L4** canonical leaves if E8 shows a low hit rate and the host class-build cost matters, **L2** only if E1 shows a residual, **L5**, then **L8/L9**. | L1a works without any hit rate, and its value grows with segment count. L4 is a circuit change and needs its own soundness review. |

The >60% target cannot be met by IO alone. Large blocks are GPU-seconds bound (26235159 ≈42 GPU-s [E, bench15]). IO on 26235159 is plausibly 8–11 link-s summed over both GPUs [E, §1.4], the same order as the kernel savings being chased, so L1a belongs in the first M9 wave.

---

## 7. Experiments once M8 lands

House rules for every experiment: AC power; `gpu.lock` through the harness; memguard (`~/Coding/ge-ops/bin/memguard`); cold + warm in the same service; canonical runners (`scripts/rv64_m8_bench15.py` for timing, `scripts/rv64_m8_census.py` for analysis); nsys with `-t cuda,nvtx,osrt` plus `nsys stats` reports `cuda_gpu_mem_size_sum`, `cuda_gpu_mem_time_sum`, `cuda_gpu_kern_sum`, `nvtx_gpu_proj_sum`.

| id | measure | how | acceptance |
|---|---|---|---|
| E0 | **Cap baseline** (B) | Today's path with the immutable cap raised (e.g. 6 GiB) ± `LEAF_IMMUTABLE=1`, on 24628607 (same-block warm) and in E8 | Records warm H2D, evictions, and device peak. This is the bar L1a/L1b must beat. |
| E1 | **Post-M8 IO baseline** on 24628607, 26235156 and **26235159** | Cold + warm per block under nsys. Per direction `cuda_gpu_mem_size_sum`; H2D by NVTX range and consumer kernel; per-upload NVTX labels (`h2d/<site>`, leaf vs fold); exposed copy-s per device; copy time inside host syncs; `staged_h2d_bytes` delta per request; `TraceChunk` bytes / guest steps. | Every number [M]. Confirms or refutes §1.4 within ±10% per row, answers Q1/Q2, replaces 26235159's [E]. |
| E2 | L0 compact chunk | `TraceChunk` B/step and capture-thread CPU time, v1 vs v2, on 24628607 | ≤ ~80 B/step; capture exposed no worse than M8 §5; 39/39 golden |
| E3 | L1a `STWO_RV64_M9_CLASS_PACKED_INGRESS=1` | E1 protocol; decoder kernel time per node | Warm and cold H2D both drop ≥14 GB on 24628607 (minus M8's fold share); decoder ≤10 ms/node; host unpack ns → 0; 39/39 + 32/32 golden |
| E4 | L2 residual | E1 protocol after M8 | Only if E1 shows ≥0.5 GB geometry H2D per request |
| E5 | L3 `STWO_RV64_M9_H2D_STREAM=1` | Exposed copy-s per device; copy time inside host syncs | Exposed H2D ≤ 20% of H2D copy-s; no kernel slowdown > 2% |
| E6 | End-to-end | `rv64_m8_bench15.py` on the 15-block basket, flags on vs off, quiet gate | Δ job and Δ proving per block [M]; accept if no block regresses beyond noise |
| E7 | L5 D2D in place | E1 D2D bytes and copy-s | D2D copy-s per device ≤ 50% of the post-M8 baseline |
| E8 | **Different-blocks warm** (class hit rate) | One service, the 15-block basket in sequence, each block once after a warm-up block. Record per request: class keys, host class-store hits/misses (`GPU_OUTER_{PP,PLAN}_PACK adopt` vs `unpack`), plan builds and `plan_ns`, H2D bytes | Gives the production hit rate that L1b and B are worth, and the class-build CPU that L4 would remove |
| E9 | **Dual-GPU H2D bandwidth** | Both GPUs uploading at once from the staged ring (8-thread bounce) and from registered sources; GB/s per GPU and combined | Replaces the assumed 2 × 24.6 GB/s [E]; post-M8 both GPUs stream at once |
| E10 | L1c leaf FIXED on device | Build leaf FIXED evaluations from the circuit description on the device; compare to uploaded raw forest | Byte-identical FIXED roots; row 1 H2D → 0 on a miss; build time per node |

---

## 8. Open questions and sources

### Open questions
- **Q1.** Of the 15.8 GB of recursion statics, how much is *leaf* and how much fold/root? M8 removes only the latter. E1 with per-upload labels.
- **Q2.** Does every M8 path adopt `class_cache` twiddles, PCS framing and FIXED trees, and does row 7 (native owner geometry) survive? E1.
- **Q3.** What is the class hit rate across different blocks (E8), and how much of the 13.2 CPU-s cold plan-build cost is leaf? This decides L1b and L4.
- **Q4.** GPU throughput of a delta-varint/LZ4 decoder over 16,384-word blocks. Unpacked residency (≈16 GB) does not fit next to a 21.8 GB fold peak [M M8 §3.7].
- **Q5.** H2D on 26235159: the census2 attempt exited 1. All of its IO numbers here are [E].
- **Q6.** Combined two-GPU H2D bandwidth (E9), and copy-engine contention between lanes after L3.
- **Q7.** Can the pod be placed on an x16 host? It matters only until L1a lands.
- **Q8.** zkDTVM internals: the prover is closed, and the article contradicts itself on interpreter vs AOT. A kernel-level comparison with NitrooZK-stwo is a separate question.

### Sources
**Local / pod:**
- `origin/codex/rv64-m8-census2:vectors/reports/rv64-m8-20261106/census1/{README.md,capture-cpu.json,m7p1-24628607-warm.json}`
- `origin/codex/rv64-m8-census2:vectors/reports/rv64-m8-20261106/census2/{README.md,h2d-api-and-pcie.txt,m7p1-24628607-warm-deep.json,m7p1-24628607-warm-d2d.json,deep_queries.py}`
- `origin/codex/rv64-m8-census2:vectors/reports/rv64-m8-20261106/bench15/{README.md,estimate.json}`
- `origin/codex/rv64-m8-gpu:design/riscv-proving-stack/rv64-m8-gpu-native.md` (l.32, l.155, H21, §3.1–3.8, §5, §6.2)
- `origin/codex/rv64-m8-gpu:src/integrations/riscv_cuda/rv64/jobs/gpu_native.zig:679-696` (`TraceChunk`)
- `origin/codex/rv64-m8-gpu-d-wire`: `jobs/native_device_stage1.zig:293,658`, `jobs/driver_serve.zig` (ring defaults), `vectors/reports/rv64-m8-20261106/gpu-d-wire/README.md`
- This branch:
  - `design/riscv-proving-stack/{rv64-m5-rootverify.md:66-76, rv64-m6-enqueue.md:94-98, rv64-m6-hint-tape.md:101-103, rv64-gpu-10x-plan.md:326}`
  - `src/backends/cuda/native/runtime/{device_arena_runtime.cuh:72,972-1185, context.cu:134,180,424,542}`
  - `src/integrations/riscv_cuda/rv64/{session_context.zig:72-75, outer_wrap.zig:277, outer_assignment.zig:793-796,896-905, outer_source.zig:351, trace_commit.zig:367-369,578-580, resident_composition.zig:726-800, pcs_native.zig:196, cpu_witness.zig:9-13, cpu_projection.zig, core_witness.zig, jobs/outer_staged.zig:6-12, jobs/outer_class_plan.zig}`
  - `src/integrations/riscv_cpu/word16_execution/{family_input.zig:8, memory_input.zig:5,18, prepared.zig}`, `src/integrations/circuit_cpu/om31/cache_pack.zig`
  - receipts `vectors/reports/rv64-m9-io-design/` (telemetry extract, queries, zkDTVM and EthProofs snapshots, `SHA256SUMS`)
- Pod: `/workspace/m3/runs/m8-census2/summary/*`; `/workspace/m3/runs/m7-integrate/daemon-24628607-r2-p1-inter-contributions-profile-20261106-01-06-baseline/{producer.stderr,nsys/timeline.sqlite}`; `/workspace/m3/inputs/24628607.bin` (2,703,496 B)

**Frontier (code):**
- zksync-airbender: `gpu_prover/src/{execution/prover.rs, execution/gpu_worker.rs, prover/context.rs, prover/transfer.rs, prover/memory_policy.rs, witness/witness_unrolled.rs}`, `riscv_transpiler/src/machine_mode_only_unrolled/mod.rs`, `cs/src/definitions/mod.rs`
- airbender-v3: `gpu/{docs/gpu_scheduling_contract.md, execution_prover/src/workers/simulation_runner.rs, prover_context/src/context.rs, gkr/src/setup/mod.rs}`
- zksync-airbender-prover: `crates/zksync_os_prover_service/src/lib.rs`
- zisk: `emulator-asm/asm-runner/src/{asm_mt.rs, asm_mo_runner.rs}`, `state-machines/mem-cpp/cu/count_and_plan.{cu,cuh}`, `state-machines/mem/src/mem_device_rows.rs`, `gpu-witness/src/lib.rs`
- pil2-proofman: `common/src/{gpu_witness.rs, packed_info.rs, memory_handler.rs}`, `proofman/src/{utils.rs, proofman.rs}`, `pil2-stark/src/{goldilocks/src/stream_commit.cuh, utils/cuda_graph_cache.cuh, starkpil/multiplicity.cuh}`, `goldilocks_tooling.cuh`, `starks_api.cu`
- sppark: `util/gpu_t.cuh`, `msm/pippenger.cuh`

**Web** (snapshots in `R/`):
- zkDTVM article: https://openlabs-intl.antdigital.com/0x/Introducing-zkDTVM-A-GPU-Native-zkVM-Built-for-End-to-End-Acceleration
- AntChainOpenLabs: https://github.com/AntChainOpenLabs/zkdtvm-docker, …/zkdtvm-stark-verifier, …/zkdtvm-wasm-stark-verifier, …/NitrooZK-stwo
- EthProofs: https://ethproofs.org/clusters (→ /provers), https://ethproofs.org/teams/antchain-openlabs
- Press and social: https://x.com/AntChainOpenLab/status/2061323404909883583, https://phemex.com/news/article/antchains-zkdtvm-breaks-global-record-in-ethereum-ethproofs-benchmark-77478
- SP1 tracegen: https://docs.rs/sp1-gpu-tracegen/6.1.0/src/sp1_gpu_tracegen/lib.rs.html, https://docs.rs/crate/sp1-gpu-tracegen/6.9.0/source/src/riscv/global.rs
- RISC Zero: https://docs.rs/risc0-circuit-rv32im-sys/latest/src/risc0_circuit_rv32im_sys/lib.rs.html

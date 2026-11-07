# RV64 M9: host↔GPU IO, "streaming direct to GPU", and what to do after M8

Status: research and design only. No GPU was used and no run was made for this document. The pod was read only: logs, summaries, and one retained nsys sqlite opened `mode=ro`.
Base: `codex/rv64-m7-integrate @ c72b51646`. Companions:
- `design/riscv-proving-stack/rv64-m8-gpu-native.md` on `origin/codex/rv64-m8-gpu` (cited below as **M8 §n**);
- `vectors/reports/rv64-m8-20261106/{census1,census2}/README.md` on `origin/codex/rv64-m8-census2` (cited below as **census1/census2**).

Labels:
- **[M]** measured, with the file cited;
- **[D]** derived, with the arithmetic shown;
- **[E]** estimate;
- **[C]** a vendor claim that cannot be checked.

No number here was measured for this document. Every [M] is from an existing receipt or trace.

Hardware: pod `rv64-resident-2x5090` (2× RTX 5090, 32 GB each). Both GPUs train PCIe Gen5 at **x8**, out of a maximum of x16 [M, census2 `h2d-api-and-pcie.txt`]. Each gets about 24.6 GB/s of H2D at the same time [M, same file].

---

## 0. TL;DR

**The hypothesis, corrected.** The 28.4 GB that a warm 24628607 request moves from host to device is *not*, for the most part, block inputs going onto the GPU or proofs coming off it:

| what crosses PCIe per warm 24628607 request | GB | share |
|---|---:|---:|
| Request-invariant **recursion class statics**: the FIXED forest (≈8.5) plus the assignment task tables (7.26). Re-uploaded on every request. | ≈15.8 [D] | 56% |
| Deterministic **geometry**: twiddles, logs, denominators, descriptors and PCS metadata. Re-sent on every trace commit, composition and PCS call. | ≈9.4–10.4 [D] | 33–37% |
| **Block-derived** compact capture (facts, events, `CompactRecord`s) feeding the `*_witness` kernels | ≈1.9 [D] | 7% |
| Per-request recursion seed tapes | 0.22 [M] | <1% |
| **D2H**: everything that comes back, proofs included | 0.062 [M] | 0.2% |
| The block input itself (`24628607.bin`) | 0.0027 [M] | ≈0% |

Other facts that set the picture:
- Cold and warm requests move **identical** H2D bytes: 28,270,666,064 B each [M, `/workspace/m3/runs/m8-census2/summary/24628607-{cold,warm}.json`]. Nothing is resident across requests today.
- The "1.2 s" is copy time summed over **both** GPUs: dev0 0.614 s, dev1 0.541 s [M, census2 `h2d-api-and-pcie.txt`].
- **None** of that copy time overlaps a kernel on its device (0.000 s overlap [M, retained M7-P1 trace]).

**zkDTVM's "streaming direct to GPU" is not an exotic transport.** Their published architecture, read from the article and its figures:
- CPU-side guest execution (AOT rv2x86);
- compact typed execution events sent to the GPU;
- trace generation on the GPU, roughly one thread per event;
- everything resident through Core → Compress → Shrink;
- a generate → upload → prove pipeline per shard.

They mention no GPUDirect, RDMA, GDS or UVM [C]. That is the shape M8 already specifies. For us, three things are worth more than streaming block inputs, which are already small and already expanded on the GPU in the default path:
1. **Stop re-uploading things that never change.** This covers about 90% of the bytes.
2. **Keep the one stream that does change compact, and overlap it with compute.**
3. **Do not regress the format in M8.**

**Recommended plan, in order:**

1. **Now, before `NativeFactory.pack` is written (M8 contract, no new flag).** Specify `TraceChunk` as *compact ingress* (v2: `CompactRecord` + seeds + `Fact`/`Event`), reusing the existing `cpu_unpack` / `cpu_witness` / `*_witness` kernels.
   - The current v1 draft carries MAIN *evaluation images* (`native_device_stage1.zig:293` on d-wire, consumed by `stwo_rv64_n1_scatter_v1`).
   - That would move witness expansion back onto the CPU capture thread, the one CPU stage on the critical path.
   - It would also grow ingress from about 2.3 GB to 7.38 GB [D, below].
2. **`STWO_RV64_M9_CLASS_PACKED_RESIDENT`.** Keep recursion class statics resident on the device in their *packed* form (0.455 GB total [M]) and decode them on the device per node. Key leaf classes by authority.
   - −15.8 GB per request [D], −0.32 link-s per GPU [D], and −3.70 CPU-s of host unpack [M].
3. **`STWO_RV64_M9_GEOMETRY_RESIDENT`.** Twiddles, logs, denominators and descriptors are made resident per (log, device), or generated on the device.
   - −9.4 GB [D], −0.19 link-s per GPU [D].
4. **`STWO_RV64_M9_H2D_STREAM`.** The residual (about 3 GB) goes on a dedicated copy stream from the pinned ring, with events, so it overlaps kernels and capture. Today 0% overlaps [M].
5. Later: D2D in place (≤0.11 s/GPU [D]), and capture on the GPU (parallel replay + grouping, M10-scale; the verdict is in §5.9).

**Expected savings.**
- Bytes: H2D 28.4 → ≈3 GB per warm 24628607 request [D: 28.39 − 15.8 − 9.4 = 3.2], and link time 0.58 → ≈0.07 s per GPU [D: 3.2 / 2 / 24.6].
- Time today: on today's host-bound path the wall saving is 0.3–0.6 s [E]. The GPUs are only about 50% busy, so not every copy-second is on the critical path.
- **Why this matters more after M8.** M8 makes the request kernel-bound: the floor is 5.29 GPU-s per GPU and the target request is about 6–7 s [M8 §5].
  - Copies on the exec stream then add directly to the critical path: 0.58 s/GPU on top of 5.29 s, which is about 9–10% of the M8 request [D: 0.58 / 6.5].
  - Levers 2–4 recover nearly all of it.
- **The big blocks are where IO really matters.** On 26235159 the per-segment scaling estimate is 200–270 GB of H2D per request, or 4–5.5 link-s per GPU [E, §1.4]. That is about 10–14% of its ~40.6 s [E] warm request, and class residency removes most of it.
  - This block has **no IO measurement**: the census2 run exited 1. Measuring it is experiment E1.

**Not worth doing for this problem:**
- **GPUDirect Storage / RDMA.** Our source is a CPU emulator in host RAM, not NVMe or a NIC.
- **Another pinning pass.** Every H2D is already staged through a pinned 4×16 MiB ring; census2 F1 misread the nsys enum (§1.3).
- **Proof-only readback.** D2H is already 62 MB, about 3 ms [M]; its cost was host *syncs*, which M8 removes.
- **CUDA graphs around copies.**

---

## 1. Measured byte census per request

### 1.1 Sources

| id | what | where |
|---|---|---|
| S1 | Fresh census2 summaries: cold and warm, H2D/D2H/D2D totals | pod `/workspace/m3/runs/m8-census2/summary/{24628607,26235156}-{cold,warm}.json` |
| S2 | Retained M7-P1 default-path nsys trace of a 24628607 two-request daemon (warm = request 1), sqlite sha256 `04573fd8…` | pod `/workspace/m3/runs/m7-integrate/daemon-24628607-r2-p1-inter-reuse-profile-retry-20261106-02-06-baseline/nsys/timeline.sqlite`, plus the `-inter-contributions-profile-20261106-01-06-baseline` run used by census1 |
| S3 | Producer telemetry (`GPU_STAGING_SUMMARY`, `GPU_RESIDENT_SETUP`, `GPU_OUTER_PP_PACK`, `GPU_OUTER_ASSIGNMENT`, `GPU_TRACE_OWNERSHIP`, `GPU_CPU_PROJECTION`) | `producer.stderr` of the S2 run directories |
| S4 | census2 deep queries: H2D by NVTX range, PCIe link state | `census2/m7p1-24628607-warm-deep.json`, `census2/h2d-api-and-pcie.txt`, `census2/m7p1-24628607-warm-d2d.json` |

The research queries were read-only Python over S2: `h2d_overlap.py`, `h2d_range.py`, `q.py`, `split.py`, `next.py`, `sizes.py`, `tele.py`. They are kept outside the repo in the session scratchpad. Their attribution method is given in §1.5.

### 1.2 Totals (24628607 warm)

| direction | bytes | copy-s (summed over both GPUs) | notes |
|---|---:|---:|---|
| H2D | **28.39 GB** [M S2/S4]; 28.27 GB [M S1] | **1.156** [M] | 11,640 copies [M]. Per GPU: dev0 15.08 GB / 0.614 s, dev1 13.31 GB / 0.541 s [M S4]. Native window 6.99 GB, recursion 21.40 GB [M, split at the first `rv64/owner/controller` range, 6.854 s of 12.601 s]. |
| D2H | 61.6 MB [M] | 0.003 [M] | 98% is `m7/pcs/final_readback_encode`: 33 PCS readbacks in 1,155 copies [M]. The proof on disk is 0.84 MB [M], so D2H is about 74× the proof [D]. The cost is 2,049 synchronous host waits, not bytes [M]. |
| D2D | 167.5 GB [M S1] | 0.214 [M] | 781 GB/s [M]. Fully exposed: it is on the same stream as the kernels. |
| memset | 52.2 GB [M] | 0.028 [M] | |
| kernels | — | 10.58 GPU-s [M census2] | H2D copy-s is 10.9% of kernel GPU-s [D: 1.156 / 10.58]. |

The second block is 26235156 warm [M S1]: H2D 21.99 GB in 0.881 copy-s, D2H 48 MB, D2D 129 GB.

### 1.3 How the copies run today (corrects census2 F1)

- **Already pinned and staged.**
  - nsys `ENUM_CUDA_MEM_KIND` in S2 is 0 = Pageable, 1 = Pinned, 2 = Device [M, the enum table of the trace]. census2 read `h2d_by_srckind = "1"` as pageable. It is **pinned**.
  - Every H2D goes through `staged_h2d` (`src/backends/cuda/native/runtime/device_arena_runtime.cuh:972-1185`, `kSlots = 4` at :1078, 16 MiB slots at :72):
    1. the source is pageable host memory;
    2. an 8-thread `CopyPool` memcpy fills the slots of a per-stream ring of 4 × 16 MiB `cudaHostAlloc` slots;
    3. `cudaMemcpyAsync` copies each slot to the device.
  - This is why the largest copy is exactly 16.777 MB, and why the CUDA API CPU time is small (0.046 s [M census2]).
- **"The pinned ring saw only 4.3 GB" read a cumulative counter mid-run** (producer.stderr line 279).
  - At the end of request 0, `GPU_STAGING_SUMMARY staged_h2d_bytes = 28,389,590,992` (line 1223). That equals the warm H2D in nsys [M].
  - At process end it reads 56,779,181,984, which is 2 × 28.39 GB [M, line 2393].
- **No overlap.** Every H2D, D2H and D2D is a `cudaMemcpyAsync` on the *same* stream as the kernels: dev0 stream 22, dev1 stream 24, issued from thread `rv64-word16-eth`, with no graph [M S2].
  - Exposed H2D time is 1.1557 of 1.1558 s; exposed D2D is 0.2142 s [M].
  - The copy engines idle during compute, and the SMs idle during copies.
- **The host can only run 64 MiB ahead** (4 slots). The uploading thread blocks on stream progress, which shows up as 93 slot waits in the warm request [M, 170 − 77].
  - The bounce also costs **28.4 GB of host memcpy per request** [D], on CPU cores that capture and recursion assembly also want.
- **D2H** goes through a synchronous `staged_d2h`: 2,049 host waits per request [M].

### 1.4 Attribution table (24628607 warm, S2)

"copy-s" is summed over both GPUs. Every row is per request, and every row is identical cold and warm [M S1, S2].

| # | GB | what it is | source / call site | consumer kernel | invariant? | copy-s |
|---|---:|---|---|---|---|---:|
| 1 | **≈8.5–8.9** [D/M] | Recursion **FIXED forest**: raw FIXED evaluations, unpacked on the host from the PP class cache and uploaded per node. Logical 8.61 GB vs packed 0.183 GB [M Σ `GPU_OUTER_PP_PACK` over 19 warm nodes]. The 18 single uploads of 168–705 MB come to 8.51 GB [M sizes]; consumer-kernel attribution gives 8.92 GB [M]. 1.04 GB lands inside the native window because leaves overlap native [M]. | `outer_wrap.zig:277` (sits inside NVTX `owner/callback`) | `b2n_stage` | per class | ≈0.35 [D] |
| 2 | **7.49** [M] | Recursion **assignment schedule**. `tasks`/`indices`/`chain_ends` are 7.255 GB [M Σ `static_words`×4] and request-invariant; packed they are 0.272 GB [M]. The seed tape is 0.217 GB [M Σ `seed_words`×4] and is per request. | `outer_assignment.zig:~896-905` `immutableWords`, then evicted; leaf plans are never reusable (`reusableClassPlan()`, :794 `!class_is_leaf`) | `generate` | static: per class | 0.313 [M] |
| 3 | 3.08 [M] | **Twiddles + itwiddles + logs, re-sent on every trace commit.** Native MAIN 0.64 + INTER 0.54; recursion 0.95 + 0.95. Sizes are exactly 2^26 B + 4·ncols (MAIN +456 B = 114 cols, INTER +1216 B = 304 cols) [D]. | `trace_commit.zig:367-369, 578-580` | `b2n_stage` | per log | 0.121 [M] |
| 4 | 3.41 [M] | **Composition per-role uploads**: selected twiddles, denominators, masks, logs, powers. Native 1.01, recursion 2.40. | `resident_composition.zig:726-799` | `n2b_*`, `fill_auxiliary`, `lift_add` | per class/log [E] | 0.133 [M] |
| 5 | 1.86 [M] | **PCS per-call metadata**: twiddles h[19], FRI twiddles, sample maps, sources, descriptors. `host_geometry_bytes` is 42–84 MB per miss [M]. | `pcs_pipeline.cuh:202-397`, `pcs_native.zig:196` | b2n / PCS | per class | 0.075 [M] |
| 6 | **≈1.9** (2.0–2.7 incl. `b2n_init` metadata) [D] | **Captured execution trace, compact.** It feeds `memory_witness` 0.97–0.98, `arithmetic_witness` 0.58–0.65, `family_witness` 0.27 and `boundary_witness` 0.07. This is the **only block-derived bulk data**: 26.89 M steps → ≈70 B/step [D: 1.89 GB / 26.89 M]. | `cpu_projection.zig`, `core_witness.zig`, `cpu_witness.zig` | `*_witness` | **per block** | ≈0.077 [D] |
| 7 | ≈1.07 [D] | Native `owner/callback` GKR/LDE geometry and twiddles, including `GPU_CPU_PROJECTION metadata_h2d_bytes` 0.47 GB [M Σ] | native owner path | `b2n_init`/`b2n_stage` | mostly per log | ≈0.044 [D] |
| 8 | 0.13 [M] | Native TC/FIXED. The setup cache hit 14 times when warm [M]. | `trace_commit.zig` | b2n | per class | 0.006 [M] |
| 9 | ≈0.97 [D] | Remainder of recursion `owner/callback` and TC/FIXED (4/8/2/1 MiB pieces) | outer path | b2n | per class [E] | ≈0.04 [D] |
| Σ | **28.39** [M] | | | | | **1.156** [M] |

**Why setup is re-sent when warm.**
- The only device setup cache is the immutable setup cache. It is capped at 2 GiB per device (`outer_source.zig:351`, `@min(byte_cap, 2<<30)`) and thrashes:
  - `GPU_RESIDENT_SETUP` dev0: uploads 336 → 670, evictions 783 → 1567 across the warm request;
  - dev1: 260 → 522 and 470 → 1099 [M, producer.stderr lines 1218, 2387-2388].
- Some segments show `rom_cache_hit=false` even when warm [M].
- Host unpack of the packed statics costs **1.94 s (PP) + 1.76 s (plan) = 3.70 CPU-s per warm request** [M Σ `ns`].

**Boundary caveat.** Rows 6, 7 and 9 and the native/recursion split come from time windows, next-kernel attribution and size fingerprints [D]. Exact per-call-site bytes need a re-profile with per-upload NVTX labels (experiment E1).

**26235159 [E].** It has no IO measurement: the census2 attempt exited 1 (`summary/26235159.log`). Scaling by segments, with 49 segments [M T10]:
- per segment, 24628607 moves 28.3 GB / 7 = 4.04 GB and 26235156 moves 22.0 GB / 4–5 = 4.4–5.5 GB [D];
- 49 × 4.0–5.5 GB gives ≈200–270 GB H2D, ≈100–135 GB per GPU, ≈4–5.5 link-s per GPU [E].

This is an upper-side estimate. Leaf classes repeat across 49 same-shape segments, so it is also exactly the case that class residency collapses.

### 1.5 Attribution method

Each H2D in S2 is assigned to its NVTX push/pop range and to the next kernel on the same stream. Sizes are matched against telemetry totals: `GPU_OUTER_PP_PACK` logical bytes, `GPU_OUTER_ASSIGNMENT static_words`/`seed_words`, and `GPU_CPU_PROJECTION metadata_h2d_bytes`. Overlap is computed per device as |∪copy ∩ ∪kernel|.

### 1.6 Critical-path seconds

| | today, M7 host-bound warm 12.3 s [M] | after M8, kernel-bound ~6–7 s [E, M8 §5] |
|---|---|---|
| H2D link time per GPU | 0.54–0.61 s [M], fully exposed on the GPU stream | the same unless the bytes change [E]. M8 removes the native `owner/callback` and TC re-uploads (H4/H5/H12/H21), the fold class region (`jobs/outer_staged.zig:6-12`) and the per-job syncs, but **leaf statics stay per node** and nothing in M8 makes the geometry resident by design. |
| share of the request wall | ≈0.3–0.6 s [E]: GPUs ~50% busy, recursion host-bound | ≈0.3–0.58 s/GPU **on** the critical path [E], ≈5–9% of the request |
| D2D | 0.214 copy-s summed → ≤0.11 s/GPU [D] | lower: no `copyColumns`, no replay [E] |
| D2H | 3 ms + 2,049 syncs [M] | ~1–2 ms, one D2H per GPU [E, M8 §3.4] |

---

## 2. zkDTVM: what they do, what can be verified, what transfers

Sources:
- the announcement article (https://openlabs-intl.antdigital.com/0x/Introducing-zkDTVM-A-GPU-Native-zkVM-Built-for-End-to-End-Acceleration). It is a JS SPA, rendered through a reader proxy, and the figures were downloaded;
- `github.com/AntChainOpenLabs/{zkdtvm-docker, zkdtvm-stark-verifier, zkdtvm-wasm-stark-verifier, NitrooZK-stwo}`;
- the EthProofs leaderboard.

### 2.1 Stack [C unless noted]
- **Proof system.** SumCheck PIOP, multilinear throughout, with the "Pangolin" PCS (Basefold-based) and a recursive STARK. The AIR is chip-decomposed, with LogUp buses and no central CPU chip. Constraints are local only (no next-row references) and have degree ≤ 3 in Core. Stages run Core → Compress → Shrink.
- **Lineage.** A Plonky3 fork with SP1's architecture (zkdtvm-docker README).
- **Shipped verifier** [M, code read of `vendor/zkdtvm-verifier-core`]:
  - Field: KoalaBear with a degree-5 extension; the recursion uses a septic curve and D11 algebra.
  - `whir_config.json`:
    - core: log_blowup 1, 261 queries, 20-bit query grinding;
    - compress: blowup 2, 160 queries;
    - shrink: blowup 3, 131 queries;
    - root_shrink: **WHIR** with stacking.
  - The sample proof for block 25954917 is 267,918 B.
  - The article says Basefold/Pangolin while the verifier ships WHIR plus FRI-style configs, so the PCS has changed since the article, or the article describes a variant.
- **Deployment** [M, docker README]:
  - binary only, `ghcr.io/doubizhizun/zkdtvm_eth_proofs:0.6.1`, "x86-64 CPUs, RTX 5090, CUDA 12.8";
  - 1, 8 or 16 GPUs, with one prover container per GPU pinned to 16 cores and a NUMA node.
  - **The prover source is not public.**

### 2.2 What runs where and how data moves [C]

| question | zkDTVM answer | transfers to us? |
|---|---|---|
| Guest execution on the GPU? | **No.** The guest ELF is AOT-compiled to x86 ("rv2x86"), with a fast checkpoint/sharding mode and a separate detailed recording mode. | Yes, the *CPU-side* idea: a fast checkpoint pass plus faster recording (§5.9). |
| Trace generation on the GPU? | **Yes.** Every trace type is built in kernels, roughly one thread per event: core, preprocessed, memory, and the precompiles. "Avoids the classical CPU-to-GPU upload bottleneck." No byte counts are given. | Already true for our default native path (§4.1). Not true for recursion statics (§1.4 rows 1–2). |
| What crosses H2D | Typed execution events, `GpuExecutionRecord: Checkpoint \| MemoryGlobal \| Precompile`, bincode-serialized in a gRPC `SubProveRequest` per GPU prover (cluster figure). | Ours is the `TraceChunk` stream. Keep it compact (lever L3). |
| Transport | Not specified. They name CUDA async memory pools (RAII), multi-stream copy/compute overlap, and a generate → upload → prove pipeline per shard. **No GPUDirect, GDS, RDMA or UVM.** | M8 arena + three streams + d-wire `Feed`. The missing piece is the copy *stream* (L4). |
| Residency | Trace matrices, proving keys, Poseidon2 constants and twiddles stay device-resident across phases. | **The biggest transfer for us** (L1, L2). |
| Shape control | A "shape catalog": a small set of per-chip height templates. | `ClassCache` / `GpuNativeClassNotWarmed` (M8 §3.1). |
| What leaves the GPU | Shard proofs go to a coordinator, then gather → compress. The final Groth16/Plonk runs on **CPU** SNARK provers, which contradicts "no stage falls back to CPU". | Our slab: one D2H per GPU (done in M8). |
| Memory trick | Padding-free DFT: padding rows stay compressed through the commitment. | Never upload padding rows; generate them on the device (L3). |
| Sumcheck tail | Univariate skip in the tail, merging the last c·k rounds. | It is a protocol change, so proof bytes would change. Not an IO lever; see census2 T7 for the non-protocol version. |

### 2.3 Verifiable numbers
- **EthProofs, fetched 2026-11-07** [M third-party, not reproduced]:
  - cluster "zkDTVM 4x5090" (evmone guest): average 4.6 s, $0.0032 per proof;
  - team multi-GPU: 1,237,787 proofs, average 4.0 s; single-GPU: 4,335 proofs, average 23.7 s.
  - The same table shows Airbender v3 at 2.4 / 3.4 / 5.9 s and OpenVM 2.1 at 3.2 s. Matching rows to clusters is my inference.
- **Press and social** [C]:
  - 3.7 s "record" (Phemex, 2026-04-30);
  - 3.1 s average with every block under 8.8 s, on a **16×5090** cluster (X post, 2026-06-01).
- **None of this compares with our 12.3 s warm request on 2×5090.** The guest is different (evmone vs GE), and so are the block mix and the GPU count. Their single-GPU average of 23.7 s is the closest shape to ours.

### 2.4 Bonus: NitrooZK-stwo
`AntChainOpenLabs/NitrooZK-stwo` is a CUDA backend for upstream Stwo (Circle STARK, M31) from the same lab.
- Its IO is naive: pageable `cudaMemcpyAsync` on stream 0 (`crates/stwo/src/stwo_cuda/cuda/utils.cuh:230-254`). It is not an IO model.
- Its README reports wide-fib Poseidon at log 23 proving in 2,010 ms on an RTX 4090 [C].
- It is worth a *kernel* comparison later (FFT, Blake2s Merkle, GKR). That is separate from this document.

### 2.5 What transfers, in one line
"Streaming direct to GPU" in the zkDTVM sense has five parts:
1. CPU emulation emits compact events into a pinned ring;
2. a copy stream overlaps the uploads with compute;
3. device kernels expand the events into traces;
4. traces and setup stay resident until the proof;
5. only the proof leaves the device.

We already have parts 1 and 3 in the default native path, and part 5 lands in M8. **Part 4 (residency of setup and geometry) is the gap that accounts for about 90% of our bytes, and part 2 (the copy stream) is the gap that accounts for 100% of the exposure.**

---

## 3. Frontier patterns (code read, local clones)

Clones are read-only under the session scratchpad `frontier/`: zksync-airbender, zksync-airbender-prover, airbender-platform, pil2-proofman, zisk, zisk-ethproofs and sppark. airbender-v3 is under `src/airbender-v3`.

### 3.1 Patterns that cut bytes
| pattern | evidence | applies to us as |
|---|---|---|
| **Compact per-cycle trace → GPU witness kernels** | **airbender** per-family records. `NonMemoryOpcodeTracingDataWithTimestamp` = 6×u32 + u16 + 4×`TimestampData` (6 B, `cs/src/definitions/mod.rs:100-104`) ≈ **52 B/cycle** [D] (`riscv_transpiler/src/machine_mode_only_unrolled/mod.rs`). Kernels: `GenerateWitnessUnrolled{Memory,NonMemory,Unified}Kernel` (`gpu_prover/src/witness/witness_unrolled.rs:16,75,146`). **ZisK** `CountAndPlan` takes a 16 B `MemOp` stream and builds memory rows on the device (`state-machines/mem-cpp/cu/count_and_plan.cu`, upload at l.1785; `state-machines/mem/src/mem_device_rows.rs`). **pil2** `common/src/gpu_witness.rs`: "the kernel writes the commit slot directly and no trace is uploaded". **SP1** `sp1-gpu-tracegen` uploads events, then a decompress kernel builds the trace (`riscv/global.rs`). **RISC Zero** `risc0_circuit_rv32im_cuda_witgen(…RawPreflightTrace…)`. | Our default path already does this at ≈70 B/step [D]. L3 keeps it that way in M8. airbender's ≈52 B/step is the reference: 1.40 GB for 26.89 M steps, 0.057 s [D]. |
| **Fixed/setup polynomials and trees resident across proofs** | **pil2** `load_device_const_pols` / `load_device_setups` (`proofman/src/utils.rs:950,1100`; `proofman.rs:6512,6551`), with a slot cache and pins (`configure_const_slot_cache_c`, `pin_const_slot_c`). Re-upload happens only after a SNARK reuses the memory (`restore_after_snark`, `proofman.rs:~900`). | L1 (recursion statics) and L2 (geometry). Our class set is small, so this fits. |
| **Bit-packed or indexed witness against a device-resident table** | **pil2** `PackedInfo` (`common/src/packed_info.rs`). The indexed mode (`pil2-stark/src/goldilocks/src/stream_commit.cuh` `StreamCommitDims.indexBits/wordsPerEntry/numEntries`) replaces per-row columns with indices into a device instruction table. Its streaming commit unpacks, LDEs and hashes column chunks without materializing the full LDE. | L3: program-constant fields (pc, decoded instruction) become indices into the program table already in `ClassCache` [E 2–4× on chunk bytes]. It also validates L1's "decode on device". |
| **Recompute instead of upload** | **airbender** `MemoryPolicy`/`CosetsCacheMode` (`prover/memory_policy.rs`); twiddles are device-resident for the context lifetime (`V3/gpu/prover_context/src/context.rs:49`). | L2: generate twiddles and denominators on the device. |

### 3.2 Patterns that only hide copies
| pattern | evidence | note |
|---|---|---|
| Pinned pools allocated once and kept across jobs | airbender `ExecutionProverHostState::new` (`gpu_prover/src/execution/prover.rs:321-405`, "tens of gigabytes"); simulator RAM is `cudaHostRegister`'d (`V3/.../simulation_runner.rs:32-50`); the service keeps state across jobs (`zksync_os_prover_service/src/lib.rs:148-153`). pil2 `register_host_buffer` with `MADV_DONTFORK`, because a fork() of a 56 GB pinned pool cost about 20 s (`common/src/memory_handler.rs:120-150`). | We already pin through a ring (§1.3). Registering *sources* removes the 28 GB CPU bounce (L6). It is a CPU win, not a link win. |
| **Counter-evidence on pinning** | ZisK: "Pinned pages disabled: no measured benefit and not supported on all devices" (`emulator-asm/asm-runner/src/asm_mo_runner.rs:173-176`). | Consistent with our link-bound measurement. |
| Dedicated h2d stream with events | airbender `ProverContext` has `exec`/`aux`/`h2d` streams (`gpu_prover/src/prover/context.rs:87-89,145-147`), and `Transfer::schedule_multiple` (`prover/transfer.rs`) fences with `allocated`/`transferred` events. **Caveat** in the v3 contract (`V3/gpu/docs/gpu_scheduling_contract.md` ll.13-153): "Default to exec_stream for copies. Use h2d_stream only when meaningful H2D overlap justifies the fork/join". | L4: worth it only for the residual's large chunks, not for small metadata. |
| Chunked prefetch with one chunk in flight | pil2 `HOST_UPLOAD_CHUNK_BYTES = 32 MiB`: "a stream with a copy always pending holds the copy engine and starves other streams' copies" (`goldilocks_tooling.cuh:812-830`); per-GPU `PrefetchZone`. sppark flip-flop streams (`util/gpu_t.cuh:173-198`, `msm/pippenger.cuh:455-515`). | Our 16 MiB ring is the same shape. L4 has to respect copy-engine starvation between the two exec streams. |
| CUDA graphs | pil2 `pil2-stark/src/utils/cuda_graph_cache.cuh` captures compute after 100 sightings (about 7 ms to instantiate on a 5090) and **poisons** regions that read per-proof staged data (ll.43-45). | Graphs do not help copies. M8 graphs stay compute-only. |
| GDS / RDMA / peer | `grep cudaGraph\|cuFile\|GPUDirect\|cudaMemcpyPeer\|NCCL` over the airbender trees finds nothing. pil2 uses peer access only to merge multiplicities (`multiplicity.cuh:210-229`). | Nobody uses GDS or RDMA. Our pod has no P2P either: peer exchange stages through the host at 26.8–27.3 µs per hop [M d-wire README], under 16 KB per request [E M8 §3.6]. |

### 3.3 One notable frontier choice that we should *not* copy
airbender re-uploads setup columns and partial Merkle caches from pinned host memory **for every circuit proof**:
- `SetupPrecomputations::schedule_transfer` (`execution/gpu_worker.rs:131-152`);
- v3 `gkr/src/setup/mod.rs:69-98,444-516`.

They do this because they prove many circuit instances in limited VRAM. We have a small class set and 32 GB per GPU, so pil2's resident const-pols is the right model for us.

---

## 4. Our data path today and after M8

### 4.1 Today (M7 default / combined-residency path)
1. **Capture (CPU).**
   - A fast pass at about 170 MIPS, then segment replay on 8 workers, then the serial ledger, then narrow scan, routing and grouping (`word16_execution/prepared.zig`).
   - 24628607: fast pass 0.49–0.50 s; recording at 14–15 MIPS; capture 1.79–1.90 s; exposed capture 2.1 s [M census1].
   - 26235159: capture 4.76 s with T1+T10 [M T10]. Worker profile summed: scan 10.94 s, routing 3.51 s, ALU hash grouping 7.51 s; ledger about 50 ms per segment, serial [M T10].
2. **Compact transport, already in place.**
   - CPU rows are sent as `CompactRecord{result u64, rom_row u32, next_pc u32}` = 16 B/row, plus a 384 B `CompactSeed` every 256 rows, for ≈17.5 B/row (`cpu_witness.zig:9-13`). Measured: `GPU_CPU_PROJECTION metadata_h2d_bytes = 73,400,304` for a 2^22-row segment = 17.5 B/row, with `main_d2h_bytes = 0` [M].
   - Family `Fact` = 32 B per deduplicated fact (`family_input.zig:8`); load/store `Event` = 64 B; public RAM `Cell` = 32 B (`memory_input.zig:5,18`). The header comment says "never padded field-column witnesses".
   - Registers and clocks are rebuilt on the device (`stwo_rv64_cpu_unpack_on`, `stwo_rv64_cpu_witness_on`). MAIN stays resident through replay (`GPU_CPU_REPLAY_RETAIN main_resident=true` [M]).
3. **Setup and geometry.** Unpacked on the host per node or per call, then uploaded every request through the staged ring (§1.4 rows 1–5, 7–9).
4. **All copies run on the exec stream** followed by `ctx.join()`, with 0% overlap (§1.3).
5. **D2H.** 33 PCS readbacks, 2,049 sync waits [M].

### 4.2 After M8 (design, `codex/rv64-m8-gpu`)
| byte stream | M8 treatment | residual after M8 [E] |
|---|---|---|
| native witness / MAIN | H4: device witness from `TraceChunk`s into `main_resident`; H5/H12: no `copyColumns`, no replay | **depends on the `TraceChunk` format (L3)**: ≈2.3 GB compact, or ≈7.4 GB if v1 MAIN images ship |
| native FIXED | n-stage1 adopts the class tree from a region filled once at warm ("no host SHA, no FIXED upload") | ≈0 |
| fold-class tasks + FIXED | `jobs/outer_staged.zig:6-12`: uploaded once per class into worker-persistent memory; FIXED coefficients produced on the device | ≈0 for folds |
| **leaf-class tasks + FIXED** | "a leaf is its own class", so they stay in the per-node region. `outer_class_plan.zig` (`STWO_RV64_M8_OUTER_CLASS_PLAN`, default 0) caches leaf statics by authority **on the host only** | **most of rows 1–2 that belong to leaves**. The split between leaf and fold bytes is unmeasured (open question Q1). |
| geometry (twiddles, composition, PCS metadata) | M8 §1 says "built once per class… device-resident" in spirit, but §3.7 sizes `class_cache` at only 2.5–3.1 GB, and nothing names twiddles per log | ≈0–9.4 GB, depending on how much the class cache really holds (Q2) |
| copy stream | M8 §6.2 says "upload on the h2d stream", but the d-wire implementation enqueues chunk H2D on the **exec** stream (`native_device_stage1.zig:658`) | still serialized |
| D2H | one slab D2H per GPU, 1 host wait [M d-wire D3] | ~1–2 ms [E] |
| streaming capture | d-wire `Feed` + `Stream` with per-segment seal; the pinned `cudaHostAlloc` ring (`m8_capture_stream.zig`) is written in place, with no bounce. The ring default is 32 × 4 MiB = 128 MiB, sized for one 2^20-row segment (`driver_serve.zig` on d-wire) → ≤128 B/row [D]. | this is the M8 win of −1.6 to −1.9 s exposed capture [E M8 §5] |

**The M8 risk (act now).**
- The draft `TraceChunk` v1 (`gpu_native.zig:679`; d-wire `native_device_stage1.zig:293`) carries MAIN evaluation runs, and the device only scatters them (`stwo_rv64_n1_scatter_v1`).
- That puts column materialization (MAIN 4.15 + 3.23 = 7.38 GB on 24628607 [M M8 §3.7]) back on the CPU capture thread. It also ships about 3× the compact bytes: 7.38 vs ≈2.3 GB [D].
- `NativeFactory.pack` is not written yet (d-wire README "Not done"), so changing the contract now costs nothing.

---

## 5. Ranked levers

Columns:
- bytes per warm request;
- link-s per GPU, where per-GPU ≈ total / 2 / 24.6 GB/s [D], with the measured split being dev0 53% / dev1 47%;
- wall seconds on 24628607, after M8;
- wall seconds on 26235159 [E, H2D unmeasured].

None of these levers changes proof bytes: they move the same values by a different route. Each must pass the frozen D2 golden (32/32, 39/39 artifacts) and the channel parity harness (M8 §4).

| rank | flag | lever | bytes saved (24628607) | 24628607 wall (post-M8) | 26235159 wall | effort | risk | byte identity | M8 dependency |
|---:|---|---|---:|---:|---:|---|---|---|---|
| 0 | *(M8 contract, no flag)* | **Compact `TraceChunk` v2** (`CompactRecord` + seeds + `Fact`/`Event`), reusing the existing `cpu_unpack`/`cpu_witness`/`*_witness` kernels | avoids +5.1 GB [D: 7.38 − 2.3] | avoids +0.10 s/GPU link [D: 5.1 / 2 / 24.6] **and** avoids CPU MAIN materialization on the capture path [E: larger than the link term] | avoids ≈+35 GB, ≈+0.7 s/GPU [E: 49 × (1.05 − 0.33) GB] | S: a contract change before the packer exists | low | none (same MAIN) | **must land inside M8** (n-stage1 / d-wire `pack`) |
| 1 | `STWO_RV64_M9_CLASS_PACKED_RESIDENT` | Keep recursion class statics (PP/FIXED forest + assignment tasks) resident **packed** in `class_cache` (0.455 GB total ≈ 0.23 GB/GPU [D]); decode on the device per node into the arena; key leaf classes by authority (move `outer_class_plan` onto the device); take the 2 GiB immutable cache off the request path | **−15.8 GB** [D], minus whatever M8's fold region already removes (Q1) | −0.32 s/GPU link [D: 15.8 / 2 / 24.6]; −3.70 CPU-s host unpack [M]; −15.8 GB host memcpy [D] | **−2 to −4 s/GPU** [E: most of ~100–200 GB of leaf statics repeat across 49 segments] | M: a GPU decoder for delta-varint/LZ4 over independent 16,384-word blocks (`circuit_cpu/om31/cache_pack.zig`); class keys | medium: decode cost ≈1–10 ms per node [E: 0.85 GB written per node at 0.1–1 TB/s], needs a decode-parity test | none | needs M8 `ClassCache` + `MemoryPlan` (+0.23 GB/GPU in `class_cache`) |
| 2 | `STWO_RV64_M9_GEOMETRY_RESIDENT` | Twiddles/itwiddles/logs made resident per (log, device) or generated on the device; composition denominators/masks/powers and PCS descriptors made resident per class | **−9.4 GB** [D: 3.08 + 3.41 + 1.86 + 1.07] | −0.19 s/GPU [D: 9.4 / 2 / 24.6] | −1 to −2 s/GPU [E] | M: per-(log) cache in `class_cache`; twiddle and denominator kernels exist in part (b2n/n2b) | low: memory ≈ a few hundred MB/GPU [E: 2^26 B per twiddle set × a handful of logs] | none | M8 `ClassCache` |
| 3 | `STWO_RV64_M9_H2D_STREAM` | Residual H2D (chunks, seeds, misses) goes on a dedicated copy stream fed from the pinned ring, with `cudaStreamWaitEvent` into exec; one 16–32 MiB chunk in flight (pil2 rule); chunks upload *during* capture | 0 (hides) | after L0–L2: hides the ≈3 GB residual, −0.06 s/GPU [D: 3.2 / 2 / 24.6]; **without L1–L2 it hides up to 0.54–0.61 s/GPU** [M], as long as kernels are available to overlap | hides most of the residual [E] | S: move `native_device_stage1.zig:658` and the staged path off exec | low: copy-engine starvation between streams | none | M8 streams (§6) |
| 4 | *(M8; nothing new)* | Streaming capture → GPU overlap, per sealed segment (d-wire `Feed`) | 0 | **−1.6 to −1.9 s** exposed capture [E M8 §5]. This is an M8 saving and must not be counted again in M9. | ≈−3.5 s [E] | — | — | none | it *is* M8 |
| 5 | `STWO_RV64_M9_D2D_INPLACE` | In-place coset/column layouts in trace commit; write INTER and the final coefficients in place (22.0 GB is explicit `final_coefficient_copy_words` [M Σ `GPU_TRACE_OWNERSHIP`]) | D2D, not H2D: ≤167 GB | ≤0.11 s/GPU [D: 0.214 / 2]; the M8 MAIN-resident path takes part of it | ≤0.75 s/GPU [E: ~7×] | M | medium (layout) | none | after M8 H5/H12 |
| 6 | `STWO_RV64_M9_HOST_REGISTER` | `cudaHostRegister` the capture source and class store so the 8-thread memcpy bounce and the 64 MiB run-ahead limit go away | 0 link bytes; −28.4 GB → ≈−3 GB of host memcpy [D, after L1–L2] | CPU relief only [E small]; ZisK found no benefit (`asm_mo_runner.rs:173-176`) | CPU relief | S | low (fork with large pinned regions: use `MADV_DONTFORK`) | none | independent |
| 7 | *(done)* | Proof-only readback | already 62 MB / 3 ms [M] | ≈0 more; the sync cost goes with M8 H13/H23 | ≤25 ms [E] | — | — | — | M8 slab |
| 8 | `STWO_RV64_M9_CHUNK_INDEXED` | pil2-style indexed chunk: pc/decoded instruction become an index into the device program table; only dynamic values ship | −0.5 to −1.4 GB [E: 2–4× on ≈1.9–2.3 GB] | −0.01 to −0.03 s/GPU [D] | −0.2 to −0.5 s/GPU [E] | M | low | none | after L0 |
| 9 | `STWO_RV64_M9_GPU_REPLAY` (+ `_GPU_GROUP`, `_AOT_RECORD`) | Capture on the GPU / faster capture (see the verdict below) | −14 GB of compact ingress on 26235159 if the GPU replays from a minimal trace of ≈0.5–1.6 GB [E] | −0.3 to −0.6 s [E] of what remains exposed after streaming | ≈−1 s [E] of the ≈1.3 s exposed first-segment latency; frees ≈92 CPU-user-s [M T10] | L (M10-scale) | high | none for the proof; needs `T10DIGEST` and `advice_all_sha256` parity of `Prepared` | after M8 + L0 |
| — | *(hardware)* | x16 PCIe host | link ≈2× [E] | halves the residual [E]; it barely matters after L1–L2 | helps until L1 lands | pod placement | — | none | independent |

**Total for 24628607 after M8, using L0–L3 [D/E]:**
- H2D 28.4 → ≈3 GB, link time 0.58 → ≈0.07 s/GPU, and that remainder mostly hidden by L3.
- That recovers ≈0.5 s/GPU of a ≈6–7 s request (≈7–9%) [E].
- It also frees ≈3.7 CPU-s of unpack plus ≈25 GB of host memcpy [D/M].

**For 26235159** the same levers are worth ≈3–6 s/GPU [E]. The precondition is measuring it (E1).

### 5.9 GPU guest execution: feasibility verdict
- **Interpreting a single RV64 hart on the GPU: no.**
  - Execution is serial and branchy, and our fast pass already runs at ≈170 MIPS on the CPU [M census1].
  - zkDTVM, the reference for "GPU-native", also executes on the CPU (AOT x86) [C].
- **Parallel replay from checkpoints on the GPU: feasible, M10-scale.** The structure already exists:
  - the fast pass produces segment boundaries;
  - the compact transport already carries a register/clock seed every 256 rows.
- **Shape of the GPU version:**
  1. The CPU (or an AOT translator, as ZisK does) runs the fast pass and emits a minimal trace: chunk-start register snapshots plus load values.
  2. The minimal trace is uploaded: ≈0.5–1.6 GB on 26235159 [E].
  3. The GPU replays thousands of chunks in parallel and emits `CompactRecord`/`Fact`/`Event`.
  4. ALU/BINARY/SHIFT dedup runs as GPU sort + reduce-by-key, replacing 7.51 s of hash grouping [M T10].
  5. The memory ledger runs as a GPU sort by (address, tick), replacing the serial ≈50 ms per segment.
- **First step:** GPU grouping + ledger (`_GPU_GROUP`), then replay.
- **CPU-side alternative, same value class:** AOT/JIT-compile the GE guest for the *recording* pass (`_AOT_RECORD`). Recording runs at 14–15 MIPS for 24628607 [M census1], and the narrow-capture worker at 5–9 MIPS against a 170 MIPS fast pass [M census2 T10].
- **Verdict.** On 24628607 the gain after M8 streaming is small (≤0.6 s [E]). On the large blocks, and on CPU contention, it is real. It belongs to the >60% plan, not to the IO pass.

---

## 6. Fit with the post-M8 sequence

The agreed order is: M8 lands → benchmarks → **cleanup/productionisation pass** with a repeatable benchmark set → **M9 >60% cut** plan.

| phase | IO items | why there |
|---|---|---|
| **Inside M8 (now)** | **L0** compact `TraceChunk` v2. Move the chunk H2D off the exec stream (`native_device_stage1.zig:658`), which M8 §6.2 already asks for. | A contract decision before the packer exists; it costs nothing now and is expensive later. |
| **Cleanup pass** | **Instrumentation as a permanent benchmark field**, so later work is measurable: H2D/D2H/D2D by NVTX range; exposed copy-s per device; `TraceChunk` B/step; warm H2D − cold H2D; `GPU_RESIDENT_SETUP` evictions. Retire the 2 GiB immutable cache from the request path, or make a request-path miss fail closed, as `ClassCache` does. Fix the census tool's srcKind enum reading. Make the H2D receipt a gate. | It is hygiene, low risk, and makes the regression harness IO-aware. It also catches L0 regressions. |
| **M9 >60% plan** | **L1** packed class residency, **L2** geometry residency, **L3** h2d stream, **L5** D2D in place, then **L8/L9** (indexed chunks, GPU grouping/replay, AOT record). Hardware x16 is noted, not planned. | L1 and L2 are the largest wins on the 15-block basket because the big blocks have the most leaves. L9 is M10-scale and is also a capture-CPU lever for the >60% target. |

The >60% target cannot be met by IO alone. Large blocks are GPU-seconds bound (26235159 ≈42 GPU-s [E, bench15]). IO on 26235159, however, is plausibly 8–11 link-s summed over both GPUs [E, §1.4], which is the same order as the kernel savings being chased. So L1 belongs in the first M9 wave.

---

## 7. Experiments once M8 lands

Every experiment respects the house rules:
- run on AC power;
- take `gpu.lock` through the harness;
- use memguard (`~/Coding/ge-ops/bin/memguard`);
- record cold + warm in the same service;
- use the canonical runner (`scripts/rv64_m8_bench15.py` for timing, `scripts/rv64_m8_census.py` for analysis);
- run nsys with `-t cuda,nvtx,osrt`, plus the `nsys stats` reports `cuda_gpu_mem_size_sum`, `cuda_gpu_mem_time_sum`, `cuda_gpu_kern_sum` and `nvtx_gpu_proj_sum`.

| id | measure | how | acceptance |
|---|---|---|---|
| E1 | **Post-M8 IO baseline** on 24628607, 26235156 and **26235159** | One cold + warm service per block under nsys. Record: `cuda_gpu_mem_size_sum` per direction; H2D by NVTX range and by consumer kernel (census tool, srcKind fixed); exposed copy-s per device = \|∪copy − ∪kernel\|; `GPU_STAGING_SUMMARY staged_h2d_bytes` delta per request; `TraceChunk` bytes / guest steps. Add per-upload NVTX labels (`h2d/<site>`) so attribution is exact, not fingerprinted. | The receipt exists with every number [M]. Confirm or refute the §1.4 attribution within ±10% per row. Establish 26235159's H2D (replacing the [E]). |
| E2 | L0 compact chunk | `TraceChunk` B/step and capture thread CPU time, v1 vs v2, on 24628607 | ≤ ~80 B/step [airbender ≈52 B, today ≈70 B]; capture exposed no worse than M8 §5; 39/39 golden |
| E3 | L1 `STWO_RV64_M9_CLASS_PACKED_RESIDENT=1` | E1 protocol; device decode time per node (nsys kernel sum for the decoder); `class_cache` bytes | Warm H2D drops ≥14 GB on 24628607. Warm H2D < cold H2D. Decoder ≤10 ms/node. Host unpack ns → 0 on warm. 0 `GPU_RESIDENT_SETUP` evictions warm. 39/39 + 32/32 golden. |
| E4 | L2 `STWO_RV64_M9_GEOMETRY_RESIDENT=1` | E1 protocol | Warm H2D ≤ ~3.5 GB on 24628607 together with L1. TC/composition/PCS-metadata ranges ≤ 5% of today. Golden. |
| E5 | L3 `STWO_RV64_M9_H2D_STREAM=1` | Exposed copy-s per device (E1 query) | Exposed H2D ≤ 20% of H2D copy-s. No kernel slowdown > 2% (`cuda_gpu_kern_sum` total). |
| E6 | End-to-end | `rv64_m8_bench15.py` on the 15-block basket, flags on vs off, quiet gate | Report Δ job and Δ proving per block [M]. Expected ≥0.4 s on 24628607 [E] and ≥3 s on 26235159 [E]. Accept if no block regresses by more than noise. |
| E7 | L5 D2D in place | E1 D2D bytes and copy-s | D2D copy-s per device ≤ 50% of the post-M8 baseline |

---

## 8. Open questions and sources

### Open questions
- **Q1.** Of the 15.8 GB of recursion statics, how much belongs to *leaf* classes and how much to fold/root classes? M8's fold region removes only the latter. Answered by E1 with per-upload NVTX labels.
- **Q2.** Does M8's `class_cache` (2.5–3.1 GB [M]) already hold twiddles and composition/PCS geometry per class? Or do rows 3–5 survive M8 unchanged? Answered by E1.
- **Q3.** What is the GPU throughput of a delta-varint/LZ4 decoder over 16,384-word blocks? It decides whether L1 decodes per node or keeps hot fold classes resident unpacked. Unpacked residency (≈16 GB) does not fit next to a 21.8 GB fold peak [M M8 §3.7].
- **Q4.** H2D on 26235159: the census2 attempt exited 1. All of its IO numbers here are [E].
- **Q5.** After L1–L3, is copy-engine contention between the two exec streams per GPU measurable (pil2's one-chunk-in-flight rule)?
- **Q6.** Can the pod be placed on an x16 host? It matters only until L1 and L2 land.
- **Q7.** zkDTVM internals: the prover is closed. A kernel-level comparison with NitrooZK-stwo (same lab, Stwo CUDA) is possible and is a separate kernel question.

### Sources
**Local / pod:**
- `origin/codex/rv64-m8-census2:vectors/reports/rv64-m8-20261106/census1/{README.md,capture-cpu.json,m7p1-24628607-warm.json}`
- `origin/codex/rv64-m8-census2:vectors/reports/rv64-m8-20261106/census2/{README.md,h2d-api-and-pcie.txt,m7p1-24628607-warm-deep.json,m7p1-24628607-warm-d2d.json,deep_queries.py}`
- `origin/codex/rv64-m8-gpu:design/riscv-proving-stack/rv64-m8-gpu-native.md` (§1, §2, §3.1–3.8, §5, §6.2)
- `origin/codex/rv64-m8-gpu:src/integrations/riscv_cuda/rv64/jobs/gpu_native.zig:679-696` (`TraceChunk`)
- `origin/codex/rv64-m8-gpu-d-wire`: `jobs/native_device_stage1.zig:293,658`, `jobs/driver_serve.zig` (ring defaults), `jobs/driver_ge.zig`, `vectors/reports/rv64-m8-20261106/gpu-d-wire/README.md`
- This branch:
  - `src/backends/cuda/native/runtime/device_arena_runtime.cuh:72,972-1185`
  - `src/integrations/riscv_cuda/rv64/{outer_wrap.zig:277, outer_assignment.zig:794,896-905, outer_source.zig:351, trace_commit.zig:367-369,578-580, resident_composition.zig:726-799, pcs_native.zig:196, cpu_witness.zig:9-13, cpu_projection.zig, core_witness.zig}`
  - `src/integrations/riscv_cpu/word16_execution/{cpu_source.zig:29,51, family_input.zig:8, memory_input.zig:5,18, prepared.zig}`
  - `src/integrations/circuit_cpu/om31/cache_pack.zig`
  - `jobs/outer_staged.zig:6-12`, `jobs/outer_class_plan.zig`, `m8_capture_stream.zig`
- Pod:
  - `/workspace/m3/runs/m8-census2/summary/*`
  - `/workspace/m3/runs/m7-integrate/daemon-24628607-r2-p1-inter-{reuse-profile-retry-20261106-02-06,contributions-profile-20261106-01-06}-baseline/{producer.stderr,nsys/timeline.sqlite}`
  - `/workspace/m3/inputs/24628607.bin` (2.70 MB)

**Frontier (code):**
- zksync-airbender:
  - `gpu_prover/src/{execution/prover.rs, execution/gpu_worker.rs, prover/context.rs, prover/transfer.rs, prover/memory_policy.rs, witness/witness_unrolled.rs}`
  - `riscv_transpiler/src/machine_mode_only_unrolled/mod.rs`
  - `cs/src/definitions/mod.rs`
- airbender-v3: `gpu/{docs/gpu_scheduling_contract.md, execution_prover/src/workers/simulation_runner.rs, prover_context/src/context.rs, gkr/src/setup/mod.rs}`
- zksync-airbender-prover: `crates/zksync_os_prover_service/src/lib.rs`
- zisk:
  - `emulator-asm/asm-runner/src/{asm_mt.rs, asm_mo_runner.rs}`
  - `state-machines/mem-cpp/cu/count_and_plan.{cu,cuh}`
  - `state-machines/mem/src/mem_device_rows.rs`
  - `gpu-witness/src/lib.rs`
- pil2-proofman:
  - `common/src/{gpu_witness.rs, packed_info.rs, memory_handler.rs}`
  - `proofman/src/{utils.rs, proofman.rs}`
  - `pil2-stark/src/{goldilocks/src/stream_commit.cuh, utils/cuda_graph_cache.cuh, starkpil/multiplicity.cuh}`
  - `goldilocks_tooling.cuh`
  - `starks_api.cu`
- sppark: `util/gpu_t.cuh`, `msm/pippenger.cuh`

**Web:**
- zkDTVM article: https://openlabs-intl.antdigital.com/0x/Introducing-zkDTVM-A-GPU-Native-zkVM-Built-for-End-to-End-Acceleration
- AntChainOpenLabs repos:
  - https://github.com/AntChainOpenLabs/zkdtvm-docker
  - https://github.com/AntChainOpenLabs/zkdtvm-stark-verifier
  - https://github.com/AntChainOpenLabs/zkdtvm-wasm-stark-verifier
  - https://github.com/AntChainOpenLabs/NitrooZK-stwo
- EthProofs: https://ethproofs.org/teams/antchain-openlabs, https://ethproofs.org/clusters
- Press and social:
  - https://x.com/AntChainOpenLab/status/2061323404909883583
  - https://phemex.com/news/article/antchains-zkdtvm-breaks-global-record-in-ethereum-ethproofs-benchmark-77478
- SP1 tracegen:
  - https://docs.rs/sp1-gpu-tracegen/6.1.0/src/sp1_gpu_tracegen/lib.rs.html
  - https://docs.rs/crate/sp1-gpu-tracegen/6.9.0/source/src/riscv/global.rs
- RISC Zero: https://docs.rs/risc0-circuit-rv32im-sys/latest/src/risc0_circuit_rv32im_sys/lib.rs.html

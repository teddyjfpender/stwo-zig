# RV64 GPU prover: the 10× plan (M4–M8)

*Lead-architect plan, 2026-11-04. Baseline: `codex/rv64-cuda-ethereum` @ `e61851f9e` (M3 integrate, all 15 basket blocks accepted on 2× RTX 5090), plus the unmerged `codex/rv64-m3-recsize` @ `5d68d0f01`. Hardware: 2× RTX 5090 (32 GB, about 1.8 TB/s each), 48 vCPU, 377 GB RAM.*

Labels used throughout: **[M]** measured (a receipt exists), **[D]** arithmetic on measured numbers, **[E]** estimate. Every target here is an [E] until a receipt replaces it.

This plan grafts Design A, which keeps Blake2s and 128-bit labels, onto the surviving parts of Design B. It also takes on every valid point from the adversarial review.
- **Rejected:** the LtHash-style χ accumulator, and stacked native PCS as Design B specified it.
- **Deferred:** Poseidon2-M31 in the outer layers.
- **Corrected:** the recursion cell factor, the compress layer (now two stages), the request critical path (full capture is on it) and the definition of the RAM metric.

---

## 1. Executive summary

We are 15–75× behind the frontier in GPU-seconds per block:
- Airbender v3 on 2× 5090: about 6.6 GPU·s.
- ZisK on 2× 5090: about 12.8 GPU·s.
- Us on 24628607: 102 GPU·s.

The guests differ, so this is only a rough calibration. Even so, the owner's 10× goal is something others have already reached on the same hardware class.

Our own data says the gap is mostly architectural, not protocol-level:
- **GPUs are idle 75–81% of the time.** Recursion is busy 25% on GPU0 and 19% on GPU1; the native stage is 17.3 s of wall time against 1.5–2.5 s of kernels [M].
- **Every recursion node is a bespoke circuit.** It is rebuilt on the host and interpreted level by level: 120,240 levels for one CPU leaf, 1.96 M launches per request [M].
- **The receiver re-derives and re-verifies the whole tree.** Root verify alone is 0.58 s; the verifier column is 77 s [M].
- **About 23 GiB of host RSS is a constant overhead.** It does not scale with the block [M].

The plan has five architectural leaps:

| leap | milestone | what changes |
|---|---|---|
| L1 | M4 | measure honestly, then make the prover a **resident service**: static arenas, lazy fatbins, a persisted artifact store; no protocol change |
| L2 | M5 | **canonical topologies and a constant recursion VK**; the receiver verifies the root only |
| L3 | M6 | a **GPU-resident, enqueue-only, streaming pipeline**: hint-tape witness, device transcript, CUDA graphs, GPU witness widening, opportunistic k-ary scheduler |
| L4 | M7 | **cell diet and compression**: k-ary folds, outer LogUp-GKR, fused Blake2s gadget, bigger canonical rungs, batched services, two-stage compress |
| L5 | M8 | ordered **scale-up**, one block at a time |

### Targets per column

The "10× target" column shows the targets for blocks 24628607 and 26235159 (607 / 159). "Realistic on 2×5090" is the honest band I expect at the end of M7 or M8.

| column | now 24628607 | now 26235159 | 10× target (607 / 159) | realistic on 2×5090 (607 / 159) | confidence |
|---|---:|---:|---:|---:|---|
| request (s) | 51.1 [M] | 250.5 [M] | 5.1 / 25 | **6–9 / 15–22** | 159: **medium-high**. 607: **medium for ≤8 s, low for ≤5.1 s**. 607 is latency-bound across about 17 proofs; reaching 5 s on 2 GPUs needs every lever. 4 GPUs reach it more comfortably. |
| capture (s, full; it sits on the critical path) | 3.28 [M] | 16.5 [M] | 0.33 / 1.65 | 0.4–0.6 / 1.5–2.5 | **medium**. The last 2× needs the block-import rewrite (2.78 s [M], the largest single item) and a fast emulator. |
| setup (s, cold service with the artifact store on disk) | 12.6 [M] | 93.0 [M] | 1.26 / 9.3 | **≤0.5 / ≤0.5** | **high**. The one-time install or first-image build (10–30 s [E]) is reported separately and is never hidden. |
| native prove (s) | 7.83 [M] | 43.7 [M] | 0.78 / 4.4 | 1.0–1.5 / 4–6 | 159: **medium**. 607: **low-medium**; per-proof latency plus the canonical padding tax. |
| recursion (s, stage wall in today's schema) | 27.3 [M] | 96.4 [M] | 2.7 / 9.6 | 2.5–4 / 8–12 | **medium**. The two-stage compress tail of about 1–1.5 s eats most of the 607 budget. |
| verifier (s, per block; VK tables derived once) | 77.3 [M] | 439 [M] | 7.7 / 44 | **≤1 / ≤1** | **high** (≥75× / ≥400×). The one-time `derive-vk-tables` cost (10–30 s [E]) is reported separately. |
| peak RAM, request-attributable private RSS (GiB) | 25.0 [M]* | 34.6 [M]* | 2.5 / 3.5 | 3–5 / 4–6 | **medium-low until the M4.0 census attributes the 22.9 GiB intercept**. |
| peak RAM, whole-daemon RSS (GiB) | (same) | (same) | — | ≤10 / ≤12 | Shown so that no one games the metric. Pinned pools and mmapped artifacts count here. |
| device peak per GPU (GB) | 33.65 [M] | — | — | ≤24 | **medium**. This is a prerequisite for concurrent nodes. |
| proof size (KB, final proof) | 708 [M] | 750 [M] | 71 / 75 | **≤100 (7×); ≤75 (10×) as a stretch** | ≤100 KB: **medium-high**. ≤75 KB: **medium-low**, needing FRI fold 8/16, caps, dedup and arity-4 Merkle in the last layer. |

\* Today's RSS includes everything, because the process is not a daemon. M4 introduces the split metric.

**Soundness stays at today's level or better.** Every profile is conjectured-128 under q·log₂(blowup) + pow. Native keeps `conjectured128_b2_q108_p20_fold4` unless decision D2 (§5, M7) changes it under a new named profile. No layer drops below the 128 label. Receiver independence is preserved: the receiver rebuilds every VK table from a pinned source commit and never reads producer caches.

**What does not reach 10× on 2× 5090:** native and request on the small headline block 24628607. We expect about 6–9× there. Closing the rest needs one of these:
- more GPUs;
- a guest diet (3.13 instructions per gas today; Keccak and u256 delegation);
- the long-term multilinear option (§3.5).

All three are tracked. None of them is assumed in the targets.

---

## 2. What our data says

### 2.1 Where the time goes on 24628607 (51.1 s request)

| stage | wall time | what dominates it [M] |
|---|---:|---|
| capture | 3.3 s | block import 2.78 s (overlapped); serial ordered ledger 1.28 s; image load 0.66 s; init 0.95 s. RV64 execution itself is 0.58 s, and 8 vs 16 workers makes no difference (3.35 vs 3.33 s). |
| setup | 12.6 s | native keys 7.51 s and FIXED authority 4.77 s. 67 geometry classes on 26235159. Warm SetupCache measured 0.77 s, or 0.16 s in-process. |
| native prove | 7.8 s (the stage window is 17.3 s with verify) | kernels 1.5 s on GPU0 and 2.5 s on GPU1. `CORE_SINGLE_STREAM=1`. MAIN is replayed from the host after the global barrier. |
| recursion | 27.3 s | 33 nodes. A leaf spans 4.30 s with 0.95 s of GPU work; a fold spans 2.85 s with 0.82 s. The fold tail is 12.7 s over 5 serial levels. |
| verifier | 77.3 s | setup 12.8 s, leaf graphs 6.0 s, leaf wraps 19.9 s, folds 21.0 s, native verify 1.56 s. **Root verify is 0.58 s.** |

**Host phases inside recursion, summed over nodes [M]:**
- assignment plan 18.3 s (tasks 7.3, pack 4.7, dependency walk 4.3);
- preprocess 15.9 s;
- leaf graphs 19.5 s;
- PCS 16.2 s, of which 8.7 s is on the device;
- assignment enqueue 8.8 s, covering 1.93 M launches at about 1.9 µs each.

**CUDA host API [M]:**

| call | count | time |
|---|---:|---:|
| `cudaStreamSynchronize` | 32,790 | 17.5 s |
| `cudaMallocFromPoolAsync` | 8,816 | 4.0 s |
| blocking pageable `cudaMemcpyAsync` | 15,326 | 5.6 s |
| `cuLibraryLoadData` at start | 686 | 3.0 s (+1.0 s unload) |

The host averages about 2.45 busy cores out of 48.

### 2.2 Scaling fits over 15 blocks [D]

Least-squares fits on Mi, millions of executed instructions.

| column | fit | r² | scales with |
|---|---|---:|---|
| request | 19.4 + 1.090·Mi | .990 | everything |
| setup | −0.1 + 0.424·Mi | .985 | **proof count**: data-dependent geometry classes |
| native | 2.15 + 0.204·Mi | .994 | instructions: 4.7 MHz over 2 GPUs |
| recursion | 16.0 + 0.386·Mi | .982 | **node count**: about 1.29 s per node per lane |
| verifier | 19.5 + 1.965·Mi | .992 | **re-verifies everything**, and costs 2× the prover |
| peak RSS | 22.9 + 0.058·Mi GiB | .951 | a **23 GiB constant floor** |

Three of these fits are not inherent to the protocol: setup, verifier and RAM. They are artefacts of bespoke per-node circuits and of a non-resident process.

### 2.3 Recursion work volume (census-v2 [M], 24628607)

- **A CPU leaf commits about 1,174 M main+interaction cells,** about 2.1× the 562 M of the native segment it verifies.

  | component | share of leaf cells |
  |---|---:|
  | Blake2s G gate | 74.3% |
  | all hashing (G gate + XOR tables + triple_xor + m31↔u32) | **≈85.5%** |
  | qm31 arithmetic (FRI, OODS, DEEP, composition) | 14.3% |
  | interaction (LogUp) columns | 50% of all cells (590 M) |

- **Folds are the same size class as leaves** (about 1,133 M cells): a fold re-verifies two q108 b2 outer proofs.
- **Padding:** Blake rows are padded about 29% (5.98 M real to 8.39 M) [D].
- **Depth:** the CPU0 leaf has 45.1 M vars, 19.0 M tasks and **120,240 non-empty levels**. Depth comes from the serial Blake2s channel and from linear accumulation chains.

### 2.4 The reconciliation the critique demanded (M4.0 must close it)

"29.2 GPU-s over 33 nodes" is a sum of *first-to-last kernel spans*: 17 × 0.95 + 16 × 0.82.

nsys busy fractions give a different number: 25% + 19% over the 27.3 s window is **about 12.0 GPU-s of kernels**, about 0.37 s per node [D].

What follows if the busy fractions are right:
- Recursion at 26235159 is **not** yet GPU-bound. The "65 GPU-s per GPU" extrapolation is about 2.4× too pessimistic.
- Recursion kernel efficiency is about 0.33 ns per LDE cell, not 0.8. Native is 0.19–0.22 ns.
- Host work and serialisation matter more than cell count. That is why L1–L3 come before L4.

There is a second discrepancy. "53.39 G recursive committed cells" [M, construction-cost] does not match "≈37 G main+interaction" [D, census-v2]; the difference is probably preprocessed columns and outer layers. M4.0 publishes one reconciled number.

### 2.5 Things we already know that limit the design

- **Device memory is full.** GPU0 peaks at 33.65 GB of 34.4 GB; the composition arena alone is 16.8 GB [M]. Two or three concurrent nodes per GPU, which every frontier prover relies on, is **impossible until composition memory shrinks**.
- **Keeping MAIN resident across the barrier is impossible at scale.** On 26235159 it would be 41–61 G cells × 4 B = 160–240 GB [D]. Compact execution records do fit (about 64 B per instruction, about 13 GB, split across 2 GPUs). MAIN must be *regenerated on the device*, not kept.
- **Pick at most two of** {2^24 segments, native b4, 2–3 concurrent nodes}. A 2^24 CPU segment is about 9 GB of base trace, and at b4 about 36 GB of LDE; composition needs every column at every LDE point [D].
- **Interaction bits per gas are 73k of 166k,** against ZisK's 28k [M, `committed-work-comparison-v1.json`].
- **Catalogue drift has already happened.** The `global_aot` log-23 guard failed on 24628590 [M]. Any cache must be keyed on generator and catalogue hashes.

---

## 3. What we take from the frontier

### 3.1 ZisK (Polygon): primary source, `0xPolygonHermez/zisk` @64a1f16 and `pil2-proofman` @27b2fc2, release notes v1.0–v1.4

| idea | ZisK evidence | our use |
|---|---|---|
| **Key-affinity stream scheduler.** Warm stream first, then a fresh load, then a reload; rec2 before rec1; deepest backlog first; phase A/B split of one big buffer into halves once the big proofs land. | `proofman/src/scheduler.rs`, `proofman.rs` around L3860–4020; release notes: "Recursion overlaps the basic proofs throughout" | **taken** (M6 `sched`) |
| **Opportunistic aggregation tree** with null slots; the first finished worker aggregates | whitepaper recursion section; `distributed/README.md` | **taken** (k ≤ 4, M6 and M7) |
| **One unified buffer per GPU,** carved by size class; overrun aborts; pinned host pools sized at init | `pil2-stark/src/api/starks_api.cu` | **taken** (M4 static arena) |
| **Streaming commit:** unpack → LDE → hash per column chunk, about 16 columns of working set | `goldilocks/src/stream_commit.cuh` | **taken** (M6 native) |
| **Merkle tree without the leaf level;** leaf hashes recomputed at query time | `merkle_noleaves.cuh` | **taken** where memory-bound (M7) |
| **CUDA graph cache** after N warm runs (about 7 ms per graph on a 5090); regions reading per-proof pinned data are "poisoned" | `utils/cuda_graph_cache.cuh` | **taken**, poison rule included |
| **GPU witness from an indexed compact witness** plus a per-program instruction table; GPU multiplicities. Memory witness went from 0.58 to 0.18 s per block. | `gpu-witness/src/lib.rs`; v1.4 notes | **taken** (M6) |
| **Minimal-trace emulator** with parallel chunk replay and a progressive trace store | `executor/src/executor.rs`, `emulator-asm/` | **taken** in stages (M4 shards; M7 emulator) |
| **Narrow recursion nodes:** 2^17 rows at ρ = 1/8, 73 queries, 20 bits of grinding; final ρ = 1/32 with 43 queries; a compressor in front of wide AIRs | whitepaper backend table | **taken as a principle** (compress layers, k-ary) |
| **Fixed aggregation VKs;** the verifier uses trusted release VKs | release notes | **taken**: our receiver *derives* them from source |
| **LtHash multiset challenge accumulator** | whitepaper | **rejected** for 2 GPUs (§4.6) |

### 3.2 Airbender and Airbender Prime (ZKsync): `matter-labs/zksync-airbender`, `main` @6ec4ea7, `av_gkr_compiler` @c1a6622, `v3`

| idea | evidence | our use |
|---|---|---|
| **Enqueue-only `prove()`.** No stream sync "not even for profiling"; Fiat–Shamir in `launch_host_fn` callbacks; the host blocks only in `finish()`. | `gpu/docs/gpu_scheduling_contract.md` | **taken.** This is the M6 contract, enforced by a lint. |
| **Static device arena** with **offline-swept memory presets:** commit mode `AllCosets`/`PerCoset`/`InPlace`, what to retain, recompute vs keep; proof-fingerprint parity across presets | `gpu/execution_prover/docs/memory_policies.md` | **taken** (M4 arena, M6 presets) |
| **3-phase per-worker pipelining** (H2D, compute, finish); shortest-queue dispatch | `workers/gpu_manager.rs` | **taken** |
| **Pre-commit of memory/bus columns,** then fully independent chunk proofs (about 5–10% redundant work) | `docs/subarguments_used.md` | **adapted.** We already commit MAIN first; we stream it per segment and regenerate MAIN on the device. |
| **Coalescing rule:** never permute the lane→leaf axis in hash or commit kernels. Bit-reversal on value addresses cost them 12× on one kernel. | contract doc | **taken.** This is the M4 kernel audit. |
| **High-LDE, few-query "feeder" final layers:** LDE 16 up to 2^20, queries [21, 17, 9, 5, 4] | `v3` WHIR config | **taken as a principle** (two-stage compress) |
| **Unrolled opcode-family circuits** of about 40 columns, registers in RAM, free range checks from the RAM argument, delegation circuits | v3 circuits | **guest and arithmetisation diet: tracked, outside 10× scope** |
| **GKR + WHIR over BabyBear;** they **left M31** when adopting GKR/WHIR | `field.cuh` `ORDER=0x78000001`; blog 2026-10-13 | **not taken now.** This is the long-term option (§3.5). |
| Reduced-round Blake2s for Merkle trees | ARCHITECTURE.md | **rejected.** It is a security change for about 1.3×. |

Published results:
- **Airbender Prime** (13 Oct 2026, zksync.io/blog/introducing-airbender-prime): 99% of 7,200 blocks in under 10 s on one RTX PRO 6000, including witness preparation.
- **Ethproofs** (ethproofs.org/provers, fetched 2026-11-04): "Zilkworm Airbender v3 2x5090", average 3.3 s.
- Whether these timings include recursion all the way to a single final proof is [unverified].

### 3.3 zkDTVM (Ant Digital): verifier only, `AntChainOpenLabs/zkdtvm-stark-verifier`

- **Layered recursion with rising blowup and falling queries.** `whir_config.json`:

  | layer | log blowup | queries |
  |---|---:|---|
  | core | 1 | 261 |
  | compress | 2 | 160 |
  | shrink | 3 | 131 |
  | root_shrink | 4 | WHIR, [67, 36, 24], Merkle path pruning |

  The real block proof is a `.seal` of 267,918 B. **This is evidence that a 2-stage compress with rising blowup is the right shape**, and that 250–300 KB is the multilinear frontier. Our ≤100 KB STARK target is therefore aggressive and needs caps, dedup and a high fold arity.
- The prover is closed: no GPU design is visible. The live board shows 4.6 s on 4× 5090.

### 3.4 Others

- **OpenVM 2.x (Axiom).** SWIRL: GKR-LogUp, stacked opening reduction, WHIR over BabyBear⁴, 100-bit provable security. Results: 19.4 MHz on one 5090; 5.0 s average and 9.7 s p99 on 4× 5090. The executor transpiles RISC-V to C. Sources: axiom.xyz/blog/openvm-2-beta, axiom.xyz/blog/2-1, reports.zksecurity.xyz/reports/openvm.md.
- **SP1 Hypercube.** Jagged PCS ("pay only for what you use") with LogUp-GKR. 99.7% of blocks under 12 s on 16× 5090 (blog.succinct.xyz/real-time-proving-16-gpus).
- **Pico Prism.** Data locality across machines; the source is secondary.
- **Common pattern across all of them:** GKR-LogUp for every interaction column, low base rate plus high PoW, an async enqueue-only GPU pipeline, compiled execution emitting a minimal trace with GPU witness expansion, and shrinking recursion.

### 3.5 The long-term option we explicitly do not take now

Every leader runs multilinear GKR with WHIR, jagged or BaseFold PCS over BabyBear or KoalaBear. Airbender moved off M31 to get there. Circle-WHIR is untested territory.

We keep the M31 Circle-STARK stack for this plan because:
- our native rate is already 0.19–0.22 ns per cell [M];
- our losses are architectural (§2);
- a field and PCS port would reset every soundness note.

**Trigger for re-evaluation (spike S-ML, after M7):** recursion still costs more than 0.3 G committed cells per verified native proof, or native stays below 15 MHz per GPU after M6.

---

## 4. Target architecture

```
┌──────────────────────── stwo-rv64d — resident prover service (1 per pod) ─────────────────────────┐
│ ArtifactStore  key = H(image, rung, profile, generator-src hash, AOT-catalogue hash, field/hash)   │
│   native VK table (≤12 canonical classes) · recursion VK table {leaf[family,rung], fold_k,         │
│   compress1, compress2} · PP/FIXED columns · witness-fill plans · memory presets · CUDA graphs ·   │
│   fatbins (1 per family, lazy)          — mmapped, clean pages; rebuilt at install, never per req  │
│ Per GPU (×2): static arena carved by size class at boot (overrun = abort, never pool fallback)     │
│   streams: S0 native-big · S1 native-small/leaf · S2 fold/compress · H2D · D2H  (events only)      │
│   device transcript (channel.cu / transcript.cu); host touched only via cudaLaunchHostFunc         │
│ Host: pinned huge-page pools (H2D staging, D2H proofs) · 48-core worker pool · THP arenas         │
└─────────────────────────────────────────────────────────────────────────────────────────────────────┘
request ─► CAPTURE (image + ROM authority already mapped)
             parallel import ─► execute ─► per-segment replay ─► sharded ledger (prefix stitch)
             │ segment k compact records (≈64 B/instr, pinned 64 MB chunks) ─► H2D on GPU (k mod 2)
             ▼
           NATIVE STAGE 1 per segment, as soon as it is captured:
             GPU witness widen → streaming LDE→Merkle → MAIN root   (records stay on device)
             ▼  barrier = roots only: χ = H(statement ‖ roots sorted by segment index)  (ms)
           NATIVE STAGE 2 per segment / batched service proof:
             MAIN regenerated ON DEVICE from records → interaction → composition → FRI → proof_k
             ▼  key-affinity scheduler: warm stream > fresh key > reload; root-closest first
           LEAF[family,rung]  canonical circuit, log sizes constant, native VK roots guessed+seeded,
             hint-tape witness (≈11 fill kernels, depth 1), 1 CUDA graph per class
             ▼  opportunistic: fold any 2–4 ready siblings (null slots tagged)
           FOLD_k (k ≤ 4)  canonical; vk_fold carried as public input (PCD self-VK)
             ▼
           ROOT ─► COMPRESS1 (b8, narrow) ─► COMPRESS2 (b16 q27 p20, fold 8/16, caps, dedup) ─► ≤100 KB
receiver: derive-vk-tables(image, profile) from pinned source commit — once, cached locally
          → verify COMPRESS2 → check vk_fold = derived constant → recompute statement digest
          (--audit: today's full-tree re-verify, kept for differential checks)
```

### 4.1 Layer profiles

Conjectured security bits are q·log₂(blowup) + pow.

| layer | hash | profile | bits | status |
|---|---|---|---:|---|
| native | Blake2s | `conjectured128_b2_q108_p20_fold4` (today) | 128 | kept. **D2** may move it to `b4_q54_p20` (128) |
| leaf / fold / root | Blake2s | `m3_b4_q51_p26` (recsize) | 128 | M7 merges it; the recsize note exists |
| compress1 | Blake2s | `b8_q36_p20` | 128 | new, in M7 |
| compress2 | Blake2s | `b16_q27_p20`, FRI fold 8 or 16 | 128 | new, in M7 |

Poseidon2-M31 is **deferred.** It helps only folds and compress, because leaves verify Blake2s natives. It is a small share once k-ary lands. Its collision resistance is about 124 bits, below the 128 label. Its cryptanalytic maturity on 31-bit primes is still moving. Reopen it only if the reconciled census shows folds above 40% of recursion GPU time after k-ary.

### 4.2 The canonical leaf (corrected per review)

- **Component log sizes, domain sizes, FRI layer count and query-index widths are circuit constants per (family, rung).** They are never guessed: guessing them would need wide in-circuit muxing, which is a source of soundness bugs.
- **Guessed and range-checked:** the native FIXED root, preprocessed roots and statement words only.
- The guessed native-VK words **seed the in-circuit child transcript.** This prevents frozen-heart-style forgery.
- The leaf's public digest is H(native_vk_hash ‖ statement ‖ family ‖ rung ‖ segment index).

### 4.3 Constant recursion VK (the PCD self-VK fix)

A fold cannot hard-code its own VK. Instead:
- `vk_fold` is a **public input** of every fold.
- Each fold asserts that each child VK is in {leaf table root membership} ∪ {its own `vk_fold` input}, and passes `vk_fold` up unchanged.
- The root's public statement contains `vk_fold`. The receiver checks it equals the constant it derived from source.
- Native VKs are checked by membership in a native-VK table root, which is also in the statement and also re-derived by the receiver.

### 4.4 Root public statement

The root's public statement is the concatenation of:
- the block statement digest;
- the image id;
- the native-VK table root;
- the recursion-VK table root and `vk_fold`;
- the **ordered segment chain** H over (segment index, family, rung, vk hash, statement);
- κ, the leaf count;
- the bus-balance sum;
- χ.

Null fold slots are explicitly tagged and excluded from the chain.

### 4.5 Witness generation is recorded verifier execution

The capturing native verify (`cpu_capture.zig`, about 0.1 s per proof on the side thread [M]) already computes every Blake input and every qm31 operand. It emits a **hint tape**. Per-component fill kernels then compute G rows, qm31 rows and XOR multiplicities in parallel.

Only witness *generation* changes. The AIR still constrains the transcript, so proofs are **byte-identical** when column order is kept.

### 4.6 Global challenge

χ = H(statement ‖ MAIN roots sorted by segment index): a sequential Blake2s, milliseconds, trivially sound under Fiat–Shamir.

The LtHash/additive accumulator is **rejected**. An M31-vector additive accumulator is exposed to Wagner/k-list attacks unless lattice-sized, and order independence is worthless on one node. Revisit it only for multi-node proving, with a vetted parameter set.

### 4.7 Stacked PCS: rejected as specified

"Width × N + one path set" needs one Merkle tree across all segments of an AIR. That is a block-wide commit barrier, and it contradicts streaming stage 1.

What we keep instead:
- **larger canonical rungs** (2^23, and 2^24 only if memory allows), which cut segment count;
- **batched truth and service proofs** (one per family);
- **shared query positions** across a leaf's batched children, which helps qm31 work but not paths.

Expected leaf gain from merging is 1.5–4×, to be sized by the M4.0 per-origin census.

---

## 5. Milestones

The general gate order is 26235156 (15.3 M instructions, 4 segments), then 24628607. **Nothing larger runs until M8**, and M8 is run only by the integration agent: one block at a time, in increasing size, each proven once, stopping at the first failure.

### M4.0: honest measurement and devx (about 1 session, all streams start in parallel)

**Entry:** `e61851f9e` plus recsize rebased onto a measurement branch. No code change to the prover.

**Deliverables:**
1. **GPU-time reconciliation** (§2.4): nsys kernel-busy GPU-s vs span GPU-s per node kind, published as one number.
2. **Fixed stage-boundary receipt schema** (§8). Projection, stage 1, replay, native verify and leaf wrap each get exactly one column, so that no column can be "won" by moving work into another.
3. **Per-origin Blake census** for CPU0, Keccak and one fold: Merkle leaf, path, FRI and channel.
4. **RSS smaps plus allocator census at the peak.** It must attribute at least 90% of the 22.9 GiB intercept.
5. **Geometry distribution over all 15 existing receipts** (read-only), and a rung padding-tax model for 2, 3 and 4 rungs.
6. **D2 paper model:** native b4_q54 cost vs leaf ×0.5, using measured LDE and leaf width.
7. **Device memory model** for 2^22, 2^23 and 2^24 segments at b2 and b4, plus the composition arena breakdown.
8. **Reconciled committed-cell count** (53.39 G vs 37 G).
9. **Tooling:** a proof-fingerprint diff tool, an nsys per-phase extractor, and a sync/launch/alloc counter shim.

**Exit gate:**
- census sums ≥90% of RSS;
- Blake origins sum ≥95%;
- rung tax computed;
- D2 has a recommendation;
- all numbers committed under `vectors/reports/rv64-m4-<date>/measure/`.

**Proof format:** unchanged. **Soundness:** none.

**Kill or re-plan:**
- If reconciled recursion kernel time is above 20 GPU-s on 607, the order changes: the L4 cell diet moves ahead of L3.
- If the RSS intercept turns out to be irreducible (for example, driver-pinned memory), the RAM target is re-scoped and the owner is told.

### M4: resident service and static arena, no protocol change (L1)

**Entry:** M4.0 exit.

**Mechanisms:**
- **`stwo-rv64d` resident service.** It caches the image and `ProgramAuthority.initWithRom`, and generalises the warm SetupCache into a persisted, content-addressed ArtifactStore keyed per §4. Byte-compare and generator-hash checks run on load.
- **Fatbin loading:** one fatbin per family with lazy loading. `CUDA_MODULE_LOADING=EAGER` and the 686-library load are dropped. A build gate byte-compares every catalogue against `--catalog` regeneration, which also closes the `global_aot` drift class.
- **Static per-GPU arena** carved by size class. Pool trim is removed from the hot path. Overrun aborts.
- **Pinned staging** replaces pageable copies.
- **Composition arena diet:** PerCoset/InPlace composition and dropping retained monomials, sized by an offline preset sweep with a fingerprint gate. The aim is to free the headroom M6 concurrency needs.
- **Kernel coalescing audit** of the LDE, Merkle and composition kernels (the Airbender rule).
- **Capture first pass:**
  - the ordered ledger sharded by address range, stitched with a prefix pass;
  - block import parallelised or streamed per account and transaction;
  - retained arenas plus THP, aimed at the 96.6 M minor faults and 334 s of system CPU on 26235159.

**Exit gate (measured on 26235156, then 24628607):**

| metric | gate |
|---|---|
| cold-service setup | ≤1.0 s |
| second request vs first | equal ±10% |
| `cuLibraryLoadData` per request | ≤20 |
| `cudaMallocFromPoolAsync` in steady state | ≈0 |
| pageable copies | 0 |
| request-attributable RSS | −30% |
| GPU0 peak | ≤28 GB |
| capture on 607 | ≤1.5 s |
| proofs | **byte-identical** to baseline |
| fresh receiver | accepts |

**Expected measured effect [E]** (607): request 51 → about 33–36 s, from setup leaving the path, capture −1.8 s, and alloc and copy API costs −9 s. Setup 12.6 → ≤1 s.

**Proof format:** unchanged.

**Soundness and receiver:**
- The cache-keying note must be written.
- The receiver must never read the ArtifactStore. A receiver test runs with the store deleted.

**Kill:** if the preset sweep cannot bring GPU0 below 28 GB without more than 15% native slowdown, M6 concurrency is cut to 2 nodes per GPU and the recursion target moves to the "realistic" band.

### M5: canonical topology and constant recursion VK (L2, protocol change)

**Entry:**
- M4 exit;
- the **binding note** (§4.2–4.4: log sizes constant, guessed roots seed the child transcript, PCD self-VK, ordered root chain with κ, bus balance and null tags) has been reviewed **before any code merges**;
- the rung set has been chosen from the M4.0 tax model.

**Mechanisms:**
- **Canonical native rungs.** Each AIR is padded to one of at most 3 heights, so there are at most about 12 native classes per image. Setup becomes a per-image install artifact, with the FIXED commit done on the GPU in one batched launch per class.
- **Canonical `R_leaf[family, rung]`** per §4.2, extending fold v2 to leaves.
- **k-ary fold classes** (`classKey([k]Child)`, k ≤ 4, null slots), generalising `execution_wrap.zig:130 combine` and the `ready_dag.zig` node. M5 keeps the q108 outer profile; the profile change comes in M7.
- **VK tables:** native and recursion tables plus `vk_fold`.
- **`derive-vk-tables`** CLI for the receiver, plus a **root-only verify** path. `portable_root_key_admission` becomes true by construction.
- **`--audit`** keeps the full-tree re-verify.
- **Graph, PP, FIXED tree, assignment plan and memory preset are built once per image** and stored in the ArtifactStore.

**Exit gate:**

| metric | gate |
|---|---|
| verifier per block, both small blocks | ≤1.5 s |
| one-time `derive-vk-tables` | ≤30 s, reported separately |
| setup | independent of block (26235156 setup = 24628607 setup ±10%) |
| distinct leaf topologies | ≤ families × rungs |
| host preprocess + plan + graph per node | ≤0.1 s |
| `--audit` | agrees with root-only on both blocks |
| negative corpus | **all rejected**: dropped, duplicated and permuted segments; forged null; wrong κ, rung or child VK; tampered native root; χ mismatch |

**Expected measured effect [E]** (607):
- verifier 77 → ≤1 s;
- recursion 27 → about 15–18 s (host phases of 19.5 + 15.9 + 18.3 s summed leave the per-node path);
- request about 33 → 22–26 s.
- The canonical padding tax costs native +10–30%.

**Proof format:**
- the leaf public digest changes;
- the root statement is per §4.4;
- the fold arity field is new;
- the proof header carries the profile id and the VK-table roots.

**Receiver obligations:**
- re-derive from a pinned source commit;
- refuse unknown profile ids;
- refuse a store-supplied VK.

**Kill:**
- If the padding tax exceeds 40% of native cells with 3 rungs, add a 4th rung.
- If it still exceeds 40% with 4 rungs, keep canonical *leaves* with a constant log size per real geometry class (a larger VK table, still constant per image) and drop canonical native padding.

### M6: GPU-resident, enqueue-only, streaming pipeline (L3, no protocol change)

**Entry:** M5 class keys frozen; the M4 arena; the hint-tape format and arena-preset schema frozen at the start of the milestone.

**Recursion mechanisms:**
- **Hint-tape witness** (§4.5), first on the fold class, then on leaves. About 11 fill kernels per node at depth 1 replace the 120k-level DAG. The 4×-QM31 host assignment arrays go away.
- **Enqueue-only outer prove.** commit → interaction → composition → OODS → DEEP → FRI → decommit runs with the device transcript. Events replace `stwo_exec_context_sync` (`runtime/context.cu:117`). There is one captured CUDA graph per class, and graph regions that read per-proof pinned buffers are poisoned. A **sync lint** in CI fails on any `StreamSynchronize` reachable from `prove()`.
- **Recursion kernel efficiency** (missed by both designs): from 0.33–0.8 down to ≤0.25 ns per LDE cell, through fused Blake leaf hashing and coalesced composition.
- **Concurrency:** 2–3 concurrent nodes per GPU on S1 and S2, within the M4 headroom.
- **Key-affinity scheduler:** warm > fresh > reload; root-closest first; fold any 2–4 ready siblings; phase A/B (leaves on half-arenas while big native segments prove).

**Native mechanisms:**
- **GPU witness widening** from compact records plus a per-image decode table uploaded once. This replaces host projection (56 B per row, 22.9 GB H2D on 26235159).
- **Streaming stage 1 per segment during capture** (the first batch is ready at 0.30 s [M]).
- **MAIN regenerated on the device after the barrier.** `STWO_RV64_GPU_CPU_REPLAY` and `CORE_SINGLE_STREAM` are removed.
- **Streaming commit.**
- **Native graphs** per canonical class.
- **AIR-batched launches** across segments.

**Exit gate (607):**

| metric | gate |
|---|---|
| syncs per node | ≤10 |
| launches per node | ≤500 |
| span/GPU ratio per node | ≤1.3 |
| GPU busy during recursion | ≥70% |
| recursion | ≤8 s |
| native | ≤2.0 s |
| H2D bytes per instruction | ≤80 |
| host replay | none |
| request | ≤12 s |
| proofs | **byte-identical** to M5 |
| transcript parity | per class, GPU vs CPU |

**Expected measured effect [E]:** native 7.8 → 1.5–2 s; recursion 15–18 → 6–8 s (still about 33 nodes of about 1.1 G cells, now GPU-bound); request → 10–12 s.

**Proof format:** unchanged. **Soundness:** none beyond the parity and byte-identical gates.

**Kill:**
- If hint-tape fill takes more than 1.5× the device time of today's assignment, or byte-identity cannot be reached within the milestone, keep the narrow-run DAG for that class and graph-capture it instead.
- If device-transcript divergence persists, fall back to host-callback Fiat–Shamir (`cudaLaunchHostFunc`), which is still enqueue-only.

### M7: cell diet and compression (L4, protocol change)

**Entry:**
- M6 exit;
- the reconciled per-origin census;
- the security notes for every new profile, the outer GKR and the k-ary binding, all reviewed before merge.

**Mechanisms:**

| lever | factor [E] | applies to | notes |
|---|---|---|---|
| merge recsize `m3_b4_q51_p26` as the outer profile | ×0.5 | **folds and root only** (what they verify) | the earlier ×0.5-on-leaves double count is corrected |
| 4-ary folds | ×1.0 per fold (4 × q51 ≈ 2 × q108) | fold *count*: 16 → about 3; depth 5 → 2 | |
| outer LogUp-GKR, batched across components | ×0.55 | all outer nodes | interaction is 50% of cells; in-circuit GKR verifies with qm31 operations, not hashes |
| fused Blake2s gadget (round-level rows, XOR via lookup or GKR, no 29% padding) | ×0.7 | all outer nodes | AIR change, not a hash change |
| 2^23 canonical rungs plus one batched service proof per truth family | leaves 17 → about 5–7 (607), 75 → about 18–25 (159) | node count | merge gain 1.5–4×, sized by the census |
| **D2** (native `b4_q54_p20`) | leaf ×0.5; native +30–40% LDE | leaves | only if the M4.0 paper model says net positive |
| **two-stage compress:** C1 `b8_q36_p20` on a narrow circuit, then C2 `b16_q27_p20`, FRI fold 8/16, Merkle caps (16-node cut), multiproof dedup, pruned last FRI layer, arity-4 Merkle in C2 only | proof ≤100 KB (stretch 75) | final proof | a b16 Blake compress of a 0.5 G-cell circuit needs about 56 GB of LDE and **does not fit**, so two stages are mandatory |
| capture: AOT/JIT RV64 emulator with checkpoints (ZisK, Airbender) | 300–500 MIPS | capture | runs in parallel from M4 onward |

**Corrected combined leaf factor:** ×0.55 × ×0.7 ≈ **×0.38** without D2, and about ×0.19 with D2. Folds are about ×0.19 per fold, with roughly 5× fewer of them.

**Exit gate:**

| metric | gate |
|---|---|
| committed cells per leaf | ≤0.5 G (≤0.3 G with D2) |
| nodes on 607 | ≤10 |
| recursion on 607 | ≤4 s, with the tail after the last leaf ≤2 s |
| final proof | ≤100 KB |
| capture on 607 | ≤0.6 s |
| request on 607 | ≤8 s |
| `--audit` and root-only | agree |
| negative corpus | extended to GKR and compress |
| receiver | fresh-process acceptance |

**Expected measured effect [E]** (607): recursion 6–8 → 2.5–4 s; native 1.5–2 → 1.0–1.5 s (fewer interaction cells per gas, offset by padding); request → 6–8 s; proof 708 → 90–110 KB.

**Proof format:** new profile ids (outer, C1, C2); a GKR section in outer proofs; fold arity up to 4; a compressed final-proof container.

**Soundness obligations:**
- an outer GKR note (sumcheck error about Σ rounds × deg / 2^124, roughly 2^-110 to 2^-115) with a CPU reference verifier and a tamper corpus;
- a completeness test of the fused Blake gadget against reference Blake2s;
- C1 and C2 entries in `PROFILES` (`om31_security_candidate.zig`) with conjectured-128 arithmetic;
- the k-ary generalisation of the fold v2 binding note.

**Kill:**
- If the in-circuit GKR verifier exceeds 25% of leaf cells, or slips by more than 2 sessions, ship k-ary, fused Blake, rungs and compress without outer GKR. Recursion then lands at about 4–5 s on 607.
- If the C2 tail exceeds 2.5 s, ship the C2 proof as an async "compact proof" output and gate request on the root.

### M8: ordered scale-up (L5, integration agent only)

The integration agent proves 24697070, then 26235168, then 24628590, then 26235159. Each block is proven once with the full receipt and accepted by a fresh receiver, and the run stops at the first failure.

**Exit:** the summary table with every column reported against §1, plus one `--audit` run on the largest block.

### Cumulative expected trajectory (24628607, [E])

| after | request | capture | setup | native | recursion | verifier | RSS (req.) | proof |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| today [M] | 51.1 | 3.3 | 12.6 | 7.8 | 27.3 | 77.3 | 25.0 | 708 KB |
| M4 | 33–36 | 1.5 | ≤1 | 7 | 22 | 77 | 15–18 | 708 KB |
| M5 | 22–26 | 1.5 | ≤0.5 | 8–9 | 15–18 | ≤1.5 | 8–10 | about 700 KB |
| M6 | 10–12 | 1.0 | ≤0.5 | 1.5–2 | 6–8 | ≤1.5 | 4–6 | about 700 KB |
| M7 | **6–8** | **0.4–0.6** | **≤0.5** | **1.0–1.5** | **2.5–4** | **≤1** | **3–5** | **90–110 KB** |

---

## 6. Work streams

### 6.1 Streams and file ownership

All branches are named `codex/rv64-m4-<stream>`, with worktrees at `~/Coding/ge-wt/rv64-m4-<stream>`. File ownership is disjoint; a file has exactly one writer per milestone.

| stream | branch | owns (sole writer) | active in |
|---|---|---|---|
| measure | `codex/rv64-m4-measure` | `vectors/reports/rv64-m4-*/measure/*`; nsys, census, fingerprint and API-counter tooling; the receipt schema | M4.0 → M8 |
| resident | `codex/rv64-m4-resident` | `backends/cuda/native/runtime/context.cu`, `pool_trim_policy.h`, `ethereum/resident_session.zig`, the ArtifactStore, the catalogue build plus byte-compare gate, fatbin loading | M4, M6 (events) |
| arena | `codex/rv64-m4-arena` | arena carving, memory presets and the sweep tool, composition-arena policies (`resident_composition.zig`) | M4, M6 |
| capture | `codex/rv64-m4-capture` | `ethereum/capture*.zig`, `word16_global_execution/collector.zig`, `word16_execution/memory/collector.zig`, block import, the M7 emulator | M4 → M7 |
| profiles | `codex/rv64-m4-profiles` | **sole owner** of `om31_security_candidate.zig` (`PROFILES`, `MAX_TRACE_LOG`); every soundness and binding note; the negative corpus spec | M4.0 → M7 |
| canon-native | `codex/rv64-m4-canon-native` | `ethereum/keys.zig`, `setup_cache.zig`, `riscv_cuda/rv64/immutable_setup.zig`, `rv64_recursion/native_fixed_root.zig`, rung padding | M5 |
| canon-vk | `codex/rv64-m4-canon-vk` | **sole owner of circuit construction:** `om31_native/{execution_wrap,outer_wrap}.zig`, `rv64_recursion/{om31_outer,root_admission,fold_root,leaf_statement}.zig`, the `ethereum/gkr_main.zig` verify entry, `derive-vk-tables` | M5, M7 (k-ary binding, compress circuits) |
| hint-tape | `codex/rv64-m4-hint-tape` | `riscv_cuda/rv64/outer_assignment.zig`, `assignment_runs.zig`, `rv64_recursion/native_capture.zig`, new `backends/cuda/native/rv64/circuit_fill_*.cu` | M6 |
| enqueue | `codex/rv64-m4-enqueue` | `outer_source.zig`, `trace_commit.zig`, `pcs_native.{zig,cu}`, `channel.cu`, `transcript.cu`, graph capture, the sync lint | M6 |
| native-stream | `codex/rv64-m4-native-stream` | `services/gkr_local/manifest.zig`, `riscv_cuda/rv64/{cpu_replay,cpu_projection}.zig`, the `*_witness.cu` family, streaming commit | M6 |
| sched | `codex/rv64-m4-sched` | `om31_native/ready_dag.zig` and the service scheduler (key affinity, phase A/B) | M6, M7 |
| kernels | `codex/rv64-m4-kernels` | LDE, Merkle and Blake kernels in `backends/cuda/native/rv64/*` that no other stream owns; coalescing audit; recursion ns per cell | M4 → M7 |
| outer-gkr | `codex/rv64-m4-outer-gkr` | in-circuit GKR verifier gadget, outer GKR prover wiring, CPU reference | M7 (prototype from M5) |
| blake-gadget | `codex/rv64-m4-blake-gadget` | fused Blake2s component AIR and its fill kernel | M7 (prototype from M5) |
| compress | `codex/rv64-m4-compress` | C1 and C2 provers, caps, multiproof, FRI fold 8/16 path (circuit shape requests go through canon-vk) | M7 |
| integrate | `codex/rv64-m4-integrate` | merge order, the gate runs, `SUMMARY.md`, the M8 scale-up | all |

Sequencing rules:
- **Parallel from day one:** measure, resident, arena, capture, profiles, kernels.
- **After M4.0:** canon-native and canon-vk.
- **After M5 keys are frozen:** hint-tape, enqueue, native-stream, sched.
- **Prototyped off the critical path from M5:** outer-gkr and blake-gadget, which merge in M7.
- **Interfaces frozen at M6 start:** the canonical VK schema, the hint-tape format and the arena-preset schema. Changes after that go through integrate.

### 6.2 Pod, GPU and build sharing rules

These follow `~/Coding/ge-cache/rv64-m3/PROTOCOL.md`.

- **Laptop:** no big Zig builds or tests locally. Edit and run git locally. Anything that must run locally goes through `~/Coding/ge-ops/bin/memguard run --gb 6 -- …`. The 36 GB laptop has already crashed under parallel agents.
- **Pod:**
  - Sync each stream with `podsync ~/Coding/ge-wt/rv64-m4-<s> m4-<s>` to `/workspace/m3/src/m4-<s>`.
  - Each stream uses its own local Zig cache, plus `ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global`.
  - Run logs go to `/workspace/m3/runs/m4-<s>/`.
  - Long jobs run in tmux and are polled by reading their log files.
- **GPU lock:** every job that touches a GPU runs under `flock -w 7200 /workspace/m3/locks/gpu.lock` (the single lock covers both GPUs), and holds it for at most about 25 minutes.
  - **Timing runs** additionally require a quiet host: 1-minute load average under 8, recorded in the receipt. They also require an AC-power and clock check.
- **Build throttle:** at most 3 concurrent pod Zig or nvcc builds, through `flock` on one of `/workspace/m3/locks/build.{1,2,3}.lock`.
- **Disk:** keep `/workspace` under about 60 GB. ArtifactStores live under `/workspace/m3/store/<branch>` and are pruned at the end of each milestone.
- **Read-only team state:** `/workspace/rv64-gpu-session` and `/workspace/rv64-*` are read-only. Never stop or delete pods.
- **No basket loops:** streams run only 26235156 and 24628607. Nothing larger runs except the integrate agent's M8 ordered scale-up.
- **Merge gate:** local CI and receipts are the gate, because GitHub CI never goes green under its limits. Each stream's merge needs:
  - a byte-identical (or, for protocol milestones, fresh-receiver-accepted) proof on 26235156 and on 24628607;
  - its receipt JSON committed with the code.
- **Commits:** commit and push often. Messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

---

## 7. Risks and kill criteria

| # | risk | signal | mitigation or kill |
|---|---|---|---|
| R1 | Our idle-GPU story is wrong: kernels dominate more than the busy fractions suggest | M4.0 reconciliation above 20 GPU-s on 607 | move the M7 cell diet ahead of M6; recursion target goes to the realistic band |
| R2 | Device memory blocks concurrency | GPU0 above 28 GB after M4 presets | cap at 2 nodes per GPU; streaming commit; leaf-less Merkle; stay at 2^22 or 2^23 rungs |
| R3 | Canonical padding tax | above 40% extra native cells | 4th rung, then fall back to per-class constant log sizes (§5 M5 kill) |
| R4 | The constant-VK binding argument has a hole | review finds an unbound field | M5 does not merge until the note and the negative corpus pass; `--audit` stays available |
| R5 | Hint-tape byte-identity fails | fingerprint diff | graph-capture the narrow-run DAG for that class instead |
| R6 | Device-transcript divergence | parity test | fall back to host-callback Fiat–Shamir, still enqueue-only |
| R7 | The outer GKR gadget is too big or too late | above 25% of leaf cells, or more than 2 sessions of slip | ship M7 without it; recursion about 4–5 s on 607 |
| R8 | The compress tail eats the request budget | C1 + C2 above 2.5 s | async compact proof; request gated on the root |
| R9 | Capture import stays at about 2.8 s | M4 capture gate missed | an import-rewrite spike; capture becomes the 607 long pole, reported honestly |
| R10 | Cache poisoning or drift | catalogue or generator hash mismatch | refuse to load; rebuild; the receiver never reads stores |
| R11 | RAM metric gaming | daemon RSS grows while request RSS shrinks | always report both metrics (§1) |
| R12 | Staffing | M5 and M7 are multi-session | the realistic calendar is about 3–5 months. Protocol milestones are gated on review, not on dates. |
| R13 | The architecture plateaus below the frontier | after M7, more than 0.3 G cells per verified native proof, or native below 15 MHz per GPU | open spike S-ML (multilinear GKR + WHIR or jagged PCS, field choice). Airbender's M31 exit is the precedent. |
| R14 | 607 is latency-bound | native ≥1.2 s after M6 | accept 6–9×. The 10× there needs 4 GPUs or a guest diet (Keccak and u256 delegation, fewer truth families; 3.13 instructions per gas today), tracked outside this plan. |

---

## 8. Measurement plan

**Location:** `vectors/reports/rv64-m4-<YYYYMMDD>/<stream>/<block>-<gate>.json`, each with a short `.md`, committed together with the code. Integration summaries go to `vectors/reports/rv64-m4-<date>/SUMMARY.md` and `summary.json`, in the same shape as `rv64-m3-20261104`.

### 8.1 Fixed stage-boundary schema

This is defined in M4.0 and is never changed silently.

| field | definition |
|---|---|
| `request_s` | wall time from request accepted to final proof bytes written |
| `capture_s` | input to the last segment's compact records being ready |
| `capture_critical_s` | the part of `capture_s` not overlapped by native work |
| `setup_s` | split into `setup_cold_service_s`, `setup_warm_s` and `setup_install_s` (the install figure is reported, never hidden) |
| `native_s` | split into `stage1_s` (first segment start to χ drawn) and `stage2_s` (χ to the last native proof); projection and widening count here, and **never** under capture |
| `recursion_s` | split into `recursion_wall_s`, `recursion_tail_s` (last native proof to final proof) and `compress_s` |
| `verifier_s` | split into `verify_per_block_s` and `derive_vk_tables_once_s`, both from a fresh, cache-disabled process |
| RAM | `rss_peak_request_private_gib`, `rss_peak_daemon_gib`, and an smaps breakdown at the peak |
| device memory | `device_peak_gb[gpu]` |
| proof size | `proof_bytes_final`, `proof_bytes_root` |

### 8.2 Per-gate ratchets

**GPU utilisation:**
- NVML kernel-active % per GPU;
- nsys kernel GPU-s (not spans) per node kind;
- kernel-overlap fraction per device;
- span/GPU ratio per node kind.

**Host API, per request and per node:** `cudaStreamSynchronize`, kernel launches, pool mallocs, `cuLibraryLoadData`, pageable copies.

**Work volume:**
- committed cells per node by component (main, interaction, preprocessed);
- node count, fold depth;
- Blake compressions per leaf by origin;
- recursion ns per LDE cell (target ≤0.25);
- native MHz per GPU.

**Native:**
- H2D bytes per instruction;
- first-segment stage-1 latency;
- MAIN regeneration time;
- canonical padding tax %.

**Host:**
- busy cores (≥16 during capture);
- minor faults;
- system CPU seconds.

**Security:** conjectured bits per layer, computed from the profile in the proof header.

**Correctness:**
- every non-protocol gate (M4, M6): proof fingerprint identical to the parent gate;
- every protocol gate (M5, M7): fresh-receiver acceptance, one `--audit` agreement, and the negative corpus with every case rejected.

**Hygiene:**
- AC power and clocks checked before any timing;
- quiet-host load average recorded;
- a cross-backend verify ratio far from 1× is treated as a measurement fault, not a finding;
- every number is labelled [M], [D] or [E], and no number is claimed unmeasured.

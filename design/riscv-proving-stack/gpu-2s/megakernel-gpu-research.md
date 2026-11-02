# Megakernels and GPU STARK provers: what to borrow for the RV64 Circle-STARK GPU path

Date: 2026-11-02. Read-only web research plus a look at PR #311 (`origin/codex/rv64-cuda-resident-gkr`,
head `771334a93`). All third-party numbers are vendor claims unless marked otherwise. Ethproofs could
not be fetched directly, so leaderboard numbers come from secondary coverage.

## TL;DR

1. **The competitive bar has moved.** As of Oct 2026 the public bar is "99% of blocks under 10 s".
   ZKsync's Airbender Prime does this on **one** RTX PRO 6000 Blackwell (7,200 blocks, all under 12 s).
   ZisK v1.1.0-alpha claims a 9.62 s p99 on **four** RTX 5090s. SP1 Hypercube reports 99.7% of
   blocks under 12 s on 16× 5090. Nobody publishes sub-2 s averages. The goal of under 2 s on average
   with a GPU group is therefore about **5× ahead of the public frontier** per block, not merely
   "ahead of ZisK".
2. **The bound is latency, not FLOPs.** Our own roofline (cost-per-cell.md §3) puts the GPU floor
   at about 50–100 ps per cell. That is ~0.25–0.5 GPU-s for the ~5.1 G cells of block 24,628,607.
   Getting under 2 s is a matter of removing bubbles: launches, host round trips, PCIe ingress,
   per-proof fixed cost, recursion depth and the critical-path proof. That is exactly the problem the
   megakernel work solves for LLM decode.
3. **The most transferable megakernel ideas:**
   - an on-device instruction interpreter with a CPU-precomputed per-SM schedule (Hazy);
   - global-memory counters as fine-grained dependency barriers, signalled per chunk (Hazy);
   - shared-memory paging, so the next task's loads start while the current task stores (Hazy);
   - in-kernel peer-to-peer stores in place of NCCL collectives (Hazy throughput megakernel,
     ParallelKittens);
   - a compiler that lowers a task graph to SM-level tasks with decentralised scheduling (Mirage MPK).
4. **The most transferable ZK-prover ideas:**
   - compile each AIR's constraints to its own GPU kernel at setup time, not an interpreter
     (ZisK v1.3);
   - prefetch the next proof's trace while the current one proves, and use completion-slot rings
     with no per-proof host sync (ZisK v1.3);
   - run recursion concurrently with base proofs on split streams (ZisK v1.3);
   - lane-pack AIRs into fewer, larger instances (ZisK v1.3), which matches our "small proofs are
     pure fixed cost" finding;
   - CPU does only RISC-V simulation and tracing; the GPU does witness generation and everything
     after it (Airbender).
5. **Status of PR #311:** the work is correct in structure: resident OM31 sumcheck/GKR with
   device-side Fiat-Shamir and fold/next-sum fusion, compiled for sm_89 and sm_120. However, it has
   **never executed on a GPU** (every hardware gate exits 77) and is not wired into the proof
   pipeline. It is a kernel library. The megakernel lessons argue it should become *instructions* in
   a persistent scheduler, not more standalone launches.

---

## 1. Flapping Airplanes and the megakernel lineage

### Flapping Airplanes

- Founded 2025 by Ben Spector (Stanford PhD student, co-author of ThunderKittens), Asher Spector and
  Aidan Smith. Sequoia lists it as a "foundational AI research lab" focused on data efficiency.
  - https://sequoiacap.com/companies/flapping-airplanes/
  - https://iq.wiki/wiki/flapping-airplanes
- Funding:
  - $180M seed at about $1.5B (GV, Sequoia, Index), early 2026.
  - $1B Series A at a reported $6B, co-led by Index and Lux, with Nvidia participating (Oct 2026).
  - https://en.wowtale.net/2026/10/23/235688/
  - https://hyper.ai/en/stories/4f7c455dafe1288682d6f787e602c64c
- Megakernel claim: the lab runs whole training runs, inference serving "and video games" inside
  **a single GPU program**. The pitch is to overlap memory-bound inference with compute-bound
  training so the GPU is never idle.
  - https://www.digitaltoday.co.kr/en/view/118226/flapping-airplanes-says-megakernel-that-keeps-gpus-busy-boosts-ai-training-efficiency
  - https://superpowerdaily.com/posts/flapping-airplanes-raises-1-billion-to-pursue-more-efficient-ai-training
- **No technical paper, code or numbers are public.** I found no primary blog post. Treat the
  design as the natural extension of Hazy's public megakernel work (below).
- Axionic Labs describes a third-party "persistent learning runtime" on one B200 that trains,
  predicts and runs Doom, built on Stanford's Kittens VM. It shows the public substrate exists.
  - https://axioniclabs.ai/research/rhfm-megakernel

**Relevance to us:** the idea that one persistent program co-schedules memory-bound and
compute-bound work maps directly onto a STARK prover. Merkle hashing and the LDE are bandwidth-bound,
while composition evaluation and PoW are ALU-bound. The prover also has hundreds of small,
heterogeneous components, much like heterogeneous LLM layers.

### Hazy Research, "Look Ma, No Bubbles" (May 2025): low-latency Llama-1B megakernel

Source: https://hazyresearch.stanford.edu/blog/2025-05-27-no-bubbles

- Problem: the batch-1 forward pass is about 100 kernels. Existing engines reach at most ~50% of
  HBM bandwidth because of launch, teardown and tail-drain stalls.
  - Measured launch cost: ~2.1 µs per launch on a stream, ~1.3 µs with CUDA graphs.
  - Tail effect: 512 blocks on 148 SMs leaves ~80 SMs idle at the end of each kernel.
- Design:
  - **On-GPU interpreter.** Each SM runs an instruction list scheduled ahead of time in Python and
    reused across hundreds of passes. All instructions share one template (load, compute, store).
  - Instructions are coarse fused ops, for example "RMSNorm+QKV+RoPE" or
    "O-proj+residual".
  - **Shared-memory paging.** 213 KB of SMEM is split into 13 pages of 16 KiB. Instructions request
    and release pages, and a freed page is handed to the next instruction so its loads start while
    the current instruction is still storing.
  - **Synchronization by global counters.** A producer increments a counter; a consumer spins until
    it reaches a target. Dependencies are chunked: the down-projection waits on 4 separate counters,
    so it starts on the first quarter.
- Results:
  - H100: under 1 ms per pass, ~78% of HBM bandwidth, 2.5× vLLM and 1.5× SGLang.
  - B200: under 680 µs per pass, 3.5× vLLM.
- B200 time breakdown (~600 µs total):
  - ~250 µs on store, readiness check and load at ~500 ns per global load or store;
  - ~200 µs of real math;
  - ~40 µs of warp sync (~60 ns per async barrier);
  - ~80 µs of setup.
- **The lesson:** once launches are gone, *the cost of global-memory handoffs between instructions
  dominates.* Instructions must be coarse enough that a ~1 µs handoff is negligible.

### Hazy throughput megakernel (Sept 2025): tensor-parallel Llama-70B

Source: https://hazyresearch.stanford.edu/blog/2025-09-28-tp-llama-intro

- The CPU generates the instruction schedule and the kernel executes it. Instructions run for
  "tens of µs" to amortize interpreter overhead.
- Warp specialization overlaps memory and compute inside each SM. SMs fetch new work dynamically
  when they finish.
- **Cross-GPU communication is done by remote loads and stores issued inside the kernel, not by NCCL
  on a side stream.** Communication is interleaved at fine grain with local compute.
- Supports 8-way tensor parallelism. Result: +22% end-to-end over SGLang. Lesson: "move more
  decision making to the CPU-side scheduler".

### ThunderKittens and ParallelKittens

- ThunderKittens is built on a few abstractions: register and shared tiles of at least 16×16 with
  managed layouts, plus tile ops.
  - Async primitives: TMA loads, `wgmma` on H100, `tcgen05` on B200.
  - Producer/consumer warp specialization: producer warps issue TMA several stages ahead while
    consumer warps compute.
  - https://arxiv.org/html/2410.20399
  - https://github.com/HazyResearch/ThunderKittens
- ParallelKittens (Sul, Arora, Spector, Ré; MLSys 2026) adds eight primitives for overlapped
  multi-GPU kernels within one node. It reports up to 2.33× on data/tensor-parallel and 4.08× on
  sequence-parallel workloads in under 50 lines of device code. Inter-node is future work.
  - https://arxiv.org/abs/2511.13940v1
- **Limits of transfer:** tensor cores do not help M31 arithmetic. Our math is 31-bit
  multiply-reduce on the integer pipes. What transfers is the *pipeline skeleton*: TMA bulk loads
  into SMEM, producer/consumer warps, mbarrier pipelining and SMEM page recycling.

### Mirage Persistent Kernel (MPK)

- A compiler and runtime that lowers a tensor program to an **SM-level task graph** and runs it in
  one persistent megakernel with decentralised scheduling. A few scheduler warps hand tasks to
  worker SMs, and tasks are triggered by events.
- Reports up to 1.7× lower latency than kernel-per-operator serving. Fine-grained dependency
  tracking that lets compute overlap inter-GPU communication gives another ~1.1×. arXiv 2512.22219,
  Dec 2025, revised June 2026.
  - https://arxiv.org/html/2512.22219v1
  - https://github.com/mirage-project/mirage (branch `mpk`)
  - https://uv-xiao.github.io/blog/2025/mirage-mpk-runtime
- **This is the closest model for our case.** Our component list is a static DAG known before
  proving: preprocessed → main commit → interaction draw → interaction commit → composition → OODS →
  DEEP → FRI → PoW → decommit, repeated for each of hundreds of components. That DAG can be compiled
  once per AIR set and replayed every block.

### NVIDIA building blocks if a full megakernel is too much

- **CUDA graphs** reduce launch cost to ~1.3 µs per node (Hazy measurement). Graphs suit our case
  because the per-block launch topology is fixed once geometry is fixed.
- **Programmatic Dependent Launch (sm_90+).** A secondary kernel's prologue (constant loads, SMEM
  setup, twiddle loads) overlaps the primary's tail. The primary calls
  `cudaTriggerProgrammaticLaunchCompletion()` and the secondary calls
  `cudaGridDependencySynchronize()` before it reads dependent data. PDL also works as programmatic
  edges inside graphs. Overlap is "opportunistic".
  - https://docs.nvidia.com/cuda/cuda-programming-guide/04-special-topics/programmatic-dependent-launch.html
- **Thread-block clusters and DSMEM (sm_90+).** Up to 8 CTAs (16 non-portable on H100) can read,
  write and do atomics on each other's shared memory. Accesses should be coalesced into 32-byte
  segments.
  - https://docs.nvidia.com/cuda/archive/12.2.1/hopper-tuning-guide/index.html
  - **Use for us:** a 16-CTA cluster has ~3.5 MB of combined SMEM. That is enough to finish the top
    ~16–18 levels of a Merkle subtree, or several upper NTT stages, without touching HBM.
- **CUTLASS/CuTe persistent tile schedulers (stream-K style).** These show how to remove wave
  quantization: tiles go to persistent CTAs from a work counter instead of to a grid. This applies
  directly to our heterogeneous-height components.

---

## 2. GPU ZK provers and real-time Ethereum proving: published state

| System | Date | Hardware | Latency claim | Notes / source |
|---|---|---|---|---|
| ZKsync **Airbender Prime** | Oct 13 2026 | **1× RTX PRO 6000 Blackwell** (96 GB) | 99% of 7,200 blocks < 10 s, all < 12 s; claims top Ethproofs time, GPU efficiency and cost | Hash-based STARK over M31 (DEEP-FRI, per secondary coverage), RISC-V. Avg, security bits and proof size undisclosed. [cryptobriefing](https://cryptobriefing.com/zksync-airbender-real-time-prover-vitalik/), [digitaltoday](https://www.digitaltoday.co.kr/en/view/115886/zksync-unveils-airbender-prime-ethereum-zero-knowledge-prover) |
| Airbender v1 | Jun 2025 | 1× H100 | ~17 s/block before recursion, ~35 s with recursion; 21.8 MHz (RISC-V cycles/s) on H100 | CPU simulates and traces; GPU does witness gen and the rest. [zksync.io/airbender](https://zksync.io/airbender), [mirror](https://zksync.mirror.xyz/ZgRmbYA_EE3wfGcXWv81m-xcED-ppNKkRzkleS6YZRc) |
| **ZisK** v1.1.0-alpha | Aug 18 2026 | 4× RTX 5090 | p99 9.62 s; 99.7% < 10 s; 128-bit claimed | Block range, sample, proof size and power not published; not yet on Ethproofs. [cryptoslate](https://cryptoslate.com/ethereums-12-gpu-proving-problem-just-got-a-4-gpu-answer/) |
| ZisK | Nov 2025 | 24× RTX 5090 | avg 6.56 s; 99.74% < 12 s | RV64IMA, Goldilocks eSTARK (pil2). [aligned blog](https://blog.alignedlayer.com/the-year-of-zkvm-real-time-proving-milestones-present-and-future/) |
| **SP1 Hypercube** | 2026 | 16× RTX 5090 | 99.7% of 954 blocks < 12 s; 95.4% < 10 s | Multilinear, jagged PCS, LogUp-GKR; formally verified RISC-V constraints. [succinct](https://blog.succinct.xyz/real-time-proving-16-gpus/) |
| SP1 Hypercube v1 | May 2025 | ~160× RTX 4090 | 93% < 12 s, avg 10.3 s | [succinct](https://blog.succinct.xyz/sp1-hypercube/) |
| Brevis Pico Prism | Oct 2025 → 2026 | 64× 5090, later 16× 5090 | avg 6.04–6.9 s; 99.6% real-time, later >99% on 16 GPUs | Two-stage distributed pipeline, near-linear scaling claimed. [4pillars](https://4pillars.io/en/issues/pico-prism-one-stone-two-wins-speed-and-efficiency), [kucoin](https://www.kucoin.com/news/flash/brevis-upgrades-pico-prism-zkvm-to-achieve-99-ethereum-real-time-proof-with-16-gpus) |
| OpenVM 2.0 | 2026 | 8× RTX 5090 | p99 9.8 s over 7,200 blocks from 24,000,000 | 100-bit provable security, proofs < 300 kB. [cryptoslate](https://cryptoslate.com/ethereums-12-gpu-proving-problem-just-got-a-4-gpu-answer/) |
| RISC Zero | 2025 | ~$120K cluster (projected) | ~9.25 s projected end to end | [risczero](https://risczero.com/blog/making-real-time-proving-accessible) |
| Cysic Venus | 2026 | single node | avg 1 m 54 s (vendor) | Open-sourced. [blockeden](https://blockeden.xyz/de/blog/2026/04/17/cysic-venus-multi-gpu-zk-proving-real-time-verification-bottleneck/) |

**EF real-time target and Ethproofs timing rules**

- The EF real-time target (Jul 2025) sets the bar for everything above:
  - p99 ≤ 10 s
  - CAPEX ≤ $100k
  - power ≤ 10 kW
  - ≥ 128-bit security
  - proofs ≤ 300 KiB
  - no trusted setup
  - fully open source
- Ethproofs measures time *including witness generation* but excluding RPC data fetch.
- Ethproofs 2025 review: the site-wide average went from 16 m 44 s to 15.9 s, and single-GPU time
  from ~16 min to under 60 s.
  - https://hackmd.io/@willcorcoran/ry16VMmfbx
- **Implication for our claims:**
  - Our 96-bit conjectured setting (70 queries, blowup 2, 26-bit PoW) does not meet the 128-bit
    criterion.
  - Any "< 2 s" claim must state its timing boundary in the Ethproofs sense, including witness
    generation and recursion down to a ≤ 300 KiB proof.
  - The fair comparison is p99, not average.

**StarkWare stwo on GPU**

- No first-party CUDA backend is public. ZAN and AntChain OpenLabs were announced to be adding GPU
  acceleration.
  - https://www.theblock.co/post/377248/starkware-deploys-s-two-prover-starknet
- Nethermind's `stwo-gpu` is a community CUDA backend that appears stale.
  - https://awesome.ecosyste.ms/projects/github.com%2Fnethermindeth%2Fstwo-gpu
- zkSecurity's WebGPU stwo work measured 5× on constraint evaluation and 2× overall.
  - https://blog.zksecurity.xyz/posts/webgpu/

**ICICLE (Ingonyama)**

- In Aug 2024, Ingonyama announced an end-to-end stwo-on-ICICLE port with Starknet.
  - https://medium.com/@ingonyama/ingonyama-x-starknet-strategic-partnership-af22539d41b2
- I found no published M31 circle-NTT, Poseidon2-M31 or Blake2s throughput numbers for ICICLE, and
  no confirmed release of an ICICLE stwo backend. ICICLE v3 only said Blake2s was "soon".
  - https://medium.com/@ingonyama/icicle-v3-1c9cc2f94402

**Hash and Merkle data points**

- NVIDIA cuPQC-Hash ships Poseidon2 over BabyBear and KoalaBear for Merkle trees. It has a
  single-block mode (one CTA builds one whole tree) and a multi-block mode. It reports 48–147× an
  EPYC 9124 on an RTX PRO 6000. It has no M31 and no Blake2s.
  - https://docs.nvidia.com/cuda/cupqc/libraries/cupqc_hash/cupqc_hash_feature.html
  - https://nvidia.github.io/cuPQC/blogs/merkle/
- A single unreviewed blog reports, on one H100 (treat as indicative only):
  - a Poseidon2-M31 width-16 tree of 2^25 leaves in 780 ms;
  - a fused sumcheck round (g(0), g(1) and the leading coefficient in one pass) at 14 ms per 2^25
    round;
  - ~92% HBM utilization;
  - only ~4× on 8× H100, because of an all-reduce after every sumcheck round.
  - https://vaamx.github.io/articles/cuda-kernels-m31.html
- The last point is a warning for PR #311's 2/4-GPU sumcheck planning: **do not shard one sumcheck
  across GPUs; shard proofs/segments.**

### ZisK GPU engineering (from release notes, the most concrete public evidence)

v1.3.0-alpha (https://newreleases.io/project/github/0xPolygonHermez/zisk/release/v1.3.0-alpha):

- Per-AIR **constraint expressions compiled into GPU kernels at setup time**, replacing the runtime
  expression interpreter.
- **Prefetch of the next proof's traces onto the device while the current proof runs.**
- **Ring of completion slots that removes per-proof host synchronization.**
- One large stream per GPU, split into two halves for recursion and small proofs once the large
  instances finish.
- Recursion runs concurrently with base proofs throughout.
- Main-trace commits run in streaming slots alongside GPU memory planning.
- Fewer, larger AIR instances: lane packing (several ops or steps per row), with the planner
  preferring fewer instances over lower memory use.
- Batch inverses; a fused circom witness solve and scatter that halves recursive witness generation.

v1.1.0-alpha (https://newreleases.io/project/github/0xPolygonHermez/zisk/release/v1.1.0-alpha):

- Memory arithmetization (mops) ported to GPU.
- Main witness generation overlapped with ASM execution.
- Less stream synchronization.
- BLAKE2b reduced from 24 to 8 rows per round.

Witness pipeline (third-party analysis, https://hackmd.io/@0xdeveloperuche/rkd1vBsElx): an AOT x86
emulator emits a *minimal trace*. Parallel workers then re-execute "memoryless" from checkpoints to
build the full witness. Our RV64 capture can feed per-segment GPU witness builders the same way.

---

## 3. Transferable techniques for our Circle-STARK GPU prover, ranked by expected latency effect

Basis for the effect estimates: ~5.1 G committed cells per block; GPU floor ~0.25–0.5 GPU-s;
7 CPU segments of 2^22 plus Keccak and other shard proofs; target < 2 s wall on N GPUs.
Estimates are reasoned, not measured.

1. **Segment-parallel sharding, never intra-proof sharding.**
   - Give each GPU whole proofs: CPU segments, Keccak shards and memory proofs. Run a greedy
     longest-processing-time schedule over a pre-computed cost model (cells × per-AIR coefficient).
   - Cross-GPU traffic is then only the commitment roots and the recursion inputs (KBs).
   - SP1, Pico and ZisK all shard this way. The 8× H100 sumcheck data point (4× on 8 GPUs) shows the
     alternative fails.
   - Critical path: Keccak truth0 (698M cells, 14 s on CPU) must be split into ≤ ~1/N-block-sized
     shards, or it alone sets the latency floor.
2. **Persistent per-GPU proof engine with a CPU-compiled schedule (megakernel-lite).**
   - The per-AIR-set proof DAG is static. Compile it once into a per-SM or per-stream instruction
     list, as Hazy and MPK do. Run it as either:
     - (a) CUDA graphs with PDL edges (low effort), or
     - (b) a persistent interpreter kernel with global-counter dependencies (high effort).
   - Instructions must be coarse, ≥ ~20–50 µs each. Examples:
     - "LDE+leaf-hash for column-batch k";
     - "composition for component c over rows [a,b)";
     - "FRI fold layer j + Merkle".
   - Hazy measured ~1 µs per handoff, so 1,000 instructions per block costs ~1 ms. Today's design
     has thousands of launches at 2–8 µs each, plus a host sync per transcript draw.
3. **Device-resident Fiat-Shamir across the whole proof.**
   - PR #311 already does this for one LogUp sumcheck: 44 words of readback per round, Blake2s
     sampling on device.
   - Extend it to the OODS point, DEEP α, FRI folding challenges and **PoW grinding on device**.
     PoW is 26 bits per proof: ~6.7e7 Blake2s hashes, about 1–3 ms on a 5090, but a host round trip
     each time.
   - A proof should cost zero host syncs until final readback. This is the counterpart of ZisK's
     completion-slot ring.
4. **On-device witness generation fed by a minimal trace.**
   - Ship compact execution records over PCIe and expand them to main and interaction columns on
     the GPU. Main cells alone are ~20 GB, ≈0.4 s over PCIe5.
   - Overlap witness generation for segment k+1 with proving segment k (ZisK prefetch). This is the
     biggest wall-clock item after sharding (cost-per-cell §3).
5. **Per-AIR compiled constraint kernels, fused with the quotient accumulation.**
   - Composition is 36% of core time. Generate one CUDA kernel per component, or per group of
     similar components, from the AIR description at build time, as ZisK v1.3 does. Do not use a
     generic interpreter.
   - Each kernel reads the extended trace tiles once from SMEM (TMA producer warps, consumer warps
     evaluating constraints) and accumulates directly into the composition quotient.
   - For hundreds of small components, use a persistent kernel with a work queue of
     (component, row-tile) pairs, stream-K style, so small components do not leave SMs idle (the
     Hazy tail effect).
6. **Fused LDE → leaf hash → (optionally) composition.**
   - In each row tile, run the circle iFFT/FFT in registers and SMEM (upper stages via cluster DSMEM
     on sm_90+). Hash the leaves immediately. Write the extended evaluations back only if they are
     needed later.
   - With blowup 2, recompute versus store is a VRAM-versus-time trade. A 2^22 segment needs about
     5.3 GB extended, which fits easily, so store.
   - Hash the lower ~16 Merkle levels inside a CTA or cluster in SMEM, and only the top levels in a
     second pass. Use the lifted leaf trick (read narrow columns at `idx >> shift`) from
     cost-per-cell lever 5.
   - Use Blake2s or Blake3 at the base layer. A Poseidon2-M31 2^25 tree is reportedly ~780 ms on an
     H100; Blake2s should be ~5× cheaper per byte.
7. **Fewer, larger proofs (lane packing).** ZisK moved toward fewer AIR instances because fixed
   per-proof cost dominates small proofs. Our small truth proofs are 82% PoW. Merge them, or batch
   their PoW and FRI tails.
8. **Recursion pipelined, not tailed.**
   - Start recursion on each segment proof as soon as it lands, on a split stream (ZisK), so only
     the last 1–2 aggregation levels sit on the critical path.
   - Airbender's own numbers show recursion doubles single-GPU latency (17 s → 35 s); Prime removed
     most of that.
   - Our H200 Cairo fold is 1.3–2.9 s today, which by itself breaks the 2 s goal.
   - A recursion verifier AIR should use the same compiled-kernel path and a Poseidon2/M31-friendly
     channel.
9. **In-kernel P2P for aggregation inputs.** Push segment roots and claims to the aggregator GPU
   with remote stores over NVLink or PCIe P2P from inside the kernel, ParallelKittens style. NCCL is
   unnecessary at these sizes; this only matters if recursion is spread across GPUs.

## 4. Notes on PR #311 (`codex/rv64-cuda-resident-gkr`)

Checked via `git show`; no checkout.

- Commits:
  - `93bfb2fdb`: resident OM31 lookup and GKR engine
  - `bccab6077`: resident sumcheck feedback and proof assembly
  - `43148eba1`: Eq-expansion fusion and four-way tuning
  - `771334a93`: fold + next-round-sum fusion
- Diff size: 72 files, +5,264 lines.
- **Strengths, in line with the research:**
  - no allocation, host transfer or sync in the numerical loop;
  - deterministic reductions with no extension-field atomics;
  - fold/next-sum fusion removes ~256 MiB of reads and 20 launches at 2^22 (source model);
  - on-device Blake2s challenge sampling.
- **Gaps against the megakernel and ZK state of the art:**
  - **Zero hardware execution.** Every gate exits 77, and no Nsight, sanitizer or timing data
    exists. Register pressure is unprofiled: 128 regs/thread for the secure numerator and fused
    first stage on sm_120, with 192 B of stack in round control on sm_89.
  - The engine is not wired into the proof pipeline. PCS, DEEP, FRI and witness ingress are
    still host-side.
  - The 2/4-GPU "credit scheduler" shards jobs, which is correct. Keep it at proof or segment
    granularity; do not split one sumcheck across devices.
  - Many small launches per round remain. This is a direct candidate for CUDA graphs plus PDL now,
    and later for a persistent instruction-interpreter kernel.
- **Next step:** rent one 5090 or RTX PRO 6000 for an afternoon and get the first real-device
  parity and Nsight trace. Every later decision depends on measured launch gaps and occupancy, and
  the repo has no RV64 GPU cells/s receipt.

## 5. Open questions and what to verify

- Ethproofs entries (ZisK 4×5090, Airbender Prime): what timing boundary and security level do they
  use? Fetch the API when reachable.
- Airbender Prime internals: is it M31 + DEEP-FRI, what recursion depth, and does it use a
  persistent or fused kernel design? The `matter-labs/zksync-airbender` `gpu_prover` source should
  answer this. It is the closest architectural analogue to us: an M31 RISC-V STARK proving a whole
  block on one GPU.
- Flapping Airplanes publications: monitor for a technical release. None is public as of
  2026-11-02.

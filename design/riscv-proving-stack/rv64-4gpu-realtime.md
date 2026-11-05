# RV64 Ethereum proving in under 10 s on 4×RTX 5090: the lever map

Status: engineering design document, 2026-11-05. It is meant to drive M8 and later work.
Baseline: M6 integrate (`codex/rv64-cuda-ethereum` @ 26ca20793), plus the M7 measurements the team reported mid-milestone.
Labels:
- **[M]** measured; a receipt exists in `vectors/reports/`.
- **[D]** arithmetic on measured numbers.
- **[E]** estimate.
- **[src]** stated by an external source (linked).

Models used for the numbers below:
- `fit.py`: per-stage scaling fits.
- `levers.py`: lever composition.
Both were written during the research for this document. They should be committed under `scripts/` before anyone quotes these numbers.

---

## 0. Executive summary

**Goal.** Prove the *largest* blocks of our basket in under 10 s on **4×RTX 5090**, at conjectured-128-bit security, hash-based only (post-quantum, no SNARK wrap). The largest is 26235159: 57.7 M gas, 204.8 M RV64 instructions, 49 CPU segments, 26 precompile "truth" proofs.

**The frontier has already done this on four GPUs.**
- ZisK reports a 9.62 s p99 on 4×RTX 5090 [src, self-reported, workload not disclosed].
- Airbender Prime reports 99% of 7,200 blocks under 10 s on one RTX PRO 6000 [src]. It runs at 80–100-bit security, not 128.
- SP1 Hypercube and Brevis Pico Prism report 99%+ under 10–12 s on 16×5090 [src].

**Where we are.**
- 24628607: 17.3 s on 2 GPUs [M, M7 in progress].
- 26235159: estimated 79–100 s on 2 GPUs and 42–55 s on 4 GPUs with today's code [E].
- Large blocks gained far less than the dev blocks. 24697070's recursion improved only ×0.69 and its native prove ×0.96 from M3 to M6. The M4–M7 wins were mostly fixed per-request costs and host time.

**The central model says 6.0 s on 4 GPUs for 26235159** (pessimistic 11.1 s, optimistic 3.7 s) [E]. That requires these levers. "Necessary" means removing it pushes the central case over 10 s.

| # | lever | what it buys | necessary? |
|---|---|---|---|
| 1 | **Parallel capture** (checkpointed, parallel traced replay, ≥100 MIPS aggregate) | capture 16 s → ≤1.5 s head | **yes, in every scenario** |
| 2 | **Native GPU efficiency** (GPU witness, streaming commit, fusion, async host) | ×2.7 kernel throughput, ×5.3 at wall level | **yes** (central and pessimistic) |
| 3 | **A recursion cell cut of about ×0.2 or better** (recursion-friendly hash, *or* fewer leaves × outer GKR) | recursion work from 7.8× native down to ~1.5× native | **yes**, through at least one route |
| 4 | **Occupancy**: device Fiat–Shamir, CUDA graphs, 2 nodes per GPU, SM partitioning | GPU busy 42% → 85% | strongly helps (8.4 s without it) |
| 5 | **Fewer leaves**: truth batching, 2^23 rungs | 75 → ~20–25 leaves | helps; the cheapest route to lever 3 |
| 6 | outer GKR, native GKR, precompiles, comb aggregation, D2 | 5–15% each | helps; D2 *hurts* once recursion is cheap |

**Recommended architecture:**
- **Poseidon2-M31 width 24** for every tree and transcript that recursion verifies (native and every recursion layer), with **Keccak only on the final on-chain layer**. A reviewed W24 substrate already exists on `codex/rv64-m7-integrate`.
- **Batched truth proofs** at high blowup.
- **2^23 canonical CPU rungs.**
- **Capacity-fit k-ary aggregation in a comb topology.**
- **A GPU-resident, enqueue-only pipeline** built with the persistent-kernel and device-Fiat–Shamir patterns of chapter 8.
- **Parallel capture.**

The plan for M8–M10 is in chapter 11.

---

## 1. Target and budget

### 1.1 The block

Source: `vectors/reports/rv64-cuda-real-segment-20261103/basket-input-readiness.json` [M]; M3 times from `rv64-m3-20261104/summary.json`.

| block | gas | instructions | instr/gas | CPU segments | truth proofs | leaves | M3 (2 GPUs) |
|---|---:|---:|---:|---:|---:|---:|---:|
| 24628607 (headline) | 7.37 M | 26.9 M | 3.648 | 7 | 10 | 17 | 51.1 s |
| 26235159 (largest) | 57.73 M | 204.8 M | 3.548 | 49 | 26 | 75 | 250.5 s |

Across the basket, instructions per gas range from 2.71 to 3.89.

Untraced native execution of 26235159 takes 1.22 s on one thread (168 MIPS) [M].

### 1.2 M3 scaling fits (2 GPUs, 15 blocks) [D]

| stage | fit | R² | at 26235159 | measured |
|---|---|---:|---:|---:|
| capture | 1.25 + 0.0722·Minstr | 0.950 | 16.0 | 16.5 |
| setup (cold) | −0.12 + 0.424·Minstr | 0.985 | 86.7 | 93.1 |
| native | 1.11 + 0.192·Minstr + 0.141·truths | 0.994 | 44.0 | 43.7 |
| recursion | 6.49 + **1.196·leaves** | 0.997 | 96.2 | 96.4 |

**Recursion time tracks the number of leaves, not instructions.** Every lever that cuts leaves cuts recursion time roughly in proportion.

### 1.3 The 10-second budget on 4 GPUs (26235159)

| item | s |
|---|---:|
| admission, warm setup, publication | 0.4 |
| capture head (first segment ready) | 0.4 |
| native + leaves + lower folds, overlapped (busy 0.85, 18.7 GPU·s) | 5.5 |
| recursion tail (last leaf + fold levels) | 1.5 |
| compress (C1 + C2) | 1.5 |
| slack | 0.7 |

What this budget implies [D]:
- **Native:** ≤11 GPU·s, i.e. **18.6 M instructions per GPU-second of kernel time** (15.8 MHz per GPU at wall level).
  - Today: 6.84 kernel and 3.0 wall, so we need ×2.7 in kernels and ×5.3 at wall level.
  - In cells: 0.265 ns per base cell, against 0.72 today.
- **Recursion:** ≤8.9 GPU·s.
  - At today's 0.29 ns/cell [M, M6 k4-cap3] that allows ≤30.7 G cells, about **150 recursion cells per instruction**.
  - Today: about 760 on 26235159 (per-leaf scaling) and 1,331 on 24628607. We need ×0.19.
- **Tail:** each serial node ≤0.3 GPU·s, against leaf 0.47 and fold 0.42 today. Host prep ≤0.1 s per node.
- **Capture:** ≥45 MIPS aggregate just to keep pace; ≥100 MIPS recommended. Today: 13.6 MIPS on 24628607.
- **Host-to-device traffic:** ≤150 B per instruction recommended. The whole one-shot request today is 1,565 B per instruction [D], which fails.

### 1.4 Hardware floors on the RTX 5090 [E]

Assumptions: 1.79 TB/s memory bandwidth, about 52 T int ops/s, 32 GB, PCIe 5 x16 at 50–64 GB/s.

| work, 26235159 | bandwidth floor (4 GPUs) | compute floor | today's kernels at 100% busy (4 GPUs) |
|---|---:|---:|---:|
| native commit (84 G LDE cells, ~10.4 G Blake compressions) | 0.21–0.47 s | 0.19 s | 7.5 s (0.72 ns/cell ≈ 6% of peak bandwidth) |
| recursion at today's cells (~116–156 G) | 0.78–1.74 s | ~0.7 s | 11.3 s |
| recursion ×0.15 | 0.12–0.27 s | — | 1.7 s |

- **Native kernels sit 15–35× above the hardware floor, and recursion kernels 6–15× above it.** There is plenty of room, but it comes from the kernels themselves, not only from keeping GPUs busy.
- PCIe is not the binding limit once host-to-device traffic is at or below about 170 B per instruction (≤0.2 s on 4 links).

### 1.5 Lever composition (`levers.py`, 4 GPUs) [E]

| block | pessimistic | central | optimistic | proof-neutral levers only | today's code |
|---|---:|---:|---:|---:|---:|
| 24628607 | 4.99 s | 2.99 s | 2.02 s | 8.45 s | 10.7 s |
| 26235159 | **11.1 s** | **6.0 s** | **3.7 s** | 26.9 s | 41.8 s |

Removing one lever at a time (26235159, central): native efficiency → 12.0 s ✗; parallel capture → 12.8 s ✗; occupancy → 8.4 s; recursion hash → 7.9 s; outer GKR → 6.5 s; leaf count → 6.8 s; native GKR → 6.7 s; precompiles → 6.4 s; D2 → 5.4 s (better without it).

The smallest central sets that still beat 10 s:
- {native efficiency, occupancy, recursion hash, parallel capture}: 9.49 s;
- {native efficiency, recursion hash, leaf count, outer GKR, parallel capture}: 8.89 s.

---

## 2. Where the work goes today

### 2.1 Committed cells, 24628607

Source: M6 native protocol, `rv64-m7-20261105/native-layout/model.json`, equal to the measured tree words.

| tree | cells | per instruction | per gas |
|---|---:|---:|---:|
| fixed | 0.259 G | 9.6 | 35 |
| MAIN | 2.703 G | 100.5 | 367 |
| INTER | 1.854 G | 68.9 | 251 |
| composition | 0.638 G | 23.7 | 87 |
| **native total** | **5.454 G** | **202.8** | **740** |
| native, native GKR v1 [D] | 4.504 G | 167.5 | 611 |
| **recursion (k4-cap3, 23 nodes)** | **35.79 G** | **1,331** | **4,854** |

**Recursion is 6.6× the native cells.** In-circuit Blake2s is about 74–85% of leaf cells:
- each leaf proves about 72k–100k Blake2s compressions per verified native proof [M/D];
- at about 8.7k–22.7k committed cells per compression, depending on padding [M/D].

### 2.2 Against ZisK, in LDE bits per gas

Fixed trees are excluded on both sides. ZisK figure from block 25701329, 59.98 M gas [src via repo file `rv64-ethereum-20261101/committed-work-comparison-v1.json`].

| tree | ours [D] | ZisK | ZisK ÷ ours |
|---|---:|---:|---:|
| MAIN | 22.7 k | 64.3 k | 2.83 |
| INTER | 15.6 k | 28.3 k | 1.82 |
| composition | 5.4 k | 2.5 k | 0.47 |
| **native total** | **43.7 k** | **95.2 k** | **2.18** |
| **including our recursion** | **≈345 k** | 95.2 k (native only) | — |

**Our native work per gas is already about 2× below ZisK. Our recursion is what puts us behind.** Caveats: the blocks and their Keccak share differ, the security regimes differ, ZisK's area figure excludes padding, and ZisK's own recursion is not in this figure.

### 2.3 The time sinks measured in M6/M7

| sink | measured |
|---|---|
| Recursion is host-latency bound | Leaves needed 1.6–2.1 s of host prep each (M7 leaf tape: recursion 12.4 → 10.7 s). The leaf witness DAG had 146k levels; 73k after GPU Blake prefill. |
| GPUs idle | 41.6% busy in the recursion window; 123 blocking calls and 1,774 launches per node. |
| Native | 4.45 s with kernel busy 1.5–2.4 s per GPU; owner-thread callbacks are synchronous; 213 B per instruction host-to-device. |
| Capture | 2.07 s: image init 0.5 s, batch-0 0.45 s, serial ledger 0.5 s. |
| Memory | Outer GKR workspace 17.65 GB OOM; RSS 23.6 GiB; no global memory planner. |

---

## 3. Lever map

| layer | lever | metric | today | target | chapter |
|---|---|---|---|---|---|
| guest | missing precompiles (BN254, BLS12-381, KZG, blake2f, P-256) | instructions per gas on heavy blocks | 2.7–3.9 | −20–35% on blocks that use them | 4 |
| guest | interpreter, trie and memory hot paths | instructions per gas | 3.55 | −10–20% | 4 |
| native AIR | native GKR, zero rung padding, narrower Keccak | committed bits per gas | 740 cells/gas | ≤550 | 4 |
| native GPU | GPU witness, streaming commit, fusion, async host, graphs | ns per base cell | 0.72 | ≤0.25 | 5, 8 |
| recursion | recursion-friendly hash | cells per leaf | 1.2–1.9 G | 0.3–0.5 G | 6, 7 |
| recursion | truth batching, 2^23 rungs, capacity-fit arity | leaves per block | 75 | 20–25 | 6 |
| recursion | outer GKR, GKR-proven hashing, hand-designed verifier AIR | cells per leaf, witness depth | — | ×0.57 / ×0.3 / O(10) levels | 6 |
| recursion | comb topology, streaming schedule | tail after the last leaf | 2.15 s | ≤1.5 s | 6, 9 |
| orchestration | parallel capture | MIPS | 13.6 | ≥100 | 9 |
| orchestration | key-affinity scheduler, 4-GPU placement, memory planner | GPU busy | 42% | ≥85% | 8, 9 |
| protocol | grinding 20→26, Merkle caps, per-layer FRI schedule, per-family blowup | queries per leaf | 108 | −5–30% | 10 |
| final | two-stage compress, Keccak last layer | proof size, tail | 709 KB | ≤120 KB, ≤1.5 s | 10 |

---

## 4. Guest and statement levers

### 4.1 Instructions per gas

- We run at 3.55–3.65 instructions per gas [M], using the evmone stateless client and RV64IM.
- Delegated today: Keccak, secp256k1 (ECDSA recover), SHA-256, arith256 (bigint/modexp), MUL/DIV, bulk memory.
- **Not delegated:** **BN254 ecAdd/ecMul/ecPairing (0x06–0x08), BLS12-381 (EIP-2537, 0x0b–0x11), KZG point evaluation (0x0a), blake2f (0x09), P-256 (RIP-7212), RIPEMD-160.**
  - On a block that calls any of them, they run as RV64 software. A BN254 pairing alone runs to millions of instructions.
  - Large mainnet blocks are where rollup verifier calls (BN254 pairings) and blob checks (KZG) concentrate.
- **Action.** Run instruction attribution on the 4 largest blocks first:
  - categories: interpreter dispatch, MPT/Keccak, memory copies, RLP, each precompile;
  - tools: `scripts/riscv64_ethereum_profile.py`, `scripts/rv64_function_census_merge.py`.
  - Then build delegations in order of instructions saved, starting with BN254 and KZG/BLS. Each needs a truth AIR with its own soundness note.
  - A delegation only pays if its truth-proof cells per call are well below the RV64 cells it replaces. Measure that ratio before committing.
- Interpreter-level work (the earlier guest-efficiency sessions took 14.1 → 3.13 instructions per gas) has diminishing returns. Profile first.

### 4.2 Committed bits per instruction

- MAIN is 100.5 cells per instruction, and that is already lean: ZisK pays 68 Goldilocks columns per step, about 2.8× more in bits.
- **Native GKR v2-gkr in production:** INTER 2,270.7 → 1,124.2 M on the strict classes [D], and Keccak truth 742.8 → 110.4 M [D]. Needs the CUDA cap raised to 128 oracles (WIP on `codex/rv64-m7-native-gkr` @ 3d5ace6d7).
- **Rung padding tax must go to zero.** v2-strict currently costs +16–22% cells [M]. Use finer rungs or a rung choice per component.
- **Keccak** is the largest native component. A narrower Keccak AIR, or Keccak lookups streamed straight into GKR, is the next native-AIR lever after native GKR.
- **Shared eq/prefix binding columns** across components of the same row log. These are about half of what remains of INTER after v2-gkr.

---

## 5. Native prover: GPU kernels and full residency

**Target:** ×2.7 kernel throughput and ×5.3 at wall level per GPU.

| lever | today [M] | design | effect [E] |
|---|---|---|---|
| GPU witness from compact records | host projection; 17.5 B/row metadata after M7 (from 56) | Upload the RV64 program, the decode table and a compact execution record once, then widen every native column on the device (ZisK gpu-witness; OFA "K_DATA gather", chapter 8 J) | host-to-device traffic ≤80 B per instruction; removes host projection from the critical path |
| Streaming commit | full LDE materialised before hashing | Per column chunk: unpack, iNTT, LDE, then leaf hash in one pass (ZisK `stream_commit.cuh`). Never write the LDE back unhashed. | about −40% HBM traffic; memory headroom for concurrency |
| Kernel fusion | separate composition, quotient and FRI passes | Fuse the last circle-FFT butterfly with the Merkle leaf hash. Fuse constraint evaluation, the quotient and the first FRI fold. Fuse each GKR layer with the next round's first pass (chapter 8 D). | one HBM round trip and one barrier saved per fused pair |
| Async host | callbacks run synchronously on the owner thread; kernel busy 1.5–2.4 s of 4.45 s | Mapped-memory progress counters, an enqueue-only contract and device Fiat–Shamir (chapter 8 I) | busy ≥85% |
| Native CUDA graphs per class | — | Strict-roster classes are fixed-shape, so a graph can be captured once per class | removes launch overhead (thousands of launches per proof) |
| Batched launches across segments | per-segment launches | One launch covers the same AIR across k segments | fewer, larger kernels |
| Memory planner | OOMs (17.65 GB GKR, 16.6 GB merged Keccak plane) | One static plan per (class, GPU) covering native retention, recursion leases and GKR workspace. Liveness-based reuse. Admission fails before launch, not mid-proof. | 2 jobs per GPU become safe |
| Retention for large blocks | all-or-nothing per device (>4 segments per GPU → replay-all) | A byte budget per device | large blocks keep native-stream's gain |

**Roofline discipline.**
- Build a per-kernel table of DRAM bytes, SM ops and achieved fraction of peak.
- `ncu` is not available in the pod container (ERR_NVGPUCTRPERM), so either get counter access or derive the numbers from in-kernel `%globaltimer` and a byte model (chapter 8 N).

---

## 6. Recursion redesign

### 6.1 What the frontier does

| system | recursion structure | hash | node size | children per node | notes |
|---|---|---|---|---|---|
| ZisK / pil2-proofman | basic → compressor → recursive1 → recursive2 tree → vadcop_final (fixed 2^18) | **Blake3** over Goldilocks (default) or Poseidon2 | ~2^19 rows × ~300 columns | capacity-fit (`recursion_batch_fit`), arity 2 for blake3 | Compiled Circom → Plonk verifier, with custom Blake3 gates; arithmetic packed into Blake-row interiors; log blowup 2, FRI fold 8, 24–27 grinding bits, 5–6 Merkle levels carried in the proof [src] |
| Airbender, Airbender Prime | the zkVM verifies itself: a Rust verifier on a reduced machine; linear chain base → unrolled → unified | Blake2s (reduced-round) | 2^20–2^24-cycle chunks | chain (horizontal chunks) | GKR + WHIR, 80–100-bit [src] |
| SP1 Hypercube | normalize (constant VK) → compress groups of 3–4 → shrink | Poseidon2 KoalaBear | — | 3–4 | multilinear, jagged PCS commits only real data; one stacked opening per verify [src] |
| RISC Zero | lift / join / resolve on a small recursion VM | Poseidon2 BabyBear | — | 2 | ~200 kB receipts [src] |
| Plonky3-recursion | hand-designed fixed-shape table circuit with FRI-fold and Merkle-path chips | Poseidon2 | — | 2 | second and later layers ~100 ms on an M4 Pro CPU [src] |
| leanVM | 2→1 in 542k VM cycles, 2^24 committed elements, 0.31 s CPU | Keccak proven via GKR (state committed every 12 rounds) | 2^24 | 2 | **~6k hash permutations per verified proof, against our ~100k** [src] |
| Stwo-Cairo | Cairo verifier in the Cairo VM; circuit multiverifier | Blake2s (lifted VCS) | — | 2 | 96-bit defaults [src] |

The common pattern:
1. One fixed recursion circuit or VM, with a constant VK.
2. Children per node chosen by capacity.
3. Nodes of 2^19–2^24 committed elements. **Ours are about 2^30.**
4. Few queries per child.
5. Recursion-friendly hashing, or GKR-proven hashing.

### 6.2 Redesign options

| option | design | effect [E] | risk | kill criterion |
|---|---|---|---|---|
| **(c) Truth batching — do first** | One multi-component proof per truth family, or all families together, at b16 q27 p20 (truth traces are small). Split into an early batch and a late batch so only the late one is in the tail. | 24628607: leaves 17 → 8–9. 26235159: 26 truth leaves → ~3, saving 25–30 G cells. | low | batched truth leaf wall >1.5× a CPU leaf, or the late-batch tail >0.5 s |
| **(d) Per-family blowup and grinding** | Truth at b16; outer at m3_b4_q51_p26; query grinding 20 → 26 (−5% queries). CPU segments at b4 (D2) only while recursion stays expensive. | b4 per leaf ×0.52–0.55, b8 ×0.36–0.40; native LDE ×2 / ×4 | low | added native GPU·s exceed the recursion GPU·s saved in a paired A/B (the model says D2 loses once the hash change lands) |
| **(b1) 2^23 rungs** | Leaf cost grows only log-wise with segment size | 49 → ~25 CPU leaves; cells per segment ×0.55 | low | padding tax >25%, or device peak >28 GB (2^24 does not fit at b4) |
| (b2) shared FRI across k segments | One OODS point and one FRI over k DEEP quotients behind a group barrier | ×0.7–0.8 per segment at k = 4 | medium | FRI <25% of leaf compressions (needs the per-origin census) |
| (b3) shared Merkle trees across k segments | Lifted VCS, one tree per phase | ×0.45–0.6 per segment | medium | needs k LDEs resident; conflicts with streaming |
| **Recursion-friendly hash** | chapter 7 | leaf ×0.20–0.25 | medium | S1 GPU throughput or S3 exact cell census misses |
| **(h1) GKR-proven Blake2s** — the alternative to switching hash | Commit Blake inputs, outputs and maybe one mid-state; prove the rounds as uncommitted GKR layers (leanVM, Airbender v3) | hash cells ×0.15–0.3, about ×0.3–0.45 per leaf | medium-high: XOR/rotate through limb lookups; soundness budget at ~124-bit QM31 | in-circuit GKR verifier >25% of the cells it saves |
| outer GKR (in flight) | DW-R1 fix (constrained eq column, succinct evaluator) | ×0.57 on node interaction; overlaps with the hash change (expect ×0.8 after Poseidon2) | medium | — |
| **(a) Hand-designed verifier AIR** | Dedicated Merkle-path/leaf-hash, FRI-fold, DEEP, sumcheck and channel components on a LogUp bus (Plonky3-recursion) | cells ×0.75–0.9; **witness depth 146k → O(10) levels**, host prep ≤0.05 s, trivial graph capture | medium | after leaf-tape lands: <15% cells and <0.1 s leaf wall |
| **(g) Capacity-fit arity and comb topology** | A fixed 2^21–2^22-row node packs as many children as fit (set-v2 VK). A running accumulator folds whatever is ready; the root folds {accumulator, last ≤3 leaves}. | tail on 75 leaves: 2.6–2.8 s (balanced 4-ary) → ~1.9 s; tail independent of N | low | the accumulator chain becomes the bottleneck (fold time > leaf inter-arrival time) |
| (e) multilinear / WHIR recursion | Outer layers only (folds and compress), or full (native moves to zerocheck + LogUp-GKR + stacked PCS) | outer-only ×0.75–0.85; full: per-child 5–15k compressions (×0.1–0.15) | high: Circle-code WHIR is unproven | (b)+(c)+(d)+hash already reach ≤35 G on the largest block |
| (f) hash-based accumulation (Arc, WARP, bounded-depth) | Accumulate code-committed instances, with one decider at the end | 2–5k compressions per instance (low confidence) | very high, no production implementation | watch only |

### 6.3 Trajectory for the largest block [E]

| step | recursion cells |
|---|---:|
| today | ~116–156 G |
| + truth batching | ~91 G |
| + per-family blowup (b16 truth, b4 CPU) | ~61 G |
| + k-ary q51 folds | ~43 G |
| + 2^23 rungs | ~24 G |
| + outer GKR | ~14 G (≈5 GPU·s) |
| or + Poseidon2-M31 instead of the per-family blowup and outer GKR | ~10–15 G |
| + GKR-Blake or Poseidon2, with everything else | ~6–8 G |

With the comb topology the tail is about 1.6–2.1 s.

**Recommendation.** Use the hash change as the backbone, with (c), (b1) and (g) around it. Use (a) for latency once leaf-tape has taken the easy depth wins. Keep (h1) as the fallback if Poseidon2's native GPU cost fails gate S1. Run (e) only as a spike, and treat (f) as watch-only.

---

## 7. Hash functions: review and migration

### 7.1 Review over M31

| hash | in-circuit cost over M31 | native and GPU | security status | users | verdict |
|---|---|---|---|---|---|
| **Blake2s** (today) | ~14.4 k raw, ~22.7 k committed cells per compression [M/D]; XOR and rotate through lookups | fastest on 32-bit ALUs; 18.9 ns per compression in our fused fill on a 5090 [M] | mature ([RFC 7693](https://www.rfc-editor.org/rfc/rfc7693)) | Stwo default, Airbender | keep for native-only trees and on-chain layers; too expensive in-circuit |
| Blake3 | 7 rounds instead of 10: ×0.7 compression, ~×0.74 per leaf | very fast; 8.8–11× faster than our old Poseidon2 W16 on CPU leaves [M] | mature | ZisK default (Goldilocks), Miden | not enough on its own for recursion |
| Keccak-f / SHA3 | worse than Blake2s per byte (our Keccak truth class is 1,923 MAIN / 1,560 INTER columns) [M] | fast | most analysed | EVM (KECCAK256 opcode) | **final on-chain layer only** |
| SHA-256 | ≥ Blake2s | fast with SHA-NI | mature | EVM precompile | no |
| **Poseidon2-M31 W24** (Plonky3: RF 8, RP 22, x^5) | dedicated degree-3 row: **~741 committed columns per permutation** absorbing 12 felts (476 MAIN + 73 FIXED + 192 INTER; 16 in GKR mode) [M]; a degree-5 layout is ~238 MAIN [D] | ~6–10× more ALU per byte than Blake2s [E]; no public M31 GPU benchmark (third-party: 2^25 leaves in 780 ms on an H100, unverified) | [2023/323](https://eprint.iacr.org/2023/323); full rounds unbroken; round-skipping and CICO results only on reduced rounds or below the claimed level ([2025/954](https://eprint.iacr.org/2025/954), [2026/306](https://eprint.iacr.org/2026/306), [2026/150](https://eprint.iacr.org/2026/150)); bounty programme running to 31 Dec 2026 ([initiative](https://www.poseidon-initiative.info/)); no official parameter change | SP1 (KoalaBear), RISC Zero (BabyBear), ZisK option (Goldilocks), Plonky3 M31 | **recommended for recursion-facing trees and transcripts** |
| Poseidon (original) | 1.5–3× Poseidon2 | slower | revised round counts | Plonky2, Poseidon252 (Stwo-Cairo) | no |
| RPO / RPX | cheap in AIR (inverse S-box verified forward) | 2–4× slower than Poseidon2 | Goldilocks-specific | **Miden dropped them** for "Eidos" + Blake3/Keccak | no |
| Monolith | lookup-heavy Bars layer, few rounds | 2–3× faster than Poseidon natively | young | none in production | watch |
| Griffin / Anemoi / Arion | low degree | — | **weakened** by FreeLunch, resultant and CheapLunch attacks ([2024/347](https://eprint.iacr.org/2024/347), [2025/259](https://eprint.iacr.org/2025/259), [2025/2040](https://eprint.iacr.org/2025/2040)) | — | **avoid** |
| Tip5, Skyscraper, Reinforced Concrete | Goldilocks or big-prime designs | — | — | Triton, ProveKit | not applicable to M31 |

### 7.2 Recommendation

1. **Poseidon2-M31-W24 everywhere recursion looks.** That covers native RV64 trees, the Fiat–Shamir channel, PoW, the native GKR channel, and every recursion layer up to C1 (OM31 variant).
   - A hybrid that keeps Blake2s natively keeps the 85% in-circuit hash cost, because every native tree is opened by a leaf.
   - Native cost rises by about 0.5–1.5 GPU·s per block [E]. That is far below the 10–12 GPU·s of recursion it removes [E].
2. **C2, the last layer:** C2's own trees and transcript use **Keccak-256** (EVM) or Blake2s / Poseidon252 (Cairo). C2 verifies C1 in-circuit with Poseidon2.
3. **Parameter decisions for gate S0:**
   - 2-to-1 truncated-permutation node compression: 1 permutation per node instead of 2. Needs its own security note.
   - A named "hardened" variant (RP 22 → 30, about +3% columns) as cheap insurance against further cryptanalysis.
   - Width 24, because width 16's 8-limb digest is only about 124-bit collision resistant.
   - Merkle caps stay at 0 under the batched multiproof.
4. **Expected effect:**
   - Leaf hash cells ×(1/8.5 – 1/17).
   - CPU leaf 1.94 G → 0.39–0.49 G (×0.20–0.25).
   - Recursion from 7.8× native to about 1.6–2.0× native.
   - Proof hash bytes +12.5% (36-byte digests instead of 32).
   - Do not multiply this with outer GKR's ×0.57; the two overlap.

### 7.3 Our hash abstraction and where Blake2s is hard-wired

**The generic layer exists:**
- `src/core/vcs/merkle_hasher.zig`, `src/core/vcs_lifted/merkle_hasher.zig`, `src/core/vcs/hash.zig`;
- the profile = Channel + MerkleHasher + mixRoot (`src/core/vcs_lifted/channel_profile.zig`; Poseidon in `poseidon2_profile.zig`);
- the engine `prover.engine.ForField(O).ProverEngine(Backend, H, MC, Channel)` (`src/integrations/circuit_cpu/om31/protocol.zig`);
- the wire family `src/interop/proof_wire/family.zig`, where `ForHasher` gives 36-byte Poseidon digests with canonical-limb checks.

**Poseidon2 W24 substrate**, on `codex/rv64-m7-integrate`, scoped gates passing, nothing selects it yet:
- `src/core/crypto/poseidon2_m31_w24*.zig` (pinned to Plonky3 `0d803737`);
- `poseidon2_m31_sponge.zig`;
- `src/core/channel/poseidon2_m31.zig` (v2: one permutation per draw);
- `src/core/vcs/poseidon2_m31_merkle.zig`;
- CUDA numerical kernels `src/backends/cuda/native/rv64/poseidon2_m31.cuh`;
- the dedicated component `src/integrations/riscv_cpu/poseidon2_outer/*`;
- the review `native-layout/POSEIDON2-REVIEW.md`.

**Hard-wired Blake2s** (75 files reference `Blake2sPrefixedMerkleHasher`, 72 reference `raw_mod_m31`):
- **Native profile:** `word16_execution/om31_security_candidate.zig` (Channel/Hasher/ID_DOMAIN lines 8–10, `admitNative` at 163, the ROM ledger's 256-bit collision term at 303–315).
- **Channels:** `src/core/channel/{raw_mod_m31,blake2s,blake2s_pow_order}.zig`.
- **In-circuit verifiers:** `src/frontends/circuit/{native_verifier,stark_verifier}/*`, `builder/blake.zig`, `fused_blake/*`, `witness/components.zig` (`blake_g_gate`, `triple_xor`, `m31_to_u32`), `circuit_cpu/air.zig` `recorded_sizes`.
- **RV64 recursion:** `rv64_recursion/vk_table.zig` (T_nat tree), `om31_native/{canon_hash,frame,fri,proof,leaf_graph,fold_tape,node_summary_v3,topology_fingerprint,outer_wrap,...}.zig`, `root_{verify,derive}.zig`, `fold_root.zig`, `leaf_statement.zig`, `public_wires.zig`.
- **CUDA:**
  - `native/commitment/{blake2s_core.cuh,blake2s_protocol.cuh,merkle.cu,progressive*.cu*}`;
  - `native/transcript/*`, `native/pow/*`, `native/decommit/*`;
  - `native/rv64/{pcs.cu,fri.cu,trace.cu,round.cuh,fused_blake2s.cu}`;
  - the ABI stages that carry 32-byte hashes.

### 7.4 Staged migration

Every stage is additive and the M6/M7 profiles stay byte-identical until the cut-over.

| stage | named identity | work | gate | estimate |
|---|---|---|---|---|
| S0 parameters | `P2M31-W24-R12-C12-D9-v2`, optional `…-C2TO1-v1`, `…-RP30` | security note (compression mode, margin); p^9 ledger; draw bias | review sign-off; Plonky3 KATs plus an independent model | 3–5 days |
| **S1 CUDA PCS / transcript / PoW** | an ABI family with 36-byte hashes next to the 32-byte one | Poseidon leaf, parent and progressive commitment; decommit; transcript; PoW kernels | GPU = CPU byte parity; memcheck; **5090 throughput vs Blake2s (go/no-go)** | 1.5–2.5 weeks |
| S2 native RV64 profile | `rv64-om31-p2m31-native-localgkr-128-CANDIDATE/v1` | parameterise `admitNative`; Poseidon native GKR channel; FIXED roots and VKs | both dev blocks; fresh receivers; tamper corpus (foreign suite, non-canonical limbs) | 1.5–2 weeks |
| **S3 in-circuit verifier** | roster `m7_outer_p2m31_…` | port `channel`, `merkle`, `raw_mod_channel` and `fri` to the `poseidon2_outer` component; drop the Blake components from the roster | circuit = native agreement; **exact padded full-leaf census (go/no-go)** | 2–3 weeks |
| S4 outer, fold and root | `protocol.zig` profile with H/Channel/MC set to Poseidon OM31 v2 | T_nat, canon_hash, node summary, root derive/verify; GPU witness for the component | full tree on both blocks, fresh receivers, quiet-run A/B against M6/M7 | 2–3 weeks |
| S5 compress + final | C1 Poseidon; C2 verifies with Poseidon and commits with Keccak | Keccak hasher/channel; EVM or Cairo verifier | ≤120 KB; fresh compressed receiver | 2 weeks |
| S6 cut-over | flip the defaults; keep legacy verification versioned | — | dev blocks, then the ordered scale-up | 1 week |

The older RV32 stack moved from Poseidon2 W16 to Blake3 for native speed and never showed an end-to-end recursion win (`design/riscv-proving-stack/blake3-migration.md`). This plan reverses that choice for RV64 recursion, for the reason the cell data now makes clear: recursion, not native hashing, is the bottleneck.

---

## 8. Learning from the GPU frontier: open-flapping-airplanes

[Bobliuuu/open-flapping-airplanes](https://github.com/Bobliuuu/open-flapping-airplanes) (OFA; read at HEAD 3d5aa45, MIT, about 21k lines) is an open rebuild of a **single persistent CUDA megakernel that is launched once and never exits**. Each block reads its SM id and takes a fixed role. On a B200 it trains a 162 M-parameter GPT on 116 SMs, serves tokens from the live weights on 24 SMs and runs Doom on 8 SMs, all at once.

Its reported results [src]:
- 3 launches per process, against 2.2–4.2 M for the baselines;
- 48.1 s training (Megatron + TE eager 62.4 s; **Megatron + TE with CUDA graphs 43.1 s, which is faster**);
- serving 1,660–1,741 tokens/s on 24 SMs, against vLLM's 1,537;
- loss bit-identical across every build.

### 8.1 How to read it

**The win comes from concurrency, not from removing launches.**
- In OFA's own small demo, the same task code launched per op is 13–25% faster per job.
- For a single job, CUDA graphs capture most of the launch saving: the graphed decode grid was within 4% of the persistent kernel, and Megatron with graphs beat the megakernel.
- The megakernel wins when several jobs share the GPU: 52.4 s measured, against about 102 s run back to back.

**Our situation is the concurrency case.**
- Native segments, recursion leaves, folds, GKR and witness generation are all ready at once, yet GPUs are 42% busy.
- So the order is: **graphs first, then a megakernel when concurrency is the remaining lever.**

**It targets datacenter Blackwell (sm_100/103).** The RTX 5090 is sm_120:
- no `tcgen05` and no TMEM;
- TMA, mbarrier, cp.async and clusters exist;
- OFA's `docs/RESEARCH.md` points to CUTLASS SM120 CLC work-stealing (example 87a) and to Lucebox as sm_120 references.

OFA has **no multi-GPU code**.

### 8.2 Pattern catalogue mapped to our problems

File references are inside OFA.

| # | OFA pattern | where | our problem | how we apply it | expected effect |
|---|---|---|---|---|---|
| A | **Persistent kernel with a phase table and dependency counters**: host-built `Job` of `PhaseDesc` (kind, ntasks, args) with CSR deps `(phase, stepDelta)`; per-phase `done[]` counters; one fetch-add `ticket`; tickets issued in topological order so no deadlock; `ld.acquire.gpu` spin with `__nanosleep` | `llm/b200/megakernel/ofa.cu` `job_loop`, `ofa_kernel` | 1,774 launches and 123 blocking calls per recursion node | Each recursion node's stages (trace/LDE, Merkle, composition, FRI folds, GKR rounds, decommit) become phases. Step-delta dependencies let node k+1's witness or LDE run during node k's FRI. One launch per batch of nodes. | removes launch and host gaps; enables overlap across nodes |
| B | **Fetch-add claims, never CAS loops**: CAS serialised at ~2 claims/µs; fetch-add went 9.7k → 10.7k steps/s; 32-way sharded queues with `__ballot_sync` + `__ffs` + `__shfl_sync` | `ofa.cu` `CLAIM_FETCHADD`; `a100-demo/demo.cu` | any device scheduler (recursion DAG, witness DAG) | fetch-add tickets; sharded queues for priority classes (tail node > leaf > native) | removes claim serialisation |
| C | **SM partitioning and placement**: roles by `%smid` with a dense rank table (`smid_probe`); 1 block per SM beat 2 when latency-bound (1,887 vs 1,677 tok/s); co-resident training blocks were 40% slower; `__launch_bounds__`, `-maxrregcount`; static shared-memory asserts; per-role L1/shared carveout | `ofa.cu`; `llm/decode/README.md` | stream concurrency defeated by synchronous callbacks; native and recursion contending | Partition SMs: native witness + LDE, Merkle/FRI, recursion witness. 1 block per SM for latency-bound GKR rounds; more for NTT and Merkle. | predictable concurrency without streams |
| D | **Task-level fusion**: LayerNorm into the GEMV prologue, attention into Wo, up into down (5 phases → 3 per layer, 50 → 35 µs); fused GEMM epilogues; optimiser fused into embedding backward | `decode_wide.cuh`; `ofa.cu` | separate LDE/hash, composition/quotient/FRI and GKR passes | last FFT pass + leaf hash; constraint eval + quotient + first FRI fold; GKR layer + next round's first pass | one HBM round trip and one barrier saved per pair |
| E | **Latency hiding in a task**: issue challenge-independent loads before the barrier; L2 prefetch of the next task (measured neutral to negative); claim one ticket ahead | `decode_wide.cuh` `gemv_issue`, `gemv_l2_prefetch` | Merkle/FRI waiting on challenges | prefetch committed columns before the challenge wait | small; measure before keeping |
| F | **Memory hierarchy**: XOR-swizzled shared memory, `cp.async` multi-stage pipelines, TMA with mbarrier full/empty rings; **warp specialisation** (producer, compute and epilogue warps); a staged, coalesced 16-byte epilogue (the biggest single win: QKV 300 → 764 TFLOP/s); coherence rules `__ldcg` / `L1::no_allocate` for data written earlier in the same launch, plus `fence.proxy.async` before TMA reads | `llm/gemm/gemm.cuh`; `gemm_tcgen05/*`; `decode_wide.cuh` `ldw()` | NTT/LDE/Merkle output stores; FRI folding; Blake2s Merkle layers | staged shared-memory transposes then 16-byte row stores for LDE and Merkle outputs; cp.async/TMA pipelines for butterfly stages; producer/compute/store warps for Merkle layers; **adopt the coherence rules before any persistent kernel** | bandwidth toward the 15–35× headroom of §1.4 |
| G | **Warp primitives**: `__shfl_xor_sync` butterfly reductions; fixed-order cross-warp combine | `decode_wide.cuh` `block_sum` | sumcheck round polynomials, LogUp fraction sums | same | — |
| H | **Determinism under any schedule**: residuals in int64 fixed point with integer `atomicAdd` (associative, so order-independent); a scramble mode that permutes order and injects delays, with bit-identical output | `decode_wide.cuh` `State`, `k_persistent scramble=1` | byte-identical proofs under a dynamic scheduler | accumulate unreduced M31/QM31 limbs with u64 `atomicAdd` (thousands of 31-bit adds before overflow), reduce once; **merge gate: proof bytes identical under scramble, graph vs persistent, and across builds** | deterministic sums without tree buffers |
| I | **Device-side feedback loop**: the SAMPLE task draws the next token on the device; the host only polls `cudaEventQuery` every 200 ms and reads mapped-memory counters | `decode_wide.cuh`; `dashboard.cuh` | 123 blocking calls per node; synchronous owner callbacks | **device Fiat–Shamir**: a single-task "challenge" phase hashes the channel state on the device and writes challenges to device memory; mapped progress counters replace callbacks | removes most blocking calls |
| J | **Inputs stay resident**: corpus, weights and activations allocated and uploaded once; a `K_DATA` task gathers each batch on the device | `ofa.cu` host side | 213 B per instruction host-to-device | upload a compact execution record once and expand it on the device (chapter 5) | host-to-device ≤80 B per instruction |
| K | **Serial chain inside one block**: Doom's thread 0 runs serial logic and 255 threads drain a queue behind a named barrier (24 → 6.7 ms per frame) | `doom_job.cuh` | **146k-level Blake-G witness DAG** at ~0.77 µs per level | Run each dependent chain inside one block or warp (`__syncwarp` / named `bar.sync`, tens of ns), with state in registers or shared memory; one independent DAG per block. 146k levels → single- to low-tens of ms. | leaf witness depth stops mattering |
| L | **Heavy tasks first; size tasks to one wave** | `run_train_task`; `B300_ROUND2.md` §2 | mixed-size components, GKR layers, FRI layers | largest-first order; task count a multiple of active blocks | removes tail waves |
| M | **Toolchain**: `-rdc=true` cost **18%** (fixed with whole-program PTX merge); family targets; no PTX JIT fallback; read ptxas `-v` for frames and spills | `llm/ofa_fast/README.md` | unknown | audit our CUDA build (Zig + nvcc) for rdc/split device objects; prefer whole-program or `-dlto`; build `sm_120a` with no PTX; spill report per hot kernel | possibly a free 10–20% |
| N | **Profiling discipline**: per-task `%globaltimer` stamps into `phase_busy[]`, `phase_first` / `phase_last`; per-block busy; three launch counts (kernels, host launch calls, graph launches); runs only on an idle GPU, 3 repeats, losses reported; `compute-sanitizer synccheck` before timings count; a `clock64` timeout-and-trap debug build | `job_loop`; `baseline/launchcount.py`; `calibrate_sms.sh` | busy only 1.5–2.4 s of 4.45 s; noisy shared pod | **copy the in-kernel phase table** (it works without ncu); the three launch counts; quiet-GPU rule; sanitizer gate | answers "where are the idle seconds" |
| O | **Static layout**: everything allocated up front from a host `Layout`; budgets asserted before launch | `ofa.cu` | GKR OOMs | static per-class plans with a pre-launch budget check; **we must add liveness-based reuse ourselves** (OFA never needed it) | no mid-proof OOM |

### 8.3 What does not transfer

- `tcgen05`, TMEM, 2-CTA and bf16 tensor-core GEMMs: sm_120 has no TMEM, and our arithmetic is M31 multiply-add.
- Deadlock-freedom requires every block resident, so the grid equals SMs × blocks per SM. Large kernels must be rewritten as tiles.
- Phase counters are too coarse for 146k-level DAGs; use pattern K.
- No multi-GPU material (we need our own 4-GPU placement; chapter 9).
- No memory planner; L2 prefetch and offset rotation were neutral.

### 8.4 Adoption order

1. **Measure:** in-kernel phase table, three launch counts, quiet-GPU and sanitizer gates (N).
2. **Remove host round trips:** device Fiat–Shamir and mapped counters (I).
3. **Cut launches cheaply:** a CUDA graph per recursion class and per native class, on prioritised streams.
4. **Witness DAG:** chains inside blocks or warps (K).
5. **Determinism:** u64 atomic M31 accumulation plus scramble tests (H).
6. **Fusion** (D) and memory-hierarchy work (F), guided by the phase table.
7. **Megakernel last:** phase table, fetch-add tickets, step-delta pipelining and SM partitions (A, B, C), once concurrency between nodes is the remaining lever.
8. **Toolchain audit (M):** cheap; do it immediately.

---

## 9. Orchestration on 4 GPUs

- **Parallel capture is mandatory.**
  - Today capture is serial at ~13.6 MIPS: about 16 s for 26235159.
  - The untraced fast pass runs at 120–168 MIPS on one thread [M], so the fast pass for the largest block takes about 1.2–1.7 s.
  - Design (ZisK, Airbender style): the fast pass records checkpoints every N instructions plus a minimal trace. Segments are then replayed, fully traced, in parallel from those checkpoints on all host cores. The ledger becomes two-phase or sharded. Each segment is handed to native the moment its replay finishes.
  - Target: segment 0 ready in ≤0.4 s and ≥100 MIPS aggregate.
  - The host has a 48-vCPU quota: plan the cores across capture replay, witness and host prep.
- **Streaming end to end:** capture → native → leaf → fold → C1 → C2, with recursion hidden behind native. Order segments so the last ones are small (ZisK phase A/B). Prove the late truth batch on the least-loaded GPU.
- **Placement on 4 GPUs:** key affinity (warm class > fresh > reload), deepest backlog first, root-critical-path priority, 2 nodes per GPU within a static arena. Segments are independent, so 2 → 4 GPUs should scale almost linearly for native. Measure it: it has never been measured.
- **No cold setup:** an install step persists every per-image class artifact. Cold setup was 93 s at M3 on the largest block; strict-roster classes make setup block-independent.
- **Memory planner:** one admission model per GPU (chapter 5).
- **Comb aggregation with capacity-fit arity** (chapter 6 g).
- **Off the request path:** C2 can ship asynchronously if the 10 s target applies to the root proof. Decide this explicitly; the EF real-time definition is about proving, not about the final proof size.

---

## 10. Protocol parameters and compression

| lever | effect [E] | note |
|---|---|---|
| query grinding 20 → 26 bits | −5% queries at b2 | ZisK uses 24–27, StarkWare 26 |
| per-family blowup (truth b16, outer m3_b4_q51_p26) | truth leaves ×0.3; folds ×0.5 | named profiles, conjectured-128 arithmetic |
| more Merkle levels carried in the proof (ZisK 5–6), solved per-layer FRI fold schedule, terminal domain 2^7 | −2–6% per leaf | nearly free |
| lifted VCS (one tree per phase across log sizes) | fewer paths | check whether native still has per-size trees |
| two-stage compress (C1 b8_q36 or b16_q27; C2 b64_q18_fold3 or b16_q27_fold3; caps; multiproof; pruned last FRI layer), Keccak-committed C2 | 709 KB → 100–120 KB; tail ≤1.5 s | the reserved names are in `m7-handoff/M7-INTERFACES-snapshot.md` |

---

## 11. Plan: M8–M10 to 4-GPU real time

Each milestone runs as parallel streams, using the same rules as before:
- done means switched on in the production prover;
- named profiles, fresh receivers and corpora for any proof-format change;
- paired A/B on a quiet pod;
- benchmark data in every commit.

### M8: measure, cut leaves, and parallelise capture

Mostly proof-neutral, plus low-risk profile changes.

1. **Instrumentation:**
   - in-kernel phase table (OFA N);
   - per-request critical-path accounting;
   - three launch counts;
   - an exact per-origin recursion census (path / opened-width / FRI / transcript compressions per leaf);
   - instruction attribution on the 4 largest blocks;
   - 2 → 4 GPU scaling on one large block.
2. **Parallel capture** from checkpoints: ≥100 MIPS; segment 0 at ≤0.4 s.
3. **Truth batching** (early and late batches) at b16, plus query grinding 26.
4. **2^23 canonical rungs**, total and with zero padding tax (strict roster).
5. **Device Fiat–Shamir and graphs** per recursion and native class; synchronous callbacks gone.
6. **Hash gates S0 and S1:** Poseidon2 W24 parameter note and CUDA PCS throughput on a 5090. This decides the M9 backbone.
7. **Toolchain audit** (rdc / whole-program, sm_120a, spills).

Exit on 24628607 (4 GPUs): ≤6 s. On 26235159: ≤20 s, with leaves ≤35.

### M9: recursion backbone

The hash change and the latency architecture.

1. **Poseidon2-M31-W24** stages S2–S4: native profile, in-circuit verifier, outer, fold and root.
   - Fallback if S1 fails: GKR-proven Blake2s (h1).
2. **Outer GKR** wired. **Native GKR v2-gkr** in production with the 128-oracle cap.
3. **Hand-designed Merkle-path/leaf-hash component** (option a, first slice), with witness chains inside blocks (OFA K).
4. **Comb aggregation** with capacity-fit k-ary nodes and set-v2 VKs.
5. **Static memory planner;** 2 nodes per GPU; SM partitioning where it measurably helps.

Exit on 26235159 (4 GPUs): recursion ≤35 G cells (≤150 per instruction); request ≤12 s.

### M10: native throughput and the last mile

1. **Native GPU witness**, streaming commit, fusion: ≤0.25 ns per base cell.
2. **Precompile delegations** ranked by M8 attribution (expected BN254 and KZG/BLS first).
3. **Megakernel scheduler** (OFA A/B/C) if busy is still below 85%.
4. **Compress S5** (Poseidon C1, Keccak C2), ≤120 KB.
5. **Ordered scale-up** across the basket: one block at a time on 4 GPUs, stopping at the first failure.

Exit: every basket block ≤10 s on 4×5090 (p99 over the basket), conjectured-128, fresh-receiver accepted.

### Kill and pivot points

- If S1 shows Poseidon2 native hashing costs more than 3 GPU·s per largest block, pivot to GKR-Blake (h1).
- If, after M9, recursion still exceeds 0.3 G cells per verified native proof, start the multilinear (WHIR/BaseFold) spike (option e; plan §3.5 S-ML).
- If 2 → 4 GPU scaling is below 3.2× on native, prioritise the scheduler and memory planner over kernels.

---

## 12. Data we still need, and the tools to get it

| gap | tool |
|---|---|
| instruction attribution by category on large blocks | `scripts/riscv64_ethereum_profile.py`, `scripts/rv64_function_census_merge.py`, `scripts/rv64_ethereum_basket.py` |
| per-kernel roofline (DRAM bytes, ops) | `ncu` (needs counter access) or an OFA-style in-kernel phase table plus a byte model; today `scripts/rv64_measure.py nsys`, `tools/rv64-cuda-counters` |
| recursion GPU·s per CPU leaf, truth leaf and fold at M7 | `scripts/rv64_measure.py`, `scripts/rv64_m6_hint_tape_prep.py` |
| native kernel GPU·s and retention on 26235159 | `scripts/rv64_m3_pod.py bench` + nsys (one scale probe) |
| parallel-capture throughput on a big block | `rv64-capture-bench` (`vectors/reports/rv64-m6-20261105/capture/raw/cap.py`) |
| today's native cells and Blake count on 26235159 | `scripts/rv64_committed_work_report.py`, `rv64_native_gkr_census.py`, `rv64_m7_layout_model.py` |
| exact Poseidon2 full-leaf padded census; per-origin Blake counter | `scripts/blake_gadget/fused_census.py`; poseidon2 README open gate |
| combined outer GKR + hash census | `scripts/rv64_m5_outer_gkr_census.py` |
| compress wall time | `scripts/rv64_m7_compress_model.py` (size only today) |
| device-memory admission on large blocks | `scripts/rv64_m40_models.py`, `rv64_m7_layout_model.py` |
| 2 → 4 GPU scaling, host DRAM/NUMA bandwidth, quiet-host timings | none yet |

---

## 13. Sources

- ZisK four-GPU claim: [CryptoSlate](https://cryptoslate.com/ethereums-12-gpu-proving-problem-just-got-a-4-gpu-answer/); [Alea Research, Jordi Baylina](https://alearesearch.io/summit-digest/ethcc/jordi-baylina-polygon-cofounder-zisk-proving-in-real-time); [pil2-proofman](https://github.com/0xPolygonHermez/pil2-proofman) (read at @27b2fc2).
- Airbender / Airbender Prime: [zksync-airbender](https://github.com/matter-labs/zksync-airbender) (main @0decdcd, v3 @36e57d3); [Introducing Airbender Prime](https://zksync.io/blog/introducing-airbender-prime).
- SP1 Hypercube: [16-GPU real time](https://blog.succinct.xyz/real-time-proving-16-gpus/); [overview](https://blog.succinct.xyz/sp1-hypercube/); [recursion docs](https://docs.succinct.xyz/docs/sp1/hypercube/recursion); [jagged PCS docs](https://docs.succinct.xyz/docs/sp1/hypercube/jagged); [jagged PCS paper](https://eprint.iacr.org/2025/917).
- Brevis Pico Prism: [KuCoin](https://www.kucoin.com/news/flash/brevis-upgrades-pico-prism-zkvm-to-achieve-99-ethereum-real-time-proof-with-16-gpus); [4pillars](https://research.4pillars.io/en/research/pico-prism-one-stone-two-wins-speed-and-efficiency).
- RISC Zero: [recursion](https://dev.risczero.com/api/recursion).
- Plonky3-recursion: [construction](https://plonky3.github.io/Plonky3-recursion/architecture_and_internals/construction.html); [benchmark](https://plonky3.github.io/Plonky3-recursion/appendix/benchmark.html).
- leanVM: [leanMultisig](https://github.com/leanEthereum/leanMultisig).
- Stwo-Cairo: [stwo-cairo](https://github.com/starkware-libs/stwo-cairo).
- Magnetar: [2026/2423](https://eprint.iacr.org/2026/2423).
- PCS and accumulation: WHIR [2024/1586](https://eprint.iacr.org/2024/1586), STIR [2024/390](https://eprint.iacr.org/2024/390), BaseFold [2023/1705](https://eprint.iacr.org/2023/1705), Blaze [2024/1609](https://eprint.iacr.org/2024/1609), FRI-Binius [2024/504](https://eprint.iacr.org/2024/504), Ligerito [2025/1187](https://eprint.iacr.org/2025/1187), accumulation without homomorphism [2024/474](https://eprint.iacr.org/2024/474), Arc [2024/1731](https://eprint.iacr.org/2024/1731), WARP [2025/753](https://eprint.iacr.org/2025/753), Quasar [2025/1912](https://eprint.iacr.org/2025/1912).
- Hashes:
  - Poseidon2 [2023/323](https://eprint.iacr.org/2023/323); Poseidon [2019/458](https://eprint.iacr.org/2019/458);
  - Poseidon/Poseidon2 cryptanalysis [2025/954](https://eprint.iacr.org/2025/954), [2026/306](https://eprint.iacr.org/2026/306), [2026/150](https://eprint.iacr.org/2026/150), [2025/937](https://eprint.iacr.org/2025/937); [Poseidon initiative](https://www.poseidon-initiative.info/);
  - Monolith [2023/1025](https://eprint.iacr.org/2023/1025); RPO [2022/1577](https://eprint.iacr.org/2022/1577); RPX [2023/1045](https://eprint.iacr.org/2023/1045);
  - Griffin/Anemoi/Arion attacks [2024/347](https://eprint.iacr.org/2024/347), [2025/259](https://eprint.iacr.org/2025/259), [2025/2040](https://eprint.iacr.org/2025/2040);
  - [BLAKE3 specs](https://github.com/BLAKE3-team/BLAKE3-specs); [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693); [Plonky3 p3-poseidon2](https://docs.rs/crate/p3-poseidon2/latest/source/generate_constants.py); [stwo vcs](https://github.com/starkware-libs/stwo/tree/dev/crates/stwo/src/core/vcs); [miden-vm](https://github.com/0xMiden/miden-vm).
- GPU: [open-flapping-airplanes](https://github.com/Bobliuuu/open-flapping-airplanes) (read at 3d5aa45; files cited in chapter 8).
- EF real-time proving definition (≥99% of blocks in 10 s, ≤$100k, ≤10 kW): [Wavect review](https://wavect.io/blog/zero-knowledge-proofs-production-2026.md).

Title: AntChain OpenLabs

URL Source: https://openlabs-intl.antdigital.com/0x/Introducing-zkDTVM-A-GPU-Native-zkVM-Built-for-End-to-End-Acceleration

Markdown Content:
**zkDTVM** is a RISC-V based zero-knowledge virtual machine engineered, from the ground up, to extract maximum throughput from modern GPUs. While most zkVMs treat GPU acceleration as an afterthought — a back-end that swaps out a few hot kernels in an otherwise CPU-shaped pipeline — zkDTVM treats the GPU as a first-class design constraint that propagates **all the way up to the proving system, the arithmetization, and the execution model**.

Concretely, zkDTVM departs from the conventional STARK [1] + univariate-FRI stack [2] and adopts a **SumCheck [3] PIOP [4] + Basefold [5] + recursive STARK** pipeline, with a chip-decomposed AIR optimized for parallel witness generation, sharding, and Merkle commitment. The result is a proving stack where **every layer — from Ethereum block execution down to NTT, hashing, and FRI folding — is shaped to feed thousands of CUDA cores efficiently**.

This post lays out the motivation, design philosophy, and architectural pillars of zkDTVM. We plan to follow up with a series of posts that dive deeper into some of the more distinctive design choices.

## 1. What is a zkVM, and Why Should You Care?

A **zero-knowledge virtual machine (zkVM)** is a program that executes another program (typically compiled to a standard ISA such as RISC-V) and, in the same pass, produces a succinct cryptographic proof that the execution was carried out correctly. A verifier — possibly a smart contract on Ethereum — can check this proof in milliseconds without re-running the program and without learning anything beyond the public inputs and outputs.

This single primitive unlocks an enormous design space:

*   **ZK-Rollups** can post a single proof attesting that an entire batch of L2 transactions was executed correctly, replacing fraud proofs and 7-day withdrawal windows.
*   **Verifiable cloud compute** lets clients outsource workloads to untrusted infrastructure with cryptographic guarantees of correctness.
*   **Privacy-preserving applications** can prove statements about private data without revealing the data itself.
*   **Cross-chain bridges** can verify the state of a foreign chain by proving the execution of its consensus client, eliminating trusted committees.

For zkDTVM, the **flagship workload is proving Ethereum block execution**: given an Ethereum block and a pre-state, produce a proof that the post-state root is correct. This workload is brutally demanding — millions of RISC-V cycles per block, dominated by Keccak, ECDSA recovery, MPT updates, and EVM interpretation — and it puts every component of a zkVM under stress.

The fundamental challenge is that generating a zk-proof is roughly **three to six orders of magnitude more expensive than running the program natively**, and for a zkVM to be useful in production this overhead has to come down. There are two levers available: **algorithmic improvements** (better PIOPs, better PCS, better recursion, better arithmetization) and **hardware acceleration** (exploiting the embarrassingly parallel structure of polynomial arithmetic, NTTs, and Merkle trees on GPUs, and eventually FPGAs and ASICs). Most existing zkVMs pull the algorithmic lever hard but treat hardware acceleration as a back-end optimization layered onto a CPU-shaped design. **zkDTVM pulls both levers at once, and lets the hardware lever inform the algorithmic one.**

## 2. The zkDTVM North Star: A GPU-Shaped Pipeline

Before we walk through the layers, it helps to state the design philosophy explicitly.

**Every component of zkDTVM is evaluated against one question: does this expose more parallelism, less data movement, or smaller working sets to the GPU?**

This single principle drives a number of concrete choices that distinguish zkDTVM from the field:

![Image 1](https://mdn.alipayobjects.com/huamei_4qw5wq/afts/img/A*zRlqS66L93gAAAAASLAAAAgAeuWVAQ/original)

The rest of this post explains _why_ each of these choices was made, _what problem_ it solves, and _how it differs_ from the rest of the industry. Concretely, the proving stack is a multi-stage funnel — **Core → Compress → Shrink**, with every stage running on the GPU.

## 3. Execution Layer: Sharded Trace Generation for Ethereum Blocks

The execution layer takes a guest program — for our flagship workload, an Ethereum execution client compiled to RISC-V — runs it on a deterministic interpreter, and emits an execution record: a structured event stream containing, per RISC-V cycle, the instruction executed, the operand values, the memory accesses, and any precompile invocations. The ExecutionRecord is then sliced into **shards** of bounded size, each of which becomes an independent proving job.

For non-trivial Ethereum blocks, a single ExecutionRecord can contain tens of millions of cycles and span dozens of gigabytes once expanded into trace matrices. A naïve "execute fully → materialize all traces → ship to GPU" pipeline has three failure modes: peak host RAM exceeds the proving box's capacity; the GPU sits idle while the CPU is generating traces; and a single oversized chip — Keccak in a Keccak-heavy block, for example — dominates wall-clock time through the long tail.

zkDTVM addresses these issues through a combination of execution-layer optimizations and GPU-centric pipeline design.

At the guest level, the EVM execution client is purpose-built for proving efficiency. A **zero-copy data plane** uses offset-based parsing and batched state updates to eliminate redundant deserialization. A **VM-native execution pipeline** maps common EVM primitives directly to RISC-V syscalls, bypassing interpretation layers for higher block throughput. And a **cryptographic co-design** offloads expensive operations like ECDSA signature recovery to the prover host while maintaining in-guest soundness, using efficient algorithms such as Pippenger multi-scalar multiplication to cut verification cost.

At the pipeline level, **trace generation is event-driven**: the interpreter emits typed events per instruction category, and each chip subscribes to its own event class and materializes its slice of the trace independently and in parallel — a structure that maps directly onto host parallelism and downstream GPU batching. Both **core and recursion trace generation run on the GPU**, not just the proving steps, keeping the device busy from the moment execution events arrive until the final SNARK is produced. Sharding is **shape-aware**: we profile production workloads to discover a small set of canonical shape templates and route each shard into the closest template via padding; careful shape tuning minimizes the total number of shards, maximizing the utilization of available GPU memory per shard and bounding the number of distinct recursion verifier circuits. Finally, the **trace generation, GPU upload, and proof generation stages are pipelined**: while one shard is being proven on the GPU, the next is being generated and the one after that is still emitting events, keeping the GPU saturated on long workloads.

## 4. Arithmetization: GPU-Optimized Circuit Design

The arithmetization layer bridges two very different worlds. On one side is a RISC-V program — an imperative sequence of register reads, arithmetic, branches, and memory accesses. On the other side is a proof system that understands only polynomial equations over a finite field. Arithmetization re-expresses _"this program ran correctly"_ as _"these matrices of field elements satisfy these polynomial identities."_ Each step of execution becomes a row of a trace matrix; low-degree polynomial constraints check that the row is a valid step; and lookup arguments — the _"foreign keys"_ of the constraint world — connect different matrices so that, for example, the chip handling `add` can refer to the chip that holds the program ROM without copying its columns.

Like some other zkVMs, zkDTVM splits the trace into dozens of **specialized chips** connected by typed LogUp interaction buses. The basic economics are simple: proof cost scales with _total trace cells_ (rows × columns), not useful ones, so giving a lightweight arithmetic instruction and a complex cryptographic round their own chips avoids wasted columns and lets unused chips contribute nothing at all. But zkDTVM pushes the chip-decomposed philosophy further in four ways:

*   **CPU-free architecture.** Most chip-based zkVMs retain a monolithic CPU chip that sequences every instruction, making it the widest chip and the throughput bottleneck of every shard. zkDTVM eliminates the central CPU chip entirely: each instruction type runs on its own dedicated, compact circuit. Control-flow integrity — the guarantee that instructions execute in the correct order — is enforced through LogUp interactions rather than a centralized dispatch table, turning instruction support into a plug-in affair.
*   **Per-chip circuit optimization.** Because each chip is an independent AIR, its trace width and constraint structure can be tuned in isolation. Columns are reused aggressively, redundant witnesses are eliminated, and constraint degrees are kept as low as each operation allows — none of which is possible when every instruction shares one wide table.
*   **Frequency-driven chip splitting.** High-frequency instructions and low-frequency instructions are separated into distinct chips so that hot-path circuits stay lean and tightly packed. This minimizes padding overhead per shard: a chip that handles a rare precompile gets a short trace (or is excluded entirely), while a high-traffic chip gets a tall trace with near-zero wasted rows.
*   **Instruction fusion.** For a given target workload, certain instruction sequences recur frequently. We identify these hot patterns and merge them into fused circuits that prove the whole sequence in a single trace row, cutting redundant rows and memory interactions. This is analogous to macro-op fusion in hardware CPUs, and for workloads with repetitive instruction patterns it yields a meaningful reduction in total cycle count and proving cost.

Where zkDTVM diverges further from the STARK-based field is the **shape of the constraints inside each chip**, driven by one question: _what makes the SumCheck prover fast on a GPU?_ Classical AIRs freely reference both the current row and the next row, relying on a univariate FRI back-end to make rotations cheap. Inside a SumCheck pipeline that convention is expensive: every polynomial whose constraint touches the next row must be paired with its rotated copy during folding, roughly doubling the working set, and permutation constraints with rotated traces require a separate, more complex protocol phase. On a GPU where trace tensors already saturate device memory, that doubling is often the difference between fitting on one card and not fitting at all.

So zkDTVM makes the opposite choice: **all chips are**_**local-only**_**— every constraint references only the current row, with no exceptions.** Anything that would naturally have used a next-row reference is re-expressed through other means (typically LogUp interactions). We pair this with a deliberately small **constraint degree** (≤ 3 in the Core stage) to keep SumCheck per-round sub-claims cheap, and an aggressive **shape catalog** that quantizes shard layouts into a small library of per-chip height templates so that GPU memory allocation is predictable and the recursion verifier only needs to support a fixed set of verification keys.

The cost of this design is honest: individual AIRs become a little more verbose than they would be with free row rotations, and the LogUp interaction graph carries more of the coordination burden. The pay-off is that the SumCheck prover walks a strictly local hot path on the bulk of the trace, the working set stays close to a single row at a time, and the GPU stays saturated end to end.

## 5. Proving System: SumCheck PIOP + Basefold

This is where zkDTVM departs most visibly from the rest of the industry. The proving system is the single largest determinant of how well a zkVM can exploit GPU hardware, and we made two coordinated choices: **replace univariate polynomials with multilinear polynomials across the entire proving stack** — both the PIOP and the PCS operate natively on multilinear representations — and **pair a SumCheck-based PIOP with Pangolin, our GPU-memory-efficient multilinear PCS built on Basefold**.

The dominant zkVM stacks treat each trace column as evaluations of a univariate polynomial over a multiplicative coset, then express constraints via a quotient polynomial and verify with a FRI low-degree test. The multilinear view, by contrast, re-interprets the same column as a multilinear polynomial over the Boolean hypercube — the most natural polynomial representation for array-shaped witness data. A zkVM's witness is essentially a collection of large tables (instruction trace, register state, memory accesses), and multilinear extension maps each table row directly to a point on the hypercube, with the number of variables growing only logarithmically with trace length.

For a GPU-accelerated zkVM, this choice brings four concrete advantages. First, the **prover approaches linear time**: sumcheck over multilinear polynomials yields linear-time IOP prover work, whereas quotient-polynomial systems typically incur quasi-linear costs due to FFTs and polynomial multiplication. Second, there is **no upfront low-degree extension (LDE) blowup**: univariate FRI-style systems must materialize enlarged evaluation domains before committing, while multilinear schemes commit directly to the original evaluations and defer expansion to the PCS, reducing peak GPU memory usage. Third, **recursion is cheaper**: sumcheck-based multilinear IOPs mainly require logarithmically many low-degree consistency checks plus a few PCS openings, whereas univariate STARK-style protocols rely on FRI queries and Merkle authentication paths, leading to larger recursive verifier circuits. Finally, **constraints map naturally to hypercube sums**: transition, memory, and lookup constraints reduce to summation identities over the hypercube, which sumcheck handles directly, while univariate systems express them through permutation arguments, grand products, and rotations.

Beyond the core SumCheck PIOP, two optimizations deserve mention.

*   First, **protocol-level sumcheck for LogUp interactions**. The standard way to verify LogUp's summation identity — a running-sum column with next-row transition constraints — forces the PCS to support shifted polynomial openings, roughly doubling commitment cost. An alternative LogUp-GKR protocol eliminates the extra commitment but introduces hundreds of sequential sumcheck rounds across the GKR circuit layers, creating severe GPU synchronization bottlenecks. We take a third path: remove the running-sum column entirely and instead fold each chip's summation claim directly into the existing zerocheck as an additional zero-sum term. The permutation trace columns still record per-row logarithmic-derivative values, and a simple local constraint enforces that each entry was computed correctly from the fingerprints — no cross-row references at all. The result is zero extra PCS cost, zero shifted openings, and the total sumcheck round count stays unchanged compared to the main constraint proof, making the protocol highly GPU-friendly.
*   Second, **univariate-skip-in-the-tail for GPU utilization**. The univariate-skip technique, originally proposed in [6], collapses the _first_`k` rounds of sumcheck into a single higher-degree round, trading more base-field work upfront for fewer extension-field rounds afterward. We extend this idea in the opposite direction to better suit GPU execution. In early rounds the trace is tall and the GPU is fully occupied; as sumcheck progresses and the working set shrinks, GPU utilization drops. By collapsing the _last_ several rounds — grouping every `k` consecutive rounds into one higher-degree round for the final `c·k` rounds — we keep the per-round workload large enough to saturate the GPU even in the tail of the protocol. Total arithmetic increases slightly, but wall-clock time decreases because the GPU stays busy throughout. The parameters `c` and `k` are tunable: different GPU memory sizes and compute budgets can choose their own optimal configuration.

![Image 2](https://intranetproxy.alipay.com/skylark/lark/0/2026/png/153582/1777450613434-618f7e4e-a7cd-4f47-87e5-0b2da38633bf.png)

_Figure: Original univariate-skip merges the first k rounds (left), leaving late rounds GPU-underutilized. zkDTVM's univariate-skip-in-the-tail merges the last c·k rounds (right), keeping GPU utilization high throughout the protocol._

For the polynomial commitment scheme we built **Pangolin**, a GPU-memory-efficient PCS based on Basefold. The key insight is a **padding-free DFT** property: when the trace matrix contains padding rows (a natural consequence of shape-aware sharding), the linear-code codeword can be computed via a DFT that keeps the data in a compressed representation throughout the entire commitment pipeline, reducing GPU memory usage in proportion to the compression ratio.

## 6. GPU Acceleration: End-to-End CUDA Pipeline

This is the layer where every preceding design choice pays off. Unlike most zkVMs that offload only a few hot kernels (NTT, hashing) to the GPU while keeping the rest on the CPU, zkDTVM accelerates the **entire proving pipeline on CUDA** — from trace generation through Merkle commitment, SumCheck evaluation, batch opening, all the way to recursion. There is no "hand back to CPU" cliff.

The acceleration rests on a clear four-layer architecture:

![Image 3](https://mdn.alipayobjects.com/huamei_4qw5wq/afts/img/A*cMw0QZp-ZLIAAAAARhAAAAgAeuWVAQ/original)

![Image 4](https://intranetproxy.alipay.com/skylark/lark/0/2026/png/153582/1777450725864-cb6e88f7-7e2d-4182-8067-5a8369ed5e0f.png)  
_Figure: End-to-end GPU acceleration architecture — from AOT-compiled execution through trace generation, proving, and SNARK wrapping._

At the bottom, the **CUDA core layer** contains custom kernels for NTT, Poseidon2 Merkle tree construction, SumCheck round evaluation, permutation trace generation, and polynomial operations — each kernel tuned with warp-level shuffles, shared-memory staging, and launch-bounds optimization to maximize GPU occupancy. The **front-end layer** handles trace generation entirely on the device: every trace type — core execution, preprocessed tables, memory, and all precompiles (Keccak, SHA-256, Poseidon2, elliptic-curve operations, uint256, and more) — is built in GPU kernels that map roughly one thread per execution event, avoiding the classical CPU-to-GPU upload bottleneck. The **adaptor layer** bridges the Rust proving framework to the GPU, implementing the prover trait as a drop-in backend so that upper layers can switch between CPU and GPU proving without API changes. Finally, the **application layer** wraps the full pipeline — setup, prove, verify — behind a clean SDK that supports Core, Compress, and Shrink stages, and scales to multi-shard distributed proving.

Several engineering principles run through all four layers:

*   **Device-resident data.** Trace matrices, proving keys, Poseidon2 constants, and NTT twiddle factors all live on the GPU. Data stays device-resident across proving phases, avoiding repeated host–device transfers.
*   **Asynchronous memory pools.** GPU memory is managed through CUDA async memory pools with RAII ownership, eliminating the synchronization cost of frequent allocations and deallocations.
*   **Multi-stream concurrency.** During SumCheck, each chip's constraint evaluation runs on a separate CUDA stream, overlapping computation across chips and pipelining kernel launches with memory transfers.
*   **Aggressive batching.** NTT, bit-reversal, Merkle openings, and SumCheck evaluations all support batched execution — processing many polynomials or matrices in a single kernel launch to amortize launch overhead and raise device utilization.
*   **AOT-compiled execution.** Rather than interpreting RISC-V, the guest ELF is ahead-of-time compiled to native x86, with separate modes for fast checkpoint-based sharding and detailed execution recording. This cuts execution time and decouples it from the proving pipeline.

For deployment, the CUDA prover is wrapped in a containerized service that exposes the proving phases over gRPC. The host SDK can transparently select between an all-Rust CPU prover (for development) and the GPU backend (for production). The same architecture scales from a single GPU node to a **distributed multi-shard cluster**, where a coordinator dispatches shards to a pool of GPU STARK provers and CPU SNARK provers, with dynamic registration, priority scheduling, and configurable per-node concurrency.

![Image 5](https://intranetproxy.alipay.com/skylark/lark/0/2026/png/153582/1777450738809-ba43f68c-c2e3-4d61-864c-ed7ac7e9a70c.png)  
_Figure: Distributed multi-shard proving — a coordinator dispatches shards across GPU STARK provers and CPU SNARK provers via gRPC._

The result is a pipeline where GPU utilization stays high from trace upload to on-chain proof emission — no stage falls back to the CPU.

## 7. What's Next

zkVMs are converging on a small set of architectural ideas — RISC-V guests, chip-decomposed AIRs, FRI-based PCS, recursive proving — but the _implementation choices that determine real-world performance_ are still wide open. zkDTVM represents one coherent answer to the question **"what does a zkVM look like if you design it for the GPU from day one?"** The answer turns out to involve rethinking the polynomial layer (multilinear), the PIOP (SumCheck with univariate-skip-in-the-tail), the PCS (Pangolin, a memory-efficient Basefold), the arithmetization (CPU-free, local-only chips with instruction fusion), and the runtime (end-to-end CUDA from trace generation to SNARK) — all in service of a pipeline where every stage saturates the hardware.

In the posts that follow, we will unpack the most distinctive parts of the stack in depth:

*   **Execution Optimization & GPU-Optimized Circuit Design.** How we purpose-built the EVM execution client for proving efficiency — zero-copy data pipelines, VM-native syscall acceleration, and cryptographic co-design — and how we eliminated the monolithic CPU chip, fused high-frequency instruction sequences, and split chips by execution frequency to produce traces that are narrower, denser, and better shaped for GPU memory.
*   **GPU-Optimized SumCheck Protocol.** The design of our SumCheck PIOP — multi-stage constraint handling, incremental chip activation across different trace heights, and how the protocol structure is shaped end-to-end for GPU parallelism.
*   **Univariate-Skip-in-the-Tail.** How we flip the classical univariate-skip technique to merge the tail rounds instead of the head, keeping GPU utilization high even as the working set shrinks — and how the tunable parameters adapt to different hardware configurations.
*   **Protocol-Level LogUp for Local-Only AIRs.** How we removed the running-sum column and folded the LogUp summation claim directly into the zerocheck, eliminating shifted polynomial openings and keeping every constraint strictly local — a design co-optimized with the local-only circuit architecture.
*   **End-to-End GPU Acceleration.** How the four-layer CUDA pipeline — from AOT-compiled execution and on-device trace generation through multi-stream SumCheck proving to distributed multi-shard coordination — achieves full device utilization across the entire proving funnel.

Stay tuned.

## References

[1]E. Ben-Sasson, I. Bentov, Y. Horesh, M. Riabzev. "Scalable, Transparent, and Post-Quantum Secure Computational Integrity." [IACR ePrint 2018/046](https://eprint.iacr.org/2018/046).  
[2]E. Ben-Sasson, I. Bentov, Y. Horesh, M. Riabzev. "Fast Reed–Solomon Interactive Oracle Proofs of Proximity." _ICALP 2018_.  
[3]L. Babai, L. Fortnow, C. Lund. "Non-Deterministic Exponential Time Has Two-Prover Interactive Protocols." _Proceedings of the 31st IEEE FOCS_, 1990.  
[4]B. Bünz, B. Fisch, A. Szepieniec. "Transparent SNARKs from DARK Compilers." [IACR ePrint 2019/1229](https://eprint.iacr.org/2019/1229).  
[5]H. Zeilberger, B. Chen, B. Fisch. "BaseFold: Efficient Field-Agnostic Polynomial Commitment Schemes from Foldable Codes." [IACR ePrint 2023/1705](https://eprint.iacr.org/2023/1705).  
[6]A. Gruen. "Some Improvements for the PIOP for ZeroCheck." [IACR ePrint 2024/108](https://eprint.iacr.org/2024/108).

**zkVM Projects**

*   [SP1](https://github.com/succinctlabs/sp1)
*   [RISC Zero](https://github.com/risc0/risc0)
*   [Ceno](https://github.com/scroll-tech/ceno)
*   [OpenVM](https://github.com/openvm-org/openvm)
*   [ZisK](https://github.com/0xPolygonHermez/zisk)

_zkDTVM is open research and engineering. Comments, issues, and pull requests are welcome._

AntChain OpenLabs is a research center founded by AntChain and world-leading computer scientists in the area of foundational trust technologies. It is dedicated to building a secure, transparent, and reliable infrastructure that connects Web3 and AI, driven by innovative research and with the aim of advancing transformative services.

## Contact Us

[Website](https://openlabs-intl.antdigital.com/home)|[Twitter](https://x.com/AntChainOpenLab)|[Github](https://github.com/AntChainOpenLabs)

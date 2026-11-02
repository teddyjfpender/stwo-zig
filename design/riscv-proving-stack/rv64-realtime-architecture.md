# RV64 real-time architecture: target, baseline, and the four deliverables

Status: design authority for the next production architecture. Each section
links one complete design document. Nothing here is a measured result unless a
receipt is cited; cost projections are labelled as projections.

## Target

Prove a pinned mainnet block end to end, as one proof, on four RTX 5090 GPUs,
within a 2 to 5x band of the EthProofs leaders measured on the same hardware
class in October 2026: ZisK (4x5090, 9.6 s p99 claimed, $0.0034 per proof on
EthProofs) and zkDTVM (4x5090, 3.1 s average claimed, $0.0031). Concretely:

| Objective | Target | Baseline (block 24,628,607, lean round-5 guest) |
| --- | ---: | ---: |
| End-to-end proof latency, 4x5090, p50 | <= 25 s | none (no GPU route, no aggregation) |
| Batch proving on one 5090 | <= 1.0 s per 2^22-step batch | 16.2 s per batch on an 18-core M5 Max CPU |
| Committed cells per retirement (CPU plus family chips) | <= 300 | 533 (385 main + 148 interaction) |
| Quotient domain | 2n (degree <= 3) | 4n (degree 4) |
| Peak host memory | <= 16 GB | 41.86 GB process RSS in the complete round-five run |
| Final artifact | one STARK root, fixed verifier key | 25 batch proofs plus terminal certificate, 72.85 MB |
| Verifier | < 1 s, < 1 GB | 7.16 s, 6.09 GB peak RSS |

The instruction count is no longer the first lever: the guest executes
104,253,913 instructions for this block with 11,496 secp ADD, 9,768 secp DOUBLE
and 32,835 Keccak service calls (`vectors/reports/rv64-guest-lean-20261031`).
Further guest reductions (SHA-256, memcpy, square root hints) are worth 10 to
20 percent and are tracked in `rv64-precompile-borrows.md`; they do not change
this architecture.

The complete round-five producer took 716.99 s on the CPU, followed by a
separate fresh receiver. [Pinned full-block evidence](../../vectors/reports/rv64-guest-lean-20261031/round5/complete-block-isolated-v1.json)
records all 25 proof/receipt/profile triples, the terminal certificate, input,
ELF and executable identities. It is one observation with no recursive proof
or GPU execution. The recycler/lifetime configuration trades retained memory
against allocation work; neither memory target is met.

## Where the time goes today

Per plain batch in the two-batch probe, M5 Max, lean guest, with commit preparation attributed
(`vectors/reports/rv64-guest-lean-20261031/commit-recycler`):

| Stage | Seconds | Scales with |
| --- | ---: | --- |
| Composition: four coset FFTs | 3.5 | columns x 4n |
| Composition: constraint rows | 2.7 | constraints x 4n |
| Commit preparation (interpolate, extend, leaf hash) | 3.2 | columns x 2n |
| FRI quotient build and commit | 2.0 | columns x n |
| Interaction generation | 1.8 | lookups x n |
| Trace decommit | 1.4 | columns x queries |
| Sampled values, PoW, misc | 1.0 | columns |
| Witness construction (outside proving) | 1.4 | columns x n |

Every line is proportional to the number of committed columns or to the
quotient domain. That is why the four deliverables are ordered as they are.

## The four deliverables and their dependency order

1. **Thin Word16 CPU on a 2n domain** (`rv64-word16-cpu-2n.md`). The CPU row
   becomes a ROM-authenticated bus emitter of about 70 main and 56 interaction
   columns; ALU, BINARY, SHIFT, LOAD/STORE and CONTROL become independently
   sized family chips; all constraints are degree <= 3 so the quotient domain
   halves. The draft 271-cell budget requires the store/ROM/range/degree reconciliation
   ledger in that document before adoption; projected
   composition cost about 0.25x. Prerequisite for the GPU memory plan.
2. **Global memory argument** (`rv64-global-memory-argument.md`). Replaces the
   per-batch Poseidon2 RAM roots with one LogUp memory relation across all
   batches under a shared challenge drawn from a sealed manifest of stage-one
   roots. Removes RAM hashing (30.41 s of witness and up to 2.1M Poseidon rows
   in the worst batch), removes the serial root chain, and makes batches
   independent once their memory advice is committed.
3. **Aggregation** (`rv64-aggregation.md`). Fixed-shape batch proofs verified by
   a leaf circuit, parents of arity two checking adjacency and the manifest,
   one root. Depends on fixed instance shapes from (1) and on the manifest
   from (2). Targets one proof with a fixed key, replacing the current 25 proofs plus terminal
   (72.85 MB). Root-key authority and leaf opening/hash costs still need qualification.
4. **CUDA port** (`rv64-cuda-port.md`). Resident proving of one batch on one
   GPU, four GPUs proving batches in parallel, aggregation overlapped. Depends
   on (1) for the memory plan and on the strict-AOT CUDA runtime that already
   exists. Projected 10 to 30x over the 18-core CPU per batch.

(1) and (2) can be built in parallel after agreeing the RAM tuple, service
bridges, clock ownership and manifest contracts. (3) needs the final batch shape from
(1) and (2). (4) can start on the current layout for kernels that do not depend
on columns (FFT, Merkle, FRI) and must switch to the Word16 layout for the
constraint and witness kernels.

## Projection to the target

Projection, not measurement. The CUDA byte-budget review found the original
5 GB model understated buffers by approximately four. Until the corrected
resource/lifetime model and real NVIDIA measurements exist, this table is a
set of hypotheses, not an established path to the target. The 36-batch row is
an older workload scenario; the current guest uses 25 batches.

| Step | Plain batch | Basis |
| --- | ---: | --- |
| Today, CPU | 16.2 s | measured |
| After (1) | ~6.5 s | cells -49 percent (family-providers model, 289 to 300 cells per row) and quotient domain halved; commit, FRI, decommit scale with columns |
| After (2) | ~5.5 s | RAM witness and Poseidon provider rows removed; worst batch 45 s -> ~25 s |
| After (4), one 5090 | 0.3 to 0.6 s | 2^22-point FFT in ~0.3 ms, leaf hashing at memory bandwidth, constraint kernels generated from the typed equations (cairo_cuda achieved 25x on its composition path) |
| 36 batches on 4 GPUs | 3 to 6 s | shard-parallel, memory manifest phase first |
| Aggregation, overlapped | +3 to 5 s | 36 leaves + 35 parents, leaf circuit ~2^19 rows on GPU |
| End to end | 8 to 12 s p50 | within the 2 to 5x band of 3 to 10 s |

Reachability of this band remains unproven. The comparison systems have
advantages in accelerator breadth (SHA-256, bn254, BLS, modexp, memcpy) and
years of CUDA tuning.

## Engineering rules that apply to all four

- Each deliverable is a new protocol version with its own fixtures and a fresh
  receiver. Byte parity with old proofs is not a gate for representation
  changes; statement, claim and fresh-verification parity is
  (`rv64-next-milestones.md`, step 2).
- No new `_vN` enum variants on the hot path. A deliverable replaces the
  production profile; the previous profile is deleted with its fixtures once
  the new one is qualified.
- Every new component ships with: the degree bound test at arbitrary QM31
  points, the adversarial list named in its document, the allocation-failure
  tests, and a CI target in `build_support/products/riscv_cpu.zig`. There is
  currently no RV64 target in any CI workflow; the first deliverable adds one.
- Geometry is fixed per chip per protocol version; request counts never choose
  columns. Padding is confined to at most one partial instance per chip.
- All cost claims carry source cells, quotient points, masks, padding and
  receiver cost, as in `rv64-family-model.json`.

## Comparison reference

zkDTVM, inspected from its public EthProofs container (`ghcr.io/doubizhizun/
zkdtvm_eth_proofs:0.6.1`), is not a Stwo or M31 prover: its CUDA kernels are
templated over KoalaBear with Poseidon2 hashing, chip kernels for divrem,
Keccak, Weierstrass add/double over secp256k1, bn254 and bls12-381 and fp
operations, a `recursion` crate, all compiled for sm_120; its guest is a 6.4 MB
RV32 ELF built from evmone, silkworm, blst, intx and evmmax in C++ with
syscall-style precompiles. It is architecturally an SP1-Hypercube-class prover
with a C++ EVM guest. The inspection was limited to file types, embedded crate
paths and kernel symbol names; no decompilation or source reconstruction.

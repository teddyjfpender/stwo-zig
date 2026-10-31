# RV64 CUDA port

Status: complete design for `rv64_cuda_v1`. Builds on the existing strict-AOT
CUDA runtime (`src/backends/cuda`: resident proof session, authenticated
kernel registry, device ABI, H100/H200 retained qualifications), the Cairo
resident prover (`src/integrations/cairo_cuda`, 25x on its composition path),
and the word-memory resident bridge (`block-v5-word-cuda-resident-v1.md`,
11 kernels: witness, range table, LogUp fractions and scan). Targets the
Word16 batch shape; kernels that do not depend on columns can be built on the
current shape first.

## 1. Pipeline per batch, resident

| Stage | Device work | Source of kernel |
| --- | --- | --- |
| Ingress | compact tape (48 B per retirement) and family request lists uploaded once; ELF/ROM fixed columns resident across batches | existing session ingress |
| Witness | CPU rows and chip rows written by kernels from the tape (one thread per retirement; chip rows from request lists); range/table multiplicities by atomic histogram | pattern from the word witness kernel |
| Memory subtree commit | interpolate + extend + Poseidon2 leaves + layers for the memory columns; root downloaded for the manifest | FFT and hash kernels below |
| Main and interaction commits | same, after the manifest digest returns | |
| Interactions | per-relation inverse table (range16, BYTE, SHIFT16, EXTEND) built once per challenge; per-row fractions; block scan prefix; mean centering | existing fractions/scan kernels (ABI 23 to 29) |
| Composition | constraint kernels on 2n points generated from the typed equations; weighted accumulation; interpolate and split | typed DAG codegen (`secure_polynomial_codegen_v1`) |
| OODS, FRI, PoW | sampled values at one point; DEEP quotient over all columns; FRI fold layers with Poseidon2 commits; PoW grind | cairo_cuda FRI kernels, hash kernels |
| Egress | roots, sampled values, FRI layers, query decommitments assembled on host | existing proof assembly |

Host owns the transcript. Nothing mid-proof is downloaded except roots and
sampled values, which is what the resident bridge's completion rules already
enforce.

## 2. Constraint kernels from one authority

The RV64 CPU and chips evaluate constraints through `emitFor(comptime F)` over
a lane type (M31 SIMD lanes on CPU, QM31 at OODS). Add a third lane: a
symbolic recording field whose operations append nodes to the typed DAG
already consumed by `secure_polynomial_codegen_v1`. Instantiating `emitFor`
with it at build time yields each component's constraint program; the
existing codegen emits CUDA, the offline builder compiles it to cubin and
registers it in the authenticated AOT pack. The CPU and the GPU therefore run
the same constraint set by construction, and the OODS check on the host
catches any divergence before a proof is published.

## 3. Memory plan, one 2^22-step batch on a 32 GB 5090

| Buffer | Size | Basis |
| --- | ---: | --- |
| CPU main + interaction + fixed at n | 0.5 GB | 125 columns x 4M x 4 B |
| Family chips at their logs | 0.6 GB | 271 cells per row model minus CPU |
| Extended evaluations at 2n for all committed columns | 2.2 GB | needed for leaves and the quotient |
| Coefficients (retained) | 1.1 GB | |
| Composition at 2n (4 QM31) | 0.13 GB | |
| Inverse tables, scratch, FRI layers | 0.5 GB | |
| **total** | **~5 GB** | fits with room for two batches in flight |

On the current 533-column shape the same plan needs about 19 GB, which is why
the port follows the Word16 CPU for the column-dependent kernels.

## 4. Throughput projection

Projection. A 2^22-point circle FFT on a 5090 is ~0.3 ms (memory-bound, 16 MB
in and out); a batch needs about 400 column transforms for commits plus 400 for
the two composition cosets: ~0.25 s. Poseidon2 leaf hashing of ~2.5 GB of
extended columns at ~50 GB/s effective: ~0.05 s. Constraint kernels on 8M
points x ~700 constraints at a few hundred Gop/s: ~0.1 s. Interactions, FRI,
decommits: ~0.1 s. Total 0.3 to 0.6 s per batch on one GPU, 36 batches on four
GPUs in 3 to 6 s with the manifest phase first.

## 5. Four GPUs

Shard-parallel: each GPU owns a queue of batches. Phase one (memory subtree
roots) runs for all batches first; roots go to the coordinator; phase two runs
as batches are assigned. Leaves run on whichever GPU finishes a batch; parents
run on any GPU as pairs complete. No cross-GPU traffic except roots, claims and
proof bytes. NCCL is not needed in this version.

## 6. What exists and what is new

| Exists | New |
| --- | --- |
| Strict-AOT registry, resident session, ABI schemas 1 to 29, cubin pinning | RV64 kernel catalog entries (ABI 30+): tape witness, chip witness, SHIFT16/EXTEND inverse tables, Poseidon2 Merkle |
| cairo_cuda executor: ingress, FFT, LDE, composition, FRI, Merkle (Blake2s) | Poseidon2 Merkle kernel; circle FFT kernels reused as is |
| word resident bridge: fractions, scan, centering, range table | generalized to the five RV64 relations |
| typed DAG codegen | symbolic lane for `emitFor` |
| host budget, allocation generation checks | multi-GPU queue in the Ethereum driver |

## 7. Implementation plan

| Step | Gate |
| --- | --- |
| 1. Symbolic lane and generated programs for BINARY (already on 2n) | generated CUDA evaluates the BINARY composition bit-identically to the CPU lane on a real fixture |
| 2. Poseidon2 Merkle kernel and FFT reuse on the current CPU shape | commit roots identical to the host for a real batch's columns |
| 3. Resident batch proof for the Word16 shape | proof verifies on the native receiver; byte-identical to the CPU proof of the same batch |
| 4. Multi-GPU driver with manifest phase | full block on 4 GPUs, fresh receiver, timings |
| 5. Leaves and parents on GPU | end-to-end root on 4 GPUs, p50 and p99 over a block range |

Requalification on an NVIDIA host is required for every step; the product
matrix defers CUDA distribution until then.

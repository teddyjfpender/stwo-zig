# RV64 CUDA port

Status: implementation proposal for `rv64_cuda_v1`; resource and latency
qualification remain outstanding. Builds on the existing strict-AOT
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
the same constraint set by construction, and the host OODS check supplies a probabilistic consistency check.
Complete native proof verification remains the acceptance gate. Shared
equations do not by themselves qualify kernel scheduling or memory safety;
register pressure, spills and intermediate lifetimes must also be measured,
particularly for the wide Keccak/secp components.

## 3. Memory plan, one 2^22-step batch on a 32 GB 5090

The arithmetic below assumes 271 effective base-field columns at n, including
125 CPU columns. This is a provisional model, not the final chip geometry.
One column at n = 2^22 costs **16,777,216 bytes**. GB here means 10^9 bytes.
The original 5 GB estimate undercounted these buffers by approximately four.

| Buffer | Decimal GB | Basis |
| --- | ---: | --- |
| CPU main + interaction + fixed at n | 2.097 | 125 x 2^22 x 4 B |
| Remaining family/table columns at equivalent n | 2.449 | (271 - 125) x 2^22 x 4 B |
| Extended evaluations at 2n | 9.093 | 271 x 2^23 x 4 B |
| Coefficients retained at n | 4.547 | 271 x 2^22 x 4 B |
| One composition evaluation at 2n | 0.134 | 2^23 QM31 values, 16 B each |
| Inverse tables, scratch, FRI layers | >= 0.500 | provisional allowance; measure by lifetime |
| **Separate-buffer subtotal** | **>= 18.821** | excludes additional service-provider work and device overhead |

Source and coefficient ownership can overlap or transfer, so this subtotal is
not an irreducible peak. Eliminating the entire 4.547 GB source copy would leave
about 14.275 GB under these assumptions. Neither figure includes independently
sized Keccak/secp providers, extra table padding, all commitment-tree buffers,
AOT/runtime allocations, or simultaneous composition intermediates. Those must
enter the allocation-lifetime ledger before admitting a batch to a 32 GB GPU.
Two batches in flight are **not** established by this model.

For comparison, 533 effective columns cost 8.942 GB at n, 17.884 GB at 2n,
and another 8.942 GB for independent coefficients: 35.769 GB before scratch and
providers. Ownership reuse can reduce that peak; a claimed 19 GB route requires
its own measured lifetime plan.

## 4. Throughput projection

Unqualified throughput hypothesis. A 2^22-point circle FFT on a 5090 is assumed to take ~0.3 ms (memory-bound, 16 MB
in and out); a batch needs about 400 column transforms for commits plus 400 for
the two composition cosets: ~0.25 s. Poseidon2 leaf hashing of ~2.5 GB of
extended columns at ~50 GB/s effective: ~0.05 s. Constraint kernels on 8M
points x ~700 constraints at a few hundred Gop/s: ~0.1 s. Interactions, FRI,
decommits: ~0.1 s. Total 0.3 to 0.6 s per batch on one GPU, 36 batches on four
GPUs in 3 to 6 s with the manifest phase first.

The per-FFT figure and resulting latency are not measurements or lower bounds.
They must be replaced by receipts for actual circle FFT sizes, memory traffic,
provider geometry, transfer costs and the complete resident proof. The corrected
resource plan above invalidates the original 5 GB basis for this projection.

## 5. Four GPUs

Shard-parallel: each GPU owns a queue of batches. Phase one (memory subtree
roots) runs for all batches first; roots go to the coordinator; phase two runs
as batches are assigned. Leaves run on whichever GPU finishes a batch; parents
run on any GPU as pairs complete. Inter-GPU communication can be restricted to roots, claims and proof bytes.
This does not eliminate host/device traffic for queued stage-one state. Before
the global challenge, the scheduler must bound retained memory advice and PCS
state across ALL queued batches, not just one resident proof. A durable spill
or root-checked reconstruction route must be qualified if complete residency
exceeds the budget; its transfers belong in end-to-end timing. NCCL is not
required by this proposed schedule.

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

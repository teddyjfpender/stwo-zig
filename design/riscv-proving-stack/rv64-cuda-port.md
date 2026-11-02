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

## 3. Actual OM31 resident contracts (2026-11-02)

The previous 5 GB and corrected 18.821 GB estimates used provisional 271-cell
geometry and QM31. They are historical estimates, not admission authority for
the current OM31 local-GKR frontend. OM31 has eight M31 coordinates (32 bytes).
CPU composition split 1 commits 16 base columns; Keccak truth split 2 commits
32. CPU and truth remain separate PCS proofs. Beta changes commitment LDE
height; the composition cosets follow each proof's own constraint degree.

The shape diagnostic now emits a machine-readable contract directly from
`Cpu.Plan.interLogs`, actual setup MAIN/FIXED logs, classic truth component
widths, and the existing PCS residency estimator. Run:

```sh
zig build rv64-om-retention-plan -Doptimize=ReleaseFast
zig-out/bin/rv64-om-retention-plan ROSTER.json 20 1
zig-out/bin/rv64-om-retention-plan ROSTER.json 20 2
```

The pinned full-block roster has 25 CPU and five truth proofs. Values below
are **GiB (2^30 bytes)** and exclude separately shared immutable FIXED and
unmodeled source-query/runtime/extra PCS scratch. These are buffer contracts,
not device measurements or sufficient GPU admission bounds.

| Compact coefficient-resident target | Beta 1 | Beta 2 |
| --- | ---: | ---: |
| All sealed MAIN coefficients/pruned nodes + bindings/known metadata | 54.75 | 55.46 |
| Largest CPU GKR seal with compact MAIN | 25.95 | 25.98 |
| That CPU's independently shared FIXED, full-retention bound | 1.14 | 2.07 |
| Keccak truth INTER commit, separate raw/coefficient owners + bounded tile | 12.76 | 12.94 |
| Keccak truth composition, one shared role/coset buffer | 14.52 | 14.43 |
| Keccak log-18, 64-column LDE tile (MiB) | 128 | 256 |

This target follows the CPU's existing compact representation: retain
coefficients and pruned nodes, stream at most 64 columns through commitment,
then release that LDE tile. Composition expands one component/coset on demand;
current/previous/next masks share its storage. DEEP keeps one secure aggregate
and bounded expansion workspace, then hands off to FRI. There is no new
cross-phase expansion cache. Progressive leaf storage now derives from the
actual native compact state: 96 bytes per leaf (32-byte chaining state plus
64-byte pending block); uniform counter/backend metadata is shared per wave.
This replaces the earlier 112-byte inner-hasher estimate. The pending block
includes a full final block when present. Historical receipt totals retain
their original source model; the planning API uses the current state type.
GPU equivalents are still unimplemented.

The contrasting policy that retains every MAIN LDE across the manifest needs
142.69 GiB at beta 1 or 231.53 GiB at beta 2 before FIXED. Under that policy,
a beta-2 Keccak INTER commit alone exceeds 40 GiB. It must not silently replace
the compact target in a device budget. The compact inventory can fit in the
aggregate capacity of four 32 GiB devices, but this does **not** establish a
per-device schedule: a live GKR task must coexist with earlier sealed owners.
Explicit per-device queued-state and transient leases remain necessary.

[Source contract](../../src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/resident_layout.zig)
provides checked geometry and represented-buffer budget rejection, with
separate source/coefficient/LDE/node owners and recursive opening exposure.
[Receipts and kernel inventory](../../vectors/reports/rv64-resident-layout-contract-20261102/summary.json)
pin the full roster at both betas. CUDA currently has M31 transform/hash
primitives, but its constraint, OODS/DEEP and FRI secure-field ABIs are QM31.
OM31 local GKR, classic interactions and full RV64 device AIR/PCS kernels need
explicit eight-coordinate implementations and qualification. No GPU run or
whole-protocol security claim follows from this ledger.

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

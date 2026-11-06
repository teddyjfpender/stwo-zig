# RV64 recursion backbone: Poseidon2 and a witness without the task DAG

Status: 2026-11-06, M8 stream poseidon-witness (delta §4 item 7, scope P2).
Decision note with a prototype plan. **No default, profile or production path
changes.** Labels: **[M]** measured, **[D]** derived from measured numbers,
**[E]** estimate. Receipts: `vectors/reports/rv64-m8-20261106/poseidon-witness/`.

## 1. The Poseidon2-W24 kernel [M]: 15.96 -> 11.83 ms (1.35x)

`src/backends/cuda/native/rv64/poseidon2_m31_fused.cuh` (default off,
selected only by `-DSTWO_P2_FUSED` in the numerical gates). Same pinned
parameters and framing as the M7 suite: width 24, RF 8, RP 22, x^5, rate 12,
capacity 12, 9-limb digests, two permutations per parent.

The deciding fact was a pipe measurement, not a kernel trick
(`tests/cuda/rv64/sm_int_pipes_probe.cu`, RTX 5090, 2.55 GHz):

| SASS class | lanes/clk/SM [M] | pipe |
|---|---:|---|
| LOP3, IADD3, SHF, LEA | 64 | integer ALU |
| IMAD | 64 | FMA (overlaps ALU: LOP3+IMAD pairs reach 2x) |
| IMAD.WIDE, IMAD.HI | 32 | FMA |
| IADD.64 | ~32 | ALU (two slots) |

Mask-and-shift M31 arithmetic (`(x & p) + (x >> 31)`, rotations, canonical
compare/select) issues only on the ALU pipe. Every formulation that kept it
(register packing, weak residues, tree sums, unrolled rounds, two rows per
thread) stayed at 15-16 ms on the 479-column x 2^20 slab: the kernel was
ALU-pipe bound with the FMA pipe idle. The kernel now writes folds as
`x - (x >> 31) p` (computed mod 2^32 as one IMAD with the multiplier in
`__constant__`, so ptxas cannot turn it back into shifts), splits u64 sums
between IMAD.WIDE accumulates and ALU carry chains, uses
`out_b = M4(x_b + X)` for the external layer, and keeps rotation sums and
round-constant folds on the ALU, so both pipes carry work. Every A/B step is
recorded in the header; compute-sanitizer memcheck reports 0 errors on the
smoke and a 479 x 2^12 tree [M]. A bit-exact u32 model with asserted fold
bounds (`scripts/rv64_m8_poseidon_fused_model.py`, unit-tested) checks the
weak-residue arithmetic, including the non-canonical zero p, against the
dense reference.

Retained Merkle tree (leaves + all parents), CUDA events, median of 5, roots
byte-identical across all variants and the independent CPU reference:

| class | permutations | Blake2s ms | v1 common-rotate ms | register-packed ms | **fused ms** | fused vs v1 | P2/Blake |
|---|---:|---:|---:|---:|---:|---:|---:|
| 47 x 2^14 | 98,302 | 0.040 | 0.525 | 0.543 | **0.328** | 1.60x | 8.3x |
| 128 x 2^14 | 212,990 | 0.048 | 0.615 | 0.656 | **0.386** | 1.60x | 8.1x |
| 479 x 2^14 | 688,126 | 0.080 | 0.982 | 1.126 | **0.633** | 1.55x | 7.9x |
| 47 x 2^17 | 786,430 | 0.068 | 0.841 | 0.840 | **0.556** | 1.51x | 8.2x |
| 128 x 2^17 | 1,703,934 | 0.097 | 1.223 | 1.219 | **0.838** | 1.46x | 8.6x |
| 304 x 2^17 | 3,670,014 | 0.171 | 2.081 | 2.074 | **1.450** | 1.44x | 8.5x |
| 479 x 2^17 | 5,505,022 | 0.234 | 2.873 | 2.852 | **2.013** | 1.43x | 8.6x |
| 128 x 2^20 | 13,631,486 | 0.440 | 5.332 | 5.110 | **3.899** | 1.37x | 8.9x |
| 479 x 2^20 | 44,040,190 | 1.367 | 15.957 | 15.195 | **11.833** | 1.35x | 8.7x |

Poseidon remains ~9x slower than Blake2s per hashed cell on this operation
(Blake is memory-bound at ~1.5 TB/s; P2 is integer-issue bound). The
remaining levers are protocol, not kernel: a width-24 compression mode for
parents (18 limbs fit one permutation: 2 -> 1 permutation per node) and rate
16 / capacity 8 for leaves (40 -> 30 permutations per 479-column row) would
cut leaf-heavy trees by up to 1.33x but change the suite and its security
argument; they are listed, not proposed here.

## 2. Net GPU-seconds per block, 24628607 [D/E]

Inputs (all committed): the kernel receipt above; the exact M7 native
hash-operation census (warm, FIXED omitted: 1.431 G P2 prefix permutations,
0.943 G Blake compressions); the D2 + coalescing recursion census (21.66 G
padded cells: 13.22 G leaves, 8.44 G folds); the measured after-native kernel
time (6.204 GPU-s of 10.585); the M7 full CPU-leaf censuses (554.8 M Blake,
106.3 M pure P2, 247.8 M mixed). Script: `scripts/rv64_m8_poseidon_backbone_cost.py`.

| per block, warm | today (D2, Blake) | (a) all-Poseidon | (b) mixed |
|---|---:|---:|---:|
| native Merkle hashing GPU-s [D] | 0.040 | 0.384-0.409 | same as (a) |
| recursion padded cells [D today, E options] | 21.66 G | 4.15-6.30 G | 14.34 G |
| recursion P2 commit overhead GPU-s [E] | 0 | 0.21-0.32 | 0 |
| recursion kernel GPU-s [M today, E options] | 6.20 | 1.40-2.13 | 4.11 |
| **net delta GPU-s per block [E]** | — | **-4.46 to -3.70** | **-1.75 to -1.73** |
| request kernel GPU-s [M today, E options] | 10.58 | 6.13-6.88 | 8.83-8.86 |

With the M7 kernel instead, the net deltas would be -4.23 to -3.42 (a) and -1.62 to -1.58 (b): the kernel pass is worth ~0.2 GPU-s per block [D]; the backbone choice is worth 2-4 GPU-s.

How to read it:

- **Native side.** The P2 native PCS adds 0.34-0.37 GPU-s of hashing
  [D, census x measured kernel rate]. The M7 kernel would have added
  0.48-0.52. That is now small against the recursion term.
- **(a) all-Poseidon.** Leaves at the measured census ratio (x0.192) [D on the
  census leaf, E on production leaves]; folds verify P2 recursive proofs, an
  unmeasured ratio banded between x0.192 and x0.447 [E]; recursion proofs now
  commit with P2, charged as LDE cells x (P2 - Blake) per-cell hashing [E].
- **(b) mixed** (P2 native PCS, residual Blake GKR/frame; folds unchanged).
  Folds still verify Blake recursive proofs, so they do not shrink [D].
- The recursion term assumes GPU-s linear in padded cells at today's
  0.2865 ns/cell [D]. Per-node fixed costs (about 105 blocking calls, ~1.8 k
  launches, graph instantiation, host prep) do **not** shrink with cells, so
  the latency gain is smaller than the GPU-second gain until the enqueue
  streams land. Request-time effects are not claimed.

## 3. The recursion witness without the task DAG

Today the recursion witness is a task-interpreter DAG (146 k -> 73 k levels)
with per-node host prep of 0.1-0.7 s [M, critical-chain table] and
MAIN-assignment kernels of 1.215 GPU-s over 19 nodes [M]. Two frontier
designs remove the DAG.

### Option A: verifier as a guest program (Airbender §1.3/§1.5)

The verifier becomes an RV64 program; recursion layers are ordinary native
proofs of its execution, and the witness is the native row-parallel path.

Cost [E]: the P2 leaf verifier is 1.92 M QM31 ops, 30.7 k P2 permutations,
82 k equalities and 119 k conversions [D, source-exact M7 AST census]. At ~85 RV64 cycles per
QM31 op (M31 mul ~6 instructions; QM31 mul ~3 CM31 muls plus adds; operand
loads) [E], and P2 through the existing custom0 precompile, that is about
1.6e8 guest cycles per leaf [E]. Our native prover spends 4.381 GPU-s on
26.89 M steps of 24628607 [M], 163 ns/step [D, includes capture/setup]. One
leaf as a guest would cost ~26 GPU-s [E] against ~0.03 GPU-s for the P2
leaf circuit at today's per-cell rate [E]: ~900x. Even a verification-only
machine 20x cheaper per cycle would stay ~45x behind. Airbender gets away with
it because its verifier is ~1 M cycles per circuit proof and its machine is
the recursion circuit. **NO-GO** for us [E].

### Option B: compact witness plus GPU gate-interior expansion (ZisK §2.3)

ZisK's circom verifier is compiled to a plonk exec map: the host computes only
the variables the map places, ships one contiguous compact buffer, and the GPU
widens it and rebuilds hash-gate interiors from their boundary cells
(`pil2-stark/src/starkpil/recursion_trace/{witness_widen_gpu.cu,gate_bands/*}`).
Hash interiors never cross PCIe; there is no dependency DAG.

For our circuit this maps directly: the recursion AST is already a fixed
per-class program. Its witness is (1) a program-order evaluation of the
verifier over the child proof (the values every QM31/eq/conversion row
places), and (2) hash-gate interiors, which are a pure function of their
inputs.

Cost:
- Host program-order evaluation of 1.92 M QM31 ops with random operand
  gathers: 35.6 ns/op single-threaded [M, synthetic proxy
  `bench/rv64/qm31_straightline_probe.c`, median of 5, pod load ~11], 68 ms
  per leaf [D]. The 54 FRI queries are independent,
  so this parallelises across cores [E]; today's prep is 100-700 ms per node [M].
- Compact buffer at most 44 MB per leaf (2.78 M variables x 16 B, QM31
  upper bound) [D]; at an assumed 25 GB/s pinned H2D that is ~1.8 ms [E].
- GPU interior expansion: with Poseidon2 the leaf has only 30.7 k
  permutation rows; at the measured 3.72 G perm/s that is ~8 us
  [D] (a Blake leaf's G-function/XOR interiors are far larger, which is the
  second reason to do this together with Poseidon2).
- Widening/placement: one gather kernel over ~0.11 G cells, well under a
  millisecond at memory bandwidth [E].

**Decision: Option B, jointly with the Poseidon2 backbone.** With Poseidon2
the hash interiors shrink to a trivial kernel, the remaining witness is
boundary values that a host program-order pass produces in tens of
milliseconds, and the DAG, its level scheduler and the per-class caches can be
deleted. Option A is rejected on derived cost.

## 4. Prototype plan (each step default off, byte-identical unless named)

1. **W1 exec map, Blake circuit first** (outer-enqueue owns `rv64_recursion/*`;
   request through M8-INTERFACES): emit, per recursion class, the straight-line
   op list and the placement map from the existing AST. A host program-order
   evaluator fills the compact buffer. Gate: the widened trace is byte-identical
   to today's DAG witness on both dev blocks; fresh receivers.
   Flag `STWO_RV64_M8_WITNESS_COMPACT=1`.
2. **W2 GPU widen + interior expansion**: one placement kernel plus one
   interior kernel per hash-gate family (Blake today, P2 later, using
   `poseidon2_m31_fused.cuh` round code with snapshot writes). Gate: same
   byte identity; measure host prep and MAIN-assignment GPU-s per node.
3. **P2-S2 native profile**: P2 physical PCS on the native side through a new
   36-byte-root device ABI (named mixed suite first), fresh receiver, tamper
   corpus. Measure native GPU-s against the derived 0.34-0.37.
4. **P2-S3 leaf circuit**: the 106.3 M-cell P2 leaf with the compact witness.
   Measure leaf cells and leaf GPU-s against the census.
5. **P2-S4 folds/root in P2** (all-Poseidon), then the matched request-time
   measurement in the composed stack. The final on-chain wrapper stays a
   separately named Blake/Keccak layer.

Prerequisites outside this stream: enqueue-only outer prove (outer-enqueue),
so that the smaller nodes translate into latency; the memory plan (memory), so
smaller nodes become two-in-flight.

## 5. Not claimed

No proof, receiver, tamper corpus, security certificate or request-time
improvement. The kernel numbers are retained-tree hashing only (no FFT,
transfer, transcript, PoW or openings). Section 2 is a cell-linear model over
committed censuses; section 3 option costs are derived or estimated as
labelled.

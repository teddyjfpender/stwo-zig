---
name: cuda-kernel-engineering
description: Implement and review CUDA prover kernels under exact field, transcript, AOT, ABI, memory-traffic, and occupancy contracts. Use after profiling identifies a dominant CUDA kernel or pass.
---

# Engineer CUDA proof kernels

Kernel work follows `../cuda-profiling/SKILL.md` and
`../cuda-performance-design/SKILL.md`. Do not start from an isolated kernel
idea. Start from a measured stage, work/byte ledger, and complete-proof target.

## Correctness first

Before editing record:

- field representation, canonical/noncanonical range, and reduction schedule;
- integer overflow bounds and signedness;
- input/output layouts, strides, alignment, and alias constraints;
- transcript-visible ordering;
- synchronization scope;
- expected CPU and CUDA intermediate digests;
- final pinned-Rust oracle vector.

Fast math, reassociation, reduced precision, undefined overflow, unaligned type
punning, and architecture-dependent ordering are correctness changes.

## Mapping checklist

For one logical output identify:

- threads, warps, cooperative groups, and blocks involved;
- contiguous global loads/stores and transaction width;
- reuse in registers, shared memory, L2, or immutable cache;
- divergence and inactive lanes;
- reductions/scans and required barriers;
- register and shared-memory budget;
- grid size needed to saturate the target SM;
- tail and non-power-of-two behavior;
- bytes and operations per output.

Use warp intrinsics only inside their valid active mask. Use block
synchronization for block-wide communication. No block may depend on another
block inside an ordinary kernel without a supported cooperative-launch contract.

## Field arithmetic

- Encode modulus and representation invariants near the primitive.
- Prove the maximum unreduced accumulator before delaying reduction.
- Prefer bounded branchless reductions when their range proof is explicit.
- Test zero, one, modulus edges, maximum limb values, carries, and random
  differential vectors.
- Verify PTX/SASS only after source-level correctness is established.
- Compare final proof bytes, not only arithmetic samples.

## Merkle and commitment work

For commitment kernels measure:

- leaf encoding/materialization passes;
- child reads and parent writes at every tree level;
- tree-layout locality;
- launch count per level or group of levels;
- register/shared-memory state for fused levels;
- retained opening/decommitment consumers;
- redundant rereads from trace and tree storage.

Consider fused lower levels, persistent tree tiles, batched independent trees,
and direct consumption of resident coefficient/LDE arenas. Reject fusion that
spills, reduces occupancy enough to lose time, or makes openings incorrect.

## FFT, quotient, and FRI work

- Derive index permutations and domain walks algebraically.
- Test target and non-target sizes.
- Compare every coefficient/evaluation for forced accelerated paths.
- Count global read/write passes per radix schedule.
- Measure twiddle cache behavior and register pressure.
- Preserve FRI round and transcript barriers.
- Fuse fold/commit work only when the proof DAG permits it.

## Variant policy

Variants are allowed for measured SM or shape regimes, not arbitrary benchmark
IDs. Admission predicates use structural properties such as alignment, width,
domain size, or resource bounds. Every accelerated predicate has:

- boundary tests immediately below/at/above admission;
- a forced-path CPU differential test;
- a generic CUDA differential path where practical;
- exact module and variant telemetry;
- a safe fail-closed rejection, never CPU fallback.

## Build and ABI

- Production kernels are AOT and listed in the authenticated source/product
  manifests.
- Kernel symbols, parameter layouts, sizes, alignments, and important offsets
  have host/device ABI tests.
- No dead vendor source becomes product authority accidentally.
- CUDA errors include stage and kernel identity and are checked at the correct
  asynchronous boundary.
- Debug-only synchronization and validation do not enter verdict binaries.

## Evidence required to keep a kernel change

1. focused arithmetic/layout/ABI tests;
2. forced-path intermediate differential tests;
3. exact proof bytes and pinned oracle acceptance;
4. zero fallback/JIT and one terminal D2H;
5. before/after kernel counters;
6. before/after complete stage time;
7. uninstrumented structural ABBA result;
8. peak memory, register, spill, launch, and synchronization delta;
9. no workload beyond its regression ceiling.

Delete rejected experiments completely and retain their diagnosis in an
autoresearch note.

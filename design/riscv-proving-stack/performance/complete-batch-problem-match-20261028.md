# Direct aggregation at the complete-bundle boundary

## Problem match before implementation

**Task and semantics.** Verify exactly the same ordered native executions and
global RAM, register, ROM, lookup, caller and endpoint equations with fewer
recursive STARKs. A complete bundle is not a standalone recursive block root:
its global proof files remain required verifier inputs.

**Inputs and measured model.** The two-segment, 307,214-cycle q70/26 comparison
uses a real register/load/store loop plus SHA and Keccak. With register-local
custody, the driver takes 86.743 s: collection 1.530, proving (including native
wrappers) 30.423, forest 52.720, verification 2.069. Memory/range proving takes
1.750 s within the proving phase. These are single samples on the M5, eight
workers. Their timing is not a production block forecast.

| Match | Relationship and limits | Transfer and risk |
|---|---|---|
| Contract unnecessary nodes in a proof dependency DAG | Structural analogy; correctness requires a new verifier theorem, not graph rewriting alone | Directly verify native children in one recursive STARK; preserve every statement and residual |
| Multi-component STARK / joint PCS | Exact protocol family already supported by Stwo | Fuse compatible base AIRs before recursion; challenge phases, indices and degree bounds must be reconciled |
| Contiguous segmentation with measured costs | Dynamic programming is exact only for a supplied additive cost model | Choose native partitions using total native plus recursion cost under peak-memory bounds; measurements are needed for mixed workloads |
| Cache setup / increase fan-in alone | Constant-factor alternative | Leaves most commitment/FRI verification work intact; insufficient by itself |

**Selected transfer.** First implement a complete receiver for a single bounded
direct-native batch (1–8 children), using existing batch AIR and native policy
reconstruction. It reuses the original fresh global receiver, not producer
receipts. Its result has a distinct type and does not masquerade as a V5 exact
forest or a self-contained block root. The initial test can reuse base files
from the old driver to establish equivalence; that does not measure a new
end-to-end driver. Next replace leaf publication and the forest scheduler,
then measure first-input-to-complete-bundle latency without executing old wrappers.

**Complexity and parameters.** For k children the batch still verifies k native
STARKs; removing wrapper nodes removes their verifier work but does not make
child verification constant-time. The existing batch limit is eight. Larger
native partitions and joint base proofs reduce k upstream. Their gains overlap
with wrapper removal and must not be multiplied. No new security parameters
or weakened transcript binding are permitted.

**Evidence and prior implementations.** Local direct batching measured 16.98×
less recursion time on a tiny two-segment open-global fixture; same-execution
native repartitioning measured 12.33× lower phase sum at 851,968 cycles. These
motivate integration, not a promised further 10×. The
[Stwo prover](https://github.com/starkware-libs/stwo/blob/dev/crates/stwo/src/prover/mod.rs)
accepts multiple component provers into one composition and commitment scheme;
this supports the later joint-PCS direction. ZisK's proof manager recently
fixed [all-null recursive aggregation](https://github.com/0xPolygonHermez/pil2-proofman/pull/618)
and [airgroup transcript binding](https://github.com/0xPolygonHermez/pil2-proofman/pull/619).
These are reasons to retain exact nonempty coverage and physical-claim binding,
not evidence for a transferable speedup. No external implementation is copied.

**Falsifier and correctness plan.** Reconstruct batch public inputs from fresh
native receipts created inside complete global verification. Require exact
segment count, full PC/clock span, job/source/seal identity, native residual,
canonical security and expected key identity. Reject omission, substitution,
wrong key and modified proof bytes. Use a real RAM/caller fixture at diagnostic
then canonical security. Record preparation, recursive proof and fresh complete
verification separately; never subtract an old phase from a total and call the
result a measured driver speedup.

**Open uncertainty.** The richer native statements may make direct aggregation
more expensive than the ALU fixtures. Global proofs remain outside recursion;
closing them can dominate a final block root. The 10× end-to-end target requires
joint proof structure and less repeated wide witness work as well as batching.

## Concrete integration boundaries

**Measured integration update:** the bounded replacement driver is now
implemented and qualified by the matched fixture. At canonical security it
measures 87.195 → 32.992 s, with fresh complete verification and hostile-claim
rejection. See [driver results](native-batch-driver-m5-20261028.md). Checklist
items 1, 2, 3, 4 (single batch only), 5 and 6 below are complete for the
one-to-eight-execution path. Multi-batch coverage and global recursive closure
remain open; no standalone block-root claim follows from this test.

The first receiver implementation now lives in
`block_v5_global_receiver_impl_v1.zig:verifyCompleteNativeBatch`, selected only
by an explicit NativeV3 call. It does not alter the existing forest receiver.
It returns a separate `VerifiedNativeBatchBundle`; its embedded V5 forest flag
stays pending. Capacity and readonly-global stacks are rejected explicitly.

The next driver change must remove work, not merely append the new proof:

1. Extract shared collection/assembly/base publication from
   `block_v5_cpu_driver_common_v1.zig` with an owned recursion-publication
   strategy. Keep the existing family queue, rollback and pool lifetime rules.
   The V5 strategy retains its current leaf/forest behavior for comparison.
2. Add bounded V6 native capture publication at `Hooks.nativeProof`. It must
   preserve the native leaf hook's original policy/catalog checks. Drain each
   admitted group into direct batch rows; bound simultaneous captures, rows and
   setups by the shared allocator. Persist finished batch proof bytes and pins.
3. Write a new metadata/manifest version for **execution spans per batch**.
   The old metadata assumes one recursive leaf per execution and cannot be
   reinterpreted by changing a count. Bind exact ordered nonempty coverage;
   no dummy proof or unverified null slot is permitted.
4. For a whole job of at most eight executions, use the batch as the native
   recursive result directly. For larger jobs, reuse the already tested
   normalized batch-to-upper receiver and independently reconstruct every child
   policy from the original native roster. Require complete span coverage at
   the final upper node; do not round the proof count up to a power of two.
5. Reopen all base files and V6 metadata in a cold detached receiver. The new
   complete receive method is the initial small-job semantic oracle. Keep
   global proof files required until their own recursive closure is implemented.
6. Compare the same ELF, external inputs, security and expected state roots
   using the old and new driver. Include source preparation, publication,
   verification and memory. Only this run can establish a replacement-driver
   speedup. A proof built from already available base files cannot do so.

After this integration, make native+companion joint PCS the next substantial
change. Native interaction columns currently occupy a different commitment
phase than the fused companion's witness/interaction columns. A valid joint
layout must remap every component's tree indices, absorb all physical claims
before their interaction commitment, retain the seal/catalog equations, and
re-pin template identity and independent recursive capture geometry. Merely
sharing a transcript object or concatenating proof bytes is not joint proving.

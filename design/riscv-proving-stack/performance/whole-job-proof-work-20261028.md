# Whole-block proof work: architecture decision after direct aggregation

## Required statement and evidence

The objective is a single independently verifiable proof of the pinned Ethereum
validator guest on its authenticated input, including successful completion and
the expected public output. Guest identity, input encoding, security parameters,
precompile semantics and output interpretation remain part of admission. A proof
of arbitrary RISC-V execution is not by itself an Ethereum validity claim.

The current V5/V6 bundle additionally binds initial and final VM RAM roots.
These are VM checkpoints, not Ethereum state roots. Changing that contract
requires an explicitly versioned theorem and independent verifier. Existing
checkpoint verification must continue rejecting altered roots.

**Measured:** the new driver reduces the mixed 307,214-cycle, two-segment fixture
from 87.195 to 32.992 s, including fresh complete bundle verification. Recursion
still takes 20.491 s (62.1%); base publication 8.882 s (26.9%). Collection and
verification together are 3.619 s. See the [measurement](native-batch-driver-m5-20261028.md).

**Derived:** even removing all work outside recursion could improve this wall
time by at most 1.61×. Removing all recursive preparation and setup still leaves
8.758 s of recursive proving alone. Faster parsing, caches or eliminating host
RAM-root reconstruction cannot independently provide another 10× here.

**Not measured:** a completed Ethereum block with the new driver; any GPU
execution of this block architecture; a transferable Stwo-versus-ZisK ratio.
The earlier hours estimate was a straight cycle extrapolation from a small CPU
fixture. It is not a production forecast and must not guide the design.

## Problem matching

Inputs are ordered execution segments, typed memory/precompile/lookup events,
fixed program data, and the independently supplied block statement. The retained
block has 139,214,856 cycles, 67 segments and 622 base proof files. Costs depend
on component populations, committed cells, verifier openings and recursive
depth, not just cycles. Memory and GPU capacity constrain concurrency.

| Candidate | Relationship and guarantee | Transfer and risk |
|---|---|---|
| Joint multi-component STARK | Existing protocol family; requires exact shared commitment and challenge schedule | Combine native and companion AIRs before recursion; eliminate repeated PCS/FRI verification while retaining every relation |
| Streaming authenticated event bridge | Commit-before-challenge reduction; requires a new binding proof | Finish wide execution proofs once; later close global buses through narrow event commitments |
| Whole-job memory consistency | Different statement from a persistent checkpoint theorem | Authenticate initialization, sorted memory transitions and final output reads; omit only unnecessary final VM RAM authentication |
| Larger recursive fan-in alone | Dependency-graph contraction | Removes intermediate nodes but still verifies all base commitments; insufficient alone |
| GPU acceleration alone | Parallel implementation of unchanged work | Useful after work removal; no claim that an inefficient proof graph becomes competitive merely by moving it to CUDA |

The first two are selected for implementation. Whole-job memory semantics are
a separately gated architectural experiment, not a flag disabling V5 checks.
No copied external implementation is included.

## 1. Joint native and companion commitment

`block_v5_program_native_batch_common_v1.zig:verifyFused` still loads an original
native proof and a separate fused projection/memory proof. The word "fused"
does not mean these share one PCS. Native proving in
`block_v5_native_execution_proof_v3.zig` commits its own interaction trace and
runs its own composition/FRI proof. A joint protocol should instead admit both
component sets under one commitment schedule.

Integration requirements:

1. Define a new template identity binding component roster, field/hash suite,
   every column's commitment phase, degree bound and public statement schema.
2. Commit the union of fixed columns and the union of input-dependent main
   columns. Remap component tree indices explicitly; do not concatenate proof
   files or change verifier indices without re-pinning the template.
3. Preserve global prechallenge binding. Absorb **every physical claim** before
   interaction commitment, in a canonical order shared by prover and verifier.
   Retain component-specific residuals; aggregate cancellation is insufficient.
4. Build one composition and PCS proof. Component domains may differ; avoid
   raising small fixed/provider tables to the native domain unnecessarily.
5. Export native and companion residuals from a single fresh verified capture.
   Compile that exact joined verifier into recursion. Reconstruct admission
   from the original independently pinned statement, not producer metadata.

The initial comparison is the same mixed guest and security profile. Count
STARKs, trees, opening words, G rows and committed cells, then measure base,
recursion and complete verification wall time. A win in base proving that adds
more recursive verification work is a failed design. The existing standalone
proofs remain the semantic comparison oracle during migration.

## 2. Prove each wide execution witness once

The duplication is explicit:
`block_v5_cpu_native_root_proposal_v1.zig:collect` builds a PCS and immediately
destroys it. `block_v5_cpu_collect_impl_v1.zig` stages the witness and collects
ordinary/caller commitments. Later, the original native producer reconstructs
and commits it again after the global source seal is available. The seal's
dependency on all first-round roots makes simply proving early incorrect.

The selected replacement is a narrow, authenticated event interface: each local
proof binds its program/step span, main witness commitment, and canonical event
commitments. Once all event commitments are fixed, the job transcript derives
global bus challenges. A bridge proves that the local committed event tuples
are exactly those consumed by memory, ROM, lookup and precompile providers.
The global reduction then verifies local proofs and bridge/provider proofs.

This removes the all-job barrier from wide trace proving without retaining all
wide PCS trees in RAM. The events must include direction, family, namespace,
segment/global clock, address/operation, value and multiplicity. Count and span
coverage are mandatory. The bridge must bind to the **same commitment** opened
by the local proof; a later hash of a separately generated event file does not
establish that relation. Zero, duplicate and omitted providers must be rejected.

Complexity target: one wide trace construction/commitment/proof per execution
component; additional work proportional to the narrower event interface and
its openings. Saving one duplicate pass is not itself 10×. It enables overlap
and the memory-area savings to reach complete-job latency.

## 3. Separate VM checkpoint custody from whole-job I/O

**Sourced comparison:** ZisK's memory AIR orders accesses by address and step,
links memory instances through continuation relations, and packs independent
lanes separately from same-value dual accesses. Its continuation identity
includes memory area and segment identity. This is a useful implementation
reference for memory consistency, not evidence that one can omit our existing
statement checks. Source pinned at
[`1e22630`](https://github.com/0xPolygonHermez/zisk/blob/1e22630bb7e143c30705a1603ed87cfd3da8c6ec/state-machines/mem/pil/mem.pil).

Our `block_v5_rw_endpoint_sources_v1.zig:check` constructs the initial RAM tree,
merges every touched endpoint with untouched initial leaves, and constructs
the final RAM tree. The source-page recursion proves related authentication
work. `blake3_execution_preflight.zig` also computes VM endpoint roots and binds
terminal output words. Existing sorted RAM already handles temporal consistency;
we must reuse it rather than reimplement sorting under a new name.

**Hypothesis:** for a new whole-job theorem, private final scratch memory need
not be externally authenticated if all execution and public output reads are
constrained. Ethereum trie/state authentication inside the guest remains required.

Before integration, the new theorem must establish:

- Exact ELF/program admission and initialized data, zero/BSS and authenticated
  input values. Prover-supplied first values are not acceptable initialization.
- Every native and precompile access participates in the same memory relation;
  no register traffic is dropped without the local register invariant.
- Strict address grouping and timestamp/operation ordering, including partition
  boundaries, with a unique start and no disconnected continuation cycles.
- Output length, output bytes and completion flag are bound to the actual last
  accesses and the expected job statement; unobserved or overwritten output
  cannot be accepted.
- Ordered PC/clock/register spans and exact nonempty execution coverage.
- Independent cryptographic verification of all those equations at the root.

Test changed initial values, later overwrite of output, omitted/duplicated RAM
events, disconnected memory partitions, phantom precompile access and altered
public state root. Validate against the checkpoint route on matched executions.
Do not reuse its key ID or report checkpoint-resume capability. This proposal
is **not implemented or soundness-qualified** and has no claimed speedup.

## Publication criterion

The deliverable is an actual first-input-to-single-root proof with all global
families recursively closed, independent verification and hardware/security
metadata. Publish guest execution, collection, native/precompile/global proofs,
recursion, final verification, peak memory and total wall time separately.
Until that exists, report component and complete-bundle results under their
actual scopes. No further cycle-based block ETA is warranted.

---
title: One caller arithmetic and relation proof: exact mask union and protocol plan
author: Teddy Pender
created_utc: 2026-10-28T19:21:24Z
---

# One caller proof: problem match and implementation boundary

Status: design and isolated mask-routing primitive. The current B6 complete
root route is unchanged. No combined caller proof has been qualified.

## Pre-implementation problem match

**Task and semantics.** Prove the conjunction of original precompile arithmetic
and caller program/state/table/memory constraints with one commitment opening,
composition polynomial and FRI proof. Keep every arithmetic physical LogUp
claim and every separately typed global accounting contribution. No provider
obligation may disappear by summing unlike relations.

**Inputs and scale.** Inputs are the independently admitted original statement,
caller binding, shared fixed/main roots, access root, frame and global seal.
The original-mask SHA1/Keccak1 fixture has 15,139 fused trace columns and 410,814
raw cells; 4,340 columns are not sampled by the fused verifier, but may be
required by arithmetic. This is fixture geometry, not an Ethereum estimate.
The cost model is field/FFT work, commitment and recursive hash work, plus
peak live allocations. The existing caller has two independent proof schedules.

**Structure and invariants.** Both proofs already lease the same fixed/main
trees and enforce identical caller roots. Their interactions and claims differ.
The native partitioned protocol demonstrates a later, stronger transformation
that keeps direct equations and covers every original lookup exactly once.
The immediate caller transformation is the conjunction of both original
constraint systems; it does not yet eliminate duplicate relation equations.

| Candidate | Relationship and guarantee | Fit and implementation | Risk |
| --- | --- | --- | --- |
| Batch both original component systems into one STARK | Exact conjunction, with independently bound randomized composition | Existing component accumulator, shared trees and joint relocation | Mask order, quotient normalization, transcript omissions |
| Direct equations plus one complete typed relation partition | Exact only after a symbolic coverage proof | B6 native layout is a local model | Caller SHA/Keccak/secp equations and relations have different decompositions |
| Delete unused fused columns | Not an equivalent transformation of shared commitments | At most 25.09% of fused cells in this fixture | Breaks root equality to arithmetic; requires a new proved projection |
| Aggregate the existing two proofs recursively | Exact but retains both base and verifier costs | Current complete route | Does not remove duplicated work |

**Chosen variant and mapping.** First use batched polynomial constraint
evaluation: concatenate the two original equation rosters under one independently
derived component schedule. Shared fixed/main columns map to one physical
tree; private interaction columns map to distinct trees. Original sample
coordinates map through an exact ordered union. Solution recovery exports
the original arithmetic and fused accounting contributions from one verified
public claim frame, not from fabricated legacy receipts.

**Prior implementation and evidence.** Stwo's original
[component accumulator](https://github.com/starkware-libs/stwo/blob/main/crates/prover/src/core/air/components.rs)
combines component quotient evaluations using a common random coefficient and
derives the maximum component degree. This supports component batching, not a
claim that arbitrary mask or transcript changes are valid. The repository's
`block_v6_joint_components_v1` already relocates trees and uses the existing
quotient-extension transform when composition splits differ. The stronger
`block_v6_partitioned_native_proof_v1` is the local implementation precedent
for a later complete caller relation partition. No external source code is
copied for this primitive.

**Complexity.** For C shared columns and at most S original samples per column,
stable exact union takes O(C S²) point comparisons and O(C S) output/route
storage; S is bounded explicitly. Each original sample has exactly one route
back into the union. This is a small bounded canonicalization problem, not an
optimization heuristic. Original ordering and duplicate occurrences remain
available through routes. The primitive does not change transcript claims.

**Prediction and falsifier.** One caller means one combined FRI/composition
instead of two. Shared roots are sampled under one joint schedule. Actual
constraint work remains approximately the sum in this first phase. Savings
are conditional: if composition-degree inflation, larger masks or recursive
columns dominate the removed proof overhead, this phase can regress. Measure
full prove+verify and parent row counts; reject a slower phase rather than
reporting proof-count reduction as performance.

**Correctness plan.** Exact mask coverage, repeated points, incompatible
ordering, empty masks, domain-separated steps, caps and allocation failures.
Then compare every original symbolic equation and point/domain accumulation
against the joint compiler. Genuine SHA, Keccak, secp and mixed proofs must
verify; altered physical claims, roots, route indices and missing components
must fail. Derive the recursive key independently from metadata, and qualify
it against the live joint verifier before replacing the current two children.

**Uncertainty.** No combined proof timing exists. A union may exceed the
current named DEEP sample-layout variants. Such a shape must be supported by
an exact authenticated offset schedule or rejected, never approximated.

## Minimal protocol and tree schedule

Use a new caller-joint version/domain and independent admission identity.

| Joint trace tree | Original arithmetic view | Original fused view |
| --- | --- | --- |
| 0 fixed | 0 | 0 |
| 1 main | 1 | 1 |
| 2 external access | absent | 2 |
| 3 arithmetic interaction | 2 | absent |
| 4 fused interaction | absent | 3 |
| 5 composition commitment | combined | combined |

Keep both interaction bases initially. Their exact tree positions and widths
must be part of the new template identity. The existing access first-round
lease owns trees 0–2 and may append interactions 3–4. The arithmetic producer
must expose its interaction columns/claims without consuming its first-round
owner or producing a separate proof. The caller and access owners must pass
the existing exact root and shared-column checks first.

The joint transcript starts from the authenticated global seal/challenges and
mixes a new domain, original caller binding, independent joint template,
geometry/route digest and access root. Mix the entire arithmetic physical
claim frame and every fused program/state/table/memory/range/count claim before
committing either interaction tree. Commit trees 3 and 4 in a fixed documented
order, then let the ordinary STARK engine derive one composition/OODS/FRI
schedule. Never reuse an old proof's later challenges or final channel.

## Changes needed for a complete implementation

1. **Original equations and geometry.** Build original arithmetic and fused
   owners, choose the canonical common composition split, and use a proved
   quotient-extension transform for lower-split components. Existing joint
   relocation only handles a one-step lift; larger differences must explicitly
   fail until their transform is supported. Build exact shared masks once and
   route each original component to its original ordered mask view. Domain
   evaluation uses the same tree remapping and quotient transformation.
2. **Shared main declaration.** Declare shared main columns exactly once.
   The existing native joint adapter's prefix-subset test is insufficient for
   general caller masks. The new isolated union primitive preserves both
   original orders; the component wrapper must consume its routes rather than
   forwarding a union array to code expecting a smaller original mask.
3. **Generation and original verification.** Extract original arithmetic
   interaction generation and fused interaction generation into owned results.
   Consume the retained access lease for one engine prove. Fresh verification
   reconstructs fixed roots, original statement/admission and both equation
   systems independently, then verifies the six-commitment proof.
4. **Recursive compiler.** Add an explicit six-commitment family profile to
   DEEP, path, opening and fixed-PCS adapters; current supported cardinalities
   cannot be silently widened. Record arithmetic then fused constraints in
   exactly the prover order, with one random-coefficient sequence. Both
   existing symbolic recorders need the same joint quotient normalization and
   mapped sample views. Use a new public bus and capture type carrying both
   claim sets. A cold key factory must reproduce the exact fixed schedule.
5. **Global receiver and roster.** One joint child replaces the paired
   arithmetic/fused roster entries. Its typed exports still expose both
   contributions, bound to the identical caller binding and census. Update
   codec version, mixed roster compiler, key schedule and public closure
   together; do not alias the old two-child identities.
6. **Second phase.** After the exact conjunction is qualified and measured,
   replace duplicated caller lookup work with one symbolic relation partition.
   A complete coverage proof must account for every original lookup entry's
   tuple, sign, symbolic multiplicity, active selector and physical batch.
   Direct arithmetic, range, clock, register and memory invariants remain.
   This can combine interaction storage into one basis and reduce six total
   commitments to five, but is a separate protocol/qualification step.

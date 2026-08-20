# ADR-0040 — Separate split-proof joining from temporal recursion

**Status:** accepted
**Date:** 2026-08-14

**Classification:** recursion soundness boundary; supersedes the combined
leaf/pair model proposed in ADR-0036

## Context

Two different binary operations are required by the original design:

1. parallel core/request and precompile-provider proofs describe different
   constraint partitions of the **same execution span**; and
2. a recursive `2 -> 1` node combines two complete proofs for **adjacent
   execution spans**.

The development V1 pair record used `core_request` and
`poseidon2_provider` as its two child roles and required their signed relation
totals to cancel.  The later binary statement source also applied
`SpanStatement.fold` to those children.  These requirements cannot describe
one sound operation: split-proof children must name the same statement, while
temporally recursive children must name adjacent statements.  A successful
STARK over that mixed authority would demonstrate equation plumbing, but not
a correct recursive aggregation protocol.

The current one-proof native RISC-V path already proves core and precompile
components together.  It therefore yields one complete execution leaf and
does not need a synthetic core/provider role at the recursion boundary.

## Decision

The two operations have distinct versioned authorities and transcripts.

### Split-proof join

A split-proof join, when the parallel proof path is activated, consumes a
`core_request` proof and a `precompile_provider` proof for the same canonical
execution statement.  It checks equal statement/session/job identities,
disjoint component ownership, the shared challenge context, and exact
cross-proof relation closure.  Its output is one complete execution-leaf
authority.  It never calls `SpanStatement.fold` and never advances a slot,
segment, or cycle range.

The existing one-proof native prover may publish the same complete
execution-leaf authority directly after independent verification and global
relation closure.

### Temporal recursive node

A temporal binary node consumes two complete child authorities.  Each child
is classified by recursion proof kind (`segment_leaf`, `binary_node`, or the
protocol-owned `empty_leaf` padding case), not by a split-proof component
role.  The node:

- independently validates each child proof publication and complete global
  closure receipt;
- decodes each verifier-published canonical span statement and applies
  `SpanStatement.fold`;
- requires equal job/session context, equal child height, adjacent aligned
  slots, continuous segment/cycle/state boundaries, and canonical trailing
  empty padding;
- binds the child proof kind, verification-key identity, profile identity,
  statement/proof/transcript/capture/receipt identities, and claimed-sums
  identity;
- permits a `segment_leaf` verification key only at height zero and requires
  the recursively pinned aggregator key for every `binary_node` child; and
- publishes one parent statement and one authenticated parent-node identity.

Every non-empty temporal child is already a complete proof.  Its 36-row
relation closure is checked independently; the parent must not repair one
child with the other child's signed total.  Empty leaves are protocol-owned
padding statements, not arbitrary proof bytes blessed as empty execution.

The V1 core/provider pair-node implementation remains immutable development
evidence for split-proof authentication and its measured Poseidon cost.  It is
`PROTOCOL_SUBSTRATE_ONLY` and is not an admissible authority for the temporal
binary parent.  Production activation requires a V2 temporal authority and a
full parent proof built from it.

## Consequences

- Parallel precompile proving and recursive span aggregation can evolve and be
  benchmarked independently without changing each other's statement meaning.
- The current full native proof can enter recursion as one complete segment
  leaf; it is not forced into fictitious core/provider child roles.
- Existing rows 18--35, composition recording, provider partial-claim custody,
  and generic PCS parent kernel remain reusable because they are child-role
  neutral.
- The V1 rows 0--17 source/cohort remains useful integration substrate, but
  its pair/session authority must be replaced or parameterized before an
  honest temporal parent proof can be claimed.
- A green proof using the V1 role-specific non-FRI source must continue to set
  `whole_frontend_verified = false` and `production_activation = false`.

## Rejected alternatives

### Reinterpret `core_request` and `poseidon2_provider` as left and right spans

Rejected because those names and their frozen V1 validation encode component
ownership and cross-proof cancellation, not temporal proof kind or span
continuity.

### Fold two split proofs for the same execution

Rejected because identical span statements are not adjacent and cannot pass
the canonical fold semantics.

### Assign split roles to two already-complete outer proofs

Rejected because it manufactures protocol meaning beside verifier output and
would make the signed relation-total closure unrelated to the proofs' actual
all-row closure.

### Treat an arbitrary verified proof as an empty leaf

Rejected because empty padding has a fixed statement and no execution witness;
proof bytes for an unrelated statement cannot authorize it.

## Revisit when

Revisit only if a future protocol deliberately proves partitioned execution
spans whose component ownership and temporal boundaries are one jointly
specified statement.  That would be a new protocol version, not a relaxed V2
validator.

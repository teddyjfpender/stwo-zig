# ADR-0030 — Session-bound cross-proof relation summaries

**Status:** proposed
**Date:** 2026-08-09

**Classification:** protocol-changing aggregation design; no production or
recursive-verifier activation

## Context

R-007 asks what a core proof and an independently proved guest-precompile
component must expose before a later verifier can establish their shared
relation closure. This is not the same problem as checking two ordinary RISC-V
proofs.

In the current one-proof protocol, all components commit their main traces into
one Fiat--Shamir transcript and then draw one challenge pair `(z, alpha)` per
relation. A relation event with signed numerator `m` and tuple
`(v_0, ..., v_(k-1))` contributes

```text
m / (v_0 + alpha*v_1 + ... + alpha^(k-1)*v_(k-1) - z).
```

The global sum is meaningful because every component uses the same challenge
pair. Two independently generated proofs normally draw different pairs. Their
QM31 claims therefore cannot be added or compared: equal tuple multisets
evaluated at different points do not produce compatible accumulators. A digest
of each local tuple stream does not repair this, and the retained
`relation_export`/`relation_evidence` artifacts are diagnostic exports rather
than public inputs authenticated by proof verification.

There are three general ways to obtain a cross-proof binding:

1. commit the complete canonical tuple/multiplicity map and prove openings;
2. introduce a compatible polynomial/vector commitment to each relation; or
3. bind all leaf main commitments before challenge derivation, then evaluate
   every leaf under one shared challenge context.

The first two permit freely composed proofs but add a new potentially large
commitment protocol. The third retains a constant-size LogUp summary and fits
the existing proof order, at the cost of making leaves specific to one
aggregation session. This ADR selects the third option for the first
core/Poseidon2 prototype.

The repository does not yet contain a recursive STARK verifier, an accepted
recursion field, or proof-bound leaf summary public inputs. This decision must
not be read as an R-008 or R-009 completion claim. It defines the artifact that
those tasks must verify.

## Decision

Define a versioned **aggregation session** before any leaf draws relation
challenges. The session canonically commits every leaf's public statement,
proof protocol, preprocessed commitment, main commitment, guest call
commitment, role, and position. One domain-separated digest of that manifest is
the common relation-challenge context for every leaf in the session.

The first version is deliberately narrow:

- execution profile `rv32im-zkvm-poseidon2-v1` only;
- relation `stwo.riscv.guest_poseidon2_io@1` only;
- exactly one core-request leaf followed by one provider-supply leaf per job;
- a power-of-two number of leaves, between 2 and 1,024;
- unit signed liveness and duplicate-preserving call rows;
- a balanced, position-preserving two-to-one tree; and
- Blake2s-256 native artifact identities, matching the current proof
  transcript family.

General relation sets, arbitrary producer graphs, post-hoc aggregation, and a
recursive-circuit hash are deferred. Narrowing v1 prevents an unaudited generic
summary API from becoming a protocol back door.

### Two-stage proving session

An admitted session has these barriers:

1. Execute each job and freeze its duplicate-preserving call buffer.
2. Construct and validate every core and provider statement, including exact
   zero-call component inclusion and geometry.
3. Commit every leaf's preprocessed and main trees. No interaction trace or
   relation challenge is produced yet.
4. Build the complete canonical session manifest and compute its digest.
5. Derive the shared guest relation pair from the domain-separated session
   digest.
6. Build each leaf interaction trace and proof against that exact pair. The
   leaf transcript and public inputs bind the session digest and leaf index.
7. Verify leaf proofs and their exposed summaries before any parent merge.
8. Merge adjacent core/provider leaves and then merge equal adjacent subtrees
   until one root remains.

This order has no Fiat--Shamir cycle: all witness data that determines the
randomized relation polynomial is committed before the common challenge is
drawn. Interaction commitments and the remainder of each leaf proof come
after the draw, as in the current one-proof protocol.

A leaf cannot be proved before its aggregation peers publish their main
commitments. It may cache stage-1 execution and main-tree work, but the final
proof is session-specific.

### Canonical pre-challenge manifest

The manifest header binds:

| Field | Requirement |
| --- | --- |
| format magic/version | `STWAGGS\0`, version 1 |
| aggregation profile | `riscv-guest-poseidon2-paired-v1` |
| proof protocol digest | exact accepted leaf verifier/proof-wire identity |
| execution profile | numeric profile ID 1 and its semantic digest |
| relation registry digest | exact 13-schema extension registry |
| relation schema | global ID 12, version 1, arity 32 |
| leaf count | power of two in `[2, 1024]` |
| request-set digest | ordered digest of all job/request identities |
| tree policy | balanced, adjacent, position-preserving, two-to-one |

Each leaf descriptor binds:

- zero-based leaf index;
- zero-based pair index;
- role `core_request` or `poseidon2_provider`;
- job/request digest;
- complete leaf statement digest;
- leaf AIR/layout/artifact digest;
- preprocessed-tree root;
- main-tree root;
- ordered guest call commitment; and
- exact active guest call count.

Descriptors are ordered by strictly increasing job/request digest. Each job
occupies exactly two positions: core at `2*j`, provider at `2*j+1`. Both
descriptors carry the same job digest, call commitment, call count, execution
profile, relation registry, and proof protocol. Their statement and AIR
digests remain role-specific.

Every digest/root field is nonzero. A zero-call job is valid only with the
canonical empty call commitment and with both zero-row components explicitly
present in their statements. It is not represented by omitting either leaf.

The manifest enforces checked integer bounds. For the v1 unit relation,
`2 * call_count < p`, where `p = 2^31 - 1`, and all aggregate counts use checked
`u64` addition. This is separate from, and does not weaken, the extension
statement's complete all-source coefficient guard.

### Shared relation challenge context

Let `M` be the exact canonical manifest bytes and

```text
session_digest = Blake2s256("stwo-zig/aggregation/session/v1\0" || M).
challenge_seed = Blake2s256(
    "stwo-zig/aggregation/shared-relations/v1\0" || session_digest
).
```

The guest `(z, alpha)` pair is drawn with the reviewed Blake2s-channel secure
felt rejection schedule initialized from `challenge_seed`. The canonical
artifact records both digests and the four canonical M31 limbs of each value.
Native and recursive verifiers must recompute the draw; accepting supplied
limbs without checking derivation is invalid.

Base relations remain local to the core leaf in v1. They continue to use that
leaf proof's ordinary challenge schedule and close against its public boundary.
Only the guest relation is placed in the shared context. This avoids silently
changing the base 12-relation transcript or exporting unrelated state,
memory, program, and fixed-table buses across proofs.

The core and provider leaf protocols therefore need an explicit aggregation
mode. Reusing an ordinary proof whose guest relation was drawn from its local
transcript is a deterministic `ChallengeContextMismatch`, even if every other
field is identical.

### Proof-bound leaf summary

After independent proof verification, one leaf exposes a fixed-size summary:

```text
LeafRelationSummaryV1 {
    session_digest,
    challenge_context_digest,
    leaf_index,
    leaf_role,
    leaf_statement_digest,
    guest_call_commitment,
    guest_call_count,
    request_count,
    supply_count,
    signed_guest_sum: QM31,
}
```

For a core leaf, `request_count = guest_call_count` and `supply_count = 0`.
For a provider leaf the inverse holds. Counts are derived from the statement,
not trusted as free public metadata. The signed sum uses `-1` for each active
request and `+1` for each active supply under the common `(z, alpha)` pair.

The leaf proof must constrain this summary to its committed interaction trace.
The native verifier must return the same summary only after checking the proof,
profile, statement, manifest membership, challenge derivation, and exact leaf
index. A separately serialized summary next to a valid proof is not
proof-bound and is inadmissible.

The public call commitment is required even though the randomized accumulator
is also checked. It binds the exact ordered, duplicate-preserving call list and
prevents a relation collision argument from becoming the only statement-level
link between caller and provider. Each leaf must prove that its committed rows
open to that call commitment.

### Pair closure and parent summaries

The level-1 parent accepts only canonical siblings:

- left is core leaf `2*j` and right is provider leaf `2*j+1`;
- session, challenge context, job digest, call commitment, and call count are
  equal;
- both leaf proofs and summary bindings verify;
- request and supply counts equal exactly; and
- the two signed guest sums add to zero in QM31.

The parent summary contains the child summary digests, contiguous leaf range,
checked aggregate counts, zero residual guest sum, request-set subtree digest,
and call-commitment subtree digest. It is marked `closed` only after every
check above succeeds.

Higher parents merge only equal-size, adjacent, already-closed subtrees from
the same session and challenge context. Left/right order is protocol-visible.
For a node covering `[first, first + count)`, both children cover `count/2`
leaves and the right starts exactly after the left. Counts add with checked
arithmetic; residual sums remain zero; child digests determine the parent
digest.

The root verifier additionally checks:

- range `[0, manifest.leaf_count)` exactly;
- the canonical tree height and every child position;
- the manifest request-set digest;
- the advertised root statement/artifact identity; and
- one recursively verified path for every manifest leaf.

These rules reject swapped siblings, omitted leaves, duplicated leaves,
cross-session leaves, cross-challenge summaries, mismatched call lists, and a
balanced tree over the wrong manifest. Global cancellation alone is not enough:
each core/provider pair must close before it can enter a higher node.

### Canonical serialization

All v1 integers use fixed-width little-endian encoding. Enums use explicit wire
values. M31 limbs are canonical `u32` representatives and QM31 values use the
existing `(c0.a, c0.b, c1.a, c1.b)` order. Arrays have fixed lengths; variable
descriptor lists carry one checked `u32` length. Strings do not occur after the
format/profile domain tags.

Serialization validates before writing and performs no allocation. Decoding
is length-delimited, rejects unknown versions/tags/reserved bits, rejects
trailing bytes, and caps descriptors before allocating. Hashing streams the
same encoder used for emitted bytes; a separate hand-written hash preimage is
forbidden.

Leaf and node summary digests use distinct domains from the session manifest
and from one another. Golden bytes and digests must cover empty-call, one-call,
two-pair, and maximum-count boundary cases. Mutation tests flip every field
class and exercise truncation, extension, noncanonical M31 limbs, overflow,
role swaps, pair reordering, duplicate jobs, and cross-context merges.

### Shadow recursion pair frame

The first recursion-owned serialization reference is a deliberately narrower
pair frame, `STWRLS\0\0` version 1. It does not replace the native aggregation
manifest or claim proof-bound summaries. Its only admitted relation-total
array has length one and contains relation `(12, 1, 32)`; accepting a second
relation requires a new format version rather than unused generic capacity.

Each child record repeats the session digest, shared-challenge-context digest,
and canonical guest-relation-domain digest. It then binds three independently
reconstructed leaf identities: the statement digest, SHA-256 of canonical
proof bytes, and the verifier-replayed transcript digest. The record also
binds the ordered public call commitment, pair and leaf indices, explicit
left/right position, core/precompile role, relation event count, and signed
QM31 total in canonical limb order. The fixed pair order is left core request,
then right Poseidon2 provider. Counts and call commitments must match and the
two totals must cancel.

The version-1 pair frame is 552 bytes: a 16-byte header followed by two
268-byte child records. Encoding validates before its first store. The slice
encoder and decoder allocate nothing; the owned encoder performs one exact
allocation after validation. Decoding requires the exact frame length and
rejects trailing data, unknown tags, nonzero reserved fields, noncanonical
M31 limbs, child swaps, omissions, duplicates, and position/count drift.

Expected statement, proof, and transcript identities remain external verifier
authority and are intentionally absent as a self-declared comparison object.
The native validation API accepts those expected identities separately. This
prevents a serialized summary beside an unrelated valid proof from
self-authenticating, but it is still only a reference boundary: a future
recursive verifier must prove the same comparisons inside its proof system.

### Soundness obligations

Activation requires a reviewed reduction with explicit bounds. At minimum it
must show:

1. all relation-determining main data is binding before challenge derivation;
2. the common challenge is unpredictable under the same Fiat--Shamir model as
   the current proof;
3. each leaf proof binds its summary accumulator and call commitment to opened
   trace columns;
4. denominators are nonzero or the proof rejects;
5. the combined randomized rational identity has the claimed degree/error
   bound under the admitted event and coefficient limits;
6. exact call-commitment equality plus collision resistance binds order and
   multiplicity;
7. recursive verification binds the leaf protocol, statement, session, and
   summary rather than verifying a detached native boolean; and
8. the aggregate security-bit ledger includes both leaf proofs, relation
   reduction, commitment hashes, recursive proof, and tree size.

The existing diagnostic tuple digests and QM31 sums may be used as independent
test oracles, but they cannot satisfy obligations 3 or 7.

### Performance contract

The v1 summary and each parent are constant-size. Manifest construction and
tree merging are `O(n)` total work with `O(log n)` depth for `n` leaves; a
single merge is fixed work over one relation accumulator. Implementations use
pre-sized storage or one exact allocation and never build tuple hash maps on
the proving hot path.

This architectural bound does not establish the M9 performance verdict. R-010
still measures the exact corpus and gates in
`performance/m5-m9-protocol-v1.json`, including proof size, verifier time,
total work, RSS, worker cleanup, eight-leaf speed, and crossover. A summary
microbenchmark cannot substitute for recursive proof/verification results.

## Consequences

- Constant-size cross-proof relation summaries become possible without a new
  tuple commitment or inflated AIR relation arity.
- Distributed proving naturally separates into commit and finish phases.
- Ordinary independently produced proofs are not post-hoc aggregatable; final
  leaves are bound to one peer set and tree manifest.
- The base-profile proof path and its twelve challenge draws remain unchanged.
- Pair-local closure makes omission and role substitution easier to audit than
  one global cancellation check.
- A recursive verifier still must be designed and proved. Blake2s challenge
  derivation may be expensive inside that verifier, so R-008 must measure it
  against a reviewed circuit-friendly alternative before protocol acceptance.
- Session retries after a changed or failed leaf require a new session digest
  and new interaction proofs, though stage-1 execution/main commitments may be
  reusable when their statements remain identical.

## Rejected alternatives

### Add ordinary leaf LogUp claims

Rejected because leaf-local challenges differ. Adding field elements evaluated
at unrelated points has no relation-closure meaning.

### Compare diagnostic tuple-stream digests

Rejected because current exports are not proof public inputs, stream order may
differ across valid caller/provider traces, and equal aggregate hashes do not
express signed multiset cancellation without a canonical proof-bound map.

### Trust a supplied common challenge

Rejected because a prover could choose the evaluation point after seeing the
relation data. The challenge must derive from every binding main commitment.

### Include interaction roots in the challenge manifest

Rejected because interaction columns require the relation challenge, creating
a Fiat--Shamir cycle.

### Freely aggregate completed proofs with a full tuple map

Deferred rather than rejected in principle. It preserves post-hoc composition
but adds variable-size public data or a new commitment/opening protocol. The
paired session is the smaller first implementation.

### Let higher nodes cancel arbitrary unmatched leaves

Rejected for v1. Pair-local call-commitment equality and closure provide a
stronger, simpler omission and substitution boundary.

### Claim R-008/R-009 from a native summary merger

Rejected. Native validation is useful serialization and adversarial evidence,
but recursive aggregation exists only when a proof verifies both child proofs
and the merge logic.

## Activation gates

This ADR may move from proposed to accepted only after:

1. C-009 and C-012 establish the one-proof guest component and mutation fleet;
2. canonical manifest/summary types and golden serialization tests are green;
3. an independent soundness review accepts the shared-challenge reduction and
   numeric bounds;
4. a leaf proof exposes and verifies the exact summary as a public output;
5. cross-session, swapped, omitted, duplicated, call-commitment, count, and
   challenge mutations reject in a new verifier process; and
6. R-008 accepts a recursion field/hash/proof-protocol ADR.

Until those gates pass, code implementing these formats is isolated protocol
research and production provers/verifiers fail closed on its version tags.

## Revisit when

- post-hoc aggregation becomes a product requirement;
- more than one cross-leaf relation is needed;
- the recursive verifier makes Blake2s challenge derivation the dominant cost;
- a reviewed vector/polynomial commitment gives smaller total recursive work;
  or
- non-paired producer/consumer graphs require a more general closure policy.

# ADR-0018 — Degree-bounded materialization and compatibility order

**Status:** accepted
**Date:** 2026-08-05

## Context

The pure typed Poseidon2 program has output degree `5^22`, while the current
prover admits degree-three constraints and commits 426 intermediate values in a
historical lane-major order. Choosing semantic cuts and assigning physical
columns are different decisions. Treating one incidental traversal as both
would make a generic compiler depend on a legacy layout and would make a
harmless authoring-order change look like a protocol change.

The materializer may run in an arena containing unrelated functions. Its cut
set, dependencies, and degree result must depend on the requested root closure,
shared activation context, and versioned policy—not on an unreachable
high-degree subgraph or allocator history. Its receipt identity still binds the
validated whole semantic program deliberately. Conversely, compatibility
admission must prove that the generic set can be bijectively associated with
every existing Poseidon temporary and output; matching only the count or degree
is insufficient.

## Decision

`stwo.typed-air.materialize.degree-bounded-v1` is the accepted shadow policy.
For one request it:

1. validates the arena and computes reachability and structural use counts
   from the ordered roots only;
2. accounts for one shared optional gate and an explicit row-mask degree
   outside every materialization equality;
3. treats an earlier materialization as a degree-one leaf;
4. recursively cuts only when the requested equality would exceed the degree
   budget, choosing greatest excess degree, then greatest structural reuse,
   then lowest `ValueId`;
5. forces every declared output to have a materialization, even when no degree
   cut is otherwise needed;
6. emits non-output cuts first in dependency-topological, lowest-`ValueId`
   order, then dependency-ready outputs with declared-root order as the stable
   priority; duplicate roots share one boundary and retain separate output
   records; and
7. revalidates the complete plan by recomputing its canonical selection,
   dependencies, degrees, names, fingerprints, and output bindings.

Degree evaluation is root-closure scoped. Unreachable nodes are assigned no
degree for this request, so an unrelated overflow cannot affect the plan.
Materialization names and fingerprints bind the semantic program identity,
source value, gate, and policy. Adding unrelated semantic nodes therefore
changes the whole-program digest, fingerprints, and names while leaving the cut
set, dependency order, and degrees unchanged.

The generic order is deliberately not a physical-layout ABI. The separate
`stark-v.poseidon2.compatibility` version-1 adapter maps the selected set into
the frozen 426-slot lane-major schedule. Admission is fail-closed and requires:

- the exact materializer policy, degree context, count, and sixteen ordered
  output roots;
- one uniquely consumed candidate for every compatibility slot;
- the expected external/internal phase, round, lane, role, and source stage;
- the pinned round constant for shifted nodes and first-round square inputs;
- the exact square-to-fourth-power dependency chain; and
- exact final output roots, column geometry, and constraint ordinals.

The adapter rejects missing, ambiguous, duplicated, unconsumed, malformed, or
misordered candidates. It may reorder the authenticated semantic set; it may
not alter the typed graph or invent a cut.

Admission is specifically an adapter over the trusted
`typed_poseidon2.define` constructor, not a universal proof about an arbitrary
graph stored in the public `Definition` struct. It checks the canonical
function name, input names and order, function input/output shell, and the local
slot shapes above. Fixed and randomized full-state differential tests bind this
canonical instance to production. An owned result retains the compatibility
identity, whole-program digest, gate, policy, and the H-003 materialization ID
for every slot. Revalidation first authenticates the plan against its arena,
then reconstructs the canonical slot mapping and rejects even a bijective swap
of complete plan-ID/value/source triples.

Any change to reachability, degree accounting, cut eligibility, tie-breaking,
forced-output behavior, generic ordering, naming/fingerprinting, or
compatibility matching requires the corresponding policy version to change and
new separately reviewed evidence. A proposed optimized policy receives a new
identity and report rather than silently replacing compatibility v1.

## Consequences

- Independent authoring order no longer has to mimic Stark-V's lane-major
  temporary allocation.
- Unrelated arena contents cannot perturb or overflow root-local cut selection
  or degree analysis; they intentionally change the whole-program identity.
- Every materialized equality has explicit gate/mask degree accounting and a
  deterministic dependency frontier.
- Poseidon compatibility is stronger than count equality: all 426 typed values
  are bijectively bound to their current semantic roles and physical slots.
- The selected policy is deterministic, not claimed globally minimal. It makes
  no trace-cell, proving-speed, or layout-optimality claim.
- This is shadow compatibility evidence only. It does not allocate production
  witness storage, switch a production consumer, or change the proof protocol.

## Rejected alternatives

- **Use raw typed node order as column order:** rejected because H-002 creates
  all shifted lanes before its S-box map, unlike the legacy lane-major layout.
- **Teach the generic selector Poseidon tie-breaks:** rejected because a
  component-specific layout rule would contaminate the reusable policy.
- **Scan the whole arena for degree:** rejected because unrelated functions can
  change or overflow a root-local result.
- **Accept count and maximum degree only:** rejected because the wrong
  temporary can satisfy both while changing witness meaning.
- **Search for a globally minimal cut set now:** rejected because compatibility
  and auditability precede optimization; cost-aware search is H-009.

## Revisit when

H-009 proposes a cost-aware policy, a new backend needs a different degree or
window context, the accepted Poseidon layout changes, or production activation
requires a statement-global materialization identity.

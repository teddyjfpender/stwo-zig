# ADR-0041 — Versioned 41-input recursion composition ABI

**Status:** proposed
**Date:** 2026-08-15

**Classification:** recursion soundness and compatibility boundary; extends
ADR-0039 without changing its frozen V2 byte or graph domains

## Context

The V2 shared composition circuit accepts 36 universal-roster claims followed
by two ordered Poseidon partial claims. A complete SegmentV2 proof instead
commits 39 physical component claims. Projecting that proof into V2 would omit
rows 36 through 38, including independently proved LogUp totals, while changing
V2 in place would invalidate its graph/profile identities and existing
evidence.

## Decision

V2 remains immutable at 36 physical claims plus two Poseidon partials. The
proof-kind-aware circuit is a new V3 protocol domain with one fixed 41-element
claim-input vector:

- `segment_leaf` uses physical claims 0 through 38 and Poseidon partials 39 and
  40;
- `binary_node` uses physical claims 0 through 35, constrains 36 through 38 to
  zero, and uses Poseidon partials 39 and 40; and
- `empty_leaf` constrains all 41 inputs to canonical zero.

For segment and binary programs, the graph constrains inputs 39 plus 40 to
equal roster claim 34. These rules are recursive graph constraints in addition
to allocation-free host preflight. The V3 configuration binds a distinct
ordered program descriptor for each proof kind, including manifest family,
manifest seal, physical/source claim counts, ordered component-program
identity, and native AIR program identity.

There is no 39-to-36 compatibility projection. A consumer missing the V3
SegmentV2 composition recorder fails closed instead of selecting V2.

## Consequences

- Every SegmentV2 component claim remains visible to recursive composition.
- All proof kinds share a branch-stable input schedule; binary proofs pay three
  zero claim inputs (12 M31 words) rather than requiring a variable graph ABI.
- V2 graphs, profiles, fixtures, and measurements retain their original
  meaning.
- Host writers are fail-atomic and allocation-free, while graph constraints
  independently reject nonzero inactive tails and invalid Poseidon splits.
- The V3 input/roster authority does not by itself constitute a complete
  prover. Production activation still requires the heterogeneous 39/36
  sampled-value layout and component recorder; capability reporting remains
  false until those gates pass.

## Rejected alternatives

### Truncate SegmentV2 to the universal 36-row prefix

Rejected because three committed component claims would have no composition
equation in the recursive verifier.

### Change V2 from 38 to 41 inputs in place

Rejected because it would silently change an already identified protocol and
make old graph seals ambiguous.

### Use a variable-length input vector per proof kind

Rejected because the row-18 schedule and graph bindings require one static
shape. Variable geometry would move branch selection outside the authenticated
circuit.

### Zero-fill only in host code

Rejected because a recursive witness must be rejected by equations even if it
bypasses the convenience writer.

## Revisit when

Revisit only for a new protocol version whose segment and binary proofs share
one fully proved physical roster, or when an authenticated packed-input design
demonstrably reduces the 12-word binary overhead without weakening claim
visibility.

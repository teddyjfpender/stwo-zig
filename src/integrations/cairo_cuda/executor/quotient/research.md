# SN2 Quotient Topology Derivation

This module compiles the authenticated Cairo composition bundle, generic
`ProofProgram`, and compact protocol into immutable host descriptors for CUDA
ingress. It does not execute a proof and makes no performance claim.

The critical geometry has four different cardinalities:

- AIR constraints and components belong to constraint evaluation.
- Canonical sampled values belong to the proof transcript.
- Periodicity adds quotient terms without adding proof samples.
- Terms collapse into structural circle-point groups for quotient combination.

For SN PIE 2, the accepted topology has 6,110 canonical sampled values, 6,342
prepared terms after adding 232 periodicity terms, and 19 structural quotient
groups. Group logs sort to:

```text
4, 6, 7, 8, 9, 10, 11, 12, 13, 14,
15, 16, 17, 18, 19, 20, 21, 23, 23
```

The source table preserves four distinct compact trace-tree segments. Each
source owns a tree ordinal, local and global column identity, tree-relative
`u64` evaluation-word offset, blowup-aware physical stride, and logical
quotient-source row log. The preprocessed
segment is process-cached while main, interaction, and composition segments are
request-local, so the topology deliberately does not claim one shared base
pointer. Runtime lowering must use an addressed or segmented source ABI; a
single-base descriptor upload would fail the ownership contract.

The topology identity binds both `ProofProgram` identities, the encoded
protocol, composition-plan geometry and component part hashes, and every
emitted descriptor and offset. Any protocol identity, trace shape, component
span, group membership, or compact extent mismatch fails before upload.

The current generic `ProofProgram.QuotientSchedule` records AIR constraint and
component counts. Those are validated as AIR semantics but are deliberately
not reused as PCS sample, term, or group counts. A later executor integration
must size its PCS slots from this authenticated topology rather than those AIR
schedule fields.

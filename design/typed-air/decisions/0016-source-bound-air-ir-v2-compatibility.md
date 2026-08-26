# ADR-0016 — Source-bound AIR IR v2 compatibility

**Status:** accepted
**Date:** 2026-08-05

## Context

AIR IR v2 is a frozen byte-level formal interface, not merely a collection of
polynomials. It fixes active-row placement to constant one, historical source
node numbering, commutative operand orientation, semantic column roles, event
ordinals, opcode projection, fixed-table metadata, and compact JSON key order.

The typed graph deliberately canonicalizes commutative expressions and the
runtime program reads an external active selector. Neither representation can
reconstruct the old wire schedule by guesswork. Re-running the production
formal builder during a supposed typed export would make byte equality trivial
but would not establish that the new compiler path can reproduce the artifact.
Writing a second JSON encoder would create an unnecessary format authority.

## Decision

The compatibility bridge retains two explicitly different identities:

1. canonical typed nodes are the semantic compiler representation; and
2. an exact source-order node copy is provenance used only for frozen wire
   compatibility.

The provenance copy is SHA-256-bound under
`stwo-zig/typed-air/source-schedule-v1`. Allocation-free validation checks its
digest, canonical source-node fields, topology, exact interning uniqueness,
columns, and node-by-node correspondence to the typed graph. The complete
program additionally retains and validates exact source IDs for the selector,
active row, ordered direct roots, signed lookup numerators, and tuple fields.

`air/lang/lower_air_ir.zig` reconstructs the formal symbolic arena by:

- emitting the semantic main-column prefix in order;
- seeding constant one at the position created by the formal builder;
- substituting the external selector source node with that constant;
- replaying the checked source schedule through fallible exact hash-consing;
- mapping every direct and lookup root through the preserved source IDs;
- deriving column roles from ordered relation dependencies;
- deriving program, state, source, and destination event projections from
  schema roles and access ordinals; and
- passing the reconstructed `extract.program.Program` to the existing
  production AIR IR v2 JSON writer.

The existing writer remains the sole encoding implementation. The typed path
does not install or invoke the global production symbolic builder.

Tests compare complete byte slices. LUI satisfies the A-010 acceptance gate,
and every opcode-manifest entry is also byte-identical to the current production
export. A source-orientation mutation fails the provenance digest before
lowering. The all-family DIV construction path passes induced allocation-
failure cleanup. ReleaseFast and ReleaseSafe package suites remain green.

## Consequences

- A-010 is complete with evidence stronger than its LUI floor.
- A-011 can focus on the combined compatibility identity and round-trip receipt
  rather than finding another per-family semantic gap.
- The typed compiler can reproduce AIR IR v2 without claiming that incidental
  source numbering is the logical semantic identity.
- Formal export still fixes active placement to one; runtime export still reads
  the committed selector. The policies are named and tested separately.
- No formal artifact bytes, source closure, digest, production exporter,
  prover, verifier, witness, or transcript changed.

## Rejected alternatives

- **Serialize canonical runtime nodes as AIR IR v2:** rejected because selector
  policy, node numbering, projections, and column roles differ.
- **Infer old commutative orientation from typed IDs:** rejected because the
  importer intentionally erased that accident.
- **Re-run the production formal builder and call it typed export:** rejected
  because it would bypass the compiler path being validated.
- **Duplicate the compact JSON writer:** rejected because key ordering, escaping,
  fixed-table digests, and schema version must have one authority.
- **Promote the raw schedule to semantic SSOT:** rejected because canonical
  typed expressions are the authoring and optimization boundary; the schedule
  exists only to reproduce a versioned legacy wire contract.

## Revisit when

AIR IR v3 deliberately adopts canonical typed node identity, the v2 formal
contract is retired, or source-schedule provenance can be removed after every
consumer and archived artifact has migrated.

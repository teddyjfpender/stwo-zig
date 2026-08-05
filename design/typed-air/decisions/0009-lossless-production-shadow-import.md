# ADR-0009 — Lossless production symbolic shadow import

**Status:** accepted
**Date:** 2026-08-05

## Context

The typed language cannot earn a production role by restating the current AIR.
The shipped `constraint_program.Builder(symbolic.Scalar)` is already the shared
authority used by semantic evaluation and runtime polynomial export. The first
compiler boundary therefore has to consume that exact symbolic DAG while
leaving every production consumer unchanged.

The two graphs intentionally have different identities. Production symbolic
hash-consing preserves operand order, whereas the typed arena canonicalizes
commutative addition and multiplication. M31 constants accepted by the source
API may also require canonical reduction. A correct adapter can consequently
produce fewer typed nodes; source and target node numbers are not an identity
mapping.

## Decision

`air/lang/shadow_import.zig` is the only initial bridge from the shipped
field-polynomial DAG into the typed arena. It operates in shadow mode and:

- validates the source intern table, topological references, complete column
  map, and non-empty unique column names before accepting the graph;
- imports every production column as an owned, stable `.felt` input;
- reduces every constant to its canonical M31 representative;
- constructs typed add, subtract, multiply, and negate nodes through normal
  checked arena APIs;
- records a total source-node-to-typed-value map instead of assuming equal
  node numbers;
- records both source-column-to-value and target-value-to-column maps so
  concrete replay is linear in graph size; and
- validates the resulting typed arena before returning ownership.

Compatibility is proved at the semantic boundary. Fixed and deterministic
random points replay both DAGs, and every source node—not only declared
constraint roots—must equal its mapped typed value. The test corpus executes
the exact production direct-constraint builder for all 17 opcode families,
checks commutative node collapse and field wraparound, rejects malformed source
schemas and replay buffers, proves imported-name ownership, and enumerates all
allocation failures.

Logical degree receives an independent second check. A six-operation
recurrence over the production symbolic graph must agree with the typed degree
pass for every mapped node and every production direct-constraint root.

This decision imports only the expression DAG. Ordered constraints, selectors,
and lookups remain A-002 work and must retain their production order explicitly.

## Consequences

- The current builder remains the single production authority during M2.
- Typed canonicalization can reduce representation size without changing field
  evaluation or degree.
- Every later source root or lookup field must pass through the explicit map;
  raw source node IDs are never valid typed IDs.
- Import and replay require linear auxiliary storage. They are shadow/compiler
  operations, not per-row witness work.
- A successful import is evidence of polynomial compatibility, not yet of
  constraint ordering, lookup ordering, physical layout, or final backend
  degree.
- No prover, verifier, witness, runtime polynomial export, transcript, or
  formal-extraction path depends on the typed module at this stage.

## Rejected alternatives

- **Copy raw nodes and preserve numeric IDs:** rejected because it bypasses
  typed construction and breaks as soon as canonical interning merges nodes.
- **Re-author each family directly in the new surface:** rejected because it
  creates a second semantic source before equivalence machinery exists.
- **Compare only final roots:** rejected because compensating internal errors
  can hide behind an equal root and give weak localization.
- **Switch production runtime export to the importer immediately:** rejected
  because A-002 through A-010 have not established ordered program and lowering
  compatibility.
- **Use the typed degree implementation as its own oracle:** rejected because
  agreement would not independently test the import mapping.

## Revisit when

A-009 reproduces the complete runtime polynomial program, the production
symbolic representation changes, or a reviewed production activation plan can
replace shadow ownership with a canonical typed authority.

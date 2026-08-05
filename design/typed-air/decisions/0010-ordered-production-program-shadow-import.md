# ADR-0010 — Ordered production program shadow import

**Status:** accepted
**Date:** 2026-08-05

## Context

Expression replay alone does not establish AIR compatibility. Constraint roots
have declared order, the placement selector and row-active expression are
distinct values, and LogUp entries carry protocol-significant domain, role,
numerator, tuple order, access ordinal, and batch boundaries. Traversing a DAG
cannot reconstruct that information reliably.

The production symbolic representation also erases semantic field types. Every
recorded value is an M31 polynomial even when its relation position represents
a byte, clock, address, or bounded integer. Treating relation position as proof
of a value's semantic type would turn compatibility metadata into an unearned
soundness claim.

## Decision

`air/lang/shadow_program.zig` consumes the exact complete result of
`constraint_program.Builder(symbolic.Scalar).build`. It never rebuilds direct
and lookup sections independently. The owned result records:

- family and production main-column count;
- main columns in source order;
- the explicit `is_active` placement selector;
- the production row-active expression;
- direct constraints inserted into the typed arena in declared order with
  stable family/index names;
- ordered compatibility lookup records containing typed schema ID, role, the
  exact shipped signed numerator, ordered mapped tuple fields, access ordinal,
  and source span; and
- exact source IDs for selector, active row, direct roots, lookup numerators,
  and tuple fields, each checked through the total source-to-typed map; and
- the exact production lookup batch size.

The lookup record is deliberately not a high-level typed `Effect`. It preserves
pre-lowering production data without normalizing role signs or guessing field
types. A dedicated `relation.validateEventShape` boundary checks schema, role,
arity, and ordinal while explicitly withholding full field-type validation.
Authored typed effects must still use `relation.validateEvent` and supply real
type evidence.

The owned program has an independent validator. It revalidates the typed arena,
family geometry, selector identity, row-active value, direct constraint IDs,
stable constraint metadata, lookup count, contiguous tuple storage, every
mapped value, relation shape, source spans, and batch size.

Compatibility tests call the importer on the same source arena and complete
program they inspect. For all 17 opcode families they compare every ordered
record field directly and replay every full-program source node—including
lookup-only expressions—at deterministic random points. Separate tests require
structurally deterministic reconstruction, reject corrupted owned metadata and
incorrect source boundaries, and enumerate every target-side allocation
failure.

## Consequences

- Constraint and lookup order are now explicit compiler input rather than
  properties inferred from expression reachability.
- Canonical expression merging remains safe because every root and field uses
  the source-node map from ADR-0009.
- The placement selector is identifiable without prematurely treating the
  production row-active polynomial as a proven Boolean gate.
- Lookup records retain current signed numerators; later effect lowering must
  prove any role/liveness normalization exactly and must not apply the sign
  twice.
- The ordinary logical manifest/digest does not yet claim to identify the
  external compatibility lookup record. A-005/A-010 must provide the complete
  report and formal/layout artifact before production activation.
- No production AIR, witness, prover, verifier, transcript, runtime export, or
  formal extraction imports this module.

## Rejected alternatives

- **Derive roots and lookup events by walking the DAG:** rejected because order,
  roles, ordinals, and batching are not expression properties.
- **Build direct and lookup sections in separate symbolic arenas:** rejected
  because comparison would depend on an untested cross-build ID assumption and
  would not describe one complete program.
- **Infer semantic types solely from relation positions:** rejected because a
  relation expectation is not evidence that the source value was range- or
  representation-constrained.
- **Immediately translate entries into high-level effects:** rejected because
  the current signed-numerator convention and effect-role convention first need
  an exact normalization contract.
- **Drop numerators and derive them from roles:** rejected because current
  requests include conditional and negated polynomial numerators whose exact
  representation is part of compatibility.

## Revisit when

A-008 defines exact typed-effect lowering, A-010 serializes the complete formal
projection, or production symbolic extraction begins carrying reviewed semantic
types directly.

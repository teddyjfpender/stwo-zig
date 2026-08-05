# ADR-0014 — Role-normalized ordered lookup lowering

**Status:** accepted
**Date:** 2026-08-05

## Context

Production lookup entries already store signed M31 numerators. Opcode requests
and bus consumes use a negative numerator; bus emits use a positive numerator.
The logical relation schema instead describes role-signed liveness. Treating a
production numerator as unsigned liveness would negate requests a second time
when lowered, while discarding it and guessing from nearby columns could change
conditional requests.

The shadow importer also lacks the semantic byte, clock, address, and bounded-
integer types required to call a compatibility record an authored typed effect.
It can establish exact polynomial, schema, role, shape, ordinal, order, and
batch compatibility, but it cannot manufacture type evidence.

Complete-program and lookup-only construction introduce another benign
representation difference: direct construction may intern a shared constant
before the lookup section uses it. Raw node IDs therefore are not a stable
comparison boundary even when the reachable lookup DAG is identical.

## Decision

`air/lang/lower_lookup.zig` lowers the production shadow into an owned,
role-normalized compatibility program:

- request and consume entries must have a syntactic leading negation; its
  operand becomes the normalized liveness root;
- emit entries use their numerator directly as liveness;
- each event retains a cached signed numerator, and validation structurally
  binds it back to role and liveness;
- schema ID, role, tuple order, arity, and access ordinal remain exact;
- fixed-capacity tuple tails contain checked sentinels rather than undefined
  bytes;
- polynomial roots are flattened as signed numerator then ordered tuple fields
  for every event in declaration order;
- lookup expressions use the physical main-column prefix only; and
- every batch records its first event, occupancy, and all four batch-major QM31
  interaction-column references from `compat-v1`.

The shared expression lowerer now canonicalizes reachable nodes by dependency
height and structural key after hash-consing. A separately implemented linear-
interning oracle uses the same documented canonical ordering. Thus the complete
shadow program and the shipped lookup-only runtime exporter converge without
making dead construction or incidental node IDs part of program identity.

Validation remains allocation-free. It rechecks the polynomial program,
family column and event counts, schema/role/arity/ordinal shape, root order,
sign binding, tuple sentinels, production batch size, batch occupancy, and every
physical interaction reference.

Across all 17 families, tests establish exact canonical node and flattened-root
identity with the production lookup runtime programs. All 242 events and 155
batches preserve metadata and placement. Four deterministic randomized M31
assignments per family agree for every numerator and tuple field and separately
recheck the role-sign equation. LUI reconstruction is deterministic; malformed
signs and stored-state corruption reject; induced allocation failure over DIV
frees every partial owner.

## Consequences

- A-008 is complete with all-family evidence stronger than its LUI acceptance
  floor.
- A-009 may export the canonical owned polynomial programs directly into the
  backend-neutral runtime types.
- E-001 still must author genuinely typed program/state effects and validate
  their semantic field types. This compatibility result is not that evidence.
- Roles can no longer drift independently from numerator signs, and batch
  order can no longer drift independently from physical interaction columns.
- The pass changes no trace, degree, lookup fraction, interaction recurrence,
  transcript, proof, or verifier behavior.

## Rejected alternatives

- **Keep only the signed numerator:** rejected because it leaves the logical
  role/liveness convention unenforced and invites double negation later.
- **Derive liveness from a presumed active column:** rejected because some
  requests use conditional polynomial liveness rather than the row enabler.
- **Strip any leading negation regardless of role:** rejected because the role
  is protocol metadata and an emitted negative polynomial would not be a
  consume.
- **Infer semantic field types from tuple position:** rejected because a schema
  expectation is not proof that the source expression is range constrained.
- **Compare raw source node IDs:** rejected because unrelated direct-section
  interning legitimately changes them.
- **Recompute batches from an unordered event collection:** rejected because
  event and batching order determine interaction columns and transcript work.

## Revisit when

E-001 supplies authored typed effects, the relation sign convention changes,
the secure extension coordinate layout changes, or a named optimized policy
changes lookup batching.

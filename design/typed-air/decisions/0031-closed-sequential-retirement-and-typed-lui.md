# ADR-0031 — Closed sequential retirement and typed LUI

**Status:** accepted
**Date:** 2026-08-10

**Classification:** logical authoring boundary; shadow-only until generated
witness and proof-path authority are accepted

## Context

E-004 requires the typed AIR surface to reproduce the production RV32 LUI
component without weakening the state chain or inventing a second description
of its relation protocol. Production LUI has 18 main columns, nine direct
constraint roots, and seven ordered relation events. Its non-control-flow
retirement emits exactly `pc + 4` and `clock + 1`; its U-immediate is proved by
the fixed `range_check_8_8_4@1` relation; and its destination write occupies
the first register-access phase.

Generic typed arithmetic is intentionally unsuitable for the state outputs.
It returns `.felt`, while the state relation requires `.pc` and `.clock`, and a
caller-provided cast or arbitrary after-state would turn the sequential
transition into an unchecked promise. The existing closed machine-derived
grammar from ADR-0026 and ADR-0028 is the appropriate authority boundary, but
adding two new operations changes that canonical grammar.

Manifest format 5/schema 4 and digest format 3 close over the E-002 register
derivations. Manifest format 6/schema 5 and digest format 4 add the E-003
memory capability. Reusing either identity for new sequential operations would
silently expose unknown tags to older consumers and contradict the explicit
version precedent in ADR-0028.

## Decision

### Sequential retirement is a closed paired operation

Add exactly two machine-derived operations:

```text
instruction_next_pc {
    current: ValueId,                  // exactly .pc
} -> .pc                               // current + 4

instruction_next_clock {
    current: ValueId,                  // exactly .clock
} -> .clock                            // current + 1
```

They may appear only as the two fields of a `registers_state@1/emit` directly
following its matching `registers_state@1/consume`. The consume and emit must
share liveness, and both derivations must reference the corresponding consume
field. A partial pair, swapped operation, generic-expression use, hint/call
use, unrelated effect use, or orphaned node rejects during whole-program
validation.

`retireSequential` constructs the pair without accepting caller-provided
after-state values. It rolls back derived nodes if construction fails, while
the existing retirement constructor atomically rolls back its adjacent effect
pair. The two operations lower to affine expressions and add no committed
column or direct constraint.

### The LUI range request is fixed

Add one reviewed constructor for `range_check_8_8_4@1/request`. Its arguments
are exactly `(byte, byte, uint4)`, its role is fixed to request, it carries no
access ordinal, and its liveness is a selector. The constructor does not accept
a caller-selected schema, role, or result type.

### Typed LUI is compatibility-exact and shadow-only

The typed LUI definition fixes:

- 18 physical main-column inputs plus the component selector;
- nine named, ungated semantic roots in production order;
- seven relation events in production order: fetch, state consume, state
  produce, immediate range, and the three destination-write records;
- destination ordinal and phase one;
- opcode ID, tuple fields, liveness, and relation versions; and
- the production x0/nonzero inverse and four result-limb equations.

Acceptance compares canonical fingerprints for every direct root and relation
field against the imported production program. Honest rows, x0, malformed
inverse/result/selector rows, substituted state outputs, altered schemas,
effect mutations, and allocation failures are covered. This decision does not
change production component selection, witness authority, trace layout,
commitments, transcript draws, or proof bytes.

### Canonical identity advances

Introduce these least-capable identities:

| Capability | Manifest | Digest |
| --- | --- | --- |
| sequential retirement, with or without earlier capabilities | format 7 / logical schema 6 | format 5 |

Manifest formats 5 and 6 reject either sequential operation with
`SequentialRetirementRequiresManifestV7`. Digest formats 3 and 4 reject them.
Format 7 and digest 5 can represent all earlier typed capabilities so a future
memory instruction with sequential retirement has one unambiguous top element
in the capability lattice. Existing programs retain byte-identical older
encodings and digest versions.

## Performance invariants

- Sequential state derivations are inline affine expressions with zero new
  witness columns, constraints, lookups, or transcript material.
- Typed LUI retains maximum direct degree two.
- Whole-program machine-derived validation uses bounded stack storage and
  allocates zero bytes.
- Construction and validation are setup work; no string, schema, allocation,
  or dynamic-dispatch work enters a production row loop.
- Any later generated witness path must compare all 18 columns before it may
  replace the handwritten writer.

## Consequences

The typed surface can author the first compatibility-exact opcode family while
keeping the state transition and range evidence unforgeable by construction.
The additional identity versions are deliberate protocol bookkeeping, not a
proof-system change. E-005 remains responsible for witness equality, and a
later authority decision remains responsible for production activation.

## Rejected alternatives

- Caller-supplied `next_pc` and `next_clock`: this restates the invariant
  instead of proving it.
- A general typed affine cast: it would make arbitrary field expressions
  acceptable as machine state.
- Extra equality constraints for state increments: they increase AIR work and
  still need a trusted result-type bridge.
- Reusing manifest 5/6 or digest 3/4: it silently expands a closed canonical
  grammar and breaks version-directed consumers.
- Switching production authority in E-004: witness equality and independent
  proof evidence belong to later gates.

## Revisit when

Revisit only if a general refinement system can preserve the same closed-use
validation, canonical identity, exact compatibility, and zero-column affine
lowering without exposing a caller-selected cast.

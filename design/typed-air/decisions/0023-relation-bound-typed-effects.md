# ADR-0023 — Relation-bound typed machine effects

**Status:** accepted
**Date:** 2026-08-06

**Classification:** logical authoring boundary; shadow-only until a later
production-authority decision

## Context

The initial logical AIR kernel stored an `EffectKind`, a value slice, optional
liveness, and an optional access ordinal. That record was sufficient for
lossless shadow import, but it was not a safe authoring surface for migrated
machine semantics. A call site could describe a program fetch, state
transition, memory access, or range request using an arbitrary tuple without
persisting the relation ABI that was meant to prove it.

`EffectKind` cannot determine that ABI by itself. Range requests select among
several schemas. Register and memory operations expand into multiple roles of
the same memory relation. Component calls will be domain- and
version-polymorphic. The existing provisional ordinal rule also treated every
ordinal as globally unique, while the production access protocol intentionally
uses one instruction-local ordinal for an adjacent consume, emit, and clock-gap
group.

The replacement must make schema, version, role, liveness, and order explicit
without putting dynamic dispatch or allocation into witness generation. It
must also preserve every already reviewed legacy manifest and semantic digest:
adding typed effects in shadow mode is not authority to rewrite closed M1–M4
evidence or change the production transcript.

## Decision

Every reviewed relation effect carries both its machine meaning and a persisted
`RelationBinding`:

```text
EffectKind
RelationBinding { schema_id, schema_version, role }
ordered ValueId tuple
liveness ValueId
optional access ordinal
source span
```

The relation registry remains the sole authority for ordered field types,
allowed roles, ordinal policy, and schema version. Semantic constructors derive
the binding from that registry and perform complete schema and type validation
before appending an effect. Call sites cannot provide a relation name or an
untyped tuple.

The first reviewed constructors are:

- `programFetch(ProgramTuple, active)`, bound to
  `program_access@1/request`; and
- `retire(before, after, active)`, represented by adjacent
  `registers_state@1/consume` and `registers_state@1/emit` effects.

`retire` preflights both events and appends them transactionally. Failure leaves
both effect pools unchanged. Whole-program validation independently
re-establishes each binding, tuple type, liveness type, and the adjacency and
shared-liveness invariant. Standalone state events exist for deserialization
and focused construction, but a validated program must contain them as a
consume/emit retirement pair.

The old `addEffect` entry point remains an explicitly provisional migration
surface. Its unbound records retain the historical global-ordinal checks so
existing compatibility evidence does not silently acquire new meaning.
Reviewed constructors use the bound entry point. Bound register and memory
effects will instead be accepted only by their instruction-local group
validator, where one ordinal deliberately identifies the consume, emit, and
clock-gap events of one architectural access. ADR-0023 does not yet define or
activate that group; E-002 and E-003 must do so before those constructors are
public.

Validated lowering exposes a borrowed numeric `EventView` and an ordered
iterator. Projection is O(1), performs no allocation, and does not look up
names, hash strings, or copy tuples. The validation boundary is cold;
row-oriented witness and relation kernels consume only prevalidated IDs,
enums, and borrowed contiguous slices.

Typed bindings are semantic identity. They use logical manifest format 4 with
logical schema 3, and semantic digest format 2. Those encodings include the
binding-presence tag, schema ID, schema version, and role in declaration order.
Legacy manifest format 3/schema 2 and digest format 1 remain byte-exact for
unbound programs. Their APIs reject a program containing relation bindings
instead of omitting the new metadata or silently changing versions.

This decision changes no production columns, constraints, relation events,
transcript bytes, proof bytes, or verifier behavior. It authorizes a shadow
authoring representation only. Production authority requires the later
per-family compatibility, mutation, proof, and performance gates.

## Performance invariants

The implementation must preserve all of the following:

- complete semantic preflight occurs before mutation;
- effect-group rollback retains capacity and performs no cleanup allocation;
- whole-program validation allocates nothing;
- lowering is one ordered linear scan with O(1) work per effect;
- the hot event projection performs zero allocation and zero string work;
- compatibility mode changes no physical geometry or production executable;
- benchmark evidence compares identical protocol identities and rejects
  unverified samples; and
- any later production consumer writes directly into preplanned final storage
  without an intermediate tuple or column copy.

M5 performance receipts must separately disclose construction/setup cost,
witness cost, committed geometry, peak memory, proof size, proving time, and
verification time. A runtime improvement cannot compensate for a semantic or
identity mismatch.

## Consequences

The authoring API now distinguishes machine intent from proof ABI while keeping
both visible in canonical artifacts. Invalid role, arity, field type, schema
version, missing liveness, split retirement, and activation-drift states reject
at construction or whole-program validation. Allocation failure cannot expose
a half-retired instruction.

The hot path is smaller than the defensive path: consumers no longer need to
infer schemas from effect kinds or revalidate strings per row. Persisted
bindings also make future compiler reports and mutation diagnostics precise.

There are deliberately two logical identity versions during migration. That
adds explicit API surface, but prevents historical evidence from being
reinterpreted. Callers must choose the typed encoding once they author a bound
effect.

Register and memory effects are not complete merely because their enum cases
can carry a binding. They remain unavailable as reviewed constructors until
the shared-subclock group, alias behavior, clock-gap constraint, and negative
tests are implemented.

## Rejected alternatives

### Derive the relation only from `EffectKind`

Rejected because range and component-call effects are schema-polymorphic, and
register/memory operations need multiple roles under one semantic kind. It
would either lose identity or recreate an implicit dispatch table in every
consumer.

### Store a relation name and arbitrary values

Rejected because strings are not protocol IDs, and late tuple validation would
move avoidable work and ambiguity into lowering and witness generation.

### Change the existing manifest and digest in place

Rejected because it would churn closed compatibility artifacts and make a
shadow representation look like a production protocol change. Explicit new
versions make the boundary auditable.

### Keep ordinals globally unique

Rejected because it contradicts the production memory-access protocol. An
ordinal identifies a semantic access group, not an individual relation event.

### Validate every event in the row loop

Rejected because schemas and types are program-static. Repeating cold checks
per row adds branch, lookup, and allocation pressure without additional
soundness once an authenticated plan has been validated.

## Revisit when

Revisit the binding shape only if a reviewed relation version requires
metadata that cannot be derived from the schema registry, or if a serialized
external program format needs a stricter capability boundary. Revisit the
dual-version migration API after every production author and consumer has
moved to typed bindings and all legacy artifacts have an explicit retirement
decision.

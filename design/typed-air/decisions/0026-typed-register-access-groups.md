# ADR-0026 — Typed register access groups and strict subclocks

**Status:** accepted
**Date:** 2026-08-06

**Classification:** logical authoring boundary; shadow-only until opcode-level
compatibility and proof gates grant production authority

## Context

The supplied Stark-V design proposes a `Reg` value that hides a repeated
protocol: consume the preceding register state, emit its state at the current
instruction subclock, and request a range check for the shifted clock gap. That
is the right authoring abstraction, but it is safe only if the typed language
preserves all of the protocol that the production AIR and runner currently
enforce.

Production uses a four-wide bucket with three usable access phases:

```text
A(c, i) = 4*(c - 1) + i + 1,  i in {0, 1, 2}, c >= 1.
```

The fourth residue is reserved. Sources are accessed before the destination.
Each access is represented by an adjacent
`memory_access@1/consume`, `memory_access@1/emit`, and
`range_check_20@1/request` triple. The first two events carry address space,
address, clock, and four bytes. The third carries
`current_clock - previous_clock - 1`. All three events have the same liveness
and one instruction-local access ordinal.

The runner resolves predecessor clocks dynamically. If `rs1 == rs2`, the
second read follows the first read's current clock. If `rd` aliases a source,
the write follows the latest preceding access to that register. Otherwise the
predecessor comes from the per-register state-chain tracker, possibly after
synthetic long-gap rows. These aliases are row values, so they cannot in
general be decided by static expression identity.

The current typed IR cannot express this protocol honestly with its generic
arithmetic alone:

- a decoded register has type `.register_index`, while memory tuple field 1 is
  exactly `.address`;
- arithmetic on a `.clock` produces `.felt`, while memory tuple field 2 is
  exactly `.clock`; and
- subtracting clocks produces `.felt`, while `range_check_20@1` requires
  exactly `.uint20`.

Changing those relation fields to `field_scalar`, or adding an unchecked cast,
would make malformed addresses, arbitrary felt clocks, and unproved range
claims type-correct. Semantic types are not themselves proof constraints, but
the language must still prevent a caller from asserting evidence it did not
construct.

The audited production anchors are
[`access_clock.zig`](../../../src/frontends/riscv/access_clock.zig),
[`access_witness.zig`](../../../src/frontends/riscv/runner/access_witness.zig),
[`state_chain.zig`](../../../src/frontends/riscv/runner/state_chain.zig),
[`common.zig`](../../../src/frontends/riscv/air/semantics/common.zig),
[`read_access.zig`](../../../src/frontends/riscv/air/semantics/read_access.zig),
and [`entry.zig`](../../../src/frontends/riscv/air/lookups/entry.zig). The
supplied Stark-V note is a design input rather than a pinned dependency; where
it is less precise than these sources, current production behavior is
authoritative.

## Decision

Introduce one instruction-wide access schedule and three closed
machine-derived expression operations. E-002 gives that schedule reviewed
register methods; E-003 will add memory methods to the same ordinal counter. A
schedule assigns one-based phases and atomically emits complete access triples.
Callers cannot construct an individual bound register event, select its
relation role, provide a raw address-space value, commit a current access
clock, or claim that an arbitrary felt is a 20-bit gap.

This decision activates bound register access groups in the logical typed IR.
It does not activate memory access groups, generated witness authority, new
production columns, or a changed proof protocol.

### Stored ordinal and clock convention

Typed effects store this enum, encoded as its displayed value:

```text
AccessOrdinal : u8 {
    first  = 1,
    second = 2,
    third  = 3,
}
```

For stored one-based ordinal `o`, the derived current clock is

```text
A(c, o) = 4*(c - 1) + o,  o in {1, 2, 3}.
```

This is the same convention as production's zero-based
`access_clock.Ordinal`; conversion is explicit and checked at that boundary.
Zero, four, truncation to two bits, and the reserved fourth phase are invalid.
The ordinal is group metadata, not a relation-tuple field and not a globally
unique event identifier.

One typed opcode program has one instruction-local `AccessSchedule` in E-002.
Its accepted access groups use ordinals `1..N` without holes, where `N <= 3`.
A non-access effect may occur between complete groups, but the three events
inside a group are contiguous. Multiple independently reset schedules in one
arena reject until functions or instruction bodies have persisted effect
ownership ranges; source spans are not ownership authority. E-003 must extend
this same schedule and validator rather than introduce a memory-specific
counter: a load needs register phase one, memory phase two, and register phase
three.

### Closed machine-derived expression operations

Add a closed `expr.Op.machine_derived` union with these variants:

```text
register_address {
    index: ValueId,                    // exactly .register_index
} -> .address

access_clock {
    instruction_clock: ValueId,        // exactly .clock
    ordinal: AccessOrdinal,
} -> .clock

strict_clock_gap {
    current_clock: ValueId,            // exact access_clock result
    previous_clock: ValueId,           // exactly .clock
    active: ValueId,                   // .bit or .selector
    ordinal: AccessOrdinal,
} -> .uint20
```

The result type is fixed by the variant. It is never accepted as a constructor
argument. These operations lower respectively to the following field
polynomials:

```text
index
4*(instruction_clock - 1) + ordinal
current_clock - previous_clock - 1
```

`active` and `ordinal` in `strict_clock_gap` are semantic evidence metadata;
they do not add factors to the polynomial. Whole-program validation requires
the gap to be the sole value of the adjacent `range_check_20@1/request` with
that exact activation and ordinal. Before that validation succeeds, a stored
`.uint20` result is untrusted arena data, not established range evidence.

These constructors are package-private and are reachable by normal authoring
only through the access schedule's reviewed methods. Validation rejects
orphaned machine-derived nodes and restricts their consumers:

- `register_address` may occupy only address field 1 of the matching consume
  and emit tuples;
- `access_clock` may occupy only emit clock field 2 and the matching gap
  derivation; and
- `strict_clock_gap` may occupy only the matching range request.

The same address node may be interned and reused when index expressions are
identical. No rule depends on ValueId uniqueness. The validator checks the
actual allowed uses and group structure.

`register_address` is a typed identity derivation, not a hidden `< 32` range
check. Its input must already be an established `.register_index`; in a complete
opcode this is the same decoded operand bound through program/decode semantics.
The access group may consume that established value, but cannot make an
arbitrary input safe merely by assigning it the `.register_index` tag. The
opcode compatibility gate owns that provenance check.

This is deliberately not a general affine/refinement system. Generic `add`,
`sub`, `mul`, and `neg` continue to return `.felt`. There is no `cast`,
`assumeType`, caller-selected result type, or generic “range-checked” wrapper.
A future reusable refinement framework may factor the implementation, but its
public variants must remain closed and each variant must name its proof
obligation.

### Instruction access schedule API

The semantic API is equivalent to:

```text
AccessSchedule.begin(
    arena,
    instruction_clock: ValueId,        // .clock
    active: ValueId,                   // .bit or .selector
    span,
) -> AccessSchedule

RegisterReadInput {
    index: ValueId,                    // .register_index
    previous_clock: ValueId,           // .clock
    value: [4]ValueId,                 // each exactly .byte, little-endian
}

RegisterWriteInput {
    index: ValueId,                    // .register_index
    previous_clock: ValueId,           // .clock
    previous: [4]ValueId,              // each exactly .byte, little-endian
    next: [4]ValueId,                  // each exactly .byte, little-endian
}

schedule.registerRead(RegisterReadInput, span) -> RegisterAccessGroup
schedule.registerWrite(RegisterWriteInput, span) -> RegisterAccessGroup
```

The schedule owns `next_ordinal`; callers do not pass one. The returned handle
may expose the three effect IDs and ordinal for diagnostics and prevalidated
witness planning. Derived address, current clock, and gap IDs remain internal
unless a consumer has a reviewed need for them.

In E-002 these two register methods are the schedule's only accepted access
methods, and bound memory groups remain fail-closed. E-003 adds memory methods
without changing `next_ordinal`, the clock formula, or the group parser.

For both methods, let `z` be the canonical felt zero, `raddr` the
`register_address(index)` result, `current` the schedule-derived access clock,
and `gap` the strict gap. The method appends exactly:

| Position | Effect kind | Binding | Tuple |
| --- | --- | --- | --- |
| 1 | method kind | `memory_access@1/consume` | `(z, raddr, previous_clock, previous[0], ..., previous[3])` |
| 2 | method kind | `memory_access@1/emit` | `(z, raddr, current, next[0], ..., next[3])` |
| 3 | method kind | `range_check_20@1/request` | `(gap)` |

Here “method kind” is `.register_read` for all three events of `registerRead`
and `.register_write` for all three events of `registerWrite`. `EffectKind`
records the architectural operation; `RelationBinding` records why each
individual event participates in its proof relation. An unrelated standalone
range request uses `.range_request` and remains fail-closed until its own
reviewed constructor.

All three records carry the same `active`, source-level access ordinal, and
semantic kind. The address-space value is always the canonical felt zero and
is not supplied by the caller. Relation schemas and versions stay unchanged:
`memory_access@1` remains
`(field_scalar,address,clock,byte,byte,byte,byte)`, and
`range_check_20@1` remains `(uint20)`.

### Read equality and write transition

A register read uses the exact same four ValueIds for `previous` and `next`.
This is structural equality, not four additional equality constraints and not
eight duplicated witness columns. It preserves the production compact
`ReadAccess` representation.

A register write consumes `previous` and emits `next`. Equal arrays are legal:
writing an unchanged value is still a real clock transition. The group proves
state-chain wiring, not opcode result semantics. The opcode body must separately
constrain `next` to the computed result and preserve the existing `x0` rule.
In particular, a register-write group by itself must never be presented as a
complete proof that destination register zero remains zero.

### Transactional construction

Construction preflights the schedule capacity, span, selector, index, clocks,
all byte limbs, fixed relation versions, and all three event shapes before
mutating the arena. It then takes both a node checkpoint and an effect
checkpoint, interns the fixed zero and machine-derived nodes, and appends the
three events.

On any allocation or append failure, effects and their value pool roll back
first, then nodes and their interning map roll back. Both rollbacks retain
capacity and allocate nothing. `next_ordinal` advances only after the entire
triple succeeds. A failed call leaves the arena and schedule observationally
identical to their state before the call, including when they already contain
a nonempty prefix.

### Whole-program validation

The arena remains an untrusted serialized representation. Whole-program
validation independently re-establishes all of the following:

1. A register effect starts a contiguous three-record group.
2. Kinds, liveness, and one-based ordinal agree across the group.
3. Roles are exactly consume, emit, request in that order and domains are
   exactly `memory_access@1`, `memory_access@1`, `range_check_20@1`.
4. Both memory tuples have arity seven; the range tuple has arity one; every
   field has the registry's exact type.
5. Both address spaces are the canonical felt-zero node, both addresses are
   the same reviewed `register_address` result, and both tuples use the same
   register index derivation.
6. The consume clock is the supplied `.clock`. The emit clock is the exact
   `access_clock` operation for the schedule's instruction clock and ordinal.
7. The gap is the exact `strict_clock_gap` operation over that current clock,
   consume clock, liveness, and ordinal.
8. A read reuses all four limb IDs. A write may change limbs but both arrays
   contain exactly four `.byte` values.
9. Across complete groups, instruction clock and liveness agree, ordinals are
   `1..N` without gaps or repeats, and `N <= 3`.
10. Every machine-derived node has at least one matching group and no consumer
    outside the closed positions listed above.

Non-access effects are skipped without resetting the expected ordinal. A
partial triple, swapped consume/emit, intervening event, duplicated range
request, later ordinal one, or second instruction clock rejects. The base
validator does not infer group boundaries from source spans or names.

The E-002 bound is three groups, so validation keeps group IDs and derivation
IDs in fixed stack arrays. It performs one ordered effect scan and bounded
node/reference scans, with no heap allocation, hashing, string comparison, or
recursive graph walk. Validation builds or authenticates the numeric event
plan once; row execution does not repeat these checks.

### Dynamic aliases and witness resolution

Static validation deliberately permits any two register-index expressions to
evaluate to the same register. It establishes declaration order and exact
subclocks; the concrete witness resolver applies groups in that order to the
per-register state tracker.

For an honest row:

- a first access to a register uses the tracker's effective predecessor;
- a later same-register read consumes the current clock and unchanged value of
  the latest earlier group;
- an aliased destination consumes the current clock and next value of the
  latest earlier same-register group; and
- a nonaliased destination uses its tracked predecessor and prior value.

This matches the current `rs1`, then `rs2`, then `rd` capture rule. It also
handles aliases that arise only at runtime, rather than only identical
ValueIds.

The runner is not the soundness boundary. The memory relation key includes
address space and address; ordered emit/consume events, strict shifted gaps,
synthetic long-gap rows, and initial/final register boundary rows force the
same-key chain. A forged alias predecessor or value must therefore fail proof
closure even if a malicious witness bypasses the honest tracker. The range
request excludes `previous_clock == current_clock`: the shifted gap is `-1` in
M31, not a 20-bit value. Existing statement clock bounds and predecessor
decomposition remain required to exclude wrapped non-increasing clocks.

### Compatibility and semantic identity

ADR-0023's compatibility split remains intact. The encodings are:

| Program capability | Logical manifest | Semantic digest |
| --- | --- | --- |
| entirely unbound legacy program | format 3 / logical schema 2 | format 1 |
| ADR-0023 bindings only | format 4 / logical schema 3 | format 2 |
| any E-002 register group or machine-derived node | format 5 / logical schema 4 | format 3 |

Formats 5 and 3 encode each machine-derived variant, its ordered operands,
selector, one-based ordinal, fixed result type, and the already-versioned
ordered effects. They add no separate mutable group name: valid group identity
is recovered from the canonical adjacent records and derivations. Reordering
groups or changing a phase changes semantic identity; source-location changes
do not.

Older encoders reject E-002 nodes and groups instead of dropping their
metadata. New encoders use the least capability that represents the validated
program. Node-interning history and irrelevant insertion order must not change
the digest.

An arena is in typed mode if it contains any relation binding or any
machine-derived operation. In typed mode, unbound machine-relation effects
reject; provisional unbound public effects retain ADR-0023's exception. An
arena with only historical unbound nodes/effects follows the old validation,
including its old ordinal interpretation, and must reproduce the existing
format-3 and digest-format-1 golden bytes exactly. Machine-derived nodes cannot
be smuggled into all-unbound mode.

The physical relation registry is unchanged. In particular, this ADR does not
bump `memory_access@1` or `range_check_20@1`, because it changes the logical
authoring proof of their fields rather than either relation tuple ABI.

### Future C-002 repeated-phase exception

The base access schedule rejects every repeated ordinal. ADR-0025 later
requires one pointer-register access at `.first` and sixteen memory lanes at a
shared `.second` phase. That does not justify a generic
`allow_duplicate_ordinals` flag.

The future precompile/memory implementation must introduce a dedicated
`SharedDistinctKeys` capability that only its reviewed fixed-lane constructor
can obtain. Validation must prove address space, alignment, non-wrapping
`ptr + 4*lane` derivations, unique lane indices, and pairwise distinct keys
before accepting the repeated phase. Two accesses to one key at the same phase
remain invalid. The E-002 `AccessSchedule` and its strict `1..N` rule do not
change.

## Performance invariants

- Every register group lowers to exactly the production three logical relation
  events, in the same order, roles, ordinal, and batch placement.
- `register_address`, `access_clock`, and `strict_clock_gap` are inline
  polynomials. They add zero committed columns and zero direct constraints.
- Address refinement is an identity expression; current clock and shifted gap
  are affine. They do not raise the direct-constraint degree frontier.
- A read stores one four-byte value group and reuses its IDs on both relation
  sides. It must not regress to an eight-limb write layout.
- The canonical zero, current clock, and gap are not witness-provided columns.
  Only the predecessor clock and existing semantic inputs remain witnesses.
- Construction performs no string dispatch. Validation and event projection
  allocate zero bytes and use fixed-capacity stack state bounded by three
  groups.
- A prepared witness plan contains numeric node IDs, roles, ordinals, and final
  column offsets. The row loop performs no schema lookup, name lookup, tuple
  allocation, intermediate copy, or per-row graph validation.
- Expression interning may eliminate repeated address/current derivations but
  correctness and cost accounting do not depend on that optimization.
- Compatibility mode changes no production geometry, transcript, proof bytes,
  relation challenges, or executable selection.
- Benchmarks report construction, validation, witness fill, committed main and
  interaction cells, peak RSS, proof size, proving time, and verification time
  separately. A setup win may not hide added proof work.

E-002 acceptance requires exact event/column/constraint-count parity with the
corresponding production register accesses. Any extra materialized clock,
address, gap, duplicate read limb, event, or interaction batch is a regression,
even if wall-clock samples are noisy.

## Required acceptance and mutation evidence

The implementation fleet must include at least:

- exact LUI destination and ADDI source/destination group comparisons against
  production, including tuple fields, roles, liveness, one-based ordinals,
  order, and batch coordinates;
- randomized polynomial replay showing current clocks and gaps equal
  production evaluation;
- ADD and ADDI rows covering no alias, `rs1 == rs2`, `rd == rs1`, `rd == rs2`,
  and all participating registers equal, with exact predecessor/current
  chains;
- read-limb mutation between consume and emit, and write previous/next
  transition cases including an honest unchanged write;
- proof-side mutations of an aliased predecessor clock and value, not merely
  honest-runner rejection;
- ordinal zero, ordinal four, reserved phase, hole, duplicate, reorder, split
  triple, wrong role, wrong domain, wrong schema version, wrong kind, and
  liveness drift;
- a witness-provided or generic-felt current clock, wrong stride, wrong offset,
  committed gap, gap off by one, missing range request, duplicate range request,
  and range request bound to another access;
- `previous == current`, `previous > current`, historical same-tuple self-loop,
  and an M31-wrapped predecessor attempt under the statement clock bounds;
- nonzero register address space, raw `.register_index` in an `.address` field,
  arbitrary `.address` not produced by `register_address`, `.felt` byte limbs,
  `.felt` clocks, `.felt` gaps, orphaned derivations, and forbidden derivation
  consumers;
- allocation failure at every node and effect append, starting both empty and
  after a nonempty successful prefix, proving exact rollback and no leak;
- exact format-5/schema-4 and digest-format-3 golden vectors, rejection by the
  v4/v2 encoders, interning-perturbation invariance, and identity change on
  group reorder;
- the existing unbound manifest and digest goldens unchanged byte-for-byte;
- Sail and Spike behavior unchanged for migrated opcode corpora;
- exact production geometry and zero-allocation validation/hot-projection
  assertions; and
- base rejection of repeated ordinal two, followed later by C-002 acceptance
  only through its certified distinct-key lane capability and rejection of one
  same-key collision.

Destination-result and `x0` mutations belong to the first opcode-authorship
milestones as well as this fleet. A passing access group alone is not evidence
that a complete opcode is constrained.

## Consequences

The typed surface gets the useful part of Stark-V's `Reg` idea: opcode authors
state a read or transition once, while the compiler emits the exact paired bus
events and clock-range evidence. Invalid partial groups and caller-selected
subclocks become unrepresentable through the public API and reject if forged in
serialized IR.

The new operations are narrow but necessary. They preserve exact relation
types without adding proof columns or relaxing the type system. This is a
better boundary than asking every opcode author to hand-build affine felts and
then cast them to protocol types.

Dynamic aliases remain a property of the stateful witness resolver and global
memory argument, while static effect order remains compiler-owned. That split
keeps the DSL declarative without pretending row-dependent aliases are known
at compile time.

Logical manifest and digest versions advance because the new typed derivations
are semantic, while relation schema versions and all legacy artifacts remain
stable. Production remains unchanged until LUI and ADDI establish full
compatibility, mutation, witness, proof, and performance evidence.

## Rejected alternatives

### Loosen memory and range schemas to field scalars

Rejected because it makes an arbitrary felt admissible as a register address,
clock, or proven 20-bit gap and moves a static soundness obligation into every
consumer.

### Add a general cast or caller-selected refinement

Rejected because `felt -> clock`, `felt -> address`, and `felt -> uint20` need
different evidence. One unchecked mechanism would let a caller manufacture all
three.

### Commit the current access clock or gap

Rejected because both are fixed affine functions of existing values. Columns
would add commitment, LDE, memory, and transcript work while also creating
forgery surface that the current AIR does not have.

### Emit independent register and range effects

Rejected because a partial or mismatched access could validate locally. The
consume, emit, and range request are one transactional semantic operation.

### Use static ValueId equality to resolve aliases

Rejected because distinct decoded expressions can evaluate to the same
register on a row. Alias resolution must occur in source-before-destination
witness order and be enforced by the relation chain.

### Require a write to change the value

Rejected because a legitimate architectural write may preserve the prior
word, including zero-register behavior. Strictness applies to clocks, not
values.

### Permit arbitrary repeated ordinals

Rejected because same-key same-clock edges reintroduce the detached self-loop.
ADR-0025's shared phase is a narrow distinct-key theorem, not a base policy.

## Revisit when

Revisit the single-schedule ownership rule when typed functions persist
instruction-local effect ranges. Revisit the closed derivation implementation
only if another reviewed machine protocol needs the same proof-carrying shape;
factor common mechanics without introducing an unchecked public cast. Revisit
the repeated-phase rule only through ADR-0025's certified distinct-key
capability. Revisit production authority after LUI and ADDI satisfy the full
compatibility and performance fleet above.

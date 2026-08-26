# ADR-0028 — Memory access groups and load/store phase plans

**Status:** accepted
**Date:** 2026-08-06

**Classification:** logical authoring boundary; shadow-only until the signed
load and generated-witness gates grant production authority

## Context

[ADR-0026](0026-typed-register-access-groups.md) introduced a single
instruction-local access schedule. For the register-only E-002 surface, the
order in which an access group is emitted and the physical subclock at which
it occurs are the same one-based value. Extending that equality to E-003 would
not reproduce the shipped load/store AIR.

Production assigns two different meanings:

- the lookup `access_ordinal` is the one-based position of a contiguous
  consume/emit/gap group in the component's ordered relation-entry list; and
- the access-clock phase selects the physical clock
  `4 * (instruction_clock - 1) + phase`.

They coincide for ordinary source-before-destination register traffic and for
stores. They deliberately differ for loads. The production load/store
component emits `rs1`, `src`, and `dst` groups in that semantic order. On a
load, `src` is the memory word and `dst` is the destination register, but the
destination register is clocked before the memory read:

```text
event group       relation ordinal       physical phase
rs1 register      1                      1
memory source     2                      3
rd register       3                      2
```

This is explicit in `semantics/load_store.zig`: the source clock is
`accessClock(clock, .second) + is_load`, while the destination clock is
`accessClock(clock, .second) + is_store`. It is also explicit in
`constraint_program.zig`, which attaches relation ordinals 1, 2, and 3 in
`rs1`, `src`, `dst` order. Reordering the two groups would change interaction
batch placement and fail the compatibility manifest even though LogUp treats
the relation itself as a multiset.

Memory addresses need a second closed refinement. The bus stores an aligned
byte address with semantic type `.address`, while the production range request
proves the aligned word index is below `2^20`. Generic typed arithmetic cannot
produce `.address`, and accepting an arbitrary address input would leave
alignment and the 22-bit byte-domain bound as an informal promise.

The audited authorities are
[`load_store.zig`](../../../src/frontends/riscv/air/semantics/load_store.zig),
[`constraint_program.zig`](../../../src/frontends/riscv/air/constraint_program.zig),
[`common.zig`](../../../src/frontends/riscv/air/semantics/common.zig),
[`access_clock.zig`](../../../src/frontends/riscv/access_clock.zig), and
[`state_chain.zig`](../../../src/frontends/riscv/runner/state_chain.zig).

## Decision

Separate relation-entry ordinal from physical access phase in the typed
language, add a closed aligned-word address refinement, and admit memory groups
only through fixed load/store plans. Callers never select an arbitrary phase,
address-space value, relation role, or partially assembled memory event.

### Ordinal and phase are distinct protocol types

`AccessOrdinal` remains the persisted relation-entry metadata:

```text
AccessOrdinal : u8 { first = 1, second = 2, third = 3 }
```

Add a distinct type for the physical access clock:

```text
AccessPhase : u8 { first = 1, second = 2, third = 3 }
```

The equal numeric encodings are intentional but do not make the types
interchangeable. `Effect.access_ordinal` stores an `AccessOrdinal` value in its
existing optional byte field. `machine_derived.access_clock` stores an
`AccessPhase`. Its polynomial is:

```text
4 * (instruction_clock - 1) + phase
```

`strict_clock_gap` carries the same physical phase as its exact current-clock
operand. The enclosing effect group carries the independent relation ordinal.
Whole-program validation checks each against the accepted instruction plan.

For every E-002 program, phase equals ordinal. Their numeric encodings and
semantic preimages therefore remain byte-for-byte unchanged. This ADR
supersedes only ADR-0026 language that treated the two concepts as universally
identical.

### Closed aligned-word address refinement

Add one machine-derived operation:

```text
aligned_word_address {
    word_index: ValueId,               // exactly .uint20
} -> .address
```

It lowers to the field polynomial `4 * word_index`. The result may appear only
in address field 1 of the matching memory consume and emit tuples. It adds no
committed column and does not increase polynomial degree.

The word index is established by one typed
`range_check_20@1/request`, with the same liveness as the memory access. The
request is a normal non-access `.range_request` effect and has no access
ordinal. The fixed plan owns this request and places it immediately after the
`rs1` access triple, exactly where `constraint_program.loadStore` emits the
production lookup. Validation requires that exact evidence before accepting
the derived memory address. Consequently:

```text
0 <= word_index < 2^20
0 <= aligned_word_address <= 2^22 - 4
aligned_word_address mod 4 = 0
```

The opcode body separately binds `word_index` to its effective-address and
byte-mask formulas. The semantic `.uint20` tag alone is not evidence; the
range relation is. A raw `.address`, a generic felt multiplication by four, a
missing or differently gated range request, and an address derived from a
different word index all reject.

This refinement covers the state-chain key. It does not by itself prove that
an unaligned byte address selects the right byte or halfword. Marker one-hot,
shift, sign, partial-store preservation, base-address non-wrapping, and M31
canonicality remain explicit opcode constraints and range effects in E-008.

### Fixed load and store plans

The schedule exposes reviewed compound plans rather than a caller-selected
phase argument. Their exact group signatures are:

| Plan | Ordinal 1 | Ordinal 2 | Ordinal 3 | Physical phases |
| --- | --- | --- | --- | --- |
| load | register read (`rs1`) | memory read (`src`) | register write (`rd`) | `1, 3, 2` |
| store | register read (`rs1`) | register read (`rs2`) | memory write (`dst`) | `1, 2, 3` |

Each entry in the table is still an adjacent three-effect group:

1. `memory_access@1/consume`;
2. `memory_access@1/emit`; and
3. `range_check_20@1/request` for the strict clock gap.

All three carry the group's semantic kind, relation ordinal, liveness, and
source span. The current clock and gap use the plan's physical phase.

The load memory read uses canonical felt address space one, the reviewed
`aligned_word_address`, one predecessor clock, and the exact same four byte
ValueIds on consume and emit. The load destination register group uses address
space zero and may transition its four bytes. The store source register is a
read, and the store memory group transitions its prior word to the masked next
word.

The aligned-address range event occurs between the complete ordinal-one and
ordinal-two groups. It does not consume or reset the access-ordinal cursor.
The fixed plan owns all three phase assignments and the range-event position at
construction time; there is no public
`withPhase`, `setOrdinal`, permutation slice, or Boolean "is load" switch.

### Construction and rollback

A compound plan accepts the established `.uint20` word-index value directly.
It preflights all register and memory types, selectors, relation schemas, phase
mapping, the aligned-address derivation, and the complete event capacity before
logical mutation. The plan, rather than the caller, creates both
`aligned_word_address(word_index)` and its matching range request. It
checkpoints nodes, effects, effect values, and the plan cursor. Any allocation
or later append failure restores all logical lengths, interning entries, and
cursor state. Capacity obtained by a successful reserve may remain but is not
proof-visible.

The commit path appends exactly ten relation effects and 46 tuple ValueIds:
the `rs1` triple, one aligned-address range request, the `src` triple, and the
`dst` triple. It performs no schema or string lookup after preflight and no
allocation after node storage, the node interning map, and the two contiguous
effect pools have been reserved. The node reserve covers the eleven-node
worst case: felt zero and one, one aligned address, two distinct register
addresses, three clocks, and three gaps. Machine-derived nodes may already be
interned; correctness and accounting do not rely on reuse or register aliasing.

There is no pre-appended evidence handle on the load/store plan path. If a
standalone aligned-address constructor is exposed for diagnostics or a later
reviewed instruction, its result does not grant load/store authority and an
unconsumed derived address or unmatched range request fails whole-program
validation as an orphan.

### Whole-program validation

Validation retains fixed stack storage bounded by three groups and performs no
heap allocation. In addition to ADR-0026's group checks, it establishes:

1. Every access group has one relation ordinal in effect-list order, exactly
   `1..N` without holes.
2. Every current-clock and strict-gap derivation has one physical phase in
   `1..3`.
3. A register-only program has phase equal to ordinal for every group.
4. Any memory group belongs to exactly one complete load or store signature
   from the table above; partial and mixed signatures reject.
5. A load has phases `1,3,2`; a store has phases `1,2,3`. No other permutation
   is accepted.
6. Register groups use canonical felt-zero address space and only
   `register_address` nodes. Memory groups use canonical felt-one address space
   and only `aligned_word_address` nodes.
7. Immediately after the ordinal-one access triple, the memory word index is
   the sole value of a matching `range_check_20@1/request` `.range_request`
   effect with the same liveness and no access ordinal.
8. Memory reads reuse all four byte IDs. Memory writes may change them.
9. Derived address, current clock, and gap values have no unreviewed consumer.
10. The instruction clock and liveness agree across all groups and address
    evidence.

The event scan remains linear. Bounded consumer checks multiply by at most
three groups, which is a fixed protocol constant rather than input-dependent
algorithmic growth.

### Witness resolution

Prepared witness metadata stores relation ordinal and physical phase in
separate numeric fields. The row loop walks groups in relation-entry order so
its output remains compatibility-exact, but it updates dynamic register and
memory trackers according to physical phase.

For a load, the destination register transition is resolved at phase two and
the memory source at phase three even though the memory relation entries are
serialized first. This requires either pre-resolving the three fixed accesses
into stack storage by phase and projecting them by ordinal, or an equivalent
fixed permutation. It must not update a tracker in effect-list order and then
pretend the clocks alone repair alias state.

Register and memory keys occupy different address spaces. Within one base
load/store instruction there is only one real memory key, so the phase
permutation creates no same-key same-clock exception. ADR-0025's sixteen-lane
shared phase remains a separate, capability-gated extension design.

### Semantic identity

E-002 formats remain unchanged:

| Capability | Manifest | Digest |
| --- | --- | --- |
| register groups only | format 5 / schema 4 | format 3 |

Any memory group, `aligned_word_address`, or non-identity ordinal/phase mapping
requires:

| Capability | Manifest | Digest |
| --- | --- | --- |
| E-003 load/store plan | format 6 / schema 5 | format 4 |

Format 6 encodes machine-derived variant tags, physical phases, ordered
effects, relation ordinals, and range evidence. Format 5 and digest v3 reject
E-003 programs instead of projecting away the new capability. The least
capable valid format is selected automatically. Source spans, allocation
capacity, and cache hit/miss history for an otherwise identical canonical node
and effect sequence do not affect identity. Node and effect order remain
semantic because persisted references bind that order.

## Performance invariants

- Current clocks, gaps, register addresses, and aligned memory addresses are
  inline affine expressions: zero new main columns and zero new direct
  constraints.
- A read stores four byte IDs once and reuses them on both relation sides.
- Each access remains exactly three relation events. The plan additionally
  emits the one aligned-address range event already present in production; it
  is not an extra proof lookup.
- Phase permutation is resolved once in the prepared plan. The row loop has no
  schema lookup, hashing, string dispatch, allocation, or data-dependent sort.
- Validation uses a fixed three-group array and bounded scans. It allocates
  zero bytes.
- The fixed load permutation is three stack entries. Introducing a general
  graph, heap queue, or dynamic permutation for this case is a regression.
- Compatibility mode preserves exact committed and interaction cell counts,
  batch coordinates, proof bytes, and transcript draws.
- Benchmarks separate authoring/validation setup from prepared witness fill;
  a setup improvement cannot hide extra proof work.

## Required evidence before production authority

The complete production-authority portfolio must include:

- exact load and store event-stream comparisons with production, including the
  `rs1` triple, aligned range request, `src` triple, and `dst` triple, plus the
  `1,3,2` load phase permutation and `1,2,3` relation ordinals;
- randomized replay of both physical clocks and strict gaps;
- aligned-word boundaries at zero and `2^20 - 1`, plus missing range, wrong
  liveness, wrong word index, raw address, unaligned address, address-space
  swap, and out-of-range witness mutations;
- load and store read-equality/masked-write mutations;
- every other phase permutation, ordinal hole/reorder, incomplete signature,
  mixed load/store signature, and same-key same-clock rejection;
- dynamic alias cases for `rd == rs1`, including witness resolution in
  physical phase order rather than relation-entry order;
- allocation failure at every construction site from empty and nonempty
  prefixes, with exact 10-effect/46-value logical rollback and no leaks;
- format-6/schema-5 and digest-v4 golden vectors, old-encoder rejection, exact
  node-reuse-history invariance, and rejection of phase-only corruption before
  identity can be issued;
- exact legacy, binding-only, and E-002 golden non-regression;
- zero-allocation prepared validation and witness-loop instrumentation; and
- signed-load Sail/Spike differential, AIR IR, proof, and performance gates
  before production authority changes.

The E-003 language delivery closes the constructor, rollback, validator,
prepared fixed-permutation, lowering, and identity portion of this portfolio.
It remains shadow-only. Dynamic tracker execution, signed-load differential
coverage, generated-witness equivalence, proof-byte compatibility, and
end-to-end proving benchmarks are deferred integration gates; they must close
before this ADR is cited as authority for replacing the production load/store
path.

## Consequences

The typed API now represents the production protocol instead of a cleaner but
incorrect source-before-destination fiction. Relation ordering and state-chain
time are both explicit, independently typed, and checked. Opcode authors use a
closed load/store plan and cannot create a phase permutation accidentally.

The aligned-word refinement makes the memory key's alignment and domain bound
traceable to a concrete range event without adding proof columns. Byte masks
and effective-address arithmetic remain opcode semantics rather than being
hidden inside the bus abstraction.

## Rejected alternatives

### Reorder load relation groups into physical phase order

Rejected because it changes the canonical interaction-entry order and batching
fixed by the compatibility artifacts.

### Keep one ordinal type and special-case arithmetic

Rejected because a stored value would have two meanings. Reviewers and later
witness code could silently use relation order where state-chain order is
required.

### Let callers pass a phase

Rejected because every permutation would become type-correct. Only the two
audited load/store plans are admitted.

### Accept a caller-provided `.address`

Rejected because semantic typing does not prove word alignment or the
`2^22` byte-address bound.

### Materialize address and clock derivations

Rejected because they are affine functions of existing values. Committing
them would add proof work and forgery surface without adding information.

## Revisit when

Revisit fixed three-group plans only when another proved base instruction has
a genuinely different access signature. Revisit repeated physical phases only
through ADR-0025's distinct-key capability. Revisit address refinement if the
memory commitment domain or word size changes; do not generalize it into an
unchecked cast.

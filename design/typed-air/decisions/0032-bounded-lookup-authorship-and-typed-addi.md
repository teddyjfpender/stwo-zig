# ADR-0032 — Bounded lookup authorship and typed ADDI

**Status:** accepted
**Date:** 2026-08-10

**Classification:** logical authoring and shadow-witness boundary; production
proof authority remains unchanged

## Context

E-006 and E-007 require one compatibility-exact RV32 ADDI slice. The shipped
ALU-immediate family has 35 main columns, 22 direct roots, and 16 ordered
relation events. ADDI shares its physical component with XORI, ORI, and ANDI,
so its selector and padding rules must retain the full family shape even when
only ADDI is active.

Three existing typed-AIR boundaries were insufficient:

1. ordinary field arithmetic erases byte and small-integer bounds, while the
   bitwise and fixed range tables require statically typed coordinates;
2. a sum of opcode bits must be usable as effect liveness without exposing a
   general field-to-selector cast; and
3. production register-read traces commit separate pre/post limbs, so exact
   read-only equality has to be proved rather than assumed by ID equality.

The manifest and semantic digest are closed grammars. Adding a distinct
bitwise-request effect and typed arithmetic cannot reuse their older identities
without making old consumers accept unknown semantics.

## Decision

### Bounded arithmetic is proof-preserving and closed

Add explicit `boundedAdd` and `boundedMul` constructors. They accept only
canonical bounded operands or unsigned constants, infer the result maximum
from their complete operand DAG, and reject any maximum at or above the M31
modulus. They cannot accept a generic felt, an M31 field constant, or a
multi-limb word. Structural validation recomputes the same bound and rejects a
forged result type.

Ordinary `add` and `mul` continue to return `.felt`. This is not a generic
refinement cast: bounds survive only operations whose range follows
mechanically from already bounded inputs.

`oneHotSelector` accepts two to five distinct bit values and constructs one
canonical addition tree. The opcode author remains responsible for the
one-hot polynomial constraints; the constructor provides only the closed
selector-typed expression shape used for liveness. Validation independently
recovers its distinct bit leaves. The fifth input is the reviewed extension
needed by the five-opcode RV32 base-ALU-register family; six or more inputs
remain outside the closed grammar and reject.

### Fixed-table operation requests are explicit effects

Add the stable `bitwise_request` effect kind and reviewed constructors for:

- four `bitwise@1/request` byte lanes;
- one `range_check_8_11@1/request`; and
- two `range_check_8_8@1/request` pairs.

The constructors fix schema, version, role, arity, types, and lack of access
ordinal. Multi-request constructors preflight every lane before appending any
effect and roll back atomically on allocation failure. A caller cannot select
an arbitrary table or relabel a component call as a bitwise operation.

### Committed read transitions require exact equality evidence

`registerReadTransition` may bind distinct committed pre/post limbs only when
each pair has the exact ungated semantic root
`active * (next - previous)`. The access group retains the production consume,
emit, and clock-gap records. Missing, reversed, differently gated, or partial
equality evidence rejects during whole-program validation.

### Typed ADDI retains the shared production geometry

The ADDI definition fixes:

- all 35 physical inputs and the shared four-selector activity equation;
- all 22 direct roots in production order, including derived, uncommitted
  carry booleanity;
- all 16 relation events in production order and batches of two;
- exact opcode IDs, immediate reconstruction, bitwise-table coordinates,
  range requests, sequential retirement, and register phases; and
- semantic digest
  `77cac74f85ee61abc8aa1ab97ee37c3f1fddb61eda7c9c982f166c75122908a6`.

The shadow witness binds the complete physical row recipe, arithmetic and
carry policy, inverse-or-zero recipe identity and metadata, all source slots,
and all 16 event bindings. Its binding digest is
`402a9f967e68d9a1f33efd9c646b6bdd51952ce89f9aa477c6de9c470f234595`.
After cold validation it writes caller-owned column-major storage directly,
allocates nothing per row, derives carries internally, and is failure-atomic.

### Canonical identity advances

Introduce manifest format 8/logical schema 7 and semantic digest format 6 for
bounded lookup-request authorship. Manifest formats 4 through 7 and digest
formats 2 through 5 reject this capability. Earlier programs continue to
select their least-capable byte-identical formats.

## Performance invariants

- Typed ADDI retains maximum direct degree three and adds no physical column,
  direct root, lookup event, interaction column, or transcript draw.
- Carry values are derived expressions, not committed witness inputs.
- The accepted witness row loop contains no allocation, schema lookup, string
  processing, recipe dispatch, or intermediate column buffer.
- Setup validation may traverse the small immutable program; no such scan is
  admitted into trace generation.
- Production witness selection, commitment geometry, and proof authority do
  not change under E-006 or E-007.

## Consequences

ADDI now demonstrates that the typed surface can express a mixed arithmetic,
range, bitwise, state, and register-access component without weakening the
production AIR or inflating it. The bounded constructors are reusable by
later opcodes but deliberately less expressive than a general refinement
system. The handwritten ADDI writer remains authoritative until E-013 passes
the clean-tree activation and proof-equivalence gates.

## Rejected alternatives

- General felt-to-byte or felt-to-selector casts: they would convert an
  unproved promise into lookup authority.
- Committed carry columns: they would inflate the trace and create new witness
  freedom for values already derived by the equations.
- Treating bitwise rows as generic component calls: it obscures the enforcing
  relation in canonical identity.
- Assuming distinct read limbs are equal: production commits both, so equality
  must be present in the AIR and validated structurally.
- Reusing manifest 7 or digest 5: that silently expands closed grammars.
- Switching production authority during authorship or parity testing: the
  activation decision requires independent proof-path evidence.

## Revisit when

Revisit if a general refinement calculus can derive the same canonical bounds,
table types, selector liveness, and read-only equality without introducing a
cast-based soundness boundary or row-loop work.

# Canonical typed IR

**Status:** design specification, version 0
**Last updated:** 2026-08-04

## Purpose

The canonical IR is the smallest object that can express one component's
meaning without committing prematurely to a physical trace layout. It must be
rich enough to generate production constraints, witness values, typed
relations, formal artifacts, and runtime polynomial programs.

It is not a general programming language. It is a deterministic,
statically-shaped circuit and effect graph.

## Core identities

All references are small integer IDs scoped to one owned program:

```zig
pub const ValueId = enum(u32) { _ };
pub const ConstraintId = enum(u32) { _ };
pub const EffectId = enum(u32) { _ };
pub const HintId = enum(u32) { _ };
pub const FunctionId = enum(u32) { _ };
pub const RelationSchemaId = enum(u16) { _ };
```

Distinct ID types prevent accidental cross-indexing. Serialized forms use
canonical unsigned integers after validation.

## Semantic types

The first version should support:

```text
felt
bit
bounded_uint(bits, representation)
u8
u16
u20
u32_limbs
reg_index
address
pc
clock
selector
array(element_type, static_length)
```

`u32_limbs` is not interchangeable with one M31 value. Composition produces
an explicitly bounded representation or a named modular operation. The IR must
be able to state which conversions rely on range evidence, directly supporting
the repository's open FV-3 obligation.

Types are semantic metadata with validation rules. They do not silently insert
constraints. Constructors that claim a constrained type must either emit the
necessary constraint/effect or consume a value already carrying reviewed
evidence.

## Values and operations

A value node contains:

- stable operation tag;
- result type;
- ordered operands;
- operation-specific immediate data;
- source span; and
- optional stable semantic name.

Initial operations:

```text
constant       input_column      row_value
add            sub               mul             neg
select         compose_limbs     decompose_limbs
cast_checked   call_output       hint_output
```

No division node exists in polynomial expressions. Division-like witness
algorithms are hints whose results are constrained by polynomial identities and
range relations.

Node order is topological. Structural interning uses the operation, type,
operands, and semantic immediates—not rendered source text.

## Constraints

A constraint contains:

- expression root;
- gate;
- row mask/window;
- semantic category;
- source span;
- stable name; and
- optional proof-obligation tag.

The constraint means `gate * expression = 0` over its declared row window.
The degree analyzer evaluates that complete expression, including the gate.

Constraint categories distinguish at least:

- semantic;
- materialization;
- type/range;
- hint binding;
- boundary;
- transition; and
- relation transition.

The category does not change mathematical meaning; it supports diagnostics,
formal coverage, mutation selection, and cost reports.

## Hints

A hint record contains:

- stable recipe ID and version;
- ordered typed inputs;
- ordered typed outputs;
- exceptional-case policy;
- source span; and
- the set of constraints/effects intended to bind each output.

Construction fails if a hint output has no binding path. A later adversarial
validator should be able to replace each hint output independently and identify
the guard that rejects the mutation.

Hint recipes are registered concrete functions. Recipe IDs are protocol
metadata when they affect witness layout, but the proof never trusts the recipe
to be honest.

## Effects

Effects form a separate ordered list. Expressions may feed effects; effects do
not gain order from expression dependencies alone.

```text
program_fetch
register_read
register_write
memory_read
memory_write
range_request
state_consume
state_produce
component_call
public_consume
public_produce
```

Each effect declares:

- schema;
- role;
- typed values;
- multiplicity/liveness expression;
- access ordinal when applicable;
- source span; and
- optional call/function activation.

High-level builder methods derive these fields. Low-level arbitrary relation
emission is kept internal to reviewed schema implementations.

## Relation schemas

A relation schema owns:

- stable domain ID and version;
- human-readable name;
- ordered field types;
- allowed roles;
- challenge-combination convention;
- multiplicity type and bounds;
- access-ordinal policy;
- padding policy;
- public-boundary policy; and
- source-coefficient bound needed to exclude field wrap/collision.

The initial registry wraps the existing program, memory, state, range-check,
Merkle, and Poseidon relations without changing their protocol order.

The version-0 implementation pins all twelve current Stark-V-compatible
domains in transcript challenge order. Each schema uses a typed domain and
`RelationSchemaId`, exact or field-scalar field specifications, allowed roles,
the alpha-powers-minus-z challenge convention, access-ordinal policy, padding
policy, public-boundary policy, and an explicit coefficient-bound authority.
Tests compare every domain and arity against the shipped lookup registry so the
logical copy cannot silently drift.

A guest Poseidon precompile receives a distinct schema/version or an explicit
mode field. It must not accidentally balance against the sparse-Merkle
infrastructure relation merely because the mathematical permutation matches.

## Functions and calls

A function has typed inputs, outputs, local values, constraints, hints, and
effects. Loops are statically unrolled. Calls are statically resolved.

Version 0 rejects recursion by detecting cycles in the function-call graph.
Inlining and relation-backed activation are both lowerings of a call:

- inline calls duplicate the callee program structurally;
- relation-backed calls emit an activation relation and place callee
  activations in a component table.

Changing between those forms is a protocol layout decision.

## Row windows and masks

Every input explicitly identifies its tree, column role, and row offset.
Supported windows begin with current and next row; no backend may assume all
programs are single-row merely because opcode families currently are.

Boundary and transition masks are first-class inputs to degree analysis.
Padding behavior is declared once per component and validated against every
constraint and effect.

## Degree

Each node carries an inferred polynomial degree:

- constants: 0;
- committed inputs: 1;
- addition/subtraction: maximum operand degree;
- multiplication: sum of operand degrees;
- selection: degree of selector plus selected expression as lowered;
- committed materialization: 1 at uses, with a separate equality constraint.

The final degree of a constraint includes:

- its gate;
- row mask or boundary selector;
- materialization equality;
- relation numerator expressions;
- interaction recurrence; and
- any batching-specific multiplication.

The compiler reports both logical-expression degree and final protocol
constraint degree. A component is rejected if either the direct or interaction
lowering exceeds its declared bound.

## Materialization

Materialization introduces a committed witness column `v` and a constraint
binding `v` to a logical expression. The algorithm must be deterministic.

Version 0 policy:

1. Preserve explicit compatibility columns.
2. Compute structural use counts and full degree.
3. Inline expressions that remain within the degree budget.
4. Materialize only when required by degree or explicitly required by the
   compatibility layout.
5. Recursively split products using a stable ordering: greatest excess degree,
   then greatest structural reuse, then lowest source/topological ID.
6. Reuse one materialization for structurally identical expressions with
   compatible gates and windows.
7. Re-run degree validation after all gates and relation constraints exist.

An experimental cost policy may later consider commitment, evaluation, and
backend costs, but it emits a proposal and cost report. It does not silently
replace the accepted protocol layout.

## Physical layout

A lowered layout assigns:

- each logical input/output/materialization to a tree and column;
- trace log size and padding rule;
- constraint order;
- relation event and batch order;
- interaction columns;
- public claim positions; and
- backend capability identity.

Every accepted layout emits a canonical manifest containing:

```text
schema version
component kind and version
logical-program digest
layout-policy ID and version
ordered column descriptors
ordered constraints and roots
ordered relation schemas/events
degree report
hint recipe IDs
formal IR version
runtime capability version
```

The logical manifest uses the versioned `STWAIRL\0` encoding: explicit stable
tags, fixed field order, length-prefixed bytes, and fixed-width little-endian
integers. Names and source paths are serialized by content rather than arena
ID, while constraints and effects retain declared semantic order. See
[ADR-0005](decisions/0005-canonical-logical-manifest.md). The later physical
layout manifest extends this identity rather than reinterpreting it.

## Validation passes

Before lowering:

1. all IDs are in range and topological;
2. types match every operation;
3. names required for protocol identity are unique;
4. function graph is acyclic;
5. effects conform to schemas;
6. access ordinals are complete and nonduplicated;
7. hint outputs have binding paths;
8. public inputs/outputs are declared;
9. row windows are supported; and
10. no logical value depends on an effect that occurs later.

After lowering:

1. column references are valid and nonoverlapping;
2. constraint and relation order is canonical;
3. full degree is within bounds;
4. every committed witness column is input, output, materialization, or bound
   hint data;
5. padding cannot emit a live effect;
6. relation coefficient and multiplicity bounds are valid;
7. layout manifest reproduces exactly;
8. runtime and formal exporters replay the lowered roots; and
9. compatibility policy matches current protocol geometry byte for byte.

## AIR IR v2 compatibility

The initial adapter lowers a migrated opcode program into the current
`ConstraintProgram` with:

- identical main-column count and order;
- identical direct constraint count and order;
- identical lookup count, tuple order, roles, access ordinals, and batching;
- identical active selector semantics; and
- identical formal projections.

AIR IR v2 remains the normative serialized object during this phase. Logical
IR metadata that does not affect it is development evidence, not a competing
formal program.

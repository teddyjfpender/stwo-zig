# Canonical typed IR

**Status:** design specification, version 0
**Last updated:** 2026-08-05

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
pub const CallId = enum(u32) { _ };
pub const HintRecipeId = enum(u16) { _ };
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
- optional selector activation;
- exceptional-case policy;
- source span; and
- the set of constraints/effects intended to bind each output.

The v0 registry is closed and numeric: arbitrary strings never select an
algorithm or signature. Each entry pins an exact input/output type sequence,
deterministic honest algorithm, and exceptional-case policy. The initial
recipes are felt identity and field inverse-or-zero; the latter returns an
inverse and nonzero bit and explicitly maps zero to `(0, 0)`.

Each output has one or more canonical proof-binding certificates. A certificate
names a `hint_binding` constraint or ordered effect with the same gate/liveness
as the hint activation, then records an output-first value path ending at that
constraint root or effect value. Every adjacent path value has a direct dataflow
edge. This supports allocation-free validation and precise diagnostics without
trusting recursive graph search. Unknown recipes, unbound outputs, activation
drift, and malformed paths reject before lowering.

Hint recipes are registered concrete functions. Recipe IDs are protocol
metadata when they affect witness layout, but the proof never trusts the recipe
to be honest. A later adversarial validator replaces each output independently
and identifies the guard that rejects the mutation.

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

The A-002 production compatibility bridge stores an ordered pre-lowering
lookup record beside the typed arena. It retains schema, role, the exact shipped
signed numerator, mapped tuple values, access ordinal, and batch size, but does
not call that record an authored `Effect`: symbolic extraction has erased the
semantic field types needed for full validation. `validateEventShape` exists
only for this explicit boundary. Authored effects must carry reviewed semantic
types and pass full `validateEvent` before lowering.

A guest Poseidon precompile receives a distinct schema/version or an explicit
mode field. It must not accidentally balance against the sparse-Merkle
infrastructure relation merely because the mathematical permutation matches.

## Functions and calls

A function has typed inputs, outputs, local values, constraints, hints, and
effects. Loops are statically unrolled. Calls are statically resolved.

Version 0 stores declarations in dependency-topological order: a function may
call only an earlier, complete declaration. A two-phase builder opens a caller,
records its calls, and seals its outputs. This makes cycles and forward edges
unrepresentable through the public API; whole-program validation independently
rechecks the rule against raw arena state. Root-level calls have no caller.

Every call owns ordered arguments and typed `call_output` values. Inlining and
relation-backed activation are explicit lowering strategies on the call:

- inline calls duplicate the callee program structurally;
- relation-backed calls emit an activation relation and place callee
  activations in a component table.

Changing between those forms is a semantic manifest change and a protocol
layout decision; the serializer never infers strategy from later compiler
heuristics.

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

The implemented logical pass evaluates the validated DAG once in topological
order. Constants are degree zero; inputs and committed hint/call outputs are
degree one; add/sub/neg preserve maxima; multiplication adds with overflow
rejection; selection adds selector degree to the maximum branch; and a
constraint total includes its gate. This report is not relabelled as final
protocol degree. Stable diagnostics render its expression, gate, total, and
limit alongside the typed source value path. See
[ADR-0008](decisions/0008-stable-structured-diagnostics.md).

The production-shadow protocol pass then analyzes the exact current lowering.
Direct placement is already present in each imported root. Relation
denominators take the maximum degree of their tuple fields; shifted cumulative
columns and `is_first` are degree one; transcript challenges and claims are
degree zero; and one- or two-entry batches use the shipped LogUp recurrence.
It converts final algebraic degree `d` into
`ceil(log2(max(1, d - 1)))` quotient-expansion bits after vanishing-polynomial
division. Every current lookup interaction is degree three, while seven direct
families are degree two and ten are degree three. The complete result and its
limitations are fixed by [ADR-0011](decisions/0011-complete-protocol-degree-and-pinned-report.md)
and the [M2 report](artifacts/m2-production-shadow-report-v1.md).

## Static collections and pure functions

`StaticArray(element, N)` keeps scalar value IDs visible to the ordinary DAG
while making element type and shape part of the Zig type. Maps, zip maps, and
left folds expand eagerly in ascending index order. Each result retains the
source span of its unrolled expansion even when structural CSE returns a value
whose primary node span came from an earlier site. Shape, type, provenance, and
all operation spans preflight before callbacks; a failed expansion rolls every
new node back to its checkpoint.

The first consumer is the isolated width-16 M31 Poseidon2 definition. It
imports the pinned numeric constants, statically expands the exact external and
internal round schedule, and declares one pure 16-input/16-output function. The
unmaterialized output degree is `5^22`, so this graph is semantic authority for
the pilot rather than an admissible direct AIR. It emits no constraint, hint,
effect, witness column, or layout. H-003 owns the separate deterministic
degree-three materialization decision; H-004 binds its semantic set bijectively
to the existing 426 temporary columns before any optimization is proposed.

## Materialization

Materialization introduces a committed witness column `v` and a constraint
binding `v` to a logical expression. The algorithm must be deterministic.

Version 1 policy:

1. Compute reachability and structural use counts from the ordered roots; an
   unreachable arena subgraph cannot affect degree or overflow the request.
2. Account for the shared gate and row-mask degree outside every equality.
3. Inline expressions that remain within the degree budget.
4. Recursively split using greatest excess degree, greatest structural reuse,
   then lowest source/topological ID.
5. Force every declared output to a materialization boundary.
6. Emit a canonical dependency-topological semantic order, which is not a
   physical-layout ABI.
7. Recompute the entire selection, dependency, degree, name, fingerprint, and
   output plan during validation.

The cut set and degrees are root-local; names and fingerprints deliberately
bind the whole-program digest. The Poseidon adapter separately reorders the
authenticated set into the historical lane-major schedule and uniquely matches
source stage, round constant, square chain, and final output root. The policy
boundary and version rules are fixed by
[ADR-0018](decisions/0018-degree-bounded-materialization-and-compatibility-order.md).

## Compiled witness and relation plans

Physical consumers do not interpret an untrusted `ValueId` list. The Poseidon
witness constructor first revalidates the semantic arena, degree-bounded plan,
and complete compatibility binding, then compiles the canonical output closure
into owned topological field instructions. It retains explicit input and
materialization slot maps plus the authority identities needed to reconstruct
and compare that executable projection after an ownership boundary.

Execution preflights the instruction structure, canonical SHA-256 projection,
trace shape, and every input/destination address range before the first write.
After that boundary it is infallible and allocation-free: padding is zeroed and
logical rows are evaluated directly into bit-reversed final column storage.
One plan owns one mutable scratch vector, so it is deliberately non-reentrant.

Relation lowering is a separate authenticated plan. Compatibility version 1
contains four request events—input, narrow output, wide output, and atomic
input/output—in two fixed pairs-batches. It preserves the signed mode/enabler
formulas, sixteen- or thirty-two-field denominator ABI, semantic projections,
eight interaction columns, and two claims. Bulk generation authenticates once
before using private allocation-free row kernels. A carried narrow output is
only an interaction optimization; cancellation with the Merkle counterpart and
validation against the committed main row remain its proof binding. See
[ADR-0019](decisions/0019-authenticated-witness-and-relation-plans.md).

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

The logical program also exposes semantic digest format 1: SHA-256 under the
`stwo-zig/typed-air/semantic` domain over a validated, allocation-free canonical
projection. It binds stable semantic names, types, declared order, recipes,
proof paths, effects, functions, and calls. Source paths/spans and arena
implementation state are deliberately excluded. See
[ADR-0007](decisions/0007-semantic-program-digest.md).

`compat-v1` now supplies the first executable physical mapping. Local tree IDs
are preprocessed 0, main 1, and interaction 2. The active selector and every
main input have reverse `ValueId` mappings; interaction columns are batch-major
QM31 coordinates with explicit current/previous windows. A main descriptor
carries separate logical and committed names because semantic paths such as
`clock` can map to physical names such as `clk`. Physical names are read from
the frozen witness schema, never inferred from logical spelling. See
[ADR-0012](decisions/0012-compat-v1-local-physical-mapping.md).

Direct constraints lower through that mapping into the production extractor's
six-operation node vocabulary. The pass emits the complete main-column prefix
followed by `is_active`, retains only direct-root dependencies, canonicalizes
commutative operand order, and expands selection as
`when_false + selector * (when_true - when_false)`. Its owned program validates
without allocation and replays only after structural validation. Exact
normalized node and ordered-root equality holds for all 17 current families;
see [ADR-0013](decisions/0013-fallible-normalized-direct-lowering.md).

Ordered lookup compatibility uses a role-normalized event record. Request and
consume numerators must be a leading negation whose operand is retained as
liveness; emit numerator and liveness are identical. The signed numerator
remains as a checked cache so lowering cannot apply the role sign twice. Event
roots are signed numerator followed by tuple fields, and batches bind directly
to their four `compat-v1` QM31 coordinate references. This shadow record still
withholds semantic field types; authored effects must pass full typed schema
validation. See
[ADR-0014](decisions/0014-role-normalized-ordered-lookup-lowering.md).

Runtime export is a representation boundary, not another compiler. It copies
validated canonical nodes and ordered roots/events into the backend-neutral
owned capability types, checks the six-operation enum ABI at compile time,
initializes unused tuple storage deterministically, and validates the result.
It performs no algebraic or layout decision; see
[ADR-0015](decisions/0015-validated-canonical-runtime-export.md).

AIR IR v2 has a distinct formal policy: `is_active` becomes constant one and
the frozen wire retains historical source numbering and commutative orientation.
The shadow therefore digest-binds an exact source schedule to the canonical
typed graph and retains source IDs for all ordered roots. Formal lowering
replays that provenance, derives roles/projections, and calls the existing JSON
writer. Raw numbering is legacy wire identity, never logical semantic identity;
see [ADR-0016](decisions/0016-source-bound-air-ir-v2-compatibility.md).

The accepted compatibility identity is the section-framed `STWAIRC\0` format
version 1. One artifact for each of the 17 production families records seven
ordered sections: authority identity, physical layout, direct runtime program,
lookup runtime program and events, complete degree analysis, hint recipes, and
formal AIR IR v2 exports. Runtime program bytes are carried in full alongside
their domain-separated digests. Each formal entry records opcode identity,
exact byte length, and SHA-256 only after the typed and production AIR IR bodies
compare byte for byte. Fixed-width little-endian integers, explicit stable enum
tags, and length-framed strings and sections make host representation irrelevant.
The family-ordered TSV index exposes whole-artifact and section identities,
geometry, export counts, and maximum degrees for review. See
[ADR-0017](decisions/0017-sectioned-compatibility-manifests.md) and the
[checked M3 artifacts](artifacts/README.md).

Receipt generation deliberately separates result and scratch allocation. The
legacy production symbolic builder retains its established panic-on-OOM
contract on stable scratch storage; exhaustive failure injection applies to
every allocation introduced by runtime ownership and manifest encoding. Normal
callers pass one allocator for both. This boundary does not weaken ordinary
ownership or deterministic-byte requirements.

## Validation passes

Before lowering:

1. all IDs are in range and topological;
2. types match every operation;
3. names required for protocol identity are unique;
4. function declarations and calls are complete and dependency-topological;
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

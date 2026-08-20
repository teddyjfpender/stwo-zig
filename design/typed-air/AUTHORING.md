# Authoring typed AIR programs

**Status:** executable pre-production interface
**Last updated:** 2026-08-05

This is the supported authoring path for the isolated logical kernel in
`src/frontends/riscv/air/lang`. It is intentionally not imported by production
AIR, witness, prover, runner, transcript, or formal-export code yet. The examples
below are compiled by
[authoring_test.zig](../../src/frontends/riscv/air/lang/authoring_test.zig).

## Surface map

| Module | Responsibility |
| --- | --- |
| `ir` | Owned arena, source/name interning, values, constraints, and provisional ordered effects |
| `types` | Semantic value types and non-interchangeable IDs |
| `static_collections` | Fixed typed arrays with deterministic map, zip-map, fold, and per-expansion provenance |
| `functions` | Dependency-topological function declarations and static calls |
| `hint_recipe` | Closed recipe registry, versions, signatures, algorithms, and exceptional cases |
| `hints` | Hint output construction and canonical proof-binding paths |
| `relation` | Typed registry for the twelve current relation domains |
| `validate` | Allocation-free completed-program trust boundary |
| `degree` | Logical value and gated-constraint degree analysis |
| `diagnostic` | Stable codes and source/type/path/degree rendering |
| `manifest` | Full source-attributed canonical logical artifact |
| `digest` | Source-independent semantic program identity |
| `typed_poseidon2` | Pure width-16 M31 Poseidon2 pilot definition; no constraints or layout |
| `degree3_materializer` | Root-scoped versioned degree-three cuts, dependencies, identities, and validation |
| `typed_poseidon2_compat` | Authenticated mapping from generic cuts to the current 426-slot Poseidon layout |
| `typed_poseidon2_witness` | Authenticated compiled evaluator that writes the 445-column compatibility trace directly into final storage |
| `typed_poseidon2_relations` | Authenticated four-event/two-batch Poseidon relation, interaction, and claim lowering |
| `direct_witness_executor` | Shared allocation-free, failure-atomic execution kernel for prepared family-to-column writers |
| `materialization_diagnostics` | Canonical 426-record source, plan, degree, constraint, and physical-placement report |

Import `air/lang/mod.zig` and use these namespaces. Callers should not mutate
arena storage directly; public fields currently exist so corruption tests can
prove the validator is independent of constructors.

## Lifecycle

1. Initialize one `ir.Arena` with an explicit allocator.
2. Register real source files and spans, or use `SourceSpan.generated()` for
   generated/test programs.
3. Create typed inputs and topological expression values.
4. Declare constraints and ordered effects in semantic order.
5. Seal every hint with bindings and every two-phase function with outputs.
6. Call `validate.validate` before treating the program as complete.
7. Derive degree reports, diagnostics, manifests, and semantic digests from the
   validated arena.
8. At a physical consumer boundary, validate the H-003 materialization plan and
   H-004 binding before compiling witness or relation plans. Reauthenticate an
   owned plan after transport or mutation-capable ownership transfer.
9. Preflight final storage before witness execution. Pure family executors use
   the shared compile-time-dispatched direct-witness kernel and are reentrant;
   an executor that owns mutable scratch, such as the Poseidon compatibility
   evaluator, is not. Bulk relation generation authenticates once and then
   uses allocation-free row kernels.
10. Call `deinit` exactly once. Views and IDs remain scoped to their arena or
    owning compiled plan.

Construction methods are transactional under allocation failure. A returned
borrowed slice is valid only until the corresponding pool grows or the arena is
deinitialized. Do not retain caller-owned strings: the arena copies stable names
and source paths. The Poseidon executor writes directly into caller-owned
bit-reversed column storage, allocates nothing during execution, and rejects
shape, alias, instruction, and slot corruption before the first mutation. These
interfaces remain shadow-only under
[ADR-0019](decisions/0019-authenticated-witness-and-relation-plans.md).

## Minimal pure component

```zig
const air = @import("air/lang/mod.zig");

var arena = air.ir.Arena.init(allocator);
defer arena.deinit();
const span = air.source.SourceSpan.generated();

const lhs = try arena.input("example.lhs", .felt, span);
const rhs = try arena.input("example.rhs", .felt, span);
const expected = try arena.input("example.expected", .felt, span);
const active = try arena.input("example.active", .bit, span);
const sum = try arena.add(lhs, rhs, span);
const difference = try arena.sub(sum, expected, span);

_ = try arena.assertZero(
    "example.addition",
    difference,
    active,
    .semantic,
    span,
);
_ = try air.functions.add(
    &arena,
    "example.add",
    &.{ lhs, rhs },
    &.{sum},
    span,
);

try air.validate.validate(&arena);
const program_identity = try air.digest.compute(&arena);
_ = program_identity;
```

The constraint means `active * (lhs + rhs - expected) = 0`. Its logical degree
is two: degree one for the expression and one for the gate. This is not yet the
final protocol degree, which will also include masks and interaction lowering.

## Bound hint and ordered effect

```zig
const input = try arena.input("example.input", .felt, span);
const active = try arena.input("example.active", .bit, span);
const hint_id = try air.hints.add(
    &arena,
    .identity_felt,
    &.{input},
    active,
    span,
);
const output = air.hints.outputs(&arena, hint_id).?[0];
const binding_root = try arena.sub(output, input, span);
const constraint = try arena.assertZero(
    "example.identity",
    binding_root,
    active,
    .hint_binding,
    span,
);
const effect = try arena.addEffect(
    .public_produce,
    &.{output},
    active,
    null,
    span,
);

try air.hints.bind(&arena, hint_id, &.{
    .{
        .output_index = 0,
        .target = .{ .constraint = constraint },
        .path = &.{ output, binding_root },
    },
    .{
        .output_index = 0,
        .target = .{ .effect = effect },
        .path = &.{output},
    },
});
try air.validate.validate(&arena);
```

The honest identity recipe is not trusted. The constraint path proves where its
output enters a gated polynomial identity; the effect path records the matching
live public event. Both targets use the exact hint activation. Bindings are
ordered by output, then constraint before effect, then target ID.

`Arena.addEffect` is a provisional low-level logical record. Production opcode
authoring waits for Phase 5 high-level constructors backed directly by the typed
relation registry; arbitrary effect tuples will not be the final public API.

## Static calls

Functions are declared in dependency order. Use `functions.add` for a body that
needs no internal calls. For a caller:

1. call `functions.begin`;
2. issue calls only to earlier complete functions;
3. consume the typed values returned by `functions.callOutputs`; and
4. call `functions.finish` with the caller outputs.

Every call explicitly chooses `inline_expansion` or `relation_backed`. That
choice changes both the manifest and semantic digest. Recursion and forward
references reject.

Run `function_frames.compile` before treating that graph as a collection of AIR
tables. The compiler rejects transitive reads outside a function's declared
arguments, derives its write-once local cells in value-topological order, and
assigns every reachable hint invocation to exactly one frame. A
`relation_backed` target must return a deterministic, non-empty tuple of at
most 64 field scalars; hint-dependent returns and limb/array values fail closed
until an explicit ABI expansion exists.

The resulting activation plan orders callee consumes by function declaration,
then caller/public emissions by call declaration. Each function relation has a
domain-separated ABI digest bound to the semantic program identity, stable
name, and argument/return types. This is compiler substrate: authoring a plan
does not activate a proof relation until a prover/verifier adapter consumes the
same authenticated plan.

## Statically shaped authoring

Use `static_collections.StaticArray(element, N)` when a pure function has a
compile-time shape but each scalar must remain visible to interning, degree
analysis, materialization, and diagnostics. Construction validates the scalar
type and every source span. `map`, `zipMap`, and `fold` expand in ascending
index order and roll the entire node expansion back if a callback fails. Their
`WithSpans` variants retain a distinct source site for every unrolled step even
when CSE returns an older node ID.

The callback builder is an expression-only convenience surface, not a Zig
security boundary; authoring callbacks remain trusted construction code and
whole-program validation remains authoritative. Collections do not implicitly
add constraints, hints, effects, or storage.

`typed_poseidon2.define` demonstrates the intended pure-function boundary. It
declares sixteen named felt inputs and statically expands the pinned permutation
to sixteen outputs. Its high unmaterialized degree is intentional. Callers must
not constrain those outputs directly. The versioned H-003 policy derives
root-local degree-three boundaries and forces the sixteen outputs; H-004 then
maps that semantic set into the current 426-column compatibility schedule.
Generic topological order is not a layout ABI; see
[ADR-0018](decisions/0018-degree-bounded-materialization-and-compatibility-order.md).

## Identity and diagnostics

- `manifest.serializeAlloc` includes source paths and spans for complete audit
  reproducibility.
- `digest.compute` excludes diagnostic sources but includes semantic names,
  types, order, recipes, bindings, effects, functions, and calls.
- `degree.analyze` owns result arrays and therefore requires `deinit`.
- `diagnostic.render` accepts a writer and optional degree analysis; use
  `renderAlloc` only when owned text is needed.

Never use a digest as evidence that independently written witness and constraint
implementations agree. It identifies one program; it does not prove refinement.

## Current boundary

The authoring kernel is executable and defensively validated. Its broad
compiler surface remains under incremental production adoption rather than a
single global authority switch. All seventeen opcode-family witness writers
are authenticated typed production paths. LUI and FENCE have additionally
crossed the stronger E-018/E-019 boundary: fixed typed capabilities now own
their architectural retirement, witness projection, direct constraints,
ordered relations, and formal/runtime export, and generated dispatch prevents
legacy fallback. See [ADR-0038](decisions/0038-pinned-typed-opcode-authority-and-generated-retirement.md).

The remaining fifteen execution/AIR families, live function-activation
lowering, compiler-owned composition metadata, and recursion-local components
are still migrations in progress. AIR IR v2, exact compatibility manifests,
Sail, malicious-proof tests, and independent verification remain mandatory
oracles throughout; a semantic digest never substitutes for those gates.

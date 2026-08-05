# Authoring typed AIR programs

**Status:** executable pre-production interface
**Last updated:** 2026-08-04

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
| `functions` | Dependency-topological function declarations and static calls |
| `hint_recipe` | Closed recipe registry, versions, signatures, algorithms, and exceptional cases |
| `hints` | Hint output construction and canonical proof-binding paths |
| `relation` | Typed registry for the twelve current relation domains |
| `validate` | Allocation-free completed-program trust boundary |
| `degree` | Logical value and gated-constraint degree analysis |
| `diagnostic` | Stable codes and source/type/path/degree rendering |
| `manifest` | Full source-attributed canonical logical artifact |
| `digest` | Source-independent semantic program identity |

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
8. Call `deinit` exactly once. Views and IDs remain scoped to that arena.

Construction methods are transactional under allocation failure. A returned
borrowed slice is valid only until the corresponding pool grows or the arena is
deinitialized. Do not retain caller-owned strings: the arena copies stable names
and source paths.

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

The authoring kernel is executable and defensively validated, but shadow-only.
AIR IR v2 and the current production builders remain authoritative until the
adapter, compatibility lowering, proof, mutation, and formal gates in
[IMPLEMENTATION.md](IMPLEMENTATION.md) are complete.

# 2026-08-12 — F-013 function frames and activation plans

## Question

Does the existing typed function graph actually enforce the Cairo-style frame
model and compile `relation_backed` calls into the `fn_io(args..., rets...)`
protocol proposed in the original design?

## Context and exact revisions

Before this tranche, `air/lang/functions.zig` authenticated function names,
typed signatures, topological calls, generated call-output identities, and the
inline-versus-relation-backed choice. It did not establish that a function read
only its arguments, did not assign hint outputs to one frame, and did not lower
the relation-backed choice into consume/emit/public activation records.

`air/lang/function_frames.zig` now compiles the validated global expression DAG
into an owned, versioned `function-frame-plan/v1`:

- a transitive declared-input visibility check for every output and call;
- one canonical topological list of write-once locals per frame;
- exclusive ownership of each untrusted hint invocation;
- deterministic-return analysis through the topological call graph;
- a field-scalar activation ABI capped at 64 values;
- one domain-separated relation identity per function, bound to the current
  semantic program identity, stable name, and exact argument/return types;
- callee-consume, caller-emit, and verifier/public-emit events in canonical
  function/call order; and
- an allocation-free owned-plan validator plus a cold strong regeneration
  check against the complete logical arena.

The canonical focused fixture digest is
`6839b8661426cac5c33bb112eeb4daf0df1fbaf1abfbb68afdd31e5f577743da`.

## Commands or experiment

```text
zig build --build-file src/frontends/riscv/build.zig \
  test-air-function-frames -Doptimize=Debug --summary all
zig build --build-file src/frontends/riscv/build.zig \
  test-air-function-frames -Doptimize=ReleaseSafe --summary all
zig build --build-file src/frontends/riscv/build.zig \
  test-air-function-frames -Doptimize=ReleaseFast --summary all
```

All three modes pass 7/7 focused tests. The suite covers internal and public
activation geometry, transitive frame escape, hint-dependent non-determinism,
non-field tuples, cross-frame hint reuse, inline impurity propagation,
event/tuple/authority mutations, and exhaustive allocation-failure cleanup.

## Observations

The unkeyed function tuple is sound only when returns are deterministic from
the declared arguments. A hint output is an untrusted committed cell even when
it has a witness recipe, so relation activation now fails closed if such a
value reaches a return. An inline call may retain that impurity because it does
not create a standalone multiset relation. A relation-backed call may target
only a transitively deterministic callee.

Function activation is not padded into the fixed 47-relation zkVM/recursion
registry. Each function owns a distinct ABI identity and future challenge slot.
This preserves exact heterogeneous arity and prevents unrelated functions with
the same tuple shape from sharing a relation accidentally.

## Interpretation

The Cairo-frame idea now has a mechanically checked compiler representation,
not merely a `CallStrategy` tag. The plan is suitable input for table layout,
interaction, public-claim, and manifest generation. It also makes the remaining
protocol work sharply reviewable: a proof adapter must reproduce these exact
events and challenge identities rather than inventing call wiring ad hoc.

## What this does not establish

- No live prover or verifier consumes the new activation plan yet.
- Function-owned constraints/effects still need explicit table-body ownership;
  the current frame closure covers expression, hint, and call dataflow.
- Inline call outputs still require substitution in the direct/AIR lowerers.
- Dynamic self-recursion remains excluded by the accepted acyclic IR-v0 rule.
- Omission, duplication, collision, and proof-transcript mutations become
  acceptance gates only after the production LogUp adapter exists.

## Decisions/tasks affected

- Adds F-013 as completed compiler substrate.
- Adds F-014 for production activation lowering and F-015 for body ownership
  and inline substitution.
- Refines the two function rows in `ORIGINAL-SCOPE.md` without claiming
  production completion.

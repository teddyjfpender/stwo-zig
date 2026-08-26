# A-013 compiler-owned row windows

**Date:** 2026-08-12
**Status:** generated 17-family production composition is proof-byte and
transcript exact; only paired global performance evidence remains open

## Result

The typed compiler now owns a versioned row-window plan for every native opcode
family. The plan records, in canonical tree order:

- the semantic and interaction component owner of every column;
- the current or previous-row offset of every committed read;
- base-field versus named QM31-coordinate type;
- the cyclic first-row LogUp boundary and public-claim geometry;
- exact preprocessing, main, and interaction tree widths; and
- the P-002 semantic-program and Sail-authoritative witness-layout identities.

The allocation-free SHA-256 identity binds all of those facts. It excludes
allocator addresses and source locations. All seventeen plan digests are
pinned in `row_window.zig`; construction rejects a semantic-program, witness
layout, owner, boundary, order, shift, type, width, or digest change.

## Production projection

The full plan is a cold compiler artifact. The live opcode LogUp component now
consumes a compact, allocation-free `ComponentMaskBinding` derived from it.
That binding owns one current `is_first` sample, borrows the semantic
component's current main columns, and owns every interaction coordinate at
current and previous points. The binding drives live interaction-column bounds
and PCS mask emission; the same fixed geometry is revalidated before cold
metadata or domain-evaluator preparation.

The row-evaluation hot loop does not hash or allocate. Compatibility backends
retain their exact program IDs and physical widths. The explicit A-014
protocol uses the same binding type, but its source identity is the
authenticated compiler-selected batch plan and its smaller interaction width;
its V2 polynomial capability remains inert unless the statement-scoped
activation is authenticated.

## Physical expression authority

The append-only V2 expression arena can now name authenticated shifted columns
directly without changing the frozen logical V1 node union or any existing
manifest bytes. Its compiler binds every read to the exact row-window plan,
physical tree/local-column pair, current/previous offset, typed component
owner, and algebraic degree. Cross-owner arithmetic, unknown or forward
operands, duplicate roots, dead subgraphs, non-canonical constants, and degree
overflow or cap violations fail before an executable program exists.

The prepared representation is pointer-free apart from its owned slices and
contains pre-resolved physical sample bindings. Evaluation and column-major
materialization perform only indexed loads and M31 arithmetic into caller-owned
scratch: no allocator, hash map, structural search, or plan lookup enters the
row loop. Row zero resolves a previous-row read cyclically. Geometry,
canonicity, and every input/output/scratch alias are rejected before the first
destination write.

The live semantic component now consumes its own authenticated
`SemanticMaskBinding` derived from the same pinned row-window plan. This retires
the independent semantic mask-width lookup while preserving one current
Tree-0 selector, exact current Tree-1 ownership, and an empty Tree-2 view. The
full binding is validated only on cold metadata/evaluator preparation paths;
the semantic row loop gained no hash, allocation, or validation branch.

## Correctness evidence

The focused corpus covers all seventeen families and checks:

- exact owner/window/column/shift construction and deterministic digests;
- degree-one shifted reads and exact direct-plus-boundary LogUp degree;
- point-exact PCS masks in current-then-previous order;
- cyclic row-zero resolution, missing-boundary and cross-row forgeries;
- semantic, witness-layout, plan, binding, owner, type, offset, boundary, and
  width corruption;
- complete allocation-failure cleanup for plan and mask construction; and
- exact compatibility and compiler-selected component metadata;
- structural interning, degree-two shifted products, constant folding inputs,
  cyclic row-zero materialization, and allocation-free hot evaluation;
- dead-expression, cross-owner, degree-cap, root, shift, plan, digest, trace
  geometry, non-canonical field, and alias mutation rejection; and
- all-seventeen semantic binding geometry plus live-consumer corruption
  rejection.

The production proof harness now also has a Tree-2-only mutation shape at the
exact post-publication, pre-commit boundary. It changes neither the honest main
trace nor the honestly derived interaction claim, so rejection cannot be
credited to a detached Tree-1 witness. The real CPU transaction rejects both a
row-zero recurrence-anchor forgery and a row-one cross-row recurrence forgery.
The bounded executor rejects the latter with one, two, and four workers and the
former with four, establishing that the planned path consumes the same
compiler-owned current/previous mask geometry. The seam is test-only; a null
mutation preserves the ordinary production path.

```text
zig build --build-file src/frontends/riscv/build.zig test-row-windows -Doptimize=Debug --summary all
Build Summary: 3/3 steps succeeded; 241/241 tests passed

zig build --build-file src/frontends/riscv/build.zig test-row-windows -Doptimize=ReleaseSafe --summary all
Build Summary: 3/3 steps succeeded; 241/241 tests passed

zig build --build-file src/frontends/riscv/build.zig test-row-windows -Doptimize=ReleaseFast --summary all
Build Summary: 3/3 steps succeeded; 241/241 tests passed

zig build --build-file src/frontends/riscv/build.zig test -Doptimize=Debug --summary all
Build Summary: 4/4 steps succeeded; 1549/1554 tests passed; 5 Sail-oracle skips

zig build test-riscv-prover \
  -Driscv-test-filter='riscv proving or verification rejects each committed witness mutation class' \
  -Doptimize=ReleaseSafe --summary all
Build Summary: 2/2 steps succeeded

zig build test-riscv-prover \
  -Driscv-test-filter='bounded Tree-2 executor rejects anchor and cross-row interaction forgeries' \
  -Doptimize=ReleaseSafe --summary all
Build Summary: 2/2 steps succeeded
```

## Production generated-composition exit

The production CPU backend already contains the narrow statement-wide
activation seam: adjacent semantic and lookup components export polynomial
DAGs from the canonical typed builder, and the bounded RISC-V composition
planner admits each exact pair only after validating component order, trace
geometry, root and entry counts, interaction placement, parameters, and
current/previous-row masks. Unsupported components remain on their ordinary
prepared evaluators. No second equation transcription was added.

The A-013 proof differential defines a reference CPU backend entirely as direct
aliases of every production CPU declaration except the two optional composition
hooks. Consequently the reference arm differs only by declining generated
composition; commitments, LDE, Merkle construction, FRI, transcript, proof
serialization, and verification are identical implementations. Both arms run
separate proof transactions over the same real all-family ELF and frozen V1
physical layout.

Debug and ReleaseFast both establish:

- exactly 17 of 17 semantic/lookup pairs admitted in one generated execution,
  with zero declines;
- the unchanged 688-column compatibility Tree 2;
- exact statement and interaction-claim equality;
- exact canonical proof-byte equality at 51,581 bytes;
- exact terminal transcript equality;
- independent verification of both separately generated proofs by the ordinary
  production engine.

The common canonical proof has SHA-256
`3a93cb594f9021f1d0625c3f31431401a668ab266d6502ade64129e0a10f783a`;
the common terminal transcript digest is
`3690d6814dbdf9ec02a85c3a59cb16d2ed87036291fed3e531c740b546c08293`.

```text
python3 scripts/typed_air_zig_lane.py --label a013-final-drift-guarded-debug -- \
  /usr/bin/time -l zig build --build-file src/integrations/riscv_cpu/build.zig \
  test-riscv-generated-composition-native-proof -Doptimize=Debug -j1 --summary all
Build Summary: 4/4 steps succeeded; 1/1 tests passed

python3 scripts/typed_air_zig_lane.py --label a013-generated-composition-releasefast-proof -- \
  /usr/bin/time -l zig build --build-file src/integrations/riscv_cpu/build.zig \
  test-riscv-generated-composition-native-proof -Doptimize=ReleaseFast -j1 --summary all
Build Summary: 4/4 steps succeeded; 1/1 tests passed
```

## Performance boundary

Plan, expression-program, and prepared-evaluator construction are cold and
allocation-explicit. Live components retain fixed-size bindings and validate
them before metadata or prepared-domain setup. No validation, dynamic string,
map, indirect semantic dispatch, or allocation was added to per-row semantic
or recurrence evaluation. The shifted-expression edit gate passes 6/6 in
4.78 seconds at 447 MiB compiler RSS; the expanded row-window authority gate
passes 11/11 in 5.49 seconds. After its mask-authority cutover, the narrow
semantic loop passes 10/10 in 11.28 seconds at 2.54 GiB compiler RSS, down from
the former broad 28.80-second/4.36-GiB loop; the post-cutover A-013 integration
gate passes 229/229. These are development-gate results, not whole-proof speed
claims.

The new proof differential retains its elapsed times only as single-process
attribution. The final drift-guarded Debug run measured 28,133.727 ms for the
reference arm and 29,508.487 ms for generated composition; a preceding Debug
run had the opposite ordering. ReleaseFast measured 2,113.513 ms and 2,117.416
ms respectively. The roughly 0.18% ReleaseFast difference is well inside a
range that cannot support a performance conclusion. Correctness and production
activation are closed; paired global proof measurements under P-004 remain
required.

## What remains

A-013's correctness and production-activation exit is complete. Typed shifted
expressions, both live opcode mask projections, and the generated semantic-plus-
interaction composition path share the compiler-owned geometry; exact proof
and transcript parity plus independent verification cover the real 17-family
statement. Only paired global performance evidence remains open. Cross-row
malicious proof coverage is no longer open for the current production lookup-
mask projection.

This advances the original document's “materialization versus masks” question
without changing the proof protocol and supplies the authenticated mask
authority required by A-014 and eventual component-composition retirement.

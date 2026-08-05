# Progress ledger

**Status date:** 2026-08-04
**Branch:** `feat/typed-air-precompiles`
**Current milestone:** M1 — validated logical IR
**Active task:** F-012 — public authoring examples
**Next ready task:** F-011 — allocation-finalization audit

## Dashboard

| Milestone | State | Evidence |
| --- | --- | --- |
| M0 — engineering dossier | complete | This directory and initial ADRs |
| M1 — validated logical IR | active | F-001 through F-010 complete; F-012 active |
| M2 — shadow compiler | queued | Requires M1 |
| M3 — compatibility lowering | queued | Requires shadow import |
| M4 — Poseidon compiler pilot | queued | Requires degree/layout passes |
| M5 — effect and witness pilot | queued | Requires typed schemas and lowering |
| M6 — guest precompile | queued | Requires Poseidon and ABI ADRs |
| M7 — parallel proving | queued | Requires working component |
| M8 — broad migration | queued | Requires vertical opcode ladder |
| M9 — recursive aggregation | deferred | Requires relation-summary design |

## Completed

- Created local branch `feat/typed-air-precompiles` from clean
  `origin/main` at `385efb9a`.
- Read and analyzed the felt-to-AIR design supplied by the user.
- Inspected Stark-V main and the later compiler/opcode development history.
- Reproduced the pre-revert Stark-V AIR compiler and prover tests.
- Mapped the proposal onto current production constraints, formal extraction,
  witness construction, Poseidon infrastructure, and component scheduler.
- Defined project charter, engineering canon, target architecture, IR,
  precompile model, soundness invariants, implementation phases, task graph,
  validation ladder, performance protocol, and initial ADRs.
- Completed F-001: the isolated `air/lang` module has an explicit logical
  schema version, is named in the test inventory, and is imported by no
  production path. The ReleaseFast RISC-V package suite passed.
- Completed F-002: distinct typed IDs, semantic integer/layout validation,
  owned stable names and sources, checked source spans, and allocation-failure
  cleanup all pass in the ReleaseFast package suite.
- Completed F-003: explicitly hashed structural expression keys, stable
  topological IDs, commutative add/multiply interning, typed operation
  rejection, primary source preservation, deterministic replay, and
  allocation-failure cleanup pass.
- Completed F-004: arena-owned constraints, hints, ordered effects, and
  function signatures pass allocation-failure cleanup and whole-program
  validation. The allocation-free structural validator verifies canonical
  ranges, topological references, interning indexes, hint-output identity,
  selector use, unique access ordinals, stable names, sources, and signatures.
  Each validator error class has a focused named negative test.
- Completed F-005: the versioned `STWAIRL\0` logical encoding writes explicit
  tags and fixed-width little-endian integers after validation. Two separately
  allocated programs remain byte-identical when name and source interning order
  is reversed; reversing semantic effect order changes the bytes. The empty
  encoding is pinned and serialization has allocation-failure coverage.
- Completed F-006: a typed registry covers all twelve production relation
  domains in transcript order. Schemas pin version, field specifications,
  roles, challenge convention, multiplicity, ordinal, padding, public-boundary,
  and coefficient-bound policies. Tests cross-check every production arity and
  reject unknown IDs, wrong roles, arities, types, and ordinals.
- Completed F-007: static calls own typed argument and output pools, preserve
  explicit inline-versus-relation-backed lowering intent, and can target only
  earlier complete functions. Two-phase declarations make dependency order
  canonical and prevent recursion through the public builder; the independent
  validator rejects missing callees, forward/self edges, malformed call
  outputs, arity drift, and type drift. Manifest format 2 records calls and
  lowering strategy. The full ReleaseFast package suite and allocation-failure
  call path pass; all 25 validator error classes have named negative tests.
- Completed F-008: hints use a closed typed recipe registry with pinned
  versions, signatures, honest algorithms, and exceptional-case policies.
  Every output carries a canonical output-first path to a matching-activation
  constraint or effect; unknown recipes, unbound outputs, malformed paths, and
  activation drift reject. Manifest format 3 records all recipe and binding
  metadata. The full ReleaseFast package suite, honest recipe vectors, and
  allocation-failure paths pass; all 28 validator errors have named negatives.
- Completed F-010: semantic digest format 1 streams a validated program into a
  domain-separated SHA-256 identity without allocating. It binds explicit
  types, stable semantic names, declared record order, hint proof metadata,
  effects, functions, and calls while excluding source spans and arena state.
  The empty identity is pinned; source/interner/allocation invariance and
  type/order/call-strategy sensitivity pass in the full ReleaseFast suite.
- Completed F-009: diagnostics render stable codes, escaped component/message
  text, exact source ranges, typed value paths, and explicit expression/gate/
  total/limit degree context. The supporting topological logical-degree pass
  covers every IR operation, treats committed hint/call outputs correctly, and
  rejects overflow. Golden rendering and partial-allocation cleanup pass.

## Immediate next actions

1. F-012 — compile minimal pure and effectful authoring examples.
2. F-011 — audit and complete partial-finalization allocation coverage.
3. A-001 — import the production symbolic polynomial DAG in shadow mode.

No production behavior should change in these tasks.

## Decisions

Accepted:

- Zig-authored canonical typed IR.
- Compatibility before optimization.
- One-proof guest precompiles before independent recursive leaves.
- Acyclic function graph in IR v0.
- Typed hint recipes with explicit proof-binding paths.
- Domain-separated semantic program digest projection.
- Stable diagnostic codes and topological logical-degree analysis.

Pending:

- guest invocation ABI;
- guest Poseidon relation schema/version;
- canonical physical-layout manifest format;
- generated witness activation policy;
- cross-proof relation summary;
- recursive verifier field/protocol.

## Risks under watch

| Risk | Current control |
| --- | --- |
| New abstraction drifts from production | Shadow import and exact compatibility lowering |
| Compiler shares wrong semantics with witness | Sail, mutation, formal, and independent runner evidence |
| Layout changes silently | Versioned deterministic manifests |
| Typed DSL becomes stringly or magical | Canon relation/effect rules and constructor validation |
| Poseidon pilot becomes a toy | Exact 445-column production component target |
| Precompile weakens base-RV32IM claim | Pending explicit guest ABI ADR |
| Parallelism hides total cost | Performance vector and critical-path telemetry |
| Recursion balances detached calls | IR v0 rejects recursive function graphs |
| Hint callback or output drifts silently | Closed versioned registry and checked proof paths |

## Baseline metrics

To be recorded before M2 implementation:

- current all-family logical node/constraint/event counts;
- current per-family maximum final degree;
- current Poseidon2 main/interaction geometry;
- current package/proof test durations;
- current RISC-V structural workload reports;
- current CPU and Metal Poseidon component timing.

## Log

### 2026-08-04 — M0 dossier established

Created the feature branch and this development directory. The architecture
decision is to complete the existing generic/symbolic design through a
canonical typed IR, rather than starting with an external language. Existing
Poseidon call collection and heterogeneous component scheduling make the
precompile path an extension of working machinery.

No production code changed. No soundness claim changed.

The repository-wide pre-commit source-conformance check is already red at the
`385efb9a` main baseline for unrelated Metal and lookup file-size entries.
The dossier passes the staged whitespace check, Zig formatting portion of the
hook, and local Markdown-link validation. This baseline failure must be
resolved separately before the hook can return green; it is not folded into
the typed-AIR scope.

### 2026-08-04 — M1 implementation started

Activated F-001. The first code change is limited to an isolated
`air/lang` module and explicit RISC-V test-inventory wiring. Production AIR,
witness, runner, prover, transcript, and formal-export paths remain unchanged.

F-001 completed with
`zig build test --build-file src/frontends/riscv/build.zig
-Doptimize=ReleaseFast -j2`. The package test-count floor observed the new
test, and the command exited successfully.

F-002 completed with the same ReleaseFast package command. Its focused tests
also run `checkAllAllocationFailures` across name/source ownership and verify
that distinct semantic IDs remain distinct Zig types.

F-003 completed with the same ReleaseFast package command. Structural hashing
uses explicit semantic fields rather than rendered text or object bytes; the
tests rebuild the graph in a second arena and require identical node keys.

F-004 completed with the same ReleaseFast package command. Whole-program
records remain isolated from production code. The validator is allocation-free
and checks all stored semantics independently of constructor success; 22
one-error corruption tests prove every public validator error is reachable and
stable. Allocation-failure enumeration now crosses hint output construction,
constraints, ordered effects, and functions.

F-005 completed with the same ReleaseFast package command. ADR-0005 fixes the
pre-production logical encoding. The serializer validates before output,
resolves names and source paths by content, preserves semantic record order,
and ignores allocator and interning-table accidents. Determinism, semantic
order sensitivity, invalid-program fail-closed behavior, and allocation
rollback each have focused tests.

F-006 completed with the same ReleaseFast package command. The isolated
registry uses enum domains and typed schema IDs instead of string dispatch. A
test-only bridge compares its stable order and arity to the production relation
entry authority; no shipped lookup or transcript behavior changed.

F-007 completed with the same ReleaseFast package command. Calls carry a typed
callee, optional lexical caller, arguments, generated output identities, source
span, and explicit inline or relation-backed strategy. Functions are declared
in dependency-topological order through a two-phase builder, so recursive and
forward edges cannot be constructed; the allocation-free validator rechecks
the complete graph and every call-output identity against raw arena state.
Manifest format 2 and logical schema 1 serialize this semantic distinction.
All 25 validator error classes have focused named rejection tests.

F-008 completed with the same ReleaseFast package command. The string recipe
surface was replaced by `HintRecipeId` and a closed registry whose entries pin
version, exact signature, deterministic algorithm, and exceptional behavior.
Hints carry activation selectors and are sealed with canonical binding lists;
each binding supplies a direct-edge value path from one output to a matching
constraint root or effect value. This keeps validation allocation-free and
source-attributable. Manifest format 3 / logical schema 2 records the complete
contract. Honest inverse-or-zero vectors, malformed bindings, missing recipes,
unbound outputs, semantic serialization, and partial allocation cleanup pass;
all 28 validator errors have named negative tests.

F-010 completed with the same ReleaseFast package command. Digest format 1
streams explicit little-endian tags and widths directly into SHA-256 under the
`stwo-zig/typed-air/semantic` domain after whole-program validation. It includes
semantic names, types, ordered constraints/effects, recipe policies and proof
paths, function signatures, calls, and lowering strategy. It excludes source
paths/spans and arena implementation state. The empty digest is a pinned vector;
separate tests prove source and interning invariance plus type, name, effect
order, and call-strategy sensitivity.

F-009 completed with the same ReleaseFast package command. The renderer pins
machine codes and escaped text while carrying component, exact source range,
typed `ValueId` path, and degree context. A new topological analysis computes
logical value and gated-constraint degree with checked arithmetic; it labels
hint/call outputs as committed degree-one values and explicitly does not claim
the later relation/mask/interaction degree. Golden output, unknown-value
fallback, overflow rejection, and partial allocation cleanup pass.

## Update protocol

Every progress update changes:

- status date;
- current milestone and active task;
- dashboard state;
- completed evidence;
- next three actions;
- new risks or decisions; and
- one dated log entry.

At most one task is marked active. A task becomes done only when its acceptance
evidence is named.

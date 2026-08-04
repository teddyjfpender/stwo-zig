# Progress ledger

**Status date:** 2026-08-04
**Branch:** `feat/typed-air-precompiles`
**Current milestone:** M1 — validated logical IR
**Active task:** F-004 — constraints, hints, effects, functions, validation
**Next ready task:** F-005 — canonical logical manifest serialization

## Dashboard

| Milestone | State | Evidence |
| --- | --- | --- |
| M0 — engineering dossier | complete | This directory and initial ADRs |
| M1 — validated logical IR | ready | F-001 is dependency-free |
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

## Immediate next actions

1. Complete F-004 with one named negative test for every validator error class.
2. F-005 — add canonical logical manifest serialization.
3. A-001 — import the current production symbolic polynomial DAG.

No production behavior should change in these tasks.

## Decisions

Accepted:

- Zig-authored canonical typed IR.
- Compatibility before optimization.
- One-proof guest precompiles before independent recursive leaves.
- Acyclic function graph in IR v0.

Pending:

- guest invocation ABI;
- guest Poseidon relation schema/version;
- canonical serialized manifest format;
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

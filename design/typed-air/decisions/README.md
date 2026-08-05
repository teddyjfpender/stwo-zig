# Architecture decision records

**Status:** active index
**Last updated:** 2026-08-05

ADRs record decisions that change the project's trusted boundary, protocol
shape, authoring model, or delivery order.

## States

- **proposed** — ready for review; implementation may explore but not depend on
  production acceptance.
- **accepted** — governs implementation until superseded.
- **superseded** — replaced by a newer ADR that links back.
- **rejected** — retained to prevent repeating settled discussion.

## Index

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-zig-authored-canonical-ir.md) | Zig-authored canonical typed IR | accepted |
| [0002](0002-compatibility-before-optimization.md) | Compatibility lowering before optimization | accepted |
| [0003](0003-one-proof-precompiles-first.md) | One-proof precompiles before separate proof recursion | accepted |
| [0004](0004-acyclic-functions-in-v0.md) | Acyclic function graph in IR v0 | accepted |
| [0005](0005-canonical-logical-manifest.md) | Canonical logical manifest encoding | accepted |
| [0006](0006-typed-hint-recipes-and-proof-paths.md) | Typed hint recipes and explicit proof paths | accepted |
| [0007](0007-semantic-program-digest.md) | Domain-separated semantic program digest | accepted |
| [0008](0008-stable-structured-diagnostics.md) | Stable structured diagnostics and logical degree context | accepted |
| [0009](0009-lossless-production-shadow-import.md) | Lossless production symbolic shadow import | accepted |
| [0010](0010-ordered-production-program-shadow-import.md) | Ordered production program shadow import | accepted |
| [0011](0011-complete-protocol-degree-and-pinned-report.md) | Complete protocol degree and pinned production report | accepted |
| [0012](0012-compat-v1-local-physical-mapping.md) | `compat-v1` local physical mapping | accepted |
| [0013](0013-fallible-normalized-direct-lowering.md) | Fallible normalized direct-constraint lowering | accepted |
| [0014](0014-role-normalized-ordered-lookup-lowering.md) | Role-normalized ordered lookup lowering | accepted |
| [0015](0015-validated-canonical-runtime-export.md) | Validated canonical runtime export | accepted |
| [0016](0016-source-bound-air-ir-v2-compatibility.md) | Source-bound AIR IR v2 compatibility | accepted |

## Pending ADRs

- Guest precompile invocation ABI and relationship to the RV32IM profile.
- Guest Poseidon relation domain/version and duplicate-call policy.
- Canonical physical layout manifest serialization format.
- Production activation criteria for generated witness writers.
- Cross-proof relation-summary construction.
- Recursive verifier field and proof protocol.

## Template

```markdown
# ADR-NNNN — title

**Status:** proposed
**Date:** YYYY-MM-DD

## Context

What forces a decision? Which authority and constraints apply?

## Decision

State one testable decision.

## Consequences

List benefits, costs, risks, and migration effects.

## Rejected alternatives

Record serious alternatives and why they are not selected now.

## Revisit when

Name evidence or conditions that justify reopening the decision.
```

# Architecture decision records

**Status:** active index
**Last updated:** 2026-08-10

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
| [0017](0017-sectioned-compatibility-manifests.md) | Sectioned `compat-v1` family manifests | accepted |
| [0018](0018-degree-bounded-materialization-and-compatibility-order.md) | Degree-bounded materialization and Poseidon compatibility order | accepted |
| [0019](0019-authenticated-witness-and-relation-plans.md) | Authenticated witness and relation execution plans | accepted |
| [0020](0020-cost-frontier-materialization-proposals.md) | Cost-frontier materialization proposals | proposed |
| [0021](0021-backend-neutral-poseidon-program-identity.md) | Backend-neutral Poseidon program identity | accepted |
| [0022](0022-authenticated-poseidon-layout-benchmark.md) | Authenticated Poseidon layout benchmark boundary | proposed |
| [0023](0023-relation-bound-typed-effects.md) | Relation-bound typed machine effects | accepted |
| [0024](0024-guest-poseidon2-custom0-abi.md) | Guest Poseidon2 CUSTOM-0 ABI | accepted |
| [0025](0025-guest-poseidon2-relation-and-subclocks.md) | Guest Poseidon2 relation and subclocks | accepted |
| [0026](0026-typed-register-access-groups.md) | Typed register access groups and strict subclocks | accepted |
| [0027](0027-bounded-component-task-graph.md) | Bounded component task graph | accepted |
| [0028](0028-memory-access-groups-and-load-phase-plan.md) | Memory access groups and load/store phase plans | accepted |
| [0029](0029-guest-component-statement-and-artifact-identity.md) | Guest Poseidon2 component, statement, and artifact identity | accepted |
| [0030](0030-session-bound-cross-proof-relation-summaries.md) | Session-bound cross-proof relation summaries | proposed |
| [0031](0031-closed-sequential-retirement-and-typed-lui.md) | Closed sequential retirement and typed LUI | accepted |

## Pending ADRs

- Production activation criteria for generated witness writers.
- Review and acceptance of the proposed cross-proof relation-summary design.
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

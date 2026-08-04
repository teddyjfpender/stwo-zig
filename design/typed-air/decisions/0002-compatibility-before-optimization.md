# ADR-0002 — Compatibility before optimization

**Status:** accepted
**Date:** 2026-08-04

## Context

Automatic materialization and CSE can change column width, constraint order,
interaction geometry, protocol artifacts, backend programs, and formal
evidence. Combining those changes with a new authoring system would make
failures difficult to attribute.

The current RISC-V path has strong proof, mutation, and formal evidence tied to
its exact production programs.

## Decision

Every existing component first lowers through a named `compat-v1` policy that
reproduces current physical geometry and semantic order exactly.

Optimized layouts are separate named proposals with their own manifests,
evidence, benchmarks, and protocol decision. They never replace compatibility
layouts implicitly.

## Consequences

- Migration can be reviewed as an observationally invisible refactor.
- Existing formal and adversarial evidence remains useful.
- Some temporary duplication is accepted during shadow comparison.
- Early code will not demonstrate the smallest possible AIR.
- Optimization work begins from measured, attributable baselines.

## Rejected alternatives

- **Optimize while migrating:** rejected because semantic, compiler, and layout
  errors would be confounded.
- **Golden-output-only comparison:** rejected because matching a few traces does
  not establish constraint or relation identity.

## Revisit when

This decision does not prevent optimized policies. It is complete for a
component after compatibility evidence is accepted; a later ADR may then
activate a new versioned layout.

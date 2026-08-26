# ADR-0006 — Typed hint recipes and explicit proof paths

**Status:** accepted
**Date:** 2026-08-04

## Context

A hint computes convenient witness values, but a malicious prover chooses those
values. Dispatching an honest algorithm by an arbitrary string does not pin its
signature, exceptional behavior, or artifact identity. Merely observing that a
hint output occurs somewhere in the program also does not identify the
constraint or relation expected to bind it.

The completed-program validator is allocation-free. Inferring arbitrary DAG
reachability during validation would otherwise require temporary storage,
unbounded recursion, or repeated graph searches with poor failure attribution.

## Decision

IR v0 uses a closed registry keyed by `HintRecipeId`. Each recipe pins:

- stable kind and numeric ID;
- semantic version and descriptive name;
- exact ordered input and output types;
- deterministic honest algorithm; and
- explicit exceptional-case policy.

Recipe evaluation is separate from proof validation. Correct execution of the
honest algorithm never substitutes for AIR constraints or relation effects.

A hint has an optional selector activation. Every output declares at least one
binding to a `hint_binding` constraint or ordered effect with exactly the same
gate or liveness value. A binding includes an output-first value path. Each
successive value must directly consume the previous value, and the path must
end at the declared constraint root or effect value. This certificate makes
dataflow validation allocation-free and gives diagnostics a stable path.

Hints are sealed in declaration order. Within a hint, bindings are ordered by
output index, target kind, and target ID. Missing recipes, missing output
bindings, malformed paths, activation drift, and noncanonical binding order are
hard validation errors.

An effect binding currently records intended proof-enforced dataflow. Its full
relation-schema soundness becomes available when typed effects are connected to
the F-006 schema registry; until then this package remains isolated from the
production proving path.

## Consequences

- String dispatch and caller-selected output types leave the authoring API.
- Exceptional behavior is versioned next to the honest implementation.
- Every output has reviewable proof metadata and a future mutation target.
- Validation remains deterministic and allocation-free without recursive DAG
  traversal.
- Gated hints cannot cite an unconditional or differently gated target.
- Adding or changing a recipe is a reviewed registry and manifest-version
  change, not an ad hoc call-site edit.
- Manifest format 3 / logical schema 2 records recipe ID/version, activation,
  binding targets, and complete value paths.

## Rejected alternatives

- **Recipe names as lookup keys:** rejected because spelling does not pin a
  signature, version, algorithm, or exceptional policy.
- **Trust the honest evaluator:** rejected because the prover controls witness
  values.
- **Infer bindings from any downstream occurrence:** rejected because occurrence
  does not identify a proof-enforced target or compatible activation.
- **Recursive reachability validation:** rejected because adversarially deep
  programs should not consume the host call stack.
- **Store only target IDs:** rejected because a checked path improves both
  allocation behavior and precise diagnostics.

## Revisit when

Typed effect schemas are integrated, conditional exceptional cases need a
richer activation algebra, or a measured compiler pass can generate canonical
paths while preserving the same validated artifact.

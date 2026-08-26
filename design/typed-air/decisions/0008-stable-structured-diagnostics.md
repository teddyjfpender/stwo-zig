# ADR-0008 — Stable structured diagnostics and logical degree context

**Status:** accepted
**Date:** 2026-08-04

## Context

The compiler must explain failures through authored values rather than lowered
temporary columns. Generic Zig formatting and free-form error strings do not
provide stable machine codes, source attribution, proof-binding paths, or
degree context. Diagnostic output also needs to remain safe when names or paths
contain quotes, control bytes, or newlines.

Degree messages require a shared calculation. Reporting only a root expression
degree hides selector/gate cost, while claiming a final protocol degree before
row masks, lookups, and interaction recurrences exist would be misleading.

## Decision

Diagnostics are structured values with:

- severity and stable `AIR0001`-style machine code;
- escaped component and message text;
- source path plus line, column, and byte-offset range;
- an ordered path of typed `ValueId` entries;
- optional expected/actual semantic types; and
- explicit expression, gate, total, and limit degree context.

The renderer uses exhaustive switches for codes and semantic types. It renders
unavailable values or degree analysis deterministically rather than dereferencing
invalid state. Its text format is pinned by golden tests and supports both a
generic writer and an owned allocation helper.

The initial degree pass analyzes the validated logical DAG in topological order:

- constants have degree zero;
- inputs, hint outputs, and call outputs have degree one at their uses;
- addition, subtraction, and negation preserve the maximum operand degree;
- multiplication adds operand degrees with checked overflow;
- selection adds selector degree to the maximum branch degree; and
- a constraint total adds its gate degree to its expression degree.

This is deliberately named logical degree. Final protocol degree additionally
includes row/boundary masks, materialization equalities, relation expressions,
interaction recurrences, and batching. Lowering must report that separate
quantity before backend admission.

Diagnostics and source spans are not part of the semantic program digest.

## Consequences

- Tests, tools, and users can match stable codes without parsing prose.
- A hint binding path can be rendered directly without re-walking the DAG.
- Source and type failures remain useful even when a referenced value is
  unavailable.
- Degree overflow rejects instead of wrapping into a falsely cheap program.
- The same logical-degree analysis becomes a foundation for A-003, but does not
  complete final protocol degree analysis by itself.
- Human-readable diagnostics may evolve only with deliberate golden updates;
  machine codes remain the compatibility anchor.

## Rejected alternatives

- **Only return Zig error names:** rejected because they lack component, source,
  path, type, and degree evidence.
- **Reflection-based type rendering:** rejected because declaration renames and
  native formatting are not a stable user interface.
- **Recursive degree calculation per diagnostic:** rejected because deep DAGs
  risk host-stack exhaustion and repeated work.
- **Call logical degree the backend degree:** rejected because masks and
  interaction constraints can raise the actual bound.
- **Include diagnostics in semantic identity:** rejected because source movement
  and prose are not AIR meaning.

## Revisit when

The shadow importer supplies component/source maps, final lowering computes
protocol degree, or machine-readable JSON/SARIF output has a concrete consumer.

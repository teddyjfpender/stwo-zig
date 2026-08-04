# ADR-0004 — Acyclic functions in IR v0

**Status:** accepted
**Date:** 2026-08-04

## Context

Function activation through multiset relations proves that caller and callee
tuples balance. For recursive functions, balance alone does not prove that
activations are reachable from a public root or form the least terminating
execution. Detached cycles can cancel.

The current state-chain proof needs explicit public boundaries, monotone clocks,
and trace-geometry bounds to exclude analogous cycles.

## Decision

IR v0 rejects cycles in the static function-call graph. Functions may be
inlined or lowered to nonrecursive component relations.

Dynamic recursion is introduced only with a reviewed, mechanically checked
well-foundedness construction such as a decreasing rank, bounded fuel, or an
equivalent reachability theorem.

This restriction is separate from recursive proof aggregation. The latter
verifies proofs recursively but need not add recursive calls to the authored
AIR program.

## Consequences

- Function relations have a simpler soundness story.
- Poseidon, opcode families, and initial precompiles are unaffected.
- General recursive DSL programs are deferred.
- Recursive proof aggregation can proceed later under its own protocol.

## Rejected alternatives

- **Assume purity implies safe recursion:** rejected; purity does not establish
  reachability or termination.
- **Rely on relation cancellation:** rejected because detached cycles balance.

## Revisit when

A concrete use case requires dynamic recursive activation and comes with a
well-foundedness design that integrates with field bounds, padding, and public
statement closure.

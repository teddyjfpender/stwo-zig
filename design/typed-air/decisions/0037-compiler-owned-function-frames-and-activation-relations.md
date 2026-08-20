# ADR-0037 — Compiler-owned function frames and activation relations

**Status:** accepted
**Date:** 2026-08-12

## Context

ADR-0004 gave IR v0 a typed, dependency-topological function graph and recorded
whether each call should be inlined or relation-backed. That representation was
necessary but insufficient for the felt-to-AIR design. A global interned DAG
does not itself prove that a function reads only its arguments, and a call
strategy tag does not create the LogUp terms that connect caller return cells
to a callee table.

The original proposal requires the Cairo frame rule, one write per local,
function activation through `(args..., rets...)`, and public entry claims. It
also relies on tuple purity: without a call-site nonce, equal arguments may
collapse in the multiset only if the function's returns are deterministic.

## Decision

Function table lowering is preceded by a versioned compiler pass over the
validated logical program.

For each function, the pass:

1. walks the transitive closure of outputs and owned calls;
2. rejects every input leaf not present in the declared argument list;
3. emits every reachable non-input/non-constant value exactly once, in global
   topological order, as the frame's local-write list;
4. assigns each reachable hint invocation to exactly one frame; and
5. propagates deterministic-return status through the acyclic call graph.

A relation-backed target must have a non-empty tuple of at most 64 values, all
with an injective single-field representation, and its return closure must be
deterministic. No automatic limb expansion or padding is admitted in format 1.

Every function receives a distinct activation-relation identity in declaration
order. Its digest binds the current semantic program identity, stable function
name, and exact argument and return types. These function-local relations are
not silently inserted into, or padded to fit, the fixed zkVM/recursion relation
registry.

The plan orders one callee-consume event for each required relation, followed by
one emission per relation-backed call in call order. An internal call uses the
caller enabler; a root call is a verifier/public emission with explicit public
multiplicity. Every tuple is arguments followed by caller-owned return cells.

Plan construction is cold and fallible. The returned plan is owned and
authenticated; its structural validator is allocation-free. A strong boundary
check regenerates the complete plan from the logical arena. Constructing the
plan alone does not change the proof protocol: prover and verifier activation
requires a separately reviewed adapter consuming this exact identity and event
order.

IR v0 remains acyclic under ADR-0004. Self-recursive function rows require a new
logical-format decision and cannot be smuggled in through an unchecked event.

## Consequences

- Cairo-style visibility and write-once frame layout are mechanically checked.
- `relation_backed` now has one canonical proof-facing meaning, ready for live
  LogUp and public-claim lowering.
- An unkeyed activation tuple cannot accidentally expose a prover-chosen return
  as if it were a mathematical function.
- Heterogeneous function arities retain exact ABIs and independent challenges.
- Inline substitution, complete function-body ownership, live challenge draws,
  and proof mutations remain explicit follow-on work rather than implicit
  properties of the plan.
- The arity cap and acyclic restriction are format-version boundaries.

## Rejected alternatives

### Treat global DAG reachability as frame ownership

Rejected because a function could transitively read an undeclared global input
and no compiler boundary would report it.

### Encode all functions in one padded fixed relation

Rejected because padding widens LogUp denominators, obscures type/arity errors,
and lets unrelated function tuples collide under one challenge domain.

### Add a call-site nonce to every tuple

Rejected for pure functions because it prevents natural multiplicity collapse
and adds columns and relation work. Determinism is checked instead. A genuinely
relational component must declare a different keyed ABI explicitly.

### Treat hint recipes as proof of deterministic returns

Rejected because a recipe is witness construction, not a constraint. A hinted
return is rejected until the proof graph itself establishes the required
functional relation.

### Activate the protocol as part of plan construction

Rejected because challenge order, claims, transcript identity, proof size, and
verifier behavior are protocol changes requiring independent proof gates.

## Revisit when

- a real component needs more than 64 scalar activation fields;
- a typed limb/array ABI expansion is specified;
- recursive self-emission is admitted in a new logical format; or
- a non-functional relation needs an explicit key or activation identity.

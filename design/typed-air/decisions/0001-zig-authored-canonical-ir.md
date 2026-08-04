# ADR-0001 — Zig-authored canonical typed IR

**Status:** accepted
**Date:** 2026-08-04

## Context

The project needs a typed semantic source that can be interpreted as
constraints, witness synthesis, relations, formal IR, and runtime programs.
Haskell would support an expressive typed EDSL and optimizer, but the
repository already has generic Zig semantics, a symbolic DAG, formal export,
and backend-neutral runtime polynomial programs.

Making a new language the initial authority would add a compiler/toolchain
boundary before the canonical IR and its invariants are stable.

## Decision

Use Zig as the production authoring language. Zig builder calls construct an
explicit, owned, canonical typed IR. All production lowerers consume that IR or
the accepted compatibility representation derived from it.

The IR must have a canonical serialized form so experimental tools in Haskell,
Lean, Rust, or another language can consume and propose transformations.
External transformations are independently validated by Zig before use.

## Consequences

- Existing semantic code and expertise are reusable.
- The production build adds no new language toolchain.
- Ownership and hot-path data layout remain explicit.
- Zig's type system is less expressive than Haskell GADTs, so some invariants
  require validated constructors.
- Optimizer experimentation remains possible without making the experiment the
  source of truth.

## Rejected alternatives

- **Haskell-first compiler:** rejected for the first delivery because it expands
  the trusted build and source-binding problem too early.
- **Textual DSL parser first:** rejected because syntax is not the missing
  architectural layer.
- **Continue only tagless-final evaluation:** insufficient for deterministic
  global analysis, materialization, manifests, and effect validation.

## Revisit when

Reconsider an external optimizer after the logical and physical IR schemas are
stable, round-trip validators exist, and a concrete optimization is difficult
to express or test in Zig.

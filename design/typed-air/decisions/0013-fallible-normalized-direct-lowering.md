# ADR-0013 — Fallible normalized direct-constraint lowering

**Status:** accepted
**Date:** 2026-08-05

## Context

The production symbolic extractor represents direct AIR constraints with six
node operations: column, constant, addition, subtraction, multiplication, and
negation. Its builder is intentionally process-global and treats allocation
failure as fatal, which is useful for extraction but unsuitable as a compiler
boundary. The typed IR also has an explicit selection operation that the target
vocabulary does not expose.

Compatibility requires more than matching evaluations on a few inputs. The
lowered program must preserve the physical column prefix, ordered roots, and
reachable expression structure while ignoring only representation accidents:
dead source nodes and operand order for commutative operations.

## Decision

`air/lang/lower_constraint.zig` implements a fallible, owned `compat-v1`
direct-constraint lowerer with the following contract:

- validate the imported production shadow and its physical layout first;
- emit every physical main column in committed order, followed by the active
  selector, as the exact target column prefix;
- traverse only the dependency closure of ordered direct roots;
- preserve canonical M31 constants, subtraction, and negation exactly;
- lower `select(s, t, f)` deterministically to `f + s * (t - f)`;
- sort operands of addition and multiplication by node ID;
- hash-cons every target node through a fallible allocator; and
- preserve direct-root count and declaration order.

The owned result has an allocation-free validator. It rejects malformed column
prefixes, noncanonical M31 constants, forward or out-of-range operands,
noncanonical commutative nodes, duplicate nodes, empty root sets, and invalid
roots. Replay validates before indexing any caller-provided buffer.

The production comparison uses an independent test normalizer with linear
interning rather than the lowerer's hash table. Across all 17 opcode families,
the resulting node slices and all 545 ordered roots are exactly equal. A second
layer replays four deterministic randomized assignments per family and compares
every production and lowered root over M31. Repeated LUI lowering is identical;
corruption and malformed-buffer cases reject; induced allocation failure across
the DIV family frees every partial allocation.

## Consequences

- A-007 is complete with stronger all-family structural evidence than its LUI
  acceptance floor.
- A-008 can lower ordered relation effects without reopening direct-expression
  semantics.
- A-009 can adapt this owned normalized program to the backend-neutral runtime
  type; production's incidental dead nodes or commutative operand order are not
  protocol identity.
- Lowering remains a shadow path. No production AIR, witness, transcript,
  prover, verifier, runtime exporter, or formal artifact consumes it yet.
- The pass does not change trace width, constraint degree, or proving
  complexity. It re-expresses the shipped direct roots through a checked
  compiler boundary.

## Rejected alternatives

- **Build through the production global symbolic arena:** rejected because a
  reusable compiler pass must expose allocation failure, own its result, and
  avoid process-global state.
- **Accept random replay as sufficient equivalence:** rejected because samples
  cannot establish structural compatibility or detect every ordering drift.
- **Compare raw production nodes byte for byte:** rejected because dead nodes
  and commutative operand orientation are construction artifacts rather than
  polynomial semantics.
- **Perform general algebraic simplification:** rejected because reassociation,
  constant folding, or distributive rewriting would make compatibility harder
  to audit and could change degree or evaluation scheduling.
- **Resolve inputs by semantic name:** rejected because ADR-0012 establishes
  that logical and committed physical names are distinct namespaces.

## Revisit when

An optimized layout intentionally materializes expressions, the lowered node
vocabulary changes, or a production consumer is ready to replace the current
runtime export after the complete M3 proof and formal gates are green.

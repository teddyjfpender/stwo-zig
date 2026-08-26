# ADR-0015 — Validated canonical runtime export

**Status:** accepted
**Date:** 2026-08-05

## Context

The prover exposes backend-neutral owned polynomial programs for direct M31
constraints and lookup tuple expressions. A compatibility compiler needs to
produce those public capability types without rebuilding algebra, trusting enum
coincidence, propagating undefined tuple tails, or bypassing validation.

Raw production node order is a construction schedule, not a semantic protocol
identity. In particular, complete and section-only builders can first encounter
the same reachable constant at different times. ADR-0013 and ADR-0014 therefore
define canonical topological identity: physical column prefix, dependency
height, stable structural key, and ordered roots/events.

## Decision

`air/lang/lower_runtime.zig` is a deliberately mechanical exporter:

- `buildDirect` and `buildLookups` run the accepted compatibility lowerers;
- `exportDirect` and `exportLookups` accept already-lowered owners for reuse;
- every source owner is structurally revalidated before output allocation;
- polynomial nodes are copied field for field with compile-time checks that all
  six operation names and integer tags match the prover ABI;
- direct root and column order are copied exactly;
- lookup entries retain signed numerator, tuple root order, arity, main-column
  count, and batch size;
- unused lookup tuple slots receive a deterministic invalid-node sentinel; and
- the prover-owned result is validated before it is returned.

The exporter performs no simplification, sign processing, root reordering,
layout selection, degree inference, or backend dispatch. Those decisions belong
to validated earlier passes.

For every one of the 17 opcode families, direct tests compare exact canonical
nodes, all ordered roots, and column counts against an independent normalization
of the shipped runtime exporter. Lookup tests compare exact canonical nodes,
every flattened entry root and arity, column and batch counts, parameter counts,
and deterministic tails. Malformed lowered owners reject before copying.
Induced allocation failure across both DIV build paths frees every partial
lowered and runtime owner.

## Consequences

- A-009 is complete for both direct and lookup runtime capability shapes.
- A-010 can serialize the same canonical nodes and ordered semantic events into
  AIR IR v2 without consulting production builders again.
- A future production activation can replace exporter construction, but only
  after proof, independent-verification, formal, and performance gates. A
  canonical node schedule may have a different constant-time evaluation order
  from the current incidental schedule even though roots are identical.
- Runtime tuple tails become deterministic development artifacts; consumers
  must continue to read only the declared arity.
- No production capability callback imports this module yet.

## Rejected alternatives

- **Return the lowerer's slices by casting:** rejected because ownership, node
  types, and allocator contracts differ.
- **Map operation tags without compile-time ABI checks:** rejected because enum
  reorder would silently reinterpret polynomials.
- **Leave tuple tails undefined:** rejected because owned compiler artifacts
  should remain deterministic even where the runtime contract ignores storage.
- **Re-run the production builder during export:** rejected because it would
  bypass the accepted typed compatibility pipeline and restore two authorities.
- **Treat raw source node IDs as identity:** rejected because they retain dead
  construction history unrelated to the reachable program.

## Revisit when

The backend polynomial ABI changes, canonical programs gain a stable serialized
digest, or a production capability is proposed for activation with benchmark
and proof receipts.

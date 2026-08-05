# ADR-0012 — `compat-v1` local physical mapping

**Status:** accepted
**Date:** 2026-08-05

## Context

Compatibility lowering needs a checked answer to a deceptively simple
question: which logical value occupies each production column? The imported
symbolic program preserves input order and semantic field-path names, while the
committed witness schema separately fixes physical names and the prover assigns
global tree offsets when it assembles a statement.

Those namespaces are not identical. The first exact differential found, for
example, a semantic input named `clock` mapped to a committed column named
`clk`. Treating a logical name as a physical name would either reject a correct
program or silently rename protocol evidence. Inferring mapping by name is
therefore invalid even when most names happen to agree.

The lookup layer adds another layout surface: each declaration-order batch owns
one QM31 cumulative column committed as four M31 coordinates and sampled at the
current and previous row. The active-row and first-row selectors live in the
preprocessed tree rather than the main tree.

## Decision

`air/lang/compat_layout.zig` defines policy
`stwo.riscv.opcode.compat-v1`, version 1, as an exact *local* mapping. Its tree
IDs match the production backend capability indices:

| Tree | ID | Local contents |
| --- | ---: | --- |
| preprocessed | 0 | `is_first`, then `is_active` |
| main | 1 | Sail-authoritative witness columns in committed order |
| interaction | 2 | batch-major QM31 cumulative coordinates |

The mapping obeys these rules:

- `is_first` is an external interaction input with no logical `ValueId` yet;
- `is_active` maps exactly to the imported production selector;
- main column `i` maps imported input `i` to physical witness column `i`;
- every main descriptor retains both its logical semantic name and its physical
  committed name; neither is synthesized from the other;
- physical names come from `witness_layout.columnNames`, whose reflected field
  order is already bound by the Sail-authoritative witness-layout digest;
- interaction columns are ordered by batch and then
  `{ c0.a, c0.b, c1.a, c1.b }`, matching `QM31.toM31Array`;
- every interaction descriptor records its first lookup, one- or two-entry
  occupancy, and current/previous row window; and
- statement-specific preprocessed, main, and interaction offsets are applied
  only through checked `ColumnRef.resolve` arithmetic.

The layout uses fixed-capacity canonical storage. Unused slots carry validated
sentinels, so copying the value cannot expose uninitialized bytes and corrupted
hidden state is rejected. Logical names and IDs remain borrowed from the
imported program; physical names are static authority data.

For all 17 families, tests compare every physical name and index directly to
the reflected witness schema, reproduce the existing
`2163899f…9d88f4f5` layout receipt from the mapped descriptors, validate all
620 interaction-coordinate positions, and resolve arbitrary local offsets into
the exact semantic and lookup backend capability geometry. Corruption and
offset-overflow tests fail closed.

## Consequences

- A-006 supplies A-007 with a reverse `ValueId`-to-tree reference mapping for
  direct constraint lowering.
- Logical naming can improve independently without changing physical protocol
  identity, provided the explicit mapping remains accepted.
- Physical renames, reorderings, width changes, tree changes, QM31 coordinate
  changes, or batch changes are now visible compatibility failures.
- Global offsets are not embedded in a reusable family layout; they remain a
  statement-composition concern and are resolved with checked arithmetic.
- `compat-v1` introduces no materialization and allocates no column. It
  describes the shipped layout only.
- No production AIR, witness, transcript, prover, verifier, runtime exporter,
  or formal artifact consumes the new mapping yet.

## Rejected alternatives

- **Use imported logical names as physical names:** rejected by the observed
  `clock`/`clk` distinction and because names serve different authorities.
- **Join logical and physical columns by name:** rejected because an explicit
  positional adapter already defines semantics and name coincidence is not a
  proof of layout identity.
- **Store statement-global offsets in each family layout:** rejected because
  offsets depend on the ordered component set, while the family mapping is
  reusable and local.
- **Describe only main columns:** rejected because preprocessed selector
  placement and interaction coordinate order are part of the backend protocol.
- **Allocate dynamic descriptor slices:** rejected because current maxima are
  fixed protocol data and allocation adds failure modes without flexibility
  useful to compatibility mode.
- **Generate new physical names for interaction columns:** rejected because
  batch and coordinate are the canonical structured identity; a display string
  would add another naming convention without an existing production authority.

## Revisit when

A named optimized layout changes width or materialization, the secure extension
representation changes, statement layout receives a canonical global manifest,
or a generated production consumer is ready to replace current offset walking.

---
title: Lifted queried-value consistency admission
author: Teddy Pender
created_utc: 2026-09-21T21:20:17Z
---

# Lifted queried-value consistency admission

Task: validate column-major opening shapes and require equal values whenever
queries project to the same native lifted column row. This includes duplicate
raw positions and different positions aliasing a shorter column under the
parity-preserving lift. Reuse the checked geometry plan's columnIndex.

Exact canonical match: keyed consistency checking. One AutoHashMap maps projected
row to M31 value, cleared with retained capacity between columns. Expected O(c*n)
work and O(n) scratch, avoiding a quadratic pairwise scan. Values remain public
auxiliary opening coordinates; this check does not replace root authentication,
DEEP equations or private source wiring.

Validate against real native mixed-size decommitments. Mutate a repeated short-
column row, truncate a column and supply an invalid position. Cover allocation
failures and keep the existing complete typed path proof passing.

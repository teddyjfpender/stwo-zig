---
title: Canonical hash evaluator with committed-column sink
author: Teddy Pender
created_utc: 2026-09-22T06:33:52Z
---

# Canonical hash witness directly into committed columns

Task: avoid materializing full G/XOR/boundary row arrays before projection. Map
canonical logical row index to the existing committedRow permutation and write each
new logical row's coordinates immediately into caller-owned columns.

Transfer: factor the current canonical hash evaluator over a comptime sink. Row
and column sinks share that evaluator and canonical row constructors; trusted
boundary generation shares the same boundary emitter. Column destination supplies
log size and logical starting offset, validates every column length and range before
writes, and preserves caller-owned padding/adjacent ranges. No sink admits a graph
or changes arithmetic. Errors after shape validation can leave partial output.

Differential test compares all live coordinates in committed layout against owned
row generation, including nonzero offsets and sentinel padding. Standard digest
vectors, existing fixed parity and closure tests remain. Direct columns alone do
not replace interaction row access; production integration must preserve that path
or provide a tested row view. No timing or full migration claim at this stage.

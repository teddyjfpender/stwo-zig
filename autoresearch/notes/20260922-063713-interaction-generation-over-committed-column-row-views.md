---
title: Interaction generation over committed-column row views
author: Teddy Pender
created_utc: 2026-09-22T06:37:13Z
---

# Interaction generation from committed column views

Task: consume direct witness-column output without reconstructing full row arrays.
Transfer: a bounded read-only ColumnRows view assembles one Row value at a time
using the inverse access implied by committedRow(first+index,log). Reuse the existing
interaction-generation kernel and explicit typed padding. Validate column sizes,
source range and scratch/output aliasing before writes. Existing row APIs preserve
behavior. This is a layout accessor, not a new interaction algorithm.

Differential gate: actual direct-hash G/XOR/boundary column output versus owned
logical rows, including nonzero offsets; compare every generated interaction column
and claimed sum. Existing failure-atomic/workspace tests remain relevant. No producer
switch or speed claim until full integration and measurements.

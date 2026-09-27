---
title: Canonical interactions consume committed-column row views
author: Teddy Pender
created_utc: 2026-09-22T06:39:05Z
---

# Interaction generation reads committed columns directly

The canonical interaction Runtime now exposes ColumnRows and
 generatePreparedFromColumns. The read-only view reconstructs one stack Row at a
time using committedRow(first + index, log_size); no full logical-row array is
allocated. It uses the same generation kernel, bulk inversion, prefix columns and
typed virtual padding as existing row APIs. Existing APIs preserve their behavior.
Column lengths/ranges and overlap with workspace/output are checked before mutation.

## Qualification

ReleaseSafe test-blake3-hash and test-recursive-fused-pcs-opening pass 15/15 tests,
8/8 steps. Hash tests: 594 ms / 17 MiB. Framework/PCS tests: 731 ms / 137 MiB.
Actual direct-hash G/XOR/boundary columns, including nonzero offsets for empty,
multi-block and multi-chunk inputs, produce exactly the same interaction columns
and claimed sums as owned rows with typed padding. Invalid source ranges reject.
Existing source-exact, allocation, failure-atomicity, alias, padding, PCS fusion and
admission tests pass. These include existing row API memory contracts; exhaustive
column-source-specific adversarial alias tests are not claimed.

No parent producer has switched to column-backed witnesses yet. This removes an
API obstacle to direct committed-column generation; adapter integration, verified
full proofs and measured memory/time comparisons remain. No performance or production
qualification claim follows from the differential test alone. Main/fixed columns
and parameter values all participate in the logical view and must be supplied from
the same admitted source when used by native parent preparation.

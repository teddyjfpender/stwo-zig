# Row-oriented OM31 DEEP finalization

The compact-coefficient quotient owner already holds aggregate numerator
evaluations as eight M31 planes and denominator inverses in batch-major order.
The earlier implementation gathered each row into OM31 values, then transposed
those values again to vectorize across batches. The new kernel instead
vectorizes independent contiguous rows. It reads the existing planes and
inverse scratch directly, without new allocations or retained evaluations.

The arithmetic authority remains the core quadratic DEEP law:
`sum_b (numerator_b - a_b * y - b_b) * inverse_b`.
Empty batches retain their linear terms. Smaller-height groups use exactly
`((position >> shift) << 1) + (position & 1)` from the original group lookup.
All eight secure coordinates and arbitrary chunk starts/tails are supported.
Denominator preparation still rejects poles before finalization, including
zero-weight terms. Input shape/order/checked bounds are validated before
output stores. Output planes must be disjoint from each other and all inputs;
the quotient owner already enforces this ownership contract.

Independent core-oracle tests cover mixed heights, multiple groups per batch,
empty batches, odd/nonzero starts, vector tails and malformed bounds. Safe and
Fast coefficient-storage gates pass. An independent source review found no
blocking law, lifetime or parallel-ownership issue; its checked-arithmetic
hardening was applied before the final benchmark.

Six alternating real 4,194,303-step prefix runs preserve all four durable
artifacts byte-for-byte, and all six fresh receivers accept. Median quotient
stage time moves from 1.398 to 1.232 seconds; median proving time from 9.104 to
8.824 seconds. These are shared-host observations, not a claim of an isolated
3% end-to-end gain. The q70/P26 control remains nominal 96-bit PCS, with no
whole-protocol 128-bit qualification. No GPU execution is involved.

Evidence: `vectors/reports/rv64-wide-deep-rows-20261102/qualification.json`.

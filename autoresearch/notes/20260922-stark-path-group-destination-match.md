# Merkle groups borrow STARK path accumulator destinations

Task: remove group G/XOR buffers followed by concatenation into STARK paths.
Transfer the exact hash destination mechanism one level outward: compute canonical
counts, reserve unused path-list capacity, lend exact ranges to live/fixed groups,
and publish those rows only after both groups and payload-use comparisons succeed.
The group rebuilds and validates destination geometry; sizing is not an admission
token. Existing path input/root checks and rollback of query read counts remain.

The group's owning API delegates to the same optional-destination builder. Hash
frame ranges now point directly into path-owned G/XOR allocations. Frame receipt
cleanup and group arena cleanup must never free borrowed ranges. Smaller rows
retain their existing append path. All capacity/count arithmetic is checked.

This is destination lifetime extension, not new hash equations or scheduling.
It removes another data copy but dynamic path-list growth can still move earlier
rows between openings. No cross-opening borrowed pointer is retained. Count
planning has additional cost, so no timing gain is presumed. Validate owned vs
borrowed group parity and all allocation failures, then full independent parent
proof and preparation/worker memory. Production completion remains unproven.

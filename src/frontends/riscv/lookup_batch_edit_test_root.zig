//! Lightweight A-014 planner edit loop.
//!
//! The production integration gate remains `test-lookup-batching`; this root
//! owns only the authenticated planner tests and intentionally omits the
//! prover-engine-backed row executor and performance diagnostic.

test {
    _ = @import("air/lang/lookup_batch_planner_test.zig");
}

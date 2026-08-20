//! Lightweight A-013 authority edit loop.
//!
//! The production integration gate remains `test-row-windows`; this root
//! deliberately excludes the prover-engine-backed component suite so changes
//! to the typed window language can fail in seconds instead of rebuilding the
//! whole proof graph.

test {
    _ = @import("air/lang/row_window_test.zig");
}

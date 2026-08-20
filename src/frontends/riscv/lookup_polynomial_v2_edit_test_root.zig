//! Lightweight A-014 variable-partition authority edit loop.
//!
//! This still imports the prover-owned polynomial DAG, but its test filter
//! prevents unrelated prover suites from entering the compile graph. The full
//! production integration gate remains `test-lookup-batching`.

test {
    _ = @import("air/lang/lookup_polynomial_program_v2_test.zig");
    _ = @import("air/lang/lookup_physical_manifest_v2_test.zig");
}

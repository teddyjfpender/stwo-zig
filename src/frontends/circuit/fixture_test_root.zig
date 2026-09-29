//! Fixture-backed tests of `stwo_circuit_frontend`. They read committed
//! vectors relative to the repository root, which the build sets as cwd.

test {
    _ = @import("air_eval/tests/projection_test.zig");
    _ = @import("air_eval/tests/r3_components.zig");
    _ = @import("builder/tests/r0_fri_test.zig");
    _ = @import("builder/tests/r2_gadgets_test.zig");
}

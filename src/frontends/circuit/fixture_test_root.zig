//! Fixture-backed tests of `stwo_circuit_frontend`. They read committed
//! vectors relative to the repository root, which the build sets as cwd.

test {
    _ = @import("builder/tests/r0_fri_test.zig");
    _ = @import("builder/tests/r2_gadgets_test.zig");
}

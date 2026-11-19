//! Focused authenticated VM AIR ProfileV2 semantic test root.

// Unnamed import survives exact child-test filters for the small compiler gate.
test {}

test "authenticated VM AIR ProfileV2 focused inventory compiles" {
    _ = @import("tests/ethereum_variable_boundary_air_profile_test.zig");
    _ = @import("stwo_riscv_recursion");
}

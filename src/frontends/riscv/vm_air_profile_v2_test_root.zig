//! Focused authenticated VM AIR ProfileV2 semantic test root.

// Unnamed import survives exact child-test filters for the small compiler gate.
test {}

test "authenticated VM AIR ProfileV2 focused inventory compiles" {
    _ = @import("recursion/tests/vm_air_profile_v2_test.zig");
    _ = @import("recursion/vm_air_composition_prepared_v2.zig");
}

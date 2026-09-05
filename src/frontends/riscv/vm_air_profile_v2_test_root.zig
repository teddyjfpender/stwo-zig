//! Focused authenticated VM AIR ProfileV2 semantic test root.

test {
    _ = @import("recursion/vm_air_profile_v2_test.zig");
    _ = @import("recursion/vm_composition_program_v2_test.zig");
}

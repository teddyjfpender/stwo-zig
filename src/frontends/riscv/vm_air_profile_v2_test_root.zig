//! Focused authenticated VM AIR ProfileV2 semantic test root.

test "authenticated VM AIR ProfileV2 focused inventory compiles" {
    _ = @import("recursion/vm_air_profile_v2_test.zig");
    _ = @import("recursion/vm_composition_program_v2_test.zig");
    _ = @import("recursion/provider_shard_child_field_test.zig");
    _ = @import("recursion/vm_air_composition_prepared_v2.zig");
}

//! The same implementation under the unchanged custody_v2 product policy.
pub const BLOCK_V5_EXECUTION_RECIPE: u32 = 0;
test "block-v5 selected production independent root policy matches executable" {
    try @import("std").testing.expectEqual(BLOCK_V5_EXECUTION_RECIPE, @intFromEnum(@import("prover/block_v5_execution_recipe_v1.zig").canonical));
}
test {
    _ = @import("prover/tests/block_v5_x0_selected_production_unit_test.zig");
}

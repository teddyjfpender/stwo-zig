test {
    _ = @import("prover/block_v5_ram_range_forest_owned_test_v1.zig");
}
test "RAM durable catalogue: actual original leaf forest final join publisher and fresh standalone bodies retained" {
    @import("block_v5_ram_range_forest_owned_codegen_v1.zig").stwo_ram_range_forest_owned_body_gate();
}
test "RAM durable catalogue: independently selected execution recipe remains local zero" {
    try @import("std").testing.expectEqual(@import("prover/block_v5_execution_recipe_v1.zig").Recipe.local_zero_v1, @import("prover/block_v5_execution_recipe_v1.zig").canonical);
}

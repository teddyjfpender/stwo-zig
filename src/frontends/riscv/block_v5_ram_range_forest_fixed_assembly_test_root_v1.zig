test {
    _ = @import("prover/block_v5_ram_range_forest_fixed_assembly_test_v1.zig");
}
test "compact memory fixed assembly: actual independent key constructors original producer receiver retained" {
    @import("block_v5_ram_range_forest_fixed_assembly_codegen_v1.zig").stwo_ram_range_forest_fixed_assembly_body_gate();
}
test "compact memory fixed assembly: explicit legacy recipe" {
    try @import("std").testing.expectEqual(@import("prover/block_v5_execution_recipe_v1.zig").Recipe.custody_v2, @import("prover/block_v5_execution_recipe_v1.zig").canonical);
}

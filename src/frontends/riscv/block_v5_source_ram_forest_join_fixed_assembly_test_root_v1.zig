test {
    _ = @import("prover/block_v5_ram_range_forest_fixed_assembly_test_v1.zig");
    _ = @import("prover/block_v5_compact_fixed_spec_inventory_test_v1.zig");
    _ = @import("prover/block_v5_source_ram_forest_join_fixed_assembly_test_v1.zig");
}
test "compact memory fixed assembly: actual PAGE16 RAM19 V20 FINAL22 independent production bodies retained" {
    @import("block_v5_source_ram_forest_join_fixed_assembly_codegen_v1.zig").stwo_source_ram_forest_join_fixed_assembly_body_gate();
}
test "compact memory fixed assembly: explicit legacy source recipe" {
    try @import("std").testing.expectEqual(@import("prover/block_v5_execution_recipe_v1.zig").Recipe.custody_v2, @import("prover/block_v5_execution_recipe_v1.zig").canonical);
}

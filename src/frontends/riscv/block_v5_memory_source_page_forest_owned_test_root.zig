test {
    _ = @import("prover/block_v5_memory_source_page_forest_live_budget_test_v1.zig");
    _ = @import("prover/block_v5_memory_source_page_leaf_catalogue_test_v1.zig");
    _ = @import("prover/block_v5_memory_source_page_forest_summary_custody_test_v1.zig");
}
test "PAGE durable catalogue: actual original setup capture publisher and fresh compact receiver bodies retained" {
    @import("block_v5_memory_source_page_forest_owned_codegen_v1.zig").stwo_source_page_forest_owned_body_gate();
}
test "PAGE durable catalogue: independently selected execution policy remains bound" {
    try @import("std").testing.expectEqual(@import("prover/block_v5_execution_recipe_v1.zig").Recipe.custody_v2, @import("prover/block_v5_execution_recipe_v1.zig").canonical);
}

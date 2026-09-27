test {
    _ = @import("prover/block_v5_heterogeneous_hierarchy_test_v1.zig");
}
test "heterogeneous hierarchy: actual original leaf and hierarchy parent producer receiver bodies retained without invocation" {
    const recipes = @import("prover/block_v5_execution_recipe_v1.zig");
    try @import("std").testing.expectEqual(@as(recipes.Recipe, @enumFromInt(@import("root").BLOCK_V5_EXECUTION_RECIPE)), recipes.canonical);
    @import("block_v5_heterogeneous_hierarchy_codegen_v1.zig").stwo_heterogeneous_hierarchy_body_gate();
}

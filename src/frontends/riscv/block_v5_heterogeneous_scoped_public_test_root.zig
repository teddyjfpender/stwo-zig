test {
    _ = @import("prover/block_v5_heterogeneous_scoped_public_test_v1.zig");
}
test "scoped public bridge: actual owned source byte graph producer and standalone fresh receiver bodies retained" {
    const recipes = @import("prover/block_v5_execution_recipe_v1.zig");
    try @import("std").testing.expectEqual(@as(recipes.Recipe, @enumFromInt(@import("root").BLOCK_V5_EXECUTION_RECIPE)), recipes.canonical);
    @import("block_v5_heterogeneous_scoped_public_codegen_v1.zig").stwo_heterogeneous_scoped_public_body_gate();
}

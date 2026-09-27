test {
    _ = @import("prover/block_v5_heterogeneous_scoped_owned_test_v1.zig");
}
test "scoped setup owner: actual admitted setup original child and compact parent publication durable bytes fresh CPU receiver bodies retained" {
    const recipes = @import("prover/block_v5_execution_recipe_v1.zig");
    try @import("std").testing.expectEqual(@as(recipes.Recipe, @enumFromInt(@import("root").BLOCK_V5_EXECUTION_RECIPE)), recipes.canonical);
    @import("block_v5_heterogeneous_scoped_owned_codegen_v1.zig").stwo_heterogeneous_scoped_owned_body_gate();
}

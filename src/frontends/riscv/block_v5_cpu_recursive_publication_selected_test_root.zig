test {
    _ = @import("prover/block_v5_cpu_recursive_publication_test_v1.zig");
}
test "cpu recursive publication: actual dual driver seven-family publication original setup derivation and fresh leaf receiver bodies retained" {
    const Recipe = @import("prover/block_v5_execution_recipe_v1.zig");
    try @import("std").testing.expectEqual(Recipe.Recipe.local_zero_v1, Recipe.canonical);
    try @import("std").testing.expectEqual(@as(Recipe.Recipe, @enumFromInt(@import("root").BLOCK_V5_EXECUTION_RECIPE)), Recipe.canonical);
    @import("block_v5_cpu_recursive_publication_codegen_v1.zig").stwo_cpu_recursive_publication_body_gate();
}

test {
    _ = @import("prover/block_v5_caller_arithmetic_recursive_test_v1.zig");
}
test "caller arithmetic recursion: independent legacy product recipe is really selected" {
    try @import("std").testing.expectEqual(@import("prover/block_v5_execution_recipe_v1.zig").Recipe.custody_v2, @import("prover/block_v5_execution_recipe_v1.zig").canonical);
}
test "caller arithmetic recursion: actual production verifier and publisher bodies are retained" {
    @import("block_v5_caller_arithmetic_recursive_codegen.zig").stwo_caller_arithmetic_recursive_body_gate();
}

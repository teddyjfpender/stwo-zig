test {
    _ = @import("prover/block_v5_memory_source_page_recursive_test_v1.zig");
}
test "source PAGE recursion: actual original capture publisher and fresh leaf bodies are retained" {
    @import("block_v5_memory_source_page_recursive_codegen_v1.zig").stwo_source_page_recursive_body_gate();
}
test "source PAGE recursion: local-zero product recipe remains independently selected" {
    try @import("std").testing.expectEqual(@import("prover/block_v5_execution_recipe_v1.zig").Recipe.local_zero_v1, @import("prover/block_v5_execution_recipe_v1.zig").canonical);
}

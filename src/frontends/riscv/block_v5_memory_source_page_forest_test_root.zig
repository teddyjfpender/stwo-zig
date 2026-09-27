test {
    _ = @import("prover/block_v5_memory_source_page_forest_test_v1.zig");
    _ = @import("prover/block_v5_memory_source_page_raw_recursive_parity_test_v1.zig");
}
test "source PAGE forest: actual typed original leaves compact parent publisher and fresh receiver bodies are retained" {
    @import("block_v5_memory_source_page_forest_codegen_v1.zig").stwo_source_page_forest_body_gate();
}
test "source PAGE forest: independent legacy recipe remains selected" {
    try @import("std").testing.expectEqual(@import("prover/block_v5_execution_recipe_v1.zig").Recipe.custody_v2, @import("prover/block_v5_execution_recipe_v1.zig").canonical);
}

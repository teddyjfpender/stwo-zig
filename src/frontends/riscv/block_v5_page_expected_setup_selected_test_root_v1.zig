test {
    _ = @import("block_v5_page_expected_setup_test_root_v1.zig");
}
test "PAGE expected setup: independent selected execution recipe" {
    try @import("std").testing.expectEqual(@import("prover/block_v5_execution_recipe_v1.zig").Recipe.local_zero_v1, @import("prover/block_v5_execution_recipe_v1.zig").canonical);
}

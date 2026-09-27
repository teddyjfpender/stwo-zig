test {
    _ = @import("block_v5_supplemental_recursive_lifetime_test_root_v1.zig");
}
test "supplemental stage lifetime: independently selected original caller recipe" {
    try @import("std").testing.expectEqual(@import("prover/block_v5_execution_recipe_v1.zig").Recipe.local_zero_v1, @import("prover/block_v5_execution_recipe_v1.zig").canonical);
}

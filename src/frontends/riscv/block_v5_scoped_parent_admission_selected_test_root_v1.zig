test {
    _ = @import("block_v5_scoped_parent_admission_test_root_v1.zig");
}
test "scoped producer lifetime: independent selected original caller recipe" {
    try @import("std").testing.expectEqual(@import("prover/block_v5_execution_recipe_v1.zig").Recipe.local_zero_v1, @import("prover/block_v5_execution_recipe_v1.zig").canonical);
}

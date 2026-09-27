test {
    _ = @import("prover/block_v5_memory_source_page_join_test_v1.zig");
}
test "source PAGE join: actual original PAGE lane range receivers setup ownership and closure bodies retained" {
    const std = @import("std");
    const Recipe = @import("prover/block_v5_execution_recipe_v1.zig");
    try std.testing.expectEqual(@as(Recipe.Recipe, @enumFromInt(@import("root").BLOCK_V5_EXECUTION_RECIPE)), Recipe.canonical);
    stwo_memory_source_page_join_body_gate();
}
pub export fn stwo_memory_source_page_join_body_gate() void {
    const Owner = @import("prover/block_v5_memory_source_page_join_owner_v1.zig").Owner;
    inline for (.{ &Owner.create, &Owner.verify, &Owner.deinit }) |function| @import("std").mem.doNotOptimizeAway(function);
}

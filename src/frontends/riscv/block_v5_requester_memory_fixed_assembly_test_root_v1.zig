test {
    _ = @import("prover/block_v5_requester_memory_fixed_assembly_test_v1.zig");
}
test "FINAL22 fixed assembly: actual complete family expected-key and original lower producer fresh bodies retained" {
    @import("block_v5_requester_memory_fixed_assembly_codegen_v1.zig").stwo_requester_memory_fixed_assembly_body_gate();
}
test "FINAL22 fixed assembly: explicit legacy source recipe retained" {
    try @import("std").testing.expectEqual(@import("prover/block_v5_execution_recipe_v1.zig").Recipe.custody_v2, @import("prover/block_v5_execution_recipe_v1.zig").canonical);
}

test {
    _ = @import("prover/block_v5_requester_public_fixed_assembly_test_v1.zig");
}
test "PUBLIC21 fixed assembly: actual complete fixed expected-key and original family bodies retained" {
    @import("block_v5_requester_public_fixed_assembly_codegen_v1.zig").stwo_requester_public_fixed_assembly_body_gate();
}
test "PUBLIC21 fixed assembly: explicit legacy source recipe retained" {
    try @import("std").testing.expectEqual(@import("prover/block_v5_execution_recipe_v1.zig").Recipe.custody_v2, @import("prover/block_v5_execution_recipe_v1.zig").canonical);
}

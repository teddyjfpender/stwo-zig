test {
    _ = @import("prover/block_v5_requester_recursive_fixed_test_v1.zig");
    _ = @import("prover/block_v5_requester_public_fixed_kernel_test_v1.zig");
}
test "requester fixed ports: explicit selected source recipe retained" {
    try @import("std").testing.expectEqual(@import("prover/block_v5_execution_recipe_v1.zig").Recipe.local_zero_v1, @import("prover/block_v5_execution_recipe_v1.zig").canonical);
}
test "requester fixed ports: actual source compiler fixed and original producer bodies retained" {
    @import("block_v5_requester_recursive_fixed_codegen_v1.zig").stwo_requester_recursive_fixed_body_gate();
}

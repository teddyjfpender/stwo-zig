comptime {
    _ = @import("prover/block_v5_wide_original_bridge_test_v1.zig");
    _ = @import("recursion/block_v5_wide_original_child_source_v1.zig");
}
test "wide original bridge body: genuine typed fresh and symbolic original verifier retention" {
    @import("block_v5_wide_original_bridge_codegen_v1.zig").stwo_wide_original_bridge_body_gate();
}

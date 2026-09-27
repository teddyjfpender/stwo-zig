test {
    _ = @import("prover/block_v5_caller_fused_recursive_test_v1.zig");
}
test "caller fused recursion: actual original capture all cohorts publication and receiver bodies retained" {
    @import("block_v5_caller_fused_recursive_codegen.zig").stwo_caller_fused_recursive_body_gate();
}

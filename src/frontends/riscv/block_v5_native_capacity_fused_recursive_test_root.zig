test {
    _ = @import("prover/block_v5_native_capacity_fused_recursive_test_v1.zig");
}
test "capacity fused recursion: actual capture all cohorts publication cache and receiver bodies retained" {
    @import("block_v5_native_capacity_fused_recursive_codegen.zig").stwo_capacity_fused_recursive_body_gate();
}

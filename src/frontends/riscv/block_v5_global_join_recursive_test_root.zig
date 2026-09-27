test {
    _ = @import("prover/block_v5_global_join_recursive_test_v1.zig");
}
test "global join recursion: actual original parent aggregate attach and publication bodies retained" {
    @import("block_v5_global_join_recursive_codegen_v1.zig").stwo_global_join_recursive_body_gate();
}

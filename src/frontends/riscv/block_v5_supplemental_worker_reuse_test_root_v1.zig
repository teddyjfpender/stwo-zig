test {
    _ = @import("prover/block_v5_supplemental_worker_reuse_test_v1.zig");
    _ = @import("prover/block_v5_native_recursive_consuming_test.zig");
}
test "supplemental worker reuse: actual canonical CPU session driver and worker bodies retained" {
    @import("block_v5_word_expected_setup_codegen_v1.zig").stwo_word_expected_setup_body_gate();
}

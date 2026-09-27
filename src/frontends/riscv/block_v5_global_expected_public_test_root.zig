test {
    _ = @import("prover/block_v5_global_expected_public_test_v1.zig");
    _ = @import("recursion/block_v5_global_public_export_normalizer_v1.zig");
}
test "global expected public body: original publisher and fresh verifier production bodies retained" {
    @import("block_v5_global_expected_public_codegen_v1.zig").stwo_global_expected_public_body_gate();
}

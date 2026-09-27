test {
    _ = @import("prover/block_v5_native_fixed_pcs_test_v1.zig");
}
test "native fixed PCS: genuine native and original parent factory body retention" {
    @import("block_v5_native_fixed_pcs_codegen_v1.zig").stwo_native_fixed_pcs_body_gate();
}

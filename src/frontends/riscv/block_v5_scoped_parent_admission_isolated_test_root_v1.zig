test {
    _ = @import("prover/blake3_scoped_parent_admission_test_v1.zig");
    _ = @import("prover/tests/block_v5_native_recursive_consuming_test.zig");
}
test "scoped producer lifetime: isolated actual default scoped Plan Worker cache bodies retained" {
    @import("block_v5_scoped_parent_admission_isolated_codegen_v1.zig").stwo_scoped_parent_admission_isolated_body_gate();
}

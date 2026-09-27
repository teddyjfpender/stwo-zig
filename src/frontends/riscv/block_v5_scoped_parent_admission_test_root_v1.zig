test {
    _ = @import("prover/blake3_scoped_parent_admission_test_v1.zig");
    _ = @import("block_v5_supplemental_recursive_lifetime_test_root_v1.zig");
}
test "scoped producer lifetime: actual default scoped producer worker cache and five family bodies retained" {
    @import("block_v5_scoped_parent_admission_codegen_v1.zig").stwo_scoped_parent_admission_body_gate();
}

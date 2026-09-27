test {
    _ = @import("prover/block_v5_global_join_semantic_test_v1.zig");
}
test "global semantic mapping: real independent derivation and same-parent attachment bodies retained" {
    @import("block_v5_global_join_semantic_codegen_v1.zig").stwo_global_join_semantic_body_gate();
}

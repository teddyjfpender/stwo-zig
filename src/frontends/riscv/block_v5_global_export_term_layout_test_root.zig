test {
    _ = @import("recursion/block_v5_global_export_term_layout_test_v1.zig");
    _ = @import("prover/block_v5_global_expected_public_test_v1.zig");
    _ = @import("recursion/block_v5_global_public_export_normalizer_v1.zig");
}
test "global export layout: actual public producer and prepared fresh verifier bodies retained" {
    @import("block_v5_global_expected_public_codegen_v1.zig").stwo_global_expected_public_body_gate();
}

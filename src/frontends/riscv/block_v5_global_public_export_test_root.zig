test {
    _ = @import("prover/block_v5_global_public_export_test_v1.zig");
}
test "global public export body: actual parent stage cache and fresh receiver bodies retained" {
    @import("block_v5_global_public_export_codegen_v1.zig").stwo_global_public_export_body_gate();
}

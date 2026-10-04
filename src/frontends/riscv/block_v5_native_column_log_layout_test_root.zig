test {
    _ = @import("prover/block_v5_native_column_log_layout_test_v1.zig");
    _ = @import("prover/tests/block_v5_native_capacity_recursive_test.zig");
}
test "native column geometry: actual public parent producer and fresh receiver bodies retained" {
    @import("block_v5_global_public_export_codegen_v1.zig").stwo_global_public_export_body_gate();
}

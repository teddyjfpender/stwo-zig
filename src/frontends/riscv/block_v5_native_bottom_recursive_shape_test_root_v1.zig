test {
    _ = @import("prover/block_v5_native_bottom_recursive_shape_test_v1.zig");
}
test "native bottom fixed: actual original shape compiler body retention" {
    @import("block_v5_native_bottom_recursive_shape_codegen_v1.zig").stwo_native_bottom_recursive_shape_body_gate();
}

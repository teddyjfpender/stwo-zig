test {
    _ = @import("prover/block_v5_recursive_execution_leaf_files_test_v1.zig");
}
test "recursive execution files: all three original typed codec fresh receiver and publication bodies retained" {
    @import("block_v5_recursive_execution_leaf_files_codegen.zig").stwo_recursive_execution_leaf_files_body_gate();
}

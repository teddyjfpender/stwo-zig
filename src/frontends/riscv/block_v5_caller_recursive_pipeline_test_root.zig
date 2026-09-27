test {
    _ = @import("prover/block_v5_caller_recursive_pipeline_test_v1.zig");
}
test "caller recursive pipeline: actual original staged caller and both parent publishers are retained" {
    @import("block_v5_caller_recursive_pipeline_codegen.zig").stwo_caller_recursive_pipeline_body_gate();
}

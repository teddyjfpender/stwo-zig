test {
    _ = @import("prover/block_v5_supplemental_recursive_lifetime_test_v1.zig");
    _ = @import("prover/block_v5_supplemental_worker_reuse_test_v1.zig");
    _ = @import("prover/block_v5_native_recursive_consuming_test.zig");
    _ = @import("prover/block_v5_caller_recursive_pipeline_test_v1.zig");
}
test "supplemental stage lifetime: all five genuine stage cache fresh receiver and caller pipeline bodies retained" {
    @import("block_v5_supplemental_recursive_lifetime_codegen_v1.zig").stwo_supplemental_recursive_lifetime_body_gate();
}

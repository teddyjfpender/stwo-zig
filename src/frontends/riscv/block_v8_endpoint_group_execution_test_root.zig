//! Focused inactive Group execution producer qualification and opt-in benchmark.
test {
    _ = @import("prover/tests/block_v8_endpoint_group_execution_test.zig");
    _ = @import("prover/tests/block_v8_endpoint_group_execution_benchmark.zig");
    _ = @import("prover/tests/block_v8_endpoint_group_pipeline_benchmark.zig");
}

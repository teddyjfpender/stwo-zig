//! Complete default assertion-bearing source collection for this component.
//! Fixture-dependent CSP proofs retain their original explicit focused gate.
//! Import-only focus collectors remain available; their subjects are owned below.
test {
    _ = @import("rv64/capture_inputs.zig");
    _ = @import("rv64/capture_execution.zig");
    _ = @import("rv64/capture_execution_consumer_test.zig");
    _ = @import("rv64/hybrid_scratch_output.zig");
    _ = @import("ethereum_recursion_ready_test.zig");
    _ = @import("rv64/host_retained_policy.zig");
    _ = @import("rv64/jobs/native_class_build_test.zig");
    _ = @import("rv64/native_publication.zig");
    _ = @import("rv64_combined_ethereum_main.zig");
}

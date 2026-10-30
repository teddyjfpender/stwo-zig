// The emitted benchmark binary first checks the small genuine native window
// and ownership handoff before accepting any explicit large-window request.
test {
    _ = @import("prover/tests/block_v8_endpoint_execution_test.zig");
    _ = @import("prover/tests/block_v8_endpoint_execution_benchmark.zig");
}

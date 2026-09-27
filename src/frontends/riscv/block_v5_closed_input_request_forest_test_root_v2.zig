const std = @import("std");
test {
    _ = @import("prover/block_v5_closed_input_request_forest_test_v2.zig");
}
test "closed input forest: retain real closed producer receiver setup and full child verifier bodies without invocation" {
    std.mem.doNotOptimizeAway(&@import("block_v5_closed_input_request_forest_codegen_v2.zig").stwo_closed_input_request_forest_body_gate);
}

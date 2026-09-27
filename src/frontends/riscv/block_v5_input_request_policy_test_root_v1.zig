const std = @import("std");
test {
    _ = @import("prover/block_v5_input_request_policy_test_v1.zig");
}
test "input request policy: retain real independent publish reconstruct and stable owner bodies without calls" {
    std.mem.doNotOptimizeAway(&@import("block_v5_input_request_policy_codegen_v1.zig").stwo_input_request_policy_body_gate);
}

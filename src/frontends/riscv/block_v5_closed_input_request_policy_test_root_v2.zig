const std = @import("std");
test {
    _ = @import("prover/block_v5_closed_input_request_policy_test_v2.zig");
}
test "closed input policy: retain real version5 durable owner CPU publish reconstruct fresh root bodies" {
    std.mem.doNotOptimizeAway(&@import("block_v5_closed_input_request_policy_codegen_v2.zig").stwo_closed_input_request_policy_body_gate);
}

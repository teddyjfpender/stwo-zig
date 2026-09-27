const std = @import("std");
test {
    _ = @import("prover/block_v5_input_request_forest_test_v1.zig");
    _ = @import("block_v5_tail_linked_public_test_root_v2.zig");
}
test "input request forest: retain real bounded run stage receiver and attachment bodies without invocation" {
    std.mem.doNotOptimizeAway(&@import("block_v5_input_request_forest_codegen_v1.zig").stwo_input_request_forest_body_gate);
}

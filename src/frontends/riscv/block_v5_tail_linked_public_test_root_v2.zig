const std = @import("std");
test {
    _ = @import("prover/block_v5_tail_linked_public_test_v2.zig");
    _ = @import("prover/block_v5_wide_public_windows_test_v1.zig");
    _ = @import("prover/block_v5_input_tail_test_v1.zig");
}
test "tail linked public: retain genuine default selected and ancestor production bodies without calls" {
    std.mem.doNotOptimizeAway(&@import("block_v5_tail_linked_public_codegen_v2.zig").stwo_tail_linked_public_body_gate);
}

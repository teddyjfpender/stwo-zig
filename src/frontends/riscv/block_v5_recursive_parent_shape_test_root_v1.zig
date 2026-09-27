const std = @import("std");
test {
    _ = @import("prover/block_v5_recursive_parent_shape_test_v1.zig");
}
test "recursive shape: retain original live and independent fixed-only compiler bodies without execution" {
    std.mem.doNotOptimizeAway(&@import("block_v5_recursive_parent_shape_codegen_v1.zig").stwo_recursive_parent_fixed_shape_body_gate);
}

test {
    const std = @import("std");
    std.testing.refAllDecls(@import("prover/block_v7_memory_joint_test_v1.zig"));
    std.testing.refAllDecls(@import("prover/block_v7_memory_cohorts_test_v1.zig"));
}

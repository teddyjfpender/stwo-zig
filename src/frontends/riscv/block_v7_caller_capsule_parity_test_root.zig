const std = @import("std");
test {
    std.testing.refAllDecls(@import("recursion/block_v7_caller_capsule_test_v1.zig"));
    std.testing.refAllDecls(@import("prover/tests/block_v7_caller_active_test.zig"));
}

test {
    const std = @import("std");
    std.testing.refAllDecls(@import("prover/block_v7_sha_window_control_projection_v1.zig"));
    std.testing.refAllDecls(@import("prover/tests/block_v7_sha_window_batch_test.zig"));
    std.testing.refAllDecls(@import("air/guest_precompile/sha256_global_wire_caller_v1.zig"));
}

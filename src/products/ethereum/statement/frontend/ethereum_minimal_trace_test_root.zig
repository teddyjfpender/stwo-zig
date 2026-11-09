const std = @import("std");

test "Ethereum compact minimal-trace declarations compile" {
    std.testing.refAllDeclsRecursive(
        @import("runner/minimal_trace/ethereum_types.zig"),
    );
    std.testing.refAllDeclsRecursive(
        @import("runner/minimal_trace/ethereum_capture.zig"),
    );
    std.testing.refAllDeclsRecursive(
        @import("runner/minimal_trace/ethereum_parallel_replay.zig"),
    );
    std.testing.refAllDeclsRecursive(
        @import("runner/minimal_trace/ethereum_replay.zig"),
    );
    std.testing.refAllDeclsRecursive(
        @import("runner/minimal_trace/ethereum_wire.zig"),
    );
}

test {
    _ = @import("runner/minimal_trace/ethereum_test.zig");
}

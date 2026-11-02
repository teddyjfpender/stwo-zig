//! Focused tests of the RV64 recursion leaf that need the circuit builder.
const std = @import("std");
test {
    std.testing.refAllDecls(@import("rv64_recursion/circuit_lane.zig"));
    std.testing.refAllDecls(@import("rv64_recursion/public_wires.zig"));
    std.testing.refAllDecls(@import("rv64_recursion/closure.zig"));
    std.testing.refAllDecls(@import("rv64_recursion/native_capture.zig"));
    std.testing.refAllDecls(@import("rv64_recursion/fold_root.zig"));
}

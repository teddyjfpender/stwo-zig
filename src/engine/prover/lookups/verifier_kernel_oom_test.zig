//! Gate output allocation is resource failure, not a malformed proof.
const std = @import("std");
const K = @import("verifier_kernel.zig");
const Q = @import("stwo_core").fields.qm31.QM31;
const Gate = enum { LogUp, GrandProduct };
test "GKR verifier gate preserves OOM and validates shape before allocation" {
    var failure = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    const allocator = failure.allocator();
    const columns = [_][2]Q{ .{ Q.one(), Q.one() }, .{ Q.one(), Q.one() } };
    try std.testing.expectError(error.OutOfMemory, K.evalGate(Q, allocator, Gate.LogUp, &columns));
    try std.testing.expectError(error.OutOfMemory, K.evalGate(Q, allocator, Gate.GrandProduct, columns[0..1]));
    try std.testing.expectError(error.InvalidMask, K.evalGate(Q, allocator, Gate.LogUp, columns[0..1]));
}

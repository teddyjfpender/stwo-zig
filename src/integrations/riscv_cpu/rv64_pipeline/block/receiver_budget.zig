//! Operational receiver allocation authority, independent of proof parameters.
const std = @import("std");
pub const DEFAULT_BYTES: usize = 32 << 30;
pub const RECYCLER_CACHE_BYTES: usize = 4 << 30;
pub const WORKER_STACK_BYTES: usize = 1024 * 1024;
/// Original command forms remain valid. The one optional final argument is a
/// requested-live allocation cap, never a proof/profile selector or RSS bound.
pub fn limit(args: anytype, candidate: bool) !usize {
    const required: usize = if (candidate) 5 else 4;
    if (args.len != required and args.len != required + 1) return error.VerifierNeedsNoExecutionPackets;
    if (args.len == required) return DEFAULT_BYTES;
    const value = try std.fmt.parseUnsigned(usize, args[required], 10);
    if (value == 0) return error.InvalidReceiverMemoryBudget;
    return value;
}
pub fn stackBytes(workers: usize) !usize {
    return std.math.mul(usize, workers, WORKER_STACK_BYTES);
}
test "receiver cap has explicit positive operational authority and preserves old command forms" {
    const a = [_][]const u8{ "driver", "verify-control", "config", "out" };
    const b = [_][]const u8{ "driver", "verify-candidate", "config", "out", "1024" };
    try std.testing.expectEqual(DEFAULT_BYTES, try limit(&a, false));
    try std.testing.expectEqual(DEFAULT_BYTES, try limit(&b, true));
    try std.testing.expectEqual(@as(usize, 1024), try limit(&b, false));
    const explicit = b ++ [_][]const u8{"2048"};
    try std.testing.expectEqual(@as(usize, 2048), try limit(&explicit, true));
    const zero = a ++ [_][]const u8{"0"};
    try std.testing.expectError(error.InvalidReceiverMemoryBudget, limit(&zero, false));
    try std.testing.expectError(error.VerifierNeedsNoExecutionPackets, limit(&explicit, false));
    try std.testing.expectEqual(@as(usize, 8 << 20), try stackBytes(8));
    try std.testing.expectError(error.Overflow, stackBytes(std.math.maxInt(usize)));
}

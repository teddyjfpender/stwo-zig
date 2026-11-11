//! Operational receiver allocation authority, independent of proof parameters.
const std = @import("std");
pub const DEFAULT_BYTES: usize = 32 << 30;
pub const RECYCLER_CACHE_BYTES: usize = 4 << 30;
pub const CPU_WRAP_RECYCLER_CACHE_BYTES: usize = 64 << 20;
/// Explicit CPU producer experiment. Freed blocks stay outside requested-live
/// accounting; the finite cache cap must be added when budgeting host capacity.
pub fn cpuWrapRecyclerBytes(a: std.mem.Allocator) !usize {
    const text = std.process.getEnvVarOwned(a, "STWO_RV64_CPU_WRAP_RECYCLE_BYTES") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return CPU_WRAP_RECYCLER_CACHE_BYTES,
        else => return err,
    };
    defer a.free(text);
    return parseCpuWrapRecyclerBytes(text);
}
fn parseCpuWrapRecyclerBytes(text: []const u8) !usize {
    const bytes = try std.fmt.parseUnsigned(usize, text, 10);
    if (bytes > RECYCLER_CACHE_BYTES) return error.InvalidCpuWrapRecyclerCap;
    return bytes;
}
test "CPU wrapping recycler override is finite and leaves the default admission unchanged" {
    try std.testing.expectEqual(@as(usize, 0), try parseCpuWrapRecyclerBytes("0"));
    try std.testing.expectEqual(@as(usize, 1 << 30), try parseCpuWrapRecyclerBytes("1073741824"));
    try std.testing.expectEqual(RECYCLER_CACHE_BYTES, try parseCpuWrapRecyclerBytes("4294967296"));
    try std.testing.expectError(error.InvalidCpuWrapRecyclerCap, parseCpuWrapRecyclerBytes("4294967297"));
    try std.testing.expectError(error.InvalidCharacter, parseCpuWrapRecyclerBytes("unbounded"));
    try std.testing.expectEqual(@as(usize, 64 << 20), CPU_WRAP_RECYCLER_CACHE_BYTES);
}
/// Native physical verification evaluates CPU and delegation AIR on helpers.
/// Keep their stack reservation explicit in the receiver budget.
pub const WORKER_STACK_BYTES: usize = 8 << 20;
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
    try std.testing.expectEqual(@as(usize, 64 << 20), try stackBytes(8));
    try std.testing.expectError(error.Overflow, stackBytes(std.math.maxInt(usize)));
}

//! Blocking, one-request native process bridge. No implicit compile or fallback.
//! Only trusted, pinned binaries are supported; benchmark harness supplies a
//! process deadline. Output is bounded and validated before callers mutate data.
const std = @import("std");
const abi = @import("abi.zig");
const M31 = @import("stwo_core").fields.m31.M31;
pub const Config = struct { executable: []const u8, threads: u8 = 1 };

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8, count: usize) ![]M31 {
    if (count > 1 << abi.max_log_size or bytes.len != 12 + count * 4) return error.InvalidBendOutput;
    if (std.mem.readInt(u32, bytes[0..4], .little) != abi.response_magic or
        std.mem.readInt(u32, bytes[4..8], .little) != abi.version or
        std.mem.readInt(u32, bytes[8..12], .little) != count) return error.InvalidBendOutput;
    const values = try allocator.alloc(M31, count);
    errdefer allocator.free(values);
    for (values, 0..) |*x, i| {
        const v = std.mem.readInt(u32, bytes[12 + 4 * i ..][0..4], .little);
        if (v >= 2147483647) return error.NonCanonicalBendOutput;
        x.* = M31.fromCanonical(v);
    }
    return values;
}

pub fn execute(allocator: std.mem.Allocator, config: Config, request: []const u8, count: usize) ![]M31 {
    if (config.executable.len == 0 or config.threads == 0 or config.threads > 128) return error.InvalidBendConfig;
    if (request.len > 16 * (1 << abi.max_log_size) or count > 1 << abi.max_log_size) return error.BendRequestTooLarge;
    var thread_buffer: [3]u8 = undefined;
    const threads = try std.fmt.bufPrint(&thread_buffer, "{d}", .{config.threads});
    var child = std.process.Child.init(&.{ config.executable, "--threads", threads, "--gpu", "off" }, allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    try child.spawn();
    var reaped = false;
    defer if (!reaped) {
        _ = child.kill() catch {};
    };
    try child.stdin.?.writeAll(request);
    child.stdin.?.close();
    child.stdin = null;
    var stdout: std.ArrayList(u8) = .empty;
    defer stdout.deinit(allocator);
    var stderr: std.ArrayList(u8) = .empty;
    defer stderr.deinit(allocator);
    try child.collectOutput(allocator, &stdout, &stderr, @max(4096, 12 + count * 4));
    const term = try child.wait();
    reaped = true;
    if (term != .Exited or term.Exited != 0) return error.BendProcessFailed;
    return decode(allocator, stdout.items, count);
}

test "bend ABI rejects truncated oversized wrong-version and noncanonical responses" {
    const a = std.testing.allocator;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    for ([_]u32{ abi.response_magic, 1, 1, 7 }) |x| try abi.word(&bytes, a, x);
    const values = try decode(a, bytes.items, 1);
    defer a.free(values);
    try std.testing.expectEqual(@as(u32, 7), values[0].v);
    try std.testing.expectError(error.InvalidBendOutput, decode(a, bytes.items[0..15], 1));
    try std.testing.expectError(error.InvalidBendOutput, decode(a, bytes.items, 2));
    bytes.items[4] = 2;
    try std.testing.expectError(error.InvalidBendOutput, decode(a, bytes.items, 1));
    bytes.items[4] = 1;
    std.mem.writeInt(u32, bytes.items[12..16], 2147483647, .little);
    try std.testing.expectError(error.NonCanonicalBendOutput, decode(a, bytes.items, 1));
}

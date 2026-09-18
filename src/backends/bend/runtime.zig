//! Blocking, one-request native process bridge. No implicit compile or fallback.
//! Only trusted, pinned binaries are supported; benchmark harness supplies a
//! process deadline. Output is bounded and validated before callers mutate data.
const std = @import("std");
const abi = @import("abi.zig");
const M31 = @import("stwo_core").fields.m31.M31;
var requests = [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** 6;
var sent_bytes = std.atomic.Value(u64).init(0);
var received_bytes = std.atomic.Value(u64).init(0);
pub fn snapshot() struct { calls: [6]u64, request_bytes: u64, response_bytes: u64 } {
    var calls: [6]u64 = undefined;
    for (&requests, &calls) |*counter, *value| value.* = counter.load(.monotonic);
    return .{ .calls = calls, .request_bytes = sent_bytes.load(.monotonic), .response_bytes = received_bytes.load(.monotonic) };
}
pub const Config = struct { executable: []const u8, threads: u8 = 1, persistent: bool = false };

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
    if (request.len < 20) return error.InvalidBendRequest;
    if (config.executable.len == 0 or config.threads == 0 or config.threads > 128) return error.InvalidBendConfig;
    if (request.len > 16 * (1 << abi.max_log_size) or count > 1 << abi.max_log_size) return error.BendRequestTooLarge;
    if (config.persistent) return executePersistent(allocator, config, request, count);
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
    const result = try decode(allocator, stdout.items, count);
    const op = std.mem.readInt(u32, request[8..12], .little);
    if (op < requests.len) _ = requests[op].fetchAdd(1, .monotonic);
    _ = sent_bytes.fetchAdd(request.len, .monotonic);
    _ = received_bytes.fetchAdd(stdout.items.len, .monotonic);
    return result;
}

// One serialized native session avoids process-per-column startup. No fallback:
// any malformed response or dead child fails the operation and destroys session.
var session_lock: std.Thread.Mutex = .{};
var session: ?std.process.Child = null;
var session_config: ?Config = null;

pub fn shutdown() void {
    session_lock.lock();
    defer session_lock.unlock();
    stopSession();
}
fn stopSession() void {
    if (session) |*child| {
        _ = child.kill() catch {};
    }
    session = null;
    if (session_config) |old| std.heap.page_allocator.free(old.executable);
    session_config = null;
}
fn executePersistent(a: std.mem.Allocator, config: Config, request: []const u8, count: usize) ![]M31 {
    session_lock.lock();
    defer session_lock.unlock();
    errdefer stopSession();
    if (session_config) |old| {
        if (old.threads != config.threads or !std.mem.eql(u8, old.executable, config.executable)) return error.BendSessionConfigChanged;
    }
    if (session == null) {
        const pa = std.heap.page_allocator;
        var env = try std.process.getEnvMap(pa);
        defer env.deinit();
        try env.put("STWO_BEND_PERSISTENT", "1");
        var thread_buffer: [3]u8 = undefined;
        const threads = try std.fmt.bufPrint(&thread_buffer, "{d}", .{config.threads});
        var child = std.process.Child.init(&.{ config.executable, "--threads", threads, "--gpu", "off" }, pa);
        child.env_map = &env;
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        const owned_path = try pa.dupe(u8, config.executable);
        errdefer pa.free(owned_path);
        try child.spawn();
        // argv/env are spawn-only. Avoid retaining pointers to stack data.
        child.argv = &.{};
        child.env_map = null;
        session = child;
        session_config = .{ .executable = owned_path, .threads = config.threads, .persistent = true };
    }
    var child = &session.?;
    var magic: [4]u8 = undefined;
    std.mem.writeInt(u32, &magic, 0x32444e42, .little);
    try child.stdin.?.writeAll(&magic);
    try child.stdin.?.writeAll(request[4..]);
    var header: [12]u8 = undefined;
    if (try child.stdout.?.readAll(&header) != header.len) return error.TruncatedBendOutput;
    if (std.mem.readInt(u32, header[0..4], .little) != abi.response_magic or
        std.mem.readInt(u32, header[4..8], .little) != abi.version or
        std.mem.readInt(u32, header[8..12], .little) != count) return error.InvalidBendOutput;
    const bytes = try a.alloc(u8, 12 + count * 4);
    defer a.free(bytes);
    @memcpy(bytes[0..12], &header);
    if (try child.stdout.?.readAll(bytes[12..]) != bytes.len - 12) return error.TruncatedBendOutput;
    const values = try decode(a, bytes, count);
    const op = std.mem.readInt(u32, request[8..12], .little);
    if (op < requests.len) _ = requests[op].fetchAdd(1, .monotonic);
    _ = sent_bytes.fetchAdd(request.len, .monotonic);
    _ = received_bytes.fetchAdd(bytes.len, .monotonic);
    return values;
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

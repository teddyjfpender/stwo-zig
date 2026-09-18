//! Blocking, one-request native process bridge. No implicit compile or fallback.
//! Only trusted, pinned binaries are supported; benchmark harness supplies a
//! process deadline. Output is bounded and validated before callers mutate data.
const std = @import("std");
const abi = @import("abi.zig");
const M31 = @import("stwo_core").fields.m31.M31;
var requests = [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** 6;
var plan_reuses = std.atomic.Value(u64).init(0);
var cache_hits = std.atomic.Value(u64).init(0);
var bridge_ns = std.atomic.Value(u64).init(0);
var oracle_ns = std.atomic.Value(u64).init(0);
var preparation_ns = std.atomic.Value(u64).init(0);
pub fn observeOracle(ns: u64) void {
    _ = oracle_ns.fetchAdd(ns, .monotonic);
}
pub fn observePreparation(ns: u64) void {
    _ = preparation_ns.fetchAdd(ns, .monotonic);
}
var sent_bytes = std.atomic.Value(u64).init(0);
var received_bytes = std.atomic.Value(u64).init(0);
pub fn snapshot() struct { calls: [6]u64, request_bytes: u64, response_bytes: u64, cache_hits: u64, bridge_ns: u64, oracle_ns: u64, preparation_ns: u64, peak_native_requests: u64, plan_reuses: u64 } {
    var calls: [6]u64 = undefined;
    for (&requests, &calls) |*counter, *value| value.* = counter.load(.monotonic);
    return .{ .calls = calls, .request_bytes = sent_bytes.load(.monotonic), .response_bytes = received_bytes.load(.monotonic), .cache_hits = cache_hits.load(.monotonic), .bridge_ns = bridge_ns.load(.monotonic), .oracle_ns = oracle_ns.load(.monotonic), .preparation_ns = preparation_ns.load(.monotonic), .peak_native_requests = peak_requests.load(.monotonic), .plan_reuses = plan_reuses.load(.monotonic) };
}
pub const Config = struct { executable: []const u8, threads: u8 = 1, persistent: bool = false, cache_bytes: usize = 0, workers: u8 = 1, lane: u8 = 0, shadow_check: bool = true };

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
    var timer = try std.time.Timer.start();
    defer {
        _ = bridge_ns.fetchAdd(timer.read(), .monotonic);
    }
    if (request.len < 20) return error.InvalidBendRequest;
    if (config.executable.len == 0 or config.threads == 0 or config.threads > 128) return error.InvalidBendConfig;
    if (request.len > 16 * (1 << abi.max_log_size) or count > 1 << abi.max_log_size) return error.BendRequestTooLarge;
    if (config.workers == 0 or config.workers > 8 or config.lane >= config.workers) return error.InvalidBendConfig;
    if (config.persistent) return sessions[config.lane].executePersistent(allocator, config, request, count);
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
var active_requests = std.atomic.Value(u64).init(0);
var peak_requests = std.atomic.Value(u64).init(0);
var sessions: [8]Session = [_]Session{.{}} ** 8;
pub fn shutdown() void {
    for (&sessions) |*session| {
        session.session_lock.lock();
        session.stopSession();
        session.session_lock.unlock();
    }
}
const CacheEntry = struct { hash: u64, request: []u8, values: []M31 };
const Session = struct {
    session_lock: std.Thread.Mutex = .{},
    session: ?std.process.Child = null,
    session_config: ?Config = null,
    cache: std.ArrayList(CacheEntry) = .empty,
    cache_size: usize = 0,
    last_plan: []u8 = &.{},
    fn clearCache(self: *Session) void {
        const a = std.heap.page_allocator;
        for (self.cache.items) |entry| {
            a.free(entry.request);
            a.free(entry.values);
        }
        self.cache.deinit(a);
        self.cache = .empty;
        self.cache_size = 0;
    }
    fn remember(self: *Session, request: []const u8, values: []const M31, hash: u64, limit: usize) !void {
        const size = request.len + values.len * @sizeOf(M31);
        if (size > limit or limit == 0) return;
        const a = std.heap.page_allocator;
        while (self.cache_size + size > limit and self.cache.items.len > 0) {
            const entry = self.cache.orderedRemove(0);
            self.cache_size -= entry.request.len + entry.values.len * @sizeOf(M31);
            a.free(entry.request);
            a.free(entry.values);
        }
        const key = try a.dupe(u8, request);
        errdefer a.free(key);
        const result = try a.dupe(M31, values);
        errdefer a.free(result);
        try self.cache.append(a, .{ .hash = hash, .request = key, .values = result });
        self.cache_size += size;
    }

    fn stopSession(self: *Session) void {
        self.clearCache();
        std.heap.page_allocator.free(self.last_plan);
        self.last_plan = &.{};
        if (self.session) |*child| {
            _ = child.kill() catch {};
        }
        self.session = null;
        if (self.session_config) |old| std.heap.page_allocator.free(old.executable);
        self.session_config = null;
    }
    fn executePersistent(self: *Session, a: std.mem.Allocator, config: Config, request: []const u8, count: usize) ![]M31 {
        self.session_lock.lock();
        defer self.session_lock.unlock();
        errdefer self.stopSession();
        if (self.session_config) |old| {
            if (old.workers != config.workers or old.cache_bytes != config.cache_bytes or old.threads != config.threads or !std.mem.eql(u8, old.executable, config.executable)) return error.BendSessionConfigChanged;
        }
        const hash = std.hash.Wyhash.hash(0, request);
        if (config.cache_bytes != 0) for (self.cache.items) |entry| {
            // Hash only indexes candidates: full request equality is mandatory.
            if (entry.hash == hash and entry.values.len == count and std.mem.eql(u8, entry.request, request)) {
                _ = cache_hits.fetchAdd(1, .monotonic);
                return a.dupe(M31, entry.values);
            }
        };
        if (self.session == null) {
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
            self.session = child;
            self.session_config = .{ .executable = owned_path, .threads = config.threads, .persistent = true, .cache_bytes = config.cache_bytes, .workers = config.workers };
        }
        const active = active_requests.fetchAdd(1, .monotonic) + 1;
        _ = peak_requests.fetchMax(active, .monotonic);
        defer _ = active_requests.fetchSub(1, .monotonic);
        var child = &self.session.?;
        const op = std.mem.readInt(u32, request[8..12], .little);
        const has_plan = op == 0 or op == 1 or op == 5;
        const plan_offset = 20 + count * 4;
        if (has_plan and request.len != plan_offset + (count - 1) * 4) return error.InvalidBendRequest;
        const plan = if (has_plan) request[plan_offset..] else &.{};
        const reuse_plan = has_plan and self.last_plan.len != 0 and std.mem.eql(u8, plan, self.last_plan);
        var prefix: [12]u8 = undefined;
        std.mem.writeInt(u32, prefix[0..4], 0x33444e42, .little);
        @memcpy(prefix[4..8], request[4..8]);
        std.mem.writeInt(u32, prefix[8..12], op | (if (reuse_plan) @as(u32, 0x80000000) else 0), .little);
        const sent_len = if (reuse_plan) plan_offset else request.len;
        try child.stdin.?.writeAll(&prefix);
        try child.stdin.?.writeAll(request[12..sent_len]);
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
        errdefer a.free(values);
        try self.remember(request, values, hash, config.cache_bytes / config.workers);
        if (has_plan and !reuse_plan) {
            const saved = try std.heap.page_allocator.dupe(u8, plan);
            std.heap.page_allocator.free(self.last_plan);
            self.last_plan = saved;
        }
        if (reuse_plan) _ = plan_reuses.fetchAdd(1, .monotonic);
        if (op < requests.len) _ = requests[op].fetchAdd(1, .monotonic);
        _ = sent_bytes.fetchAdd(sent_len, .monotonic);
        _ = received_bytes.fetchAdd(bytes.len, .monotonic);
        return values;
    }
};

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

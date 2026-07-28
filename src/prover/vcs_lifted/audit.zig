//! TEMPORARY audit instrumentation for the lifted Merkle commit pipeline.
//!
//! Gated behind `STWO_MERKLE_AUDIT=1`. Reverted before the increment lands.

const std = @import("std");
const builtin = @import("builtin");

var enabled_once = std.once(detect);
var enabled_flag: bool = false;

fn detect() void {
    if (comptime builtin.is_test) return;
    const raw = std.process.getEnvVarOwned(std.heap.page_allocator, "STWO_MERKLE_AUDIT") catch return;
    defer std.heap.page_allocator.free(raw);
    enabled_flag = std.mem.eql(u8, raw, "1");
}

pub fn enabled() bool {
    enabled_once.call();
    return enabled_flag;
}

pub const Timer = struct {
    start: std.time.Instant,

    pub fn begin() Timer {
        return .{ .start = std.time.Instant.now() catch unreachable };
    }

    pub fn endNs(self: Timer) u64 {
        const now = std.time.Instant.now() catch return 0;
        return now.since(self.start);
    }
};

var mutex: std.Thread.Mutex = .{};

pub fn note(comptime fmt: []const u8, args: anytype) void {
    if (!enabled()) return;
    mutex.lock();
    defer mutex.unlock();
    var buf: [512]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "MERKLE_AUDIT " ++ fmt ++ "\n", args) catch return;
    std.fs.File.stderr().writeAll(line) catch {};
}

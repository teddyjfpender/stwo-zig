//! Platform-explicit peak-RSS sampling for the isolated H-010 runner.
//!
//! Darwin reports `ru_maxrss` in bytes; Linux reports KiB. The admission
//! probe allocates and page-touches a known region so a unit mistake cannot
//! survive as plausible-looking receipt data.

const std = @import("std");
const builtin = @import("builtin");
const protocol = @import("poseidon_layout_benchmark_protocol.zig");

const page_bytes: usize = 4096;
pub const probe_allocation_bytes: usize = 64 * 1024 * 1024;

pub const Peak = struct {
    native_value: u64,
    unit: protocol.RssUnit,
    bytes: u64,
    source: []const u8,
};

pub const Probe = struct {
    allocated_bytes: u64,
    delta_bytes: u64,
    source: []const u8,
};

pub fn checkAdapter(allocator: std.mem.Allocator) !Probe {
    const before = try sample();
    const allocation = try allocator.alloc(u8, probe_allocation_bytes);
    defer allocator.free(allocation);
    touchPages(allocation);
    const after = try sample();
    if (before.unit != after.unit or
        !std.mem.eql(u8, before.source, after.source) or
        after.bytes <= before.bytes)
    {
        return error.ResourceUsageProbeFailed;
    }
    const delta = after.bytes - before.bytes;
    if (delta < probe_allocation_bytes / 2)
        return error.ResourceUsageProbeFailed;
    return .{
        .allocated_bytes = probe_allocation_bytes,
        .delta_bytes = delta,
        .source = after.source,
    };
}

pub fn sample() !Peak {
    const resource_usage = std.posix.getrusage(0);
    if (resource_usage.maxrss <= 0) return error.InvalidPeakRss;
    const native: u64 = @intCast(resource_usage.maxrss);
    const unit: protocol.RssUnit = switch (builtin.os.tag) {
        .linux => .kib,
        .macos, .ios => .bytes,
        else => return error.ResourceUsageUnavailable,
    };
    return .{
        .native_value = native,
        .unit = unit,
        .bytes = try protocol.normalizePeakRss(native, unit),
        .source = switch (builtin.os.tag) {
            .linux => "getrusage-self-maxrss-kib-normalized-bytes",
            .macos, .ios => "getrusage-self-maxrss-native-bytes",
            else => unreachable,
        },
    };
}

fn touchPages(allocation: []u8) void {
    var offset: usize = 0;
    while (offset < allocation.len) : (offset += page_bytes) {
        const byte: *volatile u8 = &allocation[offset];
        byte.* = @truncate(offset / page_bytes);
    }
    if (allocation.len != 0) {
        const last: *volatile u8 = &allocation[allocation.len - 1];
        last.* = 0xa5;
    }
}

test "H-010 RSS adapter returns a positive normalized process sample" {
    const peak = try sample();
    try std.testing.expect(peak.native_value > 0);
    try std.testing.expect(peak.bytes >= peak.native_value);
    try std.testing.expect(peak.source.len != 0);
}

test "H-010 RSS admission probe page-touches a known allocation" {
    const allocation = try std.testing.allocator.alloc(u8, page_bytes * 3 + 2);
    defer std.testing.allocator.free(allocation);
    touchPages(allocation);
    try std.testing.expectEqual(@as(u8, 0), allocation[0]);
    try std.testing.expectEqual(@as(u8, 1), allocation[page_bytes]);
    try std.testing.expectEqual(@as(u8, 2), allocation[page_bytes * 2]);
    try std.testing.expectEqual(@as(u8, 3), allocation[page_bytes * 3]);
    try std.testing.expectEqual(@as(u8, 0xa5), allocation[allocation.len - 1]);
}

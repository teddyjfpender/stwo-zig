//! Transport-only conversion of the canonical child frame compiler's anchors.
//! Packet words remain untrusted input; device replay outputs remain device
//! values. The original parent equations authenticate their eventual uses.
const std = @import("std");
const Frames = @import("resident_parent_child_frames_v1.zig");
const Routes = @import("resident_parent_value_routes_v1.zig");
const Schedule = @import("resident_parent_schedule_v1.zig");
pub const Layout = struct { packet_words: u32, output_first: u32, output_words: u32, trace_first: u32, trace_words: u32, ready_phase: u32 };
pub fn append(a: std.mem.Allocator, out: *std.ArrayList(Schedule.Seed), anchors: []const Frames.Anchor, layout: Layout) !void {
    for (anchors) |anchor| {
        const source = try word(anchor.value, layout);
        var coordinates: [4]Routes.Source = @splat(Routes.Source.constant(0));
        switch (anchor.encoding) {
            .scalar => coordinates[0] = source,
            .bytes4 => for (&coordinates, 0..) |*dest, j| {
                dest.* = switch (anchor.value.kind) {
                    .literal => Routes.Source.constant((anchor.value.index >> @as(u5, @intCast(j * 8))) & 255),
                    .packet => .{ .kind = @intFromEnum(Routes.Kind.raw_byte), .index = anchor.value.index * 4 + @as(u32, @intCast(j)) },
                    .trace, .output => Routes.Source.residentByte(source.index, @intCast(j), layout.ready_phase),
                };
            },
        }
        try out.append(a, .{ .key = (@as(u64, anchor.circuit) << 32) | anchor.wire, .coordinates = coordinates, .word = if (anchor.encoding == .bytes4) source else null });
    }
}
pub fn derive(a: std.mem.Allocator, frames: *const Frames.Owned, layout: Layout, extra: []const Frames.Anchor) ![]Schedule.Seed {
    var out: std.ArrayList(Schedule.Seed) = .empty;
    errdefer out.deinit(a);
    try append(a, &out, frames.ports, layout);
    for (frames.frames) |f| try append(a, &out, f.sources, layout);
    try append(a, &out, extra, layout);
    return out.toOwnedSlice(a);
}
fn word(v: Frames.Word, l: Layout) !Routes.Source {
    return switch (v.kind) {
        .literal => Routes.Source.constant(v.index),
        .packet => blk: {
            if (v.index >= l.packet_words or v.index > std.math.maxInt(u32) / 4) return error.InvalidResidentSeed;
            break :blk Routes.Source.raw(v.index * 4);
        },
        .output => blk: {
            if (v.index >= l.output_words) return error.InvalidResidentSeed;
            break :blk Routes.Source.resident(try std.math.add(u32, l.output_first, v.index), l.ready_phase);
        },
        .trace => blk: {
            if (v.index >= l.trace_words) return error.InvalidResidentSeed;
            break :blk Routes.Source.resident(try std.math.add(u32, l.trace_first, v.index), l.ready_phase);
        },
    };
}
test "resident frame seed transport preserves raw bytes and device output ownership" {
    const a = std.testing.allocator;
    var out: std.ArrayList(Schedule.Seed) = .empty;
    defer out.deinit(a);
    const layout = Layout{ .packet_words = 8, .output_first = 100, .output_words = 8, .trace_first = 200, .trace_words = 40, .ready_phase = 1 };
    const anchors = [_]Frames.Anchor{ .{ .circuit = 7, .wire = 10, .value = .{ .kind = .packet, .index = 3 }, .encoding = .bytes4 }, .{ .circuit = 8, .wire = 11, .value = .{ .kind = .output, .index = 4 }, .encoding = .scalar } };
    try append(a, &out, &anchors, layout);
    try std.testing.expectEqual(@as(u32, 12), out.items[0].word.?.index);
    for (out.items[0].coordinates, 0..) |c, i| {
        try std.testing.expectEqual(@intFromEnum(Routes.Kind.raw_byte), c.kind);
        try std.testing.expectEqual(12 + i, c.index);
    }
    try std.testing.expectEqual(@as(u32, 104), out.items[1].coordinates[0].index);
    try std.testing.expectEqual(@as(?Routes.Source, null), out.items[1].word);
    var bad = anchors;
    bad[0].value.index = 8;
    try std.testing.expectError(error.InvalidResidentSeed, append(a, &out, &bad, layout));
}

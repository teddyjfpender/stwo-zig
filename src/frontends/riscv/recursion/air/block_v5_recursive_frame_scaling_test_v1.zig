//! Pure channel-framing fixtures. No Fresh, proof or authority is created.
const std = @import("std");
const core = @import("stwo_core");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
const Source = @import("../block_v5_requester_public_source_v1.zig");
fn rootFor(index: usize) [32]u8 {
    var root: [32]u8 = @splat(0);
    std.mem.writeInt(u64, root[0..8], @intCast(index), .little);
    root[31] = 1;
    return root;
}
const FramingOnly = struct {
    roots: usize,
    pub fn mix(self: *const @This(), channel: anytype) !void {
        channel.mixU32s(&.{ 0x42355246, 21 });
        for (0..self.roots) |index| channel.mixRoot(rootFor(index));
        channel.mixU64(0x0123456789abcdef);
        channel.mixFelts(&.{core.fields.qm31.QM31.fromBase(core.fields.m31.M31.fromCanonical(17))});
    }
};
test "recursive frame scaling: original tracked native offsets still enforce exact32 root limit" {
    var builder = Frames.Builder{ .allocator = std.testing.allocator };
    defer builder.deinit();
    for (0..32) |index| builder.mixRoot(rootFor(index));
    try builder.check();
    try std.testing.expectEqual(@as(usize, 32), builder.root_count);
    for (builder.root_offsets, 0..) |offset, index| try std.testing.expectEqual(@as(u32, @intCast(8 * index)), offset);
    builder.mixRoot(rootFor(32));
    try std.testing.expectError(error.RecursiveStatementFrameLimit, builder.check());
    try std.testing.expectEqual(@as(usize, 256), builder.data.items.len);
}
test "recursive frame scaling: exact PUBLIC21 recorder covers67 and4096 window roots with original replay digest and transition" {
    const a = std.testing.allocator;
    for ([_]usize{ 32, 67, 4096 }) |windows| {
        const input = FramingOnly{ .roots = windows + 12 };
        var frame = try Source.testing.recordFrame(a, &input, .{});
        defer frame.deinit();
        try std.testing.expectEqual(windows + 15, frame.first.len);
        try std.testing.expectEqual(@as(u32, @intCast(4 + 8 * input.roots)), try Source.testing.transitionCoordinate(&frame));
        var direct = core.channel.blake3.Channel{};
        try input.mix(&direct);
        var replay = core.channel.blake3.Channel{};
        try frame.replay(&replay, frame.first);
        try std.testing.expectEqualSlices(u8, &direct.digestBytes(), &replay.digestBytes());
        for (frame.first[1 .. input.roots + 1], 0..) |step, index| {
            try std.testing.expect(step == .root);
            try std.testing.expectEqual(@as(u32, @intCast(2 + 8 * index)), step.root);
            try std.testing.expectEqualSlices(u8, &rootFor(index), &(try frame.digest(step.root)));
        }
    }
}
test "recursive frame scaling: aggregate words felts and steps still enforce exact original limits" {
    const input = FramingOnly{ .roots = 67 };
    try std.testing.expectError(error.RecursiveStatementFrameLimit, Source.testing.recordFrame(std.testing.allocator, &input, .{ .max_words = 2 + 8 * 67 + 1 }));
    try std.testing.expectError(error.RequesterPublicSourceLimit, Source.testing.recordFrame(std.testing.allocator, &input, .{ .max_steps = 69 }));
    var builder = Frames.Builder{ .allocator = std.testing.allocator, .max_felts = 0, .track_root_offsets = false };
    defer builder.deinit();
    builder.mixRoot(rootFor(0));
    builder.mixFelts(&.{core.fields.qm31.QM31.one()});
    try std.testing.expectError(error.RecursiveStatementFrameLimit, builder.check());
}
fn frameAllocation(a: std.mem.Allocator) !void {
    const input = FramingOnly{ .roots = 67 };
    var frame = try Source.testing.recordFrame(a, &input, .{});
    defer frame.deinit();
    var channel = core.channel.blake3.Channel{};
    try frame.replay(&channel, frame.first);
}
test "recursive frame scaling: every aggregate recording allocation failure releases exact original frame ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, frameAllocation, .{});
}

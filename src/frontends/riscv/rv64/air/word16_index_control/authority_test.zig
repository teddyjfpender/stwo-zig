const std = @import("std");
const core = @import("stwo_core");
const A = @import("authority.zig");
const physical = @import("../word16_cpu/layout.zig").physical;
const M = core.fields.m31.M31;
const allocator = std.testing.allocator;
const add: u32 = 0x002081b3;
fn branch(offset: u13) u32 {
    return 0x00000063 | (@as(u32, (offset >> 11) & 1) << 7) | (@as(u32, (offset >> 1) & 15) << 8) | (@as(u32, (offset >> 5) & 63) << 25) | (@as(u32, offset >> 12) << 31);
}
fn rawPc(authority: *const A.Authority, physical_row: usize) u64 {
    const n = @as(usize, 1) << @intCast(authority.log_size);
    var pc: u64 = 0;
    for (0..4) |i| pc |= @as(u64, authority.fixed[(A.RAW_PC + i) * n + physical_row].v) << @as(u6, @intCast(16 * i));
    return pc;
}
test "index IDs preserve sparse full64 addresses and reject truncation and field aliases" {
    const high: u64 = 0x8000000000000400;
    var authority = try A.Authority.init(allocator, .{ .base = 1024, .words = &.{ add, add }, .addresses = &.{ 1024, high } });
    defer authority.deinit();
    const low_id = try authority.idForPc(1024);
    const high_id = try authority.idForPc(high);
    try std.testing.expect(low_id != high_id);
    try authority.validatePair(high_id, high);
    try std.testing.expectError(error.InvalidIndexAddressPair, authority.validatePair(high_id, high & 0x0000ffffffffffff));
    try std.testing.expectError(error.InvalidIndexAddressPair, authority.validatePair(@as(u64, high_id) + core.fields.m31.Modulus, high));
    try std.testing.expectError(error.UnknownIndexAddress, authority.idForPc(0x1234567800000000));
}
test "index branch rows share one address ID and static endpoint IDs are nonfetchable" {
    var authority = try A.Authority.init(allocator, .{ .base = 1024, .words = &.{ branch(8), add, add } });
    defer authority.deinit();
    const id = try authority.idForPc(1024);
    const fall = try authority.edgeFor(id, false);
    const taken = try authority.edgeFor(id, true);
    try std.testing.expect(fall != taken);
    try std.testing.expectEqual(authority.edges[fall].id, authority.edges[taken].id);
    try std.testing.expectEqual(try authority.idForPc(1028), authority.edges[fall].next_id);
    try std.testing.expectEqual(try authority.idForPc(1032), authority.edges[taken].next_id);
    const next_word_id = try authority.idForPc(1028);
    try std.testing.expect(try authority.edgeFor(next_word_id, false) != next_word_id);
    _ = try authority.idForPc(1036);
    try std.testing.expectError(error.NonfetchableIndexAddress, authority.executableId(1036));
}
test "index canonical padded mapping repeats first full PC rather than inventing PC zero" {
    var authority = try A.Authority.init(allocator, .{ .base = 1024, .words = &.{add} });
    defer authority.deinit();
    const n = @as(usize, 1) << @intCast(authority.log_size);
    for (authority.edges.len..n) |logical| {
        const row = physical(logical, authority.log_size);
        try std.testing.expectEqual(@as(u32, 0), authority.fixed[n + row].v);
        try std.testing.expectEqual(@as(u64, 1024), rawPc(&authority, row));
        try authority.validatePair(authority.fixed[n + row].v, rawPc(&authority, row));
        try std.testing.expect(authority.fixed[row].isZero());
    }
    try std.testing.expectError(error.InvalidIndexAddressPair, authority.validatePair(0, 0));
}
test "index authority retains invalid raw words in full identity and address map" {
    var left = try A.Authority.init(allocator, .{ .base = 1024, .words = &.{ 0, add } });
    defer left.deinit();
    var right = try A.Authority.init(allocator, .{ .base = 1024, .words = &.{ 0xffffffff, add } });
    defer right.deinit();
    try std.testing.expect(!std.mem.eql(u8, &left.identity, &right.identity));
    try std.testing.expectEqualSlices(M, left.fixed, right.fixed);
    try std.testing.expectError(error.NonfetchableIndexAddress, left.executableId(1024));
    try left.validatePair(try left.idForPc(1024), 1024);
    _ = try left.executableId(1028);
}
test "index static next PC wraps full64 before address lookup" {
    const top = std.math.maxInt(u64) - 3;
    var authority = try A.Authority.init(allocator, .{ .base = top, .words = &.{add} });
    defer authority.deinit();
    const id = try authority.executableId(top);
    const edge = authority.edges[try authority.edgeFor(id, false)];
    try std.testing.expectEqual(@as(u64, 0), authority.addresses[edge.next_id]);
    try std.testing.expectError(error.NonfetchableIndexAddress, authority.executableId(0));
}
fn allocationCase(a: std.mem.Allocator) !void {
    var authority = try A.Authority.init(a, .{ .base = 1024, .words = &.{ branch(8), 0, add } });
    defer authority.deinit();
}
test "index authority unwinds all allocation failures including owned slice transfers" {
    try std.testing.checkAllAllocationFailures(allocator, allocationCase, .{});
}

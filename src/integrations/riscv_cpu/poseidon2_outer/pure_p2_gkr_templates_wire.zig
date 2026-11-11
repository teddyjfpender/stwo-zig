//! Bounded transport of legal coefficient-length classes. These bytes select
//! verifier cost only; all dimensions are re-derived from the native roster.
const std = @import("std");
const Shape = @import("pure_p2_gkr_template.zig");
const MAGIC = "OPGKSH01";
pub const MAX_BYTES: usize = 12 + 256 * (2 + Shape.MAX_COEFFICIENT_LENGTHS);
pub const Owned = struct {
    shapes: [][]u8,
    pub fn deinit(self: *Owned, a: std.mem.Allocator) void {
        for (self.shapes) |shape| a.free(shape);
        a.free(self.shapes);
        self.* = undefined;
    }
};
pub fn encode(a: std.mem.Allocator, shapes: []const []const u8) ![]u8 {
    if (shapes.len == 0 or shapes.len > 256) return error.InvalidOpGkrTemplatesCount;
    var n: usize = 12;
    for (shapes) |shape| {
        if (shape.len > Shape.MAX_COEFFICIENT_LENGTHS) return error.InvalidOpGkrTemplatesSize;
        for (shape) |width| if (width > 4) return error.InvalidOpGkrTemplateDegree;
        n += 2 + shape.len;
    }
    const out = try a.alloc(u8, n);
    @memcpy(out[0..8], MAGIC);
    std.mem.writeInt(u32, out[8..12], @intCast(shapes.len), .little);
    var at: usize = 12;
    for (shapes) |shape| {
        std.mem.writeInt(u16, out[at..][0..2], @intCast(shape.len), .little);
        at += 2;
        @memcpy(out[at..][0..shape.len], shape);
        at += shape.len;
    }
    return out;
}
pub fn preflight(bytes: []const u8) !usize {
    if (bytes.len < 12 or bytes.len > MAX_BYTES or !std.mem.eql(u8, bytes[0..8], MAGIC)) return error.InvalidOpGkrTemplatesCount;
    const count = std.mem.readInt(u32, bytes[8..12], .little);
    if (count == 0 or count > 256) return error.InvalidOpGkrTemplatesCount;
    var at: usize = 12;
    for (0..count) |_| {
        if (bytes.len - at < 2) return error.InvalidOpGkrTemplatesSize;
        const n = std.mem.readInt(u16, bytes[at..][0..2], .little);
        at += 2;
        if (n > Shape.MAX_COEFFICIENT_LENGTHS or n > bytes.len - at) return error.InvalidOpGkrTemplatesSize;
        for (bytes[at..][0..n]) |width| if (width > 4) return error.InvalidOpGkrTemplateDegree;
        at += n;
    }
    if (at != bytes.len) return error.InvalidOpGkrTemplatesSize;
    return count;
}
pub fn decode(a: std.mem.Allocator, bytes: []const u8, expected_count: usize) !Owned {
    if (try preflight(bytes) != expected_count) return error.InvalidOpGkrTemplatesCount;
    const shapes = try a.alloc([]u8, expected_count);
    var made: usize = 0;
    errdefer {
        for (shapes[0..made]) |shape| a.free(shape);
        a.free(shapes);
    }
    var at: usize = 12;
    for (shapes) |*shape| {
        const n = std.mem.readInt(u16, bytes[at..][0..2], .little);
        at += 2;
        shape.* = try a.dupe(u8, bytes[at..][0..n]);
        made += 1;
        at += n;
    }
    return .{ .shapes = shapes };
}
test "OP pure P2 GKR templates transport rejects count degree and trailing ambiguity" {
    const a = std.testing.allocator;
    const wire = try encode(a, &.{ &.{ 0, 1, 2, 3, 4 }, &.{ 4, 4, 4 } });
    defer a.free(wire);
    var owned = try decode(a, wire, 2);
    defer owned.deinit(a);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3, 4 }, owned.shapes[0]);
    try std.testing.expectError(error.InvalidOpGkrTemplatesCount, decode(a, wire, 1));
    wire[14] = 5;
    try std.testing.expectError(error.InvalidOpGkrTemplateDegree, decode(a, wire, 2));
    wire[14] = 0;
    const trailing = try a.alloc(u8, wire.len + 1);
    defer a.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try std.testing.expectError(error.InvalidOpGkrTemplatesSize, decode(a, trailing, 2));
    try std.testing.expectError(error.InvalidOpGkrTemplatesSize, decode(a, wire[0 .. wire.len - 1], 2));
}

//! Physical masks derived from the receiver's original captured AIR. Every
//! logical quartic INTER coordinate authenticates both OM31 physical halves.
const std = @import("std");
const C = @import("stwo_cairo_frontend").witness;
const G = C.resident_geometry;
pub const Span = G.Span;
pub const Component = C.composition_bundle.Component;
pub const freeOffsets = G.freeOffsetLists;
pub fn span(c: Component, tree: u32) !Span {
    const original = try G.componentSpan(c, tree);
    if (tree != 2) return original;
    if (original.start % 4 != 0 or original.end % 4 != 0) return error.UnalignedOm31InteractionSpan;
    return .{ .start = try std.math.mul(usize, original.start, 2), .end = try std.math.mul(usize, original.end, 2) };
}
pub fn offsets(a: std.mem.Allocator, c: Component, tree: u32) ![]std.ArrayList(i32) {
    const logical = try G.componentOffsets(a, c, tree);
    if (tree != 2) return logical;
    defer freeOffsets(a, logical);
    if (logical.len % 4 != 0) return error.UnalignedOm31InteractionSpan;
    const physical = try a.alloc(std.ArrayList(i32), try std.math.mul(usize, logical.len, 2));
    for (physical) |*list| list.* = .empty;
    errdefer freeOffsets(a, physical);
    for (logical, 0..) |list, i| {
        const low = 8 * (i / 4) + i % 4;
        try physical[low].appendSlice(a, list.items);
        try physical[low + 4].appendSlice(a, list.items);
    }
    return physical;
}

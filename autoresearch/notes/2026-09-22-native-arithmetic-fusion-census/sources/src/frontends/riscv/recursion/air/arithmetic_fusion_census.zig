//! Read-only use of the canonical fusion matchers; never alters graph authority.
const std = @import("std");
const lowering = @import("verifier_arithmetic_lowering.zig");
const dot4 = @import("detached_opening_accumulation_plan.zig");
const fma = @import("detached_arithmetic_fusion_plan.zig");
pub const Census = struct {
    nodes: usize,
    multiply: usize = 0,
    linear: usize = 0,
    inverse: usize = 0,
    dot4_matches: usize,
    fma_matches: usize,
    pub fn removedRows(self: Census) usize {
        return 7 * self.dot4_matches + self.fma_matches;
    }
};
pub fn inspect(a: std.mem.Allocator, lane: lowering.Lane) !Census {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    const uses = try lowering.computeLaneUseCountsInto(lane, try temp.alloc(u32, lane.graph.nodes.len));
    const reserved = try temp.alloc(bool, lane.graph.nodes.len);
    @memset(reserved, false);
    var dots: std.ArrayList(dot4.Match) = .empty;
    try dot4.reserve(&dots, temp, lane.graph, uses, reserved);
    var singles: std.ArrayList(fma.Match) = .empty;
    try fma.reserve(&singles, temp, lane.graph, uses, reserved);
    var result = Census{ .nodes = lane.graph.nodes.len, .dot4_matches = dots.items.len, .fma_matches = singles.items.len };
    for (lane.graph.nodes) |node| switch (node.op) {
        .mul => result.multiply += 1,
        .add, .sub, .neg => result.linear += 1,
        .inverse => result.inverse += 1,
        else => {},
    };
    return result;
}

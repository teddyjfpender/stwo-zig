//! Compare the former independent paths with the shared topology used by hash
//! emission. Input schedules are authenticated before geometry is constructed.
const std = @import("std");
const topology = @import("blake3_shared_path_topology.zig");
const plan = @import("blake3_commitment_plan.zig");
pub const Geometry = struct {
    words: usize,
    independent_compressions: usize,
    shared_compressions: usize,
    /// Actual AIR compressions; public ROM is authenticated in preprocessing.
    proved_compressions: usize,
    leaves: usize,
    parents: usize,
    frontier: usize,
};
pub fn measure(a: std.mem.Allocator, admission: plan.Admission) ![3]Geometry {
    try admission.validate();
    var addresses: std.ArrayList(u32) = .empty;
    defer addresses.deinit(a);
    var result: [3]Geometry = undefined;
    // Separate roots retain separate graphs, even if their digests coincide.
    for (&result, 0..) |*geometry, group| {
        addresses.clearRetainingCapacity();
        if (group == 0) {
            for (admission.plan.programs) |item| for (0..4) |byte| {
                try addresses.append(a, item.address + @as(u32, @intCast(byte)));
            };
        } else {
            for (admission.plan.memories) |item| {
                if ((group == 1) != (item.direction == .initial)) continue;
                for (0..4) |byte| try addresses.append(a, item.address + @as(u32, @intCast(byte)));
            }
        }
        geometry.* = .{ .words = addresses.items.len / 4, .independent_compressions = try std.math.mul(usize, addresses.items.len, 1 + 2 * topology.DEPTH), .shared_compressions = 0, .proved_compressions = 0, .leaves = 0, .parents = 0, .frontier = 0 };
        if (addresses.items.len == 0) continue;
        var graph = try topology.Graph.init(a, addresses.items);
        defer graph.deinit();
        geometry.shared_compressions = try graph.compressionCount();
        geometry.proved_compressions = if (group == 0) 0 else geometry.shared_compressions;
        geometry.leaves = graph.leaf_count;
        geometry.parents = graph.nodes.len - graph.leaf_count;
        geometry.frontier = graph.frontier.len;
    }
    return result;
}

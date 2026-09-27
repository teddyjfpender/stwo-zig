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
    // The two memory roots use the same union topology. `words` still counts
    // actual lookup boundaries, while leaves/compressions include fixed-zero
    // leaves on a public-custody side missing its lookup boundary.
    for (&result, 0..) |*geometry, group| {
        addresses.clearRetainingCapacity();
        if (group == 0) {
            for (admission.plan.programs) |item| for (0..4) |byte| {
                try addresses.append(a, item.address + @as(u32, @intCast(byte)));
            };
        } else {
            for (admission.plan.memories) |item| {
                try addresses.append(a, try @import("../air/memory_commitment/blake3_state_tree.zig").memoryIndex(item.address));
            }
            std.mem.sort(u32, addresses.items, {}, std.sort.asc(u32));
            var count: usize = 0;
            for (addresses.items) |address| {
                if (count == 0 or addresses.items[count - 1] != address) {
                    addresses.items[count] = address;
                    count += 1;
                }
            }
            addresses.items.len = count;
        }
        var words: usize = if (group == 0) addresses.items.len / 4 else 0;
        if (group != 0) for (admission.plan.memories) |item| {
            if ((group == 1) == (item.direction == .initial)) words += 1;
        };
        geometry.* = .{ .words = words, .independent_compressions = try std.math.mul(usize, addresses.items.len, 1 + 2 * topology.DEPTH), .shared_compressions = 0, .proved_compressions = 0, .leaves = 0, .parents = 0, .frontier = 0 };
        if (addresses.items.len == 0) continue;
        var graph = try topology.Graph.init(a, addresses.items);
        defer graph.deinit();
        geometry.shared_compressions = try graph.compressionCount();
        geometry.proved_compressions = 0;
        if (group != 0) {
            const known = try a.alloc(bool, graph.nodes.len);
            defer a.free(known);
            var cursor: usize = 0;
            if (group == 2) while (cursor < admission.plan.memories.len and admission.plan.memories[cursor].direction == .initial) {
                cursor += 1;
            };
            for (graph.nodes, 0..) |node, index| {
                known[index] = switch (node.source) {
                    .leaf => |i| blk: {
                        const address = addresses.items[i] * 4;
                        while (cursor < admission.plan.memories.len and
                            ((group == 1) == (admission.plan.memories[cursor].direction == .initial)) and
                            admission.plan.memories[cursor].address < address)
                        {
                            cursor += 1;
                        }
                        break :blk !(cursor < admission.plan.memories.len and
                            ((group == 1) == (admission.plan.memories[cursor].direction == .initial)) and
                            admission.plan.memories[cursor].address == address);
                    },
                    .children => |children| blk: {
                        for (children) |child| switch (child) {
                            .frontier => break :blk false,
                            .computed => |i| if (!known[i]) break :blk false,
                        };
                        break :blk true;
                    },
                };
                if (!known[index]) geometry.proved_compressions += if (node.source == .leaf) @as(usize, 1) else 2;
            }
        }
        geometry.leaves = graph.leaf_count;
        geometry.parents = graph.nodes.len - graph.leaf_count;
        geometry.frontier = graph.frontier.len;
    }
    return result;
}

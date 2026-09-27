//! Derive sample scalar/secure links from canonical DEEP input bindings.
const std = @import("std");
const deep = @import("pcs_deep_circuit.zig");
pub const Link = struct { composition: u32, deep: [4]u32 };
pub fn build(a: std.mem.Allocator, graph: *const deep.Circuit, count: usize, first: u32) ![]Link {
    const links = try a.alloc(Link, count);
    errdefer a.free(links);
    const missing = std.math.maxInt(u32);
    for (links, 0..) |*link, i| link.* = .{ .composition = try std.math.add(u32, first, @intCast(i)), .deep = @splat(missing) };
    for (graph.bindings) |binding| switch (binding.source) {
        .sampled_value_word => |source| {
            if (source.sample >= count or source.word >= 4 or links[source.sample].deep[source.word] != missing) return error.InvalidParentSampleLink;
            links[source.sample].deep[source.word] = binding.node_id;
        },
        else => {},
    };
    for (links) |link| for (link.deep) |node| if (node == missing) return error.InvalidParentSampleLink;
    return links;
}

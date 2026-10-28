//! Diagnostic only: split actual planned G work by origin. Topology dedup is
//! an optimistic work bound, not authority to omit any authenticated opening.
const std = @import("std");
const core = @import("stwo_core");
const sharing = @import("blake3_path_sharing_census.zig");
const Cache = @import("blake3_merkle_plan_cache.zig").Cache;

const Work = struct {
    leaf: usize = 0,
    subtree: usize = 0,
    upper: usize = 0,
    unique_leaf: usize = 0,
    unique_subtree: usize = 0,
    unique_upper: usize = 0,
    fn total(self: Work) usize {
        return self.leaf + self.subtree + self.upper;
    }
};

pub fn report(a: std.mem.Allocator, capture: anytype, transcript_g: usize, paths_g: usize) !void {
    var cache = Cache.init(a);
    defer cache.deinit();
    var sum = Work{};
    for (capture.column_log_sizes, capture.trace_paths, 0..) |columns, path, i| {
        const work = try tree(a, &cache, "trace", i, columns.len, 1, path.positions, path.path_depth, 0);
        inline for (std.meta.fields(Work)) |f| @field(sum, f.name) += @field(work, f.name);
    }
    for (capture.fri.layers, 0..) |layer, i| {
        const width: u32 = if (layer.fold_step > 1) 4 else 1;
        const work = try tree(a, &cache, "fri", i, width * 4, layer.fold_width / width, layer.positions, layer.path_depth, layer.fold_step);
        inline for (std.meta.fields(Work)) |f| @field(sum, f.name) += @field(work, f.name);
    }
    if (sum.total() != paths_g) return error.HashWorkCensusMismatch;
    std.debug.print("BLAKE3_HASH_WORK_TOTAL transcript_g={d} leaf_g={d} subtree_g={d} upper_g={d} paths_g={d} unique_leaf_g={d} unique_subtree_g={d} unique_upper_g={d} total_g={d}\n", .{ transcript_g, sum.leaf, sum.subtree, sum.upper, paths_g, sum.unique_leaf, sum.unique_subtree, sum.unique_upper, transcript_g + paths_g });
}

fn tree(a: std.mem.Allocator, cache: *Cache, kind: []const u8, index: usize, words: usize, leaves: usize, positions: []const usize, depth: u32, shift: u32) !Work {
    const topology = try sharing.inspect(a, positions, depth, shift);
    const leaf_bytes = try std.math.add(usize, core.channel.blake3.PROTOCOL_ID.len + 1, try std.math.mul(usize, words, 4));
    const plans = try cache.get(leaf_bytes);
    const queries = positions.len;
    // This is the current two-level fixed frontier, not ideal topology sharing.
    const removed = if (depth >= 2 and queries > 1) 2 * queries - 3 else if (depth == 1 and queries > 1) queries - 1 else 0;
    const work = Work{
        .leaf = queries * leaves * plans.leaf.g.len,
        .subtree = queries * (leaves - 1) * plans.node.g.len,
        .upper = (topology.upper_hashes - removed) * plans.node.g.len,
        .unique_leaf = topology.unique_groups * leaves * plans.leaf.g.len,
        .unique_subtree = topology.unique_groups * (leaves - 1) * plans.node.g.len,
        .unique_upper = topology.unique_upper_hashes * plans.node.g.len,
    };
    std.debug.print("BLAKE3_HASH_WORK kind={s} tree={d} words={d} leaves={d} depth={d} queries={d} unique_groups={d} leaf_bytes={d} leaf_g={d} subtree_g={d} upper_g={d} unique_leaf_g={d} unique_subtree_g={d} unique_upper_g={d} node_g_per_hash={d}\n", .{ kind, index, words, leaves, depth, queries, topology.unique_groups, leaf_bytes, work.leaf, work.subtree, work.upper, work.unique_leaf, work.unique_subtree, work.unique_upper, plans.node.g.len });
    return work;
}

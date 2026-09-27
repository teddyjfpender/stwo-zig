//! Canonical dyadic sharding for a complete sparse initial RW tree.
//! Each nonempty shard proves its own complete subtree; the receiver folds
//! public shard roots with canonical empty subtrees to the admitted full root.
const std = @import("std");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
pub const MAX_LEAVES_PER_SHARD: usize = 4096;
pub const Shard = struct {
    coordinate: tree.Coordinate,
    first: usize,
    end: usize,
};
pub const Root = struct { coordinate: tree.Coordinate, digest: tree.Digest };

pub fn plan(a: std.mem.Allocator, addresses: []const u32) ![]Shard {
    if (addresses.len == 0) return error.EmptySparseShardRoster;
    for (addresses, 0..) |address, i| {
        if (address >= tree.MEMORY_WORD_LIMIT or (i != 0 and addresses[i - 1] >= address)) return error.InvalidSparseShardAddresses;
    }
    var out: std.ArrayList(Shard) = .empty;
    errdefer out.deinit(a);
    try split(a, addresses, .{ .level = tree.DEPTH, .index = 0 }, 0, addresses.len, &out);
    return out.toOwnedSlice(a);
}

fn split(a: std.mem.Allocator, addresses: []const u32, coordinate: tree.Coordinate, first: usize, end: usize, out: *std.ArrayList(Shard)) !void {
    if (first == end) return;
    if (end - first <= MAX_LEAVES_PER_SHARD) {
        try out.append(a, .{ .coordinate = coordinate, .first = first, .end = end });
        return;
    }
    if (coordinate.level == 0) return error.InvalidSparseShardPlan;
    const child_level = coordinate.level - 1;
    const right_start = (@as(u64, coordinate.index) * 2 + 1) << @intCast(child_level);
    const middle = lowerBound(addresses, first, end, right_start);
    try split(a, addresses, .{ .level = child_level, .index = coordinate.index * 2 }, first, middle, out);
    try split(a, addresses, .{ .level = child_level, .index = coordinate.index * 2 + 1 }, middle, end, out);
}

fn lowerBound(addresses: []const u32, first: usize, end: usize, target: u64) usize {
    var lo = first;
    var hi = end;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (addresses[mid] < target) lo = mid + 1 else hi = mid;
    }
    return lo;
}

pub fn rootsForPlan(a: std.mem.Allocator, leaves: []const tree.Leaf, shards: []const Shard) ![]Root {
    const hasher = tree.TreeHasher.init(.memory);
    const result = try a.alloc(Root, shards.len);
    errdefer a.free(result);
    for (shards, result) |shard, *out| {
        var digest: [1]tree.Digest = undefined;
        try hasher.subtreeRoots(leaves, &.{shard.coordinate}, &digest);
        out.* = .{ .coordinate = shard.coordinate, .digest = digest[0] };
    }
    return result;
}

/// Recompute the full commitment from independently verified public shard
/// roots. No hidden nonzero leaf can fit an omitted range: it is folded as the
/// domain-separated default subtree digest, and the final root is pinned.
pub fn assemble(roots: []const Root) !tree.Digest {
    if (roots.len == 0) return error.EmptySparseShardRoster;
    var at: usize = 0;
    const hasher = tree.TreeHasher.init(.memory);
    const digest = try fold(&hasher, roots, &at, .{ .level = tree.DEPTH, .index = 0 });
    if (at != roots.len) return error.NoncanonicalSparseShardRoster;
    return digest;
}

fn fold(hasher: *const tree.TreeHasher, roots: []const Root, at: *usize, coordinate: tree.Coordinate) !tree.Digest {
    if (at.* == roots.len) return hasher.defaults[tree.DEPTH - coordinate.level];
    const selected = roots[at.*].coordinate;
    const current_start = @as(u64, coordinate.index) << @intCast(coordinate.level);
    const current_end = current_start + (@as(u64, 1) << @intCast(coordinate.level));
    const selected_start = @as(u64, selected.index) << @intCast(selected.level);
    const selected_end = selected_start + (@as(u64, 1) << @intCast(selected.level));
    if (selected_start >= current_end) return hasher.defaults[tree.DEPTH - coordinate.level];
    if (selected_start < current_start or selected_end > current_end or selected.level > coordinate.level) return error.NoncanonicalSparseShardRoster;
    if (selected.level == coordinate.level) {
        if (selected.index != coordinate.index) return error.NoncanonicalSparseShardRoster;
        at.* += 1;
        return roots[at.* - 1].digest;
    }
    if (coordinate.level == 0) return error.NoncanonicalSparseShardRoster;
    const child_level = coordinate.level - 1;
    const left = try fold(hasher, roots, at, .{ .level = child_level, .index = coordinate.index * 2 });
    const right = try fold(hasher, roots, at, .{ .level = child_level, .index = coordinate.index * 2 + 1 });
    return hasher.pair(left, right);
}

test "dyadic shard roots recompose exact sparse memory root and reject overlap" {
    const a = std.testing.allocator;
    const leaves = [_]tree.Leaf{ .{ .index = 1024, .value = 11 }, .{ .index = 2048, .value = 22 } };
    const addresses = [_]u32{ 1024, 2048 };
    const shards = try plan(a, &addresses);
    defer a.free(shards);
    try std.testing.expectEqual(@as(usize, 1), shards.len);
    const whole = try rootsForPlan(a, &leaves, shards);
    defer a.free(whole);
    try std.testing.expectEqualDeep(try tree.TreeHasher.init(.memory).root(&leaves), try assemble(whole));
    const hasher = tree.TreeHasher.init(.memory);
    var left: [1]tree.Digest = undefined;
    var right: [1]tree.Digest = undefined;
    try hasher.subtreeRoots(&leaves, &.{.{ .level = 11, .index = 0 }}, &left);
    try hasher.subtreeRoots(&leaves, &.{.{ .level = 11, .index = 1 }}, &right);
    const split_roots = [_]Root{ .{ .coordinate = .{ .level = 11, .index = 0 }, .digest = left[0] }, .{ .coordinate = .{ .level = 11, .index = 1 }, .digest = right[0] } };
    try std.testing.expectEqualDeep(try hasher.root(&leaves), try assemble(&split_roots));
    try std.testing.expectError(error.NoncanonicalSparseShardRoster, assemble(&.{ split_roots[0], split_roots[0] }));
    var changed = split_roots;
    changed[0].digest.bytes[0] ^= 1;
    try std.testing.expect(!std.meta.eql(try hasher.root(&leaves), try assemble(&changed)));
}

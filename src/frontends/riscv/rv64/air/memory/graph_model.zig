//! Exact-integer model of the PRIVATE graph argument under construction.
//! It checks topology/coverage only. Digest values are opaque: permutation AIR,
//! cell/CPU bindings, permission certificates and receiver authority are separate
//! obligations. Passing this model is not a STARK or continuation admission.
const std = @import("std");
pub const Digest = [9]u32;
pub const MAX_RECORDS = 1 << 24; // At most four unit contributions/record < M31.
pub const Node = struct { height: u6, index: u64, left: Digest, right: Digest, digest: Digest, reuse: bool = false };
pub const Leaf = struct { index: u64, before: Digest, after: Digest, changed: bool, reuse: bool = false };
pub const Side = struct { height: u6, index: u64, digest: Digest, reuse: bool = false };
const Key = struct { epoch: u1, height: u6, index: u64, digest: Digest };
const Counts = std.AutoHashMap(Key, i32);

fn position(depth: u6, height: u6, index: u64) !void {
    if (height > depth or index >= @as(u64, 1) << (depth - height)) return error.InvalidRamGraphPosition;
}
fn add(counts: *Counts, epoch: u1, height: u6, index: u64, digest: Digest, weight: i32) !void {
    for (digest) |word| if (word >= 0x7fff_ffff) return error.NoncanonicalRamGraphDigest;
    const entry = try counts.getOrPut(.{ .epoch = epoch, .height = height, .index = index, .digest = digest });
    if (!entry.found_existing) entry.value_ptr.* = 0;
    entry.value_ptr.* += weight;
}

/// Each BEFORE record supplies exactly once unconditionally; reuse supplies
/// its SAME authenticated value to epoch1. No after-only Side can be expressed.
pub fn verify(a: std.mem.Allocator, depth: u6, before_root: Digest, after_root: Digest, before: []const Node, after: []const Node, leaves: []const Leaf, sides: []const Side) !void {
    if (depth == 0 or depth > 55) return error.InvalidRamGraphDepth;
    const records = try std.math.add(usize, try std.math.add(usize, before.len, after.len), try std.math.add(usize, leaves.len, sides.len));
    if (records > MAX_RECORDS) return error.RamGraphResourceLimit;
    var counts = Counts.init(a);
    defer counts.deinit();
    try add(&counts, 0, depth, 0, before_root, 1);
    try add(&counts, 1, depth, 0, after_root, 1);
    for (before) |node| {
        try position(depth, node.height, node.index);
        if (node.height == 0) return error.InvalidRamGraphPosition;
        try add(&counts, 0, node.height, node.index, node.digest, -1);
        if (node.reuse) try add(&counts, 1, node.height, node.index, node.digest, -1);
        try add(&counts, 0, node.height - 1, 2 * node.index, node.left, 1);
        try add(&counts, 0, node.height - 1, 2 * node.index + 1, node.right, 1);
    }
    for (after) |node| {
        try position(depth, node.height, node.index);
        if (node.height == 0 or node.reuse) return error.InvalidRamGraphPosition;
        try add(&counts, 1, node.height, node.index, node.digest, -1);
        try add(&counts, 1, node.height - 1, 2 * node.index, node.left, 1);
        try add(&counts, 1, node.height - 1, 2 * node.index + 1, node.right, 1);
    }
    for (leaves) |leaf| {
        try position(depth, 0, leaf.index);
        if ((leaf.changed and leaf.reuse) or (!leaf.changed and !std.meta.eql(leaf.before, leaf.after))) return error.InvalidRamGraphLeaf;
        try add(&counts, 0, 0, leaf.index, leaf.before, -1);
        if (leaf.changed) try add(&counts, 1, 0, leaf.index, leaf.after, -1) else if (leaf.reuse) try add(&counts, 1, 0, leaf.index, leaf.before, -1);
    }
    for (sides) |side| {
        try position(depth, side.height, side.index);
        if (side.height == depth) return error.UnhashedRamGraphRoot;
        try add(&counts, 0, side.height, side.index, side.digest, -1);
        if (side.reuse) try add(&counts, 1, side.height, side.index, side.digest, -1);
    }
    var values = counts.valueIterator();
    while (values.next()) |count| if (count.* != 0) return error.UnbalancedRamGraph;
}

test "RV64 private RAM graph model: before-root coverage authenticates changed and reused after children" {
    const a = std.testing.allocator;
    const left: Digest = @splat(1);
    const right: Digest = @splat(2);
    const changed: Digest = @splat(3);
    const before_root: Digest = @splat(4);
    const after_root: Digest = @splat(5);
    const before = [_]Node{.{ .height = 1, .index = 0, .left = left, .right = right, .digest = before_root }};
    const after = [_]Node{.{ .height = 1, .index = 0, .left = changed, .right = right, .digest = after_root }};
    const leaves = [_]Leaf{.{ .index = 0, .before = left, .after = changed, .changed = true }};
    const sides = [_]Side{.{ .height = 0, .index = 1, .digest = right, .reuse = true }};
    try verify(a, 1, before_root, after_root, &before, &after, &leaves, &sides);
    const orphan: Digest = @splat(6);
    const forged_after = [_]Node{.{ .height = 1, .index = 0, .left = orphan, .right = right, .digest = after_root }};
    const forged_sides = [_]Side{ sides[0], .{ .height = 0, .index = 0, .digest = orphan, .reuse = true } };
    const read_only = [_]Leaf{.{ .index = 0, .before = left, .after = left, .changed = false }};
    // With an unsafe after-only side, ALL other equations would balance.
    // Its unconditional BEFORE supply is the sole orphan in this attack.
    try std.testing.expectError(error.UnbalancedRamGraph, verify(a, 1, before_root, after_root, &before, &forged_after, &read_only, &forged_sides));
    try std.testing.expectError(error.UnbalancedRamGraph, verify(a, 1, before_root, after_root, &before, &after, &leaves, &.{}));
}

test "RV64 private RAM graph model: read-only openings can reuse an authenticated computed subtree" {
    const a = std.testing.allocator;
    const root: Digest = @splat(7);
    const left: Digest = @splat(8);
    const right: Digest = @splat(9);
    const before = [_]Node{.{ .height = 1, .index = 0, .left = left, .right = right, .digest = root, .reuse = true }};
    try verify(a, 1, root, root, &before, &.{}, &.{.{ .index = 0, .before = left, .after = left, .changed = false }}, &.{.{ .height = 0, .index = 1, .digest = right }});
    try std.testing.expectError(error.UnhashedRamGraphRoot, verify(a, 1, root, root, &.{}, &.{}, &.{}, &.{.{ .height = 1, .index = 0, .digest = root, .reuse = true }}));
}

test "RV64 private RAM graph model: high positions and duplicate/orphan supplies cannot alias" {
    const a = std.testing.allocator;
    const root: Digest = @splat(1);
    try std.testing.expectError(error.InvalidRamGraphPosition, verify(a, 55, root, root, &.{}, &.{}, &.{.{ .index = @as(u64, 1) << 55, .before = root, .after = root, .changed = false }}, &.{}));
    try std.testing.expectError(error.UnbalancedRamGraph, verify(a, 55, root, root, &.{}, &.{}, &.{.{ .index = (@as(u64, 1) << 55) - 1, .before = root, .after = root, .changed = false, .reuse = true }}, &.{}));
}

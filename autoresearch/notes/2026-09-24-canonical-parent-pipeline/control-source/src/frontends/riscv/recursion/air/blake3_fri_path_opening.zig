//! Recover one original leaf path from a verifier-owned FRI folding-group capture.
//! The returned sibling digests are witness data: this adapter does not constrain
//! the other folding-group values to recursive arithmetic wires.
const std = @import("std");
const core = @import("stwo_core");
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const M31 = core.fields.m31.M31;
const Layer = core.fri.FriLayerQueryCapture(H);
pub const Opening = struct {
    allocator: std.mem.Allocator,
    leaf: []M31,
    siblings: []H.Hash,
    index: u32,
    depth: u5,
    pub fn deinit(self: *Opening) void {
        self.allocator.free(self.leaf);
        self.allocator.free(self.siblings);
        self.* = undefined;
    }
};
pub fn firstLeaf(a: std.mem.Allocator, layer: Layer, q: usize) !Opening {
    const fail = error.InvalidBlake3FriCapture;
    if (layer.fold_step == 0 or layer.fold_step > 31 or q >= layer.query_count) return fail;
    const width: usize = @as(usize, 1) << @as(u5, @intCast(layer.fold_step));
    const packed_log: u32 = if (layer.fold_step > 1) core.fri.LOG_PACKED_LEAF_SIZE else 0;
    if (packed_log > layer.fold_step or layer.fold_width != width) return fail;
    const subtree = layer.fold_step - packed_log;
    const depth = std.math.add(u32, layer.path_depth, subtree) catch return fail;
    const domain_log = std.math.add(u32, layer.path_depth, layer.fold_step) catch return fail;
    if (depth > 31 or domain_log > 31 or layer.positions.len != layer.query_count or
        layer.values.len != (std.math.mul(usize, layer.query_count, width) catch return fail) or
        layer.siblings.len != (std.math.mul(usize, layer.query_count, layer.path_depth) catch return fail)) return fail;
    const position = layer.positions[q];
    if (position >= @as(usize, 1) << @as(u5, @intCast(domain_log))) return fail;
    const leaf_width: usize = @as(usize, 1) << @as(u5, @intCast(packed_log));
    const leaf = try a.alloc(M31, leaf_width * 4);
    errdefer a.free(leaf);
    const siblings = try a.alloc(H.Hash, depth);
    errdefer a.free(siblings);
    const hashes = try a.alloc(H.Hash, width / leaf_width);
    defer a.free(hashes);
    const values = layer.queryValues(q);
    for (hashes, 0..) |*digest, i| {
        for (values[i * leaf_width ..][0..leaf_width], 0..) |value, j| @memcpy(leaf[j * 4 ..][0..4], &value.toM31Array());
        var hasher = H.defaultWithInitialState();
        hasher.updateLeaf(leaf);
        digest.* = hasher.finalize();
    }
    var count = hashes.len;
    for (siblings[0..subtree]) |*sibling| {
        sibling.* = hashes[1];
        for (0..count / 2) |i| hashes[i] = H.hashChildren(.{ .left = hashes[2 * i], .right = hashes[2 * i + 1] });
        count /= 2;
    }
    @memcpy(siblings[subtree..], layer.queryPath(q));
    for (values[0..leaf_width], 0..) |value, j| @memcpy(leaf[j * 4 ..][0..4], &value.toM31Array());
    return .{ .allocator = a, .leaf = leaf, .siblings = siblings, .index = @intCast((position >> @as(u5, @intCast(layer.fold_step))) << @as(u5, @intCast(subtree))), .depth = @intCast(depth) };
}

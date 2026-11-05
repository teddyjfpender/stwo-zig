//! Named experimental Poseidon2 commitment family, canonical 36-byte roots.
const S = @import("../crypto/poseidon2_m31_sponge.zig");
const M31 = S.M31;
pub const Poseidon2M31MerkleHasher = struct {
    pub const Hash = S.Digest;
    pub const Children = struct { left: Hash, right: Hash };
    inner: S.Sponge,
    const Self = @This();
    pub fn defaultWithInitialState() Self {
        return .{ .inner = S.Sponge.init(.leaf) };
    }
    pub fn updateLeaf(self: *Self, values: []const M31) void {
        self.inner.absorbFelts(values);
    }
    pub fn finalize(self: Self) Hash {
        return self.inner.digest();
    }
    pub fn hashChildren(children: Children) Hash {
        var sponge = S.Sponge.init(.node);
        sponge.absorbDigest(children.left);
        sponge.absorbDigest(children.right);
        return sponge.digest();
    }
    pub fn hashNode(children: ?Children, values: []const M31) Hash {
        var sponge = S.Sponge.init(if (children != null) .node else .leaf);
        if (children) |pair| {
            sponge.absorbDigest(pair.left);
            sponge.absorbDigest(pair.right);
        }
        sponge.absorbFelts(values);
        return sponge.digest();
    }
};
test "Poseidon Merkle hasher satisfies both VCS interfaces" {
    const std = @import("std");
    const H = Poseidon2M31MerkleHasher;
    comptime @import("merkle_hasher.zig").assertMerkleHasher(H);
    comptime @import("../vcs_lifted/merkle_hasher.zig").assertMerkleHasherLifted(H);
    var leaf = H.defaultWithInitialState();
    leaf.updateLeaf(&.{M31.one()});
    leaf.updateLeaf(&.{M31.zero()});
    try std.testing.expectEqualSlices(u8, &leaf.finalize(), &H.hashNode(null, &.{ M31.one(), M31.zero() }));
    const pair = H.Children{ .left = leaf.finalize(), .right = leaf.finalize() };
    try std.testing.expectEqualSlices(u8, &H.hashChildren(pair), &H.hashNode(.{ .left = pair.left, .right = pair.right }, &.{}));
    try std.testing.expect(!std.mem.eql(u8, &H.hashChildren(pair), &leaf.finalize()));
    const generic = @import("merkle_hasher.zig").hashNode(H, .{ .left = pair.left, .right = pair.right }, &.{});
    try std.testing.expectEqualSlices(u8, &H.hashChildren(pair), &generic);
}

test "Poseidon leaf and node match independent dense matrix sponge" {
    const std = @import("std");
    var leaf = Poseidon2M31MerkleHasher.defaultWithInitialState();
    for (0..479) |i| leaf.updateLeaf(&.{M31.fromCanonical(@intCast(i))});
    const leaf_479: [9]u32 = .{ 75302569, 257737695, 1624457975, 1579973030, 1400139966, 1447753837, 28457724, 607448533, 1394666894 };
    const leaf_479_values = try S.decode(leaf.finalize());
    for (leaf_479_values, leaf_479) |actual, expected| try std.testing.expectEqual(expected, actual.v);
    const node: [9]u32 = .{ 1537522230, 2040128408, 1238183579, 301663181, 1576296983, 1473021156, 1359818301, 233623515, 648580489 };
    const node_values = try S.decode(Poseidon2M31MerkleHasher.hashChildren(.{ .left = leaf.finalize(), .right = leaf.finalize() }));
    for (node_values, node) |actual, expected| try std.testing.expectEqual(expected, actual.v);
}

//! Experimental full-digest BLAKE3 lifted commitments. No device-family ID is
//! advertised until an authenticated implementation is available on that device.
const protocol = @import("../channel/blake3.zig");
const hash = @import("../vcs/blake3_hash.zig");
const M31 = @import("../fields/m31.zig").M31;

pub const MerkleHasher = struct {
    inner: hash.Blake3Hasher,
    const Self = @This();
    pub const Hash = hash.Blake3Hash;
    pub const NodeSeed = void;
    pub fn nodeSeed() NodeSeed {}
    pub fn hashChildrenWithSeed(_: NodeSeed, children: Children) Hash {
        return hashChildren(children);
    }
    pub const Children = struct { left: Hash, right: Hash };
    pub fn defaultWithInitialState() Self {
        return .{ .inner = protocol.start(.leaf) };
    }
    pub fn hashChildren(children: Children) Hash {
        return (protocol.Frame{ .node = .{ .left = children.left, .right = children.right } }).hash();
    }
    pub fn updateLeaf(self: *Self, values: []const M31) void {
        // Streaming boundaries do not change the committed sequence.
        protocol.framing.writeLeaf(&self.inner, values);
    }
    /// Canonical little-endian M31 bytes supplied by the shared tiled builder.
    pub fn updateLeafPackedBytes(self: *Self, bytes: []const u8) void {
        @import("std").debug.assert(bytes.len % 4 == 0);
        self.inner.update(bytes);
    }
    pub fn finalize(self: *const Self) Hash {
        return self.inner.finalize();
    }
};
pub const MerkleChannel = struct {
    pub fn mixRoot(channel: *protocol.Channel, root: MerkleHasher.Hash) void {
        channel.mixRoot(root);
    }
};
comptime {
    @import("merkle_hasher.zig").assertMerkleHasherLifted(MerkleHasher);
}

//! Experimental full-digest BLAKE3 lifted commitments. No device-family ID is
//! advertised until an authenticated implementation is available on that device.
const protocol = @import("../channel/blake3.zig");
const hash = @import("../vcs/blake3_hash.zig");
const M31 = @import("../fields/m31.zig").M31;
const std = @import("std");
const batch = @import("../crypto/blake3_equal_messages4.zig");
const LEAF_PREFIX = protocol.framing.PROTOCOL_ID ++ [_]u8{@intFromEnum(protocol.framing.Domain.leaf)};

pub const MerkleHasher = struct {
    inner: hash.Blake3Hasher,
    const Self = @This();
    pub const Hash = hash.Blake3Hash;
    pub const NodeSeed = void;
    pub fn nodeSeed() NodeSeed {}
    pub fn leafSeed() NodeSeed {}
    /// The same prefix and full multi-chunk tree as the streaming leaf path.
    pub fn hashPackedLeavesWithSeed4(_: NodeSeed, messages: *const [4][]const u8) [4]Hash {
        return batch.hashPrefixed(LEAF_PREFIX, messages) catch unreachable;
    }
    /// Reads four consecutive rows directly from immutable committed columns.
    /// The shared builder has already admitted row extents and lifting shape.
    pub fn hashDirectM31LeavesWithSeed4(_: NodeSeed, columns: anytype, position: usize) [4]Hash {
        const Reader = struct {
            columns: @TypeOf(columns),
            position: usize,
            pub fn byteLength(self: @This()) !usize {
                return std.math.add(usize, LEAF_PREFIX.len, try std.math.mul(usize, self.columns.len, @sizeOf(M31)));
            }
            pub fn block(self: @This(), offset: usize, length: usize) batch.Blocks {
                if (comptime LEAF_PREFIX.len % 4 == 0) {
                    // Prefix, field encoding and compression boundaries are all
                    // word-aligned. Read canonical M31 words directly instead
                    // of writing then decoding the same little-endian bytes.
                    var result: batch.Blocks = @splat(@splat(0));
                    const prefix_words = LEAF_PREFIX.len / 4;
                    const first_payload_word = if (offset == 0) prefix_words else 0;
                    if (offset == 0) {
                        inline for (0..prefix_words) |word| {
                            const value = std.mem.readInt(u32, LEAF_PREFIX[word * 4 ..][0..4], .little);
                            inline for (0..4) |lane| result[lane][word] = value;
                        }
                    }
                    for (first_payload_word..length / 4) |word| {
                        const index = offset / 4 + word - prefix_words;
                        inline for (0..4) |lane| result[lane][word] = self.columns[index].values[self.position + lane].toU32();
                    }
                    return result;
                }
                var bytes: [4][64]u8 = undefined;
                var written = batch.prefixBlock(LEAF_PREFIX, offset, length, &bytes);
                var payload = offset + written -| LEAF_PREFIX.len;
                while (written < length) {
                    const index = payload / 4;
                    const within = payload % 4;
                    const take = @min(4 - within, length - written);
                    inline for (0..4) |lane| {
                        var word: [4]u8 = undefined;
                        std.mem.writeInt(u32, &word, self.columns[index].values[self.position + lane].toU32(), .little);
                        @memcpy(bytes[lane][written..][0..take], word[within..][0..take]);
                    }
                    written += take;
                    payload += take;
                }
                return batch.words(&bytes);
            }
        };
        return batch.hashReader(Reader{ .columns = columns, .position = position }) catch unreachable;
    }
    pub fn hashChildrenWithSeed(_: NodeSeed, children: Children) Hash {
        return hashChildren(children);
    }
    /// Existing lifted layer dispatch batches four independent node frames.
    /// Children remain left/right interleaved in the original canonical order.
    pub fn hashChildrenWithSeed4(_: NodeSeed, children: *const [8]Hash) [4]Hash {
        var frames: [4]protocol.Frame = undefined;
        for (&frames, 0..) |*frame, lane| frame.* = .{ .node = .{ .left = children[2 * lane], .right = children[2 * lane + 1] } };
        return protocol.Frame.hash4(frames);
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

//! Named experimental Poseidon2 commitment family, canonical 36-byte roots.
const S = @import("../crypto/poseidon2_m31_sponge.zig");
const M31 = S.M31;
const std = @import("std");
const Packed = @import("../crypto/poseidon2_m31_sponge4.zig").Sponge4;
pub const Poseidon2M31MerkleHasher = ForVersion(1);
/// Same commitment arithmetic, distinct suite type for the v2 transcript/wire.
pub const Poseidon2M31MerkleHasherV2 = ForVersion(2);
fn ForVersion(comptime version: u8) type {
    return struct {
        pub const protocol_version = version;
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
        pub const NodeSeed = void;
        pub fn nodeSeed() NodeSeed {}
        pub fn leafSeed() NodeSeed {}
        pub fn hashChildrenWithSeed(_: NodeSeed, children: Children) Hash {
            return hashChildren(children);
        }
        pub fn hashChildrenWithSeed4(_: NodeSeed, children: *const [8]Hash) [4]Hash {
            var decoded: [8][S.DIGEST_WORDS]M31 = undefined;
            for (&decoded, children) |*out, child| out.* = S.decode(child) catch @panic("noncanonical Poseidon2 digest");
            var lane_sponge = Packed.init(.node);
            for (0..2) |side| for (0..S.DIGEST_WORDS) |coordinate| {
                var words: [4]u32 = undefined;
                inline for (0..4) |lane| {
                    words[lane] = decoded[2 * lane + side][coordinate].v;
                }
                lane_sponge.absorb(words);
            };
            return lane_sponge.finish();
        }
        pub fn hashPackedLeavesWithSeed4(_: NodeSeed, messages: *const [4][]const u8) [4]Hash {
            const len = messages[0].len;
            std.debug.assert(len % 4 == 0);
            inline for (0..4) |lane| std.debug.assert(messages[lane].len == len);
            var lane_sponge = Packed.init(.leaf);
            var offset: usize = 0;
            while (offset < len) : (offset += 4) {
                var words: [4]u32 = undefined;
                inline for (0..4) |lane| words[lane] = std.mem.readInt(u32, messages[lane][offset..][0..4], .little);
                lane_sponge.absorb(words);
            }
            return lane_sponge.finish();
        }
        pub fn hashDirectLiftedM31LeavesWithSeed4(_: NodeSeed, columns: anytype, position: usize, max_log: u32) [4]Hash {
            var lane_sponge = Packed.init(.leaf);
            for (columns) |column| {
                const shift: std.math.Log2Int(usize) = @intCast(max_log - column.log_size + 1);
                var words: [4]u32 = undefined;
                inline for (0..4) |lane| {
                    const source_index = (((position + lane) >> shift) << 1) + ((position + lane) & 1);
                    words[lane] = column.values[source_index].v;
                }
                lane_sponge.absorb(words);
            }
            return lane_sponge.finish();
        }
        pub fn updateM31Columns4(hashers: *[4]Self, columns: anytype, position: usize) void {
            inline for (0..4) |lane| {
                if (hashers[lane].inner.at != hashers[0].inner.at) {
                    inline for (0..4) |scalar_lane| for (columns) |column| {
                        hashers[scalar_lane].updateLeaf(column.values[position + scalar_lane ..][0..1]);
                    };
                    return;
                }
            }
            var states: [4]S.Sponge = undefined;
            inline for (0..4) |lane| states[lane] = hashers[lane].inner;
            var lane_sponge = Packed.fromStates(&states);
            for (columns) |column| {
                var words: [4]u32 = undefined;
                inline for (0..4) |lane| words[lane] = column.values[position + lane].v;
                lane_sponge.absorb(words);
            }
            lane_sponge.writeStates(&states);
            inline for (0..4) |lane| hashers[lane].inner = states[lane];
        }
        pub fn finalize4(hashers: *[4]Self) [4]Hash {
            inline for (0..4) |lane| {
                if (hashers[lane].inner.at != hashers[0].inner.at) {
                    var result: [4]Hash = undefined;
                    inline for (0..4) |scalar_lane| result[scalar_lane] = hashers[scalar_lane].finalize();
                    return result;
                }
            }
            var states: [4]S.Sponge = undefined;
            inline for (0..4) |lane| states[lane] = hashers[lane].inner;
            return Packed.fromStates(&states).finish();
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
}
test "Poseidon Merkle hasher satisfies both VCS interfaces" {
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
    var leaf = Poseidon2M31MerkleHasher.defaultWithInitialState();
    for (0..479) |i| leaf.updateLeaf(&.{M31.fromCanonical(@intCast(i))});
    const leaf_479: [9]u32 = .{ 75302569, 257737695, 1624457975, 1579973030, 1400139966, 1447753837, 28457724, 607448533, 1394666894 };
    const leaf_479_values = try S.decode(leaf.finalize());
    for (leaf_479_values, leaf_479) |actual, expected| try std.testing.expectEqual(expected, actual.v);
    const node: [9]u32 = .{ 1537522230, 2040128408, 1238183579, 301663181, 1576296983, 1473021156, 1359818301, 233623515, 648580489 };
    const node_values = try S.decode(Poseidon2M31MerkleHasher.hashChildren(.{ .left = leaf.finalize(), .right = leaf.finalize() }));
    for (node_values, node) |actual, expected| try std.testing.expectEqual(expected, actual.v);
}

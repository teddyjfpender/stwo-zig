const std = @import("std");
const channel_blake2s = @import("../channel/blake2s.zig");
const m31 = @import("../fields/m31.zig");
const blake2_hash = @import("../vcs/blake2_hash.zig");

const M31 = m31.M31;

pub const LEAF_PREFIX = makePrefix("leaf");
pub const NODE_PREFIX = makePrefix("node");

pub const Blake2sMerkleHasher = Blake2sMerkleHasherGeneric(false);
pub const Blake2sM31MerkleHasher = Blake2sMerkleHasherGeneric(true);

pub fn Blake2sMerkleHasherGeneric(comptime is_m31_output: bool) type {
    const InnerHasher = blake2_hash.Blake2sHasherGeneric(is_m31_output);
    return struct {
        inner: InnerHasher,
        pub const Hash = blake2_hash.Blake2sHash;

        const Self = @This();

        pub fn init() Self {
            return .{ .inner = InnerHasher.init() };
        }

        pub fn defaultWithInitialState() Self {
            var hasher = Self.init();
            hasher.inner.update(LEAF_PREFIX[0..]);
            return hasher;
        }

        pub fn hashChildren(children: struct { left: Hash, right: Hash }) Hash {
            var hasher = Self.init();
            hasher.inner.update(NODE_PREFIX[0..]);
            hasher.inner.update(children.left[0..]);
            hasher.inner.update(children.right[0..]);
            return hasher.inner.finalize();
        }

        pub fn updateLeaf(self: *Self, column_values: []const M31) void {
            for (column_values) |x| {
                const bytes = x.toBytesLe();
                self.inner.update(bytes[0..]);
            }
        }

        pub fn finalize(self: *Self) Hash {
            return self.inner.finalize();
        }
    };
}

pub fn Blake2sMerkleChannelGeneric(comptime is_m31_output: bool) type {
    return struct {
        pub fn mixRoot(
            channel: *channel_blake2s.Blake2sChannelGeneric(is_m31_output),
            root: blake2_hash.Blake2sHash,
        ) void {
            const digest = channel.digestBytes();
            channel.updateDigest(
                blake2_hash.Blake2sHasherGeneric(is_m31_output).concatAndHash(digest, root),
            );
        }
    };
}

pub const Blake2sMerkleChannel = Blake2sMerkleChannelGeneric(false);
pub const Blake2sM31MerkleChannel = Blake2sMerkleChannelGeneric(true);

fn makePrefix(comptime tag: []const u8) [64]u8 {
    var out: [64]u8 = [_]u8{0} ** 64;
    inline for (tag, 0..) |c, i| out[i] = c;
    return out;
}

test "vcs_lifted blake2: hash children deterministic" {
    const left = [_]u8{1} ** 32;
    const right = [_]u8{2} ** 32;
    const h1 = Blake2sMerkleHasher.hashChildren(.{ .left = left, .right = right });
    const h2 = Blake2sMerkleHasher.hashChildren(.{ .left = left, .right = right });
    try std.testing.expect(std.mem.eql(u8, h1[0..], h2[0..]));
}

test "vcs_lifted blake2: mix root changes channel digest" {
    var channel = channel_blake2s.Blake2sChannel{};
    const before = channel.digestBytes();
    Blake2sMerkleChannel.mixRoot(&channel, [_]u8{3} ** 32);
    try std.testing.expect(!std.mem.eql(u8, before[0..], channel.digestBytes()[0..]));
}

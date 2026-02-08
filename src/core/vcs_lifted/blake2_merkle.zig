const std = @import("std");
const builtin = @import("builtin");
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
    const pack_chunk_elems = 32;
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
            var payload: [64 + 32 + 32]u8 = undefined;
            @memcpy(payload[0..64], NODE_PREFIX[0..]);
            @memcpy(payload[64..96], children.left[0..]);
            @memcpy(payload[96..128], children.right[0..]);
            return InnerHasher.hash(payload[0..]);
        }

        /// Pre-hashed node-domain separator state used to avoid reprocessing
        /// `NODE_PREFIX` for every parent hash on one Merkle layer.
        pub fn nodeSeed() Self {
            var hasher = Self.init();
            hasher.inner.update(NODE_PREFIX[0..]);
            return hasher;
        }

        pub fn hashChildrenWithSeed(seed: Self, children: struct { left: Hash, right: Hash }) Hash {
            var hasher = seed;
            hasher.inner.update(children.left[0..]);
            hasher.inner.update(children.right[0..]);
            return hasher.inner.finalize();
        }

        pub fn updateLeaf(self: *Self, column_values: []const M31) void {
            if (column_values.len == 0) return;

            var at: usize = 0;
            if (builtin.cpu.arch.endian() == .little) {
                var words: [pack_chunk_elems]u32 = undefined;
                while (at < column_values.len) {
                    const chunk = @min(pack_chunk_elems, column_values.len - at);
                    for (0..chunk) |i| {
                        words[i] = column_values[at + i].toU32();
                    }
                    self.inner.update(std.mem.sliceAsBytes(words[0..chunk]));
                    at += chunk;
                }
            } else {
                var bytes: [pack_chunk_elems * 4]u8 = undefined;
                while (at < column_values.len) {
                    const chunk = @min(pack_chunk_elems, column_values.len - at);
                    for (0..chunk) |i| {
                        const value_bytes = column_values[at + i].toBytesLe();
                        const start = i * 4;
                        @memcpy(bytes[start .. start + 4], value_bytes[0..]);
                    }
                    self.inner.update(bytes[0 .. chunk * 4]);
                    at += chunk;
                }
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

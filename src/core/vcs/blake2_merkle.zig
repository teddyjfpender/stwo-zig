const std = @import("std");
const builtin = @import("builtin");
const m31 = @import("../fields/m31.zig");
const blake2_hash = @import("blake2_hash.zig");

const M31 = m31.M31;
const Blake2sHash = blake2_hash.Blake2sHash;

pub const LEAF_PREFIX = makePrefix("leaf");
pub const NODE_PREFIX = makePrefix("node");

pub const Blake2sMerkleHasher = Blake2sMerkleHasherGeneric(false);
pub const Blake2sM31MerkleHasher = Blake2sMerkleHasherGeneric(true);

pub fn Blake2sMerkleHasherGeneric(comptime is_m31_output: bool) type {
    const Hasher = blake2_hash.Blake2sHasherGeneric(is_m31_output);
    const pack_chunk_elems = 32;
    comptime {
        std.debug.assert(@sizeOf(M31) == @sizeOf(u32));
        std.debug.assert(@alignOf(M31) == @alignOf(u32));
    }
    return struct {
        pub const Hash = Blake2sHash;

        pub fn hashNode(
            children_hashes: ?struct { left: Blake2sHash, right: Blake2sHash },
            column_values: []const M31,
        ) Blake2sHash {
            var hasher = Hasher.init();

            if (children_hashes) |children| {
                hasher.update(NODE_PREFIX[0..]);
                hasher.update(children.left[0..]);
                hasher.update(children.right[0..]);
            } else {
                hasher.update(LEAF_PREFIX[0..]);
            }

            var at: usize = 0;
            if (builtin.cpu.arch.endian() == .little) {
                // `M31` is represented as canonical little-endian u32 words.
                hasher.update(std.mem.sliceAsBytes(column_values));
            } else {
                var bytes: [pack_chunk_elems * 4]u8 = undefined;
                while (at < column_values.len) {
                    const chunk = @min(pack_chunk_elems, column_values.len - at);
                    for (0..chunk) |i| {
                        const value_bytes = column_values[at + i].toBytesLe();
                        const start = i * 4;
                        @memcpy(bytes[start .. start + 4], value_bytes[0..]);
                    }
                    hasher.update(bytes[0 .. chunk * 4]);
                    at += chunk;
                }
            }

            return hasher.finalize();
        }
    };
}

fn makePrefix(comptime tag: []const u8) [64]u8 {
    var out: [64]u8 = [_]u8{0} ** 64;
    inline for (tag, 0..) |c, i| out[i] = c;
    return out;
}

fn readU32Le(bytes: []const u8) u32 {
    std.debug.assert(bytes.len == 4);
    return (@as(u32, bytes[0])) |
        (@as(u32, bytes[1]) << 8) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 24);
}

test "blake2 merkle: leaf and node prefixes are domain separated" {
    const values = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
    };
    const leaf_hash = Blake2sMerkleHasher.hashNode(null, values[0..]);
    const node_hash = Blake2sMerkleHasher.hashNode(.{
        .left = [_]u8{0} ** 32,
        .right = [_]u8{0xff} ** 32,
    }, values[0..]);
    try std.testing.expect(!std.mem.eql(u8, leaf_hash[0..], node_hash[0..]));
}

test "blake2 merkle: deterministic hashing" {
    const values = [_]M31{
        M31.fromCanonical(42),
        M31.fromCanonical(17),
    };
    const h1 = Blake2sMerkleHasher.hashNode(null, values[0..]);
    const h2 = Blake2sMerkleHasher.hashNode(null, values[0..]);
    try std.testing.expect(std.mem.eql(u8, h1[0..], h2[0..]));
}

test "blake2 merkle: m31-output hasher produces canonical limbs" {
    const values = [_]M31{
        M31.fromCanonical(13),
        M31.fromCanonical(37),
        M31.fromCanonical(99),
    };
    const h = Blake2sM31MerkleHasher.hashNode(null, values[0..]);
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const start = i * 4;
        const word = readU32Le(h[start .. start + 4]);
        try std.testing.expect(word < m31.Modulus);
    }
}

test "blake2 merkle: leaf hashing matches explicit byte packing" {
    var prng = std.Random.DefaultPrng.init(0x0ddc_0ffe_e123_4567);
    const rng = prng.random();

    var values: [65]M31 = undefined;
    for (values[0..]) |*value| {
        value.* = M31.fromU64(rng.int(u32));
    }

    const digest = Blake2sMerkleHasher.hashNode(null, values[0..]);
    var manual = blake2_hash.Blake2sHasher.init();
    manual.update(LEAF_PREFIX[0..]);
    for (values[0..]) |value| {
        const encoded = value.toBytesLe();
        manual.update(encoded[0..]);
    }
    const expected = manual.finalize();
    try std.testing.expect(std.mem.eql(u8, digest[0..], expected[0..]));
}

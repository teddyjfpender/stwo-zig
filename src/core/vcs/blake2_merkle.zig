const std = @import("std");
const m31 = @import("../fields/m31.zig");
const blake2_hash = @import("blake2_hash.zig");

const M31 = m31.M31;
const Blake2sHash = blake2_hash.Blake2sHash;

pub const LEAF_PREFIX = makePrefix("leaf");
pub const NODE_PREFIX = makePrefix("node");

pub const Blake2sMerkleHasher = Blake2sMerkleHasherGeneric(false);
pub const Blake2sM31MerkleHasher = Blake2sMerkleHasherGeneric(true);

pub fn Blake2sMerkleHasherGeneric(comptime is_m31_output: bool) type {
    return struct {
        pub const Hash = Blake2sHash;

        pub fn hashNode(
            children_hashes: ?struct { left: Blake2sHash, right: Blake2sHash },
            column_values: []const M31,
        ) Blake2sHash {
            const Hasher = blake2_hash.Blake2sHasherGeneric(is_m31_output);
            var hasher = Hasher.init();

            if (children_hashes) |children| {
                hasher.update(NODE_PREFIX[0..]);
                hasher.update(children.left[0..]);
                hasher.update(children.right[0..]);
            } else {
                hasher.update(LEAF_PREFIX[0..]);
            }

            for (column_values) |value| {
                const bytes = value.toBytesLe();
                hasher.update(bytes[0..]);
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

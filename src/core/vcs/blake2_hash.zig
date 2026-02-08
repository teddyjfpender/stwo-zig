const std = @import("std");
const m31 = @import("../fields/m31.zig");

const M31 = m31.M31;

const Blake2s256 = blk: {
    if (@hasDecl(std.crypto.hash, "Blake2s256")) break :blk std.crypto.hash.Blake2s256;
    if (@hasDecl(std.crypto.hash, "blake2") and @hasDecl(std.crypto.hash.blake2, "Blake2s256")) {
        break :blk std.crypto.hash.blake2.Blake2s256;
    }
    @compileError("Blake2s256 not found in std.crypto.hash");
};

pub const Blake2sHash = [32]u8;

pub const Blake2sHasher = Blake2sHasherGeneric(false);
pub const Blake2sM31Hasher = Blake2sHasherGeneric(true);

pub fn Blake2sHasherGeneric(comptime is_m31_output: bool) type {
    return struct {
        ctx: Blake2s256,

        const Self = @This();

        pub fn init() Self {
            return .{ .ctx = Blake2s256.init(.{}) };
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.ctx.update(data);
        }

        pub fn finalize(self: *Self) Blake2sHash {
            var out: Blake2sHash = undefined;
            self.ctx.final(&out);
            if (is_m31_output) {
                out = reduceToM31(out);
            }
            return out;
        }

        pub fn hash(data: []const u8) Blake2sHash {
            var hasher = Self.init();
            hasher.update(data);
            return hasher.finalize();
        }

        pub fn concatAndHash(v1: Blake2sHash, v2: Blake2sHash) Blake2sHash {
            var hasher = Self.init();
            hasher.update(v1[0..]);
            hasher.update(v2[0..]);
            return hasher.finalize();
        }
    };
}

/// Reduces each little-endian u32 limb modulo M31.
pub fn reduceToM31(value: Blake2sHash) Blake2sHash {
    var out: Blake2sHash = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const start = i * 4;
        const word = readU32Le(value[start .. start + 4]);
        const reduced = M31.fromU64(word);
        const bytes = reduced.toBytesLe();
        @memcpy(out[start .. start + 4], bytes[0..]);
    }
    return out;
}

fn readU32Le(bytes: []const u8) u32 {
    std.debug.assert(bytes.len == 4);
    return (@as(u32, bytes[0])) |
        (@as(u32, bytes[1]) << 8) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 24);
}

fn digestToHex(digest: Blake2sHash) [64]u8 {
    return std.fmt.bytesToHex(digest, .lower);
}

test "blake2 hash: single hash test" {
    const hash_a = Blake2sHasher.hash("a");
    const hex = digestToHex(hash_a);
    try std.testing.expectEqualStrings(
        "4a0d129873403037c2cd9b9048203687f6233fb6738956e0349bd4320fec3e90",
        &hex,
    );
}

test "blake2 hash: incremental equals one-shot" {
    var state = Blake2sHasher.init();
    state.update("a");
    state.update("b");
    const hash_ab = state.finalize();
    const one_shot = Blake2sHasher.hash("ab");
    try std.testing.expect(std.mem.eql(u8, hash_ab[0..], one_shot[0..]));
}

test "blake2 hash: m31 output limbs are canonical" {
    const hash = Blake2sM31Hasher.hash("canonical-limbs-check");
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const start = i * 4;
        const word = readU32Le(hash[start .. start + 4]);
        try std.testing.expect(word < m31.Modulus);
    }
}

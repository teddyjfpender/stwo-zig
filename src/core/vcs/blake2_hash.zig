const std = @import("std");
const builtin = @import("builtin");
const m31 = @import("../fields/m31.zig");
const blake2_backend = @import("../crypto/blake2s_backend.zig");

const M31 = m31.M31;

// Independent standard-library oracle used only by differential tests.
const StdBlake2s256 = blk: {
    if (@hasDecl(std.crypto.hash, "Blake2s256")) break :blk std.crypto.hash.Blake2s256;
    if (@hasDecl(std.crypto.hash, "blake2") and @hasDecl(std.crypto.hash.blake2, "Blake2s256")) {
        break :blk std.crypto.hash.blake2.Blake2s256;
    }
    @compileError("Blake2s256 not found in std.crypto.hash");
};

pub const BackendMode = blake2_backend.BackendMode;
pub const BackendSelection = blake2_backend.BackendSelection;

pub fn setDefaultBackendMode(mode: BackendMode) void {
    blake2_backend.setDefaultBackendMode(mode);
}

pub fn getDefaultBackendSelection() BackendSelection {
    return blake2_backend.getDefaultBackendSelection();
}

/// Compatibility aliases for callers that predate explicit default naming.
pub fn setBackendMode(mode: BackendMode) void {
    setDefaultBackendMode(mode);
}

pub fn getBackendMode() BackendMode {
    return blake2_backend.getDefaultBackendMode();
}

pub fn getEffectiveBackendMode() BackendMode {
    return getDefaultBackendSelection().effective;
}

pub fn resetTestCompressionCounts() void {
    blake2_backend.resetTestCompressionCounts();
}

pub fn testCompressionCounts() blake2_backend.TestCompressionCounts {
    return blake2_backend.testCompressionCounts();
}

pub fn selectBackend(mode: BackendMode) BackendSelection {
    return blake2_backend.selectBackend(mode);
}

pub fn supportsSimdBackend() bool {
    return blake2_backend.supportsSimdBackend();
}

pub const Blake2sHash = blake2_backend.Blake2sHash;

pub const Blake2sHasher = Blake2sHasherGeneric(false);
pub const Blake2sM31Hasher = Blake2sHasherGeneric(true);

pub fn Blake2sHasherGeneric(comptime is_m31_output: bool) type {
    return struct {
        ctx: blake2_backend.Blake2sHasher,

        const Self = @This();
        pub const Fixed64Seed = blake2_backend.Blake2sHasher.Fixed64Seed;

        pub fn init() Self {
            return .{ .ctx = blake2_backend.Blake2sHasher.init() };
        }

        pub fn initWithMode(mode: BackendMode) Self {
            return .{ .ctx = blake2_backend.Blake2sHasher.initWithMode(mode) };
        }

        pub fn backendSelection(self: *const Self) BackendSelection {
            return self.ctx.backendSelection();
        }

        pub fn update(self: *Self, data: []const u8) void {
            self.ctx.update(data);
        }

        pub fn finalize(self: *Self) Blake2sHash {
            var out = self.ctx.finalize();
            if (is_m31_output) out = reduceToM31(out);
            return out;
        }

        pub fn hash(data: []const u8) Blake2sHash {
            var hasher = Self.init();
            hasher.update(data);
            return hasher.finalize();
        }

        pub fn hashWithMode(mode: BackendMode, data: []const u8) Blake2sHash {
            var hasher = Self.initWithMode(mode);
            hasher.update(data);
            return hasher.finalize();
        }

        pub fn hashFixedSingleBlock(comptime byte_len: usize, data: *const [byte_len]u8) Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashFixedSingleBlock(byte_len, data);
            if (is_m31_output) out = reduceToM31(out);
            return out;
        }

        pub fn hashFixedSingleBlockWithMode(
            comptime byte_len: usize,
            mode: BackendMode,
            data: *const [byte_len]u8,
        ) Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashFixedSingleBlockWithMode(byte_len, mode, data);
            if (is_m31_output) out = reduceToM31(out);
            return out;
        }

        pub fn hashFixedSingleBlock4(
            comptime byte_len: usize,
            data: *const [4][byte_len]u8,
        ) [4]Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashFixedSingleBlock4(
                byte_len,
                data,
            );
            if (is_m31_output) {
                for (&out) |*digest| digest.* = reduceToM31(digest.*);
            }
            return out;
        }

        pub fn hashFixedSingleBlock8(
            comptime byte_len: usize,
            data: *const [8][byte_len]u8,
        ) [8]Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashFixedSingleBlock8(
                byte_len,
                data,
            );
            if (is_m31_output) {
                for (&out) |*digest| digest.* = reduceToM31(digest.*);
            }
            return out;
        }

        pub fn hashFixed64(data: *const [64]u8) Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashFixed64(data);
            if (is_m31_output) out = reduceToM31(out);
            return out;
        }

        pub fn hashFixed64WithMode(mode: BackendMode, data: *const [64]u8) Blake2sHash {
            return hashFixedSingleBlockWithMode(64, mode, data);
        }

        /// Fixed-size Merkle-node path (64-byte prefix + 64-byte children)
        /// routed through the shared backend implementation.
        pub fn hashFixed128(data: *const [128]u8) Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashFixed128(data);
            if (is_m31_output) out = reduceToM31(out);
            return out;
        }

        pub fn hashFixed128WithMode(mode: BackendMode, data: *const [128]u8) Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashFixed128WithMode(mode, data);
            if (is_m31_output) out = reduceToM31(out);
            return out;
        }

        pub fn seedAfterFixed64(data: *const [64]u8) Fixed64Seed {
            return blake2_backend.Blake2sHasher.seedAfterFixed64(data);
        }

        pub fn seedAfterFixed64WithMode(mode: BackendMode, data: *const [64]u8) Fixed64Seed {
            return blake2_backend.Blake2sHasher.seedAfterFixed64WithMode(mode, data);
        }

        pub fn hashFinal64FromSeed(seed: Fixed64Seed, data: *const [64]u8) Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashFinal64FromSeed(seed, data);
            if (is_m31_output) out = reduceToM31(out);
            return out;
        }

        pub fn hashFinal64FromSeedWithMode(
            mode: BackendMode,
            seed: Fixed64Seed,
            data: *const [64]u8,
        ) Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashFinal64FromSeedWithMode(mode, seed, data);
            if (is_m31_output) out = reduceToM31(out);
            return out;
        }

        pub fn hashFinal64FromSeed4(seed: Fixed64Seed, data: *const [4][64]u8) [4]Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashFinal64FromSeed4(seed, data);
            if (is_m31_output) {
                for (&out) |*digest| digest.* = reduceToM31(digest.*);
            }
            return out;
        }

        pub fn hashFinal64FromSeed4WithMode(
            mode: BackendMode,
            seed: Fixed64Seed,
            data: *const [4][64]u8,
        ) [4]Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashFinal64FromSeed4WithMode(mode, seed, data);
            if (is_m31_output) {
                for (&out) |*digest| digest.* = reduceToM31(digest.*);
            }
            return out;
        }

        pub fn hashEqualFromSeed4(seed: Fixed64Seed, data: *const [4][]const u8) [4]Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashEqualFromSeed4(seed, data);
            if (is_m31_output) {
                for (&out) |*digest| digest.* = reduceToM31(digest.*);
            }
            return out;
        }

        pub fn hashEqualFromSeed4WithMode(
            mode: BackendMode,
            seed: Fixed64Seed,
            data: *const [4][]const u8,
        ) [4]Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashEqualFromSeed4WithMode(mode, seed, data);
            if (is_m31_output) {
                for (&out) |*digest| digest.* = reduceToM31(digest.*);
            }
            return out;
        }

        pub fn hashM31ColumnsFromSeed4WithMode(
            mode: BackendMode,
            seed: Fixed64Seed,
            columns: anytype,
            position: usize,
        ) [4]Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashM31ColumnsFromSeed4WithMode(
                mode,
                seed,
                columns,
                position,
            );
            if (is_m31_output) {
                for (&out) |*digest| digest.* = reduceToM31(digest.*);
            }
            return out;
        }

        pub fn hashM31Columns4WithMode(
            mode: BackendMode,
            columns: anytype,
            position: usize,
        ) [4]Blake2sHash {
            var out = blake2_backend.Blake2sHasher.hashM31Columns4WithMode(
                mode,
                columns,
                position,
            );
            if (is_m31_output) {
                for (&out) |*digest| digest.* = reduceToM31(digest.*);
            }
            return out;
        }

        pub fn concatAndHash(v1: Blake2sHash, v2: Blake2sHash) Blake2sHash {
            var payload: [64]u8 = undefined;
            @memcpy(payload[0..32], v1[0..]);
            @memcpy(payload[32..64], v2[0..]);
            return hashFixed64(&payload);
        }

        pub fn concatAndHashWithMode(mode: BackendMode, v1: Blake2sHash, v2: Blake2sHash) Blake2sHash {
            var payload: [64]u8 = undefined;
            @memcpy(payload[0..32], v1[0..]);
            @memcpy(payload[32..64], v2[0..]);
            return hashFixed64WithMode(mode, &payload);
        }
    };
}

/// Reduces each little-endian u32 limb modulo M31.
pub fn reduceToM31(value: Blake2sHash) Blake2sHash {
    if (comptime builtin.cpu.arch.endian() == .little) {
        const V4 = @Vector(4, u32);
        const p: V4 = @splat(m31.Modulus);
        var words: [8]u32 = @bitCast(value);
        inline for (0..2) |group| {
            const start = group * 4;
            const input: V4 = words[start..][0..4].*;
            const folded = (input & p) +% (input >> @as(V4, @splat(31)));
            const reduced = @select(u32, folded >= p, folded -% p, folded);
            words[start..][0..4].* = reduced;
        }
        return @bitCast(words);
    }

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

test "blake2 hash: fixed128 backend matches generic hasher" {
    var prng = std.Random.DefaultPrng.init(0x9e37_79b9_7f4a_7c15);
    const rng = prng.random();

    var i: usize = 0;
    while (i < 128) : (i += 1) {
        var payload: [128]u8 = undefined;
        rng.bytes(payload[0..]);

        const generic = Blake2sHasher.hash(payload[0..]);
        const fixed = Blake2sHasher.hashFixed128(&payload);
        try std.testing.expect(std.mem.eql(u8, generic[0..], fixed[0..]));

        const generic_m31 = Blake2sM31Hasher.hash(payload[0..]);
        const fixed_m31 = Blake2sM31Hasher.hashFixed128(&payload);
        try std.testing.expect(std.mem.eql(u8, generic_m31[0..], fixed_m31[0..]));
    }
}

test "blake2 hash: scalar and simd backends match without shared policy mutation" {
    var payload: [128]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x1f83_d9ab_5be0_cd19);
    prng.random().bytes(payload[0..]);

    const scalar_hash = Blake2sHasher.hashFixed128WithMode(.scalar, &payload);
    const simd_hash = Blake2sHasher.hashFixed128WithMode(.simd, &payload);

    try std.testing.expect(std.mem.eql(u8, scalar_hash[0..], simd_hash[0..]));
}

test "blake2 hash: compatibility backend selectors remain observable" {
    const previous = getBackendMode();
    defer setBackendMode(previous);

    setBackendMode(.scalar);
    try std.testing.expectEqual(BackendMode.scalar, getBackendMode());
    try std.testing.expectEqual(BackendMode.scalar, getEffectiveBackendMode());
    try std.testing.expectEqual(BackendMode.scalar, Blake2sHasher.init().backendSelection().effective);
}

test "blake2 hash: backend wrapper matches std reference on varied lengths" {
    var prng = std.Random.DefaultPrng.init(0x8bad_f00d_cafe_d00d);
    const rng = prng.random();

    var len: usize = 0;
    while (len <= 192) : (len += 3) {
        var payload: [192]u8 = undefined;
        if (len > 0) rng.bytes(payload[0..len]);

        var std_hasher = StdBlake2s256.init(.{});
        std_hasher.update(payload[0..len]);
        var expected: Blake2sHash = undefined;
        std_hasher.final(&expected);

        const actual = Blake2sHasher.hash(payload[0..len]);
        try std.testing.expect(std.mem.eql(u8, expected[0..], actual[0..]));
    }
}

const std = @import("std");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const blake2_hash = @import("../vcs/blake2_hash.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const Digest32 = [32]u8;
pub const BLAKE_BYTES_PER_HASH: usize = 32;
pub const FELTS_PER_HASH: usize = 8;

pub const Blake2sChannel = Blake2sChannelGeneric(false);
pub const Blake2sM31Channel = Blake2sChannelGeneric(true);

pub fn Blake2sChannelGeneric(comptime is_m31_output: bool) type {
    const Hasher = blake2_hash.Blake2sHasherGeneric(is_m31_output);

    return struct {
        digest: Digest32 = [_]u8{0} ** 32,
        n_draws: u32 = 0,

        const Self = @This();
        pub const POW_PREFIX: u32 = 0x12345678;

        pub inline fn digestBytes(self: Self) Digest32 {
            return self.digest;
        }

        pub inline fn updateDigest(self: *Self, new_digest: Digest32) void {
            self.digest = new_digest;
            self.n_draws = 0;
        }

        pub fn mixFelts(self: *Self, felts: []const QM31) void {
            var hasher = Hasher.init();
            hasher.update(self.digest[0..]);
            for (felts) |felt| {
                const arr = felt.toM31Array();
                for (arr) |v| {
                    const bytes = v.toBytesLe();
                    hasher.update(bytes[0..]);
                }
            }
            self.updateDigest(hasher.finalize());
        }

        pub fn mixU32s(self: *Self, data: []const u32) void {
            var hasher = Hasher.init();
            hasher.update(self.digest[0..]);
            for (data) |word| {
                const bytes = u32ToBytesLe(word);
                hasher.update(bytes[0..]);
            }
            self.updateDigest(hasher.finalize());
        }

        pub fn mixU64(self: *Self, value: u64) void {
            self.mixU32s(&[_]u32{
                @truncate(value),
                @truncate(value >> 32),
            });
        }

        pub fn drawU32s(self: *Self) [FELTS_PER_HASH]u32 {
            var hash_input: [37]u8 = undefined;
            @memcpy(hash_input[0..32], self.digest[0..]);
            const counter = u32ToBytesLe(self.n_draws);
            @memcpy(hash_input[32..36], counter[0..]);
            hash_input[36] = 0;

            self.n_draws +%= 1;
            const hash = hashBytes(hash_input[0..]);

            var out: [FELTS_PER_HASH]u32 = undefined;
            var i: usize = 0;
            while (i < FELTS_PER_HASH) : (i += 1) {
                const base = i * 4;
                out[i] = readU32Le(hash[base .. base + 4]);
            }
            return out;
        }

        pub fn drawSecureFelt(self: *Self) QM31 {
            const felts = self.drawBaseFelts();
            return QM31.fromM31Array(.{ felts[0], felts[1], felts[2], felts[3] });
        }

        pub fn drawSecureFelts(self: *Self, allocator: std.mem.Allocator, n_felts: usize) ![]QM31 {
            const out = try allocator.alloc(QM31, n_felts);
            var produced: usize = 0;
            while (produced < n_felts) {
                const felts = self.drawBaseFelts();
                var i: usize = 0;
                while (i < FELTS_PER_HASH and produced < n_felts) : (i += qm31.SECURE_EXTENSION_DEGREE) {
                    out[produced] = QM31.fromM31Array(.{
                        felts[i + 0],
                        felts[i + 1],
                        felts[i + 2],
                        felts[i + 3],
                    });
                    produced += 1;
                }
            }
            return out;
        }

        /// Verifies that `H(H(POW_PREFIX, [0u8;12], digest, n_bits), nonce)` has at least
        /// `n_bits` trailing zero bits in the first 128 bits (little-endian), matching upstream.
        pub fn verifyPowNonce(self: Self, n_bits: u32, nonce: u64) bool {
            var prefixed_hasher = Hasher.init();
            const prefix_bytes = u32ToBytesLe(POW_PREFIX);
            const bits_bytes = u32ToBytesLe(n_bits);
            prefixed_hasher.update(prefix_bytes[0..]);
            prefixed_hasher.update(&[_]u8{0} ** 12);
            prefixed_hasher.update(self.digest[0..]);
            prefixed_hasher.update(bits_bytes[0..]);
            const prefixed_digest = prefixed_hasher.finalize();

            var hasher = Hasher.init();
            hasher.update(prefixed_digest[0..]);
            const nonce_bytes = u64ToBytesLe(nonce);
            hasher.update(nonce_bytes[0..]);
            const out = hasher.finalize();
            return trailingZeroBits(out[0..16]) >= n_bits;
        }

        fn drawBaseFelts(self: *Self) [FELTS_PER_HASH]M31 {
            while (true) {
                const words = self.drawU32s();
                const two_p = 2 * m31.Modulus;
                var valid = true;
                for (words) |x| {
                    if (x >= two_p) {
                        valid = false;
                        break;
                    }
                }
                if (!valid) continue;

                var felts: [FELTS_PER_HASH]M31 = undefined;
                for (words, 0..) |x, i| {
                    felts[i] = M31.fromU64(x);
                }
                return felts;
            }
        }

        fn hashBytes(data: []const u8) Digest32 {
            var hasher = Hasher.init();
            hasher.update(data);
            return hasher.finalize();
        }
    };
}

fn trailingZeroBits(bytes: []const u8) u32 {
    var count: u32 = 0;
    for (bytes) |b| {
        if (b == 0) {
            count += 8;
            continue;
        }
        count += @ctz(@as(u8, b));
        break;
    }
    return count;
}

fn u32ToBytesLe(x: u32) [4]u8 {
    return .{
        @truncate(x),
        @truncate(x >> 8),
        @truncate(x >> 16),
        @truncate(x >> 24),
    };
}

fn u64ToBytesLe(x: u64) [8]u8 {
    return .{
        @truncate(x),
        @truncate(x >> 8),
        @truncate(x >> 16),
        @truncate(x >> 24),
        @truncate(x >> 32),
        @truncate(x >> 40),
        @truncate(x >> 48),
        @truncate(x >> 56),
    };
}

fn readU32Le(bytes: []const u8) u32 {
    std.debug.assert(bytes.len == 4);
    return (@as(u32, bytes[0])) |
        (@as(u32, bytes[1]) << 8) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 24);
}

test "blake2s channel: draw counters" {
    var channel = Blake2sChannel{};
    try std.testing.expectEqual(@as(u32, 0), channel.n_draws);

    _ = channel.drawU32s();
    try std.testing.expectEqual(@as(u32, 1), channel.n_draws);

    const felts = try channel.drawSecureFelts(std.testing.allocator, 9);
    defer std.testing.allocator.free(felts);
    try std.testing.expectEqual(@as(u32, 6), channel.n_draws);
}

test "blake2s channel: draw_u32s differs on successive calls" {
    var channel = Blake2sChannel{};
    const a = channel.drawU32s();
    const b = channel.drawU32s();
    try std.testing.expect(!std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b)));
}

test "blake2s channel: draw_secure_felt differs on successive calls" {
    var channel = Blake2sChannel{};
    const a = channel.drawSecureFelt();
    const b = channel.drawSecureFelt();
    try std.testing.expect(!a.eql(b));
}

test "blake2s channel: draw_secure_felts are unique for small sample" {
    var channel = Blake2sChannel{};
    const a = try channel.drawSecureFelts(std.testing.allocator, 5);
    defer std.testing.allocator.free(a);
    const b = try channel.drawSecureFelts(std.testing.allocator, 4);
    defer std.testing.allocator.free(b);

    var all = std.ArrayList(QM31).empty;
    defer all.deinit(std.testing.allocator);
    try all.appendSlice(std.testing.allocator, a);
    try all.appendSlice(std.testing.allocator, b);

    var i: usize = 0;
    while (i < all.items.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < all.items.len) : (j += 1) {
            try std.testing.expect(!all.items[i].eql(all.items[j]));
        }
    }
}

test "blake2s channel: mix_felts changes digest" {
    var channel = Blake2sChannel{};
    const before = channel.digestBytes();
    const felts = [_]QM31{
        QM31.fromBase(M31.fromCanonical(1_923_782)),
        QM31.fromBase(M31.fromCanonical(1_923_783)),
    };
    channel.mixFelts(felts[0..]);
    try std.testing.expect(!std.mem.eql(u8, before[0..], channel.digestBytes()[0..]));
}

test "blake2s channel: mix_u64 matches mix_u32s and upstream digest bytes" {
    var channel_64 = Blake2sChannel{};
    channel_64.mixU64(0x1111_2222_3333_4444);
    const digest_64 = channel_64.digestBytes();

    var channel_32 = Blake2sChannel{};
    channel_32.mixU32s(&[_]u32{ 0x3333_4444, 0x1111_2222 });
    try std.testing.expect(std.mem.eql(u8, digest_64[0..], channel_32.digestBytes()[0..]));

    const expected = [_]u8{
        0xbc, 0x9e, 0x3f, 0xc1, 0xd2, 0x4e, 0x88, 0x97,
        0x95, 0x6d, 0x33, 0x59, 0x32, 0x73, 0x97, 0x24,
        0x9d, 0x6b, 0xca, 0xcd, 0x22, 0x4d, 0x92, 0x74,
        0x04, 0xe7, 0xba, 0x4a, 0x77, 0xdc, 0x6e, 0xce,
    };
    try std.testing.expect(std.mem.eql(u8, digest_64[0..], expected[0..]));
}

test "blake2s channel: mix_u32s upstream digest bytes" {
    var channel = Blake2sChannel{};
    channel.mixU32s(&[_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 9 });
    const expected = [_]u8{
        0x70, 0x91, 0x76, 0x83, 0x57, 0xbb, 0x1b, 0xb3,
        0x34, 0x6f, 0xda, 0xb6, 0xb3, 0x57, 0xd7, 0xfa,
        0x46, 0xb8, 0xfb, 0xe3, 0x2c, 0x2e, 0x43, 0x24,
        0xa0, 0xff, 0xc2, 0x94, 0xcb, 0xf9, 0xa1, 0xc7,
    };
    try std.testing.expect(std.mem.eql(u8, channel.digestBytes()[0..], expected[0..]));
}

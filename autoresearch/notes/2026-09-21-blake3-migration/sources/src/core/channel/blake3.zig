//! Experimental BLAKE3 protocol v1. Production keys do not select this suite.
//! All encodings are little endian; digests retain all 256 bits.
const std = @import("std");
const hash = @import("../vcs/blake3_hash.zig");
const m31 = @import("../fields/m31.zig");
const QM31 = @import("../fields/qm31.zig").QM31;
const M31 = m31.M31;
pub const Digest = hash.Blake3Hash;
pub const PROTOCOL_ID = "stwo.blake3.experimental.v1";
pub const MAX_POW_BITS: u32 = 32;

/// One fixed protocol prefix and one byte identifying the operation.
pub const Domain = enum(u8) {
    init = 0,
    words = 1,
    felts = 2,
    integer = 3,
    root = 4,
    draw = 5,
    pow = 6,
    leaf = 7,
    node = 8,
};
pub fn start(domain: Domain) hash.Blake3Hasher {
    var h = hash.Blake3Hasher.init();
    h.update(PROTOCOL_ID);
    h.update(&.{@intFromEnum(domain)});
    return h;
}
pub fn writeInt(h: *hash.Blake3Hasher, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    h.update(&bytes);
}

/// Exact uniform reduction: accepted words have two preimages per M31 value.
pub fn sampleWord(word: u32) ?M31 {
    if (word >= 2 * m31.Modulus) return null;
    return M31.fromU64(word);
}

pub const Channel = struct {
    digest: Digest = initialDigest(),
    n_draws: u64 = 0,
    const Self = @This();

    // BLAKE3(PROTOCOL_ID || init tag), pinned by the independent oracle.
    fn initialDigest() Digest {
        return .{ 0xba, 0xfb, 0x41, 0x3e, 0x8e, 0x24, 0xe7, 0x87, 0xd5, 0x22, 0x2, 0xbb, 0x4d, 0xec, 0xd2, 0x1c, 0x81, 0x91, 0xa4, 0xee, 0xc2, 0x9b, 0xc0, 0x82, 0x2d, 0x59, 0x66, 0xb, 0xdc, 0x49, 0x38, 0x56 };
    }
    pub fn digestBytes(self: Self) Digest {
        return self.digest;
    }
    fn begin(self: Self, domain: Domain) hash.Blake3Hasher {
        var h = start(domain);
        h.update(&self.digest);
        return h;
    }
    fn finish(self: *Self, h: *const hash.Blake3Hasher) void {
        self.digest = h.finalize();
        self.n_draws = 0;
    }
    pub fn mixU32s(self: *Self, words: []const u32) void {
        var h = self.begin(.words);
        writeInt(&h, u64, @intCast(words.len));
        for (words) |word| writeInt(&h, u32, word);
        self.finish(&h);
    }
    pub fn mixU64(self: *Self, value: u64) void {
        var h = self.begin(.integer);
        writeInt(&h, u64, value);
        self.finish(&h);
    }
    pub fn mixFelts(self: *Self, felts: []const QM31) void {
        var h = self.begin(.felts);
        writeInt(&h, u64, @intCast(felts.len));
        for (felts) |felt| for (felt.toM31Array()) |word| {
            writeInt(&h, u32, word.toU32());
        };
        self.finish(&h);
    }
    pub fn mixRoot(self: *Self, root: Digest) void {
        var h = self.begin(.root);
        h.update(&root);
        self.finish(&h);
    }
    pub fn drawU32s(self: *Self) [8]u32 {
        var h = self.begin(.draw);
        writeInt(&h, u64, self.n_draws);
        self.n_draws = std.math.add(u64, self.n_draws, 1) catch @panic("BLAKE3 draw counter exhausted");
        const bytes = h.finalize();
        var result: [8]u32 = undefined;
        for (&result, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
        return result;
    }
    fn drawBaseFelts(self: *Self) [8]M31 {
        while (true) {
            const words = self.drawU32s();
            var values: [8]M31 = undefined;
            var valid = true;
            for (words, &values) |word, *value| {
                value.* = sampleWord(word) orelse {
                    valid = false;
                    break;
                };
            }
            if (valid) return values;
        }
    }
    pub fn drawSecureFelt(self: *Self) QM31 {
        const words = self.drawBaseFelts();
        return QM31.fromM31Array(words[0..4].*);
    }
    /// Match the PCS interface: each block supplies up to two QM31 values.
    pub fn drawSecureFelts(self: *Self, allocator: std.mem.Allocator, count: usize) ![]QM31 {
        const result = try allocator.alloc(QM31, count);
        var i: usize = 0;
        while (i < count) {
            const words = self.drawBaseFelts();
            result[i] = QM31.fromM31Array(words[0..4].*);
            i += 1;
            if (i < count) {
                result[i] = QM31.fromM31Array(words[4..8].*);
                i += 1;
            }
        }
        return result;
    }
    fn powPrefix(self: Self, bits: u32) hash.Blake3Hasher {
        var h = self.begin(.pow);
        writeInt(&h, u32, bits);
        return h;
    }
    fn validNonce(prefix: hash.Blake3Hasher, bits: u32, nonce: u64) bool {
        var h = prefix;
        writeInt(&h, u64, nonce);
        const bytes = h.finalize();
        return @ctz(std.mem.readInt(u32, bytes[0..4], .little)) >= bits;
    }
    pub fn verifyPowNonce(self: Self, bits: u32, nonce: u64) bool {
        if (bits > MAX_POW_BITS) return false;
        return validNonce(self.powPrefix(bits), bits, nonce);
    }
    /// Reference grinder; optimized CPU/device grinding must preserve this nonce predicate.
    pub fn grind(self: Self, bits: u32) u64 {
        if (bits > MAX_POW_BITS) @panic("unsupported BLAKE3 PoW difficulty");
        const prefix = self.powPrefix(bits);
        var nonce: u64 = 0;
        while (!validNonce(prefix, bits, nonce)) {
            nonce = std.math.add(u64, nonce, 1) catch @panic("BLAKE3 nonce space exhausted");
        }
        return nonce;
    }
};

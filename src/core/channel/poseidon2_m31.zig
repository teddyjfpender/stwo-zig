//! Experimental M7 transcript. New domain and 36-byte state; no Blake fallback.
//! Draws return canonical 31-bit words. Query logs and PoW bits must be <=30.
const std = @import("std");
const S = @import("../crypto/poseidon2_m31_sponge.zig");
pub const Qm31Channel = ForField(@import("../fields/qm31.zig").QM31);
pub const Om31Channel = ForField(@import("../fields/om31.zig").OM31);
pub const MAX_POW_BITS = 30;
pub fn ForField(comptime Secure: type) type {
    return struct {
        pub const SecureField = Secure;
        const Self = @This();
        const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
        digest: S.Digest = initialDigest(),
        n_draws: u64 = 0,
        fn initialDigest() S.Digest {
            @setEvalBranchQuota(100000);
            var initial = S.Sponge.init(.mix_words);
            initial.absorbU32(DEGREE);
            return initial.digest();
        }
        pub fn init() Self {
            return .{};
        }
        pub fn digestBytes(self: Self) S.Digest {
            return self.digest;
        }
        pub fn updateDigest(self: *Self, digest: S.Digest) void {
            _ = S.decode(digest) catch @panic("noncanonical Poseidon transcript");
            self.digest = digest;
            self.n_draws = 0;
        }
        fn start(self: Self, domain: S.Domain) S.Sponge {
            var s = S.Sponge.init(domain);
            s.absorbDigest(self.digest);
            return s;
        }
        pub fn mixRoot(self: *Self, root: S.Digest) void {
            var s = self.start(.mix_root);
            s.absorbDigest(root);
            self.updateDigest(s.digest());
        }
        pub fn mixU32s(self: *Self, words: []const u32) void {
            var s = self.start(.mix_words);
            for (words) |word| s.absorbU32(word);
            self.updateDigest(s.digest());
        }
        pub fn mixU64(self: *Self, value: u64) void {
            self.mixU32s(&.{ @truncate(value), @truncate(value >> 32) });
        }
        pub fn mixFelts(self: *Self, values: []const Secure) void {
            var s = self.start(.mix_felts);
            for (values) |value| s.absorbFelts(&value.toM31Array());
            self.updateDigest(s.digest());
        }
        /// Draw counter is checked, never wraps into an earlier challenge.
        pub fn drawU32s(self: *Self) [8]u32 {
            var s = self.start(.draw);
            s.absorbU64(self.n_draws);
            self.n_draws = std.math.add(u64, self.n_draws, 1) catch @panic("Poseidon draw counter exhausted");
            const values = s.finish();
            var out: [8]u32 = undefined;
            for (&out, values[0..8]) |*word, value| word.* = value.v;
            return out;
        }
        pub fn drawSecureFelt(self: *Self) Secure {
            const words = self.drawU32s();
            var values: [DEGREE]S.M31 = undefined;
            for (&values, words[0..DEGREE]) |*value, word| value.* = S.M31.fromCanonical(word);
            return Secure.fromM31Array(values);
        }
        /// One indexed draw per felt, same semantics as repeated scalar draws.
        pub fn drawSecureFelts(self: *Self, a: std.mem.Allocator, count: usize) ![]Secure {
            const out = try a.alloc(Secure, count);
            for (out) |*value| value.* = self.drawSecureFelt();
            return out;
        }
        pub fn verifyPowNonce(self: Self, bits: u32, nonce: u64) bool {
            if (bits > MAX_POW_BITS) return false;
            if (bits == 0) return nonce == 0;
            var s = self.start(.pow);
            s.absorbU32(bits);
            s.absorbU64(nonce);
            return s.finish()[0].v & ((@as(u32, 1) << @intCast(bits)) - 1) == 0;
        }
        /// Canonical smallest natural nonce. GPU implementation must match.
        pub fn grind(self: Self, bits: u32) u64 {
            if (bits > MAX_POW_BITS) @panic("unsupported Poseidon PoW bits");
            var nonce: u64 = 0;
            while (!self.verifyPowNonce(bits, nonce)) : (nonce = std.math.add(u64, nonce, 1) catch @panic("Poseidon nonce exhausted")) {}
            return nonce;
        }
        pub fn grindWithWorkerCount(self: Self, bits: u32, _: usize) u64 {
            return self.grind(bits);
        }
    };
}
test "Poseidon transcripts separate domains, replay draws and grind canonically" {
    inline for (.{ Qm31Channel, Om31Channel }) |Channel| {
        var a = Channel.init();
        var b = a;
        a.mixU32s(&.{ 1, 2 });
        b.mixU32s(&.{ 1, 3 });
        try std.testing.expect(!std.mem.eql(u8, &a.digestBytes(), &b.digestBytes()));
        b = a;
        const many = try a.drawSecureFelts(std.testing.allocator, 5);
        defer std.testing.allocator.free(many);
        for (many) |value| try std.testing.expect(value.eql(b.drawSecureFelt()));
        a.mixFelts(many);
        b.mixFelts(many);
        try std.testing.expectEqualSlices(u8, &a.digestBytes(), &b.digestBytes());
        const nonce = a.grind(5);
        try std.testing.expect(a.verifyPowNonce(5, nonce));
        for (0..nonce) |n| try std.testing.expect(!a.verifyPowNonce(5, n));
        try std.testing.expect(!a.verifyPowNonce(31, 0));
        try std.testing.expect(!a.verifyPowNonce(0, 1));
        try std.testing.expectEqual(@as(u64, 0), a.grind(0));
    }
}

test "Poseidon OM31 transcript matches independent Python framing" {
    var c = Om31Channel.init();
    const om31_initial: [9]u32 = .{ 1330976328, 831062042, 1895455003, 48331469, 559002403, 963616176, 541419123, 498048611, 975458412 };
    const om31_initial_values = try S.decode(c.digestBytes());
    for (om31_initial_values, om31_initial) |actual, expected| try std.testing.expectEqual(expected, actual.v);
    c.mixU32s(&.{ 0xffffffff, 2147483647 });
    const mixed_max_and_p: [9]u32 = .{ 348281176, 2081254126, 754483733, 834140345, 694420978, 965114686, 1021524188, 194545677, 29427344 };
    const mixed_max_and_p_values = try S.decode(c.digestBytes());
    for (mixed_max_and_p_values, mixed_max_and_p) |actual, expected| try std.testing.expectEqual(expected, actual.v);
    const draw: [8]u32 = .{ 637042778, 932126381, 313942954, 1285771035, 1162516394, 1897078136, 2128892566, 1090472593 };
    try std.testing.expectEqualSlices(u32, &draw, &c.drawU32s());
}

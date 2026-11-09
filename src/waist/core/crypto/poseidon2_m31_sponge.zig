//! Experimental M7 w24/r12/c12 sponge. Nine canonical M31 digest limbs.
//! This is a new protocol, not wire-compatible with any Blake profile.
const std = @import("std");
const F = @import("../fields/m31.zig");
const P = @import("poseidon2_m31_w24.zig");
pub const M31 = F.M31;
pub const RATE = 12;
pub const DIGEST_WORDS = 9;
pub const Digest = [36]u8;
pub const Domain = enum(u32) { leaf = 1, node = 2, mix_words = 3, mix_felts = 4, mix_root = 5, draw = 6, pow = 7, words = 8, bytes = 9 };
pub const PROFILE_NAME = "M7-P2M31-W24-R12-C12-D9-v1";
pub const Sponge = struct {
    state: P.State,
    at: usize = 0,
    pub fn init(domain: Domain) Sponge {
        var state = [_]M31{M31.zero()} ** P.WIDTH;
        state[22] = M31.fromCanonical(1);
        state[23] = M31.fromCanonical(@intFromEnum(domain));
        return .{ .state = state };
    }
    pub fn absorb(self: *Sponge, value: M31) void {
        std.debug.assert(value.v < F.Modulus);
        self.state[self.at] = self.state[self.at].add(value);
        self.at += 1;
        if (self.at == RATE) {
            P.permute(&self.state);
            self.at = 0;
        }
    }
    pub fn absorbFelts(self: *Sponge, values: []const M31) void {
        for (values) |v| self.absorb(v);
    }
    /// Injective raw-u32 encoding. Never reduce arbitrary u32 modulo p.
    pub fn absorbU32(self: *Sponge, word: u32) void {
        self.absorb(M31.fromCanonical(word & 0xffff));
        self.absorb(M31.fromCanonical(word >> 16));
    }
    pub fn absorbU64(self: *Sponge, word: u64) void {
        self.absorbU32(@truncate(word));
        self.absorbU32(@truncate(word >> 32));
    }
    pub fn absorbDigest(self: *Sponge, bytes: Digest) void {
        const values = decode(bytes) catch @panic("noncanonical Poseidon2 digest");
        self.absorbFelts(&values);
    }
    /// Mandatory end marker, including an extra block at exact rate boundaries.
    pub fn finish(self: Sponge) [DIGEST_WORDS]M31 {
        var result = self;
        result.state[result.at] = result.state[result.at].add(M31.one());
        P.permute(&result.state);
        return result.state[0..DIGEST_WORDS].*;
    }
    pub fn digest(self: Sponge) Digest {
        return encode(self.finish());
    }
};
pub fn encode(values: [DIGEST_WORDS]M31) Digest {
    var bytes: Digest = undefined;
    for (values, 0..) |value, i| {
        std.debug.assert(value.v < F.Modulus);
        std.mem.writeInt(u32, bytes[4 * i ..][0..4], value.v, .little);
    }
    return bytes;
}
pub fn decode(bytes: Digest) ![DIGEST_WORDS]M31 {
    var values: [DIGEST_WORDS]M31 = undefined;
    for (&values, 0..) |*value, i| {
        const word = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
        if (word >= F.Modulus) return error.NonCanonicalPoseidonDigest;
        value.* = M31.fromCanonical(word);
    }
    return values;
}
pub fn identity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PROFILE_NAME);
    hash.update(&P.parameterIdentity());
    // Pins additive absorption, 16-bit raw-word encoding, mandatory 1 padding,
    // capacity words version/domain, canonical nine-word LE serialization.
    hash.update("additive/le16/one-pad/cap22-version1-cap23-domain/9le32");
    return hash.finalResult();
}
test "Poseidon sponge encoding, framing and raw words are injective" {
    var a = Sponge.init(.leaf);
    var b = Sponge.init(.node);
    try std.testing.expect(!std.mem.eql(u8, &a.digest(), &b.digest()));
    b = a;
    b.absorb(M31.zero());
    try std.testing.expect(!std.mem.eql(u8, &a.digest(), &b.digest()));
    a.absorbU32(0);
    b = Sponge.init(.leaf);
    b.absorbU32(F.Modulus);
    try std.testing.expect(!std.mem.eql(u8, &a.digest(), &b.digest()));
    const words = try decode(a.digest());
    try std.testing.expectEqualSlices(u8, &a.digest(), &encode(words));
    var bad = a.digest();
    std.mem.writeInt(u32, bad[0..4], F.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalPoseidonDigest, decode(bad));
    for (0..25) |count| {
        a = Sponge.init(.leaf);
        b = a;
        for (0..count) |_| {
            a.absorb(M31.one());
            b.absorb(M31.one());
        }
        b.absorb(M31.zero());
        try std.testing.expect(!std.mem.eql(u8, &a.digest(), &b.digest()));
    }
}

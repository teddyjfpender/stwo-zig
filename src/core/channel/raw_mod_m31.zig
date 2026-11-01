//! Additive experimental raw-Blake modulo-M31 profiles. Neither profile is
//! selected by an existing prover/verifier. Legacy rejection sampling is unchanged.
const std = @import("std");
const B = @import("blake2s.zig");
const M = @import("../fields/m31.zig");
const Q = @import("../fields/qm31.zig").QM31;
const O = @import("../fields/om31.zig").OM31;
pub const Profile = struct {
    degree: u32,
    values_per_block: u32,
    pub fn tag(self: Profile) [8]u32 {
        return .{ 0x5354574f, 0x524d3331, 1, M.Modulus, 32, 8, self.degree, self.values_per_block };
    }
    pub fn identity(self: Profile) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-native-raw-u32-mod-m31/v1\x00");
        for (self.tag()) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            hash.update(&bytes);
        }
        return hash.finalResult();
    }
};
pub const qm31_profile = Profile{ .degree = 4, .values_per_block = 2 };
pub const om31_profile = Profile{ .degree = 8, .values_per_block = 1 };
/// Exact max point mass per coordinate is3/2^32. Relative to uniform M31
/// its density is3p/2^32 <3/2. These are bounds, not a security certificate.
pub const MAX_PREIMAGES: u32 = 3;
pub const RAW_ORDER: u64 = @as(u64, 1) << 32;
pub fn reduceWords(words: [8]u32) [8]M.M31 {
    var out: [8]M.M31 = undefined;
    for (&out, words) |*v, word| v.* = M.M31.fromU64(word);
    return out;
}
fn initInner(profile: Profile) B.Blake2sChannel {
    var inner: B.Blake2sChannel = .{};
    inner.mixU32s(&profile.tag());
    return inner;
}
pub const Qm31Channel = struct {
    inner: B.Blake2sChannel,
    pub const profile = qm31_profile;
    pub fn init() Qm31Channel {
        return .{ .inner = initInner(profile) };
    }
    pub fn digestBytes(self: Qm31Channel) [32]u8 {
        return self.inner.digestBytes();
    }
    pub fn mixU32s(self: *Qm31Channel, values: []const u32) void {
        self.inner.mixU32s(values);
    }
    pub fn mixU64(self: *Qm31Channel, value: u64) void {
        self.inner.mixU64(value);
    }
    pub fn mixFelts(self: *Qm31Channel, values: []const Q) void {
        self.inner.mixFelts(values);
    }
    pub fn drawU32s(self: *Qm31Channel) [8]u32 {
        return self.inner.drawU32s();
    }
    pub fn drawSecureFelt(self: *Qm31Channel) Q {
        const words = reduceWords(self.drawU32s());
        return Q.fromM31Array(words[0..4].*);
    }
    pub fn drawSecureFelts(self: *Qm31Channel, a: std.mem.Allocator, count: usize) ![]Q {
        const out = try a.alloc(Q, count);
        var at: usize = 0;
        while (at < count) {
            const words = reduceWords(self.drawU32s());
            out[at] = Q.fromM31Array(words[0..4].*);
            at += 1;
            if (at < count) {
                out[at] = Q.fromM31Array(words[4..8].*);
                at += 1;
            }
        }
        return out;
    }
};
pub const Om31Channel = struct {
    inner: B.Blake2sChannel,
    pub const profile = om31_profile;
    pub fn init() Om31Channel {
        return .{ .inner = initInner(profile) };
    }
    pub fn digestBytes(self: Om31Channel) [32]u8 {
        return self.inner.digestBytes();
    }
    pub fn mixU32s(self: *Om31Channel, values: []const u32) void {
        self.inner.mixU32s(values);
    }
    pub fn mixU64(self: *Om31Channel, value: u64) void {
        self.inner.mixU64(value);
    }
    pub fn mixFelts(self: *Om31Channel, values: []const O) void {
        var hash = @import("../vcs/blake2_hash.zig").Blake2sHasher.init();
        hash.update(&self.inner.digest);
        for (values) |value| hash.update(&value.toBytesLe());
        self.inner.updateDigest(hash.finalize());
    }
    pub fn drawU32s(self: *Om31Channel) [8]u32 {
        return self.inner.drawU32s();
    }
    pub fn drawSecureFelt(self: *Om31Channel) O {
        return O.fromM31Array(reduceWords(self.drawU32s()));
    }
    pub fn drawSecureFelts(self: *Om31Channel, a: std.mem.Allocator, count: usize) ![]O {
        const out = try a.alloc(O, count);
        for (out) |*value| value.* = self.drawSecureFelt();
        return out;
    }
};
test {
    _ = @import("raw_mod_m31_test.zig");
}

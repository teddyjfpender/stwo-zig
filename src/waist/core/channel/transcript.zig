const std = @import("std");
const hash256 = @import("../crypto/hash256.zig");
const m31 = @import("../fields/m31.zig");

const Hasher256 = hash256.Hasher256;
const Digest32 = hash256.Digest32;
const M31 = m31.M31;

const PREFIX_INIT: u8 = 0x80;
const PREFIX_ABSORB: u8 = 0x81;
const PREFIX_SQUEEZE: u8 = 0x82;

/// Deterministic Fiat–Shamir transcript.
///
/// This is intentionally simple at this milestone:
/// - a 32-byte state
/// - a squeeze counter
/// - domain separated by one-byte prefixes
pub const Transcript = struct {
    state: Digest32,
    counter: u64,

    pub fn init(label: []const u8) Transcript {
        return .{
            .state = hash256.hashPrefix1(PREFIX_INIT, label),
            .counter = 0,
        };
    }

    pub fn absorb(self: *Transcript, label: []const u8, data: []const u8) void {
        var h = Hasher256.init();
        h.update(&[_]u8{PREFIX_ABSORB});
        h.update(self.state[0..]);
        h.update(label);
        h.update(data);
        h.final(&self.state);
        self.counter = 0;
    }

    pub fn squeezeBlock(self: *Transcript) Digest32 {
        var h = Hasher256.init();
        h.update(&[_]u8{PREFIX_SQUEEZE});
        h.update(self.state[0..]);
        const ctr_bytes = u64ToBytesLe(self.counter);
        h.update(ctr_bytes[0..]);
        h.final(&self.state);
        self.counter += 1;
        return self.state;
    }

    pub fn challengeM31(self: *Transcript) M31 {
        while (true) {
            const block = self.squeezeBlock();
            const x = readU32Le(block[0..4]) & m31.Modulus;
            if (x != m31.Modulus) return M31.fromCanonical(x);
        }
    }

    pub fn challengeU64(self: *Transcript) u64 {
        const block = self.squeezeBlock();
        return readU64Le(block[0..8]);
    }
};

fn u64ToBytesLe(x: u64) [8]u8 {
    return .{
        @intCast(x & 0xff),
        @intCast((x >> 8) & 0xff),
        @intCast((x >> 16) & 0xff),
        @intCast((x >> 24) & 0xff),
        @intCast((x >> 32) & 0xff),
        @intCast((x >> 40) & 0xff),
        @intCast((x >> 48) & 0xff),
        @intCast((x >> 56) & 0xff),
    };
}

fn readU32Le(bytes: []const u8) u32 {
    std.debug.assert(bytes.len == 4);
    return (@as(u32, bytes[0])) |
        (@as(u32, bytes[1]) << 8) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 24);
}

fn readU64Le(bytes: []const u8) u64 {
    std.debug.assert(bytes.len == 8);
    return (@as(u64, bytes[0])) |
        (@as(u64, bytes[1]) << 8) |
        (@as(u64, bytes[2]) << 16) |
        (@as(u64, bytes[3]) << 24) |
        (@as(u64, bytes[4]) << 32) |
        (@as(u64, bytes[5]) << 40) |
        (@as(u64, bytes[6]) << 48) |
        (@as(u64, bytes[7]) << 56);
}

test "transcript: determinism" {
    var t1 = Transcript.init("test");
    var t2 = Transcript.init("test");

    t1.absorb("a", "hello");
    t2.absorb("a", "hello");

    const c1 = t1.challengeM31();
    const c2 = t2.challengeM31();
    try std.testing.expect(c1.eql(c2));

    const n1 = t1.challengeU64();
    const n2 = t2.challengeU64();
    try std.testing.expect(n1 == n2);
}

test "transcript: domain separation" {
    var t1 = Transcript.init("label-1");
    var t2 = Transcript.init("label-2");

    t1.absorb("a", "hello");
    t2.absorb("a", "hello");

    const c1 = t1.challengeM31();
    const c2 = t2.challengeM31();

    // Extremely unlikely to collide.
    try std.testing.expect(!c1.eql(c2));
}

test "transcript: challengeM31 returns canonical" {
    var t = Transcript.init("canon");
    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        const c = t.challengeM31();
        try std.testing.expect(c.toU32() < m31.Modulus);
    }
}

//! Fiat-Shamir transcript for the tensor frontend: stwo's Blake2s channel.
const std = @import("std");
const core = @import("stwo_core");
const f = @import("field.zig");

const QM31 = f.QM31;
const Blake2s = core.channel.blake2s.Blake2sChannel;
/// stwo's Blake2s channel; in an -Dchallenge=om31 build, the same channel
/// with felts of the degree-8 field (Om31Blake2s).
pub const Channel = if (f.IS_OM31) Om31Blake2s else Blake2s;

/// Blake2s channel over OM31 = QM31[v]/(v^2-u): an OM31 felt is mixed as its
/// two QM31 halves (c0, c1) and drawn from one hash output: stwo's base-felt
/// rejection sampling (all 8 words < 2p, each reduced mod p; drawBaseFelts
/// in core/channel/blake2s.zig), all 8 coordinates used. Each coordinate is
/// uniform on M31 given acceptance (2p is a multiple of p), so the draw is
/// uniform on p^8.
pub const Om31Blake2s = struct {
    inner: Blake2s = .{},

    pub fn mixU32s(self: *Om31Blake2s, v: []const u32) void {
        self.inner.mixU32s(v);
    }
    pub fn mixU64(self: *Om31Blake2s, v: u64) void {
        self.inner.mixU64(v);
    }
    pub fn mixFelts(self: *Om31Blake2s, v: []const QM31) void {
        var buf: [64]f.Q4 = undefined;
        var i: usize = 0;
        while (i < v.len) {
            const n: usize = @min(v.len - i, buf.len / 2);
            for (v[i..][0..n], 0..) |x, k| {
                buf[2 * k] = x.c0;
                buf[2 * k + 1] = x.c1;
            }
            self.inner.mixFelts(buf[0 .. 2 * n]);
            i += n;
        }
    }
    pub fn drawSecureFelt(self: *Om31Blake2s) QM31 {
        while (true) {
            const words = self.inner.drawU32s();
            var ok = true;
            for (words) |x| ok = ok and x < 2 * f.P;
            if (!ok) continue;
            var m: [8]f.M31 = undefined;
            for (words, 0..) |x, i| m[i] = f.M31.fromCanonical(x % f.P);
            return QM31.fromM31Array(m);
        }
    }
    pub fn drawU32s(self: *Om31Blake2s) [8]u32 {
        return self.inner.drawU32s();
    }
    pub fn grind(self: *Om31Blake2s, bits: u32) u64 {
        return self.inner.grind(bits);
    }
    pub fn verifyPowNonce(self: *Om31Blake2s, bits: u32, nonce: u64) bool {
        return self.inner.verifyPowNonce(bits, nonce);
    }
    pub fn digestBytes(self: Om31Blake2s) [32]u8 {
        return self.inner.digestBytes();
    }
};

pub const Transcript = struct {
    ch: Channel = .{},

    pub fn initDomain(label: []const u8) Transcript {
        var t = Transcript{};
        var words: [16]u32 = [_]u32{0} ** 16;
        for (label, 0..) |c, i| {
            if (i >= 64) break;
            words[i / 4] |= @as(u32, c) << @intCast(8 * (i % 4));
        }
        t.ch.mixU32s(&words);
        // degree-8 proofs are domain-separated from QM31 proofs (the default
        // build mixes nothing extra: its transcripts are unchanged)
        if (f.IS_OM31) t.ch.mixU32s(&.{ 0x4f4d3331, f.CHALLENGE_DEGREE });
        return t;
    }

    pub fn mixDigest(self: *Transcript, d: [32]u8) void {
        var w: [8]u32 = undefined;
        for (0..8) |i| w[i] = std.mem.readInt(u32, d[i * 4 ..][0..4], .little);
        self.ch.mixU32s(&w);
    }

    pub fn mixU64(self: *Transcript, v: u64) void {
        self.ch.mixU64(v);
    }

    pub fn mixU32s(self: *Transcript, v: []const u32) void {
        self.ch.mixU32s(v);
    }

    pub fn mixFelts(self: *Transcript, v: []const QM31) void {
        self.ch.mixFelts(v);
    }

    pub fn mixFelt(self: *Transcript, v: QM31) void {
        self.ch.mixFelts(&.{v});
    }

    pub fn draw(self: *Transcript) QM31 {
        return self.ch.drawSecureFelt();
    }

    pub fn drawN(self: *Transcript, out: []QM31) void {
        for (out) |*o| o.* = self.ch.drawSecureFelt();
    }

    /// Draw `out.len` indices uniformly in [0, 2^log_n).
    pub fn drawIndices(self: *Transcript, log_n: u32, out: []usize) void {
        var i: usize = 0;
        const mask: u32 = if (log_n >= 32) 0xffff_ffff else (@as(u32, 1) << @intCast(log_n)) - 1;
        while (i < out.len) {
            const words = self.ch.drawU32s();
            for (words) |w| {
                if (i >= out.len) break;
                out[i] = w & mask;
                i += 1;
            }
        }
    }

    pub fn grind(self: *Transcript, bits: u32) u64 {
        if (bits == 0) return 0;
        const nonce = self.ch.grind(bits);
        self.ch.mixU64(nonce);
        return nonce;
    }

    pub fn verifyPow(self: *Transcript, bits: u32, nonce: u64) bool {
        if (bits == 0) return true;
        if (!self.ch.verifyPowNonce(bits, nonce)) return false;
        self.ch.mixU64(nonce);
        return true;
    }
};

//! Fiat-Shamir transcript for the tensor frontend: stwo's Blake2s channel.
const std = @import("std");
const core = @import("stwo_core");
const f = @import("field.zig");

const QM31 = f.QM31;
pub const Channel = core.channel.blake2s.Blake2sChannel;

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

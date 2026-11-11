//! Independent expected CPU retirement records. These are never reconstructed
//! from descriptor MAIN. A fragment does not grant execution acceptance.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak_sponge;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const F = @import("fractions.zig");
pub const Call = struct { pointer: u64, epoch: u16, tick: u24 };
pub const Boundary = struct {
    calls: []const Call,
    pub fn digest(self: Boundary) ![32]u8 {
        if (self.calls.len == 0 or self.calls.len >= core.fields.m31.Modulus) return error.SpongeLocalBoundary;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("op-serialized-sponge-expected-cpu-owner/v1");
        var count: [8]u8 = undefined;
        std.mem.writeInt(u64, &count, self.calls.len, .little);
        hash.update(&count);
        for (self.calls) |call| {
            if (call.pointer % 8 != 0 or call.epoch == 0 or call.tick == 0) return error.SpongeLocalBoundary;
            var words: [16]u8 = @splat(0);
            std.mem.writeInt(u64, words[0..8], call.pointer, .little);
            std.mem.writeInt(u32, words[8..12], call.epoch, .little);
            std.mem.writeInt(u32, words[12..16], call.tick, .little);
            hash.update(&words);
        }
        return hash.finalResult();
    }
    pub fn ownerClaim(self: Boundary, ch: F.Challenges) !O {
        _ = try self.digest();
        var out = O.zero();
        for (self.calls) |call| {
            var m: [K.serialized.descriptor.MAIN]O = @splat(O.zero());
            for (m[K.layout.call.pointer..][0..4], 0..) |*v, i| v.* = O.fromBase(M.fromCanonical(@as(u16, @truncate(call.pointer >> @as(u6, @intCast(16 * i))))));
            m[K.layout.call.epoch] = O.fromBase(M.fromCanonical(call.epoch));
            m[K.layout.call.tick_low] = O.fromBase(M.fromCanonical(@as(u16, @truncate(call.tick))));
            m[K.layout.call.tick_high] = O.fromBase(M.fromCanonical(call.tick >> 16));
            const tuple = K.equations.ecallTuple(O, &m);
            const d = A.evaluation.denominatorFor(O, ch.owner.offset, &ch.owner.coefficients, &tuple, true);
            if (d.isZero()) return error.LocalGkrPole;
            out = out.add(try d.inv());
        }
        return out;
    }
};

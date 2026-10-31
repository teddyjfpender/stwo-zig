//! Public encoded claims and owning proof bundle for the canonical service lane.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const T = @import("types.zig");
const G = @import("../protocol.zig");
const P = @import("protocol.zig");
const R = @import("roster.zig");
const Source = @import("../../word16_execution/sources.zig");
const Q = G.Q;
pub const CpuClaims = struct {
    base: G.Old.Claims,
    extras: [3]T.ExtraClaims,
    pub fn values(self: @This()) [P.CPU_CLAIM_COUNT]Q {
        var out: [P.CPU_CLAIM_COUNT]Q = undefined;
        out[0..P.CORE_CLAIM_COUNT].* = self.base.values();
        for (self.extras, 0..) |extra, k| out[P.CORE_CLAIM_COUNT + 5 * k ..][0..5].* = extra.values();
        return out;
    }
    pub fn canonical(self: @This()) !void {
        try Source.validateCanonicalClaims(self.base);
        for (self.extras) |b| for (b.values()) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalSecpClaim;
    }
    pub fn presence(self: @This(), setup: *const R.CpuSetup) !void {
        for (self.extras, 0..) |c, k| if (setup.bridges.at(@enumFromInt(k)) == null) {
            for (c.values()) |q| if (!q.isZero()) return error.NonzeroAbsentServiceClaim;
        };
    }
    pub fn ram(self: @This()) Q {
        const base = G.Old.ramClaim(self.base);
        var sum = base;
        for (self.extras) |c| sum = sum.add(c.ram);
        return sum;
    }
    pub fn local(self: @This()) !void {
        var sum = Q.zero();
        for (self.values()) |v| sum = sum.add(v);
        sum = sum.sub(self.ram());
        for (self.extras) |c| sum = sum.sub(c.truth);
        if (!sum.isZero()) return error.UnclosedCombinedCpuRelations;
    }
};
pub const CpuEncoded = struct {
    bytes: []u8,
    request: P.Request,
    claims: CpuClaims,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.request.base.memory.initial);
        a.free(self.request.base.memory.terminal);
    }
};
pub const TruthEncoded = struct { bytes: []u8, claims: [3]Q };
pub const Bundle = struct {
    manifest: G.Manifest,
    cpus: []CpuEncoded,
    truths: []TruthEncoded,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        for (self.cpus) |*p| p.deinit(a);
        a.free(self.cpus);
        for (self.truths) |t| a.free(t.bytes);
        a.free(self.truths);
        self.manifest.deinit();
    }
};

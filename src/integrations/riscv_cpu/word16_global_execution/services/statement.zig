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
    /// Bulk-memory claims (desc, copy, set): RAM14, OWNER19, U16. Zero and
    /// omitted from JSON/transcript when the CPU setup has no bulk component.
    bulk: [3]T.BulkClaims = @splat(T.BulkClaims.zero()),
    pub fn jsonStringify(self: @This(), jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("base");
        try jws.write(self.base);
        try jws.objectField("extras");
        try jws.write(self.extras);
        if (!self.bulkZero()) {
            try jws.objectField("bulk");
            try jws.write(self.bulk);
        }
        try jws.endObject();
    }
    fn bulkZero(self: @This()) bool {
        for (self.bulk) |c| for (c.values()) |q| if (!q.isZero()) return false;
        return true;
    }
    pub fn bulkValues(self: @This()) [9]Q {
        var out: [9]Q = undefined;
        for (self.bulk, 0..) |c, k| out[3 * k ..][0..3].* = c.values();
        return out;
    }
    /// Transcript claims: the v2 block, then the bulk block only when present.
    pub fn mixInto(self: @This(), channel: anytype, setup: *const R.CpuSetup) void {
        channel.mixFelts(&self.values());
        if (setup.bridges.bulk.any()) channel.mixFelts(&self.bulkValues());
    }
    pub fn values(self: @This()) [P.CPU_CLAIM_COUNT]Q {
        var out: [P.CPU_CLAIM_COUNT]Q = undefined;
        out[0..P.CORE_CLAIM_COUNT].* = self.base.values();
        for (self.extras, 0..) |extra, k| out[P.CORE_CLAIM_COUNT + 5 * k ..][0..5].* = extra.values();
        return out;
    }
    pub fn canonical(self: @This()) !void {
        try Source.validateCanonicalClaims(self.base);
        for (self.extras) |b| for (b.values()) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalSecpClaim;
        for (self.bulkValues()) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalSecpClaim;
    }
    pub fn presence(self: @This(), setup: *const R.CpuSetup) !void {
        for (self.extras, 0..) |c, k| if (setup.bridges.at(@enumFromInt(k)) == null) {
            for (c.values()) |q| if (!q.isZero()) return error.NonzeroAbsentServiceClaim;
        };
        for (T.bulk_kinds, self.bulk) |kind, c| if (setup.bridges.bulk.at(kind) == null) {
            for (c.values()) |q| if (!q.isZero()) return error.NonzeroAbsentServiceClaim;
        };
    }
    pub fn ram(self: @This()) Q {
        const base = G.Old.ramClaim(self.base);
        var sum = base;
        for (self.extras) |c| sum = sum.add(c.ram);
        for (self.bulk) |c| sum = sum.add(c.ram);
        return sum;
    }
    pub fn local(self: @This()) !void {
        var sum = Q.zero();
        for (self.values()) |v| sum = sum.add(v);
        for (self.bulkValues()) |v| sum = sum.add(v);
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

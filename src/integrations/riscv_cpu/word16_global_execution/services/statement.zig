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
    /// Families in T.Family order; an absent bridge's claims are zero.
    extras: [T.FAMILIES]T.ExtraClaims,
    /// Bulk-memory claims in T.bulk_kinds order (desc, copy, set, then the
    /// extension ucopy, cdesc, cmp): RAM14, OWNER19, U16. Zero and omitted from
    /// the transcript (and wire, see WireClaims) when the CPU setup has no
    /// bulk component (resp. no extension component).
    bulk: [T.bulk_kinds.len]T.BulkClaims = @splat(T.BulkClaims.zero()),
    /// Keccak-sponge claims (call, perm): RAM14, OWNER19, IO11, AND, U16, U8.
    /// Zero and omitted from transcript and wire when the setup has no sponge.
    sponge: [2]T.SpongeClaims = @splat(T.SpongeClaims.zero()),
    pub fn spongeValues(self: @This()) [12]Q {
        var out: [12]Q = undefined;
        for (self.sponge, 0..) |c, k| out[6 * k ..][0..6].* = c.values();
        return out;
    }
    pub fn bulkValues(self: @This()) [3 * T.bulk_kinds.len]Q {
        var out: [3 * T.bulk_kinds.len]Q = undefined;
        for (self.bulk, 0..) |c, k| out[3 * k ..][0..3].* = c.values();
        return out;
    }
    pub fn values(self: @This()) [P.CORE_CLAIM_COUNT + 5 * T.FAMILIES]Q {
        var out: [P.CORE_CLAIM_COUNT + 5 * T.FAMILIES]Q = undefined;
        out[0..P.CORE_CLAIM_COUNT].* = self.base.values();
        for (self.extras, 0..) |extra, k| out[P.CORE_CLAIM_COUNT + 5 * k ..][0..5].* = extra.values();
        return out;
    }
    /// Transcript length: v2 shards (no v3 bridge) mix exactly the v2
    /// vector, then five claims per PRESENT v3 bridge in T.V3 order;
    /// presence() separately forces every absent claim to zero.
    pub fn count(setup: *const R.CpuSetup) usize {
        var n: usize = P.CPU_CLAIM_COUNT;
        for (T.V3) |f| n += if (setup.bridges.at(f) != null) @as(usize, 5) else 0;
        return n;
    }
    pub fn mix(self: @This(), channel: anytype, setup: *const R.CpuSetup) void {
        const all = self.values();
        // ONE mixFelts call over the v2 vector followed by the claims of each
        // present v3 family in T.V3 order (a channel mix is not
        // concatenation-invariant, so splitting it would change SHA-only
        // transcripts relative to the pre-arith encoding).
        var buffer: [P.CORE_CLAIM_COUNT + 5 * T.FAMILIES]Q = undefined;
        @memcpy(buffer[0..P.CPU_CLAIM_COUNT], all[0..P.CPU_CLAIM_COUNT]);
        var n: usize = P.CPU_CLAIM_COUNT;
        for (T.V3) |f| if (setup.bridges.at(f) != null) {
            const k = @intFromEnum(f);
            @memcpy(buffer[n..][0..5], all[P.CORE_CLAIM_COUNT + 5 * k ..][0..5]);
            n += 5;
        };
        channel.mixFelts(buffer[0..n]);
        // Bulk block last and only when present: v2, SHA-only and
        // arith-only transcripts are unchanged.
        const bulk = self.bulkValues();
        if (setup.bridges.bulk.any()) channel.mixFelts(bulk[0 .. 3 * T.BULK_BASE]);
        // Bulk extension (unaligned memcpy, memcmp) after it, only when present.
        if (setup.bridges.bulk.anyExtension()) channel.mixFelts(bulk[3 * T.BULK_BASE .. 3 * T.BULK_EXT]);
        // Sponge block after bulk, only when present.
        if (setup.bridges.sponge.any()) channel.mixFelts(&self.spongeValues());
        // JUMPDEST block after the sponge, only when present.
        if (setup.bridges.bulk.jump()) channel.mixFelts(bulk[3 * T.BULK_EXT ..]);
    }
    pub fn canonical(self: @This()) !void {
        try Source.validateCanonicalClaims(self.base);
        for (self.extras) |b| for (b.values()) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalSecpClaim;
        for (self.bulkValues()) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalSecpClaim;
        for (self.spongeValues()) |q| for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalSecpClaim;
    }
    pub fn presence(self: @This(), setup: *const R.CpuSetup) !void {
        for (self.extras, 0..) |c, k| if (setup.bridges.at(@enumFromInt(k)) == null) {
            for (c.values()) |q| if (!q.isZero()) return error.NonzeroAbsentServiceClaim;
        };
        for (T.bulk_kinds, self.bulk) |kind, c| if (setup.bridges.bulk.at(kind) == null) {
            for (c.values()) |q| if (!q.isZero()) return error.NonzeroAbsentServiceClaim;
        };
        for (T.sponge_kinds, self.sponge) |kind, c| if (setup.bridges.sponge.at(kind) == null) {
            for (c.values()) |q| if (!q.isZero()) return error.NonzeroAbsentServiceClaim;
        };
    }
    pub fn ram(self: @This()) Q {
        const base = G.Old.ramClaim(self.base);
        var sum = base;
        for (self.extras) |c| sum = sum.add(c.ram);
        for (self.bulk) |c| sum = sum.add(c.ram);
        for (self.sponge) |c| sum = sum.add(c.ram);
        return sum;
    }
    pub fn local(self: @This()) !void {
        var sum = Q.zero();
        for (self.values()) |v| sum = sum.add(v);
        for (self.bulkValues()) |v| sum = sum.add(v);
        for (self.spongeValues()) |v| sum = sum.add(v);
        sum = sum.sub(self.ram());
        for (self.extras) |c| sum = sum.sub(c.truth);
        for (self.sponge) |c| sum = sum.sub(c.io);
        if (!sum.isZero()) return error.UnclosedCombinedCpuRelations;
    }
    /// Shared Keccak IO11 debt of this shard: the Keccak-f bridge and both
    /// sponge components (links cancel inside the sponge's own claims).
    pub fn io(self: @This()) Q {
        var sum = self.extras[0].truth;
        for (self.sponge) |c| sum = sum.add(c.io);
        return sum;
    }
    /// Shared Wire35 debt of this shard: every non-Keccak bridge.
    pub fn wire(self: @This()) Q {
        var sum = Q.zero();
        for (self.extras[1..]) |c| sum = sum.add(c.truth);
        return sum;
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

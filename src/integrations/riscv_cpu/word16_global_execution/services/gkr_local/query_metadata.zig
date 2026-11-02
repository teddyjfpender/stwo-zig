//! Static raw-fraction cardinalities generated from the actual polynomial
//! emitters. Values/claims are irrelevant here: only relation labels are counted.
//! This is no proof component and supplies no witness or acceptance authority.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const M = core.fields.m31.M31;
const Fns = @import("fractions.zig");
const Geometry = @import("../../../word16_execution/geometry.zig");
const Types = @import("../types.zig");
const Role = @import("role.zig");
const Table = @import("table_role.zig");
const Roster = @import("roster.zig");
pub const Counts = [std.meta.fields(Fns.Relation).len]u32;
const Counter = struct {
    counts: Counts = @splat(0),
    pub fn emit(self: *@This(), relation: Fns.Relation, tuple: anytype, _: M) void {
        std.debug.assert(tuple.len == relation.arity());
        self.counts[@intFromEnum(relation)] += 1;
    }
};
fn coreCounts(kind: Geometry.Role) Counts {
    const fixed = [_]M{M.zero()} ** 34;
    const main = [_]M{M.zero()} ** 134;
    var sink = Counter{};
    if (kind == .initial or kind == .terminal) return sink.counts;
    if (kind == .boundary) {
        // The public-register boundary has no MAIN. The same roster authority
        // supplies its two signed unit queries; actual boundary tests compare it.
        sink.counts[@intFromEnum(Fns.Relation.register)] = Roster.terms(kind);
        return sink.counts;
    }
    if (Table.kindForRole(kind)) |table| {
        switch (table) {
            .rom => Fns.romFor(M, &fixed, &main, &sink),
            .range16 => Fns.scalarTableFor(M, .range16, &fixed, &main, &sink),
            .range8 => Fns.scalarTableFor(M, .range8, &fixed, &main, &sink),
            .and_table => Fns.andTableFor(M, &fixed, &main, &sink),
            .shift_table => Fns.shiftTableFor(M, &fixed, &main, &sink),
            .selection => Fns.selectionTableFor(M, &fixed, &main, &sink),
            .boundary => unreachable,
        }
    } else |_| {
        const role = Role.mainRole(kind) catch unreachable;
        const shape = A.main_only.authority.shape(role);
        Role.emitLocalFor(M, role, fixed[0..shape.fixed], main[0..shape.main], M.zero(), &sink);
    }
    return sink.counts;
}
fn bridgeCounts(kind: Types.Family) Counts {
    const fixed = [_]M{M.zero()} ** 34;
    const main = [_]M{M.zero()} ** 134;
    var sink = Counter{};
    if (kind == .keccak) Fns.keccakBridgeFor(M, &fixed, &main, &sink) else Fns.secpBridgeFor(M, if (kind == .add) .add else .double, &fixed, &main, &sink);
    return sink.counts;
}
pub const CORE: [Geometry.ROLE_COUNT]Counts = blk: {
    @setEvalBranchQuota(1000000);
    var result: [Geometry.ROLE_COUNT]Counts = undefined;
    for (std.enums.values(Geometry.Role), &result) |kind, *row| row.* = coreCounts(kind);
    break :blk result;
};
pub const BRIDGES: [std.meta.fields(Types.Family).len]Counts = blk: {
    @setEvalBranchQuota(1000000);
    var result: [std.meta.fields(Types.Family).len]Counts = undefined;
    for (std.enums.values(Types.Family), &result) |kind, *row| row.* = bridgeCounts(kind);
    break :blk result;
};
pub fn sum(counts: Counts) u32 {
    var result: u32 = 0;
    for (counts) |count| result += count;
    return result;
}
test "static actual-fraction cardinalities match every admitted core and bridge roster" {
    for (std.enums.values(Geometry.Role), CORE) |kind, counts| try std.testing.expectEqual(Roster.terms(kind), sum(counts));
    for (std.enums.values(Types.Family), BRIDGES) |kind, counts| try std.testing.expectEqual(Roster.bridgeTerms(kind), sum(counts));
}

fn bulkCounts(comptime kind: Types.BulkKind) Counts {
    const B = A.crypto.bulk_memory;
    var sink = Counter{};
    @import("bulk_projection.zig").emitLocalFor(M, kind, &([_]M{M.zero()} ** B.layout.fixedWidth(kind)), &([_]M{M.zero()} ** B.layout.main(kind)), &sink);
    return sink.counts;
}
pub const BULK: [Types.bulk_kinds.len]Counts = blk: {
    @setEvalBranchQuota(1000000);
    var out: [Types.bulk_kinds.len]Counts = undefined;
    for (Types.bulk_kinds, &out) |kind, *counts_value| counts_value.* = bulkCounts(kind);
    break :blk out;
};

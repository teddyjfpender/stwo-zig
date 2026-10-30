//! Conditional sorted endpoint RAM. Canonical address/value/coarse-clock
//! validity is INHERITED through the authenticated local-root/bridge multiset,
//! not asserted by this small row. Without those proofs this is no VM theorem.
//! Initial and final lookup planes must close SEPARATELY: a delta-only lookup
//! would let an unchanged uninitialized value cancel against itself.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("block_v7_memory_relations_v1.zig");
pub const VERSION: u32 = 1;
pub const production_active = false;
pub const COLUMN_COUNT: usize = 12;
pub const DIRECT_COUNT: usize = 13 + COLUMN_COUNT;
pub const Transition = @import("../air/block/memory_transition.zig").Transition;
pub const Col = struct {
    pub const address_low = 0;
    pub const address_high = 1;
    pub const clock = 2;
    pub const before_low = 3;
    pub const before_high = 4;
    pub const after_low = 5;
    pub const after_high = 6;
    pub const same = 7;
    pub const inverse = 8;
    pub const gap_low = 9;
    pub const gap_high = 10;
    pub const clock_gap = 11;
};
pub const Policy = struct {
    cohort_count: u32,
    pub fn validate(self: Policy) !void {
        if (self.cohort_count == 0 or self.cohort_count > 4096) return error.InvalidCompactRamPolicy;
    }
    pub fn maximumClock(self: Policy) !u32 {
        try self.validate();
        return 4 * self.cohort_count - 1;
    }
};
pub fn c(comptime S: type, value: u32) S {
    return R.base(S, value);
}
pub fn addressWord(comptime S: type, row: [COLUMN_COUNT]S) S {
    // Every source address is aligned and below2^30. The field inverse of4
    // therefore recovers its ordinary28-bit word index without a new witness.
    return row[0].add(row[1].mul(c(S, 65536))).mul(c(S, 536870912));
}
pub fn newAddress(comptime S: type, fixed: [3]S, row: [COLUMN_COUNT]S) S {
    return fixed[0].sub(fixed[1]).sub(row[Col.same]);
}
pub fn initialTuple(comptime S: type, row: [COLUMN_COUNT]S) [5]S {
    return .{ S.one(), row[0], row[1], row[3], row[4] };
}
pub fn finalTuple(comptime S: type, row: [COLUMN_COUNT]S) [5]S {
    return .{ S.one(), row[0], row[1], row[5], row[6] };
}
pub fn transitionTuple(comptime S: type, row: [COLUMN_COUNT]S) [11]S {
    return .{ S.one(), row[0], row[1], row[2], S.zero(), S.zero(), S.zero(), row[3], row[4], row[5], row[6] };
}
/// fixed=active prefix, first active row, last active row. These are receiver-
/// reconstructed columns for the exact endpoint-event count.
pub fn constraints(comptime S: type, fixed: [3]S, row: [COLUMN_COUNT]S, previous: [COLUMN_COUNT]S) [DIRECT_COUNT]S {
    @setEvalBranchQuota(20000);
    const active = fixed[0];
    const same = row[Col.same];
    const inverse = row[Col.inverse];
    const delta = addressWord(S, row).sub(addressWord(S, previous));
    const fresh = newAddress(S, fixed, row);
    var out: [DIRECT_COUNT]S = undefined;
    out[0] = same.mul(same.sub(S.one()));
    out[1] = fixed[1].mul(same);
    out[2] = same.mul(delta);
    out[3] = delta.mul(inverse).sub(fresh);
    out[4] = fixed[1].add(S.one().sub(active)).mul(inverse);
    out[5] = same.mul(inverse);
    out[6] = fresh.mul(delta.sub(S.one()).sub(row[Col.gap_low]).sub(row[Col.gap_high].mul(c(S, 65536))));
    out[7] = S.one().sub(fresh).mul(row[Col.gap_low]);
    out[8] = S.one().sub(fresh).mul(row[Col.gap_high]);
    out[9] = same.mul(row[Col.clock].sub(previous[Col.clock]).sub(S.one()).sub(row[Col.clock_gap]));
    out[10] = S.one().sub(same).mul(row[Col.clock_gap]);
    out[11] = same.mul(row[Col.before_low].sub(previous[Col.after_low]));
    out[12] = same.mul(row[Col.before_high].sub(previous[Col.after_high]));
    for (row, 13..) |value, i| out[i] = S.one().sub(active).mul(value);
    return out;
}
pub fn construct(policy: Policy, current: Transition, previous: ?Transition) ![COLUMN_COUNT]R.M {
    const maximum = try policy.maximumClock();
    if (current.space != 1 or current.address >= 1 << 30 or current.address & 3 != 0 or current.clock == 0 or current.clock > maximum or current.clock % 4 != 3)
        return error.InvalidCompactRamSourceTuple;
    var row: [COLUMN_COUNT]R.M = @splat(R.M.zero());
    const values = [_]u32{ current.address & 65535, current.address >> 16, @intCast(current.clock), current.before & 65535, current.before >> 16, current.after & 65535, current.after >> 16 };
    for (values, row[0..7]) |value, *cell| cell.* = R.M.fromCanonical(value);
    if (previous) |prior| {
        if (prior.space != 1 or prior.address >= 1 << 30 or prior.address & 3 != 0 or prior.clock == 0 or prior.clock > maximum or prior.clock % 4 != 3) return error.InvalidCompactRamSourceTuple;
        if (current.address < prior.address) return error.UnorderedCompactRam;
        if (current.address == prior.address) {
            if (current.clock <= prior.clock or current.before != prior.after) return error.UnorderedCompactRam;
            row[Col.same] = R.M.one();
            row[Col.clock_gap] = R.M.fromCanonical(@intCast(current.clock - prior.clock - 1));
        } else {
            const delta = (current.address - prior.address) / 4;
            row[Col.inverse] = try R.M.fromCanonical(delta).inv();
            row[Col.gap_low] = R.M.fromCanonical((delta - 1) & 65535);
            row[Col.gap_high] = R.M.fromCanonical((delta - 1) >> 16);
        }
    }
    return row;
}
/// Discrete audit used by witness/negative tests. The original proof must close
/// these range requests against the fixed range16 provider, not call this host
/// checker in place of their AIR.
pub fn checkRanges(row: [COLUMN_COUNT]R.M) !void {
    if (row[Col.gap_low].v >= 65536 or row[Col.gap_high].v >= 4096 or row[Col.clock_gap].v >= 65536) return error.InvalidCompactRamRange;
}
comptime {
    if (@as(u64, 4) * 536870912 != @as(u64, core.fields.m31.Modulus) + 1) @compileError("invalid word-index field inverse");
}

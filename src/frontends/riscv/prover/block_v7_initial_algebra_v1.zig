//! First-touch interval constraints embedded in the experimental v7 RAM AIR.
//! Requires genuine RAM-derived gates and range-checked address/before limbs,
//! plus a separately verified independently fixed interval-table provider.
const M = @import("stwo_core").fields.m31.M31;
const Policy = @import("block_v7_initial_intervals_v1.zig");
pub const COLUMN_COUNT: usize = 11;
pub const CONSTRAINT_COUNT: usize = 7;
pub const RANGE_COUNT: usize = 7;
pub const Witness = struct {
    interval: [6]M,
    low_quarter: M,
    gaps: [2][2]M,
    pub fn columns(self: Witness) [COLUMN_COUNT]M {
        return self.interval ++ .{self.low_quarter} ++ self.gaps[0] ++ self.gaps[1];
    }
};
pub fn witness(interval: Policy.Interval, address: u32, first_touch: bool) !Witness {
    if (!first_touch) return .{ .interval = @splat(M.zero()), .low_quarter = M.zero(), .gaps = @splat(@splat(M.zero())) };
    if (address & 3 != 0 or interval.lower > address / 4 or interval.upper <= address / 4 or interval.upper > Policy.WORD_LIMIT)
        return error.InvalidV7InitializationMembership;
    const gaps = [2]u32{ address / 4 - interval.lower, interval.upper - address / 4 - 1 };
    var result = Witness{ .interval = interval.tuple(), .low_quarter = M.fromCanonical((address & 65535) / 4), .gaps = undefined };
    for (&result.gaps, gaps) |*out, gap| out.* = .{ M.fromCanonical(gap & 65535), M.fromCanonical(gap >> 16) };
    return result;
}

pub fn Algebra(comptime S: type) type {
    return struct {
        pub const Row = [COLUMN_COUNT]S;
        pub const Access = struct {
            /// Bound to the original sorted RAM fixed/current cells, never a
            /// new free private first-touch selector.
            global_first: S,
            predecessor_active: S,
            same_address: S,
            address: [2]S,
            before: [2]S,
            pub fn gate(self: Access) S {
                return self.global_first.add(self.predecessor_active.mul(S.one().sub(self.same_address)));
            }
        };
        pub const RangePoint = struct { value: S, weight: S };
        pub const Membership = struct { tuple: [Policy.TUPLE_WIDTH]S, weight: S };

        pub fn constraints(access: Access, row: Row) [CONSTRAINT_COUNT]S {
            @setEvalBranchQuota(500000);
            const g = access.gate();
            const w = row[6].add(constant(16384).mul(access.address[1]));
            const low_gap = row[7].add(constant(65536).mul(row[8]));
            const high_gap = row[9].add(constant(65536).mul(row[10]));
            return .{
                g.mul(g.sub(S.one())),
                g.mul(access.address[0].sub(constant(4).mul(row[6]))),
                g.mul(w.sub(row[0]).sub(low_gap)),
                g.mul(row[1].sub(w).sub(S.one()).sub(high_gap)),
                g.mul(S.one().sub(row[2])),
                g.mul(S.one().sub(row[3])).mul(access.before[0].sub(row[4])),
                g.mul(S.one().sub(row[3])).mul(access.before[1].sub(row[5])),
            };
        }
        pub fn membership(access: Access, row: Row) Membership {
            return .{ .tuple = row[0..6].*, .weight = access.gate() };
        }
        /// All seven requests must close against the genuine range16 provider.
        /// The four input address/before limbs retain the original RAM ranges.
        /// Range16(4*high) cuts each gap's high limb down to fourteen bits.
        pub fn rangePoints(access: Access, row: Row) [RANGE_COUNT]RangePoint {
            const values = [RANGE_COUNT]S{ row[6], row[7], row[8], constant(4).mul(row[8]), row[9], row[10], constant(4).mul(row[10]) };
            var out: [RANGE_COUNT]RangePoint = undefined;
            for (&out, values) |*point, value| point.* = .{ .value = value, .weight = access.gate() };
            return out;
        }
        fn constant(value: u32) S {
            if (S == M) return M.fromCanonical(value);
            const core = @import("stwo_core");
            if (S == core.fields.packed_qm31.PackedQM31) return S.splat(core.fields.qm31.QM31.fromBase(M.fromCanonical(value)));
            return S.fromBase(M.fromCanonical(value));
        }
    };
}

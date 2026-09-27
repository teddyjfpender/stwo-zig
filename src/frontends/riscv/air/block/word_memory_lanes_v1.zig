//! Two ordered RAM events in one committed row. Direct equations delegate the
//! exact word-v4 oracle; the only extra identities enforce writable RAM space.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Word = @import("word_memory_v5.zig");
const Protocol = @import("../../prover/block_v5_ram_lanes_protocol_v1.zig");
pub const MAIN_COLUMNS = Protocol.MAIN_COLUMNS;
pub const FIXED_COLUMNS = Protocol.FIXED_COLUMNS;
pub const DIRECT_COUNT = 2 * (Word.DIRECT_COUNT + 1);
pub const RANGE_POINTS = 2 * Word.RANGE_COUNT;
pub const Layout = Word.Layout;
pub const Row = [2]Word.Row;
pub const Fixed = [2]Word.Fixed;
pub const constraints = Algebra(Q).constraints;
pub const rangePoints = Algebra(Q).rangePoints;
pub const shiftedColumns = [_]usize{
    27 + Layout.current_key,       27 + Layout.current_key + 1,   27 + Layout.current_key + 2,
    27 + Layout.current_clock,     27 + Layout.current_clock + 1, 27 + Layout.current_clock + 2,
    27 + Layout.current_clock + 3, 27 + Layout.after,             27 + Layout.after + 1,
};
comptime {
    if (Word.Layout.len != 27 or MAIN_COLUMNS != 2 * Word.Layout.len or Word.DIRECT_COUNT != 46 or
        DIRECT_COUNT != Protocol.DIRECT_CONSTRAINTS or Word.RANGE_COUNT != 17)
        @compileError("two-event RAM ABI requires the exact word-v4 equation oracle");
}
/// All direct polynomial bounds count fixed selectors as degree1. The public
/// first-row/shifted predecessor interpolation has degree2; multiplying it by
/// active*same or active*(1-same) has degree4, never silently degree3.
pub fn constraintDegree(index: usize) !u8 {
    if (index >= DIRECT_COUNT) return error.InvalidConstraintIndex;
    return switch (index % (Word.DIRECT_COUNT + 1)) {
        0 => 1,
        1...9 => 3,
        10...17, 19...22 => 4,
        18, 23 => 3,
        else => 2,
    };
}
pub fn witness(previous: ?@import("memory_transition.zig").Transition, first: @import("memory_transition.zig").Transition, second: ?@import("memory_transition.zig").Transition) !Row {
    if (first.space != 1 or (if (previous) |value| value.space != 1 else false) or (if (second) |value| value.space != 1 else false)) return error.InvalidV5RamLanesSpace;
    return .{ try Word.witness(previous, first), if (second) |value| try Word.witness(first, value) else @as(Word.Row, @splat(M.zero())) };
}
pub fn Algebra(comptime S: type) type {
    return struct {
        const Self = @This();
        const Oracle = Word.Algebra(S);
        pub const Row = [2][Word.Layout.len]S;
        pub const Fixed = [2]Oracle.Fixed;
        pub const RangePoint = Oracle.RangePoint;
        pub fn constraints(claim: Protocol.Claim, fixed: Self.Fixed, row: Self.Row, previous: Self.Row) [DIRECT_COUNT]S {
            @setEvalBranchQuota(300000);
            const left = Oracle.constraints(claim.legacy(), fixed[0], row[0], previous[1]);
            const right = Oracle.constraints(claim.legacy(), fixed[1], row[1], row[0]);
            return joinConstraints(left, right, fixed, row);
        }
        pub fn constraintsWithEndpoints(prior: [@import("../../prover/block_v5_word_memory_protocol_v1.zig").ENDPOINT_ARITY]S, first: [@import("../../prover/block_v5_word_memory_protocol_v1.zig").TRANSITION_ARITY]S, last: [@import("../../prover/block_v5_word_memory_protocol_v1.zig").TRANSITION_ARITY]S, fixed: Self.Fixed, row: Self.Row, previous: Self.Row) [DIRECT_COUNT]S {
            @setEvalBranchQuota(300000);
            const left = Oracle.constraintsWithEndpoints(prior, first, last, fixed[0], row[0], previous[1]);
            const right = Oracle.constraintsWithEndpoints(prior, first, last, fixed[1], row[1], row[0]);
            return joinConstraints(left, right, fixed, row);
        }
        fn joinConstraints(left: [Word.DIRECT_COUNT]S, right: [Word.DIRECT_COUNT]S, fixed: Self.Fixed, row: Self.Row) [DIRECT_COUNT]S {
            // One canonical ordering, including both strict-space equations.
            return left ++ .{fixed[0].active.mul(row[0][Layout.current_key + 2].sub(S.one()))} ++
                right ++ .{fixed[1].active.mul(row[1][Layout.current_key + 2].sub(S.one()))};
        }
        pub fn rangePoints(fixed: Self.Fixed, row: Self.Row) [RANGE_POINTS]Self.RangePoint {
            return Oracle.rangePoints(fixed[0], row[0]) ++ Oracle.rangePoints(fixed[1], row[1]);
        }
    };
}

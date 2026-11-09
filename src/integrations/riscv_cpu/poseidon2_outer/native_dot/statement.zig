//! Eight-role recursive verification under a receiver-owned R7 source key.
//! The first six roles use the exact R6 evaluator; DOT and INPUT append roots
//! in native order, at each role's independently lifted height.
const Core = @import("stwo_core");
const K = @import("outer_authority.zig");
const Old = @import("../native_omul/statement.zig").Statement;
const C = @import("../full_p2_common.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const D = @import("row.zig");
const I = @import("input_row.zig");
const F = C.F;
const M = Core.fields.m31.M31;
pub const Statement = struct {
    key: *const K.Key,
    fixed: C.Hash,
    outputs: []const C.Var,
    claims: [8]F,
    base: Old = undefined,
    pub fn mixPublic(self: *@This(), ctx: *C.Context, channel: *C.Channel) !void {
        self.base = .{ .key = &self.key.core, .fixed = self.fixed, .outputs = self.outputs, .claims = self.claims[0..6].* };
        try self.base.mixPublic(ctx, channel);
    }
    pub fn nTreesBeforeChallenges(_: *@This()) usize {
        return 2;
    }
    pub fn drawChallenges(self: *@This(), ctx: *C.Context, channel: *C.Channel) !void {
        try self.base.drawChallengesForClaims(ctx, channel, &self.claims);
    }
    pub fn mixClaims(self: *@This(), ctx: *C.Context, channel: *C.Channel) !void {
        try channel.mixFelts(ctx, &self.claims);
    }
    fn inverse(log: u32, global: u32, point: V.Point) F {
        const p = Core.circle.CirclePoint(F){ .x = point.x, .y = point.y };
        const local = p.repeatedDouble(global - log);
        return Core.constraints.cosetVanishing(F, Core.poly.circle.canonic.CanonicCoset.new(log).coset(), local).inv();
    }
    fn single(column: []const F) !F {
        if (column.len != 1) return error.InvalidNativeDotR7Mask;
        return column[0];
    }
    pub fn evalComposition(self: *@This(), ctx: *C.Context, point: V.Point, sampled: []const []const []const F, alpha: F, _: void) !F {
        var accumulator = @import("stwo_riscv_frontend").rv64_air.evaluation.lane.PointAccumulator(F).init(alpha);
        const global = self.key.maxLog();
        try self.base.evalInto(ctx, point, sampled, global, &accumulator);
        var main: [D.MAIN]F = undefined;
        var previous_main: [8]F = undefined;
        var fixed: [D.FIXED]F = undefined;
        for (&main, sampled[1][K.MAIN_START..][0..D.MAIN], 0..) |*value, column, i| {
            const shifted = i >= D.ACC;
            if (column.len != (if (shifted) @as(usize, 2) else 1)) return error.InvalidNativeDotR7Mask;
            value.* = column[0];
            if (shifted) previous_main[i - D.ACC] = column[1];
        }
        for (&fixed, sampled[0][K.FIXED_START..][0..D.FIXED]) |*value, column| value.* = try single(column);
        var current: [3]F = undefined;
        var previous: [8]F = undefined;
        for (&current, 0..) |*value, i| {
            var coords: [8]F = undefined;
            for (&coords, 0..) |*coord, j| {
                const column = sampled[2][K.INTER_START + 8 * i + j];
                if (column.len != (if (i == 2) @as(usize, 2) else 1)) return error.InvalidNativeDotR7Mask;
                coord.* = column[0];
                if (i == 2) previous[j] = column[1];
            }
            value.* = F.fromPartialEvals(coords);
        }
        const dot_shift = self.claims[6].mulM31(try M.fromU64(self.key.dot_rows).inv());
        const dot_inverse = inverse(self.key.dot_log, global, point);
        for (D.rootsFor(F, &main, &previous_main, &fixed, &current, F.fromPartialEvals(previous), self.base.z, self.base.powers, dot_shift)) |root| accumulator.accumulate(root.mul(dot_inverse));
        var input: [I.MAIN]F = undefined;
        var input_fixed: [I.FIXED]F = undefined;
        for (&input, sampled[1][K.INPUT_MAIN_START..][0..I.MAIN]) |*value, column| value.* = try single(column);
        for (&input_fixed, sampled[0][K.INPUT_FIXED_START..][0..I.FIXED]) |*value, column| value.* = try single(column);
        var now: [8]F = undefined;
        for (&now, &previous, sampled[2][K.INPUT_INTER_START..][0..I.INTER]) |*n, *p, column| {
            if (column.len != 2) return error.InvalidNativeDotR7Mask;
            n.* = column[0];
            p.* = column[1];
        }
        const input_shift = self.claims[7].mulM31(try M.fromU64(self.key.input_rows).inv());
        accumulator.accumulate(I.rootFor(F, &input, &input_fixed, F.fromPartialEvals(now), F.fromPartialEvals(previous), self.base.z, self.base.powers, input_shift).mul(inverse(self.key.input_log, global, point)));
        try C.lane.check();
        return accumulator.finalize();
    }
};

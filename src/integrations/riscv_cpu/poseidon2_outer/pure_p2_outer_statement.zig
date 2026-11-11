//! Exact source AIR/closure authority for verifying a physical P2 circuit child.
//! The admitted child key is receiver authority, never decoded from the proof.
const std = @import("std");
const Core = @import("stwo_core");
const Circuit = @import("stwo_circuit_frontend");
const A = @import("authority.zig");
const L = @import("layout.zig");
const Row = @import("row.zig");
const C = @import("full_p2_common.zig");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const F = C.F;
const M = Core.fields.m31.M31;
const O = Core.fields.om31.OM31;
const G = @import("stwo_circuit_cpu_integration").om31.geometry;
const Program = @import("stwo_circuit_cpu_integration").om31.program.ForLane(F);
const B = Circuit.builder;
const Word = B.wrappers.U32Wrapper(C.Var);
const Simd = B.simd.Simd;
pub const Statement = struct {
    key: *const A.Authority,
    fixed: C.Hash,
    outputs: []const C.Var,
    claims: [5]F,
    z: F = undefined,
    alpha: F = undefined,
    powers: [6]F = undefined,
    pub fn mixPublic(self: *@This(), ctx: *C.Context, channel: *C.Channel) !void {
        try @import("full_p2_frame.zig").requireRoot(ctx, self.fixed, self.key.fixed_root);
        if (self.outputs.len != self.key.n_outputs) return error.InvalidPoseidonOutputCount;
        try channel.mixConfig(ctx, self.key.profile.config());
        const words = try ctx.scratch().alloc(Word, 9 + 4 * self.outputs.len);
        for (words[0..8], 0..) |*word, i| word.* = try B.wrappers.constU32(C.Q, ctx, std.mem.readInt(u32, self.key.identity[4 * i ..][0..4], .little));
        words[8] = try B.wrappers.constU32(C.Q, ctx, @intCast(self.outputs.len));
        for (self.outputs, 0..) |output, i| {
            const coordinates = try B.blake.unpackQm31sToU32Words(C.Q, ctx, &.{output});
            @memcpy(words[9 + 4 * i ..][0..4], coordinates);
        }
        try channel.mixU32s(ctx, words);
    }
    pub fn nTreesBeforeChallenges(_: *@This()) usize {
        return 2;
    }
    fn outputTerm(self: *const @This(), ctx: *C.Context, address: usize, value: C.Var) !F {
        var denominator = F.fromBase(M.fromCanonical(Row.GATE_RELATION_ID)).sub(self.z).add(self.powers[1].mulM31(M.fromU64(address)));
        const coordinates = Simd.fromPacked(&[1]C.Var{value}, 4);
        for (0..4) |i| denominator = denominator.add(self.powers[2 + i].mul(C.base(try B.simd.unpackIdx(C.Q, ctx, coordinates, i))));
        return denominator.inv();
    }
    pub fn drawChallenges(self: *@This(), ctx: *C.Context, channel: *C.Channel) !void {
        self.z = try channel.draw(ctx);
        self.alpha = try channel.draw(ctx);
        var power = F.one();
        for (&self.powers) |*value| {
            value.* = power;
            power = power.mul(self.alpha);
        }
        var sum = F.zero();
        for (self.claims) |claim| sum = sum.add(claim);
        for (self.outputs, 0..) |output, i| sum = sum.add(try self.outputTerm(ctx, 3 + i, output));
        sum = sum.add(try self.outputTerm(ctx, 2, try ctx.constant(Circuit.witness.trace.U_VALUE)));
        try C.eq(ctx, sum, F.zero());
    }
    pub fn mixClaims(self: *@This(), ctx: *C.Context, channel: *C.Channel) !void {
        try channel.mixFelts(ctx, &self.claims);
    }
    const Reader = struct {
        component: *const @import("stwo_cairo_frontend").witness.composition_bundle.Component,
        sampled: []const []const []const F,
        main: []const std.ArrayList(i32),
        inter: []const std.ArrayList(i32),
        fn get(raw: *const anyopaque, tree: u8, column: u32, offset: i32) !F {
            const self: *const @This() = @ptrCast(@alignCast(raw));
            if (tree >= self.sampled.len) return error.MissingOm31Mask;
            if (tree == 0) {
                if (offset != 0 or column >= self.component.preprocessed_indices.len) return error.MissingOm31Mask;
                const global = self.component.preprocessed_indices[column];
                if (global >= self.sampled[0].len or self.sampled[0][global].len != 1) return error.MissingOm31Mask;
                return self.sampled[0][global][0];
            }
            const span = try G.span(self.component.*, tree);
            const offsets = if (tree == 1) self.main else self.inter;
            if (column >= offsets.len or span.start + column >= self.sampled[tree].len) return error.MissingOm31Mask;
            const values = self.sampled[tree][span.start + column];
            if (values.len != offsets[column].items.len) return error.MissingOm31Mask;
            for (offsets[column].items, values) |candidate, value| if (candidate == offset) return value;
            return error.MissingOm31Mask;
        }
    };
    pub fn evalComposition(self: *@This(), ctx: *C.Context, point: V.Point, sampled: []const []const []const F, alpha: F, _: void) !F {
        var global_log: u32 = 0;
        for (self.key.logs) |log| global_log = @max(global_log, log);
        var accumulator = @import("stwo_riscv_frontend").rv64_air.evaluation.lane.PointAccumulator(F).init(alpha);
        // Exact native component order: EQ, arithmetic, M31/u32, P2, range.
        for (0..5) |kind| {
            const p = Core.circle.CirclePoint(F){ .x = point.x, .y = point.y };
            const local = p.repeatedDouble(global_log - self.key.logs[kind]);
            const inverse = Core.constraints.cosetVanishing(F, Core.poly.circle.canonic.CanonicCoset.new(self.key.logs[kind]).coset(), local).inv();
            if (kind == 3) {
                var main: [L.MAIN_COLUMNS]F = undefined;
                var fixed: [L.FIXED_COLUMNS]F = undefined;
                for (&main, sampled[1][A.MAIN_START[3]..][0..L.MAIN_COLUMNS]) |*value, column| {
                    if (column.len != 1) return error.InvalidPoseidonFiveMask;
                    value.* = column[0];
                }
                for (&fixed, sampled[0][A.FIXED_START[3]..][0..L.FIXED_COLUMNS]) |*value, column| {
                    if (column.len != 1) return error.InvalidPoseidonFiveMask;
                    value.* = column[0];
                }
                for (try Row.evaluateFor(F, &main)) |root| accumulator.accumulate(root.mul(inverse));
                const ports = Row.portsFor(F, &main, &fixed);
                var prior = F.zero();
                for (0..24) |i| {
                    var coords: [8]F = undefined;
                    var previous: [8]F = undefined;
                    for (&coords, 0..) |*coordinate, j| {
                        const column = sampled[2][A.INTER_START[3] + 8 * i + j];
                        if (column.len != (if (i == 23) @as(usize, 2) else 1)) return error.InvalidPoseidonFiveMask;
                        coordinate.* = column[0];
                        if (i == 23) previous[j] = column[1];
                    }
                    const current = F.fromPartialEvals(coords);
                    var d0 = self.z.neg();
                    var d1 = self.z.neg();
                    for (ports[2 * i].tuple, ports[2 * i + 1].tuple, self.powers) |a, b, power| {
                        d0 = d0.add(a.mul(power));
                        d1 = d1.add(b.mul(power));
                    }
                    const numerator = ports[2 * i].numerator.mul(d1).add(ports[2 * i + 1].numerator.mul(d0));
                    const shift = self.claims[3].mulM31(try M.fromU64(self.key.rows[3]).inv());
                    const delta = if (i == 23) current.sub(F.fromPartialEvals(previous)).add(shift).sub(prior) else current.sub(prior);
                    accumulator.accumulate(delta.mul(d0.mul(d1)).sub(numerator).mul(inverse));
                    prior = current;
                }
                continue;
            }
            const old = A.OLD_SLOTS[if (kind < 3) kind else 3];
            const component = &self.key.bound.components[old];
            const main_offsets = try G.offsets(ctx.scratch(), component.*, 1);
            const inter_offsets = try G.offsets(ctx.scratch(), component.*, 2);
            const reader = Reader{ .component = component, .sampled = sampled, .main = main_offsets, .inter = inter_offsets };
            const parameters = try Program.extensionParameters(ctx.scratch(), component, self.z, self.alpha, self.claims[kind]);
            for (component.parts) |part| {
                const roots = try Program.evaluate(ctx.scratch(), part.program, .{ .context = &reader, .get = Reader.get }, parameters);
                for (roots) |root| accumulator.accumulate(root.mul(inverse));
            }
        }
        try C.lane.check();
        return accumulator.finalize();
    }
};

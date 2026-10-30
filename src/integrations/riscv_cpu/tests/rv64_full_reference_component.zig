//! Test-only 4n materialization oracle for the n-scratch CPU quotient evaluator.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const air = core.air.components;
const Point = core.circle.CirclePointQM31;
const E = rv.evaluation;
const L = rv.layout;
const F = rv.full.frame;
pub const Reference = struct {
    component: *const rv.full.component.Component,
    const Adapter = core.air.derive.ComponentAdapter(Reference, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Reference) cp.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn nConstraints(self: *const Reference) usize {
        return self.component.nConstraints();
    }
    pub fn maxConstraintLogDegreeBound(self: *const Reference) u32 {
        return self.component.maxConstraintLogDegreeBound();
    }
    pub fn compositionLogSplit(self: *const Reference) u32 {
        return self.component.compositionLogSplit();
    }
    pub fn constraintDegreeBound(self: *const Reference, index: usize) !u8 {
        return self.component.constraintDegreeBound(index);
    }
    pub fn traceLogDegreeBounds(self: *const Reference, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
        return self.component.traceLogDegreeBounds(a);
    }
    pub fn preprocessedColumnIndices(self: *const Reference, a: std.mem.Allocator) ![]usize {
        return self.component.preprocessedColumnIndices(a);
    }
    pub fn maskPoints(self: *const Reference, a: std.mem.Allocator, point: Point, log: u32) !air.MaskPoints {
        return self.component.maskPoints(a, point, log);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Reference, point: Point, mask: *const air.MaskValues, out: *core.air.accumulation.PointEvaluationAccumulator, log: u32) !void {
        return self.component.evaluateConstraintQuotientsAtPoint(point, mask, out, log);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Reference, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        const c = self.component;
        const a = accumulator.allocator;
        const eval_log = c.log_size + 2;
        const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
        const size = domain.size();
        const total = F.FIXED + c.mainCount() + c.interactionCount();
        const polys = try a.alloc(cp.Poly, total);
        defer a.free(polys);
        @memcpy(polys[0..F.FIXED], trace.polys.items[0][c.offsets.fixed..][0..F.FIXED]);
        @memcpy(polys[F.FIXED..][0..c.mainCount()], trace.polys.items[1][c.offsets.main..][0..c.mainCount()]);
        @memcpy(polys[F.FIXED + c.mainCount() ..], trace.polys.items[2][c.offsets.interaction..][0..c.interactionCount()]);
        const scratch = try a.alloc(M, total * size);
        defer a.free(scratch);
        const values = try a.alloc([]M, total);
        defer a.free(values);
        for (polys, values, 0..) |poly, *buffer, i| {
            try poly.validate();
            const coefficients = poly.coefficients orelse return error.MissingReferenceCoefficients;
            const source = coefficients.coefficients();
            buffer.* = scratch[i * size ..][0..size];
            @memcpy(buffer.*[0..source.len], source);
            @memset(buffer.*[source.len..], M.zero());
        }
        var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
        defer engine.poly.twiddles.deinitM31(a, &twiddles);
        try engine.poly.circle.poly.evaluateBuffersWithTwiddles(values, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
        var inverses: [4]M = undefined;
        for (&inverses, 0..) |*inverse, i| inverse.* = try core.constraints.cosetVanishing(M, core.poly.circle.canonic.CanonicCoset.new(c.log_size).coset(), domain.at(core.utils.bitReverseIndex(i, 2))).inv();
        const columns = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = c.constraint_count }});
        defer a.free(columns);
        var output = columns[0];
        for (0..size) |row| {
            const prior_row = core.utils.previousBitReversedCircleDomainIndex(row, c.log_size, eval_log);
            var geometry: F.Geometry = undefined;
            for (&geometry, values[0..F.FIXED]) |*value, source| value.* = Q.fromBase(source[row]);
            var main: [L.MAIN + F.WIDTH]Q = undefined;
            var prior_main: [L.MAIN + F.WIDTH]Q = @splat(Q.zero());
            for (main[0..c.mainCount()], values[F.FIXED..][0..c.mainCount()], 0..) |*value, source, i| {
                value.* = Q.fromBase(source[row]);
                if (c.needsPreviousMain(i)) prior_main[i] = Q.fromBase(source[prior_row]);
            }
            var current: [rv.full.component.MAX_INTERACTION]Q = undefined;
            var previous: [rv.full.component.MAX_INTERACTION]Q = @splat(Q.zero());
            for (current[0..c.interactionCount()], values[F.FIXED + c.mainCount() ..], 0..) |*value, source, i| {
                value.* = Q.fromBase(source[row]);
                if (c.needsPreviousInteraction(i)) previous[i] = Q.fromBase(source[prior_row]);
            }
            var row_accumulator = core.air.accumulation.PointEvaluationAccumulator.init(accumulator.random_coeff_powers[1]);
            var sink = E.Sink{ .values = null, .accumulator = &row_accumulator };
            c.emit(geometry, main[0..c.mainCount()], prior_main[0..c.mainCount()], current[0..c.interactionCount()], previous[0..c.interactionCount()], &sink);
            output.accumulate(row, row_accumulator.finalize().mul(output.random_coeff_powers[0]).mulM31(inverses[row >> @as(std.math.Log2Int(usize), @intCast(c.log_size))]));
        }
    }
};

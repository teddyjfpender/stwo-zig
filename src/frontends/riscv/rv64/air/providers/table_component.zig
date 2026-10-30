//! Concrete typed bitwise-table component in the shared PCS/FRI transaction.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const air = core.air.components;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const canonic = core.poly.circle.canonic;
const geometry = @import("../geometry.zig");
const provider = @import("tables.zig");
const support = @import("../../../air/memory_commitment/hash_component_prepared_support.zig");
const points = @import("../../../air/component_point_support.zig");

pub const Component = struct {
    kind: provider.Kind,
    fixed_offset: usize,
    main_offset: usize,
    interaction_offset: usize,
    challenges: provider.Challenges,
    claim: Q,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Component) air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Component) usize {
        return provider.N_CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.kind.logSize() + 2;
    }
    pub fn compositionLogSplit(_: *const Component) u32 {
        return 2;
    }
    pub fn constraintDegreeBound(_: *const Component, index: usize) !u8 {
        if (index >= provider.N_CONSTRAINTS) return error.InvalidConstraintIndex;
        return 2;
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
        const fixed = try points.emptyOrFilledLogs(a, self.kind.arity() + 2, self.kind.logSize());
        errdefer a.free(fixed);
        const main = try points.emptyOrFilledLogs(a, 1, self.kind.logSize());
        errdefer a.free(main);
        const interaction = try points.emptyOrFilledLogs(a, provider.N_INTERACTION, self.kind.logSize());
        errdefer a.free(interaction);
        return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const indices = try a.alloc(usize, self.kind.arity() + 2);
        for (indices, 0..) |*index, i| index.* = self.fixed_offset + i;
        return indices;
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
        _ = try geometry.localPoint(point, global_log, self.kind.logSize());
        const fixed = try points.currentPointColumns(a, self.kind.arity() + 2, point);
        errdefer points.freePointColumns(a, fixed);
        const main = try points.currentPointColumns(a, 1, point);
        errdefer points.freePointColumns(a, main);
        const interaction = try points.currentPointColumns(a, provider.N_INTERACTION, point);
        errdefer points.freePointColumns(a, interaction);
        for (interaction[4..]) |*column| {
            const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
            a.free(column.*);
            column.* = replacement;
        }
        return air.MaskPoints.initOwned(try a.dupe([][]Point, &.{ fixed, main, interaction }));
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        if (mask.items.len < 3 or mask.items[0].len < self.fixed_offset + self.kind.arity() + 2 or mask.items[1].len <= self.main_offset or mask.items[2].len < self.interaction_offset + 8) return error.InvalidLookupProviderShape;
        const fixed = mask.items[0][self.fixed_offset..][0 .. self.kind.arity() + 2];
        for (fixed) |column| if (column.len != 1) return error.InvalidLookupProviderShape;
        const main = mask.items[1][self.main_offset];
        if (main.len != 1) return error.InvalidLookupProviderShape;
        const interaction = mask.items[2][self.interaction_offset..][0..8];
        for (interaction, 0..) |column, i| if (column.len != @as(usize, if (i < 4) 1 else 2)) return error.InvalidLookupProviderShape;
        var tuple: [provider.MAX_ARITY]Q = undefined;
        for (tuple[0..self.kind.arity()], fixed[0..self.kind.arity()]) |*dst, column| dst.* = column[0];
        const residuals = provider.evaluate(tuple[0..self.kind.arity()], fixed[self.kind.arity()][0], fixed[self.kind.arity() + 1][0], main[0], try points.sampledSecure(interaction, 0, 0), try points.sampledSecure(interaction, 4, 0), try points.sampledSecure(interaction, 4, 1), self.claim, self.challenges);
        const inverse = try geometry.denominatorInverse(point, global_log, self.kind.logSize());
        for (residuals) |value| accumulator.accumulate(value.mul(inverse));
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len != 3 or trace.polys.items[0].len < self.fixed_offset + self.kind.arity() + 2 or trace.polys.items[1].len <= self.main_offset or trace.polys.items[2].len < self.interaction_offset + 8) return error.InvalidLookupProviderShape;
        const a = accumulator.allocator;
        const eval_log = self.kind.logSize() + 2;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const size = domain.size();
        const fixed_count = self.kind.arity() + 2;
        const total = fixed_count + 1 + provider.N_INTERACTION;
        var poly_storage: [provider.MAX_ARITY + 11]cp.Poly = undefined;
        const polys = poly_storage[0..total];
        @memcpy(polys[0..fixed_count], trace.polys.items[0][self.fixed_offset..][0..fixed_count]);
        polys[fixed_count] = trace.polys.items[1][self.main_offset];
        @memcpy(polys[fixed_count + 1 ..], trace.polys.items[2][self.interaction_offset..][0..8]);
        var owned_count: usize = 0;
        for (polys) |poly| owned_count += @intFromBool(try support.sourceNeedsExtension(poly, self.kind.logSize(), eval_log));
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        var evaluation_storage: [provider.MAX_ARITY + 11][]const M = undefined;
        const evaluations = evaluation_storage[0..total];
        for (polys, evaluations) |poly, *values| values.* = try support.evaluationValues(a, poly, eval_log, size, owned, &initialized);
        if (owned.len != 0) {
            var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &twiddles);
            try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
        }
        const inverses = try geometry.denominatorInverses(a, self.kind.logSize(), eval_log);
        defer a.free(inverses);
        const columns = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = provider.N_CONSTRAINTS }});
        defer a.free(columns);
        var output = columns[0];
        for (0..size) |row| {
            const prior = core.utils.previousBitReversedCircleDomainIndex(row, self.kind.logSize(), eval_log);
            var tuple: [provider.MAX_ARITY]Q = undefined;
            for (tuple[0..self.kind.arity()], evaluations[0..self.kind.arity()]) |*dst, values| dst.* = Q.fromBase(values[row]);
            const interaction = evaluations[fixed_count + 1 ..];
            const residuals = provider.evaluate(tuple[0..self.kind.arity()], Q.fromBase(evaluations[fixed_count - 2][row]), Q.fromBase(evaluations[fixed_count - 1][row]), Q.fromBase(evaluations[fixed_count][row]), points.secureAt(interaction[0..4], row), points.secureAt(interaction[4..8], row), points.secureAt(interaction[4..8], prior), self.claim, self.challenges);
            var folded = Q.zero();
            for (residuals, 0..) |value, i| folded = folded.add(output.random_coeff_powers[provider.N_CONSTRAINTS - 1 - i].mul(value));
            output.accumulate(row, folded.mulM31(inverses[row >> @as(std.math.Log2Int(usize), @intCast(self.kind.logSize()))]));
        }
    }
};

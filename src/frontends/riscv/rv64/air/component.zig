//! Concrete RV64 Stwo adapter. One polynomial authority serves domain and OODS.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const air = core.air.components;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const canonic = core.poly.circle.canonic;
const E = @import("evaluation.zig");
const L = E.L;
const relation = @import("relations.zig");
const support = @import("../../air/memory_commitment/hash_component_prepared_support.zig");
pub const Component = struct {
    log_size: u32,
    projection: @import("projection.zig").Projection,
    challenges: relation.Challenges,
    expected_sum: Q,
    constraint_count: usize,

    // This is the existing engine's erased-handle adapter, not a CPU type factory.
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn init(log_size: u32, projection: @import("projection.zig").Projection, challenges: relation.Challenges, expected_sum: Q) !Component {
        if (log_size < 5 or log_size > 8) return error.InvalidRv64ProofLog;
        return .{ .log_size = log_size, .projection = projection, .challenges = challenges, .expected_sum = expected_sum, .constraint_count = countConstraints() };
    }
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Component) air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(self: *const Component) usize {
        return self.constraint_count;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.log_size + L.EXPANSION;
    }
    pub fn compositionLogSplit(_: *const Component) u32 {
        return L.EXPANSION;
    }
    pub fn constraintDegreeBound(self: *const Component, index: usize) !u8 {
        if (index >= self.constraint_count) return error.InvalidConstraintIndex;
        return L.MAX_DEGREE;
    }

    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
        const fixed = try a.alloc(u32, self.projection.fixed_count);
        errdefer a.free(fixed);
        const main = try a.alloc(u32, self.projection.main_count);
        errdefer a.free(main);
        const interaction = try a.alloc(u32, L.INTERACTION);
        errdefer a.free(interaction);
        @memset(fixed, self.log_size);
        @memset(main, self.log_size);
        @memset(interaction, self.log_size);
        return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
    }

    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: core.circle.CirclePointQM31, max_log: u32) !air.MaskPoints {
        if (max_log != self.log_size) return error.InvalidRv64MaskGeometry;
        const previous = @import("../../air/logup.zig").prevRowPoint(max_log, point);
        const fixed = try pointColumns(a, self.projection.fixed_count, point, null, 0);
        errdefer freePoints(a, fixed);
        const main = try pointColumns(a, self.projection.main_count, point, null, 0);
        errdefer freePoints(a, main);
        const interaction = try pointColumns(a, L.INTERACTION, point, previous, 32);
        errdefer freePoints(a, interaction);
        return air.MaskPoints.initOwned(try a.dupe([][]core.circle.CirclePointQM31, &.{ fixed, main, interaction }));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const result = try a.alloc(usize, self.projection.fixed_count);
        for (result, 0..) |*index, i| index.* = i;
        return result;
    }

    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: core.circle.CirclePointQM31, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (max_log != self.log_size or mask.items.len < 3 or mask.items[0].len != self.projection.fixed_count or mask.items[1].len != self.projection.main_count or mask.items[2].len != L.INTERACTION) return error.InvalidRv64PointShape;
        var fixed_physical: [L.fixed.COUNT]Q = undefined;
        var main_physical: [L.MAIN]Q = undefined;
        var current: [L.INTERACTION]Q = undefined;
        var previous: [L.INTERACTION]Q = @splat(Q.zero());
        for (fixed_physical[0..self.projection.fixed_count], mask.items[0]) |*value, column| value.* = try sample(column, 0, 1);
        for (main_physical[0..self.projection.main_count], mask.items[1]) |*value, column| value.* = try sample(column, 0, 1);
        for (&current, mask.items[2], 0..) |*value, column, i| {
            value.* = try sample(column, 0, if (i < 32) 1 else 2);
            if (i >= 32) previous[i] = try sample(column, 1, 2);
        }
        const fixed = self.projection.inflateFixed(fixed_physical[0..self.projection.fixed_count]);
        const main = self.projection.inflateMain(main_physical[0..self.projection.main_count]);
        const inverse = try core.constraints.cosetVanishing(Q, canonic.CanonicCoset.new(self.log_size).coset(), point).inv();
        var sink = E.Sink{ .values = null, .accumulator = accumulator, .scale = inverse };
        self.emitConstraints(&fixed, &main, &current, &previous, &sink);
    }

    pub fn evaluate(self: *const Component, fixed: *const E.Fixed, main: *const E.Main, current: *const [L.INTERACTION]Q, previous: *const [L.INTERACTION]Q, output: []Q) void {
        var sink = E.Sink{ .values = output };
        self.emitConstraints(fixed, main, current, previous, &sink);
    }
    fn emitConstraints(self: *const Component, fixed: *const E.Fixed, main: *const E.Main, current: *const [L.INTERACTION]Q, previous: *const [L.INTERACTION]Q, sink: *E.Sink) void {
        const view = E.View{ .f = fixed, .m = main };
        E.localSupported(view, sink, self.projection.support);
        relation.evaluate(view, current, previous, self.challenges, self.expected_sum, sink);
        std.debug.assert(sink.count == self.constraint_count);
    }

    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, source: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        const a = accumulator.allocator;
        if (source.polys.items.len != 3 or source.polys.items[0].len != self.projection.fixed_count or source.polys.items[1].len != self.projection.main_count or source.polys.items[2].len != L.INTERACTION) return error.InvalidRv64TraceShape;
        const eval_log = self.log_size + L.EXPANSION;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const size = domain.size();
        const total = self.projection.fixed_count + self.projection.main_count + L.INTERACTION;
        const polys = try a.alloc(cp.Poly, total);
        defer a.free(polys);
        var cursor: usize = 0;
        for (source.polys.items) |tree| {
            @memcpy(polys[cursor..][0..tree.len], tree);
            cursor += tree.len;
        }
        var owned_count: usize = 0;
        for (polys) |poly| owned_count += @intFromBool(try support.sourceNeedsExtension(poly, self.log_size, eval_log));
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        const evals = try a.alloc([]const M, total);
        defer a.free(evals);
        for (polys, evals) |poly, *values| values.* = try support.evaluationValues(a, poly, eval_log, size, owned, &initialized);
        if (owned.len != 0) {
            var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &twiddles);
            try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
        }
        var inverses: [1 << L.EXPANSION]M = undefined;
        for (&inverses, 0..) |*inverse, i| inverse.* = try core.constraints.cosetVanishing(M, canonic.CanonicCoset.new(self.log_size).coset(), domain.at(core.utils.bitReverseIndex(i, L.EXPANSION))).inv();
        const columns = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = self.constraint_count }});
        defer a.free(columns);
        var output_column = columns[0];
        const values = try a.alloc(Q, self.constraint_count);
        defer a.free(values);
        for (0..size) |row| {
            const prior = core.utils.previousBitReversedCircleDomainIndex(row, self.log_size, eval_log);
            var fixed_physical: [L.fixed.COUNT]Q = undefined;
            var main_physical: [L.MAIN]Q = undefined;
            var current: [L.INTERACTION]Q = undefined;
            var previous: [L.INTERACTION]Q = @splat(Q.zero());
            for (fixed_physical[0..self.projection.fixed_count], 0..) |*value, i| value.* = Q.fromBase(evals[i][row]);
            for (main_physical[0..self.projection.main_count], 0..) |*value, i| value.* = Q.fromBase(evals[self.projection.fixed_count + i][row]);
            for (&current, 0..) |*value, i| {
                value.* = Q.fromBase(evals[self.projection.fixed_count + self.projection.main_count + i][row]);
                if (i >= 32) previous[i] = Q.fromBase(evals[self.projection.fixed_count + self.projection.main_count + i][prior]);
            }
            const fixed = self.projection.inflateFixed(fixed_physical[0..self.projection.fixed_count]);
            const main = self.projection.inflateMain(main_physical[0..self.projection.main_count]);
            self.evaluate(&fixed, &main, &current, &previous, values);
            var folded = Q.zero();
            for (values, 0..) |value, i| folded = folded.add(output_column.random_coeff_powers[values.len - 1 - i].mul(value));
            output_column.accumulate(row, folded.mulM31(inverses[row >> @as(std.math.Log2Int(usize), @intCast(self.log_size))]));
        }
    }
};

pub fn countConstraints() usize {
    const fixed: E.Fixed = @splat(Q.zero());
    const main: E.Main = @splat(Q.zero());
    const interaction: [L.INTERACTION]Q = @splat(Q.zero());
    const challenges = relation.Challenges{ .offset = Q.zero(), .coefficients = @splat(Q.zero()) };
    var sink = E.Sink{ .values = null };
    const view = E.View{ .f = &fixed, .m = &main };
    E.local(view, &sink);
    relation.evaluate(view, &interaction, &interaction, challenges, Q.zero(), &sink);
    return sink.count;
}
fn sample(values: []const Q, index: usize, expected: usize) !Q {
    if (values.len != expected) return error.InvalidRv64PointShape;
    return values[index];
}
fn pointColumns(a: std.mem.Allocator, count: usize, point: core.circle.CirclePointQM31, previous: ?core.circle.CirclePointQM31, start: usize) ![][]core.circle.CirclePointQM31 {
    const result = try a.alloc([]core.circle.CirclePointQM31, count);
    errdefer a.free(result);
    var initialized: usize = 0;
    errdefer for (result[0..initialized]) |column| a.free(column);
    for (result, 0..) |*column, i| {
        const shifted = previous != null and i >= start;
        column.* = try a.alloc(core.circle.CirclePointQM31, if (shifted) 2 else 1);
        initialized += 1;
        column.*[0] = point;
        if (shifted) column.*[1] = previous.?;
    }
    return result;
}
fn freePoints(a: std.mem.Allocator, columns: [][]core.circle.CirclePointQM31) void {
    for (columns) |column| a.free(column);
    a.free(columns);
}

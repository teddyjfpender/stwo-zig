//! MUL arithmetic, BYTE and typed bus in ordinary shared PCS trees.
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
const geometry = @import("../../geometry.zig");
const provider = @import("provider.zig");
const L = @import("layout.zig");
const Byte = @import("../../range/cpu.zig");
const E = @import("../../evaluation.zig");
const support = @import("../../../../air/memory_commitment/hash_component_prepared_support.zig");
const points = @import("../../../../air/component_point_support.zig");
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
const TOTAL = L.FIXED + L.MAIN + L.INTERACTION;

pub const Component = struct {
    log_size: u32,
    count: u32,
    fixed_offset: usize,
    main_offset: usize,
    interaction_offset: usize,
    challenges: provider.Challenges,
    claim: Q,
    byte_alpha: Byte.PreparedAlpha,
    /// Prover-only reference path for exact proof-byte qualification.
    reference_domain: bool = false,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        var result = Adapter.asProverComponent(self);
        result.domain_parallel_evaluator = evaluateParallelErased;
        return result;
    }
    fn evaluateParallelErased(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
        const self: *const Component = @ptrCast(@alignCast(ctx));
        if (pool.stackSize() < MIN_STACK_BYTES) return error.InvalidRv64MultiplicationWorkerStack;
        if (self.reference_domain) return self.evaluateReference(trace, accumulator);
        return self.evaluateBounded(trace, accumulator, pool);
    }
    pub fn asVerifierComponent(self: *const Component) air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Component) usize {
        return L.CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.log_size + 2;
    }
    pub fn compositionLogSplit(_: *const Component) u32 {
        return 2;
    }
    pub fn constraintDegreeBound(_: *const Component, index: usize) !u8 {
        if (index >= L.CONSTRAINTS) return error.InvalidConstraintIndex;
        return 4;
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
        const fixed = try points.emptyOrFilledLogs(a, L.FIXED, self.log_size);
        errdefer a.free(fixed);
        const main = try points.emptyOrFilledLogs(a, L.MAIN, self.log_size);
        errdefer a.free(main);
        const interaction = try points.emptyOrFilledLogs(a, L.INTERACTION, self.log_size);
        errdefer a.free(interaction);
        return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const result = try a.alloc(usize, L.FIXED);
        for (result, 0..) |*value, i| value.* = self.fixed_offset + i;
        return result;
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
        _ = try geometry.localPoint(point, global_log, self.log_size);
        const fixed = try points.currentPointColumns(a, L.FIXED, point);
        errdefer points.freePointColumns(a, fixed);
        const main = try points.currentPointColumns(a, L.MAIN, point);
        errdefer points.freePointColumns(a, main);
        const previous_count = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
        a.free(main[L.COUNT]);
        main[L.COUNT] = previous_count;
        const interaction = try points.currentPointColumns(a, L.INTERACTION, point);
        errdefer points.freePointColumns(a, interaction);
        for (interaction[L.INTERACTION - 4 ..]) |*column| {
            const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
            a.free(column.*);
            column.* = replacement;
        }
        return air.MaskPoints.initOwned(try a.dupe([][]Point, &.{ fixed, main, interaction }));
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        if (mask.items.len < 3) return error.InvalidRv64MultiplicationShape;
        try self.checkShape(mask.items[0].len, mask.items[1].len, mask.items[2].len);
        var geometry_values: [L.FIXED]Q = undefined;
        var physical: provider.Values = undefined;
        for (&geometry_values, 0..) |*value, i| value.* = try sample(mask.items[0][self.fixed_offset + i], 0, 1);
        for (&physical, 0..) |*value, i| value.* = try sample(mask.items[1][self.main_offset + i], 0, if (i == L.COUNT) 2 else 1);
        const previous_count = try sample(mask.items[1][self.main_offset + L.COUNT], 1, 2);
        var current: [L.INTERACTION]Q = undefined;
        var previous: [L.INTERACTION]Q = @splat(Q.zero());
        for (&current, mask.items[2][self.interaction_offset..][0..L.INTERACTION], 0..) |*value, column, i| {
            value.* = try sample(column, 0, if (i < L.INTERACTION - 4) 1 else 2);
            if (i >= L.INTERACTION - 4) previous[i] = try sample(column, 1, 2);
        }
        var sink = E.Sink{ .values = null, .accumulator = accumulator, .scale = try geometry.denominatorInverse(point, global_log, self.log_size) };
        provider.evaluate(geometry_values, &physical, &current, &previous, previous_count, self.count, self.challenges, &self.byte_alpha, self.claim, &sink);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        if (self.reference_domain) return self.evaluateReference(trace, accumulator);
        return self.evaluateBounded(trace, accumulator, null);
    }
    fn evaluateBounded(self: *const Component, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
        if (trace.polys.items.len != 3) return error.InvalidRv64MultiplicationShape;
        try self.checkShape(trace.polys.items[0].len, trace.polys.items[1].len, trace.polys.items[2].len);
        const a = accumulator.allocator;
        var polys: [TOTAL]cp.Poly = undefined;
        @memcpy(polys[0..L.FIXED], trace.polys.items[0][self.fixed_offset..][0..L.FIXED]);
        @memcpy(polys[L.FIXED..][0..L.MAIN], trace.polys.items[1][self.main_offset..][0..L.MAIN]);
        @memcpy(polys[L.FIXED + L.MAIN ..], trace.polys.items[2][self.interaction_offset..][0..L.INTERACTION]);
        var previous_columns: [TOTAL]bool = @splat(false);
        previous_columns[L.FIXED + L.COUNT] = true;
        @memset(previous_columns[L.FIXED + L.MAIN + L.INTERACTION - 4 ..], true);
        const Partition = @import("../../full/coset_evaluation.zig").Evaluation;
        var evaluation = try Partition.init(a, &polys, self.log_size, &previous_columns);
        defer evaluation.deinit();
        const columns = try accumulator.columns(a, &.{.{ .log_size = self.log_size + 2, .n_cols = L.CONSTRAINTS }});
        defer a.free(columns);
        var output = columns[0];
        for (0..4) |part| {
            try evaluation.evaluatePartWithPool(part, pool);
            const inverse = try evaluation.denominatorInverse(part);
            for (0..evaluation.size) |row| {
                const prior = evaluation.previousRow(part, row);
                var geometry_values: [L.FIXED]Q = undefined;
                var physical: provider.Values = undefined;
                var current: [L.INTERACTION]Q = undefined;
                var previous: [L.INTERACTION]Q = @splat(Q.zero());
                for (&geometry_values, 0..) |*value, i| value.* = Q.fromBase(evaluation.current_values[i][row]);
                for (&physical, 0..) |*value, i| value.* = Q.fromBase(evaluation.current_values[L.FIXED + i][row]);
                for (&current, 0..) |*value, i| {
                    value.* = Q.fromBase(evaluation.current_values[L.FIXED + L.MAIN + i][row]);
                    if (i >= L.INTERACTION - 4) previous[i] = Q.fromBase(evaluation.previous_values[L.FIXED + L.MAIN + i][prior]);
                }
                const previous_count = Q.fromBase(evaluation.previous_values[L.FIXED + L.COUNT][prior]);
                var weighted = E.WeightedAccumulator{ .powers = output.random_coeff_powers };
                var sink = E.Sink{ .values = null, .weighted_accumulator = &weighted };
                provider.evaluate(geometry_values, &physical, &current, &previous, previous_count, self.count, self.challenges, &self.byte_alpha, self.claim, &sink);
                std.debug.assert(sink.count == L.CONSTRAINTS);
                output.accumulate(evaluation.globalRow(part, row), weighted.accumulation.mulM31(inverse));
            }
        }
    }
    fn evaluateReference(self: *const Component, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len != 3) return error.InvalidRv64MultiplicationShape;
        try self.checkShape(trace.polys.items[0].len, trace.polys.items[1].len, trace.polys.items[2].len);
        const a = accumulator.allocator;
        const eval_log = self.log_size + 2;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const size = domain.size();
        const n_fixed = L.FIXED;
        const total = TOTAL;
        var polynomial_storage: [TOTAL]cp.Poly = undefined;
        const polys = polynomial_storage[0..total];
        @memcpy(polys[0..n_fixed], trace.polys.items[0][self.fixed_offset..][0..n_fixed]);
        @memcpy(polys[n_fixed..][0..L.MAIN], trace.polys.items[1][self.main_offset..][0..L.MAIN]);
        @memcpy(polys[n_fixed + L.MAIN ..], trace.polys.items[2][self.interaction_offset..][0..L.INTERACTION]);
        var owned_count: usize = 0;
        for (polys) |poly| owned_count += @intFromBool(try support.sourceNeedsExtension(poly, self.log_size, eval_log));
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        var evaluation_storage: [TOTAL][]const M = undefined;
        const evaluations = evaluation_storage[0..total];
        for (polys, evaluations) |poly, *values| values.* = try support.evaluationValues(a, poly, eval_log, size, owned, &initialized);
        if (owned.len != 0) {
            var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &twiddles);
            try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
        }
        const inverses = try geometry.denominatorInverses(a, self.log_size, eval_log);
        defer a.free(inverses);
        const columns = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = L.CONSTRAINTS }});
        defer a.free(columns);
        var output = columns[0];
        for (0..size) |row| {
            const prior = core.utils.previousBitReversedCircleDomainIndex(row, self.log_size, eval_log);
            var geometry_values: [L.FIXED]Q = undefined;
            var physical: provider.Values = undefined;
            for (&geometry_values, 0..) |*value, i| value.* = Q.fromBase(evaluations[i][row]);
            for (&physical, 0..) |*value, i| value.* = Q.fromBase(evaluations[n_fixed + i][row]);
            var current: [L.INTERACTION]Q = undefined;
            var previous: [L.INTERACTION]Q = @splat(Q.zero());
            for (&current, evaluations[n_fixed + L.MAIN ..], 0..) |*value, column, i| {
                value.* = Q.fromBase(column[row]);
                if (i >= L.INTERACTION - 4) previous[i] = Q.fromBase(column[prior]);
            }
            const previous_count = Q.fromBase(evaluations[L.FIXED + L.COUNT][prior]);
            var weighted = E.WeightedAccumulator{ .powers = output.random_coeff_powers };
            var sink = E.Sink{ .values = null, .weighted_accumulator = &weighted };
            provider.evaluate(geometry_values, &physical, &current, &previous, previous_count, self.count, self.challenges, &self.byte_alpha, self.claim, &sink);
            std.debug.assert(sink.count == L.CONSTRAINTS);
            output.accumulate(row, weighted.accumulation.mulM31(inverses[row >> @as(std.math.Log2Int(usize), @intCast(self.log_size))]));
        }
    }
    fn checkShape(self: *const Component, fixed: usize, main: usize, interaction: usize) !void {
        if (self.log_size < 5 or self.log_size > 22 or self.count > (@as(usize, 1) << @intCast(self.log_size)) or fixed < try points.checkedEnd(self.fixed_offset, L.FIXED) or main < try points.checkedEnd(self.main_offset, L.MAIN) or interaction < try points.checkedEnd(self.interaction_offset, L.INTERACTION)) return error.InvalidRv64MultiplicationShape;
    }
};
fn sample(column: []const Q, index: usize, count: usize) !Q {
    if (column.len != count) return error.InvalidRv64MultiplicationShape;
    return column[index];
}

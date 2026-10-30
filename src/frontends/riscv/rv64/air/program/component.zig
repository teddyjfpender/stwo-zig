//! Concrete program provider in the same three trees/FRI as execution and range.
//! Offsets identify slices in shared trees; preprocessing remains receiver-owned.
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
const provider = @import("provider.zig");
const rom = @import("setup.zig");
const compact = @import("compact.zig");
const E = @import("../evaluation.zig");
const support = @import("../../../air/memory_commitment/hash_component_prepared_support.zig");
const points = @import("../../../air/component_point_support.zig");
pub const FIXED = rom.field.COUNT + 2;
const TOTAL = FIXED + 1 + provider.INTERACTION;

pub const Component = struct {
    log_size: u32,
    encoding: enum { full155, compact41 } = .full155,
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
        return provider.CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.log_size + 2;
    }
    pub fn compositionLogSplit(_: *const Component) u32 {
        return 2;
    }
    pub fn constraintDegreeBound(_: *const Component, index: usize) !u8 {
        if (index >= provider.CONSTRAINTS) return error.InvalidConstraintIndex;
        return 3;
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
        const fixed = try points.emptyOrFilledLogs(a, self.fixedCount(), self.log_size);
        errdefer a.free(fixed);
        const main = try points.emptyOrFilledLogs(a, 1, self.log_size);
        errdefer a.free(main);
        const interaction = try points.emptyOrFilledLogs(a, provider.INTERACTION, self.log_size);
        errdefer a.free(interaction);
        return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &.{ fixed, main, interaction }));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const result = try a.alloc(usize, self.fixedCount());
        for (result, 0..) |*value, i| value.* = self.fixed_offset + i;
        return result;
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
        _ = try geometry.localPoint(point, global_log, self.log_size);
        const fixed = try points.currentPointColumns(a, self.fixedCount(), point);
        errdefer points.freePointColumns(a, fixed);
        const main = try points.currentPointColumns(a, 1, point);
        errdefer points.freePointColumns(a, main);
        const interaction = try points.currentPointColumns(a, provider.INTERACTION, point);
        errdefer points.freePointColumns(a, interaction);
        for (interaction[4..]) |*column| {
            const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
            a.free(column.*);
            column.* = replacement;
        }
        return air.MaskPoints.initOwned(try a.dupe([][]Point, &.{ fixed, main, interaction }));
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        if (mask.items.len < 3) return error.InvalidRv64RomShape;
        try self.checkShape(mask.items[0].len, mask.items[1].len, mask.items[2].len);
        var entry: rom.Tuple = @splat(Q.zero());
        for (0..self.tupleCount()) |i| {
            entry[if (self.encoding == .compact41) compact.fields[i] else i] = try sample(mask.items[0][self.fixed_offset + i], 0, 1);
        }
        var current: [provider.INTERACTION]Q = undefined;
        var previous: [provider.INTERACTION]Q = @splat(Q.zero());
        for (&current, mask.items[2][self.interaction_offset..][0..provider.INTERACTION], 0..) |*value, column, i| {
            value.* = try sample(column, 0, if (i < 4) 1 else 2);
            if (i >= 4) previous[i] = try sample(column, 1, 2);
        }
        var sink = E.Sink{ .values = null, .accumulator = accumulator, .scale = try geometry.denominatorInverse(point, global_log, self.log_size) };
        provider.evaluate(try sample(mask.items[0][self.fixed_offset + self.tupleCount()], 0, 1), try sample(mask.items[0][self.fixed_offset + self.tupleCount() + 1], 0, 1), &entry, try sample(mask.items[1][self.main_offset], 0, 1), &current, &previous, self.challenges, self.claim, &sink);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len != 3) return error.InvalidRv64RomShape;
        try self.checkShape(trace.polys.items[0].len, trace.polys.items[1].len, trace.polys.items[2].len);
        const a = accumulator.allocator;
        const eval_log = self.log_size + 2;
        const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
        const size = domain.size();
        const n_fixed = self.fixedCount();
        const total = n_fixed + 1 + provider.INTERACTION;
        var polynomial_storage: [TOTAL]cp.Poly = undefined;
        const polys = polynomial_storage[0..total];
        @memcpy(polys[0..n_fixed], trace.polys.items[0][self.fixed_offset..][0..n_fixed]);
        polys[n_fixed] = trace.polys.items[1][self.main_offset];
        @memcpy(polys[n_fixed + 1 ..], trace.polys.items[2][self.interaction_offset..][0..provider.INTERACTION]);
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
        const columns = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = provider.CONSTRAINTS }});
        defer a.free(columns);
        var output = columns[0];
        for (0..size) |row| {
            const prior = core.utils.previousBitReversedCircleDomainIndex(row, self.log_size, eval_log);
            var entry: rom.Tuple = @splat(Q.zero());
            for (0..self.tupleCount()) |i| {
                entry[if (self.encoding == .compact41) compact.fields[i] else i] = Q.fromBase(evaluations[i][row]);
            }
            var current: [provider.INTERACTION]Q = undefined;
            var previous: [provider.INTERACTION]Q = @splat(Q.zero());
            for (&current, evaluations[n_fixed + 1 ..], 0..) |*value, column, i| {
                value.* = Q.fromBase(column[row]);
                if (i >= 4) previous[i] = Q.fromBase(column[prior]);
            }
            var residuals: [provider.CONSTRAINTS]Q = undefined;
            var sink = E.Sink{ .values = &residuals };
            provider.evaluate(Q.fromBase(evaluations[self.tupleCount()][row]), Q.fromBase(evaluations[self.tupleCount() + 1][row]), &entry, Q.fromBase(evaluations[n_fixed][row]), &current, &previous, self.challenges, self.claim, &sink);
            var folded = Q.zero();
            for (residuals, 0..) |value, i| folded = folded.add(output.random_coeff_powers[provider.CONSTRAINTS - 1 - i].mul(value));
            output.accumulate(row, folded.mulM31(inverses[row >> @as(std.math.Log2Int(usize), @intCast(self.log_size))]));
        }
    }
    pub fn tupleCount(self: *const Component) usize {
        return if (self.encoding == .compact41) compact.COUNT else rom.field.COUNT;
    }
    pub fn fixedCount(self: *const Component) usize {
        return self.tupleCount() + 2;
    }
    fn checkShape(self: *const Component, fixed: usize, main: usize, interaction: usize) !void {
        if (self.log_size < 5 or self.log_size > 22 or fixed < try points.checkedEnd(self.fixed_offset, self.fixedCount()) or main < try points.checkedEnd(self.main_offset, 1) or interaction < try points.checkedEnd(self.interaction_offset, provider.INTERACTION)) return error.InvalidRv64RomShape;
    }
};
fn sample(column: []const Q, index: usize, count: usize) !Q {
    if (column.len != count) return error.InvalidRv64RomShape;
    return column[index];
}

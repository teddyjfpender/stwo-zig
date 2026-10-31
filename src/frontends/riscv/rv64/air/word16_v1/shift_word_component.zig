//! Concrete D3/2n SHIFT adapter. OODS and SIMD domain use one emit authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const P = @import("shift_word_lookup.zig");
const geometry = @import("../geometry.zig");
const points = @import("../../../air/component_point_support.zig");
const support = @import("../../../air/memory_commitment/hash_component_prepared_support.zig");
const M = core.fields.m31.M31;
const Q = E.Q;
const Point = core.circle.CirclePointQM31;
const Air = core.air.components;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
pub const COLUMNS = 2 + P.MAIN + P.INTERACTION;
pub const Component = struct {
    log_size: u32,
    offsets: [3]usize,
    challenges: P.Challenges,
    claims: P.Claims,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Component) Air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(_: *const Component) usize {
        return P.CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.log_size + 1;
    }
    pub fn compositionLogSplit(_: *const Component) u32 {
        return 1;
    }
    pub fn constraintDegreeBound(_: *const Component, i: usize) !u8 {
        if (i >= P.CONSTRAINTS) return error.InvalidConstraintIndex;
        return 3;
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        if (self.log_size < 5 or self.log_size > 26) return error.InvalidWordShiftGeometry;
        var logs: [3][]u32 = undefined;
        var initialized: usize = 0;
        errdefer for (logs[0..initialized]) |values| a.free(values);
        for ([_]usize{ 2, P.MAIN, P.INTERACTION }, &logs) |width, *values| {
            values.* = try points.emptyOrFilledLogs(a, width, self.log_size);
            initialized += 1;
        }
        return Air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &logs));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const result = try a.alloc(usize, 2);
        result[0] = self.offsets[0];
        result[1] = self.offsets[0] + 1;
        return result;
    }
    pub fn needsPrevious(column: usize) bool {
        return column >= P.PREFIX;
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
        _ = try geometry.localPoint(point, global_log, self.log_size);
        var masks: [3][][]Point = undefined;
        var initialized: usize = 0;
        errdefer for (masks[0..initialized]) |columns| points.freePointColumns(a, columns);
        for ([_]usize{ 2, P.MAIN, P.INTERACTION }, &masks) |width, *columns| {
            columns.* = try points.currentPointColumns(a, width, point);
            initialized += 1;
        }
        for (masks[2], 0..) |*column, i| if (needsPrevious(i)) {
            const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
            a.free(column.*);
            column.* = replacement;
        };
        return Air.MaskPoints.initOwned(try a.dupe([][]Point, &masks));
    }
    pub fn emitFor(self: *const Component, comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, sink: *E.SinkFor(F)) void {
        P.emitFor(F, main, current, previous, fixed[0], fixed[1], self.claims, self.challenges, sink);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const Air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        if (mask.items.len < 3) return error.InvalidWordShiftMask;
        var values: [COLUMNS]Q = undefined;
        var previous: [P.INTERACTION]Q = @splat(Q.zero());
        var cursor: usize = 0;
        for ([_]usize{ 2, P.MAIN, P.INTERACTION }, 0..) |width, tree| {
            if (mask.items[tree].len < self.offsets[tree] + width) return error.InvalidWordShiftMask;
            for (mask.items[tree][self.offsets[tree]..][0..width], 0..) |samples, i| {
                const prior = tree == 2 and needsPrevious(i);
                if (samples.len != @as(usize, if (prior) 2 else 1)) return error.InvalidWordShiftMask;
                values[cursor] = samples[0];
                cursor += 1;
                if (prior) previous[i] = samples[1];
            }
        }
        var sink = E.Sink{ .values = null, .accumulator = accumulator, .scale = try geometry.denominatorInverse(point, global_log, self.log_size) };
        self.emitFor(Q, values[0..2], values[2..][0..P.MAIN], values[2 + P.MAIN ..], &previous, &sink);
        std.debug.assert(sink.count == P.CONSTRAINTS);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        const a = accumulator.allocator;
        if (trace.polys.items.len != 3) return error.InvalidWordShiftTrace;
        var polys: [COLUMNS]cp.Poly = undefined;
        var cursor: usize = 0;
        for ([_]usize{ 2, P.MAIN, P.INTERACTION }, 0..) |width, tree| {
            if (trace.polys.items[tree].len < self.offsets[tree] + width) return error.InvalidWordShiftTrace;
            @memcpy(polys[cursor..][0..width], trace.polys.items[tree][self.offsets[tree]..][0..width]);
            cursor += width;
        }
        const eval_log = self.log_size + 1;
        const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
        const n = domain.size();
        var owned_count: usize = 0;
        for (polys) |poly| owned_count += @intFromBool(try support.sourceNeedsExtension(poly, self.log_size, eval_log));
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        var evaluations: [COLUMNS][]const M = undefined;
        for (polys, &evaluations) |poly, *values| values.* = try support.evaluationValues(a, poly, eval_log, n, owned, &initialized);
        if (owned_count != 0) {
            var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &twiddles);
            try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
        }
        const inverses = try geometry.denominatorInverses(a, self.log_size, eval_log);
        defer a.free(inverses);
        const columns = try accumulator.columns(a, &.{.{ .log_size = eval_log, .n_cols = P.CONSTRAINTS }});
        defer a.free(columns);
        var output = columns[0];
        try @import("shift_word_packed_rows.zig").evaluate(self, &evaluations, 0, n, inverses, &output);
    }
};

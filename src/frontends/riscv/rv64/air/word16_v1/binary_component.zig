//! Three concrete roles for the standalone BINARY qualification transaction.
//! The expected role is PUBLIC DIAGNOSTIC IO, not an RV64 CPU replacement.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const P = @import("binary_lookup.zig");
const Tables = @import("../providers/tables.zig");
const geometry = @import("../geometry.zig");
const points = @import("../../../air/component_point_support.zig");
const support = @import("../../../air/memory_commitment/hash_component_prepared_support.zig");
const M = core.fields.m31.M31;
const Q = E.Q;
const Point = core.circle.CirclePointQM31;
const air = core.air.components;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
pub const Kind = enum { binary, expected, and_table };
pub const Component = struct {
    kind: Kind,
    log_size: u32,
    offsets: [3]usize,
    challenges: P.Challenges,
    claims: P.Claims,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Component) air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn widths(self: *const Component) [3]usize {
        return switch (self.kind) {
            .binary => .{ 2, P.MAIN, P.INTERACTION },
            .expected => .{ 16, 0, 8 },
            .and_table => .{ 5, 1, 8 },
        };
    }
    pub fn nConstraints(self: *const Component) usize {
        return switch (self.kind) {
            .binary => P.CONSTRAINTS,
            .expected => 3,
            .and_table => Tables.N_CONSTRAINTS,
        };
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        return self.log_size + 1;
    }
    pub fn compositionLogSplit(_: *const Component) u32 {
        return 1;
    }
    pub fn constraintDegreeBound(self: *const Component, index: usize) !u8 {
        if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
        return 3;
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
        const widths_ = self.widths();
        var logs: [3][]u32 = undefined;
        var initialized: usize = 0;
        errdefer for (logs[0..initialized]) |values| a.free(values);
        for (widths_, &logs) |width, *values| {
            values.* = try points.emptyOrFilledLogs(a, width, self.log_size);
            initialized += 1;
        }
        return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &logs));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const indices = try a.alloc(usize, self.widths()[0]);
        for (indices, 0..) |*index, i| index.* = self.offsets[0] + i;
        return indices;
    }
    pub fn needsPrevious(self: *const Component, column: usize) bool {
        return if (self.kind == .binary) (column >= 16 and column < 20) or column >= 24 else column >= 4;
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
        _ = try geometry.localPoint(point, global_log, self.log_size);
        const widths_ = self.widths();
        var masks: [3][][]Point = undefined;
        var initialized: usize = 0;
        errdefer for (masks[0..initialized]) |columns| points.freePointColumns(a, columns);
        for (widths_, &masks) |width, *columns| {
            columns.* = try points.currentPointColumns(a, width, point);
            initialized += 1;
        }
        for (masks[2], 0..) |*column, i| if (self.needsPrevious(i)) {
            const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
            a.free(column.*);
            column.* = replacement;
        };
        return air.MaskPoints.initOwned(try a.dupe([][]Point, &masks));
    }
    pub fn emitFor(self: *const Component, comptime F: type, fixed: []const F, main: []const F, inter: []const F, previous: []const F, sink: *E.SinkFor(F)) void {
        switch (self.kind) {
            .binary => P.emitFor(F, main, inter, previous, fixed[0], fixed[1], self.claims, self.challenges, sink),
            .expected => {
                var tuple: [13]F = undefined;
                @memcpy(&tuple, fixed[0..13]);
                P.emitFunctionFor(F, tuple, fixed[13], fixed[14], fixed[15], E.secureFor(F, inter, 0), E.secureFor(F, inter, 4), E.secureFor(F, previous, 4), self.claims.function, self.challenges.function, sink);
            },
            .and_table => {
                const residuals = Tables.evaluateFor(F, fixed[0..3], fixed[3], fixed[4], main[0], E.secureFor(F, inter, 0), E.secureFor(F, inter, 4), E.secureFor(F, previous, 4), self.claims.and_, self.challenges.and_);
                for (residuals) |value| sink.emit(value);
            },
        }
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const air.MaskValues, acc: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        if (mask.items.len < 3) return error.InvalidWord16Mask;
        const widths_ = self.widths();
        var values: [72]Q = undefined;
        var previous: [P.INTERACTION]Q = @splat(Q.zero());
        var cursor: usize = 0;
        for (widths_, 0..) |width, tree| {
            if (mask.items[tree].len < self.offsets[tree] + width) return error.InvalidWord16Mask;
            for (mask.items[tree][self.offsets[tree]..][0..width], 0..) |samples, i| {
                const needs = tree == 2 and self.needsPrevious(i);
                if (samples.len != @as(usize, if (needs) 2 else 1)) return error.InvalidWord16Mask;
                values[cursor] = samples[0];
                cursor += 1;
                if (needs) previous[i] = samples[1];
            }
        }
        var sink = E.Sink{ .values = null, .accumulator = acc, .scale = try geometry.denominatorInverse(point, global_log, self.log_size) };
        self.emitFor(Q, values[0..widths_[0]], values[widths_[0]..][0..widths_[1]], values[widths_[0] + widths_[1] ..][0..widths_[2]], previous[0..widths_[2]], &sink);
        std.debug.assert(sink.count == self.nConstraints());
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator) !void {
        const a = acc.allocator;
        const widths_ = self.widths();
        const total = widths_[0] + widths_[1] + widths_[2];
        var polys_storage: [72]cp.Poly = undefined;
        const polys = polys_storage[0..total];
        var cursor: usize = 0;
        for (widths_, 0..) |width, tree| {
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
        var evaluation_storage: [72][]const M = undefined;
        const evaluations = evaluation_storage[0..total];
        for (polys, evaluations) |poly, *values| values.* = try support.evaluationValues(a, poly, eval_log, n, owned, &initialized);
        if (owned_count != 0) {
            var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &twiddles);
            try engine.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
        }
        const inverses = try geometry.denominatorInverses(a, self.log_size, eval_log);
        defer a.free(inverses);
        const columns = try acc.columns(a, &.{.{ .log_size = eval_log, .n_cols = self.nConstraints() }});
        defer a.free(columns);
        var output = columns[0];
        try @import("binary_packed_rows.zig").evaluate(self, evaluations, 0, n, inverses, &output);
    }
};

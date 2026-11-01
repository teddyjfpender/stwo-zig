const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../../evaluation.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const Eq = @import("equations.zig");
const geometry = @import("../../geometry.zig");
const point_lane = @import("../../lane.zig");
const points = @import("../../../../air/component_point_support.zig");
const support = @import("../../../../air/memory_commitment/hash_component_prepared_support.zig");
const M = core.fields.m31.M31;
const Q = T.Q;
const Point = core.circle.CirclePointQM31;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
/// One bulk-memory bridge kind inside a CPU proof. `rows` is the public active
/// row count (calls for desc, words for copy/set) bound by the statement.
pub const Component = struct {
    kind: L.Kind,
    log_size: u32,
    rows: u32,
    offsets: [3]usize,
    claims: T.Claims,
    challenges: T.Challenges,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        var result = Adapter.asProverComponent(self);
        result.domain_parallel_evaluator = evaluateParallel;
        result.pool_exclusive_domain = true;
        // Domain splits go only through the shared row/column providers.
        result.cooperative_domain = true;
        return result;
    }
    fn evaluateParallel(ctx: *const anyopaque, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
        const self: *const Component = @ptrCast(@alignCast(ctx));
        return self.evaluateDomain(trace, acc, pool);
    }
    pub fn asVerifierComponent(self: *const Component) core.air.components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn widths(self: *const Component) [3]usize {
        return L.widths(self.kind);
    }
    pub fn nConstraints(self: *const Component) usize {
        return L.constraints(self.kind);
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
    pub fn emitFor(self: *const Component, comptime F: type, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, sink: *E.SinkFor(F)) void {
        switch (self.kind) {
            inline else => |k| Eq.emitFor(F, k, f, m, pm, i, pi, self.rows, self.claims, self.challenges, sink),
        }
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        _ = try T.validateGeometry(self.kind, self.rows, self.log_size);
        var logs: [3][]u32 = undefined;
        var n: usize = 0;
        errdefer for (logs[0..n]) |data| a.free(data);
        for (self.widths(), &logs) |width, *data| {
            data.* = try points.emptyOrFilledLogs(a, width, self.log_size);
            n += 1;
        }
        return core.air.components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &logs));
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        const data = try a.alloc(usize, self.widths()[0]);
        for (data, 0..) |*v, c| v.* = self.offsets[0] + c;
        return data;
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !core.air.components.MaskPoints {
        _ = try T.validateGeometry(self.kind, self.rows, self.log_size);
        _ = try geometry.localPoint(point, global_log, self.log_size);
        var masks: [3][][]Point = undefined;
        var n: usize = 0;
        errdefer for (masks[0..n]) |data| points.freePointColumns(a, data);
        for (self.widths(), &masks) |width, *data| {
            data.* = try points.currentPointColumns(a, width, point);
            n += 1;
        }
        for (1..3) |tree| for (masks[tree], 0..) |*data, c| {
            if (if (tree == 1) L.previousMainFor(self.kind, c) else L.previousInterFor(self.kind, c)) {
                const replacement = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
                a.free(data.*);
                data.* = replacement;
            }
        };
        return core.air.components.MaskPoints.initOwned(try a.dupe([][]Point, &masks));
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const core.air.components.MaskValues, acc: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        if (mask.items.len < 3) return error.InvalidBulkMemoryMask;
        var sink = E.Sink{ .values = null, .accumulator = acc };
        try self.evaluatePointFor(Q, point, global_log, point_lane.NativeMasks{ .values = mask }, self.rows, self.claims, self.challenges, &sink);
    }
    /// The one point authority for every lane (QM31 natively, circuit wires
    /// for recursion). Rows, claims and challenges are explicit constant-lane
    /// values; only the kind, log size and column offsets come from `self`.
    pub fn evaluatePointFor(self: *const Component, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, rows: T.RowsFor(E.ConstFor(F)), claims: T.ClaimsFor(E.ConstFor(F)), challenges: T.ChallengesFor(E.ConstFor(F)), sink: *E.SinkFor(F)) !void {
        const widths_ = self.widths();
        var data: [128]F = undefined;
        var pm: [64]F = @splat(F.zero());
        var pi: [64]F = @splat(F.zero());
        var at: usize = 0;
        for (widths_, 0..) |width, tree| for (0..width) |c| {
            const prev = if (tree == 1) L.previousMainFor(self.kind, c) else tree == 2 and L.previousInterFor(self.kind, c);
            const n = masks.count(tree, self.offsets[tree] + c) catch return error.InvalidBulkMemoryMask;
            if (n != @as(usize, if (prev) 2 else 1)) return error.InvalidBulkMemoryMask;
            data[at] = try masks.at(tree, self.offsets[tree] + c, 0);
            at += 1;
            if (prev) {
                const previous = try masks.at(tree, self.offsets[tree] + c, 1);
                if (tree == 1) pm[c] = previous else pi[c] = previous;
            }
        };
        sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.log_size);
        const before = sink.count;
        const f = data[0..widths_[0]];
        const m = data[widths_[0]..][0..widths_[1]];
        const i = data[widths_[0] + widths_[1] ..][0..widths_[2]];
        switch (self.kind) {
            inline else => |k| Eq.emitFor(F, k, f, m, pm[0..widths_[1]], i, pi[0..widths_[2]], rows, claims, challenges, sink),
        }
        std.debug.assert(sink.count - before == self.nConstraints());
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator) !void {
        return self.evaluateDomain(trace, acc, null);
    }
    fn evaluateDomain(self: *const Component, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
        const a = acc.allocator;
        const widths_ = self.widths();
        const total = widths_[0] + widths_[1] + widths_[2];
        var polys_buffer: [128]cp.Poly = undefined;
        const polys = polys_buffer[0..total];
        var at: usize = 0;
        for (widths_, 0..) |width, tree| {
            @memcpy(polys[at..][0..width], trace.polys.items[tree][self.offsets[tree]..][0..width]);
            at += width;
        }
        const log = self.log_size + 1;
        const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
        const n = domain.size();
        var owned_count: usize = 0;
        for (polys) |poly| owned_count += @intFromBool(try support.sourceNeedsExtension(poly, self.log_size, log));
        const owned = try a.alloc([]M, owned_count);
        var initialized: usize = 0;
        defer {
            for (owned[0..initialized]) |column| a.free(column);
            a.free(owned);
        }
        var eval_buffer: [128][]const M = undefined;
        const evals = eval_buffer[0..total];
        for (polys, evals) |poly, *data| data.* = try support.evaluationValues(a, poly, log, n, owned, &initialized);
        if (owned_count != 0) {
            var tw = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            defer engine.poly.twiddles.deinitM31(a, &tw);
            try @import("../../providers/domain_transform.zig").evaluate(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(tw.root_coset, tw.twiddles, tw.itwiddles), pool);
        }
        const inverses = try geometry.denominatorInverses(a, self.log_size, log);
        defer a.free(inverses);
        const columns = try acc.columns(a, &.{.{ .log_size = log, .n_cols = self.nConstraints() }});
        defer a.free(columns);
        var output = columns[0];
        const rows = Rows{ .component = self, .columns = evals, .inverses = inverses };
        try @import("../../providers/parallel_rows.zig").evaluate(.{ .context = &rows, .run = Rows.run }, n, &output, pool);
    }
};
const Rows = struct {
    component: *const Component,
    columns: []const []const M,
    inverses: []const M,
    fn run(ctx: *const anyopaque, start: usize, end: usize, output: *accumulation.ColumnAccumulator) anyerror!void {
        const self: *const Rows = @ptrCast(@alignCast(ctx));
        return @import("packed_rows.zig").evaluate(self.component, self.columns, start, end, self.inverses, output);
    }
};
pub const testing = if (@import("builtin").is_test) struct {
    pub const packedRows = @import("packed_rows.zig");
    pub fn evaluateRows(component: *const Component, columns: []const []const M, inverses: []const M, output: *accumulation.ColumnAccumulator, pool: *engine.work_pool.WorkPool) !void {
        const rows = Rows{ .component = component, .columns = columns, .inverses = inverses };
        return @import("../../providers/parallel_rows.zig").evaluate(.{ .context = &rows, .run = Rows.run }, columns[0].len, output, pool);
    }
} else struct {};

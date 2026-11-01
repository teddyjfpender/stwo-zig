const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../../evaluation.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const Eq = @import("equations.zig");
const geometry = @import("../../geometry.zig");
const points = @import("../../../../air/component_point_support.zig");
const support = @import("../../../../air/memory_commitment/hash_component_prepared_support.zig");
const M = core.fields.m31.M31;
const Q = T.Q;
const Point = core.circle.CirclePointQM31;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
comptime {
    for (std.meta.tags(L.Kind)) |kind| {
        const widths = L.widths(kind);
        if (widths[0] > 6 or widths[1] > L.MAIN or widths[2] > L.INTERACTION)
            @compileError("load/store point scratch does not cover physical layout");
    }
}
pub const Component = ComponentFor(Q);
pub fn ComponentFor(comptime C: type) type {
    E.assertConstLane(C);
    return struct {
        const Self = @This();
        kind: L.Kind,
        log_size: u32,
        rows: E.CountFor(C),
        /// External statements supply the derived count!=0 wire, not a host bool.
        rows_nonzero: E.FlagFor(C) = E.flagDefault(C),
        offsets: [3]usize,
        claims: T.ClaimsFor(C),
        challenges: T.ChallengesFor(C),
        const Adapter = core.air.derive.ComponentAdapter(Self, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
        pub fn asProverComponent(self: *const Self) cp.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.domain_parallel_evaluator = evaluateParallel;
            result.pool_exclusive_domain = true;
            // Domain splits go only through the shared row/column providers.
            result.cooperative_domain = true;
            return result;
        }
        fn evaluateParallel(ctx: *const anyopaque, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            return self.evaluateDomain(trace, acc, pool);
        }
        pub fn asVerifierComponent(self: *const Self) core.air.components.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn widths(self: *const Self) [3]usize {
            return L.widths(self.kind);
        }
        pub fn nConstraints(self: *const Self) usize {
            return L.constraints(self.kind);
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + 1;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 1;
        }
        pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
            if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
            return 3;
        }
        pub fn emitFor(self: *const Self, comptime F: type, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, sink: *E.SinkFor(F)) void {
            comptime if (E.ConstFor(F) != C) @compileError("load/store component lane mismatch");
            if (comptime C == Q) {
                Eq.emitFor(F, self.kind, f, m, pm, i, pi, self.rows, self.claims, self.challenges, sink);
            } else {
                const nonempty = self.rows_nonzero orelse @panic("missing admitted load/store count flag");
                Eq.emitWithPublicFor(F, self.kind, f, m, pm, i, pi, self.rows, nonempty, self.claims, self.challenges, sink);
            }
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
            var logs: [3][]u32 = undefined;
            var n: usize = 0;
            errdefer for (logs[0..n]) |data| a.free(data);
            for (self.widths(), &logs) |width, *data| {
                data.* = try points.emptyOrFilledLogs(a, width, self.log_size);
                n += 1;
            }
            return core.air.components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &logs));
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const data = try a.alloc(usize, self.widths()[0]);
            for (data, 0..) |*v, c| v.* = self.offsets[0] + c;
            return data;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !core.air.components.MaskPoints {
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
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const core.air.components.MaskValues, acc: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
            var sink = E.Sink{ .values = null, .accumulator = acc };
            self.evaluateQuotientsAtPointFor(Q, point, global_log, E.lane.NativeMasks{ .values = mask }, &sink) catch |err| return if (err == error.InvalidRv64MaskShape) error.InvalidLoadStoreMask else err;
        }
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *E.SinkFor(F)) !void {
            comptime if (E.ConstFor(F) != C) @compileError("load/store component lane mismatch");
            if (comptime C != Q) if (self.rows_nonzero == null) return error.MissingRv64LaneFlag;
            const widths_ = self.widths();
            var fixed: [6]F = undefined;
            var main: [L.MAIN]F = undefined;
            var pm: [L.MAIN]F = @splat(F.zero());
            var inter: [L.INTERACTION]F = undefined;
            var pi: [L.INTERACTION]F = @splat(F.zero());
            for (fixed[0..widths_[0]], 0..) |*v, c| v.* = try E.lane.sample(F, masks, 0, self.offsets[0] + c, 0, 1);
            for (main[0..widths_[1]], 0..) |*v, c| {
                const prior = L.previousMainFor(self.kind, c);
                v.* = try E.lane.sample(F, masks, 1, self.offsets[1] + c, 0, if (prior) 2 else 1);
                if (prior) pm[c] = try E.lane.sample(F, masks, 1, self.offsets[1] + c, 1, 2);
            }
            for (inter[0..widths_[2]], 0..) |*v, c| {
                const prior = L.previousInterFor(self.kind, c);
                v.* = try E.lane.sample(F, masks, 2, self.offsets[2] + c, 0, if (prior) 2 else 1);
                if (prior) pi[c] = try E.lane.sample(F, masks, 2, self.offsets[2] + c, 1, 2);
            }
            sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.log_size);
            self.emitFor(F, fixed[0..widths_[0]], main[0..widths_[1]], pm[0..widths_[1]], inter[0..widths_[2]], pi[0..widths_[2]], sink);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator) !void {
            return self.evaluateDomain(trace, acc, null);
        }
        fn evaluateDomain(self: *const Self, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
            const a = acc.allocator;
            const widths_ = self.widths();
            const total = widths_[0] + widths_[1] + widths_[2];
            var polys_buffer: [256]cp.Poly = undefined;
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
            var eval_buffer: [256][]const M = undefined;
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
}

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

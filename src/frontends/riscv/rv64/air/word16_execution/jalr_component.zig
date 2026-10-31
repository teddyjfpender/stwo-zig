//! Checked unit composite JALR delegation; no duplicated arithmetic truth.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const J = @import("jalr_equations.zig");
const CONSTRAINTS = J.CONSTRAINTS;
const L = @import("layout.zig");
const T = @import("types.zig");
const geometry = @import("../geometry.zig");
const points = @import("../../../air/component_point_support.zig");
const support = @import("../../../air/memory_commitment/hash_component_prepared_support.zig");
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const M = core.fields.m31.M31;
const Q = E.Q;
pub const COLUMNS = J.FIXED + J.MAIN + J.INTERACTION;
pub const Component = ComponentFor(Q);
pub fn ComponentFor(comptime C: type) type {
    E.assertConstLane(C);
    return struct {
        log_size: u32,
        offsets: [3]usize,
        claim: C,
        challenges: T.FunctionChallengesFor(C),
        const Self = @This();
        const Adapter = core.air.derive.ComponentAdapter(Self, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
        pub fn asProverComponent(self: *const Self) cp.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.domain_parallel_evaluator = evaluateParallel;
            result.pool_exclusive_domain = true;
            return result;
        }
        fn evaluateParallel(ctx: *const anyopaque, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            return self.evaluateDomain(trace, acc, pool);
        }
        pub fn asVerifierComponent(self: *const Self) core.air.components.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(_: *const Self) usize {
            return CONSTRAINTS;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + 1;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 1;
        }
        pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
            if (index >= CONSTRAINTS) return error.InvalidConstraintIndex;
            return 3;
        }
        pub fn widths(_: *const Self) [3]usize {
            return .{ J.FIXED, J.MAIN, J.INTERACTION };
        }
        pub fn needsPrevious(_: *const Self, tree: usize, column: usize) bool {
            return tree == 2 and column >= 8;
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
            if (self.log_size < L.MIN_LOG or self.log_size > L.MAX_LOG) return error.InvalidExecutionGeometry;
            var logs: [3][]u32 = undefined;
            var done: usize = 0;
            errdefer for (logs[0..done]) |data| a.free(data);
            for (self.widths(), &logs) |width, *data| {
                data.* = try points.emptyOrFilledLogs(a, width, self.log_size);
                done += 1;
            }
            return core.air.components.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &logs));
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const data = try a.alloc(usize, J.FIXED);
            for (data, 0..) |*v, c| v.* = self.offsets[0] + c;
            return data;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: core.circle.CirclePointQM31, global_log: u32) !core.air.components.MaskPoints {
            _ = try geometry.localPoint(point, global_log, self.log_size);
            var masks: [3][][]core.circle.CirclePointQM31 = undefined;
            var done: usize = 0;
            errdefer for (masks[0..done]) |data| points.freePointColumns(a, data);
            for (self.widths(), &masks, 0..) |width, *data, tree| {
                data.* = try points.currentPointColumns(a, width, point);
                done += 1;
                for (data.*, 0..) |*column, c| if (self.needsPrevious(tree, c)) {
                    const replacement = try a.dupe(core.circle.CirclePointQM31, &.{ point, geometry.previousPoint(point, global_log) });
                    a.free(column.*);
                    column.* = replacement;
                };
            }
            return core.air.components.MaskPoints.initOwned(try a.dupe([][]core.circle.CirclePointQM31, &masks));
        }
        pub fn emitFor(self: *const Self, comptime F: type, f: []const F, m: []const F, pm: []const F, i: []const F, pi: []const F, sink: *E.SinkFor(F)) void {
            _ = pm;
            J.emitFor(F, f, m, i, pi, self.claim, self.challenges, sink);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: core.circle.CirclePointQM31, mask: *const core.air.components.MaskValues, acc: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
            var sink = E.Sink{ .values = null, .accumulator = acc };
            try self.evaluateQuotientsAtPointFor(Q, point, global_log, E.lane.NativeMasks{ .values = mask }, &sink);
        }
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *E.SinkFor(F)) !void {
            comptime if (E.ConstFor(F) != C) @compileError("execution component lane mismatch");
            var fixed: [J.FIXED]F = undefined;
            var main: [J.MAIN]F = undefined;
            var pm: [J.MAIN]F = @splat(F.zero());
            var inter: [J.INTERACTION]F = undefined;
            var pi: [J.INTERACTION]F = @splat(F.zero());
            for (&fixed, 0..) |*v, c| v.* = try E.lane.sample(F, masks, 0, self.offsets[0] + c, 0, 1);
            for (&main, 0..) |*v, c| {
                const prior = false;
                v.* = try E.lane.sample(F, masks, 1, self.offsets[1] + c, 0, if (prior) 2 else 1);
                if (prior) pm[c] = try E.lane.sample(F, masks, 1, self.offsets[1] + c, 1, 2);
            }
            for (&inter, 0..) |*v, c| {
                const prior = c >= 8;
                v.* = try E.lane.sample(F, masks, 2, self.offsets[2] + c, 0, if (prior) 2 else 1);
                if (prior) pi[c] = try E.lane.sample(F, masks, 2, self.offsets[2] + c, 1, 2);
            }
            sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.log_size);
            self.emitFor(F, &fixed, &main, &pm, &inter, &pi, sink);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator) !void {
            return self.evaluateDomain(trace, acc, null);
        }
        fn evaluateDomain(self: *const Self, trace: *const cp.Trace, acc: *accumulation.DomainEvaluationAccumulator, pool: ?*engine.work_pool.WorkPool) !void {
            comptime if (C != Q) @compileError("external lane has no native domain evaluator");
            if (self.log_size < L.MIN_LOG or self.log_size > L.MAX_LOG or trace.polys.items.len != 3) return error.InvalidExecutionGeometry;
            const a = acc.allocator;
            var polys: [COLUMNS]cp.Poly = undefined;
            var at: usize = 0;
            for (self.widths(), 0..) |width, tree| {
                if (trace.polys.items[tree].len < self.offsets[tree] + width) return error.InvalidExecutionShape;
                @memcpy(polys[at..][0..width], trace.polys.items[tree][self.offsets[tree]..][0..width]);
                at += width;
            }
            const log = self.log_size + 1;
            const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
            const n = domain.size();
            var count: usize = 0;
            for (polys) |poly| count += @intFromBool(try support.sourceNeedsExtension(poly, self.log_size, log));
            const owned = try a.alloc([]M, count);
            var initialized: usize = 0;
            defer {
                for (owned[0..initialized]) |data| a.free(data);
                a.free(owned);
            }
            var evals: [COLUMNS][]const M = undefined;
            for (polys, &evals) |poly, *data| data.* = try support.evaluationValues(a, poly, log, n, owned, &initialized);
            if (count != 0) {
                var tw = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
                defer engine.poly.twiddles.deinitM31(a, &tw);
                try @import("../providers/domain_transform.zig").evaluate(owned, domain, engine.poly.twiddles.TwiddleTree([]const M).init(tw.root_coset, tw.twiddles, tw.itwiddles), pool);
            }
            const inverses = try geometry.denominatorInverses(a, self.log_size, log);
            defer a.free(inverses);
            const columns = try acc.columns(a, &.{.{ .log_size = log, .n_cols = CONSTRAINTS }});
            defer a.free(columns);
            var output = columns[0];
            const rows = Rows{ .component = self, .columns = &evals, .inverses = inverses };
            try @import("../providers/parallel_rows.zig").evaluate(.{ .context = &rows, .run = Rows.run }, n, &output, pool);
        }
    };
}
const Rows = struct {
    component: *const Component,
    columns: []const []const M,
    inverses: []const M,
    fn run(ctx: *const anyopaque, start: usize, end: usize, output: *accumulation.ColumnAccumulator) anyerror!void {
        const self: *const Rows = @ptrCast(@alignCast(ctx));
        return @import("jalr_packed_rows.zig").evaluate(self.component, self.columns, start, end, self.inverses, output);
    }
};
pub const testing = if (@import("builtin").is_test) struct {
    pub const packedRows = @import("jalr_packed_rows.zig");
} else struct {};

//! Explicit MUL degree3/2n component. Legacy triple/4n receiver stays intact.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../../evaluation.zig");
const L = @import("degree3_layout.zig");
const P = @import("degree3_provider.zig");
const geometry = @import("../../geometry.zig");
const lane = @import("../../lane.zig");
const points = @import("../../../../air/component_point_support.zig");
const cp = engine.air.component_prover;
const acc = engine.air.accumulation;
const air = core.air.components;
const Point = core.circle.CirclePointQM31;
pub fn ComponentFor(comptime Lane: type) type {
    return struct {
        const Self = @This();
        log_size: u32,
        count: E.CountFor(Lane),
        fixed_offset: usize,
        main_offset: usize,
        interaction_offset: usize,
        challenges: P.ChallengesFor(Lane),
        byte_alpha: Lane,
        claim: Lane,
        const Adapter = core.air.derive.ComponentAdapter(Self, cp.ComponentProver, cp.Trace, acc.DomainEvaluationAccumulator);
        pub fn asProverComponent(self: *const Self) cp.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.domain_parallel_evaluator = evaluateParallelErased;
            return result;
        }
        pub fn asVerifierComponent(self: *const Self) air.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(_: *const Self) usize {
            return L.CONSTRAINTS;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + 1;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 1;
        }
        pub fn constraintDegreeBound(_: *const Self, i: usize) !u8 {
            if (i >= L.CONSTRAINTS) return error.InvalidConstraintIndex;
            return 3;
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
            var logs: [3][]u32 = undefined;
            var initialized: usize = 0;
            errdefer for (logs[0..initialized]) |v| a.free(v);
            for ([_]usize{ L.FIXED, L.MAIN, L.INTERACTION }, &logs) |n, *v| {
                v.* = try points.emptyOrFilledLogs(a, n, self.log_size);
                initialized += 1;
            }
            return air.TraceLogDegreeBounds.initOwned(try a.dupe([]u32, &logs));
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const indices = try a.alloc(usize, L.FIXED);
            for (indices, 0..) |*v, i| v.* = self.fixed_offset + i;
            return indices;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
            _ = try geometry.localPoint(point, global_log, self.log_size);
            const fixed = try points.currentPointColumns(a, L.FIXED, point);
            errdefer points.freePointColumns(a, fixed);
            const main = try points.currentPointColumns(a, L.MAIN, point);
            errdefer points.freePointColumns(a, main);
            const prior_count = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
            a.free(main[L.COUNT]);
            main[L.COUNT] = prior_count;
            const inter = try points.currentPointColumns(a, L.INTERACTION, point);
            errdefer points.freePointColumns(a, inter);
            for (inter[L.PREFIX..]) |*v| {
                const prior = try a.dupe(Point, &.{ point, geometry.previousPoint(point, global_log) });
                a.free(v.*);
                v.* = prior;
            }
            return air.MaskPoints.initOwned(try a.dupe([][]Point, &.{ fixed, main, inter }));
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, masks: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
            var sink = E.Sink{ .values = null, .accumulator = accumulator };
            return self.evaluateQuotientsAtPointFor(E.Q, point, global_log, lane.NativeMasks{ .values = masks }, &sink);
        }
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *E.SinkFor(F)) !void {
            comptime if (E.ConstFor(F) != Lane) @compileError("MUL degree3 lane mismatch");
            if (self.log_size < 5 or self.log_size > 22) return error.InvalidRv64MaskShape;
            var fixed: [L.FIXED]F = undefined;
            var main: [L.MAIN]F = undefined;
            var current: [L.INTERACTION]F = undefined;
            var previous: [4]F = undefined;
            for (&fixed, 0..) |*v, i| v.* = try lane.sample(F, masks, 0, self.fixed_offset + i, 0, 1);
            for (&main, 0..) |*v, i| v.* = try lane.sample(F, masks, 1, self.main_offset + i, 0, if (i == L.COUNT) 2 else 1);
            const previous_count = try lane.sample(F, masks, 1, self.main_offset + L.COUNT, 1, 2);
            for (&current, 0..) |*v, i| v.* = try lane.sample(F, masks, 2, self.interaction_offset + i, 0, if (i >= L.PREFIX) 2 else 1);
            for (&previous, 0..) |*v, i| v.* = try lane.sample(F, masks, 2, self.interaction_offset + L.PREFIX + i, 1, 2);
            sink.scale = try geometry.denominatorInverseFor(F, point, global_log, self.log_size);
            P.evaluateFor(F, fixed, &main, &current, E.secureFromCoordinatesFor(F, previous), previous_count, E.scalarFor(F, self.count), self.challenges, self.byte_alpha, self.claim, sink);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const cp.Trace, accumulator: *acc.DomainEvaluationAccumulator) !void {
            return @import("degree3_native.zig").evaluate(self, trace, accumulator, null);
        }
        fn evaluateParallelErased(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *acc.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            return @import("degree3_native.zig").evaluate(self, trace, accumulator, pool);
        }
    };
}
pub const Component = ComponentFor(E.Q);

pub const testing = if (@import("builtin").is_test) struct {
    pub fn scalarErased(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *acc.DomainEvaluationAccumulator) anyerror!void {
        const self: *const Component = @ptrCast(@alignCast(ctx));
        return @import("degree3_native.zig").testing.scalar(self, trace, accumulator);
    }
} else struct {};

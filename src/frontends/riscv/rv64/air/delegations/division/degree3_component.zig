//! Explicit native2n DIV route. The legacy4n component and transcript stay intact.
//! Both routes use exactly the same 1567 provider equations and OODS authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../../evaluation.zig");
const Base = @import("component.zig");
const geometry = @import("../../geometry.zig");
const cp = engine.air.component_prover;
const acc = engine.air.accumulation;
const air = core.air.components;
const Point = core.circle.CirclePointQM31;

pub fn ComponentFor(comptime Lane: type) type {
    return struct {
        const Self = @This();
        base: Base.ComponentFor(Lane),
        const Adapter = core.air.derive.ComponentAdapter(Self, cp.ComponentProver, cp.Trace, acc.DomainEvaluationAccumulator);
        pub fn asProverComponent(self: *const Self) cp.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.domain_parallel_evaluator = evaluateParallelErased;
            return result;
        }
        pub fn asVerifierComponent(self: *const Self) air.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(self: *const Self) usize {
            return self.base.nConstraints();
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.base.log_size + 1;
        }
        pub fn compositionLogSplit(_: *const Self) u32 {
            return 1;
        }
        pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
            return self.base.constraintDegreeBound(index);
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
            return self.base.traceLogDegreeBounds(a);
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            return self.base.preprocessedColumnIndices(a);
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
            return self.base.maskPoints(a, point, global_log);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, masks: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
            return self.base.evaluateConstraintQuotientsAtPoint(point, masks, accumulator, global_log);
        }
        pub fn evaluateQuotientsAtPointFor(self: *const Self, comptime F: type, point: geometry.PointFor(F), global_log: u32, masks: anytype, sink: *E.SinkFor(F)) !void {
            return self.base.evaluateQuotientsAtPointFor(F, point, global_log, masks, sink);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const cp.Trace, accumulator: *acc.DomainEvaluationAccumulator) !void {
            return @import("degree3_native.zig").evaluate(&self.base, trace, accumulator, null);
        }
        fn evaluateParallelErased(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *acc.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
            const self: *const Self = @ptrCast(@alignCast(ctx));
            return @import("degree3_native.zig").evaluate(&self.base, trace, accumulator, pool);
        }
    };
}
pub const Component = ComponentFor(E.Q);

pub const testing = if (@import("builtin").is_test) struct {
    pub fn scalarErased(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *acc.DomainEvaluationAccumulator) anyerror!void {
        const self: *const Component = @ptrCast(@alignCast(ctx));
        return @import("degree3_native.zig").testing.scalar(&self.base, trace, accumulator);
    }
} else struct {};

//! Core verifier adaptation of a field-specific prover component.
const std = @import("std");
const core = @import("stwo_core");

pub fn Adapter(comptime Secure: type, comptime ComponentProver: type) type {
    const core_air_components = core.air.components.ForField(Secure);
    const core_air_accumulation = core.air.accumulation.ForField(Secure);
    const CirclePointQM31 = core.circle.CirclePoint(Secure);
    return struct {
        pub const vtable = core_air_components.ComponentVTable{
            .nConstraints = coreAdapterNConstraints,
            .maxConstraintLogDegreeBound = coreAdapterMaxConstraintLogDegreeBound,
            .compositionLogSplit = coreAdapterCompositionLogSplit,
            .traceLogDegreeBounds = coreAdapterTraceLogDegreeBounds,
            .maskPoints = coreAdapterMaskPoints,
            .preprocessedColumnIndices = coreAdapterPreprocessedColumnIndices,
            .evaluateConstraintQuotientsAtPoint = coreAdapterEvaluateConstraintQuotientsAtPoint,
        };

        fn coreAdapterCast(ctx: *const anyopaque) *const ComponentProver {
            return @ptrCast(@alignCast(ctx));
        }

        fn coreAdapterNConstraints(ctx: *const anyopaque) usize {
            return coreAdapterCast(ctx).nConstraints();
        }

        fn coreAdapterMaxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
            return coreAdapterCast(ctx).maxConstraintLogDegreeBound();
        }

        fn coreAdapterCompositionLogSplit(ctx: *const anyopaque) u32 {
            return coreAdapterCast(ctx).compositionLogSplit();
        }

        fn coreAdapterTraceLogDegreeBounds(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
        ) anyerror!core_air_components.TraceLogDegreeBounds {
            return coreAdapterCast(ctx).traceLogDegreeBounds(allocator);
        }

        fn coreAdapterMaskPoints(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            max_log_degree_bound: u32,
        ) anyerror!core_air_components.MaskPoints {
            return coreAdapterCast(ctx).maskPoints(
                allocator,
                point,
                max_log_degree_bound,
            );
        }

        fn coreAdapterPreprocessedColumnIndices(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
        ) anyerror![]usize {
            return coreAdapterCast(ctx).preprocessedColumnIndices(allocator);
        }

        fn coreAdapterEvaluateConstraintQuotientsAtPoint(
            ctx: *const anyopaque,
            point: CirclePointQM31,
            mask: *const core_air_components.MaskValues,
            evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
            max_log_degree_bound: u32,
        ) anyerror!void {
            return coreAdapterCast(ctx).evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                evaluation_accumulator,
                max_log_degree_bound,
            );
        }
    };
}

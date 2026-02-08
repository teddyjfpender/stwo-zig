const std = @import("std");
const accumulation = @import("accumulation.zig");
const components = @import("components.zig");
const circle = @import("../circle.zig");

const CirclePointQM31 = circle.CirclePointQM31;

/// Comptime adapter that derives both verifier and prover AIR component bindings.
///
/// Required methods on `Impl`:
/// - `nConstraints(self: *const Impl) usize`
/// - `maxConstraintLogDegreeBound(self: *const Impl) u32`
/// - `traceLogDegreeBounds(self: *const Impl, allocator: Allocator) !TraceLogDegreeBounds`
/// - `maskPoints(self: *const Impl, allocator: Allocator, point: CirclePointQM31, max_log_degree_bound: u32) !MaskPoints`
/// - `preprocessedColumnIndices(self: *const Impl, allocator: Allocator) ![]usize`
/// - `evaluateConstraintQuotientsAtPoint(...) !void`
/// - `evaluateConstraintQuotientsOnDomain(...) !void`
pub fn ComponentAdapter(
    comptime Impl: type,
    comptime ProverComponentType: type,
    comptime ProverTraceType: type,
    comptime DomainEvaluationAccumulatorType: type,
) type {
    return struct {
        pub fn asVerifierComponent(self: *const Impl) components.Component {
            return .{
                .ctx = self,
                .vtable = &.{
                    .nConstraints = nConstraints,
                    .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                    .traceLogDegreeBounds = traceLogDegreeBounds,
                    .maskPoints = maskPoints,
                    .preprocessedColumnIndices = preprocessedColumnIndices,
                    .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                },
            };
        }

        pub fn asProverComponent(self: *const Impl) ProverComponentType {
            return .{
                .ctx = self,
                .vtable = &.{
                    .nConstraints = nConstraints,
                    .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                    .traceLogDegreeBounds = traceLogDegreeBounds,
                    .maskPoints = maskPoints,
                    .preprocessedColumnIndices = preprocessedColumnIndices,
                    .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                    .evaluateConstraintQuotientsOnDomain = evaluateConstraintQuotientsOnDomain,
                },
            };
        }

        fn cast(ctx: *const anyopaque) *const Impl {
            return @ptrCast(@alignCast(ctx));
        }

        fn nConstraints(ctx: *const anyopaque) usize {
            return cast(ctx).nConstraints();
        }

        fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
            return cast(ctx).maxConstraintLogDegreeBound();
        }

        fn traceLogDegreeBounds(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
        ) anyerror!components.TraceLogDegreeBounds {
            return cast(ctx).traceLogDegreeBounds(allocator);
        }

        fn maskPoints(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            max_log_degree_bound: u32,
        ) anyerror!components.MaskPoints {
            return cast(ctx).maskPoints(allocator, point, max_log_degree_bound);
        }

        fn preprocessedColumnIndices(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
        ) anyerror![]usize {
            return cast(ctx).preprocessedColumnIndices(allocator);
        }

        fn evaluateConstraintQuotientsAtPoint(
            ctx: *const anyopaque,
            point: CirclePointQM31,
            mask: *const components.MaskValues,
            evaluation_accumulator: *accumulation.PointEvaluationAccumulator,
            max_log_degree_bound: u32,
        ) anyerror!void {
            return cast(ctx).evaluateConstraintQuotientsAtPoint(
                point,
                mask,
                evaluation_accumulator,
                max_log_degree_bound,
            );
        }

        fn evaluateConstraintQuotientsOnDomain(
            ctx: *const anyopaque,
            trace: *const ProverTraceType,
            evaluation_accumulator: *DomainEvaluationAccumulatorType,
        ) anyerror!void {
            return cast(ctx).evaluateConstraintQuotientsOnDomain(trace, evaluation_accumulator);
        }
    };
}

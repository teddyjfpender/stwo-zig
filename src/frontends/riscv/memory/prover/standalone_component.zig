//! Research-only degree authority for one standalone base Poseidon provider.
//!
//! The integrated RISC-V proof gets its composition-domain maximum from the
//! wider component set.  A provider-only proof does not, so the adapter raises
//! the local bound by one bit without changing a constraint, trace column, or
//! relation.  Prover and verifier use the same wrapper.

const std = @import("std");
const core_air = @import("stwo_core").air;
const circle = @import("stwo_core").circle;
const prover_air = @import("stwo_prover_engine").air;
const work_pool = @import("stwo_prover_engine").work_pool;

pub const COMPOSITION_BOUND_IS_STANDALONE_ONLY = true;
pub const composition_log_lift: u32 = 1;

pub const Prover = struct {
    inner: prover_air.component_prover.ComponentProver,

    pub fn asComponent(self: *const @This()) prover_air.component_prover.ComponentProver {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = nConstraints,
                .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                .traceLogDegreeBounds = traceLogDegreeBounds,
                .maskPoints = maskPoints,
                .preprocessedColumnIndices = preprocessedColumnIndices,
                .evaluateConstraintQuotientsAtPoint = evaluateAtPoint,
                .evaluateConstraintQuotientsOnDomain = evaluateOnDomain,
            },
            .profile_identity = self.inner.profile_identity,
            .prepare_domain_evaluator = if (self.inner.prepare_domain_evaluator != null)
                prepareDomainEvaluator
            else
                null,
            .domain_parallel_evaluator = if (self.inner.domain_parallel_evaluator != null)
                evaluateOnDomainParallel
            else
                null,
            .pool_exclusive_domain = self.inner.pool_exclusive_domain,
        };
    }

    fn cast(ctx: *const anyopaque) *const @This() {
        return @ptrCast(@alignCast(ctx));
    }

    fn nConstraints(ctx: *const anyopaque) usize {
        return cast(ctx).inner.nConstraints();
    }

    fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
        return cast(ctx).inner.maxConstraintLogDegreeBound() + composition_log_lift;
    }

    fn traceLogDegreeBounds(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!core_air.components.TraceLogDegreeBounds {
        return cast(ctx).inner.traceLogDegreeBounds(allocator);
    }

    fn maskPoints(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        point: circle.CirclePointQM31,
        max_log_degree_bound: u32,
    ) anyerror!core_air.components.MaskPoints {
        return cast(ctx).inner.maskPoints(allocator, point, max_log_degree_bound);
    }

    fn preprocessedColumnIndices(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror![]usize {
        return cast(ctx).inner.preprocessedColumnIndices(allocator);
    }

    fn evaluateAtPoint(
        ctx: *const anyopaque,
        point: circle.CirclePointQM31,
        mask: *const core_air.components.MaskValues,
        accumulator: *core_air.accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) anyerror!void {
        return cast(ctx).inner.evaluateConstraintQuotientsAtPoint(
            point,
            mask,
            accumulator,
            max_log_degree_bound,
        );
    }

    fn evaluateOnDomain(
        ctx: *const anyopaque,
        trace: *const prover_air.component_prover.Trace,
        accumulator: *prover_air.accumulation.DomainEvaluationAccumulator,
    ) anyerror!void {
        return cast(ctx).inner.evaluateConstraintQuotientsOnDomain(trace, accumulator);
    }

    fn prepareDomainEvaluator(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        trace: *const prover_air.component_prover.Trace,
        accumulator: *prover_air.accumulation.DomainEvaluationAccumulator,
    ) anyerror!prover_air.prepared_domain.PreparedDomainEvaluation {
        const inner = cast(ctx).inner;
        const prepare = inner.prepare_domain_evaluator orelse unreachable;
        return prepare(inner.ctx, allocator, trace, accumulator);
    }

    fn evaluateOnDomainParallel(
        ctx: *const anyopaque,
        trace: *const prover_air.component_prover.Trace,
        accumulator: *prover_air.accumulation.DomainEvaluationAccumulator,
        pool: *work_pool.WorkPool,
    ) anyerror!void {
        const inner = cast(ctx).inner;
        const evaluate = inner.domain_parallel_evaluator orelse unreachable;
        return evaluate(inner.ctx, trace, accumulator, pool);
    }
};

pub const Verifier = struct {
    inner: core_air.components.Component,

    pub fn asComponent(self: *const @This()) core_air.components.Component {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = nConstraints,
                .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                .traceLogDegreeBounds = traceLogDegreeBounds,
                .maskPoints = maskPoints,
                .preprocessedColumnIndices = preprocessedColumnIndices,
                .evaluateConstraintQuotientsAtPoint = evaluateAtPoint,
            },
        };
    }

    fn cast(ctx: *const anyopaque) *const @This() {
        return @ptrCast(@alignCast(ctx));
    }

    fn nConstraints(ctx: *const anyopaque) usize {
        return cast(ctx).inner.nConstraints();
    }

    fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
        return cast(ctx).inner.maxConstraintLogDegreeBound() + composition_log_lift;
    }

    fn traceLogDegreeBounds(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!core_air.components.TraceLogDegreeBounds {
        return cast(ctx).inner.traceLogDegreeBounds(allocator);
    }

    fn maskPoints(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        point: circle.CirclePointQM31,
        max_log_degree_bound: u32,
    ) anyerror!core_air.components.MaskPoints {
        return cast(ctx).inner.maskPoints(allocator, point, max_log_degree_bound);
    }

    fn preprocessedColumnIndices(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror![]usize {
        return cast(ctx).inner.preprocessedColumnIndices(allocator);
    }

    fn evaluateAtPoint(
        ctx: *const anyopaque,
        point: circle.CirclePointQM31,
        mask: *const core_air.components.MaskValues,
        accumulator: *core_air.accumulation.PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) anyerror!void {
        return cast(ctx).inner.evaluateConstraintQuotientsAtPoint(
            point,
            mask,
            accumulator,
            max_log_degree_bound,
        );
    }
};

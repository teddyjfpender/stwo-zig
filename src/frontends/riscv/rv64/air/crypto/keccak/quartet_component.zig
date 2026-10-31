//! Experimental quartet-v3 adapter. Production CPU rosters never instantiate it.
//! Shares K sampling, domain ownership and row algebra; no generated machine type.
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const C = @import("component.zig");
const E = @import("equations.zig");
const V = @import("../../evaluation.zig");
const Q = E.Q;
const Point = core.circle.CirclePointQM31;
const air = core.air.components;
const cp = engine.air.component_prover;
const accumulation = engine.air.accumulation;
const std = @import("std");
pub const Component = struct {
    base: C.Component,
    const Adapter = core.air.derive.ComponentAdapter(Component, cp.ComponentProver, cp.Trace, accumulation.DomainEvaluationAccumulator);
    pub fn parameters(self: *const Component) C.Parameters {
        var result = self.base.parameters();
        result.kind = .permutation;
        result.batches = E.BatchPolicy.quartet_v3.batches();
        result.lookup_degree = 5;
        result.emit_q = emitQuartetQ;
        return result;
    }
    pub fn proverParameters(self: *const Component) C.Parameters {
        var result = self.parameters();
        result.emit_packed = emitQuartetPacked;
        return result;
    }
    pub fn validate(self: *const Component) !void {
        if (self.base.kind != .permutation) return error.InvalidKeccakQuartetKind;
        const p = self.parameters();
        return p.validate();
    }
    pub fn asProverComponent(self: *const Component) cp.ComponentProver {
        var result = Adapter.asProverComponent(self);
        result.domain_parallel_evaluator = evaluateParallelErased;
        result.pool_exclusive_domain = true;
        return result;
    }
    pub fn asVerifierComponent(self: *const Component) air.Component {
        return Adapter.asVerifierComponent(self);
    }
    fn evaluateParallelErased(ctx: *const anyopaque, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator, pool: *engine.work_pool.WorkPool) anyerror!void {
        const self: *const Component = @ptrCast(@alignCast(ctx));
        try self.validate();
        const p = self.proverParameters();
        return p.evaluateDomain(trace, accumulator, pool);
    }
    pub fn fixedCount(self: *const Component) usize {
        const p = self.parameters();
        return p.fixedCount();
    }
    pub fn mainCount(self: *const Component) usize {
        const p = self.parameters();
        return p.mainCount();
    }
    pub fn interactionCount(self: *const Component) usize {
        const p = self.parameters();
        return p.interactionCount();
    }
    pub fn nConstraints(self: *const Component) usize {
        const p = self.parameters();
        return p.nConstraints();
    }
    pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
        const p = self.parameters();
        return p.maxConstraintLogDegreeBound();
    }
    pub fn compositionLogSplit(self: *const Component) u32 {
        const p = self.parameters();
        return p.compositionLogSplit();
    }
    pub fn constraintDegreeBound(self: *const Component, index: usize) !u8 {
        try self.validate();
        const p = self.parameters();
        return p.constraintDegreeBound(index);
    }
    pub fn traceLogDegreeBounds(self: *const Component, a: std.mem.Allocator) !air.TraceLogDegreeBounds {
        try self.validate();
        const p = self.parameters();
        return p.traceLogDegreeBounds(a);
    }
    pub fn preprocessedColumnIndices(self: *const Component, a: std.mem.Allocator) ![]usize {
        try self.validate();
        const p = self.parameters();
        return p.preprocessedColumnIndices(a);
    }
    pub fn maskPoints(self: *const Component, a: std.mem.Allocator, point: Point, global_log: u32) !air.MaskPoints {
        try self.validate();
        const p = self.parameters();
        return p.maskPoints(a, point, global_log);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const air.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, global_log: u32) !void {
        try self.validate();
        const p = self.parameters();
        return p.evaluateConstraintQuotientsAtPoint(point, mask, accumulator, global_log);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const cp.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
        try self.validate();
        const p = self.proverParameters();
        return p.evaluateDomain(trace, accumulator, null);
    }
};
fn emitQuartetQ(row: E.Row, interaction: []const Q, prior: Q, claim: Q, ch: E.Challenges, public: E.Public, sink: *V.Sink) void {
    E.emitForBatch(Q, 4, row, interaction, prior, claim, ch, public, sink);
}
fn emitQuartetPacked(row: E.RowFor(V.PackedBase), interaction: []const V.PackedSecure, prior: V.PackedSecure, claim: Q, ch: E.Challenges, public: E.Public, sink: *V.PackedSink) void {
    E.emitForBatch(V.PackedBase, 4, row, interaction, prior, claim, ch, public, sink);
}

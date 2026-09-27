//! Four-tree projection adapter. The established projection equations still
//! read fixed/main and their own interaction cells; tree two is reserved for
//! the source-sealed ordinary access witness. No opening mask is discarded.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Projection = @import("block_v5_native_projection_fused_component_v1.zig").Component;
const Access = @import("block_execution_sidecar_stark_v2.zig").Component;
const ComponentProver = engine.air.component_prover.ComponentProver;
const Trace = engine.air.component_prover.Trace;
const DomainAccumulator = engine.air.accumulation.DomainEvaluationAccumulator;
const Point = core.circle.CirclePointQM31;

pub const ProjectionComponent = struct {
    inner: Projection,
    has_access_witness: bool = true,
    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, ComponentProver, Trace, DomainAccumulator);
    pub fn init(self: Self) !Self {
        _ = try self.inner.init();
        return self;
    }
    pub fn asProverComponent(self: *const Self) ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) core.air.components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(self: *const Self) usize {
        return self.inner.nConstraints();
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.inner.maxConstraintLogDegreeBound();
    }
    pub fn compositionLogSplit(self: *const Self) u32 {
        return self.inner.compositionLogSplit();
    }
    pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
        return self.inner.constraintDegreeBound(index);
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        return self.inner.preprocessedColumnIndices(a);
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        if (!self.has_access_witness) return self.inner.traceLogDegreeBounds(a);
        var original = try self.inner.traceLogDegreeBounds(a);
        errdefer original.deinitDeep(a);
        const empty = try a.alloc(u32, 0);
        errdefer a.free(empty);
        const result = try a.dupe([]u32, &.{ original.items[0], original.items[1], empty, original.items[2] });
        a.free(original.items);
        return .initOwned(result);
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !core.air.components.MaskPoints {
        if (!self.has_access_witness) return self.inner.maskPoints(a, point, max_log);
        var original = try self.inner.maskPoints(a, point, max_log);
        errdefer original.deinitDeep(a);
        const empty = try a.alloc([]Point, 0);
        errdefer a.free(empty);
        const result = try a.dupe([][]Point, &.{ original.items[0], original.items[1], empty, original.items[2] });
        a.free(original.items);
        return .initOwned(result);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const core.air.components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (!self.has_access_witness) {
            if (mask.items.len != 3) return error.InvalidV5FullFusedTrees;
            return self.inner.evaluateConstraintQuotientsAtPoint(point, mask, accumulator, max_log);
        }
        if (mask.items.len != 4) return error.InvalidV5FullFusedTrees;
        var trees: [3][][]core.fields.qm31.QM31 = .{ mask.items[0], mask.items[1], mask.items[3] };
        const view = core.air.components.MaskValues{ .items = &trees };
        try self.inner.evaluateConstraintQuotientsAtPoint(point, &view, accumulator, max_log);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const Trace, accumulator: *DomainAccumulator) !void {
        if (!self.has_access_witness) {
            if (trace.polys.items.len != 3) return error.InvalidV5FullFusedTrees;
            return self.inner.evaluateConstraintQuotientsOnDomain(trace, accumulator);
        }
        if (trace.polys.items.len != 4) return error.InvalidV5FullFusedTrees;
        var trees: [3][]const engine.air.component_prover.Poly = .{ trace.polys.items[0], trace.polys.items[1], trace.polys.items[3] };
        const view = Trace{ .polys = core.pcs.TreeVec([]const engine.air.component_prover.Poly).initOwned(&trees) };
        try self.inner.evaluateConstraintQuotientsOnDomain(&view, accumulator);
    }
};

/// Sharing a composition polynomial does not require increasing an access
/// component's own evaluation degree. Its established log+2 quotient is added
/// to the same accumulator, then split with the other projection polynomials.
pub const AccessComponent = struct {
    inner: Access,
    composition_split: u32,
    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, ComponentProver, Trace, DomainAccumulator);
    pub fn init(self: Self) !Self {
        _ = try self.inner.init();
        if (self.composition_split < self.inner.compositionLogSplit() or
            self.composition_split > core.verifier_types.MAX_COMPOSITION_LOG_SPLIT or
            self.inner.external_source != null or self.inner.v5_packed == null or self.inner.v5_universal == null)
            return error.InvalidV5FullFusedAccessComponent;
        return self;
    }
    pub fn asProverComponent(self: *const Self) ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) core.air.components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(self: *const Self) usize {
        return self.inner.nConstraints();
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        return self.inner.maxConstraintLogDegreeBound();
    }
    pub fn compositionLogSplit(self: *const Self) u32 {
        return self.composition_split;
    }
    pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
        return self.inner.constraintDegreeBound(index);
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        return self.inner.traceLogDegreeBounds(a);
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !core.air.components.MaskPoints {
        return self.inner.maskPoints(a, point, max_log);
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        return self.inner.preprocessedColumnIndices(a);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const core.air.components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (mask.items.len != 4) return error.InvalidV5FullFusedTrees;
        try self.inner.evaluateConstraintQuotientsAtPoint(point, mask, accumulator, max_log);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const Trace, accumulator: *DomainAccumulator) !void {
        if (trace.polys.items.len != 4) return error.InvalidV5FullFusedTrees;
        try self.inner.evaluateConstraintQuotientsOnDomain(trace, accumulator);
    }
};

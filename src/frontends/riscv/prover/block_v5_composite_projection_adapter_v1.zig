//! Share existing AIR equations in a four-tree composite proof. No source
//! equation, sample or degree bound is replaced by a host-side shortcut.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Point = core.circle.CirclePointQM31;
const PC = engine.air.component_prover;
const Domain = engine.air.accumulation.DomainEvaluationAccumulator;

pub fn Projection(comptime Inner: type) type {
    return struct {
        inner: Inner,
        composition_split: u32,
        const Self = @This();
        const Adapter = core.air.derive.ComponentAdapter(Self, PC.ComponentProver, PC.Trace, Domain);
        pub fn init(self: Self) !Self {
            _ = try self.inner.init();
            if (self.composition_split < self.inner.compositionLogSplit() or self.composition_split > core.verifier_types.MAX_COMPOSITION_LOG_SPLIT)
                return error.InvalidV5CompositeComposition;
            return self;
        }
        pub fn asProverComponent(self: *const Self) PC.ComponentProver {
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
        pub fn constraintDegreeBound(self: *const Self, i: usize) !u8 {
            return self.inner.constraintDegreeBound(i);
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            return self.inner.preprocessedColumnIndices(a);
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
            var old = try self.inner.traceLogDegreeBounds(a);
            errdefer old.deinitDeep(a);
            const empty = try a.alloc(u32, 0);
            errdefer a.free(empty);
            const items = try a.dupe([]u32, &.{ old.items[0], old.items[1], empty, old.items[2] });
            a.free(old.items);
            return .initOwned(items);
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !core.air.components.MaskPoints {
            var old = try self.inner.maskPoints(a, point, max_log);
            errdefer old.deinitDeep(a);
            const empty = try a.alloc([]Point, 0);
            errdefer a.free(empty);
            const items = try a.dupe([][]Point, &.{ old.items[0], old.items[1], empty, old.items[2] });
            a.free(old.items);
            return .initOwned(items);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const core.air.components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
            if (mask.items.len != 4) return error.InvalidV5CompositeTrees;
            var items: [3][][]core.fields.qm31.QM31 = .{ mask.items[0], mask.items[1], mask.items[3] };
            const view = core.air.components.MaskValues{ .items = &items };
            try self.inner.evaluateConstraintQuotientsAtPoint(point, &view, accumulator, max_log);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const PC.Trace, accumulator: *Domain) !void {
            if (trace.polys.items.len != 4) return error.InvalidV5CompositeTrees;
            var items: [3][]const PC.Poly = .{ trace.polys.items[0], trace.polys.items[1], trace.polys.items[3] };
            const view = PC.Trace{ .polys = core.pcs.TreeVec([]const PC.Poly).initOwned(&items) };
            try self.inner.evaluateConstraintQuotientsOnDomain(&view, accumulator);
        }
    };
}

/// Existing access AIR already consumes four trace trees. Only its advertised
/// composition split is shared; its established quotient domain is unchanged.
pub fn Access(comptime Inner: type) type {
    return struct {
        inner: Inner,
        composition_split: u32,
        const Self = @This();
        const Adapter = core.air.derive.ComponentAdapter(Self, PC.ComponentProver, PC.Trace, Domain);
        pub fn init(self: Self) !Self {
            _ = try self.inner.init();
            if (self.composition_split < self.inner.compositionLogSplit() or self.composition_split > core.verifier_types.MAX_COMPOSITION_LOG_SPLIT or self.inner.v5_packed == null or self.inner.v5_universal == null)
                return error.InvalidV5CompositeComposition;
            return self;
        }
        pub fn asProverComponent(self: *const Self) PC.ComponentProver {
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
        pub fn constraintDegreeBound(self: *const Self, i: usize) !u8 {
            return self.inner.constraintDegreeBound(i);
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            return self.inner.preprocessedColumnIndices(a);
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
            return self.inner.traceLogDegreeBounds(a);
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !core.air.components.MaskPoints {
            return self.inner.maskPoints(a, point, max_log);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const core.air.components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
            if (mask.items.len != 4) return error.InvalidV5CompositeTrees;
            try self.inner.evaluateConstraintQuotientsAtPoint(point, mask, accumulator, max_log);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const PC.Trace, accumulator: *Domain) !void {
            if (trace.polys.items.len != 4) return error.InvalidV5CompositeTrees;
            try self.inner.evaluateConstraintQuotientsOnDomain(trace, accumulator);
        }
    };
}

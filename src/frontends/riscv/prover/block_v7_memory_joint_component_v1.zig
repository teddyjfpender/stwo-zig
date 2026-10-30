//! Checked column placement around the original three-tree word component.
//! Core concatenates ordinary tree inventories; fixed indices are explicit.
//! Quotient equations, masks, degree and evaluation domains remain original.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Prover = engine.air.component_prover;
const Domain = engine.air.accumulation.DomainEvaluationAccumulator;
const C = core.air.components;
const Point = core.circle.CirclePointQM31;
const Layout = @import("block_v7_memory_joint_layout_v1.zig");
pub fn For(comptime Spec: type) type {
    return ForPlacement(Spec, Layout.Part);
}
pub fn ForPlacement(comptime Spec: type, comptime Part: type) type {
    const Inner = @import("block_v5_word_quotient_adapter_v1.zig").For(Spec);
    const widths = [3]usize{ Spec.FIXED_COUNT, Spec.MAIN_COUNT, Spec.INTERACTION_COUNT };
    return struct {
        const Self = @This();
        inner: Inner,
        offsets: [3]u32,
        const Adapter = core.air.derive.ComponentAdapter(Self, Prover.ComponentProver, Prover.Trace, Domain);
        pub fn init(spec: Spec, part: Part) !Self {
            for (widths, part.width) |expected, got| if (expected != got) return error.InvalidV7JointPlacement;
            if (part.log == 0 or part.log > 24 or part.claim_count != (Spec.INTERACTION_COUNT / 4)) return error.InvalidV7JointPlacement;
            return .{ .inner = .{ .spec = spec, .log_size = part.log }, .offsets = part.offset };
        }
        pub fn asProverComponent(self: *const Self) Prover.ComponentProver {
            var out = Adapter.asProverComponent(self);
            out.domain_parallel_evaluator = evaluateParallel;
            out.pool_exclusive_domain = true;
            return out;
        }
        pub fn asVerifierComponent(self: *const Self) C.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(self: *const Self) usize {
            return self.inner.nConstraints();
        }
        pub fn compositionLogSplit(self: *const Self) u32 {
            return self.inner.compositionLogSplit();
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.inner.maxConstraintLogDegreeBound();
        }
        pub fn constraintDegreeBound(self: *const Self, index: usize) !u8 {
            return self.inner.constraintDegreeBound(index);
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !C.TraceLogDegreeBounds {
            return self.inner.traceLogDegreeBounds(a);
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !C.MaskPoints {
            return self.inner.maskPoints(a, point, max_log);
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const out = try a.alloc(usize, Spec.FIXED_COUNT);
            for (out, 0..) |*index, i| index.* = self.offsets[0] + i;
            return out;
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const C.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
            if (mask.items.len != 3 and mask.items.len != 4) return error.InvalidV7JointTrees;
            var local: [3][][]core.fields.qm31.QM31 = undefined;
            for (&local, self.offsets, widths, mask.items[0..3]) |*tree, offset, width, values| {
                if (offset > values.len or width > values.len - offset) return error.InvalidV7JointPlacement;
                tree.* = values[offset..][0..width];
            }
            const view = C.MaskValues.initOwned(&local);
            try self.inner.evaluateConstraintQuotientsAtPoint(point, &view, accumulator, max_log);
        }
        fn localTrace(self: *const Self, trace: *const Prover.Trace, out: *[3][]const Prover.Poly) !Prover.Trace {
            if (trace.polys.items.len != 3) return error.InvalidV7JointTrees;
            for (out, self.offsets, widths, trace.polys.items) |*tree, offset, width, values| {
                if (offset > values.len or width > values.len - offset) return error.InvalidV7JointPlacement;
                tree.* = values[offset..][0..width];
            }
            var local = trace.*;
            local.polys = .{ .items = out };
            return local;
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const Prover.Trace, accumulator: *Domain) !void {
            var trees: [3][]const Prover.Poly = undefined;
            const local = try self.localTrace(trace, &trees);
            try self.inner.evaluateConstraintQuotientsOnDomain(&local, accumulator);
        }
        fn evaluateParallel(raw: *const anyopaque, trace: *const Prover.Trace, accumulator: *Domain, pool: *engine.work_pool.WorkPool) !void {
            const self: *const Self = @ptrCast(@alignCast(raw));
            var trees: [3][]const Prover.Poly = undefined;
            const local = try self.localTrace(trace, &trees);
            try self.inner.asProverComponent().evaluateConstraintQuotientsOnDomainParallel(&local, accumulator, pool);
        }
    };
}

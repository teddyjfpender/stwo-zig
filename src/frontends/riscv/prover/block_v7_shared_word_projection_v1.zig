//! A relation projection that reuses already-declared fixed/main columns.
//! Its caller must prove the complete original component over those columns.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
pub fn For(comptime Spec: type) type {
    return Shared(Spec, false);
}
/// The fixed selector is newly declared, while main columns still belong to
/// the complete original component. Its independently admitted fixed offset
/// must match the appended selector inventory.
pub fn ForOwnedFixed(comptime Spec: type) type {
    return Shared(Spec, true);
}
fn Shared(comptime Spec: type, comptime owns_fixed: bool) type {
    const Part = struct { log: u32, offset: [3]u32, width: [3]usize, claim_count: usize };
    const Mapped = @import("block_v7_memory_joint_component_v1.zig").ForPlacement(Spec, Part);
    return struct {
        const Self = @This();
        inner: Mapped,
        const Adapter = core.air.derive.ComponentAdapter(Self, engine.air.component_prover.ComponentProver, engine.air.component_prover.Trace, engine.air.accumulation.DomainEvaluationAccumulator);
        pub fn init(spec: Spec, log: u32, offsets: [3]u32) !Self {
            return .{ .inner = try Mapped.init(spec, .{ .log = log, .offset = offsets, .width = .{ Spec.FIXED_COUNT, Spec.MAIN_COUNT, Spec.INTERACTION_COUNT }, .claim_count = Spec.INTERACTION_COUNT / 4 }) };
        }
        pub fn asProverComponent(self: *const Self) engine.air.component_prover.ComponentProver {
            return Adapter.asProverComponent(self);
        }
        pub fn asVerifierComponent(self: *const Self) core.air.components.Component {
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
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            return self.inner.preprocessedColumnIndices(a);
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
            var bounds = try self.inner.traceLogDegreeBounds(a);
            errdefer bounds.deinitDeep(a);
            for (bounds.items[if (owns_fixed) 1 else 0..2]) |*tree| {
                const empty = try a.alloc(u32, 0);
                a.free(tree.*);
                tree.* = empty;
            }
            return bounds;
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: core.circle.CirclePointQM31, max_log: u32) !core.air.components.MaskPoints {
            var masks = try self.inner.maskPoints(a, point, max_log);
            errdefer masks.deinitDeep(a);
            for (masks.items[if (owns_fixed) 1 else 0..2]) |*tree| {
                const empty = try a.alloc([]core.circle.CirclePointQM31, 0);
                for (tree.*) |column| a.free(column);
                a.free(tree.*);
                tree.* = empty;
            }
            return masks;
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: core.circle.CirclePointQM31, mask: *const core.air.components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
            return self.inner.evaluateConstraintQuotientsAtPoint(point, mask, accumulator, max_log);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const engine.air.component_prover.Trace, accumulator: *engine.air.accumulation.DomainEvaluationAccumulator) !void {
            return self.inner.evaluateConstraintQuotientsOnDomain(trace, accumulator);
        }
    };
}

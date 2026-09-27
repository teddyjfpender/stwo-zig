//! Equation-free tree/column placement for genuine shared PAGE components.
//! Every local mask is retained exactly; no copied private value is introduced.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Components = core.air.components;
const Point = core.circle.CirclePointQM31;
const Trace = engine.air.component_prover.Trace;
const Domain = engine.air.accumulation.DomainEvaluationAccumulator;
/// offset/count select the full global view passed to inner equations. Mask
/// inventories themselves are component-local and concatenate exactly once.
pub const Binding = struct { tree: usize, offset: usize = 0, count: usize };
pub fn For(comptime Inner: type, comptime tree_count: usize, comptime local_count: usize) type {
    return struct {
        const Self = @This();
        inner: Inner,
        bindings: [local_count]Binding,
        const Adapter = core.air.derive.ComponentAdapter(Self, engine.air.component_prover.ComponentProver, Trace, Domain);
        pub fn init(inner: Inner, bindings: [local_count]Binding) !Self {
            for (bindings, 0..) |binding, i| {
                if (binding.tree >= tree_count or binding.count > std.math.maxInt(usize) - binding.offset) return error.InvalidSourcePageComponentPlacement;
                for (bindings[0..i]) |previous| if (previous.tree == binding.tree) return error.InvalidSourcePageComponentPlacement;
            }
            return .{ .inner = inner, .bindings = bindings };
        }
        pub fn asProverComponent(self: *const Self) engine.air.component_prover.ComponentProver {
            return Adapter.asProverComponent(self);
        }
        pub fn asVerifierComponent(self: *const Self) Components.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(self: *const Self) usize {
            return self.inner.nConstraints();
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.inner.maxConstraintLogDegreeBound();
        }
        pub fn compositionLogSplit(self: *const Self) u32 {
            return if (@hasDecl(Inner, "compositionLogSplit")) self.inner.compositionLogSplit() else 1;
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            const local = try self.inner.preprocessedColumnIndices(a);
            defer a.free(local);
            // Original preprocessed columns become explicit ordinary columns
            // when remapped away from tree0. Only the actual global tree0
            // owner participates in the core's preprocessed inventory.
            for (self.bindings) |binding| if (binding.tree == 0) {
                if (binding.offset != 0) return error.InvalidSourcePagePreprocessedAlias;
                const indices = try a.alloc(usize, binding.count);
                for (indices, 0..) |*index, i| index.* = i;
                return indices;
            };
            return a.alloc(usize, 0);
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !Components.TraceLogDegreeBounds {
            var original = try self.inner.traceLogDegreeBounds(a);
            defer original.deinitDeep(a);
            if (original.items.len != local_count) return error.InvalidSourcePageComponentPlacement;
            const trees = try a.alloc([]u32, tree_count);
            for (trees) |*tree| tree.* = &.{};
            errdefer {
                for (trees) |tree| a.free(tree);
                a.free(trees);
            }
            for (original.items, self.bindings) |logs, binding| {
                if (logs.len > binding.count) return error.InvalidSourcePageComponentPlacement;
                const result = try a.dupe(u32, logs);
                trees[binding.tree] = result;
            }
            return .initOwned(trees);
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !Components.MaskPoints {
            var original = try self.inner.maskPoints(a, point, max_log);
            errdefer original.deinitDeep(a);
            if (original.items.len != local_count) return error.InvalidSourcePageComponentPlacement;
            const trees = try a.alloc([][]Point, tree_count);
            for (trees) |*tree| tree.* = &.{};
            // Before ownership moves, only the new outer headers are owned here.
            errdefer {
                for (trees) |tree| a.free(tree);
                a.free(trees);
            }
            for (original.items, self.bindings) |columns, binding| {
                if (columns.len > binding.count) return error.InvalidSourcePageComponentPlacement;
                const result = try a.dupe([]Point, columns);
                trees[binding.tree] = result;
            }
            for (original.items) |columns| a.free(columns);
            a.free(original.items);
            return .initOwned(trees);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, mask: *const Components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
            if (mask.items.len != tree_count) return error.InvalidSourcePageComponentMasks;
            var views: [local_count][][]core.fields.qm31.QM31 = undefined;
            for (&views, self.bindings) |*view, binding| {
                const columns = mask.items[binding.tree];
                if (binding.offset > columns.len or binding.count > columns.len - binding.offset) return error.InvalidSourcePageComponentMasks;
                view.* = columns[binding.offset..][0..binding.count];
            }
            const local = Components.MaskValues{ .items = &views };
            try self.inner.evaluateConstraintQuotientsAtPoint(point, &local, accumulator, max_log);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const Trace, accumulator: *Domain) !void {
            if (trace.polys.items.len != tree_count) return error.InvalidSourcePageComponentTrees;
            var views: [local_count][]const engine.air.component_prover.Poly = undefined;
            for (&views, self.bindings) |*view, binding| {
                const columns = trace.polys.items[binding.tree];
                if (binding.offset > columns.len or binding.count > columns.len - binding.offset) return error.InvalidSourcePageComponentTrees;
                view.* = columns[binding.offset..][0..binding.count];
            }
            var local = trace.*;
            local.polys = .{ .items = &views };
            try self.inner.evaluateConstraintQuotientsOnDomain(&local, accumulator);
        }
    };
}

//! Finite compile-time heterogeneous placement. Original equations and
//! quotient domains remain authoritative. No producer-chosen tree mapping.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CP = engine.air.component_prover;
const C = core.air.components;
const DA = engine.air.accumulation.DomainEvaluationAccumulator;
const Point = core.circle.CirclePointQM31;
pub fn For(comptime maps: anytype, comptime trace_trees: usize, comptime proving: bool) type {
    const H = if (proving) CP.ComponentProver else C.Component;
    const Inner = Dynamic(proving);
    return struct {
        inner: Inner,
        handles: []H,
        pub fn init(a: std.mem.Allocator, partitions: [maps.len][]const H, fixed_counts: [maps.len]usize) !@This() {
            var parts: [maps.len]Inner.Part = undefined;
            inline for (maps, 0..) |map, i| parts[i] = .{ .map = &map, .handles = partitions[i], .fixed_count = fixed_counts[i] };
            const inner = try Inner.init(a, &parts, trace_trees);
            return .{ .inner = inner, .handles = inner.handles };
        }
        pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
            self.inner.deinit(a);
            self.* = undefined;
        }
    };
}
/// Runtime placement is accepted only as independently derived finite metadata.
/// This adapter authenticates no shape; original verifiers and the source scope
/// remain authoritative. Both static and dynamic routes use these exact bodies.
pub fn Dynamic(comptime proving: bool) type {
    const H = if (proving) CP.ComponentProver else C.Component;
    return struct {
        pub const Part = struct { map: []const usize, handles: []const H, fixed_count: usize };
        wrappers: []Placed,
        handles: []H,
        const Self = @This();
        pub fn init(a: std.mem.Allocator, parts: []const Part, trace_trees: usize) !Self {
            if (trace_trees == 0 or trace_trees > 256 or parts.len == 0 or parts.len > 256) return error.InvalidUnionTreeMap;
            var split: u32 = 0;
            var count: usize = 0;
            var seen: [256]bool = @splat(false);
            for (parts) |part| {
                if (part.map.len < 2 or part.map.len > 5 or part.map[0] != 0 or part.fixed_count == 0 or part.handles.len == 0) return error.InvalidUnionRoster;
                for (part.map[1..]) |tree| {
                    if (tree == 0 or tree >= trace_trees or seen[tree]) return error.InvalidUnionTreeMap;
                    seen[tree] = true;
                }
                count = try std.math.add(usize, count, part.handles.len);
                if (count > 1 << 16) return error.InvalidUnionRoster;
                for (part.handles) |h| split = @max(split, h.compositionLogSplit());
            }
            for (seen[1..trace_trees]) |used| if (!used) return error.InvalidUnionTreeMap;
            const wrappers = try a.alloc(Placed, count);
            errdefer a.free(wrappers);
            const handles = try a.alloc(H, count);
            errdefer a.free(handles);
            var at: usize = 0;
            var fixed_start: usize = 0;
            for (parts) |part| {
                for (part.handles) |original_handle| {
                    var original = original_handle;
                    if (original.compositionLogSplit() != split) {
                        // Preserve an existing source lift and the effective
                        // quotient-domain width. The CPU evaluator supports
                        // genuine polynomial extension through q1 -> q3;
                        // replacing a prior override would silently drop it.
                        const prior: u32 = if (original.composition_geometry_override_v1) |g| g.max_constraint_log_degree_bound_delta else 0;
                        const delta = try std.math.add(u32, prior, split - original.compositionLogSplit());
                        if (delta > 2) return error.UnsupportedUnionDegreeLift;
                        original = try original.withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = @intCast(delta), .composition_log_split = @intCast(split) });
                    }
                    const w = &wrappers[at];
                    w.* = .{ .inner = original, .trace_trees = trace_trees, .map = @splat(0), .source_trees = part.map.len, .fixed_start = fixed_start, .fixed_count = part.fixed_count };
                    @memcpy(w.map[0..part.map.len], part.map);
                    handles[at] = if (proving) w.asProverComponent() else w.asVerifierComponent();
                    at += 1;
                }
                fixed_start = try std.math.add(usize, fixed_start, part.fixed_count);
            }
            return .{ .wrappers = wrappers, .handles = handles };
        }
        pub fn deinit(self: *Self, a: std.mem.Allocator) void {
            a.free(self.handles);
            a.free(self.wrappers);
            self.* = undefined;
        }
        const Placed = struct {
            inner: H,
            trace_trees: usize,
            map: [5]usize,
            source_trees: usize,
            fixed_start: usize,
            fixed_count: usize,
            const Adapter = core.air.derive.ComponentAdapter(@This(), CP.ComponentProver, CP.Trace, DA);
            fn mapping(self: *const @This()) []const usize {
                return self.map[0..self.source_trees];
            }
            pub fn asProverComponent(self: *const @This()) CP.ComponentProver {
                var out = Adapter.asProverComponent(self);
                out.pool_exclusive_domain = self.inner.pool_exclusive_domain;
                if (self.inner.domain_parallel_evaluator != null) out.domain_parallel_evaluator = parallel;
                return out;
            }
            pub fn asVerifierComponent(self: *const @This()) C.Component {
                return Adapter.asVerifierComponent(self);
            }
            pub fn nConstraints(self: *const @This()) usize {
                return self.inner.nConstraints();
            }
            pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
                return self.inner.maxConstraintLogDegreeBound();
            }
            pub fn compositionLogSplit(self: *const @This()) u32 {
                return self.inner.compositionLogSplit();
            }
            pub fn preprocessedColumnIndices(self: *const @This(), a: std.mem.Allocator) ![]usize {
                const indices = try self.inner.preprocessedColumnIndices(a);
                errdefer a.free(indices);
                for (indices) |*index| {
                    if (index.* >= self.fixed_count) return error.InvalidUnionFixedIndex;
                    index.* = try std.math.add(usize, index.*, self.fixed_start);
                }
                return indices;
            }
            fn relocate(self: *const @This(), comptime T: type, a: std.mem.Allocator, original: core.pcs.TreeVec([]T)) !core.pcs.TreeVec([]T) {
                var owned = original;
                errdefer owned.deinitDeep(a);
                const map = self.mapping();
                if (original.items.len != map.len) return error.InvalidUnionSourceTrees;
                const result = try a.alloc([]T, self.trace_trees);
                @memset(result, &.{});
                for (map, original.items) |to, cols| result[to] = cols;
                a.free(original.items);
                return .initOwned(result);
            }
            pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !C.TraceLogDegreeBounds {
                return self.relocate(u32, a, try self.inner.traceLogDegreeBounds(a));
            }
            pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, p: Point, log: u32) !C.MaskPoints {
                return self.relocate([]Point, a, try self.inner.maskPoints(a, p, log));
            }
            pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), p: Point, masks: *const C.MaskValues, acc: *core.air.accumulation.PointEvaluationAccumulator, log: u32) !void {
                if (masks.items.len != self.trace_trees and masks.items.len != self.trace_trees + 1) return error.InvalidUnionTrees;
                var local: [5][][]core.fields.qm31.QM31 = undefined;
                const map = self.mapping();
                for (map, 0..) |to, i| local[i] = masks.items[to];
                if (self.fixed_start > local[0].len or self.fixed_count > local[0].len - self.fixed_start) return error.InvalidUnionFixedIndex;
                local[0] = local[0][self.fixed_start..][0..self.fixed_count];
                const mask_view = C.MaskValues.initOwned(local[0..map.len]);
                try self.inner.evaluateConstraintQuotientsAtPoint(p, &mask_view, acc, log);
            }
            fn view(self: *const @This(), trace: *const CP.Trace, local: *[5][]const CP.Poly) !CP.Trace {
                if (trace.polys.items.len != self.trace_trees) return error.InvalidUnionTrees;
                const map = self.mapping();
                for (map, 0..) |to, i| local[i] = trace.polys.items[to];
                if (self.fixed_start > local[0].len or self.fixed_count > local[0].len - self.fixed_start) return error.InvalidUnionFixedIndex;
                local[0] = local[0][self.fixed_start..][0..self.fixed_count];
                var out = trace.*;
                out.polys = .initOwned(local[0..map.len]);
                return out;
            }
            pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const CP.Trace, acc: *DA) !void {
                var local: [5][]const CP.Poly = undefined;
                const mapped = try self.view(trace, &local);
                try self.inner.evaluateConstraintQuotientsOnDomain(&mapped, acc);
            }
            fn parallel(raw: *const anyopaque, trace: *const CP.Trace, acc: *DA, pool: *engine.work_pool.WorkPool) !void {
                const self: *const @This() = @ptrCast(@alignCast(raw));
                var local: [5][]const CP.Poly = undefined;
                const mapped = try self.view(trace, &local);
                try self.inner.evaluateConstraintQuotientsOnDomainParallel(&mapped, acc, pool);
            }
        };
    };
}

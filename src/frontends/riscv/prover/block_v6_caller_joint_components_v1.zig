//! Exact arithmetic + relation AIR union. Five trace trees, one composition.
//! The two original equation rosters remain authoritative. Shared openings are
//! a point-wise union, never a prefix assumption or an alias of claimed sums.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const C = core.air.components;
const CP = engine.air.component_prover;
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const DA = engine.air.accumulation.DomainEvaluationAccumulator;

pub fn Owner(comptime proving: bool) type {
    return struct {
        allocator: std.mem.Allocator,
        arithmetic: []Handle,
        relations: []Handle,
        arithmetic_verifiers: []C.Component,
        relation_verifiers: []C.Component,
        relation_masks: []C.Component,
        logs: C.TraceLogDegreeBounds,
        preprocessed: []usize,
        split: u32,
        bound: u32,
        constraints: usize,
        const Self = @This();
        const Handle = if (proving) CP.ComponentProver else C.Component;
        const Adapter = core.air.derive.ComponentAdapter(Self, CP.ComponentProver, CP.Trace, DA);

        pub fn create(a: std.mem.Allocator, arithmetic: []const Handle, relations: []const Handle, geometry: [5][]const u32, relation_memory_prefix: usize) !*Self {
            const fixed_count = geometry[0].len;
            if (arithmetic.len == 0 or relations.len == 0) return error.EmptyJointCaller;
            var split: u32 = 0;
            for (arithmetic) |h| split = @max(split, h.compositionLogSplit());
            for (relations) |h| split = @max(split, h.compositionLogSplit());
            const left = try adjusted(a, arithmetic, split);
            errdefer a.free(left);
            const right = try adjusted(a, relations, split);
            errdefer a.free(right);
            const lv = try verifiers(a, left);
            errdefer a.free(lv);
            const rv = try verifiers(a, right);
            errdefer a.free(rv);
            try validateOriginalGeometry(a, lv, &.{ geometry[0], geometry[1], geometry[3] });
            if (relation_memory_prefix > rv.len) return error.InvalidJointCallerRoster;
            const rm = try a.alloc(C.Component, rv.len);
            errdefer a.free(rm);
            // Constraints keep original memory/program/table order. The
            // physical private tree is program/state/table/memory ordered;
            // every original component appears exactly once in this rotation.
            for (rm, 0..) |*h, i| h.* = rv[(i + relation_memory_prefix) % rv.len];
            try validateOriginalGeometry(a, rm, &.{ geometry[0], geometry[1], geometry[2], geometry[4] });
            const items = try a.alloc([]u32, 5);
            @memset(items, &.{});
            var logs = C.TraceLogDegreeBounds.initOwned(items);
            errdefer logs.deinitDeep(a);
            for (geometry, items) |source, *dest| dest.* = try a.dupe(u32, source);
            const selected = try a.alloc(bool, fixed_count);
            defer a.free(selected);
            @memset(selected, false);
            for ([_][]const C.Component{ lv, rv }) |partition| for (partition) |h| {
                const indices = try h.preprocessedColumnIndices(a);
                defer a.free(indices);
                for (indices) |i| {
                    if (i >= fixed_count) return error.InvalidJointCallerFixedIndex;
                    selected[i] = true;
                }
            };
            var indices: std.ArrayList(usize) = .empty;
            defer indices.deinit(a);
            for (selected, 0..) |yes, i| if (yes) {
                try indices.append(a, i);
            };
            const preprocessed = try indices.toOwnedSlice(a);
            errdefer a.free(preprocessed);
            var bound: u32 = 0;
            var constraints: usize = 0;
            for (lv) |h| {
                bound = @max(bound, h.maxConstraintLogDegreeBound());
                constraints = try std.math.add(usize, constraints, h.nConstraints());
            }
            for (rv) |h| {
                bound = @max(bound, h.maxConstraintLogDegreeBound());
                constraints = try std.math.add(usize, constraints, h.nConstraints());
            }
            const self = try a.create(Self);
            self.* = .{ .allocator = a, .arithmetic = left, .relations = right, .arithmetic_verifiers = lv, .relation_verifiers = rv, .relation_masks = rm, .logs = logs, .preprocessed = preprocessed, .split = split, .bound = bound, .constraints = constraints };
            return self;
        }
        fn validateOriginalGeometry(a: std.mem.Allocator, handles: []const C.Component, expected: []const []const u32) !void {
            var offsets: [4]usize = @splat(0);
            for (handles) |h| {
                var logs = try h.traceLogDegreeBounds(a);
                defer logs.deinitDeep(a);
                if (logs.items.len != expected.len) return error.InvalidJointCallerTrees;
                const indices = try h.preprocessedColumnIndices(a);
                defer a.free(indices);
                if (logs.items[0].len == expected[0].len) {
                    if (!std.mem.eql(u32, logs.items[0], expected[0])) return error.UnsharedJointCallerGeometry;
                } else if (logs.items[0].len != 0) {
                    if (logs.items[0].len != indices.len) {
                        return error.UnsharedJointCallerGeometry;
                    }
                    for (indices, logs.items[0]) |i, log| if (i >= expected[0].len or expected[0][i] != log) return error.UnsharedJointCallerGeometry;
                }
                for (1..expected.len) |t| {
                    if (logs.items[t].len > expected[t].len - offsets[t] or !std.mem.eql(u32, logs.items[t], expected[t][offsets[t]..][0..logs.items[t].len])) {
                        return error.UnsharedJointCallerGeometry;
                    }
                    offsets[t] += logs.items[t].len;
                }
            }
            for (1..expected.len) |t| if (offsets[t] != expected[t].len) {
                return error.UnsharedJointCallerGeometry;
            };
        }
        fn adjusted(a: std.mem.Allocator, original: []const Handle, split: u32) ![]Handle {
            const out = try a.dupe(Handle, original);
            errdefer a.free(out);
            for (out) |*h| if (h.compositionLogSplit() != split) {
                if (split - h.compositionLogSplit() != 1 or h.composition_geometry_override_v1 != null) return error.UnsupportedJointCallerLift;
                h.* = try h.withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = @intCast(split) });
            };
            return out;
        }
        fn verifiers(a: std.mem.Allocator, source: []const Handle) ![]C.Component {
            const out = try a.alloc(C.Component, source.len);
            for (source, out) |*h, *dest| dest.* = if (proving) core.air.derive.ComponentAdapter(CP.ComponentProver, CP.ComponentProver, CP.Trace, DA).asVerifierComponent(h) else h.*;
            return out;
        }
        pub fn destroy(self: *Self) void {
            const a = self.allocator;
            self.logs.deinitDeep(a);
            a.free(self.preprocessed);
            a.free(self.relation_masks);
            a.free(self.relation_verifiers);
            a.free(self.arithmetic_verifiers);
            a.free(self.relations);
            a.free(self.arithmetic);
            a.destroy(self);
        }
        pub fn asProverComponent(self: *const Self) CP.ComponentProver {
            var out = Adapter.asProverComponent(self);
            if (proving) {
                for (self.arithmetic) |h| if (h.domain_parallel_evaluator != null) {
                    out.domain_parallel_evaluator = parallel;
                    out.pool_exclusive_domain = true;
                };
                for (self.relations) |h| if (h.domain_parallel_evaluator != null) {
                    out.domain_parallel_evaluator = parallel;
                    out.pool_exclusive_domain = true;
                };
            }
            return out;
        }
        pub fn asVerifierComponent(self: *const Self) C.Component {
            return Adapter.asVerifierComponent(self);
        }
        pub fn nConstraints(self: *const Self) usize {
            return self.constraints;
        }
        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.bound;
        }
        pub fn compositionLogSplit(self: *const Self) u32 {
            return self.split;
        }
        pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
            return a.dupe(usize, self.preprocessed);
        }
        pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !C.TraceLogDegreeBounds {
            const items = try a.alloc([]u32, 5);
            @memset(items, &.{});
            var out = C.TraceLogDegreeBounds.initOwned(items);
            errdefer out.deinitDeep(a);
            items[0] = try a.alloc(u32, self.preprocessed.len);
            for (items[0], self.preprocessed) |*log, i| log.* = self.logs.items[0][i];
            for (items[1..], self.logs.items[1..]) |*dest, source| dest.* = try a.dupe(u32, source);
            return out;
        }
        fn originalMasks(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32, arithmetic: bool) !C.MaskPoints {
            return (C.Components{ .components = if (arithmetic) self.arithmetic_verifiers else self.relation_masks, .n_preprocessed_columns = self.logs.items[0].len }).maskPoints(a, point, max_log, false);
        }
        pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !C.MaskPoints {
            var left = try self.originalMasks(a, point, max_log, true);
            defer left.deinitDeep(a);
            var right = try self.originalMasks(a, point, max_log, false);
            defer right.deinitDeep(a);
            const trees = try a.alloc([][]Point, 5);
            @memset(trees, &.{});
            var out = C.MaskPoints.initOwned(trees);
            errdefer out.deinitDeep(a);
            for (trees, self.logs.items, 0..) |*tree, logs, t| {
                tree.* = try a.alloc([]Point, logs.len);
                @memset(tree.*, &.{});
                for (tree.*, 0..) |*column, c| {
                    const l: []const Point = if (t < 2) left.items[t][c] else if (t == 3) left.items[2][c] else &.{};
                    const r: []const Point = if (t < 2) right.items[t][c] else if (t == 2) right.items[2][c] else if (t == 4) right.items[3][c] else &.{};
                    var union_points: std.ArrayList(Point) = .empty;
                    defer union_points.deinit(a);
                    for (l) |p| try appendUnique(a, &union_points, p);
                    for (r) |p| try appendUnique(a, &union_points, p);
                    column.* = try union_points.toOwnedSlice(a);
                }
            }
            return out;
        }
        fn appendUnique(a: std.mem.Allocator, out: *std.ArrayList(Point), point: Point) !void {
            for (out.items) |p| if (std.meta.eql(p, point)) return;
            try out.append(a, point);
        }
        pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, values: *const C.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
            if (values.items.len != 5 and values.items.len != 6) return error.InvalidJointCallerTrees;
            const a = self.allocator;
            var joint = try self.maskPoints(a, point, max_log);
            defer joint.deinitDeep(a);
            for (joint.items, values.items[0..5]) |expected, actual| {
                if (expected.len != actual.len) return error.InvalidJointCallerMasks;
                for (expected, actual) |e, v| if (e.len != v.len) return error.InvalidJointCallerMasks;
            }
            inline for (.{ true, false }) |arithmetic| {
                var original = try self.originalMasks(a, point, max_log, arithmetic);
                defer original.deinitDeep(a);
                const map: []const usize = if (arithmetic) &.{ 0, 1, 3 } else &.{ 0, 1, 2, 4 };
                const trees = try a.alloc([][]Q, map.len);
                @memset(trees, &.{});
                var mapped = C.MaskValues.initOwned(trees);
                defer mapped.deinitDeep(a);
                for (map, trees, original.items) |t, *tree, points| {
                    tree.* = try a.alloc([]Q, points.len);
                    @memset(tree.*, &.{});
                    for (tree.*, points, 0..) |*column, old, c| {
                        column.* = try a.alloc(Q, old.len);
                        for (old, column.*) |p, *value| {
                            var found = false;
                            for (joint.items[t][c], values.items[t][c]) |candidate, sampled| if (std.meta.eql(p, candidate)) {
                                value.* = sampled;
                                found = true;
                                break;
                            };
                            if (!found) return error.MissingJointCallerOpening;
                        }
                    }
                }
                for (if (arithmetic) self.arithmetic_verifiers else self.relation_verifiers) |h| try h.evaluateConstraintQuotientsAtPoint(point, &mapped, accumulator, max_log);
            }
        }
        fn parallel(raw: *const anyopaque, trace: *const CP.Trace, accumulator: *DA, pool: *engine.work_pool.WorkPool) anyerror!void {
            const self: *const Self = @ptrCast(@alignCast(raw));
            try self.evaluateWithPool(trace, accumulator, pool);
        }
        pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const CP.Trace, accumulator: *DA) !void {
            try self.evaluateWithPool(trace, accumulator, null);
        }
        fn evaluateWithPool(self: *const Self, trace: *const CP.Trace, accumulator: *DA, pool: ?*engine.work_pool.WorkPool) !void {
            if (trace.polys.items.len != 5) return error.InvalidJointCallerTrees;
            inline for (.{ true, false }) |arithmetic| {
                const map: []const usize = if (arithmetic) &.{ 0, 1, 3 } else &.{ 0, 1, 2, 4 };
                var trees: [4][]const CP.Poly = undefined;
                for (map, 0..) |t, i| trees[i] = trace.polys.items[t];
                var view = trace.*;
                view.polys = .initOwned(trees[0..map.len]);
                for (if (arithmetic) self.arithmetic else self.relations) |h| {
                    if (pool) |shared| try h.evaluateConstraintQuotientsOnDomainParallel(&view, accumulator, shared) else try h.evaluateConstraintQuotientsOnDomain(&view, accumulator);
                }
            }
        }
    };
}

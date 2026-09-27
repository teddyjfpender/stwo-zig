//! One PAGE component with exact aliases of the original committed cells.
//! The generic core concatenates ordinary tree inventories across components;
//! therefore original-source suppliers and hash requesters cannot be exported
//! as separate components when they share a main tree. This owner unions their
//! opening masks once, then reconstructs each original local mask exactly.
//! No equation, denominator, evaluation domain or private value is rewritten.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const Components = core.air.components;
const Prover = engine.air.component_prover;
pub const TREE_COUNT: usize = 9;
pub const Limits = struct {
    max_children: usize = 32,
    max_columns: usize = 1 << 16,
    max_points_per_column: usize = 32,
    max_mask_points: usize = 1 << 22,
};
/// Original local trees are passed their complete view, including columns
/// before a typed manifest's offset. Its reported mask/log inventory contains
/// only used_count columns beginning at used_first in that local view.
pub const Placement = struct {
    tree: usize,
    offset: usize = 0,
    view_count: usize,
    used_first: usize = 0,
    used_count: usize,
};
pub const Child = struct {
    prover: Prover.ComponentProver,
    verifier: Components.Component,
    placements: []const Placement,
    pub fn maskPoints(self: Child, a: std.mem.Allocator, point: Point, max_log: u32) !Components.MaskPoints {
        return self.verifier.maskPoints(a, point, max_log);
    }
    /// Both handles must name the same original owner and equations. The PAGE
    /// lifecycle keeps that owner alive until this composition is destroyed.
    pub fn from(inner: anytype, placements: []const Placement) Child {
        return .{ .prover = inner.asProverComponent(), .verifier = inner.asVerifierComponent(), .placements = placements };
    }
};
pub const Owner = struct {
    a: std.mem.Allocator,
    children: []Child,
    logs: [TREE_COUNT][]u32,
    split: u32,
    limits: Limits,
    const Self = @This();
    const Adapter = core.air.derive.ComponentAdapter(Self, Prover.ComponentProver, Prover.Trace, engine.air.accumulation.DomainEvaluationAccumulator);
    pub fn init(a: std.mem.Allocator, children: []const Child, logs: [TREE_COUNT][]const u32, split: u32, limits: Limits) !*Self {
        if (children.len == 0 or children.len > limits.max_children or limits.max_children > 32 or
            limits.max_columns == 0 or limits.max_points_per_column == 0 or limits.max_points_per_column > 32 or
            limits.max_mask_points == 0 or split == 0 or split > core.verifier_types.MAX_COMPOSITION_LOG_SPLIT)
            return error.InvalidSourcePageComposition;
        var column_count: usize = 0;
        for (logs) |tree| {
            column_count = try std.math.add(usize, column_count, tree.len);
            for (tree) |log| if (log == 0 or log >= core.circle.M31_CIRCLE_LOG_ORDER) return error.InvalidSourcePageComposition;
        }
        if (logs[0].len == 0 or column_count > limits.max_columns) return error.SourcePageCompositionResourceLimit;
        const self = try a.create(Self);
        errdefer a.destroy(self);
        const owned_children = try a.alloc(Child, children.len);
        var child_count: usize = 0;
        errdefer {
            for (owned_children[0..child_count]) |child| a.free(child.placements);
            a.free(owned_children);
        }
        var owned_logs: [TREE_COUNT][]u32 = undefined;
        var log_count: usize = 0;
        errdefer for (owned_logs[0..log_count]) |tree| a.free(tree);
        for (logs, &owned_logs) |tree, *owned| {
            owned.* = try a.dupe(u32, tree);
            log_count += 1;
        }
        for (children, owned_children) |child, *owned| {
            if (child.placements.len == 0 or child.placements.len > TREE_COUNT or
                child.verifier.compositionLogSplit() > split or child.verifier.compositionLogSplit() == 0 or
                child.verifier.nConstraints() != child.prover.nConstraints() or
                child.verifier.compositionLogSplit() != child.prover.compositionLogSplit() or
                child.verifier.maxConstraintLogDegreeBound() != child.prover.maxConstraintLogDegreeBound())
                return error.InvalidSourcePageComposition;
            var local_logs = try child.verifier.traceLogDegreeBounds(a);
            defer local_logs.deinitDeep(a);
            if (local_logs.items.len != child.placements.len) return error.InvalidSourcePageComposition;
            for (child.placements, local_logs.items) |placement, sizes| {
                if (placement.tree >= TREE_COUNT or placement.used_first > placement.view_count or
                    placement.used_count > placement.view_count - placement.used_first or sizes.len != placement.used_count or
                    placement.offset > logs[placement.tree].len or placement.view_count > logs[placement.tree].len - placement.offset)
                    return error.InvalidSourcePageComposition;
                for (sizes, 0..) |size, i| if (size != logs[placement.tree][placement.offset + placement.used_first + i])
                    return error.InvalidSourcePageComposition;
            }
            owned.* = child;
            owned.placements = try a.dupe(Placement, child.placements);
            child_count += 1;
            const geometry = Components.CompositionGeometryOverrideV1{
                .max_constraint_log_degree_bound_delta = @intCast(split - child.verifier.compositionLogSplit() + if (child.verifier.composition_geometry_override_v1) |prior| @as(u32, prior.max_constraint_log_degree_bound_delta) else 0),
                .composition_log_split = @intCast(split),
            };
            if (child.verifier.composition_geometry_override_v1 != null and child.prover.composition_geometry_override_v1 == null or
                child.verifier.composition_geometry_override_v1 == null and child.prover.composition_geometry_override_v1 != null)
                return error.InvalidSourcePageComposition;
            if (child.verifier.composition_geometry_override_v1) |prior| if (!std.meta.eql(prior, child.prover.composition_geometry_override_v1.?)) return error.InvalidSourcePageComposition;
            // The original producer implements q1 -> q2 polynomial extension
            // in this checked override API. Reporting a wider bound without
            // invoking that transform would change the quotient polynomial.
            owned.prover = try child.prover.withCompositionGeometryOverrideV1(geometry);
            owned.verifier = try child.verifier.withCompositionGeometryOverrideV1(geometry);
        }
        self.* = .{ .a = a, .children = owned_children, .logs = owned_logs, .split = split, .limits = limits };
        return self;
    }
    pub fn deinit(self: *Self) void {
        for (self.children) |child| self.a.free(child.placements);
        self.a.free(self.children);
        for (self.logs) |tree| self.a.free(tree);
        self.a.destroy(self);
    }
    pub fn asProverComponent(self: *const Self) Prover.ComponentProver {
        return Adapter.asProverComponent(self);
    }
    pub fn asVerifierComponent(self: *const Self) Components.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn nConstraints(self: *const Self) usize {
        var count: usize = 0;
        for (self.children) |child| count += child.verifier.nConstraints();
        return count;
    }
    pub fn compositionLogSplit(self: *const Self) u32 {
        return self.split;
    }
    pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
        var bound: u32 = 0;
        for (self.children) |child| bound = @max(bound, child.verifier.maxConstraintLogDegreeBound());
        return bound;
    }
    pub fn preprocessedColumnIndices(self: *const Self, a: std.mem.Allocator) ![]usize {
        const out = try a.alloc(usize, self.logs[0].len);
        for (out, 0..) |*value, i| value.* = i;
        return out;
    }
    pub fn traceLogDegreeBounds(self: *const Self, a: std.mem.Allocator) !Components.TraceLogDegreeBounds {
        const out = try a.alloc([]u32, TREE_COUNT);
        var initialized: usize = 0;
        errdefer {
            for (out[0..initialized]) |tree| a.free(tree);
            a.free(out);
        }
        for (out, self.logs) |*value, tree| {
            value.* = try a.dupe(u32, tree);
            initialized += 1;
        }
        return .initOwned(out);
    }
    fn equalPoint(left: Point, right: Point) bool {
        return left.x.eql(right.x) and left.y.eql(right.y);
    }
    pub fn maskPoints(self: *const Self, a: std.mem.Allocator, point: Point, max_log: u32) !Components.MaskPoints {
        var logs: [TREE_COUNT][]const u32 = undefined;
        for (&logs, self.logs) |*view, columns| view.* = columns;
        return unionMaskPoints(a, logs, self.children, self.limits, point, max_log);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const Self, point: Point, values: *const Components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (values.items.len != TREE_COUNT) return error.InvalidSourcePageComposition;
        var union_masks = try self.maskPoints(self.a, point, max_log);
        defer union_masks.deinitDeep(self.a);
        for (values.items, union_masks.items) |columns, requests| {
            if (columns.len != requests.len) return error.InvalidSourcePageComposition;
            for (columns, requests) |samples, points| if (samples.len != points.len) return error.InvalidSourcePageComposition;
        }
        for (self.children) |child| {
            var requested = try child.verifier.maskPoints(self.a, point, max_log);
            defer requested.deinitDeep(self.a);
            const trees = try self.a.alloc([][]Q, child.placements.len);
            for (trees) |*tree| tree.* = &.{};
            var local = Components.MaskValues.initOwned(trees);
            defer local.deinitDeep(self.a);
            for (trees, child.placements, requested.items) |*tree, placement, columns| {
                tree.* = try self.a.alloc([]Q, placement.view_count);
                for (tree.*) |*column| column.* = &.{};
                for (columns, 0..) |points, i| {
                    const global_index = placement.offset + placement.used_first + i;
                    const samples = try self.a.alloc(Q, points.len);
                    tree.*[placement.used_first + i] = samples;
                    for (points, samples) |original, *sample| {
                        var found: ?usize = null;
                        for (union_masks.items[placement.tree][global_index], 0..) |candidate, ordinal| if (equalPoint(candidate, original)) {
                            found = ordinal;
                            break;
                        };
                        sample.* = values.items[placement.tree][global_index][found orelse return error.InvalidSourcePageComposition];
                    }
                }
            }
            try child.verifier.evaluateConstraintQuotientsAtPoint(point, &local, accumulator, max_log);
        }
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const Self, trace: *const Prover.Trace, accumulator: *engine.air.accumulation.DomainEvaluationAccumulator) !void {
        if (trace.polys.items.len != TREE_COUNT) return error.InvalidSourcePageComposition;
        for (trace.polys.items, self.logs) |tree, sizes| if (tree.len != sizes.len) return error.InvalidSourcePageComposition;
        for (self.children) |child| {
            var views: [TREE_COUNT][]const Prover.Poly = undefined;
            for (views[0..child.placements.len], child.placements) |*view, placement| view.* = trace.polys.items[placement.tree][placement.offset..][0..placement.view_count];
            var local = trace.*;
            local.polys = .{ .items = views[0..child.placements.len] };
            try child.prover.evaluateConstraintQuotientsOnDomain(&local, accumulator);
        }
    }
};

/// Original mask union over independently selected metadata children. The
/// callback supplies exact masks only; no verifier/claims/capture is required.
pub fn unionMaskPoints(a: std.mem.Allocator, logs: [TREE_COUNT][]const u32, children: anytype, limits: Limits, point: Point, max_log: u32) !Components.MaskPoints {
    if (children.len == 0 or children.len > limits.max_children or limits.max_children > 32 or limits.max_points_per_column == 0 or limits.max_points_per_column > 32 or limits.max_mask_points == 0) return error.InvalidSourcePageComposition;
    var column_count: usize = 0;
    for (logs) |tree| column_count = try std.math.add(usize, column_count, tree.len);
    if (column_count > limits.max_columns) return error.SourcePageCompositionResourceLimit;
    const trees = try a.alloc([][]Point, TREE_COUNT);
    for (trees) |*tree| tree.* = &.{};
    var result = Components.MaskPoints.initOwned(trees);
    errdefer result.deinitDeep(a);
    for (trees, logs) |*tree, sizes| {
        tree.* = try a.alloc([]Point, sizes.len);
        for (tree.*) |*column| column.* = &.{};
    }
    var total: usize = 0;
    for (trees[0]) |*column| {
        column.* = try a.dupe(Point, &.{point});
        total += 1;
    }
    if (total > limits.max_mask_points) return error.SourcePageCompositionResourceLimit;
    for (children) |child| {
        var masks = try child.maskPoints(a, point, max_log);
        defer masks.deinitDeep(a);
        if (masks.items.len != child.placements.len) return error.InvalidSourcePageComposition;
        for (masks.items, child.placements) |columns, placement| {
            if (placement.tree >= TREE_COUNT or placement.offset > logs[placement.tree].len or placement.view_count > logs[placement.tree].len - placement.offset or placement.used_first > placement.view_count or placement.used_count > placement.view_count - placement.used_first or columns.len != placement.used_count) return error.InvalidSourcePageComposition;
            for (columns, 0..) |points, i| {
                const target = &trees[placement.tree][placement.offset + placement.used_first + i];
                for (points) |requested| {
                    var present = false;
                    for (target.*) |existing| if (existing.eql(requested)) {
                        present = true;
                        break;
                    };
                    if (present) continue;
                    if (target.len >= limits.max_points_per_column or total == limits.max_mask_points)
                        return error.SourcePageCompositionResourceLimit;
                    const replacement = try a.alloc(Point, target.len + 1);
                    @memcpy(replacement[0..target.len], target.*);
                    replacement[target.len] = requested;
                    a.free(target.*);
                    target.* = replacement;
                    total += 1;
                }
            }
        }
    }
    // The core independently opens tree0 at the OODS point. No child may
    // require an alternative tree0 point that the generic core would drop.
    for (trees[0]) |points| if (points.len != 1 or !points[0].eql(point)) return error.InvalidSourcePagePreprocessedMask;
    return result;
}

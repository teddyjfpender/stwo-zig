//! Close execution companions first, then each original field-safe table
//! group. Exact physical roster and carried tails; no artificial provider span.
const std = @import("std");
const Coverage = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
const Full = @import("block_v5_heterogeneous_policy_v1.zig").Policy;
const Scoped = @import("block_v5_heterogeneous_scoped_plan_v1.zig");
const Span = @import("block_v5_pc_clock_span_v1.zig");
pub const Ref = Coverage.Ref;
pub const Node = struct { children: [4]Ref, child_count: u32, descendants: []const u32, span: ?Span.Span };
pub const Limits = struct { max_nodes: usize = 32768, max_descendant_ids: usize = 1 << 20, max_owned_bytes: usize = 64 << 20 };
pub const Plan = struct {
    recipe: Scoped.Recipe = .complete,
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    arena: std.heap.ArenaAllocator,
    full: Full,
    nodes: []const Node,
    root: Ref,
    limits: Limits,
    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn descendants(self: *const Plan, ref: Ref, leaf_storage: *[1]u32) ![]const u32 {
        return switch (ref) {
            .leaf => |ordinal| block: {
                if (ordinal >= self.full.children.len or !Scoped.includes(self.recipe, self.full.children[ordinal].physical)) return error.InvalidScopedCohort;
                leaf_storage[0] = ordinal;
                break :block leaf_storage;
            },
            .node => |index| block: {
                if (index >= self.nodes.len) return error.InvalidScopedCohort;
                break :block self.nodes[index].descendants;
            },
        };
    }
    pub fn validate(self: *const Plan) !void {
        try self.full.validate();
        if (self.nodes.len > self.limits.max_nodes) return error.ScopedCohortResourceLimit;
        var total: usize = 0;
        for (self.nodes, 0..) |node, index| {
            if (node.child_count < 2 or node.child_count > 4) return error.InvalidScopedCohort;
            total = try std.math.add(usize, total, node.descendants.len);
            if (total > self.limits.max_descendant_ids) return error.ScopedCohortResourceLimit;
            var count: usize = 0;
            var derived_span: ?Span.Span = null;
            for (node.children[0..node.child_count]) |ref| {
                if (ref == .node and ref.node >= index) return error.InvalidScopedCohort;
                var leaf: [1]u32 = undefined;
                const ids = try self.descendants(ref, &leaf);
                count = try std.math.add(usize, count, ids.len);
                for (ids) |ordinal| if (std.sort.binarySearch(u32, node.descendants, ordinal, struct {
                    fn order(key: u32, item: u32) std.math.Order {
                        return std.math.order(key, item);
                    }
                }.order) == null) return error.InvalidScopedCohort;
                const child_span = switch (ref) {
                    .leaf => |ordinal| self.full.children[ordinal].span,
                    .node => |ordinal| self.nodes[ordinal].span,
                };
                if (child_span) |part| derived_span = if (derived_span) |previous| try Span.merge(&.{ previous, part }) else part;
            }
            if (count != node.descendants.len or !std.meta.eql(derived_span, node.span)) return error.InvalidScopedCohort;
            for (node.descendants, 0..) |ordinal, at| if (ordinal >= self.full.children.len or at > 0 and node.descendants[at - 1] >= ordinal) return error.InvalidScopedCohort;
        }
        var leaf: [1]u32 = undefined;
        const root = try self.descendants(self.root, &leaf);
        var selected: usize = 0;
        for (self.full.children, 0..) |child, ordinal| if (Scoped.includes(self.recipe, child.physical)) {
            if (selected >= root.len or root[selected] != ordinal) return error.IncompleteScopedCohort;
            selected += 1;
        };
        if (root.len != selected) return error.IncompleteScopedCohort;
    }
};
const Builder = struct {
    a: std.mem.Allocator,
    full: Full,
    nodes: std.ArrayList(Node) = .empty,
    ids: usize = 0,
    limits: Limits,
    fn span(self: *const Builder, ref: Ref) !?Span.Span {
        return switch (ref) {
            .leaf => |ordinal| self.full.children[ordinal].span,
            .node => |index| self.nodes.items[index].span,
        };
    }
    fn node(self: *Builder, children: []const Ref) !Ref {
        if (children.len == 1) return children[0];
        if (children.len < 2 or children.len > 4 or self.nodes.items.len >= self.limits.max_nodes) return error.ScopedCohortResourceLimit;
        var count: usize = 0;
        var native: ?Span.Span = null;
        for (children) |ref| {
            count = try std.math.add(usize, count, switch (ref) {
                .leaf => 1,
                .node => |index| self.nodes.items[index].descendants.len,
            });
            if (try self.span(ref)) |part| native = if (native) |previous| try Span.merge(&.{ previous, part }) else part;
        }
        self.ids = try std.math.add(usize, self.ids, count);
        if (self.ids > self.limits.max_descendant_ids) return error.ScopedCohortResourceLimit;
        const descendants = try self.a.alloc(u32, count);
        var at: usize = 0;
        for (children) |ref| switch (ref) {
            .leaf => |ordinal| {
                descendants[at] = ordinal;
                at += 1;
            },
            .node => |index| {
                const values = self.nodes.items[index].descendants;
                @memcpy(descendants[at..][0..values.len], values);
                at += values.len;
            },
        };
        std.mem.sort(u32, descendants, {}, std.sort.asc(u32));
        for (descendants, 0..) |ordinal, index| if (ordinal >= self.full.children.len or index > 0 and descendants[index - 1] == ordinal) return error.InvalidScopedCohort;
        var result = Node{ .children = undefined, .child_count = @intCast(children.len), .descendants = descendants, .span = native };
        @memcpy(result.children[0..children.len], children);
        try self.nodes.append(self.a, result);
        return .{ .node = @intCast(self.nodes.items.len - 1) };
    }
    fn fold(self: *Builder, refs: []const Ref) !Ref {
        if (refs.len == 0) return error.InvalidScopedCohort;
        var current = try self.a.dupe(Ref, refs);
        while (current.len > 1) {
            var next: std.ArrayList(Ref) = .empty;
            var at: usize = 0;
            while (at < current.len) {
                const count = @min(@as(usize, 4), current.len - at);
                try next.append(self.a, try self.node(current[at..][0..count]));
                at += count;
            }
            current = try next.toOwnedSlice(self.a);
        }
        return current[0];
    }
};
pub fn init(backing: std.mem.Allocator, scoped: *const @import("block_v5_heterogeneous_scoped_plan_v1.zig").Plan, limits: Limits) !Plan {
    try scoped.validate();
    const full = scoped.full;
    const semantic = &scoped.semantic;
    if (limits.max_owned_bytes == 0) return error.ScopedCohortResourceLimit;
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(backing, limits.max_owned_bytes);
    errdefer budget.destroy();
    var arena = std.heap.ArenaAllocator.init(budget.allocator());
    errdefer arena.deinit();
    const a = arena.allocator();
    const used = try a.alloc(bool, full.children.len);
    @memset(used, false);
    const executions = try a.alloc(Ref, semantic.execution_count);
    var builder = Builder{ .a = a, .full = full, .limits = limits };
    const companions = try a.alloc([4]Ref, executions.len);
    const counts = try a.alloc(u32, executions.len);
    @memset(counts, 0);
    for (full.children, 0..) |child, ordinal| switch (child.physical.kind) {
        .native_arithmetic, .native_fused, .caller_arithmetic, .caller_fused => {
            const execution = child.physical.index;
            if (execution >= executions.len or counts[execution] == 4 or used[ordinal]) return error.InvalidScopedCohort;
            companions[execution][counts[execution]] = .{ .leaf = @intCast(ordinal) };
            counts[execution] += 1;
            used[ordinal] = true;
        },
        else => {},
    };
    for (executions, 0..) |*cohort, execution| cohort.* = try builder.node(companions[execution][0..counts[execution]]);
    var roots: std.ArrayList(Ref) = .empty;
    var next_execution: usize = 0;
    for (semantic.groups) |group| {
        var refs: std.ArrayList(Ref) = .empty;
        if (group.first_execution != next_execution) return error.InvalidScopedCohort;
        for (0..group.execution_count) |_| {
            if (next_execution >= executions.len) return error.InvalidScopedCohort;
            try refs.append(a, executions[next_execution]);
            next_execution += 1;
        }
        // Deduplicate repeated six-kind claims of this real provider. It can
        // belong to exactly one group; reusing it in another group rejects.
        var suppliers = std.AutoHashMap(u32, void).init(a);
        for (semantic.exports) |entry| if (entry.role == .table_provider and entry.owner == group.index) {
            const ordinal = entry.field.child;
            if (ordinal >= full.children.len or full.children[ordinal].physical.kind != .native_lookup) return error.InvalidScopedCohort;
            _ = try suppliers.getOrPut(ordinal);
        };
        // Stable physical order, without rescanning the entire roster per group.
        const ordinals = try a.alloc(u32, suppliers.count());
        var iterator = suppliers.keyIterator();
        var at: usize = 0;
        while (iterator.next()) |ordinal| {
            ordinals[at] = ordinal.*;
            at += 1;
        }
        std.mem.sort(u32, ordinals, {}, std.sort.asc(u32));
        for (ordinals) |ordinal| {
            if (used[ordinal]) return error.InvalidScopedCohort;
            used[ordinal] = true;
            try refs.append(a, .{ .leaf = ordinal });
        }
        try roots.append(a, try builder.fold(refs.items));
    }
    if (next_execution != executions.len) return error.InvalidScopedCohort;
    for (full.children, 0..) |child, ordinal| if (!used[ordinal] and Scoped.includes(scoped.recipe, child.physical)) {
        switch (child.physical.kind) {
            .native_arithmetic, .native_fused, .caller_arithmetic, .caller_fused, .native_lookup => return error.IncompleteScopedCohort,
            else => {},
        }
        used[ordinal] = true;
        try roots.append(a, .{ .leaf = @intCast(ordinal) });
    };
    const root = try builder.fold(roots.items);
    const result = Plan{ .recipe = scoped.recipe, .budget = budget, .arena = arena, .full = full, .nodes = try builder.nodes.toOwnedSlice(a), .root = root, .limits = limits };
    try result.validate();
    return result;
}

/// Pure exact-fold metadata fixture. This shares the production Builder, but
/// does not validate Full and must never be passed as proof/source admission.
pub const testing = struct {
    pub fn foldMetadata(backing: std.mem.Allocator, full: Full, limits: Limits) !Plan {
        return foldMetadataForRecipe(.complete, backing, full, limits);
    }
    pub fn foldMetadataForRecipe(comptime recipe: Scoped.Recipe, backing: std.mem.Allocator, full: Full, limits: Limits) !Plan {
        if (limits.max_owned_bytes == 0) return error.ScopedCohortResourceLimit;
        const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(backing, limits.max_owned_bytes);
        errdefer budget.destroy();
        var arena = std.heap.ArenaAllocator.init(budget.allocator());
        errdefer arena.deinit();
        const a = arena.allocator();
        var selected: std.ArrayList(Ref) = .empty;
        for (full.children, 0..) |child, index| if (Scoped.includes(recipe, child.physical)) {
            try selected.append(a, .{ .leaf = @intCast(index) });
        };
        const refs = try selected.toOwnedSlice(a);
        var builder = Builder{ .a = a, .full = full, .limits = limits };
        const root = try builder.fold(refs);
        return .{ .recipe = recipe, .budget = budget, .arena = arena, .full = full, .nodes = try builder.nodes.toOwnedSlice(a), .root = root, .limits = limits };
    }
};

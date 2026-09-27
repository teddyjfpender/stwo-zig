//! Exact original contribution routing. Completed scopes close at their real
//! lowest common parent; unresolved keyed slots are propagated without frames.
const std = @import("std");
const core = @import("stwo_core");
const Scoped = @import("block_v5_heterogeneous_scoped_plan_v1.zig");
const Cohorts = @import("block_v5_heterogeneous_scoped_cohorts_v1.zig");
pub const Node = struct { inputs: []const u32, exports: []const u32, closed: []const u32 };
pub const Limits = struct { max_slot_ids: usize = 1 << 22, max_owned_bytes: usize = 128 << 20 };
pub const Plan = struct {
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    arena: std.heap.ArenaAllocator,
    scoped: *const Scoped.Plan,
    cohorts: *const Cohorts.Plan,
    leaves: []const []const u32,
    nodes: []const Node,
    digest: [32]u8,
    limits: Limits,
    pub fn deinit(self: *Plan) void {
        self.arena.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn identity(self: *const Plan) [32]u8 {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42355a52, 1 }); // B5ZR
        channel.mixRoot(self.scoped.digest);
        channel.mixU64(self.leaves.len);
        for (self.leaves) |ids| {
            channel.mixU64(ids.len);
            channel.mixU32s(ids);
        }
        channel.mixU64(self.nodes.len);
        for (self.nodes, self.cohorts.nodes) |node, cohort| {
            channel.mixU32s(&.{cohort.child_count});
            for (cohort.children[0..cohort.child_count]) |ref| channel.mixU32s(&.{ @intFromEnum(std.meta.activeTag(ref)), switch (ref) {
                .leaf, .node => |i| i,
            } });
            inline for (.{ node.inputs, node.exports, node.closed }) |ids| {
                channel.mixU64(ids.len);
                channel.mixU32s(ids);
            }
        }
        return channel.digestBytes();
    }
    pub fn validate(self: *const Plan) !void {
        try self.scoped.validate();
        try self.cohorts.validate();
        if (self.scoped.recipe != self.cohorts.recipe or self.leaves.len != self.scoped.full.children.len or self.nodes.len != self.cohorts.nodes.len or !std.meta.eql(self.digest, self.identity())) return error.UntrustedScopedRoute;
        var expected = try initAdmitted(self.arena.child_allocator, self.scoped, self.cohorts, self.limits);
        defer expected.deinit();
        if (!std.meta.eql(expected.digest, self.digest)) return error.UntrustedScopedRoute;
        for (self.nodes) |node| inline for (.{ node.inputs, node.exports, node.closed }) |ids| for (ids, 0..) |id, index| if (id >= self.scoped.requirements.len or index > 0 and ids[index - 1] >= id) return error.InvalidScopedRoute;
    }
};
fn ancestor(parent: []const ?u32, lower: u32, upper: u32) bool {
    var cursor: ?u32 = lower;
    while (cursor) |index| {
        if (index == upper) return true;
        cursor = parent[index];
    }
    return false;
}
fn lca(parent: []const ?u32, left: u32, right: u32) !u32 {
    var cursor: ?u32 = left;
    while (cursor) |index| {
        if (ancestor(parent, right, index)) return index;
        cursor = parent[index];
    }
    return error.IncompleteScopedRoute;
}
pub fn init(backing: std.mem.Allocator, scoped: *const Scoped.Plan, cohorts: *const Cohorts.Plan, limits: Limits) !Plan {
    try scoped.validate();
    try cohorts.validate();
    if (scoped.recipe != cohorts.recipe or !std.meta.eql(scoped.full.plan.pinned_digest, cohorts.full.plan.pinned_digest)) return error.UntrustedScopedRoute;
    return initAdmitted(backing, scoped, cohorts, limits);
}
fn initAdmitted(backing: std.mem.Allocator, scoped: *const Scoped.Plan, cohorts: *const Cohorts.Plan, limits: Limits) !Plan {
    if (limits.max_owned_bytes == 0) return error.UntrustedScopedRoute;
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(backing, limits.max_owned_bytes);
    errdefer budget.destroy();
    var arena = std.heap.ArenaAllocator.init(budget.allocator());
    errdefer arena.deinit();
    const a = arena.allocator();
    const leaf_parent = try a.alloc(?u32, scoped.full.children.len);
    @memset(leaf_parent, null);
    const node_parent = try a.alloc(?u32, cohorts.nodes.len);
    @memset(node_parent, null);
    for (cohorts.nodes, 0..) |node, index| {
        if (node.child_count < 2 or node.child_count > 4) return error.InvalidScopedRoute;
        for (node.children[0..node.child_count]) |ref| switch (ref) {
            .leaf => |ordinal| {
                if (ordinal >= leaf_parent.len or leaf_parent[ordinal] != null) return error.InvalidScopedRoute;
                leaf_parent[ordinal] = @intCast(index);
            },
            .node => |ordinal| {
                if (ordinal >= index or node_parent[ordinal] != null) return error.InvalidScopedRoute;
                node_parent[ordinal] = @intCast(index);
            },
        };
    }
    if (cohorts.root == .node) {
        const root = cohorts.root.node;
        if (root >= cohorts.nodes.len) return error.InvalidScopedRoute;
        for (leaf_parent, scoped.full.children) |parent, child| {
            if ((parent != null) != Scoped.includes(scoped.recipe, child.physical)) return error.IncompleteScopedRoute;
        }
        for (node_parent, 0..) |parent, index| if ((parent == null) != (index == root)) return error.IncompleteScopedRoute;
    } else {
        if (cohorts.nodes.len != 0 or cohorts.root.leaf >= scoped.full.children.len) return error.InvalidScopedRoute;
        var selected: usize = 0;
        for (scoped.full.children, 0..) |child, ordinal| if (Scoped.includes(scoped.recipe, child.physical)) {
            if (cohorts.root.leaf != ordinal) return error.InvalidScopedRoute;
            selected += 1;
        };
        if (selected != 1) return error.InvalidScopedRoute;
    }
    const lists = try a.alloc(std.ArrayList(u32), leaf_parent.len);
    @memset(lists, .empty);
    const closure = try a.alloc(?u32, scoped.requirements.len);
    @memset(closure, null);
    var used_ids: usize = 0;
    for (scoped.requirements, 0..) |requirement, id| {
        var participants = std.AutoHashMap(u32, void).init(a);
        for (requirement.terms) |term| _ = try participants.getOrPut(term.selection.child());
        var iterator = participants.keyIterator();
        var common: ?u32 = null;
        while (iterator.next()) |ordinal| {
            if (ordinal.* >= lists.len or !Scoped.includes(scoped.recipe, scoped.full.children[ordinal.*].physical)) return error.InvalidScopedRoute;
            used_ids = try std.math.add(usize, used_ids, 1);
            if (used_ids > limits.max_slot_ids) return error.ScopedRouteResourceLimit;
            try lists[ordinal.*].append(a, @intCast(id));
            if (leaf_parent[ordinal.*]) |first_parent| common = if (common) |previous| try lca(node_parent, previous, first_parent) else first_parent;
        }
        if (requirement.disposition == .zero_when_complete) {
            closure[id] = common;
            if (closure[id] == null and cohorts.root == .node) closure[id] = cohorts.root.node;
        }
    }
    const leaves = try a.alloc([]const u32, lists.len);
    for (leaves, lists) |*ids, list| {
        var owned = list;
        ids.* = try owned.toOwnedSlice(a);
    }
    const nodes = try a.alloc(Node, cohorts.nodes.len);
    for (cohorts.nodes, 0..) |cohort, index| {
        var gathered = std.AutoHashMap(u32, void).init(a);
        for (cohort.children[0..cohort.child_count]) |ref| {
            const ids: []const u32 = switch (ref) {
                .leaf => |ordinal| leaves[ordinal],
                .node => |ordinal| nodes[ordinal].exports,
            };
            for (ids) |id| _ = try gathered.getOrPut(id);
        }
        // Empty scopes still have exact constant-zero exports/closure at root.
        if (cohorts.root == .node and cohorts.root.node == index) for (scoped.requirements, 0..) |requirement, id| if (requirement.terms.len == 0) {
            _ = try gathered.getOrPut(@intCast(id));
        };
        const inputs = try a.alloc(u32, gathered.count());
        var iterator = gathered.keyIterator();
        var at: usize = 0;
        while (iterator.next()) |id| {
            inputs[at] = id.*;
            at += 1;
        }
        std.mem.sort(u32, inputs, {}, std.sort.asc(u32));
        var exports: std.ArrayList(u32) = .empty;
        var closed: std.ArrayList(u32) = .empty;
        for (inputs) |id| {
            if (closure[id] != null and closure[id].? == index) try closed.append(a, id) else try exports.append(a, id);
        }
        used_ids = try std.math.add(usize, used_ids, try std.math.mul(usize, inputs.len, 2));
        if (used_ids > limits.max_slot_ids) return error.ScopedRouteResourceLimit;
        nodes[index] = .{ .inputs = inputs, .exports = try exports.toOwnedSlice(a), .closed = try closed.toOwnedSlice(a) };
    }
    var result = Plan{ .budget = budget, .arena = arena, .scoped = scoped, .cohorts = cohorts, .leaves = leaves, .nodes = nodes, .digest = undefined, .limits = limits };
    result.digest = result.identity();
    return result;
}

/// Pure topology/routing construction without any admitted proof/source token.
pub const testing = struct {
    pub const routeMetadata = initAdmitted;
};

//! Actual same-parent original PAGE-root/RAM/range verifier rows plus join AIR.
//! No fake execution spans; transition remains an authenticated OPEN output.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Public = @import("block_v5_source_ram_forest_join_public_v1.zig");
const Protocol = @import("block_v5_source_ram_forest_join_protocol_v1.zig");
const Root = @import("block_v5_memory_source_page_forest_summary_source_v1.zig");
const Graph = @import("air/block_v5_source_ram_forest_join_graph_v1.zig");
const Child = @import("air/block_v5_scoped_child_verifier_rows_v1.zig");
const Parent = @import("blake3_execution_parent_preparation.zig");
const Attach = @import("air/block_v5_scoped_admitted_graph_attach_v1.zig");
const Join = @import("air/blake3_parent_join.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Context = @import("block_v5_source_ram_forest_join_fixed_context_v1.zig");
pub const Limits = struct { max_owned_bytes: usize = 4 << 30, public_supply: @import("air/block_v5_closed_public_supply_v1.zig").Limits = .{} };
pub const Prepared = struct {
    budget: *Budget,
    backing_owner: ?*Budget,
    recursive: Parent.Prepared,
    wires: []Public.Wire,
    pub const complete_block_authority = false;
    pub fn deinit(self: *@This()) void {
        self.recursive.rows.allocator.free(self.wires);
        self.recursive.deinit();
        self.budget.destroy();
        if (self.backing_owner) |owner| owner.destroy();
        self.* = undefined;
    }
};
pub fn prepare(backing: std.mem.Allocator, public: *const Public.Owner, capacity: u32, limits: Limits) !Prepared {
    if (capacity == 0 or limits.max_owned_bytes == 0) return error.RecursiveMemoryJoinResourceLimit;
    try public.validate();
    const lease = if (Budget.fromAllocator(backing)) |owner| owner.retain() else null;
    errdefer if (lease) |owner| owner.destroy();
    const budget = try Budget.create(backing, limits.max_owned_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    var parent: ?Parent.Prepared = null;
    errdefer if (parent) |*value| value.deinit();
    var wires: std.ArrayList(Public.Wire) = .empty;
    errdefer wires.deinit(a);
    var next: u32 = 1;
    var ids = Context.Owned.init(1 + @as(u32, @intFromBool(public.policy.aggregate != null)), Protocol.sourceAuthority(), public.policy.memory.memory.seal.memory_plan_digest, public.policy.memory.sealed.digest);
    {
        var child = try Child.prepare(a, Root.Admission.init(public.policy.source), &public.policy.source.fresh.equation, 0, Root.PUBLIC_CIRCUIT, next, capacity);
        defer child.deinit();
        try append(a, &parent, &wires, &next, &ids, &child, public.policy.source.fresh.policy.expected_id);
    }
    if (public.policy.aggregate) |source| {
        const S = Public.Memory;
        var child = try Child.prepare(a, S.Admission.init(source), &source.fresh.equation, 1, S.PUBLIC_CIRCUIT, next, capacity);
        defer child.deinit();
        try append(a, &parent, &wires, &next, &ids, &child, source.fresh.policy.expected_id);
    }
    var graph = try Graph.prepare(a, public);
    defer graph.deinit();
    const graph_identity = try Attach.attach(a, &parent.?, &wires, graph.graph(), Public.Values{ .public = public }, &next);
    ids.attachment(graph_identity);
    parent.?.context = ids.finish(public.policy.memory.memory.seal.config);
    std.mem.sort(Public.Wire, wires.items, {}, struct {
        fn less(_: void, left: Public.Wire, right: Public.Wire) bool {
            return left.circuit < right.circuit or (left.circuit == right.circuit and left.wire < right.wire);
        }
    }.less);
    _ = try @import("block_v5_heterogeneous_scoped_public_bus_v1.zig").scheduleDigest(wires.items);
    const closed = try @import("air/block_v5_closed_public_supply_v1.zig").append(a, &parent.?.rows, wires.items, Public.Values{ .public = public }, limits.public_supply);
    ids.attachment(closed);
    parent.?.context = ids.finish(public.policy.memory.memory.seal.config);
    wires.clearRetainingCapacity();
    const owned = try wires.toOwnedSlice(a);
    const recursive = parent.?;
    parent = null;
    return .{ .budget = budget, .backing_owner = lease, .recursive = recursive, .wires = owned };
}
fn append(a: std.mem.Allocator, parent: *?Parent.Prepared, wires: *std.ArrayList(Public.Wire), next: *u32, ids: *Context.Owned, child: *Child.Prepared, key: [32]u8) !void {
    try wires.appendSlice(a, child.wires);
    ids.child(key, child.namespace_identity, child.recursive.context);
    if (parent.*) |*value| {
        const joined = try Join.joinDraining(a, &value.rows, &child.recursive.rows, .{ .{ .first = 1, .end = next.* }, .{ .first = next.*, .end = child.next_namespace } });
        value.rows.deinit();
        value.rows = joined;
    } else {
        parent.* = child.recursive;
        child.recursive.allocation_budget = null;
        child.recursive.rows = .{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
        inline for (0..Storage.Airs.len) |index| child.recursive.rows.fixed[index] = &.{};
    }
    next.* = child.next_namespace;
}

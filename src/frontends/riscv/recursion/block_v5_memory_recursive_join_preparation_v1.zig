//! Actual same-parent original PAGE-root/RAM/range verifier rows plus join AIR.
//! No fake execution spans; transition remains an authenticated OPEN output.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Public = @import("block_v5_memory_recursive_join_public_v1.zig");
const Protocol = @import("block_v5_memory_recursive_join_protocol_v1.zig");
const Root = @import("block_v5_memory_source_page_forest_source_v1.zig");
const Graph = @import("air/block_v5_memory_recursive_join_graph_v1.zig");
const Child = @import("air/block_v5_scoped_child_verifier_rows_v1.zig");
const Parent = @import("blake3_execution_parent_preparation.zig");
const Attach = @import("air/block_v5_scoped_admitted_graph_attach_v1.zig");
const Join = @import("air/blake3_parent_join.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
pub const Limits = struct { max_owned_bytes: usize = 4 << 30 };
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
    var ids: [5]core.channel.blake3.Channel = @splat(.{});
    for (&ids, 0..) |*channel, index| {
        channel.mixU32s(&.{ 0x42354d52, Public.VERSION, @intCast(index), public.childCount() });
        channel.mixRoot(Protocol.sourceAuthority());
        channel.mixRoot(public.policy.memory.seal.memory_plan_digest);
        channel.mixRoot(public.policy.memory.expected_seal_digest);
    }
    {
        var child = try Child.prepare(a, Root.Admission.init(public.policy.source), &public.policy.source.fresh.equation, 0, Root.PUBLIC_CIRCUIT, next, capacity);
        defer child.deinit();
        try append(a, &parent, &wires, &next, &ids, &child, public.policy.source.fresh.policy.expected_id);
    }
    for (public.ram, 0..) |*source, index| {
        var child = try Child.prepare(a, Public.Ram.Admission.init(source), &source.fresh.open.equation, @intCast(1 + index), Public.Ram.PUBLIC_CIRCUIT, next, capacity);
        defer child.deinit();
        try append(a, &parent, &wires, &next, &ids, &child, source.fresh.policy.expected_id);
    }
    for (public.range, 0..) |*source, index| {
        var child = try Child.prepare(a, Public.Range.Admission.init(source), &source.fresh.open.equation, @intCast(1 + public.ram.len + index), Public.Range.PUBLIC_CIRCUIT, next, capacity);
        defer child.deinit();
        try append(a, &parent, &wires, &next, &ids, &child, source.fresh.policy.expected_id);
    }
    var graph = try Graph.prepare(a, public);
    defer graph.deinit();
    const graph_identity = try Attach.attach(a, &parent.?, &wires, graph.graph(), Public.Values{ .public = public }, &next);
    for (&ids) |*channel| channel.mixRoot(graph_identity);
    parent.?.context = .{ .child_key_id = ids[0].digestBytes(), .child_config = public.policy.memory.seal.config, .graph_ids = .{ ids[1].digestBytes(), ids[2].digestBytes(), ids[3].digestBytes() }, .transcript_plan_id = ids[4].digestBytes() };
    std.mem.sort(Public.Wire, wires.items, {}, struct {
        fn less(_: void, left: Public.Wire, right: Public.Wire) bool {
            return left.circuit < right.circuit or (left.circuit == right.circuit and left.wire < right.wire);
        }
    }.less);
    _ = try Public.scheduleDigest(wires.items);
    const owned = try wires.toOwnedSlice(a);
    const recursive = parent.?;
    parent = null;
    return .{ .budget = budget, .backing_owner = lease, .recursive = recursive, .wires = owned };
}
fn append(a: std.mem.Allocator, parent: *?Parent.Prepared, wires: *std.ArrayList(Public.Wire), next: *u32, ids: *[5]core.channel.blake3.Channel, child: *Child.Prepared, key: [32]u8) !void {
    try wires.appendSlice(a, child.wires);
    for (ids) |*channel| {
        channel.mixRoot(key);
        channel.mixRoot(child.namespace_identity);
    }
    for (ids[1..4], child.recursive.context.graph_ids) |*channel, id| channel.mixRoot(id);
    ids[4].mixRoot(child.recursive.context.transcript_plan_id);
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

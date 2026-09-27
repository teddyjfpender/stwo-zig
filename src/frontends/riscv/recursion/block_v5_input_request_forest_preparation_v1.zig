//! Real bounded forest producer rows. Every selected original WM/v2 or prior
//! node has its FULL original verifier embedded, then one exact request/coverage
//! graph is attached to the SAME parent. Carrier appears only at the root.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Bus = @import("block_v5_input_request_forest_bus_v1.zig");
const Source = @import("block_v5_input_request_forest_source_v1.zig");
const Receiver = @import("block_v5_input_request_forest_receiver_v1.zig");
const W = @import("block_v5_tail_linked_public_windows_receiver_v2.zig");
const WS = @import("block_v5_tail_linked_public_windows_source_v2.zig");
const C = @import("block_v5_input_tail_receiver_v1.zig");
const CS = @import("block_v5_input_tail_source_v1.zig");
const Plan = @import("block_v5_input_request_forest_plan_v1.zig");
const Child = @import("air/block_v5_scoped_child_verifier_rows_v1.zig");
const Graph = @import("air/block_v5_input_request_forest_graph_v1.zig");
const Attach = @import("air/block_v5_scoped_admitted_graph_attach_v1.zig");
const Parent = @import("blake3_execution_parent_preparation.zig");
const Join = @import("air/blake3_parent_join.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
pub const Limits = struct { max_owned_bytes: usize = 4 << 30 };
pub const Verified = union(enum) { leaf: *const W.Fresh, node: *const Receiver.Fresh };
pub const Prepared = struct {
    budget: *Budget,
    backing_owner: ?*Budget,
    recursive: Parent.Prepared,
    wires: []Bus.Wire,
    pub const complete_source_authority = false;
    pub fn deinit(self: *Prepared) void {
        self.recursive.rows.allocator.free(self.wires);
        self.recursive.deinit();
        self.budget.destroy();
        if (self.backing_owner) |owner| owner.destroy();
        self.* = undefined;
    }
};
fn coordinate(child: u32, source: anytype) Graph.Coordinate {
    return .{ .child = child, .first_cell = source.first_cell, .word_count = source.word_count };
}
pub fn prepare(backing: std.mem.Allocator, public: *const Bus.Owner, verified: []const Verified, carrier: ?*const C.Fresh, capacity: u32, limits: Limits) !Prepared {
    try public.validate();
    const node = public.policy.forest.geometry.nodes[public.policy.index];
    if (capacity == 0 or limits.max_owned_bytes == 0 or verified.len != node.child_count or ((node.kind == .carrier) != (carrier != null))) return error.UntrustedInputRequestNode;
    const lease = if (Budget.fromAllocator(backing)) |owner| owner.retain() else null;
    errdefer if (lease) |owner| owner.destroy();
    const budget = try Budget.create(backing, limits.max_owned_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    var wires: std.ArrayList(Bus.Wire) = .empty;
    errdefer wires.deinit(a);
    var parent: ?Parent.Prepared = null;
    errdefer if (parent) |*value| value.deinit();
    var next: u32 = 1;
    var identities: [5]core.channel.blake3.Channel = @splat(.{});
    for (&identities, 0..) |*channel, index| {
        channel.mixU32s(&.{ 0x4235494e, 1, public.policy.index, @intCast(index) });
        channel.mixRoot(@import("block_v5_input_request_forest_protocol_v1.zig").sourceAuthority());
        channel.mixRoot(public.policy.forest.geometry.digest);
    }
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var provider: ?Graph.Child = null;
    if (carrier) |fresh| {
        try fresh.validate();
        if (!std.meta.eql(fresh.policy, public.policy.carrier)) return error.UntrustedInputRequestNode;
        const source = try CS.Source.init(fresh);
        var rows = try Child.prepare(a, CS.Admission.init(&source), &fresh.equation, 0, CS.PUBLIC_CIRCUIT, next, capacity);
        defer rows.deinit();
        try append(a, &parent, &wires, &next, &identities, &rows);
        const cvs = try temp.alloc(Graph.Coordinate, public.input.frontier.len);
        for (cvs, 0..) |*cv, index| cv.* = coordinate(0, try source.frontier(index));
        provider = .{ .root = coordinate(0, source.inputRoot()), .length = coordinate(0, source.inputLength()), .prefix = coordinate(0, source.inputPrefix()), .frontier = cvs, .first_cycle = null, .last_cycle = null, .first_window = null, .window_count = null, .leaf_count = null };
    }
    const children = try temp.alloc(Graph.Child, verified.len);
    const ranges = try temp.alloc(Plan.Range, verified.len);
    const offset: u32 = if (carrier != null) 1 else 0;
    for (verified, node.children[0..node.child_count], children, ranges, 0..) |received, ref, *desc, *range, index| {
        const ordinal: u32 = offset + @as(u32, @intCast(index));
        range.* = try public.policy.forest.geometry.range(ref);
        const cvs = try temp.alloc(Graph.Coordinate, public.input.frontier.len);
        switch (ref) {
            .leaf => |leaf| {
                if (received != .leaf) return error.UntrustedInputRequestNode;
                const fresh = received.leaf;
                try fresh.validate();
                if (!std.meta.eql(fresh.policy, public.policy.forest.policies[leaf])) return error.UntrustedInputRequestNode;
                var source = try WS.Source.init(a, fresh);
                defer source.deinit();
                var rows = try Child.prepare(a, WS.Admission.init(&source), &fresh.equation, ordinal, WS.PUBLIC_CIRCUIT, next, capacity);
                defer rows.deinit();
                try append(a, &parent, &wires, &next, &identities, &rows);
                for (cvs, 0..) |*cv, i| cv.* = coordinate(ordinal, try source.inputFrontier(@intCast(i)));
                const r = source.rangeCoordinates();
                desc.* = .{ .root = coordinate(ordinal, source.inputRoot()), .length = coordinate(ordinal, source.inputLength()), .prefix = coordinate(ordinal, try source.inputPrefix()), .frontier = cvs, .first_cycle = coordinate(ordinal, try source.firstCycle()), .last_cycle = coordinate(ordinal, try source.lastCycle()), .first_window = .{ .child = ordinal, .first_cell = r.first_window, .word_count = 1 }, .window_count = .{ .child = ordinal, .first_cell = r.window_count, .word_count = 1 }, .leaf_count = null };
            },
            .node => |index_child| {
                if (received != .node) return error.UntrustedInputRequestNode;
                const fresh = received.node;
                try fresh.validate();
                var p = public.policy;
                p.index = index_child;
                const expected = try Receiver.admit(.{ .public = p, .public_limits = public.limits, .max_proof_bytes = fresh.policy.max_proof_bytes });
                if (!std.meta.eql(fresh.policy, expected)) return error.UntrustedInputRequestNode;
                var source = try Source.Source.init(a, fresh);
                defer source.deinit();
                var rows = try Child.prepare(a, Source.Admission.init(&source), &fresh.equation, ordinal, Source.PUBLIC_CIRCUIT, next, capacity);
                defer rows.deinit();
                try append(a, &parent, &wires, &next, &identities, &rows);
                for (cvs, 0..) |*cv, i| cv.* = coordinate(ordinal, try source.frontier(i));
                const r = try source.rangeCoordinates();
                desc.* = .{ .root = coordinate(ordinal, try source.inputRoot()), .length = coordinate(ordinal, try source.inputLength()), .prefix = coordinate(ordinal, try source.inputPrefix()), .frontier = cvs, .first_cycle = coordinate(ordinal, try source.firstCycle()), .last_cycle = coordinate(ordinal, try source.lastCycle()), .first_window = .{ .child = ordinal, .first_cell = r.first, .word_count = 1 }, .window_count = .{ .child = ordinal, .first_cell = r.count, .word_count = 1 }, .leaf_count = .{ .child = ordinal, .first_cell = r.leaves, .word_count = 1 } };
            },
        }
    }
    var graph = try Graph.prepare(a, Bus.Values{ .public = public }, &public.summary, children, provider, ranges);
    defer graph.deinit();
    const identity = try Attach.attach(a, &parent.?, &wires, graph.graph(), Bus.Values{ .public = public }, &next);
    for (&identities) |*channel| channel.mixRoot(identity);
    parent.?.context = .{ .child_key_id = identities[0].digestBytes(), .child_config = public.policy.specs[public.policy.index].geometry.config, .graph_ids = .{ identities[1].digestBytes(), identities[2].digestBytes(), identities[3].digestBytes() }, .transcript_plan_id = identities[4].digestBytes() };
    std.mem.sort(Bus.Wire, wires.items, {}, struct {
        fn less(_: void, l: Bus.Wire, r: Bus.Wire) bool {
            return l.circuit < r.circuit or (l.circuit == r.circuit and l.wire < r.wire);
        }
    }.less);
    _ = try Bus.scheduleDigest(wires.items);
    const owned = try wires.toOwnedSlice(a);
    const recursive = parent.?;
    parent = null;
    return .{ .budget = budget, .backing_owner = lease, .recursive = recursive, .wires = owned };
}
fn append(a: std.mem.Allocator, parent: *?Parent.Prepared, wires: *std.ArrayList(Bus.Wire), next: *u32, ids: *[5]core.channel.blake3.Channel, child: *Child.Prepared) !void {
    try wires.appendSlice(a, child.wires);
    for (ids) |*channel| channel.mixRoot(child.namespace_identity);
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
        inline for (0..Storage.Airs.len) |i| child.recursive.rows.fixed[i] = &.{};
    }
    next.* = child.next_namespace;
}

//! Actual local common-ancestor rows: ONE genuine tail capture, <=3 genuine
//! v2 window captures, and exact provider/consumer byte equations in that same
//! parent. Larger forest/source/global closure is deliberately not conferred.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Bus = @import("block_v5_input_tail_ancestor_bus_v1.zig");
const Carrier = @import("block_v5_input_tail_receiver_v1.zig");
const CarrierSource = @import("block_v5_input_tail_source_v1.zig");
const Window = @import("block_v5_tail_linked_public_windows_receiver_v2.zig");
const WindowSource = @import("block_v5_tail_linked_public_windows_source_v2.zig");
const Child = @import("air/block_v5_scoped_child_verifier_rows_v1.zig");
const Graph = @import("air/block_v5_input_tail_ancestor_graph_v1.zig");
const Attach = @import("air/block_v5_scoped_admitted_graph_attach_v1.zig");
const Parent = @import("blake3_execution_parent_preparation.zig");
const Join = @import("air/blake3_parent_join.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
pub const Limits = struct { max_owned_bytes: usize = 4 << 30 };
pub const Prepared = struct {
    budget: *Budget,
    backing_owner: ?*Budget,
    recursive: Parent.Prepared,
    wires: []Bus.Wire,
    pub const complete_source_authority = false;
    pub const local_carrier_links_constrained = true;
    pub fn deinit(self: *Prepared) void {
        self.recursive.rows.allocator.free(self.wires);
        self.recursive.deinit();
        self.budget.destroy();
        if (self.backing_owner) |owner| owner.destroy();
        self.* = undefined;
    }
};
pub fn prepare(backing: std.mem.Allocator, public: *const Bus.Owner, carrier: *const Carrier.Fresh, windows: []const *const Window.Fresh, capacity: u32, limits: Limits) !Prepared {
    if (capacity == 0 or limits.max_owned_bytes == 0 or windows.len != public.consumers.len) return error.UntrustedInputTailAncestor;
    try public.validate();
    try carrier.validate();
    if (!std.meta.eql(carrier.policy, public.policy.carrier)) return error.UntrustedInputTailAncestor;
    for (windows, public.policy.consumers) |fresh, p| {
        try fresh.validate();
        if (!std.meta.eql(fresh.policy, p)) return error.UntrustedInputTailAncestor;
    }
    const lease = if (Budget.fromAllocator(backing)) |owner| owner.retain() else null;
    errdefer if (lease) |owner| owner.destroy();
    const budget = try Budget.create(backing, limits.max_owned_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    var wires: std.ArrayList(Bus.Wire) = .empty;
    errdefer wires.deinit(a);
    var next: u32 = 1;
    var parent: ?Parent.Prepared = null;
    errdefer if (parent) |*value| value.deinit();
    var ids: [5]core.channel.blake3.Channel = @splat(.{});
    for (&ids, 0..) |*channel, index| {
        channel.mixU32s(&.{ 0x4235544e, 1, @intCast(index), public.policy.first_window, public.policy.window_count });
        channel.mixRoot(@import("block_v5_input_tail_ancestor_protocol_v1.zig").sourceAuthority());
    }
    const cs = try CarrierSource.Source.init(carrier);
    var carrier_rows = try Child.prepare(a, CarrierSource.Admission.init(&cs), &carrier.equation, 0, CarrierSource.PUBLIC_CIRCUIT, next, capacity);
    defer carrier_rows.deinit();
    try append(a, &parent, &wires, &next, &ids, &carrier_rows);
    for (windows, 0..) |fresh, ordinal| {
        var source = try WindowSource.Source.init(a, fresh);
        defer source.deinit();
        var child = try Child.prepare(a, WindowSource.Admission.init(&source), &fresh.equation, @intCast(ordinal + 1), WindowSource.PUBLIC_CIRCUIT, next, capacity);
        defer child.deinit();
        try append(a, &parent, &wires, &next, &ids, &child);
    }
    var graph = try Graph.prepare(a, public);
    defer graph.deinit();
    const identity = try Attach.attach(a, &parent.?, &wires, graph.graph(), Bus.Values{ .public = public }, &next);
    for (&ids) |*channel| channel.mixRoot(identity);
    parent.?.context = .{ .child_key_id = ids[0].digestBytes(), .child_config = public.policy.carrier.key.config, .graph_ids = .{ ids[1].digestBytes(), ids[2].digestBytes(), ids[3].digestBytes() }, .transcript_plan_id = ids[4].digestBytes() };
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

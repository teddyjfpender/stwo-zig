//! Actual PAGE source parent: <=4 genuine leaf/lower-parent captures and exact
//! original claim/roster byte equations. Endpoint and global joins remain OPEN.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Bus = @import("block_v5_memory_source_page_forest_bus_v1.zig");
const Leaves = @import("block_v5_memory_source_page_forest_leaf_v1.zig");
const DefaultLower = @import("block_v5_memory_source_page_forest_receiver_v1.zig");
const DefaultLowerSource = @import("block_v5_memory_source_page_forest_source_v1.zig");
const Child = @import("air/block_v5_scoped_child_verifier_rows_v1.zig");
const Graph = @import("air/block_v5_memory_source_page_forest_graph_v1.zig");
const Attach = @import("air/block_v5_scoped_admitted_graph_attach_v1.zig");
const Parent = @import("blake3_execution_parent_preparation.zig");
const Join = @import("air/blake3_parent_join.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Context = @import("block_v5_memory_source_page_forest_fixed_context_v1.zig");
pub const Limits = struct { max_owned_bytes: usize = 4 << 30, public_supply: @import("air/block_v5_closed_public_supply_v1.zig").Limits = .{} };
pub const Prepared = struct {
    budget: *Budget,
    backing_owner: ?*Budget,
    recursive: Parent.Prepared,
    wires: []Bus.Wire,
    pub const complete_source_authority = false;
    pub const page_claim_byte_merges_constrained = true;
    pub fn deinit(self: *Prepared) void {
        self.recursive.rows.allocator.free(self.wires);
        self.recursive.deinit();
        self.budget.destroy();
        if (self.backing_owner) |owner| owner.destroy();
        self.* = undefined;
    }
};
/// Statically selected lower-node receiver/source; the same canonical row,
/// namespace, merge and closed supplier kernel serves both paths. Proof bytes
/// do not select this factory. Original defaults remain exact delegates.
pub const Capture = ForNode(DefaultLower, DefaultLowerSource).Capture;
pub const prepare = ForNode(DefaultLower, DefaultLowerSource).prepare;
pub fn ForNode(comptime Lower: type, comptime LowerSource: type) type {
    return struct {
        pub const Capture = union(enum) { raw: *const Leaves.ForKind(.raw).Fresh, fold: *const Leaves.ForKind(.fold).Fresh, node: *const Lower.Fresh };
        pub fn prepare(backing: std.mem.Allocator, public: *const Bus.Owner, captures: []const @This().Capture, capacity: u32, limits: Limits) !Prepared {
            if (capacity == 0 or limits.max_owned_bytes == 0 or captures.len != public.child_count) return error.PageForestResourceLimit;
            try public.validateSources();
            const roster = try public.policy.forest.node(public.policy.index, public.policy.expected_plan);
            for (captures, roster.children[0..roster.child_count]) |capture, ref| switch (capture) {
                .raw => |fresh| {
                    try fresh.validate();
                    if (ref != .leaf or ref.leaf >= public.policy.forest.raw.len or !std.meta.eql(fresh.policy, public.policy.forest.raw[ref.leaf])) return error.UntrustedPageForestCapture;
                },
                .fold => |fresh| {
                    try fresh.validate();
                    if (ref != .leaf or ref.leaf < public.policy.forest.raw.len or !std.meta.eql(fresh.policy, public.policy.forest.fold[ref.leaf - public.policy.forest.raw.len])) return error.UntrustedPageForestCapture;
                },
                .node => |fresh| {
                    try fresh.validate();
                    var expected = public.policy;
                    if (ref != .node) return error.UntrustedPageForestCapture;
                    expected.index = ref.node;
                    if (!std.meta.eql(fresh.policy.public, expected)) return error.UntrustedPageForestCapture;
                },
            };
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
            var ids = Context.Owned.init(public.policy.index, roster, public.policy.expected_plan, @import("block_v5_memory_source_page_forest_protocol_v1.zig").sourceAuthority());
            for (captures, 0..) |capture, index| switch (capture) {
                .raw => |fresh| {
                    const S = Leaves.ForKind(.raw);
                    const source = try S.Source.init(fresh);
                    var child = try Child.prepare(a, S.Admission.init(&source), &fresh.open.equation, @intCast(index), S.PUBLIC_CIRCUIT, next, capacity);
                    defer child.deinit();
                    try append(a, &parent, &wires, &next, &ids, &child);
                },
                .fold => |fresh| {
                    const S = Leaves.ForKind(.fold);
                    const source = try S.Source.init(fresh);
                    var child = try Child.prepare(a, S.Admission.init(&source), &fresh.open.equation, @intCast(index), S.PUBLIC_CIRCUIT, next, capacity);
                    defer child.deinit();
                    try append(a, &parent, &wires, &next, &ids, &child);
                },
                .node => |fresh| {
                    var source = try LowerSource.Source.init(a, fresh);
                    defer source.deinit();
                    var child = try Child.prepare(a, LowerSource.Admission.init(&source), &fresh.equation, @intCast(index), LowerSource.PUBLIC_CIRCUIT, next, capacity);
                    defer child.deinit();
                    try append(a, &parent, &wires, &next, &ids, &child);
                },
            };
            var graph = try Graph.prepare(a, public);
            defer graph.deinit();
            const identity = try Attach.attach(a, &parent.?, &wires, graph.graph(), Bus.SourceValues{ .public = public }, &next);
            ids.attachment(identity);
            parent.?.context = ids.finish(public.policy.forest.context.fold_plan.config);
            std.mem.sort(Bus.Wire, wires.items, {}, struct {
                fn less(_: void, l: Bus.Wire, r: Bus.Wire) bool {
                    return l.circuit < r.circuit or (l.circuit == r.circuit and l.wire < r.wire);
                }
            }.less);
            _ = try Bus.scheduleDigest(wires.items);
            const closure = try @import("air/block_v5_closed_public_supply_v1.zig").append(a, &parent.?.rows, wires.items, Bus.SourceValues{ .public = public }, limits.public_supply);
            ids.attachment(closure);
            parent.?.context = ids.finish(public.policy.forest.context.fold_plan.config);
            // Internal suppliers are proved here. The external public schedule is empty.
            wires.clearRetainingCapacity();
            const owned = try wires.toOwnedSlice(a);
            const recursive = parent.?;
            parent = null;
            return .{ .budget = budget, .backing_owner = lease, .recursive = recursive, .wires = owned };
        }
        fn append(a: std.mem.Allocator, parent: *?Parent.Prepared, wires: *std.ArrayList(Bus.Wire), next: *u32, ids: *Context.Owned, child: *Child.Prepared) !void {
            try wires.appendSlice(a, child.wires);
            ids.child(child.namespace_identity, child.recursive.context);
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
    };
}

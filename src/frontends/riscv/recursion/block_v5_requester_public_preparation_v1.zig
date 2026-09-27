//! One genuine requester verifier plus the original public tuple/B5SS AIR in
//! the same parent. No public-parent/RAM/range verifier is added a second time.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Public = @import("block_v5_requester_public_compensation_v1.zig");
const Bus = @import("block_v5_requester_public_bus_v1.zig");
const Requester = @import("block_v5_requester_summary_source_v1.zig");
const Child = @import("air/block_v5_scoped_child_verifier_rows_v1.zig");
const Composition = @import("air/block_v5_requester_public_composition_v1.zig");
const Rows = @import("air/block_v5_global_public_export_rows_v1.zig").ForModules(Public, Composition, Bus);
const Rebase = @import("air/blake3_parent_rebase.zig");
const Join = @import("air/blake3_parent_join.zig");
const Ports = @import("block_v5_requester_public_assembly_ports_v1.zig");
pub const Limits = struct { max_preparation_bytes: usize = 8 << 30, max_graph_bytes: usize = 512 << 20 };
pub const Prepared = struct {
    budget: *Budget,
    recursive: @import("blake3_execution_parent_preparation.zig").Prepared,
    wires: []Bus.Wire,
    pub fn deinit(self: *Prepared) void {
        self.recursive.rows.allocator.free(self.wires);
        self.recursive.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
};
pub fn prepare(backing: std.mem.Allocator, public: *const Public.Owner, requester: *const Requester.Source, capacity: u32, limits: Limits) !Prepared {
    if (capacity == 0 or limits.max_preparation_bytes == 0 or limits.max_graph_bytes == 0) return error.RequesterPublicResourceLimit;
    try public.validate();
    try requester.validate();
    // Both Sources are independently paired to the exact catalogue root by
    // validate(). Identity equality permits stable expected metadata to supply
    // public bytes after this actual child capture has been consumed/released.
    if (public.requester != requester.owner or !std.meta.eql(public.compact.seal, requester.fresh.source.seal) or
        !std.meta.eql(public.compact.ref, requester.fresh.source.ref)) return error.UnpairedRequesterPublicSource;
    const budget = try Budget.createRetainingParent(backing, limits.max_preparation_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    const admission = Requester.Admission.init(requester);
    var child = try Child.prepare(a, admission, &requester.fresh.equation, 0, Requester.PUBLIC_CIRCUIT, 1, capacity);
    defer child.deinit();
    var graph = try Composition.prepare(a, public, limits.max_graph_bytes);
    defer graph.deinit();
    var tuples = try Rows.prepare(a, public, &graph, capacity);
    defer tuples.deinit();
    var namespace = try Rebase.prepare(a, &tuples.rows, child.next_namespace);
    defer namespace.deinit();
    const end = try namespace.end();
    const namespace_identity = try namespace.identity();
    for (tuples.wires) |*wire| wire.circuit = namespace.map(wire.circuit) orelse return error.MissingRequesterPublicNamespace;
    try Rebase.apply(&tuples.rows, &namespace, namespace_identity);
    var wires: std.ArrayList(Bus.Wire) = .empty;
    errdefer wires.deinit(a);
    for (child.wires) |wire| try wires.append(a, try Ports.childWire(wire));
    try wires.appendSlice(a, tuples.wires);
    const combined = try Join.joinDraining(a, &child.recursive.rows, &tuples.rows, .{ .{ .first = 1, .end = child.next_namespace }, .{ .first = child.next_namespace, .end = end } });
    child.recursive.rows.deinit();
    child.recursive.rows = combined;
    child.recursive.context = Ports.context(.{
        .source_authority = @import("block_v5_requester_public_protocol_v1.zig").sourceAuthority(),
        .public_identity = public.identity,
        .requester_expected = requester.fresh.source.expected_id,
        .tuple_identity = tuples.identity,
        .child_namespace = child.namespace_identity,
        .tuple_namespace = namespace_identity,
        .child = child.recursive.context,
    });
    try Ports.sortAndRequire(wires.items);
    const result = Prepared{ .budget = budget, .recursive = child.recursive, .wires = try wires.toOwnedSlice(a) };
    child.recursive.allocation_budget = null;
    child.recursive.rows = .{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..@import("air/blake3_parent_row_storage.zig").Airs.len) |i| child.recursive.rows.fixed[i] = &.{};
    return result;
}

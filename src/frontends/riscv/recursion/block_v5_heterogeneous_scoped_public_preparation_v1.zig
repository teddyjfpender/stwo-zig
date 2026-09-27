//! Actual independently fresh compact/public-child verifier rows and the
//! original scoped compensation graph in one real parent arithmetic schedule.
const std = @import("std");
const core = @import("stwo_core");
const Context = @import("block_v5_heterogeneous_scoped_public_context_v1.zig");
const Child = @import("air/block_v5_scoped_child_verifier_rows_v1.zig");
const Parent = @import("blake3_execution_parent_preparation.zig");
const Bus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Source = @import("block_v5_heterogeneous_scoped_source_v1.zig");
const PublicSource = @import("block_v5_heterogeneous_scoped_public_source_v1.zig");
const Join = @import("air/blake3_parent_join.zig");
pub const Limits = struct { max_preparation_bytes: usize = 4 << 30 };
pub const Prepared = struct {
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    recursive: Parent.Prepared,
    wires: []Bus.Wire,
    pub fn deinit(self: *Prepared) void {
        self.recursive.rows.allocator.free(self.wires);
        self.recursive.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
};
/// Context retains both real captures, original policy catalogues, expected
/// public owner and lazy source bytes through preparation and publication.
pub fn prepare(backing: std.mem.Allocator, context: *const Context.Context, capacity: u32, limits: Limits) !Prepared {
    if (capacity == 0 or limits.max_preparation_bytes == 0) return error.ScopedPublicBridgeResourceLimit;
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(backing, limits.max_preparation_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    const values = context.values();
    try values.validate();
    const compact_admission = Source.Admission.init(&context.compact.source, &.{});
    var compact = try Child.prepare(a, compact_admission, &context.compact.equation, 0, Source.PUBLIC_CIRCUIT, 1, capacity);
    defer compact.deinit();
    const public_admission = PublicSource.Admission.init(&context.source);
    var public = try Child.prepare(a, public_admission, &context.public.equation.equation, 1, @import("block_v5_global_public_export_normalizer_v1.zig").PUBLIC_CIRCUIT, compact.next_namespace, capacity);
    defer public.deinit();
    if (!std.meta.eql(compact.recursive.context.child_config, public.recursive.context.child_config)) return error.V5OpenParentSecurityMismatch;
    var wires: std.ArrayList(Bus.Wire) = .empty;
    errdefer wires.deinit(a);
    try wires.appendSlice(a, compact.wires);
    try wires.appendSlice(a, public.wires);
    const combined = try Join.joinDraining(a, &compact.recursive.rows, &public.recursive.rows, .{ .{ .first = 1, .end = compact.next_namespace }, .{ .first = compact.next_namespace, .end = public.next_namespace } });
    compact.recursive.rows.deinit();
    compact.recursive.rows = combined;
    // joinDraining releases source column buffers; deferred child teardown
    // releases their remaining metadata. Bind exact combined contexts below.
    var result = compact.recursive;
    compact.recursive.allocation_budget = null;
    compact.recursive.rows = .{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..@import("air/blake3_parent_row_storage.zig").Airs.len) |i| compact.recursive.rows.fixed[i] = &.{};
    errdefer result.deinit();
    var graph = try @import("air/block_v5_heterogeneous_scoped_public_equations_v1.zig").prepare(a, values);
    defer graph.deinit();
    var next_namespace = public.next_namespace;
    const graph_identity = try @import("air/block_v5_scoped_admitted_graph_attach_v1.zig").attach(a, &result, &wires, graph.graph(), values, &next_namespace);
    var channels: [5]core.channel.blake3.Channel = @splat(.{});
    for (&channels, 0..) |*channel, index| {
        channel.mixU32s(&.{ 0x42354743, 0x4d503152, 1, @intCast(index) });
        channel.mixRoot(context.policy.owner.pinned_identity);
        channel.mixRoot(context.plan.pinned_digest);
        channel.mixRoot(context.compact.source.expected_id);
        channel.mixRoot(context.source.expected_id);
        channel.mixRoot(graph_identity);
    }
    for (channels[1..4], result.context.graph_ids, public.recursive.context.graph_ids) |*channel, left, right| {
        channel.mixRoot(left);
        channel.mixRoot(compact.namespace_identity);
        channel.mixRoot(right);
        channel.mixRoot(public.namespace_identity);
    }
    channels[4].mixRoot(result.context.transcript_plan_id);
    channels[4].mixRoot(compact.namespace_identity);
    channels[4].mixRoot(public.recursive.context.transcript_plan_id);
    channels[4].mixRoot(public.namespace_identity);
    result.context = .{ .child_key_id = channels[0].digestBytes(), .child_config = compact_admission.key.config, .graph_ids = .{ channels[1].digestBytes(), channels[2].digestBytes(), channels[3].digestBytes() }, .transcript_plan_id = channels[4].digestBytes() };
    std.mem.sort(Bus.Wire, wires.items, {}, struct {
        fn less(_: void, left: Bus.Wire, right: Bus.Wire) bool {
            return left.circuit < right.circuit or (left.circuit == right.circuit and left.wire < right.wire);
        }
    }.less);
    _ = try Bus.scheduleDigest(wires.items);
    return .{ .budget = budget, .recursive = result, .wires = try wires.toOwnedSlice(a) };
}

//! Consuming extension of genuine heterogeneous verifier rows in the SAME
//! parent. The new public policy is rebuilt from original independent metadata.
//! Source completeness is OPEN; old default parent routes remain unchanged.
const std = @import("std");
const core = @import("stwo_core");
const Original = @import("block_v5_heterogeneous_parent_preparation_v1.zig");
const Public = @import("block_v5_global_public_export_policy_v1.zig");
const Fields = @import("block_v5_global_public_fields_v1.zig");
const Bus = @import("block_v5_global_public_export_bus_v1.zig");
const Semantic = @import("block_v5_global_join_semantic_plan_v1.zig");
const Graph = @import("air/block_v5_global_public_export_composition_v1.zig");
const Rows = @import("air/block_v5_global_public_export_rows_v1.zig");
const rebase = @import("air/blake3_parent_rebase.zig");
const join = @import("air/blake3_parent_join.zig");
pub const Limits = struct { fields: Fields.Limits = .{}, semantic: Semantic.Limits = .{}, max_graph_bytes: usize = 512 << 20 };
pub const Prepared = struct {
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    allocator: std.mem.Allocator,
    recursive: @import("blake3_execution_parent_preparation.zig").Prepared,
    wires: []Bus.Wire,
    values: Bus.Values,
    next_namespace: u32,
    public: *Public.Owner,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Prepared) void {
        self.recursive.deinit();
        self.allocator.free(self.wires);
        self.public.deinit();
        self.allocator.destroy(self.public);
        self.budget.destroy();
        self.* = undefined;
    }
    pub fn requireComplete(_: *const Prepared) !void {
        return error.GlobalPublicSourceAuthorityUnavailable;
    }
};
/// Success consumes original exactly once; errors leave it requiring deinit,
/// with destructive joined-row failures explicitly allowed to consume rows.
/// Borrowed original policy/windows/job input must outlive this returned owner.
pub fn extend(original: *Original.Prepared, windows: @import("../prover/block_v5_register_windows_v1.zig").Plan, attempt_capacity: u32, limits: Limits) !Prepared {
    if (attempt_capacity == 0 or limits.max_graph_bytes == 0) return error.GlobalPublicExportResourceLimit;
    const a = original.allocator;
    const public = try a.create(Public.Owner);
    errdefer a.destroy(public);
    public.* = try Public.init(a, .{ .original = original.values.policy, .windows = windows }, limits.fields);
    errdefer public.deinit();
    var derived = try Semantic.derive(a, original.values.policy, limits.semantic);
    defer derived.deinit();
    // Existing exact execution/group/transition scopes remain actual equations,
    // never replaced by a global zero sum or by this public extension's metadata.
    try derived.attachOpen(original, limits.max_graph_bytes);
    var graph = try Graph.prepare(a, public, &derived, limits.max_graph_bytes);
    defer graph.deinit();
    var rows = try Rows.prepare(a, public, &graph, attempt_capacity);
    defer rows.deinit();
    var namespace = try rebase.prepare(a, &rows.rows, original.next_namespace);
    defer namespace.deinit();
    const end = try namespace.end();
    const namespace_identity = try namespace.identity();
    for (rows.wires) |*wire| wire.circuit = namespace.map(wire.circuit) orelse return error.MissingGlobalPublicNamespace;
    const count = try std.math.add(usize, original.wires.len, rows.wires.len);
    const wires = try a.alloc(Bus.Wire, count);
    errdefer a.free(wires);
    for (original.wires, wires[0..original.wires.len]) |wire, *destination| destination.* = Bus.fromOriginal(wire);
    @memcpy(wires[original.wires.len..], rows.wires);
    sortWires(wires);
    _ = try Bus.scheduleDigest(wires);
    try rebase.apply(&rows.rows, &namespace, namespace_identity);
    const combined = try join.joinDraining(a, &original.recursive.rows, &rows.rows, .{ .{ .first = 1, .end = original.next_namespace }, .{ .first = original.next_namespace, .end = end } });
    original.recursive.rows.deinit();
    original.recursive.rows = combined;
    for (&original.recursive.context.graph_ids) |*identity| {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42354741, Bus.VERSION });
        channel.mixRoot(sourceAuthority());
        channel.mixRoot(identity.*);
        channel.mixRoot(rows.identity);
        channel.mixRoot(namespace_identity);
        identity.* = channel.digestBytes();
    }
    var transcript_identity = core.channel.blake3.Channel{};
    transcript_identity.mixRoot(original.recursive.context.transcript_plan_id);
    transcript_identity.mixRoot(rows.identity);
    transcript_identity.mixRoot(namespace_identity);
    original.recursive.context.transcript_plan_id = transcript_identity.digestBytes();
    const result = Prepared{ .budget = original.budget, .allocator = a, .recursive = original.recursive, .wires = wires, .values = .{ .public = public }, .next_namespace = end, .public = public };
    a.free(original.wires);
    original.* = undefined;
    return result;
}
fn sortWires(wires: []Bus.Wire) void {
    std.mem.sort(Bus.Wire, wires, {}, struct {
        fn less(_: void, a: Bus.Wire, b: Bus.Wire) bool {
            return a.circuit < b.circuit or (a.circuit == b.circuit and a.wire < b.wire);
        }
    }.less);
}
pub fn sourceAuthority() [32]u8 {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42354753, Bus.VERSION });
    inline for (.{ @embedFile("block_v5_global_public_export_parent_v1.zig"), @embedFile("block_v5_global_public_fields_v1.zig"), @embedFile("block_v5_global_public_export_policy_v1.zig"), @embedFile("block_v5_global_public_export_bus_v1.zig"), @embedFile("block_v5_reusable_global_public_export_protocol_v1.zig"), @embedFile("block_v5_global_public_export_receiver_v1.zig"), @embedFile("../prover/block_v5_global_public_export_stage_v1.zig"), @embedFile("air/block_v5_global_public_tuple_algebra_v1.zig"), @embedFile("air/block_v5_global_public_export_composition_v1.zig"), @embedFile("air/block_v5_global_public_export_rows_v1.zig"), @embedFile("../air/public_data.zig"), @embedFile("../air/program/decode.zig"), @embedFile("../prover/block_v5_universal_channel_v1.zig"), @embedFile("../prover/block_v5_register_windows_v1.zig"), @embedFile("../prover/block_v5_global_join_algebra_v1.zig") }) |source| {
        var hash: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(source, &hash, .{});
        channel.mixRoot(hash);
    }
    channel.mixRoot(Semantic.sourceAuthority());
    return channel.digestBytes();
}

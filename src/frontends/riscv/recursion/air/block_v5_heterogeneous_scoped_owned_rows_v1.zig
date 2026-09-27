//! Visibility-only bridge to the exact qualified compact lowering kernel.
//! It is callable only with a genuine locally validated owner admission.
//! The caller preserves immutable source/policy lifetime and validates locally.
const std = @import("std");
const core = @import("stwo_core");
const Owner = @import("../block_v5_heterogeneous_scoped_owner_v1.zig");
const Source = @import("../block_v5_heterogeneous_scoped_source_v1.zig");
const Bus = @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Kernel = @import("block_v5_heterogeneous_scoped_graph_rows_v1.zig");
const rebase = @import("blake3_parent_rebase.zig");
const join = @import("blake3_parent_join.zig");
const storage = @import("blake3_parent_row_storage.zig");
pub fn attach(a: std.mem.Allocator, parent: *@import("../blake3_execution_parent_preparation.zig").Prepared, wires: *std.ArrayList(Bus.Wire), graph: Kernel.Graph, admitted: Owner.Values, next_namespace: *u32) ![32]u8 {
    try admitted.validate();
    var source_storage: [4]Source.Source = undefined;
    const values = try admitted.original(&source_storage);
    var lowered = try Kernel.materializeLocallyAdmitted(a, graph, values);
    defer lowered.deinit();
    var namespace = try rebase.prepare(a, &lowered.rows, next_namespace.*);
    defer namespace.deinit();
    const end = try namespace.end();
    const namespace_id = try namespace.identity();
    for (lowered.wires) |*wire| wire.circuit = namespace.map(wire.circuit) orelse return error.MissingHeterogeneousGraphNamespace;
    // Reserve before the destructive row transfer. The caller tears down its
    // parent on every later error; no borrowed source is consumed by this API.
    try wires.ensureUnusedCapacity(a, lowered.wires.len);
    try rebase.apply(&lowered.rows, &namespace, namespace_id);
    const joined = try join.joinDraining(a, &parent.rows, &lowered.rows, .{ .{ .first = 1, .end = next_namespace.* }, .{ .first = next_namespace.*, .end = end } });
    parent.rows.deinit();
    lowered.rows.deinit();
    lowered.rows = .{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..storage.Airs.len) |i| lowered.rows.fixed[i] = &.{};
    parent.rows = joined;
    wires.appendSliceAssumeCapacity(lowered.wires);
    next_namespace.* = end;
    var channel = core.channel.blake3.Channel{};
    channel.mixRoot(lowered.identity);
    channel.mixRoot(namespace_id);
    return channel.digestBytes();
}

//! Same admitted canonical graph lowering and shared parent row join, with a
//! statically chosen genuine source coordinate view. No new equation recipe.
const std = @import("std");
const core = @import("stwo_core");
const Bus = @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Parent = @import("../blake3_execution_parent_preparation.zig");
const Kernel = @import("block_v5_heterogeneous_scoped_graph_rows_v1.zig");
const Rebase = @import("blake3_parent_rebase.zig");
const Join = @import("blake3_parent_join.zig");
const Storage = @import("blake3_parent_row_storage.zig");
pub fn attach(a: std.mem.Allocator, parent: *Parent.Prepared, wires: *std.ArrayList(Bus.Wire), graph: Kernel.Graph, admitted_values: anytype, next_namespace: *u32) ![32]u8 {
    try admitted_values.validate();
    var lowered = try Kernel.materializeLocallyAdmittedFor(a, graph, admitted_values);
    defer lowered.deinit();
    var namespace = try Rebase.prepare(a, &lowered.rows, next_namespace.*);
    defer namespace.deinit();
    const end = try namespace.end();
    const namespace_id = try namespace.identity();
    for (lowered.wires) |*wire| wire.circuit = namespace.map(wire.circuit) orelse return error.MissingScopedGraphNamespace;
    try wires.ensureUnusedCapacity(a, lowered.wires.len);
    try Rebase.apply(&lowered.rows, &namespace, namespace_id);
    const combined = try Join.joinDraining(a, &parent.rows, &lowered.rows, .{ .{ .first = 1, .end = next_namespace.* }, .{ .first = next_namespace.*, .end = end } });
    parent.rows.deinit();
    lowered.rows.deinit();
    lowered.rows = .{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..Storage.Airs.len) |i| lowered.rows.fixed[i] = &.{};
    parent.rows = combined;
    wires.appendSliceAssumeCapacity(lowered.wires);
    next_namespace.* = end;
    var channel = core.channel.blake3.Channel{};
    channel.mixRoot(lowered.identity);
    channel.mixRoot(namespace_id);
    return channel.digestBytes();
}

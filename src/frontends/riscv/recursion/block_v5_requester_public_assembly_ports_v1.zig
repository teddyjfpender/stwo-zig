//! Exact PUBLIC21 schedule conversion/context binding. Setup metadata only;
//! callers must derive inputs from the original admitted compiler, not files.
const std = @import("std");
const core = @import("stwo_core");
const Bus = @import("block_v5_requester_public_bus_v1.zig");
const ScopedBus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Public = @import("block_v5_requester_public_compensation_v1.zig");
pub const ContextInputs = struct {
    source_authority: [32]u8,
    public_identity: [32]u8,
    requester_expected: [32]u8,
    tuple_identity: [32]u8,
    child_namespace: [32]u8,
    tuple_namespace: [32]u8,
    child: Base.Context,
};
pub fn context(inputs: ContextInputs) Base.Context {
    var channels: [5]core.channel.blake3.Channel = @splat(.{});
    for (&channels, 0..) |*channel, i| {
        channel.mixU32s(&.{ 0x52515052, Public.VERSION, @intCast(i) });
        channel.mixRoot(inputs.source_authority);
        channel.mixRoot(inputs.public_identity);
        channel.mixRoot(inputs.requester_expected);
        channel.mixRoot(inputs.tuple_identity);
        channel.mixRoot(inputs.child_namespace);
        channel.mixRoot(inputs.tuple_namespace);
    }
    for (channels[1..4], inputs.child.graph_ids) |*channel, id| channel.mixRoot(id);
    channels[4].mixRoot(inputs.child.transcript_plan_id);
    return .{ .child_key_id = channels[0].digestBytes(), .child_config = inputs.child.child_config, .graph_ids = .{ channels[1].digestBytes(), channels[2].digestBytes(), channels[3].digestBytes() }, .transcript_plan_id = channels[4].digestBytes() };
}
pub fn childWire(wire: ScopedBus.Wire) !Bus.Wire {
    if (wire.child != 0) return error.InvalidRequesterPublicSchedule;
    const kind: @import("block_v5_heterogeneous_public_bus_v1.zig").Kind = switch (wire.kind) {
        .child_cell => if (wire.part == null) .frame_cell else .pairing_coordinate,
        .child_term => if (wire.part == null) .child_supply_packed else return error.InvalidRequesterPublicSchedule,
        else => return error.InvalidRequesterPublicSchedule,
    };
    return .{ .circuit = wire.circuit, .wire = wire.wire, .uses = wire.uses, .negative = wire.negative, .source = .{ .original = .{ .child = 0, .kind = kind, .coordinate = wire.coordinate, .part = wire.part orelse 0 } } };
}
pub fn less(_: void, left: Bus.Wire, right: Bus.Wire) bool {
    return left.circuit < right.circuit or (left.circuit == right.circuit and left.wire < right.wire);
}
pub fn sortAndRequire(wires: []Bus.Wire) !void {
    std.mem.sort(Bus.Wire, wires, {}, less);
    _ = try Bus.scheduleDigest(wires);
}

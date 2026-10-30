//! Domain-separated context for the exact common-prefix/bridge verifier layout.
const core = @import("stwo_core");
const Base = @import("blake3_execution_parent_protocol.zig");
pub fn finish(channels: [5]core.channel.blake3.Channel, config: core.pcs.PcsConfig, prefix: [32]u8, namespace: [32]u8, bridges: [32]u8) Base.Context {
    var result = channels;
    for (&result, 0..) |*channel, i| {
        channel.mixU32s(&.{ 0x42375345, 1, @intCast(i) });
        channel.mixRoot(prefix);
        channel.mixRoot(namespace);
        channel.mixRoot(bridges);
    }
    return .{ .child_key_id = result[0].digestBytes(), .child_config = config, .graph_ids = .{ result[1].digestBytes(), result[2].digestBytes(), result[3].digestBytes() }, .transcript_plan_id = result[4].digestBytes() };
}

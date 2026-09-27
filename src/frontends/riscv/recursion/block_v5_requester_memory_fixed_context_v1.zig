//! Exact original FINAL22 context operations. No child key is selected here.
const core = @import("stwo_core");
const Base = @import("blake3_execution_parent_protocol.zig");
pub const Owned = struct {
    channels: [5]core.channel.blake3.Channel,
    pub fn init(source_authority: [32]u8, memory_plan: [32]u8, source_seal: [32]u8) Owned {
        var result = Owned{ .channels = @splat(.{}) };
        for (&result.channels, 0..) |*channel, index| {
            channel.mixU32s(&.{ 0x42354d52, @import("block_v5_requester_memory_public_v1.zig").VERSION, @intCast(index), 2 });
            channel.mixRoot(source_authority);
            channel.mixRoot(memory_plan);
            channel.mixRoot(source_seal);
        }
        return result;
    }
    pub fn child(self: *Owned, expected: [32]u8, namespace: [32]u8, context: Base.Context) void {
        for (&self.channels) |*channel| {
            channel.mixRoot(expected);
            channel.mixRoot(namespace);
        }
        for (self.channels[1..4], context.graph_ids) |*channel, graph| channel.mixRoot(graph);
        self.channels[4].mixRoot(context.transcript_plan_id);
    }
    pub fn attachment(self: *Owned, identity: [32]u8) void {
        for (&self.channels) |*channel| channel.mixRoot(identity);
    }
    pub fn finish(self: *const Owned, config: core.pcs.PcsConfig) Base.Context {
        return .{ .child_key_id = self.channels[0].digestBytes(), .child_config = config, .graph_ids = .{ self.channels[1].digestBytes(), self.channels[2].digestBytes(), self.channels[3].digestBytes() }, .transcript_plan_id = self.channels[4].digestBytes() };
    }
};

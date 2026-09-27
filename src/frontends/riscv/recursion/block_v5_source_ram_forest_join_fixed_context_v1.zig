//! Exact original VERSION20 context ordering; source value custody is separate.
const core = @import("stwo_core");
const Base = @import("blake3_execution_parent_protocol.zig");
pub const Owned = struct {
    channels: [5]core.channel.blake3.Channel,
    pub fn init(count: u32, authority: [32]u8, plan: [32]u8, seal: [32]u8) Owned {
        var out = Owned{ .channels = @splat(.{}) };
        for (&out.channels, 0..) |*c, i| {
            c.mixU32s(&.{ 0x42354d52, 20, @intCast(i), count });
            c.mixRoot(authority);
            c.mixRoot(plan);
            c.mixRoot(seal);
        }
        return out;
    }
    pub fn child(self: *Owned, expected: [32]u8, namespace: [32]u8, context: Base.Context) void {
        for (&self.channels) |*c| {
            c.mixRoot(expected);
            c.mixRoot(namespace);
        }
        for (self.channels[1..4], context.graph_ids) |*c, id| c.mixRoot(id);
        self.channels[4].mixRoot(context.transcript_plan_id);
    }
    pub fn attachment(self: *Owned, id: [32]u8) void {
        for (&self.channels) |*c| c.mixRoot(id);
    }
    pub fn finish(self: *const Owned, config: core.pcs.PcsConfig) Base.Context {
        return .{ .child_key_id = self.channels[0].digestBytes(), .child_config = config, .graph_ids = .{ self.channels[1].digestBytes(), self.channels[2].digestBytes(), self.channels[3].digestBytes() }, .transcript_plan_id = self.channels[4].digestBytes() };
    }
};

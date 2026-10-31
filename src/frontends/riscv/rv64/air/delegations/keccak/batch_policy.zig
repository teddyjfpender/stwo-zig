//! Explicit experimental lookup clearing policy; default v2 remains triple.
const L = @import("layout.zig");
pub const Policy = enum {
    triple_v2,
    quartet_v3,
    pub fn width(self: Policy) usize {
        return if (self == .triple_v2) 3 else 4;
    }
    pub fn roundBatches(self: Policy) usize {
        return L.LOOKUPS / self.width();
    }
    pub fn ioBatches(self: Policy) usize {
        return (L.IO_LANES + self.width() - 1) / self.width();
    }
    pub fn batches(self: Policy) usize {
        return self.roundBatches() + self.ioBatches();
    }
    pub fn interactionCount(self: Policy) usize {
        return 4 * self.batches();
    }
    pub fn constraints(self: Policy) usize {
        return L.DIRECT + self.batches();
    }
    pub fn degree(self: Policy) u8 {
        return @intCast(self.width() + 1);
    }
    /// New authority is mixed before roots/challenges by the experimental owner.
    /// Legacy owners never call this and retain their old transcript exactly.
    pub fn mix(self: Policy, channel: anytype) void {
        channel.mixU32s(&.{ 0x4b424154, 1, @intFromEnum(self), @intCast(self.width()), @intCast(self.interactionCount()), self.degree() });
    }
};

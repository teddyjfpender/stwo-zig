//! Explicit D3 pair-inverse permutation geometry; legacy layouts unchanged.
const K = @import("../layout.zig");
pub const FIXED = K.FIXED;
pub const ROUND_ENABLE = K.MAIN;
pub const IO_ENABLE = ROUND_ENABLE + 1;
pub const MAIN = IO_ENABLE + 1;
pub const ROUND_PAIRS = K.LOOKUPS / 2;
pub const IO_PAIRS = (K.IO_LANES + 1) / 2;
pub const PAIRS = ROUND_PAIRS + IO_PAIRS;
pub const PREFIX = 4 * PAIRS;
pub const INTERACTION = PREFIX + 4;
pub const CONSTRAINTS = K.DIRECT + 4 + 2 * PAIRS + 1;
pub fn mix(channel: anytype) void {
    channel.mixU32s(&.{ 0x4b50324e, 1, MAIN, INTERACTION, CONSTRAINTS, 3, 1 });
}

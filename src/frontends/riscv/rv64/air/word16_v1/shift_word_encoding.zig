//! One concrete interaction encoding; no new runtime representation policy.
const std = @import("std");
const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
pub const VERSION: u32 = 2;
const S = @import("shift_word.zig");
pub const MAIN = S.LOCAL_MAIN + 1;
pub const UNIT_QUERIES = S.TABLE_QUERIES + S.RANGE_QUERIES;
comptime {
    std.debug.assert(UNIT_QUERIES % 2 == 0);
}
pub const PAIRS = UNIT_QUERIES / 2;
pub const FUNCTION_INVERSE = 4 * PAIRS;
pub const PREFIX = FUNCTION_INVERSE + 4;
pub const INTERACTION = PREFIX + 4;
pub fn identity() [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo-rv64/word16-shift/encoding-v2/SHIFT5-U16nine-cross-family-strict-pairs/joint-prefix/FUNCTION13-multiplicity-only/D3");
    for ([_]u32{ VERSION, MAIN, INTERACTION, 5, 9, 13, 3 }) |v| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, v, .little);
        h.update(&bytes);
    }
    return h.finalResult();
}
pub fn mix(ch: *Channel) void {
    ch.mixU32s(&.{ 0x5348454e, VERSION, MAIN, INTERACTION, 5, 9, 3 });
    const d = identity();
    var words: [8]u32 = undefined;
    for (&words, 0..) |*w, i| w.* = std.mem.readInt(u32, d[4 * i ..][0..4], .little);
    ch.mixU32s(&words);
}

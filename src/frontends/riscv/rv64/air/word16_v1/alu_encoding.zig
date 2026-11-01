//! Immutable physical encoding identity. One experimental representation, no
//! runtime mode switch. Semantic FUNCTION13 operation IDs stay unchanged.
const std = @import("std");
const Channel = @import("stwo_core").channel.blake2s.Blake2sChannel;
pub const VERSION: u32 = 5;
/// A[4], B[4], active, selectors10 and auxiliaries; op and C[4] are derived.
pub const LOCAL_MAIN = 46;
pub const MAIN = LOCAL_MAIN + 1;
pub const LOCAL_CONSTRAINTS = 53; // Logical diagnostic authority.
pub const PROJECTED_LOCAL_CONSTRAINTS = LOCAL_CONSTRAINTS - 5;
pub const FUNCTION_INVERSE = 4 * (RANGE_QUERIES / 2);
pub const PREFIX = FUNCTION_INVERSE + 4;
pub const INTERACTION = PREFIX + 4;
pub const RANGE_QUERIES = 12;
pub const DIFFERENCE_SUM_MAX = 4 * 65535;
pub const INVERSE_CACHE_LEN = DIFFERENCE_SUM_MAX + 1;
pub fn identity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-rv64/word16-alu/encoding-v5/main47/derived-FUNCTION13-affine-op-quadratic-C/canonical-REG-ROM-inputs/ranged-sum-difference-W-low-write-anchors/sum-of-four-U16-differences-zero/signed-less-staged/joint-U16-FUNCTION-prefix/FUNCTION13-ops0..9");
    for ([_]u32{ VERSION, LOCAL_MAIN, MAIN, LOCAL_CONSTRAINTS, PROJECTED_LOCAL_CONSTRAINTS, INTERACTION, RANGE_QUERIES, DIFFERENCE_SUM_MAX, 3 }) |value| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .little);
        hash.update(&bytes);
    }
    return hash.finalResult();
}
pub fn mix(channel: *Channel) void {
    channel.mixU32s(&.{ 0x414c5545, VERSION, MAIN, INTERACTION, RANGE_QUERIES, PROJECTED_LOCAL_CONSTRAINTS });
    const digest = identity();
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    channel.mixU32s(&words);
}

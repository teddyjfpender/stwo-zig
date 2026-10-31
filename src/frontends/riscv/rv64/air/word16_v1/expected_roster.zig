//! Public diagnostic consumer parameters; geometry-only preprocessing.
//! The integration must bind digest(roster) to the independently expected
//! statement in BOTH local stage-one FS and the complete root manifest.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const physical = @import("../witness.zig").physical;
pub const LOG = 5;
pub const ROWS = 32;
pub const WIDTH = 14;
pub const FIXED = 34;
pub const Roster = [ROWS][WIDTH]M;
pub fn validate(roster: *const Roster) !void {
    for (roster) |row| {
        for (row) |value| if (value.v >= core.fields.m31.Modulus) return error.NonCanonicalWord16Roster;
        if (row[13].v > 1) return error.InvalidWord16RosterWeight;
    }
}
pub fn digest(roster: *const Roster) ![32]u8 {
    try validate(roster);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-word16-public-roster-v1:32x14:le32");
    var bytes: [4]u8 = undefined;
    for (roster) |row| for (row) |value| {
        std.mem.writeInt(u32, &bytes, value.v, .little);
        h.update(&bytes);
    };
    var output: [32]u8 = undefined;
    h.final(&output);
    return output;
}
pub fn fixed(a: std.mem.Allocator) ![]M {
    const data = try a.alloc(M, FIXED * ROWS);
    @memset(data, M.zero());
    data[physical(0, LOG)] = M.one();
    data[ROWS + physical(ROWS - 1, LOG)] = M.one();
    for (0..ROWS) |i| data[(2 + i) * ROWS + physical(i, LOG)] = M.one();
    return data;
}
pub fn main(a: std.mem.Allocator, roster: *const Roster) ![]M {
    try validate(roster);
    const data = try a.alloc(M, WIDTH * ROWS);
    for (roster, 0..) |row, i| for (row, 0..) |value, c| {
        data[c * ROWS + physical(i, LOG)] = value;
    };
    return data;
}

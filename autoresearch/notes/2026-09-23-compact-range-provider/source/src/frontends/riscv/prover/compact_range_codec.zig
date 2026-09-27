//! Fixed-size compact-range geometry contract for the next execution envelope.
//! The caller supplies the authenticated identity; bytes never authorize themselves.
const std = @import("std");
const geometry = @import("../recursion/air/compact_range_geometry.zig");
pub const MAGIC = "CRNGEO01";
pub const ENCODED_BYTES = 12 + 8 * geometry.kinds.len;
pub fn encode(plan: geometry.Plan) ![ENCODED_BYTES]u8 {
    try plan.validate();
    var result: [ENCODED_BYTES]u8 = undefined;
    @memcpy(result[0..8], MAGIC);
    std.mem.writeInt(u32, result[8..12], geometry.VERSION, .little);
    for (plan.shapes, 0..) |shape, i| {
        std.mem.writeInt(u32, result[12 + i * 8 ..][0..4], shape.n_rows, .little);
        std.mem.writeInt(u32, result[16 + i * 8 ..][0..4], shape.log_size, .little);
    }
    return result;
}
pub fn decode(raw: []const u8, expected: [32]u8) !geometry.Plan {
    if (raw.len != ENCODED_BYTES) return error.InvalidCompactRangeEncodingLength;
    if (!std.mem.eql(u8, raw[0..8], MAGIC) or std.mem.readInt(u32, raw[8..12], .little) != geometry.VERSION) return error.InvalidCompactRangeEncodingVersion;
    var plan: geometry.Plan = undefined;
    for (&plan.shapes, 0..) |*shape, i| shape.* = .{
        .n_rows = std.mem.readInt(u32, raw[12 + i * 8 ..][0..4], .little),
        .log_size = std.mem.readInt(u32, raw[16 + i * 8 ..][0..4], .little),
    };
    try plan.admit(expected);
    return plan;
}
/// Call from a versioned protocol only after validating the complete statement.
/// This does not by itself admit native/extension statements or replace old tables.
pub fn mixAdmitted(channel: anytype, plan: geometry.Plan, expected: [32]u8) !void {
    try plan.admit(expected);
    channel.mixU32s(&.{ 0x43524e47, geometry.VERSION });
    var limbs: [16]u32 = undefined;
    for (&limbs, 0..) |*limb, i| limb.* = std.mem.readInt(u16, expected[2 * i ..][0..2], .little);
    channel.mixU32s(&limbs);
}

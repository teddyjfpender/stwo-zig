//! Little-endian numerical fixture encoding; cold qualification tools only.
const std = @import("std");
const O = @import("stwo_core").fields.om31.OM31;
pub fn words(w: anytype, values: []const u32) !void {
    for (values) |v| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, v, .little);
        try w.writeAll(&bytes);
    }
}
pub fn felts(w: anytype, values: []const O) !void {
    for (values) |v| {
        var row: [8]u32 = undefined;
        for (v.toM31Array(), &row) |c, *out| out.* = c.v;
        try words(w, &row);
    }
}
pub fn soa(w: anytype, values: []const O) !void {
    for (0..8) |c| for (values) |v| try words(w, &.{v.toM31Array()[c].v});
}

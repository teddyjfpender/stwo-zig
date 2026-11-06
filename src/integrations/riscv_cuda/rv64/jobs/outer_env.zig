//! Strict parsing of the STWO_RV64_M8_OUTER_* knobs (jobs/README.md, "Outer
//! job environment"). Unset -> the default; a flag accepts exactly "0" or
//! "1"; a number must parse completely. Anything else fails closed with
//! error.InvalidM8OuterEnvironment, so a mistyped A/B arm ("false", "off",
//! "4x") cannot silently run the other arm.
const std = @import("std");

pub fn flagValue(name: []const u8, value: ?[]const u8, default: bool) !bool {
    const v = value orelse return default;
    if (std.mem.eql(u8, v, "0")) return false;
    if (std.mem.eql(u8, v, "1")) return true;
    std.log.warn("{s}={s}: expected 0 or 1", .{ name, v });
    return error.InvalidM8OuterEnvironment;
}
pub fn unsignedValue(comptime T: type, name: []const u8, value: ?[]const u8, default: T) !T {
    const v = value orelse return default;
    return std.fmt.parseUnsigned(T, v, 10) catch {
        std.log.warn("{s}={s}: expected an unsigned integer", .{ name, v });
        return error.InvalidM8OuterEnvironment;
    };
}

pub fn flag(comptime name: []const u8, default: bool) !bool {
    return flagValue(name, std.posix.getenv(name), default);
}
pub fn unsigned(comptime T: type, comptime name: []const u8, default: T) !T {
    return unsignedValue(T, name, std.posix.getenv(name), default);
}
/// Unset -> null; otherwise a strictly parsed integer.
pub fn optionalUnsigned(comptime T: type, comptime name: []const u8) !?T {
    const v = std.posix.getenv(name) orelse return null;
    return try unsignedValue(T, name, v, 0);
}

test "outer env knobs: unset is the default, only exact values are accepted" {
    const t = std.testing;
    try t.expectEqual(true, try flagValue("X", null, true));
    try t.expectEqual(false, try flagValue("X", "0", true));
    try t.expectEqual(true, try flagValue("X", "1", false));
    for ([_][]const u8{ "false", "off", "", "01", "true" }) |bad| try t.expectError(error.InvalidM8OuterEnvironment, flagValue("X", bad, true));
    try t.expectEqual(@as(u32, 7), try unsignedValue(u32, "X", null, 7));
    try t.expectEqual(@as(u32, 4), try unsignedValue(u32, "X", "4", 7));
    for ([_][]const u8{ "4x", "-1", "", "0x10" }) |bad| try t.expectError(error.InvalidM8OuterEnvironment, unsignedValue(u32, "X", bad, 7));
}

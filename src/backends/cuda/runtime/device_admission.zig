//! Exact CUDA device architecture admission.

const std = @import("std");
const types = @import("../abi/types.zig");

pub fn sm(device: types.DeviceSnapshot) !u32 {
    if (device.sm_minor > 9) return error.InvalidDeviceArchitecture;
    const major = std.math.mul(u32, device.sm_major, 10) catch
        return error.InvalidDeviceArchitecture;
    return std.math.add(u32, major, device.sm_minor) catch
        return error.InvalidDeviceArchitecture;
}

pub fn contains(values: []const u32, expected: u32) bool {
    for (values) |value| if (value == expected) return true;
    return false;
}

test "device architecture is encoded exactly" {
    try std.testing.expectEqual(@as(u32, 90), try sm(.{
        .count = 1,
        .current = 0,
        .sm_major = 9,
        .sm_minor = 0,
    }));
    try std.testing.expectError(error.InvalidDeviceArchitecture, sm(.{
        .count = 1,
        .current = 0,
        .sm_major = 9,
        .sm_minor = 10,
    }));
}

/// Parse the exact numeric SM set selected by the archive build. Admission
/// never guesses a GPU generation or accepts an architecture absent from it.
pub fn parseArchitectures(allocator: std.mem.Allocator, text: []const u8) ![]u32 {
    var output = std.ArrayList(u32).empty;
    errdefer output.deinit(allocator);
    var values = std.mem.splitScalar(u8, text, ',');
    while (values.next()) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        const number = if (std.mem.startsWith(u8, trimmed, "sm_")) trimmed[3..] else trimmed;
        if (number.len < 2 or number.len > 3 or number[0] == '0') return error.InvalidDeviceArchitecture;
        for (number) |digit| if (digit < '0' or digit > '9') return error.InvalidDeviceArchitecture;
        const value = std.fmt.parseUnsigned(u32, number, 10) catch return error.InvalidDeviceArchitecture;
        if (!contains(output.items, value)) try output.append(allocator, value);
    }
    if (output.items.len == 0) return error.InvalidDeviceArchitecture;
    std.mem.sort(u32, output.items, {}, std.sort.asc(u32));
    return output.toOwnedSlice(allocator);
}

test "archive architecture admission supports Ampere Hopper and Blackwell exactly" {
    const allocator = std.testing.allocator;
    const parsed = try parseArchitectures(allocator, "sm_90, 80,120,sm_100,sm_120");
    defer allocator.free(parsed);
    try std.testing.expectEqualSlices(u32, &.{ 80, 90, 100, 120 }, parsed);
    try std.testing.expect(!contains(parsed, 89));
    for ([_][]const u8{ "", "native", "sm_9", "sm_090", "compute_90", "sm_120a", "90,", "sm_1000" }) |invalid| {
        try std.testing.expectError(error.InvalidDeviceArchitecture, parseArchitectures(allocator, invalid));
    }
}

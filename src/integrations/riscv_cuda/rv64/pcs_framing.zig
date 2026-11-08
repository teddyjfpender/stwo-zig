//! Transport-only aggregate lengths. Version 2 remains byte-identical for
//! ordinary requests; version 3 carries high halves, never truncated totals.
const std = @import("std");
pub fn encode(header: *[28]u32, counts: [4]u64, supported: bool) !usize {
    var wide = false;
    for (counts) |count| {
        if (count > (@as(u64, 1) << 48)) return error.DevicePcsExportSizeExceeded;
        wide = wide or count > std.math.maxInt(u32);
    }
    if (wide and !supported) return error.DevicePcsWideFramingUnsupported;
    header[1] = if (wide) 3 else 2;
    for (counts, 0..) |count, i| {
        header[15 + i] = @truncate(count);
        header[24 + i] = @truncate(count >> 32);
    }
    return if (wide) 28 else 24;
}
test "PCS framing preserves v2 and refuses truncation without runtime capability" {
    var h: [28]u32 = @splat(0);
    try std.testing.expectEqual(@as(usize, 24), try encode(&h, .{ 1, 2, 3, std.math.maxInt(u32) }, false));
    try std.testing.expectEqual(@as(u32, 2), h[1]);
    try std.testing.expectEqual(@as(u32, 0xffffffff), h[18]);
    const counts: [4]u64 = .{ 3_642_887_168, 7_285_774_336, (@as(u64, 1) << 32), (@as(u64, 1) << 40) + 17 };
    const before = h;
    try std.testing.expectError(error.DevicePcsWideFramingUnsupported, encode(&h, counts, false));
    try std.testing.expectEqualSlices(u32, &before, &h);
    try std.testing.expectEqual(@as(usize, 28), try encode(&h, counts, true));
    try std.testing.expectEqual(@as(u32, 3), h[1]);
    for (counts, 0..) |count, i| try std.testing.expectEqual(count, @as(u64, h[15 + i]) | (@as(u64, h[24 + i]) << 32));
    try std.testing.expectError(error.DevicePcsExportSizeExceeded, encode(&h, .{ std.math.maxInt(u64), 0, 0, 0 }, true));
}

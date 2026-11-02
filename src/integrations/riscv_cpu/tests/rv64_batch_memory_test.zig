const std = @import("std");
const Memory = @import("../rv64_batch_memory.zig");

test "batch RSS sampler joins on cleanup and preserves observed interval peak" {
    var sampler = Memory.Sampler{};
    try sampler.start();
    defer _ = sampler.finish();
    const report = sampler.finish();
    try std.testing.expect(sampler.thread == null);
    try std.testing.expect(report.samples >= 2);
    try std.testing.expectEqual(@as(u64, 0), report.failed_samples);
    try std.testing.expect(report.baseline_rss_bytes.? > 0);
    try std.testing.expect(report.sampled_peak_rss_bytes.? >= report.baseline_rss_bytes.?);
    try std.testing.expect(report.sampled_peak_rss_bytes.? >= report.last_rss_bytes.?);
    try std.testing.expect(report.process_lifetime_peak_rss_bytes.? > 0);
    try std.testing.expectEqualDeep(report, sampler.finish());
}

test "batch RSS JSON extends existing stage fields without nesting or peak aliasing" {
    const Profile = struct { schema_version: u32, events: []const u8 };
    const value = Memory.WithMemory(Profile){ .profile = .{ .schema_version = 4, .events = "retained" }, .memory = .{ .sampled_peak_rss_bytes = 123, .process_lifetime_peak_rss_bytes = 999 } };
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, value, .{});
    defer std.testing.allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqual(@as(i64, 4), object.get("schema_version").?.integer);
    try std.testing.expectEqualStrings("retained", object.get("events").?.string);
    try std.testing.expect(!object.contains("profile"));
    const memory = object.get("memory").?.object;
    try std.testing.expectEqual(@as(i64, 123), memory.get("sampled_peak_rss_bytes").?.integer);
    try std.testing.expectEqual(@as(i64, 999), memory.get("process_lifetime_peak_rss_bytes").?.integer);
}

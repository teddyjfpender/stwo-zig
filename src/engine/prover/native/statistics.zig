const std = @import("std");

pub const Summary = struct {
    median: f64,
    min: f64,
    max: f64,
    mad: f64,
};

pub fn summarize(allocator: std.mem.Allocator, values: []const f64) !Summary {
    if (values.len == 0) return error.EmptySamples;
    const ordered = try allocator.dupe(f64, values);
    defer allocator.free(ordered);
    std.mem.sort(f64, ordered, {}, std.sort.asc(f64));

    const median = middle(ordered);
    const deviations = try allocator.alloc(f64, ordered.len);
    defer allocator.free(deviations);
    for (ordered, deviations) |value, *deviation| deviation.* = @abs(value - median);
    std.mem.sort(f64, deviations, {}, std.sort.asc(f64));
    return .{
        .median = median,
        .min = ordered[0],
        .max = ordered[ordered.len - 1],
        .mad = middle(deviations),
    };
}

fn middle(ordered: []const f64) f64 {
    const upper = ordered.len / 2;
    if ((ordered.len & 1) == 1) return ordered[upper];
    return (ordered[upper - 1] + ordered[upper]) / 2.0;
}

test "native proof statistics: median and MAD handle odd and even samples" {
    const odd = try summarize(std.testing.allocator, &.{ 9.0, 1.0, 5.0 });
    try std.testing.expectEqual(@as(f64, 5.0), odd.median);
    try std.testing.expectEqual(@as(f64, 1.0), odd.min);
    try std.testing.expectEqual(@as(f64, 9.0), odd.max);
    try std.testing.expectEqual(@as(f64, 4.0), odd.mad);

    const even = try summarize(std.testing.allocator, &.{ 4.0, 1.0, 3.0, 2.0 });
    try std.testing.expectEqual(@as(f64, 2.5), even.median);
    try std.testing.expectEqual(@as(f64, 1.0), even.mad);
}

test "native proof statistics: empty sample set is rejected" {
    try std.testing.expectError(error.EmptySamples, summarize(std.testing.allocator, &.{}));
}

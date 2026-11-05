//! CPU-only diagnostics over original dependency levels; never proof authority.
const std = @import("std");
pub const bucket_upper_bounds = [_]usize{ 1, 4, 16, 32, 64, 128, 256, 1024, 4096, std.math.maxInt(u32) };
pub const Potential = struct { cta_threads: usize, max_levels_per_run: usize = 256, ordinary_calls: usize = 0, fused_runs: usize = 0, fused_nonempty_levels: usize = 0, projected_level_calls: usize = 0, fused_tasks: usize = 0 };
pub const Census = struct { levels: usize, nonempty_levels: usize = 0, empty_levels: usize = 0, tasks: usize, max_width: usize = 0, bucket_counts: [bucket_upper_bounds.len]usize = @splat(0), bucket_task_counts: [bucket_upper_bounds.len]usize = @splat(0), cta128: Potential, cta256: Potential };
fn potential(ends: []const usize, width_limit: usize) Potential {
    var p = Potential{ .cta_threads = width_limit };
    var i: usize = 0;
    var begin: usize = 0;
    while (i < ends.len) {
        const width = ends[i] - begin;
        if (width == 0) {
            i += 1;
            continue;
        }
        const first = i;
        var nonempty: usize = 1;
        var end = ends[i];
        i += 1;
        if (width <= width_limit) while (i < ends.len and i - first < p.max_levels_per_run) {
            const next = ends[i] - end;
            if (next > width_limit) break;
            nonempty += @intFromBool(next != 0);
            end = ends[i];
            i += 1;
        };
        if (nonempty > 1) {
            p.fused_runs += 1;
            p.fused_nonempty_levels += nonempty;
            p.fused_tasks += end - begin;
        } else p.ordinary_calls += 1;
        begin = end;
    }
    p.projected_level_calls = p.ordinary_calls + p.fused_runs;
    return p;
}
pub fn inspect(ends: []const usize, tasks: usize) !Census {
    var c = Census{ .levels = ends.len, .tasks = tasks, .cta128 = undefined, .cta256 = undefined };
    var begin: usize = 0;
    for (ends) |end| {
        if (end < begin or end > tasks) return error.InvalidScheduleCensus;
        const width = end - begin;
        c.max_width = @max(c.max_width, width);
        if (width == 0) c.empty_levels += 1 else {
            c.nonempty_levels += 1;
            for (bucket_upper_bounds, 0..) |upper, i| if (width <= upper) {
                c.bucket_counts[i] += 1;
                c.bucket_task_counts[i] += width;
                break;
            };
        }
        begin = end;
    }
    if (begin != tasks or tasks > std.math.maxInt(u32)) return error.InvalidScheduleCensus;
    c.cta128 = potential(ends, 128);
    c.cta256 = potential(ends, 256);
    return c;
}
test "real-width census distinguishes128 and256 and preserves broad barriers" {
    const c = try inspect(&.{ 0, 1, 129, 258, 259, 515, 516 }, 516);
    try std.testing.expectEqual(@as(usize, 6), c.nonempty_levels);
    try std.testing.expectEqual(@as(usize, 1), c.empty_levels);
    try std.testing.expectEqual(@as(usize, 5), c.cta128.projected_level_calls);
    try std.testing.expectEqual(@as(usize, 1), c.cta256.projected_level_calls);
    try std.testing.expectEqual(@as(usize, 256), c.max_width);
    try std.testing.expectEqual(@as(usize, 129), c.cta128.fused_tasks);
    try std.testing.expectEqual(@as(usize, 516), c.cta256.fused_tasks);
}
test "census bounds narrow runs and rejects malformed ranges" {
    var ends: [514]usize = undefined;
    for (&ends, 0..) |*v, i| v.* = i;
    const c = try inspect(&ends, 513);
    try std.testing.expectEqual(@as(usize, 3), c.cta128.projected_level_calls);
    try std.testing.expectEqual(@as(usize, 512), c.cta128.fused_nonempty_levels);
    try std.testing.expectError(error.InvalidScheduleCensus, inspect(&.{ 2, 1 }, 2));
    try std.testing.expectError(error.InvalidScheduleCensus, inspect(&.{1}, 2));
}

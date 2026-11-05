//! Numerical GG elision only. The original circuit and AIR are unchanged.
const std = @import("std");
pub fn enabled() !bool {
    const value = std.posix.getenv("STWO_RV64_BLAKE_SAMPLE_PREFILL") orelse return false;
    if (std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    return error.InvalidBlakeSamplePrefillOption;
}
/// Preserve every remaining task's relative order and all nonempty dependency
/// barriers. Prefilled GG outputs exist before this reduced schedule starts.
pub fn filter(comptime T: type, a: std.mem.Allocator, tasks: *[]T, ends: *[]usize, first: u32, count: u32) !void {
    const last = @as(u64, first) + count;
    if (count == 0 or last > std.math.maxInt(u32)) return error.InvalidBlakeSampleSpan;
    var read: usize = 0;
    var write: usize = 0;
    var levels: usize = 0;
    var removed: usize = 0;
    var previous: usize = 0;
    for (ends.*) |end| {
        if (end < read or end > tasks.len) return error.InvalidBlakeSamplePlan;
        for (tasks.*[read..end]) |task| {
            if (task.kind == .blake_g and task.index >= first and task.index < last) {
                removed += 1;
            } else {
                tasks.*[write] = task;
                write += 1;
            }
        }
        if (write != previous) {
            ends.*[levels] = write;
            levels += 1;
            previous = write;
        }
        read = end;
    }
    if (read != tasks.len or removed != count) return error.InvalidBlakeSamplePlan;
    tasks.* = try a.realloc(tasks.*, write);
    ends.* = try a.realloc(ends.*, levels);
}
test "sample prefill retains non-GG tasks and all surviving barriers" {
    const T = struct { kind: enum { add, blake_g }, index: u32 };
    const a = std.testing.allocator;
    var tasks = try a.dupe(T, &.{ .{ .kind = .blake_g, .index = 8 }, .{ .kind = .add, .index = 9 }, .{ .kind = .blake_g, .index = 9 }, .{ .kind = .blake_g, .index = 10 }, .{ .kind = .add, .index = 10 }, .{ .kind = .blake_g, .index = 11 } });
    defer a.free(tasks);
    var ends = try a.dupe(usize, &.{ 0, 2, 3, 4, 5, 6 });
    defer a.free(ends);
    try filter(T, a, &tasks, &ends, 9, 2);
    try std.testing.expectEqualSlices(usize, &.{ 2, 3, 4 }, ends);
    try std.testing.expectEqual(@as(usize, 4), tasks.len);
    try std.testing.expectEqual(@as(u32, 9), tasks[1].index);
    try std.testing.expectEqual(@as(@TypeOf(tasks[0].kind), .add), tasks[2].kind);
    try std.testing.expectEqual(@as(u32, 11), tasks[3].index);
}

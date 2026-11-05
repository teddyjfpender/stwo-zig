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

/// Original packed order is topological. Prefilled output variables have level
/// zero; recompute earliest legal levels for every remaining task, then stable
/// counting-sort by level. No primitive, variable or seed value changes.
pub fn relevel(comptime S: type, a: std.mem.Allocator, ctx: anytype, plan: *S.Plan) !void {
    const variable_levels = try a.alloc(u32, ctx.circuit.n_vars);
    defer a.free(variable_levels);
    @memset(variable_levels, 0);
    var maximum_level: u32 = 0;
    for (plan.tasks) |*task| {
        var input_buf: [6]u32 = undefined;
        var output_buf: [4]u32 = undefined;
        var maximum: u32 = 0;
        for (S.inputs(ctx, task.*, &input_buf)) |variable| {
            if (variable >= variable_levels.len) return error.InvalidBlakeSamplePlan;
            maximum = @max(maximum, variable_levels[variable]);
        }
        task.level = try std.math.add(u32, maximum, 1);
        maximum_level = @max(maximum_level, task.level);
        for (S.outputs(ctx, task.*, &output_buf)) |variable| {
            if (variable >= variable_levels.len) return error.InvalidBlakeSamplePlan;
            variable_levels[variable] = task.level;
        }
    }
    const ends = try a.alloc(usize, @as(usize, maximum_level) + 1);
    errdefer a.free(ends);
    @memset(ends, 0);
    for (plan.tasks) |task| ends[task.level] += 1;
    const cursor = try a.alloc(usize, ends.len);
    defer a.free(cursor);
    var count: usize = 0;
    for (ends, cursor) |*end, *start| {
        start.* = count;
        count += end.*;
        end.* = count;
    }
    const ordered = try a.alloc(S.Task, plan.tasks.len);
    errdefer a.free(ordered);
    for (plan.tasks) |task| {
        ordered[cursor[task.level]] = task;
        cursor[task.level] += 1;
    }
    a.free(plan.tasks);
    a.free(plan.level_ends);
    plan.tasks = ordered;
    plan.level_ends = ends;
}

test "sample prefill relevels independent work without crossing dependencies" {
    const S = struct {
        pub const Task = struct { args: [2]u32, out: u32, level: u32 = 0 };
        pub const Plan = struct { tasks: []Task, level_ends: []usize };
        pub fn inputs(_: anytype, task: Task, buf: *[6]u32) []const u32 {
            buf[0..2].* = task.args;
            return buf[0..2];
        }
        pub fn outputs(_: anytype, task: Task, buf: *[4]u32) []const u32 {
            buf[0] = task.out;
            return buf[0..1];
        }
    };
    const a = std.testing.allocator;
    var plan = S.Plan{ .tasks = try a.dupe(S.Task, &.{ .{ .args = .{ 0, 1 }, .out = 2 }, .{ .args = .{ 2, 0 }, .out = 3 }, .{ .args = .{ 0, 0 }, .out = 4 }, .{ .args = .{ 3, 4 }, .out = 5 } }), .level_ends = try a.dupe(usize, &.{ 0, 1, 2, 3, 4 }) };
    defer a.free(plan.tasks);
    defer a.free(plan.level_ends);
    try relevel(S, a, .{ .circuit = .{ .n_vars = @as(u32, 6) } }, &plan);
    try std.testing.expectEqualSlices(usize, &.{ 0, 2, 3, 4 }, plan.level_ends);
    try std.testing.expectEqual(@as(u32, 2), plan.tasks[0].out);
    try std.testing.expectEqual(@as(u32, 4), plan.tasks[1].out);
    try std.testing.expectEqual(@as(u32, 3), plan.tasks[2].out);
    try std.testing.expectEqual(@as(u32, 3), plan.tasks[3].level);
}

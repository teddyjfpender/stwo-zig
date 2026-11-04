//! Private execution grouping of an already authenticated, dependency-layered
//! assignment schedule. No topology, ordering, origin or transcript changes.
const std = @import("std");
pub const threads: u32 = 128;
pub const max_levels: u32 = 256;
pub const Kind = enum { ordinary, narrow };
pub const Run = struct { kind: Kind, first_task: u32, task_count: u32, first_level: u32, level_count: u32 };
pub fn parseOptIn(value: ?[]const u8) !bool {
    const text = value orelse return false;
    if (std.mem.eql(u8, text, "0")) return false;
    if (std.mem.eql(u8, text, "1")) return true;
    return error.InvalidAssignmentNarrowRunOption;
}
pub const Stats = struct {
    levels: usize = 0,
    nonempty: usize = 0,
    empty: usize = 0,
    width_1_32: usize = 0,
    width_33_64: usize = 0,
    width_65_128: usize = 0,
    width_129_256: usize = 0,
    width_gt256: usize = 0,
    max_width: usize = 0,
};
pub fn inspect(ends: []const usize, task_count: usize) !Stats {
    if (ends.len > std.math.maxInt(u32) or task_count > std.math.maxInt(u32)) return error.AssignmentRunTooLarge;
    var out = Stats{ .levels = ends.len };
    var begin: usize = 0;
    for (ends) |end| {
        if (end < begin or end > task_count) return error.InvalidAssignmentLevels;
        const width = end - begin;
        out.max_width = @max(out.max_width, width);
        if (width == 0) out.empty += 1 else {
            out.nonempty += 1;
            if (width <= 32) out.width_1_32 += 1 else if (width <= 64) out.width_33_64 += 1 else if (width <= 128) out.width_65_128 += 1 else if (width <= 256) out.width_129_256 += 1 else out.width_gt256 += 1;
        }
        begin = end;
    }
    if (begin != task_count) return error.InvalidAssignmentLevels;
    return out;
}
pub const Plan = struct {
    allocator: std.mem.Allocator,
    runs: []Run,
    ends: []u32,
    stats: Stats,
    narrow_runs: usize,
    narrow_levels: usize,
    pub fn init(a: std.mem.Allocator, level_ends: []const usize, task_count: usize) !Plan {
        const stats = try inspect(level_ends, task_count);
        const ends = try a.alloc(u32, level_ends.len);
        errdefer a.free(ends);
        for (level_ends, ends) |end, *dst| dst.* = @intCast(end);
        var runs: std.ArrayList(Run) = .empty;
        errdefer runs.deinit(a);
        var i: usize = 0;
        var first: usize = 0;
        var narrow_runs: usize = 0;
        var narrow_levels: usize = 0;
        while (i < level_ends.len) {
            const width = level_ends[i] - first;
            if (width == 0) {
                i += 1;
                continue;
            }
            const level = i;
            var nonempty: usize = 1;
            var end = level_ends[i];
            i += 1;
            if (width <= threads) while (i < level_ends.len and i - level < max_levels) {
                const next_width = level_ends[i] - end;
                if (next_width > threads) break;
                nonempty += @intFromBool(next_width != 0);
                end = level_ends[i];
                i += 1;
            };
            const kind: Kind = if (nonempty > 1) .narrow else .ordinary;
            if (kind == .narrow) {
                narrow_runs += 1;
                narrow_levels += nonempty;
            }
            try runs.append(a, .{ .kind = kind, .first_task = @intCast(first), .task_count = @intCast(end - first), .first_level = @intCast(level), .level_count = @intCast(i - level) });
            first = end;
        }
        return .{ .allocator = a, .runs = try runs.toOwnedSlice(a), .ends = ends, .stats = stats, .narrow_runs = narrow_runs, .narrow_levels = narrow_levels };
    }
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.runs);
        self.allocator.free(self.ends);
        self.* = undefined;
    }
};

test "narrow runs preserve broad barriers, empty levels and exact task coverage" {
    const ends = [_]usize{ 0, 1, 129, 258, 259, 259, 261 };
    var p = try Plan.init(std.testing.allocator, &ends, 261);
    defer p.deinit();
    try std.testing.expectEqual(@as(usize, 3), p.runs.len);
    try std.testing.expectEqual(Kind.narrow, p.runs[0].kind);
    try std.testing.expectEqual(Kind.ordinary, p.runs[1].kind);
    try std.testing.expectEqual(@as(u32, 129), p.runs[1].task_count);
    try std.testing.expectEqual(Kind.narrow, p.runs[2].kind);
    var next: u32 = 0;
    for (p.runs) |r| {
        try std.testing.expectEqual(next, r.first_task);
        next += r.task_count;
    }
    try std.testing.expectEqual(@as(u32, 261), next);
    try std.testing.expectEqual(@as(usize, 2), p.stats.empty);
}
test "narrow runs are bounded to256 levels and leave singleton old route" {
    var ends: [258]usize = undefined;
    for (&ends, 0..) |*v, i| v.* = i;
    var p = try Plan.init(std.testing.allocator, &ends, 257);
    defer p.deinit();
    try std.testing.expectEqual(@as(usize, 2), p.runs.len);
    try std.testing.expectEqual(@as(u32, 256), p.runs[0].level_count);
    try std.testing.expectEqual(Kind.ordinary, p.runs[1].kind);
}
test "level validation rejects inversions missing tasks and bounds overflow" {
    try std.testing.expectError(error.InvalidAssignmentLevels, inspect(&.{ 2, 1 }, 2));
    try std.testing.expectError(error.InvalidAssignmentLevels, inspect(&.{1}, 2));
    try std.testing.expectError(error.InvalidAssignmentLevels, inspect(&.{3}, 2));
    try std.testing.expectError(error.AssignmentRunTooLarge, inspect(&.{}, @as(usize, std.math.maxInt(u32)) + 1));
}
test "histogram reports actual widths without inferring them from average" {
    const s = try inspect(&.{ 0, 1, 33, 66, 130, 195, 323, 452, 708, 965 }, 965);
    try std.testing.expectEqual(@as(usize, 1), s.empty);
    try std.testing.expectEqual(@as(usize, 2), s.width_1_32);
    try std.testing.expectEqual(@as(usize, 2), s.width_33_64);
    try std.testing.expectEqual(@as(usize, 2), s.width_65_128);
    try std.testing.expectEqual(@as(usize, 2), s.width_129_256);
    try std.testing.expectEqual(@as(usize, 1), s.width_gt256);
}
test "host grouping preserves dependency chain values across broad barriers" {
    const ends = [_]usize{ 0, 1, 2, 131, 132, 133 };
    var p = try Plan.init(std.testing.allocator, &ends, 133);
    defer p.deinit();
    var original: [134]u64 = @splat(0);
    original[0] = 7;
    var prior: usize = 0;
    for (ends) |end| {
        const dependency = prior; // Last output of a STRICTLY earlier level.
        for (prior..end) |task| original[task + 1] = original[dependency] + task + 3;
        prior = end;
    }
    var grouped: [134]u64 = @splat(0);
    grouped[0] = 7;
    for (p.runs) |r| {
        var begin: usize = r.first_task;
        for (p.ends[r.first_level .. r.first_level + r.level_count]) |end| {
            const dependency = begin;
            for (begin..end) |task| grouped[task + 1] = grouped[dependency] + task + 3;
            begin = end;
        }
    }
    try std.testing.expectEqualSlices(u64, &original, &grouped);
}

test "narrow grouping opt-in is explicit and defaults off" {
    try std.testing.expect(!try parseOptIn(null));
    try std.testing.expect(!try parseOptIn("0"));
    try std.testing.expect(try parseOptIn("1"));
    for ([_][]const u8{ "", "true", "2" }) |bad| try std.testing.expectError(error.InvalidAssignmentNarrowRunOption, parseOptIn(bad));
}

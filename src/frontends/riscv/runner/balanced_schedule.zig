//! Exact nonempty execution partitions. V1 binary roots require a power-of-two
//! leaf count; V2 forests may use the exact count. Preflight establishes total
//! cycles; proof replay authenticates every boundary and completion separately.
const std = @import("std");
pub const Schedule = struct {
    cycles: u64,
    segments: u32,
    terminal_cycles: u32 = 0,
    /// Borrowed explicit budgets. The caller keeps this slice alive throughout replay.
    explicit_budgets: ?[]const u32 = null,
    pub fn initExplicit(cycles: u64, maximum: u32, required_terminal: u64, budgets: []const u32) !Schedule {
        if (!std.math.isPowerOfTwo(budgets.len)) return error.InvalidSegmentSchedule;
        return initExplicitExact(cycles, maximum, required_terminal, budgets);
    }
    /// Versioned exact-count path. The older binary-root protocol continues
    /// to call `initExplicit` and retain its power-of-two slot contract.
    pub fn initExplicitExact(cycles: u64, maximum: u32, required_terminal: u64, budgets: []const u32) !Schedule {
        if (cycles == 0 or maximum == 0 or budgets.len == 0) return error.InvalidSegmentSchedule;
        const segments = std.math.cast(u32, budgets.len) orelse return error.InvalidSegmentSchedule;
        var sum: u64 = 0;
        for (budgets) |amount| {
            if (amount == 0 or amount > maximum) return error.InvalidSegmentSchedule;
            sum = try std.math.add(u64, sum, amount);
        }
        if (sum != cycles) return error.InvalidSegmentSchedule;
        if (required_terminal == 0 or required_terminal > budgets[budgets.len - 1]) return error.InvalidTerminalSuffix;
        return .{ .cycles = cycles, .segments = segments, .explicit_budgets = budgets };
    }
    pub fn init(cycles: u64, max_segment_cycles: u32) !Schedule {
        const exact = try initExact(cycles, max_segment_cycles);
        const segments = try std.math.ceilPowerOfTwo(u64, exact.segments);
        if (segments > std.math.maxInt(u32) or segments > cycles) return error.InvalidSegmentSchedule;
        return .{ .cycles = cycles, .segments = @intCast(segments) };
    }
    pub fn initExact(cycles: u64, max_segment_cycles: u32) !Schedule {
        if (cycles == 0 or max_segment_cycles == 0) return error.InvalidSegmentSchedule;
        const needed = try std.math.divCeil(u64, cycles, max_segment_cycles);
        if (needed > std.math.maxInt(u32) or needed > cycles) return error.InvalidSegmentSchedule;
        return .{ .cycles = cycles, .segments = @intCast(needed) };
    }
    /// Keep every last output access in the final proof leaf. Earlier leaves
    /// stay balanced, nonempty and within the same caller-supplied cycle bound.
    pub fn initWithTerminalSuffix(cycles: u64, max_segment_cycles: u32, required: u64) !Schedule {
        return withTerminalSuffix(try init(cycles, max_segment_cycles), max_segment_cycles, required);
    }
    pub fn initExactWithTerminalSuffix(cycles: u64, max_segment_cycles: u32, required: u64) !Schedule {
        return withTerminalSuffix(try initExact(cycles, max_segment_cycles), max_segment_cycles, required);
    }
    fn withTerminalSuffix(initial: Schedule, max_segment_cycles: u32, required: u64) !Schedule {
        const cycles = initial.cycles;
        if (required == 0 or required > cycles) return error.InvalidTerminalSuffix;
        var result = initial;
        if (required > max_segment_cycles) return error.TerminalPublicationExceedsSegmentBudget;
        if (required <= try result.budget(result.segments - 1)) return result;
        if (cycles - required < result.segments - 1) return error.InvalidTerminalSuffix;
        result.terminal_cycles = @intCast(required);
        return result;
    }
    pub fn budget(self: Schedule, index: u32) !u32 {
        if (index >= self.segments) return error.InvalidSegmentIndex;
        if (self.explicit_budgets) |budgets| return budgets[index];
        if (self.terminal_cycles != 0 and index == self.segments - 1) return self.terminal_cycles;
        const count = self.segments - @intFromBool(self.terminal_cycles != 0);
        const cycles = self.cycles - self.terminal_cycles;
        return std.math.cast(u32, cycles / count + @intFromBool(index < cycles % count)) orelse error.InvalidSegmentSchedule;
    }
    pub fn firstCycle(self: Schedule, index: u32) !u64 {
        if (index >= self.segments) return error.InvalidSegmentIndex;
        if (self.explicit_budgets) |budgets| {
            var first: u64 = 1;
            for (budgets[0..index]) |amount| first += amount;
            return first;
        }
        if (self.terminal_cycles != 0 and index == self.segments - 1) return self.cycles - self.terminal_cycles + 1;
        const count = self.segments - @intFromBool(self.terminal_cycles != 0);
        const cycles = self.cycles - self.terminal_cycles;
        return 1 + cycles / count * index + @min(index, cycles % count);
    }
};
test "balanced execution schedule covers every cycle with nonempty binary leaves" {
    for ([_]u64{ 1, 3, 8, 17, 65537, 1630632307 }) |cycles| {
        for ([_]u32{ 2, 17, 65536, 4194304 }) |limit| {
            const schedule = try Schedule.init(cycles, limit);
            try std.testing.expect(std.math.isPowerOfTwo(schedule.segments));
            if (schedule.segments > 65536) {
                const last = schedule.segments - 1;
                try std.testing.expectEqual(cycles, try schedule.firstCycle(last) - 1 + try schedule.budget(last));
                for ([_]u32{ 0, 1, schedule.segments / 2, last }) |index| {
                    const amount = try schedule.budget(index);
                    try std.testing.expect(amount > 0 and amount <= limit);
                }
                continue;
            }
            var sum: u64 = 0;
            for (0..schedule.segments) |index| {
                const i: u32 = @intCast(index);
                const budget = try schedule.budget(i);
                try std.testing.expect(budget > 0 and budget <= limit);
                try std.testing.expectEqual(sum + 1, try schedule.firstCycle(i));
                sum += budget;
            }
            try std.testing.expectEqual(cycles, sum);
            try std.testing.expectError(error.InvalidSegmentIndex, schedule.budget(schedule.segments));
        }
    }
}
test "balanced execution schedule rejects impossible and overflowing geometry" {
    try std.testing.expectError(error.InvalidSegmentSchedule, Schedule.init(0, 1));
    try std.testing.expectError(error.InvalidSegmentSchedule, Schedule.init(1, 0));
    try std.testing.expectError(error.InvalidSegmentSchedule, Schedule.init(3, 1));
    try std.testing.expectError(error.InvalidSegmentSchedule, Schedule.init(std.math.maxInt(u64), 2));
}

test "terminal publication scheduling preserves bounds and exact coverage" {
    for (1..129) |cycles| for (2..33) |limit| {
        for (1..@min(cycles, limit) + 1) |required| {
            const schedule = Schedule.initWithTerminalSuffix(cycles, @intCast(limit), required) catch |err| {
                if (err == error.InvalidTerminalSuffix) continue;
                return err;
            };
            var sum: u64 = 0;
            for (0..schedule.segments) |i| {
                try std.testing.expectEqual(sum + 1, try schedule.firstCycle(@intCast(i)));
                const amount = try schedule.budget(@intCast(i));
                try std.testing.expect(amount > 0 and amount <= limit);
                sum += amount;
            }
            try std.testing.expectEqual(@as(u64, cycles), sum);
            try std.testing.expect(try schedule.budget(schedule.segments - 1) >= required);
        }
    };
    const adjusted = try Schedule.initWithTerminalSuffix(18, 5, 5);
    try std.testing.expectEqual(@as(u32, 4), adjusted.segments);
    for ([_]u32{ 5, 4, 4, 5 }, 0..) |amount, i| try std.testing.expectEqual(amount, try adjusted.budget(@intCast(i)));
    try std.testing.expectEqualDeep(try Schedule.init(21635, 2048), try Schedule.initWithTerminalSuffix(21635, 2048, 500));
    try std.testing.expectError(error.TerminalPublicationExceedsSegmentBudget, Schedule.initWithTerminalSuffix(18, 5, 6));
    try std.testing.expectError(error.InvalidTerminalSuffix, Schedule.initWithTerminalSuffix(18, 5, 0));
}

test "explicit work budgets preserve all cycles and terminal publication" {
    const budgets = [_]u32{ 3, 9, 5, 7 };
    const schedule = try Schedule.initExplicit(24, 9, 7, &budgets);
    for ([_]u64{ 1, 4, 13, 18 }, 0..) |first, i| {
        try std.testing.expectEqual(first, try schedule.firstCycle(@intCast(i)));
        try std.testing.expectEqual(budgets[i], try schedule.budget(@intCast(i)));
    }
    try std.testing.expectError(error.InvalidSegmentIndex, schedule.budget(4));
    try std.testing.expectError(error.InvalidSegmentSchedule, Schedule.initExplicit(25, 9, 7, &budgets));
    try std.testing.expectError(error.InvalidSegmentSchedule, Schedule.initExplicit(24, 8, 7, &budgets));
    try std.testing.expectError(error.InvalidSegmentSchedule, Schedule.initExplicit(3, 3, 1, &.{ 0, 3 }));
    try std.testing.expectError(error.InvalidSegmentSchedule, Schedule.initExplicit(3, 3, 1, &.{ 1, 1, 1 }));
    try std.testing.expectError(error.InvalidTerminalSuffix, Schedule.initExplicit(24, 9, 8, &budgets));
}

test "exact schedule retains three real segments and an unequal terminal suffix" {
    const exact = try Schedule.initExactWithTerminalSuffix(23, 9, 7);
    try std.testing.expectEqual(@as(u32, 3), exact.segments);
    var total: u64 = 0;
    for (0..exact.segments) |index| {
        const i: u32 = @intCast(index);
        try std.testing.expectEqual(total + 1, try exact.firstCycle(i));
        total += try exact.budget(i);
    }
    try std.testing.expectEqual(@as(u64, 23), total);
    const explicit = try Schedule.initExplicitExact(23, 9, 7, &.{ 9, 7, 7 });
    try std.testing.expectEqual(@as(u32, 3), explicit.segments);
    try std.testing.expectError(error.InvalidSegmentSchedule, Schedule.initExplicit(23, 9, 7, &.{ 9, 7, 7 }));
}

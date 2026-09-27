//! Optional borrowed work-based schedule, validated against full execution preflight.
const std = @import("std");
const Schedule = @import("balanced_schedule.zig").Schedule;
pub const Owned = struct {
    parsed: std.json.Parsed([]u32),
    pub fn read(a: std.mem.Allocator, path: []const u8) !Owned {
        const bytes = try std.fs.cwd().readFileAlloc(a, path, 1024 * 1024);
        defer a.free(bytes);
        return .{ .parsed = try std.json.parseFromSlice([]u32, a, bytes, .{ .allocate = .alloc_always }) };
    }
    pub fn deinit(self: *Owned) void {
        self.parsed.deinit();
        self.* = undefined;
    }
    pub fn schedule(self: *const Owned, cycles: u64, maximum: u32, required_terminal: u64) !Schedule {
        return Schedule.initExplicit(cycles, maximum, required_terminal, self.parsed.value);
    }
    pub fn scheduleExact(self: *const Owned, cycles: u64, maximum: u32, required_terminal: u64) !Schedule {
        return Schedule.initExplicitExact(cycles, maximum, required_terminal, self.parsed.value);
    }
};

//! Operational controls only; none select proof statements or transcript data.
const std = @import("std");
pub const Options = struct {
    count: usize,
    jobs: ?u8 = null,
    batch: u32 = 64,
    batch_set: bool = false,
    keep_capture_cache: bool = false,
    keep_fixed_witness: bool = false,
    retained_cpu_lde: bool = false,
    pub fn parse(args: []const [:0]u8) !Options {
        var out = Options{ .count = args.len };
        while (out.count > 1) {
            const arg = args[out.count - 1];
            if (std.mem.startsWith(u8, arg, "--proof-jobs=")) {
                if (out.jobs != null) return error.DuplicateOperationalOption;
                out.jobs = try std.fmt.parseUnsigned(u8, arg[13..], 10);
                if (out.jobs.? == 0 or out.jobs.? > 2) return error.InvalidServiceSchedule;
            } else if (std.mem.startsWith(u8, arg, "--commit-batch-columns=")) {
                if (out.batch_set) return error.DuplicateOperationalOption;
                out.batch_set = true;
                out.batch = try std.fmt.parseUnsigned(u32, arg[23..], 10);
                if (out.batch == 0) return error.InvalidStreamingBatchSize;
            } else if (std.mem.eql(u8, arg, "--retained-cpu-lde")) {
                if (out.retained_cpu_lde) return error.DuplicateOperationalOption;
                out.retained_cpu_lde = true;
            } else if (std.mem.eql(u8, arg, "--keep-capture-cache")) {
                if (out.keep_capture_cache) return error.DuplicateOperationalOption;
                out.keep_capture_cache = true;
            } else if (std.mem.eql(u8, arg, "--keep-fixed-witness")) {
                if (out.keep_fixed_witness) return error.DuplicateOperationalOption;
                out.keep_fixed_witness = true;
            } else break;
            out.count -= 1;
        }
        return out;
    }
    pub fn schedule(self: Options, workers: usize) !@import("../services/schedule.zig").Policy {
        if (workers == 0 or workers > 32) return error.InvalidWorkerBudget;
        const jobs = self.jobs orelse @as(u8, @intCast(@min(2, workers)));
        if (jobs > workers) return error.InvalidWorkerBudget;
        return .{ .lanes = jobs, .workers_per_lane = @intCast(workers / jobs) };
    }
    pub fn producerOnly(self: Options) bool {
        return self.jobs != null or self.batch_set or self.keep_capture_cache or self.retained_cpu_lde;
    }
};
test "operational jobs and batch parsing cannot silently broaden the worker budget" {
    const args = [_][:0]const u8{ "tool", "produce", "--proof-jobs=2", "--commit-batch-columns=8" };
    var mutable: [args.len][:0]u8 = undefined;
    for (args, &mutable) |value, *target| target.* = @constCast(value);
    const options = try Options.parse(&mutable);
    try std.testing.expectEqual(@as(usize, 2), options.count);
    try std.testing.expectEqual(@as(u32, 8), options.batch);
    try std.testing.expectError(error.InvalidWorkerBudget, options.schedule(1));
    try std.testing.expectEqual(@as(u8, 8), (try options.schedule(16)).workers_per_lane);
}

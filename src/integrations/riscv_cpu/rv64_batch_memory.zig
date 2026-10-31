//! Optional process-wide RSS observations during one proving invocation.
//! Sampling is a lower bound on the interval peak, not allocator ownership or
//! GPU residency. The OS lifetime high-water mark is deliberately separate.
const std = @import("std");
const builtin = @import("builtin");

pub const Report = struct {
    scope: []const u8 = "provePrepared entry through receipt writing and stage snapshot; excludes native capture, packet decode and final publication",
    method: []const u8 = "process RSS sampled every 10ms; peak is an observed lower bound",
    target_bytes: u64 = 16_000_000_000,
    interval_ns: u64 = 10 * std.time.ns_per_ms,
    baseline_rss_bytes: ?u64 = null,
    last_rss_bytes: ?u64 = null,
    sampled_peak_rss_bytes: ?u64 = null,
    process_lifetime_peak_rss_bytes: ?u64 = null,
    samples: u64 = 0,
    failed_samples: u64 = 0,
};

/// Must stay at a stable address from start until finish. Only the sampling
/// thread writes report while running; the caller reads it after join.
pub const Sampler = struct {
    report: Report = .{},
    stop: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,

    pub fn start(self: *Sampler) !void {
        self.observe();
        self.report.baseline_rss_bytes = self.report.last_rss_bytes;
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    pub fn finish(self: *Sampler) Report {
        self.stop.store(true, .release);
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
            self.observe();
            const usage = std.posix.getrusage(0);
            if (usage.maxrss >= 0) self.report.process_lifetime_peak_rss_bytes = @as(u64, @intCast(usage.maxrss)) * (if (builtin.os.tag == .macos) @as(u64, 1) else 1024);
        }
        return self.report;
    }

    fn run(self: *Sampler) void {
        while (!self.stop.load(.acquire)) {
            std.Thread.sleep(self.report.interval_ns);
            if (!self.stop.load(.acquire)) self.observe();
        }
    }

    fn observe(self: *Sampler) void {
        const bytes = currentRss() catch {
            self.report.failed_samples += 1;
            return;
        };
        self.report.samples += 1;
        self.report.last_rss_bytes = bytes;
        self.report.sampled_peak_rss_bytes = @max(self.report.sampled_peak_rss_bytes orelse 0, bytes);
    }
};

fn currentRss() !u64 {
    switch (builtin.os.tag) {
        .macos => {
            var info: std.c.mach_task_basic_info = undefined;
            var count: u32 = std.c.MACH_TASK_BASIC_INFO_COUNT;
            if (std.c.task_info(std.c.mach_task_self(), std.c.MACH_TASK_BASIC_INFO, @ptrCast(&info), &count) != 0 or count != std.c.MACH_TASK_BASIC_INFO_COUNT) return error.RssUnavailable;
            return info.resident_size;
        },
        .linux => {
            var file = try std.fs.openFileAbsolute("/proc/self/statm", .{});
            defer file.close();
            var buffer: [256]u8 = undefined;
            const n = try file.read(&buffer);
            var words = std.mem.tokenizeAny(u8, buffer[0..n], " \t\n");
            _ = words.next() orelse return error.RssUnavailable;
            const pages = try std.fmt.parseInt(u64, words.next() orelse return error.RssUnavailable, 10);
            return std.math.mul(u64, pages, std.heap.pageSize());
        },
        else => return error.RssUnavailable,
    }
}

/// Preserve existing stage JSON fields, adding only a sibling memory object.
pub fn WithMemory(comptime Profile: type) type {
    return struct {
        profile: Profile,
        memory: Report,
        pub fn jsonStringify(self: @This(), writer: anytype) !void {
            try writer.beginObject();
            inline for (@typeInfo(Profile).@"struct".fields) |field| {
                try writer.objectField(field.name);
                try writer.write(@field(self.profile, field.name));
            }
            try writer.objectField("memory");
            try writer.write(self.memory);
            try writer.endObject();
        }
    };
}

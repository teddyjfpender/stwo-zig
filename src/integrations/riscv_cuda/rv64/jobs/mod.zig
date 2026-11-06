//! M8 job runtime entry. `combined-serve` routes here when STWO_RV64_M8_JOBS=1
//! (rv64_combined_ethereum_main.zig); unset or "0" keeps today's path unchanged.
//!
//! Environment (job path only):
//!   STWO_RV64_M8_JOBS_LIBRARY        libstwo-rv64-jobs.so (addon, required)
//!   STWO_RV64_GPU_DEVICES            device ordinals, e.g. "0,1" (default "0")
//!   STWO_RV64_M8_JOBS_ARENA_BYTES    static arena per GPU (default 8 GiB; §3.7 hook)
//!   STWO_RV64_M8_JOBS_PINNED_BYTES   pinned bytes per pipeline slot (default 256 MiB)
//!   STWO_RV64_M8_JOBS_PLAN_OUT       write measured per-class plans (JSON) at stop (§3.7 sweep input)
const std = @import("std");
pub const api = @import("api.zig");
pub const worker = @import("worker.zig");
pub const ops = @import("ops.zig");
pub const channel = @import("channel.zig");
pub const slab = @import("slab.zig");
pub const scheduler = @import("scheduler.zig");
pub const request = @import("request.zig");
pub const channel_parity = @import("channel_parity.zig");

/// STWO_RV64_M8_JOBS: unset or "0" → legacy path; "1" → job runtime; else fail closed.
pub fn selected() !bool {
    const value = std.posix.getenv("STWO_RV64_M8_JOBS") orelse return false;
    if (std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    return error.InvalidM8JobsSelection;
}

fn envBytes(name: []const u8, default: usize) !usize {
    const text = std.posix.getenv(name) orelse return default;
    return std.fmt.parseUnsigned(usize, text, 10) catch error.InvalidM8JobsEnvironment;
}

pub const Config = struct {
    devices: [8]u32 = undefined,
    device_count: usize = 0,
    arena_words: usize,
    pinned_slot_words: usize,
    pub fn fromEnv() !Config {
        var c = Config{
            .arena_words = std.mem.alignBackward(usize, try envBytes("STWO_RV64_M8_JOBS_ARENA_BYTES", 8 << 30) / 4, worker.Arena.granule),
            .pinned_slot_words = try envBytes("STWO_RV64_M8_JOBS_PINNED_BYTES", 256 << 20) / 4,
        };
        var it = std.mem.tokenizeScalar(u8, std.posix.getenv("STWO_RV64_GPU_DEVICES") orelse "0", ',');
        while (it.next()) |d| {
            if (c.device_count == c.devices.len) return error.InvalidM8JobsEnvironment;
            c.devices[c.device_count] = std.fmt.parseUnsigned(u32, std.mem.trim(u8, d, " "), 10) catch return error.InvalidM8JobsEnvironment;
            c.device_count += 1;
        }
        if (c.device_count == 0 or c.arena_words == 0 or c.pinned_slot_words == 0) return error.InvalidM8JobsEnvironment;
        return c;
    }
};

/// The request provider (capture + native/truth/outer job factories + seal +
/// publication). Integrated here as the native-job and outer-job streams land.
fn provider(_: std.mem.Allocator, _: []const *worker.Worker) !request.Provider {
    std.log.err("STWO_RV64_M8_JOBS=1: the job runtime booted, but the native/outer job providers have not landed yet", .{});
    return error.M8RequestProviderNotLanded;
}

const Boot = struct {
    result: ?anyerror!void = null,
    receipt: api.Receipt = .{},
    fn done(raw: *anyopaque, c: api.Completion) void {
        const self: *Boot = @ptrCast(@alignCast(raw));
        self.receipt = c.receipt;
        self.result = c.result;
    }
};

/// Boot self-test: the channel parity job (every op kind incl. PoW) on each
/// worker before READY, so a broken addon/base pairing fails at start.
fn selfTest(a: std.mem.Allocator, workers: []const *worker.Worker) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const script = try channel_parity.coverageScript(arena.allocator(), true);
    for (workers) |w| {
        var job = try channel_parity.ParityJob.init(script);
        var boot: Boot = .{};
        try w.submit(api.Job.from(channel_parity.ParityJob, &job), .{ .ctx = &boot, .done = Boot.done });
        while (w.load() != 0) std.Thread.sleep(100 * std.time.ns_per_us);
        try boot.result.?;
        std.debug.print("GPU_M8_JOBS boot_parity device={} ops={} wait_ns={} host_waits={}\n", .{ boot.receipt.device, job.checked_ops, boot.receipt.wait_ns, boot.receipt.host_waits });
    }
}

/// Host-side helpers composed OUTSIDE rv64/jobs/ (their import closures reach
/// legacy owner-path files, which the sync lint forbids under jobs/). The
/// combined-serve entry passes them in; jobs/ code only calls the pointers,
/// in pre-stage/stage, never from enqueue. Typed as each provider lands.
pub const Hooks = struct {
    /// outer-job pre-stage (host graph/tape preparation ahead of phase 1).
    outer_prestage: ?*const anyopaque = null,
    outer_prestage_ctx: ?*anyopaque = null,
};

/// The job runtime's devices: libraries + one booted, self-tested worker per
/// STWO_RV64_GPU_DEVICES entry. Usable by any entry (serve, or a legacy entry
/// that hands workers to job-backed factories).
pub const WorkerSet = struct {
    libs: ops.Libraries,
    workers: [8]*worker.Worker = undefined,
    count: usize = 0,
    /// Heap-pinned so `libs.ops` (referenced by every worker) never moves.
    pub fn start(a: std.mem.Allocator, library: []const u8) !*WorkerSet {
        const addon = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return error.MissingM8JobsLibrary;
        const config = try Config.fromEnv();
        const self = try a.create(WorkerSet);
        errdefer a.destroy(self);
        self.* = .{ .libs = try ops.Libraries.open(library, addon) };
        errdefer self.stopWorkers();
        for (config.devices[0..config.device_count]) |device| {
            self.workers[self.count] = try worker.Worker.create(a, &self.libs.ops, .{ .device = device, .arena_words = config.arena_words, .pinned_slot_words = config.pinned_slot_words });
            self.count += 1;
        }
        try selfTest(a, self.slice());
        return self;
    }
    pub fn slice(self: *WorkerSet) []const *worker.Worker {
        return self.workers[0..self.count];
    }
    fn stopWorkers(self: *WorkerSet) void {
        for (self.workers[0..self.count]) |w| w.destroy();
        self.count = 0;
        self.libs.close();
    }
    pub fn stop(self: *WorkerSet, a: std.mem.Allocator) void {
        if (std.posix.getenv("STWO_RV64_M8_JOBS_PLAN_OUT")) |path| writePlans(a, self.slice(), path) catch |err| std.log.err("M8 class plan output failed: {s}", .{@errorName(err)});
        self.stopWorkers();
        a.destroy(self);
    }
};

pub fn serve(a: std.mem.Allocator, library: []const u8, manifest_path: []const u8, spool: []const u8, hooks: Hooks) !void {
    _ = hooks;
    _ = manifest_path; // the provider reads the manifest (blocks, profile) when it lands
    var timer = try std.time.Timer.start();
    const set = try WorkerSet.start(a, library);
    defer set.stop(a);
    const p = try provider(a, set.slice());
    try request.serve(a, p, set.slice(), spool, timer.read());
}

/// Measured class plans of every worker (declared vs measured peak words).
pub fn writePlans(a: std.mem.Allocator, workers: []const *worker.Worker, path: []const u8) !void {
    const Row = struct { device: u32, class_key: [64]u8, stat: worker.ClassStat };
    var rows: std.ArrayListUnmanaged(Row) = .empty;
    defer rows.deinit(a);
    for (workers) |w| {
        const stats = try w.classStats(a);
        defer a.free(stats);
        for (stats) |e| try rows.append(a, .{ .device = w.device_ordinal, .class_key = std.fmt.bytesToHex(e.key, .lower), .stat = e.stat });
    }
    var text: std.Io.Writer.Allocating = .init(a);
    defer text.deinit();
    try std.json.Stringify.value(.{ .schema = "rv64-m8-jobs-class-plans/v1", .classes = rows.items }, .{ .whitespace = .indent_1 }, &text.writer);
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = text.written() });
}

test "selection is explicit and fails closed" {
    // The test process environment does not set STWO_RV64_M8_JOBS.
    try std.testing.expect(!(try selected()));
}

test "service entry points are analyzed" {
    _ = &serve;
    _ = &WorkerSet.start;
    _ = &WorkerSet.stop;
}

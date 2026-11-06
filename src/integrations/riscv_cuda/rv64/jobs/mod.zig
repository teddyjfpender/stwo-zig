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

pub fn serve(a: std.mem.Allocator, library: []const u8, manifest_path: []const u8, spool: []const u8) !void {
    _ = manifest_path; // the provider reads the manifest (blocks, profile) when it lands
    var timer = try std.time.Timer.start();
    const addon = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return error.MissingM8JobsLibrary;
    const config = try Config.fromEnv();
    var libs = try ops.Libraries.open(library, addon);
    defer libs.close();
    var workers: [8]*worker.Worker = undefined;
    var made: usize = 0;
    defer for (workers[0..made]) |w| w.destroy();
    for (config.devices[0..config.device_count]) |device| {
        workers[made] = try worker.Worker.create(a, &libs.ops, .{ .device = device, .arena_words = config.arena_words, .pinned_slot_words = config.pinned_slot_words });
        made += 1;
    }
    defer if (std.posix.getenv("STWO_RV64_M8_JOBS_PLAN_OUT")) |path| writePlans(a, workers[0..made], path) catch |err| std.log.err("M8 class plan output failed: {s}", .{@errorName(err)});
    try selfTest(a, workers[0..made]);
    const p = try provider(a, workers[0..made]);
    try request.serve(a, p, workers[0..made], spool, timer.read());
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

//! M8 job runtime entry. `combined-serve` routes here when STWO_RV64_M8_JOBS=1
//! (rv64_combined_ethereum_main.zig); unset or "0" keeps today's path unchanged.
//!
//! Environment (job path only):
//!   STWO_RV64_M8_JOBS_LIBRARY        libstwo-rv64-jobs.so (addon, required)
//!   STWO_RV64_GPU_DEVICES            device ordinals, e.g. "0,1" (default "0")
//!   STWO_RV64_M8_JOBS_ARENA_BYTES    static arena per GPU (default 8 GiB; §3.7 hook)
//!   STWO_RV64_M8_JOBS_PINNED_BYTES   pinned bytes per pipeline slot (default 256 MiB)
//!   STWO_RV64_M8_JOBS_PLAN_OUT       write measured per-class plans (JSON) at stop (§3.7 sweep input)
//!   STWO_RV64_M8_JOBS_PINNED_LAZY    "1": pinned slots allocated on first need, grow-only, capped at
//!                                    STWO_RV64_M8_JOBS_PINNED_BYTES (default "0" = eager; persistent sets default 1)
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

fn envFlag(name: []const u8, default: bool) !bool {
    const text = std.posix.getenv(name) orelse return default;
    if (std.mem.eql(u8, text, "1")) return true;
    if (std.mem.eql(u8, text, "0")) return false;
    return error.InvalidM8JobsEnvironment;
}

pub const Config = struct {
    devices: [8]u32 = undefined,
    device_count: usize = 0,
    arena_words: usize,
    pinned_slot_words: usize,
    /// worker.Config.pinned_lazy (grow-only pinned slots; `pinned_slot_words` is the cap).
    pinned_lazy: bool = false,
    /// worker.Config.reuse_frees (non-LIFO frees reclaimed; native-hybrid).
    reuse_frees: bool = false,
    pub fn fromEnv() !Config {
        var c = Config{
            .arena_words = std.mem.alignBackward(usize, try envBytes("STWO_RV64_M8_JOBS_ARENA_BYTES", 8 << 30) / 4, worker.Arena.granule),
            .pinned_slot_words = try envBytes("STWO_RV64_M8_JOBS_PINNED_BYTES", 256 << 20) / 4,
            .pinned_lazy = try envFlag("STWO_RV64_M8_JOBS_PINNED_LAZY", false),
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

pub const feeder = @import("provider.zig");

/// The scheduler-driven request provider (capture + job factories + seal +
/// publication as one scheduler graph). STWO_RV64_M8_JOBS=1 today runs the
/// request FEEDER instead (provider.zig + rv64/m8_feeder.zig: the resident
/// service with every proof a job, legacy orchestration as the driver), and
/// combined-serve no longer reaches `serve`. This DAG provider stays fail-
/// closed until the coordinator's capture/seal move under the scheduler.
fn provider(_: std.mem.Allocator, _: []const *worker.Worker) !request.Provider {
    std.log.err("STWO_RV64_M8_JOBS=1 via jobs.serve: the scheduler-driven request DAG is not implemented; combined-serve runs the M8 feeder (rv64/m8_feeder.zig)", .{});
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
        return startWith(a, library, try Config.fromEnv());
    }
    /// As `start`, with an explicit config (hybrid mode sizes the arena from
    /// the measured free process arena; outer_job_factory.zig Hybrid).
    pub fn startWith(a: std.mem.Allocator, library: []const u8, config: Config) !*WorkerSet {
        const addon = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return error.MissingM8JobsLibrary;
        if (config.device_count == 0 or config.arena_words == 0 or config.arena_words % worker.Arena.granule != 0) return error.InvalidM8JobsEnvironment;
        const self = try a.create(WorkerSet);
        errdefer a.destroy(self);
        self.* = .{ .libs = try ops.Libraries.open(library, addon) };
        errdefer self.stopWorkers();
        for (config.devices[0..config.device_count]) |device| {
            self.workers[self.count] = try worker.Worker.create(a, &self.libs.ops, .{ .device = device, .arena_words = config.arena_words, .pinned_slot_words = config.pinned_slot_words, .pinned_lazy = config.pinned_lazy, .reuse_frees = config.reuse_frees });
            self.count += 1;
        }
        try selfTest(a, self.slice());
        return self;
    }
    pub fn slice(self: *WorkerSet) []const *worker.Worker {
        return self.workers[0..self.count];
    }

    // ---- persistent service (runtime-persist; M8-INTERFACES) ----
    // Boot ONCE per process: contexts, streams, events, pinned slots and the
    // boot self-test happen here; per request only the static arena moves
    // (park → the legacy owner may use the memory; unpark → the job window).
    // Persistent class regions and class stats survive a park; captured
    // graphs survive when `Receipt.same_base` (else key them on arenaEpoch).

    /// startWith + park: the set boots on `config.arena_words` (a small boot
    /// arena is enough for the self-test), then releases it. Pinned slots are
    /// lazy (grow-only to what jobs stage) unless STWO_RV64_M8_JOBS_PINNED_LAZY=0.
    pub fn startParked(a: std.mem.Allocator, library: []const u8, config_in: Config) !*WorkerSet {
        var config = config_in;
        config.pinned_lazy = try envFlag("STWO_RV64_M8_JOBS_PINNED_LAZY", true);
        const self = try startWith(a, library, config);
        errdefer self.stop(a);
        _ = try self.park(.{});
        return self;
    }

    pub const Receipt = struct {
        workers: usize = 0,
        /// Wall time of the whole call (workers run their part concurrently).
        ns: u64 = 0,
        max_worker_ns: u64 = 0,
        arena_words: [8]usize = @splat(0),
        same_base: [8]bool = @splat(false),
        epoch: [8]u64 = @splat(0),
    };

    const Op = struct {
        w: *worker.Worker,
        words: usize = 0,
        park: bool,
        options: worker.ParkOptions = .{},
        result: anyerror!worker.ParkReceipt = .{},
        fn run(self: *Op) void {
            self.result = if (self.park) self.w.park(self.options) else self.w.unpark(self.words);
        }
    };

    fn each(self: *WorkerSet, ops_: []Op) !Receipt {
        var timer = try std.time.Timer.start();
        var threads: [8]?std.Thread = @splat(null);
        for (ops_[1..], 1..) |*op, i| threads[i] = std.Thread.spawn(.{}, Op.run, .{op}) catch null;
        for (ops_, 0..) |*op, i| if (threads[i] == null) op.run();
        for (threads[1..ops_.len]) |t| if (t) |th| th.join();
        var r = Receipt{ .workers = self.count };
        var first_err: ?anyerror = null;
        for (ops_, 0..) |op, i| {
            if (op.result) |pr| {
                r.max_worker_ns = @max(r.max_worker_ns, pr.ns);
                r.arena_words[i] = pr.arena_words;
                r.same_base[i] = pr.same_base;
                r.epoch[i] = pr.epoch;
            } else |err| first_err = first_err orelse err;
        }
        r.ns = timer.read();
        if (first_err) |err| return err;
        return r;
    }

    /// Release every worker's static arena (waits for submitted jobs).
    pub fn park(self: *WorkerSet, options: worker.ParkOptions) !Receipt {
        var ops_: [8]Op = undefined;
        for (self.slice(), 0..) |w, i| ops_[i] = .{ .w = w, .park = true, .options = options };
        return self.each(ops_[0..self.count]);
    }

    /// Re-acquire every worker's static arena: `arena_words` for all (0 = the
    /// size before the park).
    pub fn unpark(self: *WorkerSet, arena_words: usize) !Receipt {
        var words: [8]usize = @splat(arena_words);
        return self.unparkEach(words[0..self.count]);
    }

    /// Per-worker arena sizes (index = slice() order).
    pub fn unparkEach(self: *WorkerSet, arena_words: []const usize) !Receipt {
        if (arena_words.len != self.count) return error.InvalidM8JobsEnvironment;
        var ops_: [8]Op = undefined;
        for (self.slice(), arena_words, 0..) |w, words, i| ops_[i] = .{ .w = w, .park = false, .words = words };
        const r = try self.each(ops_[0..self.count]);
        return r;
    }

    pub fn parked(self: *WorkerSet) bool {
        for (self.slice()) |w| if (!w.isParked()) return false;
        return self.count != 0;
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
    _ = &WorkerSet.startWith;
    _ = &WorkerSet.stop;
    _ = &WorkerSet.startParked;
    _ = &WorkerSet.park;
    _ = &WorkerSet.unpark;
    _ = &WorkerSet.unparkEach;
}

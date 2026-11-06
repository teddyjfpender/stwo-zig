//! GPU channel parity for the M8 job runtime (pod test). For every selected
//! device: one DeviceWorker over the frozen base image + libstwo-rv64-jobs.so,
//! a back-to-back batch of ParityJobs (so the 3-stage pipeline, top/bottom
//! alternation and h2d/exec ordering run for real), each comparing every
//! device channel boundary snapshot and draw output with the host
//! Om31Channel word for word. Prints one JSON receipt; exit 1 on any mismatch.
//!
//!   STWO_RV64_GPU_LIBRARY=<base .so> STWO_RV64_M8_JOBS_LIBRARY=<addon .so> \
//!   rv64-jobs-channel-parity [devices=0,1] [rounds=4]
//!
//! `rv64-jobs-channel-parity pipeline <device> <jobs> <upload_mib> <pow_bits>`
//! measures the worker pipeline itself: each job stages `upload_mib` of inputs
//! (h2d stream) and enqueues a device PoW grind (exec stream). Run once with the
//! 3-stage pipeline (depth 3) and once serialized (depth 1: the next job is only
//! submitted after the previous finished), wall clock per arm.
const std = @import("std");
const Raw = @import("stwo_core").channel.raw_mod_m31;
const api = @import("rv64/jobs/api.zig");
const W = @import("rv64/jobs/worker.zig");
const O = @import("rv64/jobs/ops.zig");
const P = @import("rv64/jobs/channel_parity.zig");

const Done = struct {
    mutex: std.Thread.Mutex = .{},
    count: usize = 0,
    failures: usize = 0,
    receipts: std.ArrayListUnmanaged(Row) = .empty,
    a: std.mem.Allocator,
    const Row = struct { device: u32, sequence: u64, placement: []const u8, ok: bool, err: []const u8, stage_ns: u64, enqueue_ns: u64, wait_ns: u64, host_waits: u32, d2h_bytes: u64, staged_words: u64, arena_peak_words: u64 };
    fn sink(self: *Done) W.Sink {
        return .{ .ctx = self, .done = done };
    }
    fn done(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        defer self.mutex.unlock();
        const ok = if (c.result) |_| true else |_| false;
        const err: []const u8 = if (c.result) |_| "" else |e| @errorName(e);
        const r = c.receipt;
        self.receipts.append(self.a, .{ .device = r.device, .sequence = r.sequence, .placement = @tagName(r.placement), .ok = ok, .err = err, .stage_ns = r.stage_ns, .enqueue_ns = r.enqueue_ns, .wait_ns = r.wait_ns, .host_waits = r.host_waits, .d2h_bytes = r.d2h_bytes, .staged_words = r.staged_words, .arena_peak_words = r.arena_peak_words }) catch {};
        if (!ok) self.failures += 1;
        self.count += 1;
    }
};

fn recordedScript(a: std.mem.Allocator, rec: *P.Recorder) !P.Script {
    var host = Raw.Om31Channel.init();
    host.mixU32s(&.{ 0x52563634, 24628607 });
    var observer = rec.observer(&host);
    const previous = Raw.om31_observer;
    Raw.om31_observer = &observer;
    defer Raw.om31_observer = previous;
    var rng = std.Random.DefaultPrng.init(24628607);
    const r = rng.random();
    for (0..12) |round| {
        var words: [8]u32 = undefined;
        for (&words) |*w| w.* = r.int(u32);
        host.mixU32s(&words); // a tree root
        const z = host.drawSecureFelt();
        const alpha = host.drawSecureFelt();
        host.mixFelts(&.{ z, alpha });
        if (round % 3 == 0) {
            const q = try @import("stwo_core").queries.drawQueries(&host, a, 20, 27);
            a.free(q);
        }
        host.mixU64(r.int(u64));
    }
    return rec.script();
}

const Load = struct {
    upload_words: usize,
    bits: u32,
    seed: api.DeviceBuffer = undefined,
    nonce: [2]u32 = .{ 0, 0 },
    pub fn classKey(_: *Load) [32]u8 {
        return @splat(0x4c);
    }
    pub fn footprint(self: *Load) api.Footprint {
        return .{ .device_words = self.upload_words + 4096, .staged_words = self.upload_words + 64, .slab_words = 16, .pinned_words = self.upload_words + 64 };
    }
    pub fn stage(self: *Load, s: *api.Stager) !void {
        const host = try s.pinned(self.upload_words);
        @memset(host, 0x1234_5678);
        host[8] = 0; // seed draws
        const b = try s.alloc(self.upload_words);
        try s.upload(b, host);
        self.seed = try b.slice(0, 9);
    }
    pub fn enqueue(self: *Load, e: *api.Enqueue) !void {
        try e.channel.initFromCheckpoint(self.seed);
        try e.channel.pow(self.bits, try e.slab.device.slice(0, 16));
    }
    pub fn finish(self: *Load, v: api.SlabView) !void {
        self.nonce = v.words[10..12].*;
    }
    pub fn abort(_: *Load) void {}
};

fn pipeline(a: std.mem.Allocator, libs: *O.Libraries, device: u32, count: usize, upload_mib: usize, bits: u32) !void {
    const words = upload_mib << 18;
    const loads = try a.alloc(Load, count);
    defer a.free(loads);
    var results: [2]u64 = undefined;
    var host_waits: [2]u64 = .{ 0, 0 };
    for ([_]usize{ 3, 1 }, 0..) |depth, arm| {
        const w = try W.Worker.create(a, &libs.ops, .{ .device = device, .arena_words = std.mem.alignForward(usize, 2 * words + (1 << 16), 64), .pinned_slot_words = words + 4096, .max_outstanding = depth });
        defer w.destroy();
        var done = Done{ .a = a };
        defer done.receipts.deinit(a);
        for (loads) |*l| l.* = .{ .upload_words = words, .bits = bits };
        // warm-up job (context, arena, pinned pages)
        var warm = Load{ .upload_words = words, .bits = 8 };
        try w.submit(api.Job.from(Load, &warm), done.sink());
        while (w.load() != 0) std.Thread.sleep(50 * std.time.ns_per_us);
        var timer = try std.time.Timer.start();
        for (loads) |*l| while (true) {
            w.submit(api.Job.from(Load, l), done.sink()) catch |err| switch (err) {
                error.WorkerBusy => {
                    std.Thread.sleep(20 * std.time.ns_per_us);
                    continue;
                },
                else => return err,
            };
            break;
        };
        while (w.load() != 0) std.Thread.sleep(20 * std.time.ns_per_us);
        results[arm] = timer.read();
        if (done.failures != 0) return error.PipelineJobFailed;
        for (done.receipts.items) |r| host_waits[arm] += r.host_waits;
    }
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    try std.json.Stringify.value(.{
        .schema = "rv64-m8-jobs-pipeline/v1",
        .device = device,
        .jobs = count,
        .upload_mib = upload_mib,
        .pow_bits = bits,
        .pipelined_depth3_ns = results[0],
        .serialized_depth1_ns = results[1],
        .host_waits = host_waits,
        .scope = "synthetic jobs (h2d upload + device PoW grind); wall clock of the job batch after one warm-up job",
    }, .{ .whitespace = .indent_1 }, &out.writer);
    std.debug.print("{s}\n", .{out.written()});
}

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const a = gpa.allocator();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 6 and std.mem.eql(u8, args[1], "pipeline")) {
        var libs = try O.Libraries.open(std.posix.getenv("STWO_RV64_GPU_LIBRARY") orelse return error.MissingBaseLibrary, std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return error.MissingJobsAddon);
        defer libs.close();
        return pipeline(a, &libs, try std.fmt.parseInt(u32, args[2], 10), try std.fmt.parseInt(usize, args[3], 10), try std.fmt.parseInt(usize, args[4], 10), try std.fmt.parseInt(u32, args[5], 10));
    }
    const base = std.posix.getenv("STWO_RV64_GPU_LIBRARY") orelse return error.MissingBaseLibrary;
    const addon = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return error.MissingJobsAddon;
    const devices_text = if (args.len > 1) args[1] else "0,1";
    const rounds = if (args.len > 2) try std.fmt.parseInt(usize, args[2], 10) else 4;
    var libs = try O.Libraries.open(base, addon);
    defer libs.close();

    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var rec = P.Recorder{ .a = arena };
    const scripts = [_]P.Script{ try P.coverageScript(arena, true), try recordedScript(arena, &rec), try P.coverageScript(arena, false) };

    var done = Done{ .a = a };
    defer done.receipts.deinit(a);
    var workers: std.ArrayListUnmanaged(*W.Worker) = .empty;
    defer workers.deinit(a);
    var it = std.mem.tokenizeScalar(u8, devices_text, ',');
    while (it.next()) |d| {
        const device = try std.fmt.parseInt(u32, d, 10);
        try workers.append(a, try W.Worker.create(a, &libs.ops, .{ .device = device, .arena_words = 1 << 22, .pinned_slot_words = 1 << 20 }));
    }
    const jobs = try arena.alloc(P.ParityJob, workers.items.len * rounds * scripts.len);
    var timer = try std.time.Timer.start();
    var n: usize = 0;
    for (0..rounds) |_| for (scripts) |script| for (workers.items) |w| {
        jobs[n] = try P.ParityJob.init(script);
        while (true) {
            w.submit(api.Job.from(P.ParityJob, &jobs[n]), done.sink()) catch |err| switch (err) {
                error.WorkerBusy => {
                    std.Thread.sleep(50 * std.time.ns_per_us);
                    continue;
                },
                else => return err,
            };
            break;
        }
        n += 1;
    };
    while (true) {
        done.mutex.lock();
        const c = done.count;
        done.mutex.unlock();
        if (c == n) break;
        std.Thread.sleep(std.time.ns_per_ms);
    }
    const wall_ns = timer.read();
    for (workers.items) |w| w.destroy();
    var checked: usize = 0;
    var mismatch: ?usize = null;
    for (jobs[0..n]) |j| {
        checked += j.checked_ops;
        if (j.mismatch_op) |m| mismatch = m;
    }
    var expected_ops: usize = 0;
    for (0..rounds) |_| for (scripts) |s| {
        expected_ops += s.ops.len * workers.items.len;
    };
    const ok = done.failures == 0 and checked == expected_ops;
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    try std.json.Stringify.value(.{
        .schema = "rv64-m8-jobs-channel-parity/v1",
        .ok = ok,
        .jobs = n,
        .failures = done.failures,
        .boundary_snapshots_checked = checked,
        .boundary_snapshots_expected = expected_ops,
        .first_mismatch_op = mismatch,
        .scripts = .{ scripts[0].ops.len, scripts[1].ops.len, scripts[2].ops.len },
        .wall_ns = wall_ns,
        .receipts = done.receipts.items,
        .scope = "device channel op semantics + worker pipeline on real GPUs; not a proof-byte parity claim",
    }, .{ .whitespace = .indent_1 }, &out.writer);
    std.debug.print("{s}\n", .{out.written()});
    if (!ok) std.process.exit(1);
}

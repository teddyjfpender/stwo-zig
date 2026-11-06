//! Request path of the job runtime (`combined-serve` with STWO_RV64_M8_JOBS=1).
//!
//! A `Provider` turns one block request into a scheduler graph: it owns
//! capture and the job factories (native stage-1/2 and truth from stream
//! native-job, leaves/folds from stream outer-job), runs the host seal, and
//! publishes the proof directory exactly as the legacy path does. The runtime
//! owns the workers, the scheduler and the spool protocol (identical to
//! resident_batch.serveSpool: inbox/<name>.request → out/<name>/ +
//! done/<name>.json, READY, STOP).
const std = @import("std");
const api = @import("api.zig");
const W = @import("worker.zig");
const S = @import("scheduler.zig");

pub const Provider = struct {
    ctx: *anyopaque,
    /// Admission: map a request file's text to a block (same rules as legacy).
    admit: *const fn (*anyopaque, []const u8) anyerror!u64,
    /// Build the request graph for `block` into `graph`; returns the factory
    /// and the stage-1 node ids to release as capture hands segments over
    /// (the provider calls `Scheduler.release` from its capture thread).
    begin: *const fn (*anyopaque, u64, *S.Graph, []const *W.Worker, out_dir: []const u8) anyerror!S.Factory,
    /// Called with the running scheduler before `run` (capture thread start).
    started: *const fn (*anyopaque, *S.Scheduler) anyerror!void,
    /// Publish the request outputs after a successful run (proof directory).
    publish: *const fn (*anyopaque, u64, out_dir: []const u8) anyerror!void,
    /// Always called after `begin` (success or failure).
    end: *const fn (*anyopaque) void,
};

/// Serve requests from `spool` until STOP. Device or proof failures are
/// terminal (no fallback), malformed requests are answered and skipped.
pub fn serve(a: std.mem.Allocator, provider: Provider, workers: []const *W.Worker, spool: []const u8, init_ns: u64) !void {
    var dir = try std.fs.cwd().openDir(spool, .{});
    defer dir.close();
    try dir.makePath("inbox");
    try dir.makePath("out");
    try dir.makePath("done");
    {
        const ready = try std.fmt.allocPrint(a, "{{\"schema\":\"rv64-resident-service/v1\",\"pid\":{d},\"init_ns\":{d},\"runtime\":\"m8-jobs\"}}\n", .{ if (@import("builtin").os.tag == .linux) std.os.linux.getpid() else 0, init_ns });
        defer a.free(ready);
        try dir.writeFile(.{ .sub_path = "READY.tmp", .data = ready });
        try dir.rename("READY.tmp", "READY");
    }
    std.debug.print("GPU_RESIDENT_SERVICE ready init_ns={} runtime=m8-jobs workers={}\n", .{ init_ns, workers.len });
    var inbox = try dir.openDir("inbox", .{ .iterate = true });
    defer inbox.close();
    var sequence: u64 = 0;
    var idle = try std.time.Timer.start();
    while (true) {
        var next: ?[]u8 = null;
        defer if (next) |n| a.free(n);
        var stop = false;
        var it = inbox.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (std.mem.eql(u8, entry.name, "STOP")) {
                stop = true;
                continue;
            }
            if (!std.mem.endsWith(u8, entry.name, ".request")) continue;
            if (next == null or std.mem.order(u8, entry.name, next.?) == .lt) {
                if (next) |n| a.free(n);
                next = try a.dupe(u8, entry.name);
            }
        }
        const name = next orelse {
            if (stop) break;
            std.Thread.sleep(5 * std.time.ns_per_ms);
            continue;
        };
        const queue_ns = idle.read();
        const stem = name[0 .. name.len - ".request".len];
        const out = try std.fs.path.join(a, &.{ spool, "out", stem });
        defer a.free(out);
        var buffer: [64]u8 = undefined;
        const admitted: anyerror!u64 = if (inbox.readFile(name, &buffer)) |text| provider.admit(provider.ctx, std.mem.trim(u8, text, " \t\r\n")) else |_| error.ResidentRequestUnreadable;
        const block = admitted catch |err| {
            try answer(a, dir, inbox, name, stem, "{{\"ok\":false,\"error\":\"{s}\",\"sequence\":null}}\n", .{@errorName(err)});
            continue;
        };
        try std.fs.cwd().makePath(out);
        var timer = try std.time.Timer.start();
        try runOne(a, provider, workers, block, out);
        const wall = timer.read();
        try answer(a, dir, inbox, name, stem, "{{\"ok\":true,\"block\":{d},\"sequence\":{d},\"request_wall_ns\":{d},\"queue_ns\":{d},\"runtime\":\"m8-jobs\"}}\n", .{ block, sequence, wall, queue_ns });
        sequence += 1;
        idle.reset();
    }
    std.debug.print("GPU_RESIDENT_SERVICE stop requests={}\n", .{sequence});
}

fn answer(a: std.mem.Allocator, dir: std.fs.Dir, inbox: std.fs.Dir, name: []const u8, stem: []const u8, comptime fmt: []const u8, args: anytype) !void {
    const body = try std.fmt.allocPrint(a, fmt, args);
    defer a.free(body);
    const done_name = try std.fmt.allocPrint(a, "done/{s}.json", .{stem});
    defer a.free(done_name);
    const tmp_name = try std.fmt.allocPrint(a, "done/{s}.tmp", .{stem});
    defer a.free(tmp_name);
    try dir.writeFile(.{ .sub_path = tmp_name, .data = body });
    try inbox.deleteFile(name);
    try dir.rename(tmp_name, done_name);
}

pub fn runOne(a: std.mem.Allocator, provider: Provider, workers: []const *W.Worker, block: u64, out: []const u8) !void {
    var graph = S.Graph{ .a = a };
    defer graph.deinit();
    defer provider.end(provider.ctx);
    const factory = try provider.begin(provider.ctx, block, &graph, workers, out);
    var scheduler = try S.Scheduler.init(a, &graph, factory, workers);
    defer scheduler.deinit();
    try provider.started(provider.ctx, &scheduler);
    var timer = try std.time.Timer.start();
    try scheduler.run();
    const scheduler_ns = timer.read();
    std.debug.print("GPU_M8_JOBS request block={} jobs={} affinity_hits={} scheduler_ns={}\n", .{ block, scheduler.dispatched, scheduler.affinity_hits, scheduler_ns });
    try provider.publish(provider.ctx, block, out);
    try writeReceipt(a, &graph, &scheduler, block, scheduler_ns, out);
}

/// out/m8-jobs.json: per-kind job counts, host waits, D2H bytes and phase times.
/// Diagnostics only (not a proof artifact; the gate's parity ignores it).
pub fn writeReceipt(a: std.mem.Allocator, graph: *const S.Graph, scheduler: *const S.Scheduler, block: u64, scheduler_ns: u64, out: []const u8) !void {
    const Kind = struct { kind: []const u8, jobs: u64 = 0, host_waits: u64 = 0, d2h_bytes: u64 = 0, stage_ns: u64 = 0, enqueue_ns: u64 = 0, wait_ns: u64 = 0, max_arena_peak_words: u64 = 0 };
    var kinds: [std.meta.fields(S.Kind).len]Kind = undefined;
    inline for (std.meta.fields(S.Kind), 0..) |f, i| kinds[i] = .{ .kind = f.name };
    for (graph.nodes.items) |n| {
        if (n.kind == .seal or n.state != .done) continue;
        const k = &kinds[@intFromEnum(n.kind)];
        k.jobs += 1;
        k.host_waits += n.receipt.host_waits;
        k.d2h_bytes += n.receipt.d2h_bytes;
        k.stage_ns += n.receipt.stage_ns;
        k.enqueue_ns += n.receipt.enqueue_ns;
        k.wait_ns += n.receipt.wait_ns;
        k.max_arena_peak_words = @max(k.max_arena_peak_words, n.receipt.arena_peak_words);
    }
    var text: std.Io.Writer.Allocating = .init(a);
    defer text.deinit();
    try std.json.Stringify.value(.{ .schema = "rv64-m8-jobs-request/v1", .block = block, .jobs = scheduler.dispatched, .affinity_hits = scheduler.affinity_hits, .scheduler_ns = scheduler_ns, .kinds = kinds }, .{ .whitespace = .indent_1 }, &text.writer);
    var dir = try std.fs.cwd().openDir(out, .{});
    defer dir.close();
    try dir.writeFile(.{ .sub_path = "m8-jobs.json", .data = text.written() });
}

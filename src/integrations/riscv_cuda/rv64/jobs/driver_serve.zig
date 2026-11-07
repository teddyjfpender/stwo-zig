//! `combined-serve` under STWO_RV64_M8_GPU_NATIVE=1 (requires STWO_RV64_M8_JOBS=1):
//! the GPU-native resident service (rv64-m8-gpu-native.md §1, §3.8; driver).
//!
//! Install (never per request):
//!   1. one warm capture per manifest block (CaptureSource.warm): the native
//!      factory's `shape` derives the block's segment rows and registers its
//!      classes, the recursion factory's `shape` its truths and fold arity;
//!      the recursion topology is the legacy ready_dag carry over
//!      (segments + truths) leaves (driver_dag.Topology.carry);
//!   2. Driver.install (factories warm, class cache sealed, memory plans,
//!      slabs, events);
//!   3. the pinned capture ring and two capture streams (one per in-flight
//!      request; they share the ring).
//! Request (`begin` + `finish`, at most two in flight):
//!   stream.prepare(planned rows) -> CaptureSource.start (capture thread:
//!   Feed.segment per captured segment = pack + seal -> Stage1 released while
//!   capture continues; Feed.end; Feed.finish) -> Driver.begin (enqueues
//!   every job, Stage1s gated on their segment's seal) ... Driver.finish:
//!   ONE host wait, one D2H per GPU, publication (status words, slicing,
//!   factories' publish hooks into out/<stem>/<block>/proof) ->
//!   CaptureSource.join.
//! Spool protocol: the resident service's (resident_batch.serveSpool):
//! READY, inbox/<stem>.request (block number), inbox/STOP, out/<stem>/,
//! done/<stem>.json; plus out/<stem>/m8-jobs.json (the driver receipt:
//! host_waits, d2h, CUDA-event GPU span per device, host plan/make/
//! enqueue/wait/publish ns).
//!
//! This file never imports the CPU integration: the GE capture lives behind
//! `CaptureSource` (driver_ge.zig), so the service is host-tested on the
//! fake device (driver_test.zig "serve" tests).
const std = @import("std");
const G = @import("gpu_native.zig");
const W = @import("worker.zig");
const O = @import("ops.zig");
const R = @import("driver_request.zig");
const D = @import("driver_dag.zig");
const C = @import("../m8_capture_stream.zig");

/// Where captures come from (GE direct capture in the service, a model in tests).
pub const CaptureSource = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        /// Install: one complete capture of `block` (no proving). The
        /// CaptureEnd stays valid until `release_warm(block)`.
        warm: *const fn (*anyopaque, block: u64) anyerror!G.CaptureEnd,
        release_warm: *const fn (*anyopaque, block: u64) void,
        /// Request: start `block`'s capture on a capture thread feeding
        /// `stream` (Stream.feed(): segment / end / finish exactly once).
        start: *const fn (*anyopaque, block: u64, stream: *C.Stream) anyerror!*anyopaque,
        /// After the request finished or failed (the driver detached the
        /// stream, so the capture reported done): join and free the capture.
        join: *const fn (*anyopaque, handle: *anyopaque) void,
    };
};

pub const RingConfig = struct {
    /// Pinned capture buffers and words per buffer (0 buffers = no ring:
    /// the native packer must not ask for one).
    buffers: usize = 0,
    words: usize = 0,
};

pub const Shape = struct {
    block: u64,
    rows: []u64,
    truths: u32,
    fold_arity: u32,
    topology: D.Topology,
};

pub const Pending = struct {
    block: u64,
    request: u64 = 0,
    generation: u64 = 0,
    stream: *C.Stream,
    handle: ?*anyopaque,
    flight: *R.InFlight,
    timer: std.time.Timer,
    begin_ns: u64,
};

pub const Result = struct {
    outcome: R.Outcome,
    /// begin -> finish returned (request wall seen by the service) [M].
    request_wall_ns: u64,
    /// Host time of `begin` (plan, make, enqueue; overlaps capture) [M].
    begin_ns: u64,
};

/// Per-request service hooks of the binding (driver_bind.zig): `publishing`
/// right before the request's finish (the block's recursion topology, for
/// artifact names), `ended` after the driver finished it (published or
/// failed) so every factory drops the request's state.
pub const RequestHooks = struct {
    ctx: *anyopaque,
    publishing: *const fn (*anyopaque, *const D.Topology) void,
    ended: *const fn (*anyopaque, request: u64, generation: u64) void,
};

pub const Service = struct {
    a: std.mem.Allocator,
    hooks: ?RequestHooks = null,
    driver: *R.Driver,
    native: G.NativeFactory,
    recursion: G.RecursionFactory,
    source: CaptureSource,
    shapes: []Shape,
    ring: ?*C.Ring = null,
    streams: [2]*C.Stream,
    busy: [2]bool = .{ false, false },
    next_id: u64 = 1,

    pub fn install(a: std.mem.Allocator, ops: *const O.Ops, peer: *const O.Peer, workers: []const *W.Worker, native: G.NativeFactory, recursion: G.RecursionFactory, source: CaptureSource, blocks: []const u64, config: R.Config, ring_config: RingConfig) !*Service {
        if (blocks.len == 0) return error.GpuNativeServiceNoBlocks;
        const shape_hook = native.vtable.shape orelse return error.GpuNativeNativeShapeHookMissing;
        const rshape_hook = recursion.vtable.shape orelse return error.GpuNativeRecursionShapeHookMissing;
        const shapes = try a.alloc(Shape, blocks.len);
        var made: usize = 0;
        errdefer {
            for (shapes[0..made]) |*s| freeShape(a, s);
            a.free(shapes);
        }
        for (blocks, shapes) |block, *shape| {
            for (shapes[0..made]) |s| if (s.block == block) return error.GpuNativeServiceDuplicateBlock;
            const warm = try source.vtable.warm(source.ctx, block);
            defer source.vtable.release_warm(source.ctx, block);
            const wb = G.WarmBlock{ .block = block, .capture = warm };
            const rows = try shape_hook(native.ctx, a, wb);
            errdefer a.free(rows);
            if (rows.len == 0 or rows.len > config.max_segments) return error.GpuNativeSegmentsExceedPlan;
            if (rows.len != warm.segments) return error.GpuNativeCaptureSegmentCountChanged;
            const keys = try a.alloc(G.ClassKey, rows.len);
            defer a.free(keys);
            // gn-shape: the block-qualified class (rows alone are ambiguous).
            for (rows, keys, 0..) |r, *k, s| k.* = if (native.vtable.class_of_block) |cob| try cob(native.ctx, block, @intCast(s), r) else try native.vtable.class_of(native.ctx, @intCast(s), r);
            const rs = try rshape_hook(recursion.ctx, wb, keys);
            var topo = try D.Topology.carry(a, @intCast(rows.len), rs.truths, rs.fold_arity);
            errdefer topo.deinit();
            shape.* = .{ .block = block, .rows = rows, .truths = rs.truths, .fold_arity = rs.fold_arity, .topology = topo };
            made += 1;
        }
        const driver = try R.Driver.install(a, ops, peer, workers, native, recursion, config);
        errdefer driver.deinit();
        const ring: ?*C.Ring = if (ring_config.buffers != 0) try C.Ring.init(a, &ops.wait, ring_config.buffers, ring_config.words) else null;
        errdefer if (ring) |r| r.deinit();
        const s0 = try C.Stream.create(a, native, ring, config.max_segments);
        errdefer s0.destroy();
        const s1 = try C.Stream.create(a, native, ring, config.max_segments);
        errdefer s1.destroy();
        s0.recursion = recursion;
        s1.recursion = recursion;
        const self = try a.create(Service);
        self.* = .{ .a = a, .driver = driver, .native = native, .recursion = recursion, .source = source, .shapes = shapes, .ring = ring, .streams = .{ s0, s1 } };
        return self;
    }

    /// Teardown after every Pending was finished (serveSpool guarantees it).
    pub fn deinit(self: *Service) void {
        self.driver.deinit();
        if (self.ring) |r| r.close();
        for (self.streams) |s| s.destroy();
        if (self.ring) |r| r.deinit();
        for (self.shapes) |*s| freeShape(self.a, s);
        self.a.free(self.shapes);
        self.a.destroy(self);
    }
    fn freeShape(a: std.mem.Allocator, s: *Shape) void {
        a.free(s.rows);
        s.topology.deinit();
    }

    pub fn shapeOf(self: *const Service, block: u64) ?*const Shape {
        for (self.shapes) |*s| if (s.block == block) return s;
        return null;
    }

    /// Start a request: capture thread + every job enqueued (returns while
    /// the capture still runs; Stage1s follow its sealed segments).
    pub fn begin(self: *Service, block: u64, out: ?std.fs.Dir) !*Pending {
        const shape = self.shapeOf(block) orelse return error.GpuNativeBlockNotWarmed;
        const slot: usize = if (!self.busy[0]) 0 else if (!self.busy[1]) 1 else return error.GpuNativePipelineFull;
        const stream = self.streams[slot];
        const p = try self.a.create(Pending);
        errdefer self.a.destroy(p);
        var timer = try std.time.Timer.start();
        try stream.prepare(shape.rows);
        const handle = self.source.vtable.start(self.source.ctx, block, stream) catch |err| {
            // No capture thread: report its `done` so the epoch closes.
            var f = stream.feed();
            f.finish(err);
            stream.detach();
            return err;
        };
        const req = R.Request{ .id = self.next_id, .segment_rows = shape.rows, .truths = shape.truths, .recursion = shape.topology.nodes, .root = shape.topology.root, .capture = stream, .block = block, .out = out };
        self.next_id += 1;
        // A failed begin detached the capture (cancelled; it reported done):
        // join its thread.
        const flight = self.driver.begin(&req) catch |err| {
            self.source.vtable.join(self.source.ctx, handle);
            // The capture may have handed segments to the factories already.
            if (self.hooks) |h| h.ended(h.ctx, req.id, self.driver.generation);
            return err;
        };
        self.busy[slot] = true;
        p.* = .{ .block = block, .request = req.id, .generation = flight.generation, .stream = stream, .handle = handle, .flight = flight, .timer = timer, .begin_ns = timer.read() };
        return p;
    }

    /// The request's single wait, publication, and the capture's join.
    pub fn finish(self: *Service, p: *Pending) !Result {
        defer {
            for (self.streams, 0..) |s, i| if (s == p.stream) {
                self.busy[i] = false;
            };
            self.a.destroy(p);
        }
        if (self.hooks) |h| if (self.shapeOf(p.block)) |shape| h.publishing(h.ctx, &shape.topology);
        const out = self.driver.finish(p.flight);
        // The driver detached the stream (capture done): join its thread.
        if (p.handle) |h| self.source.vtable.join(self.source.ctx, h);
        if (self.hooks) |h| h.ended(h.ctx, p.request, p.generation);
        return .{ .outcome = try out, .request_wall_ns = p.timer.read(), .begin_ns = p.begin_ns };
    }

    pub fn serve(self: *Service, block: u64, out: ?std.fs.Dir) !Result {
        return self.finish(try self.begin(block, out));
    }
};

// ---------------------------------------------------------------------------
// Spool
// ---------------------------------------------------------------------------

pub const Spool = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    inbox: std.fs.Dir,
    sequence: u64 = 0,
    /// Stems admitted but not yet answered (a scan never re-admits one).
    taken: std.StringHashMapUnmanaged(void) = .empty,

    pub fn open(a: std.mem.Allocator, path: []const u8) !Spool {
        var dir = try std.fs.cwd().openDir(path, .{});
        errdefer dir.close();
        try dir.makePath("inbox");
        try dir.makePath("out");
        try dir.makePath("done");
        const inbox = try dir.openDir("inbox", .{ .iterate = true });
        return .{ .a = a, .dir = dir, .inbox = inbox };
    }
    pub fn close(self: *Spool) void {
        var it = self.taken.keyIterator();
        while (it.next()) |k| self.a.free(k.*);
        self.taken.deinit(self.a);
        self.inbox.close();
        self.dir.close();
    }
    pub fn ready(self: *Spool, init_ns: u64) !void {
        const pid: i64 = if (@import("builtin").os.tag == .linux) std.os.linux.getpid() else 0;
        const text = try std.fmt.allocPrint(self.a, "{{\"schema\":\"rv64-resident-service/v1\",\"runtime\":\"m8-gpu-native\",\"pid\":{d},\"init_ns\":{d}}}\n", .{ pid, init_ns });
        defer self.a.free(text);
        try self.dir.writeFile(.{ .sub_path = "READY.tmp", .data = text });
        try self.dir.rename("READY.tmp", "READY");
    }
    /// `stem` is owned by the spool until `answer`.
    pub const Next = struct { stem: []const u8, block: u64 = 0, err: ?anyerror = null };
    /// The lexicographically first un-admitted request (null: none); sets
    /// `stop` when inbox/STOP exists.
    pub fn next(self: *Spool, stop: *bool) !?Next {
        var best: ?[]u8 = null;
        defer if (best) |b| self.a.free(b);
        var it = self.inbox.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (std.mem.eql(u8, entry.name, "STOP")) {
                stop.* = true;
                continue;
            }
            if (!std.mem.endsWith(u8, entry.name, ".request")) continue;
            const stem = entry.name[0 .. entry.name.len - ".request".len];
            if (stem.len == 0 or stem.len > 200 or self.taken.contains(stem)) continue;
            if (best == null or std.mem.order(u8, stem, best.?) == .lt) {
                if (best) |b| self.a.free(b);
                best = try self.a.dupe(u8, stem);
            }
        }
        const stem = best orelse return null;
        best = null;
        try self.taken.put(self.a, stem, {});
        var name_buf: [256]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "{s}.request", .{stem});
        var buffer: [64]u8 = undefined;
        const raw = self.inbox.readFile(name, &buffer) catch return .{ .stem = stem, .err = error.ResidentRequestUnreadable };
        const block = std.fmt.parseUnsigned(u64, std.mem.trim(u8, raw, " \t\r\n"), 10) catch return .{ .stem = stem, .err = error.ResidentRequestMalformed };
        // A reused name would mix two requests' artifacts.
        var out_buf: [300]u8 = undefined;
        if (self.dir.access(try std.fmt.bufPrint(&out_buf, "out/{s}", .{stem}), .{})) |_| return .{ .stem = stem, .block = block, .err = error.ResidentRequestNameReused } else |e| if (e != error.FileNotFound) return e;
        return .{ .stem = stem, .block = block };
    }
    /// out/<stem>/<block>/proof (the resident harness reads proofs there).
    pub fn proofDir(self: *Spool, stem: []const u8, block: u64) !std.fs.Dir {
        var buf: [320]u8 = undefined;
        const path = try std.fmt.bufPrint(&buf, "out/{s}/{d}/proof", .{ stem, block });
        try self.dir.makePath(path);
        return self.dir.openDir(path, .{});
    }
    /// done/<stem>.json (atomic), the request file removed, `stem` freed.
    pub fn answer(self: *Spool, stem: []const u8, json: []const u8) !void {
        var b1: [300]u8 = undefined;
        var b2: [300]u8 = undefined;
        var b3: [300]u8 = undefined;
        const tmp = try std.fmt.bufPrint(&b1, "done/{s}.tmp", .{stem});
        const done = try std.fmt.bufPrint(&b2, "done/{s}.json", .{stem});
        try self.dir.writeFile(.{ .sub_path = tmp, .data = json });
        self.inbox.deleteFile(try std.fmt.bufPrint(&b3, "{s}.request", .{stem})) catch |e| if (e != error.FileNotFound) return e;
        try self.dir.rename(tmp, done);
        if (self.taken.fetchRemove(stem)) |kv| self.a.free(kv.key);
    }
    fn refuse(self: *Spool, stem: []const u8, err: anyerror, sequence: ?u64) !void {
        var buf: [256]u8 = undefined;
        const text = if (sequence) |s| try std.fmt.bufPrint(&buf, "{{\"ok\":false,\"error\":\"{s}\",\"sequence\":{d}}}\n", .{ @errorName(err), s }) else try std.fmt.bufPrint(&buf, "{{\"ok\":false,\"error\":\"{s}\",\"sequence\":null}}\n", .{@errorName(err)});
        try self.answer(stem, text);
    }
};

/// The driver receipt as published per request (m8-jobs.json; D4/D5).
pub fn receiptJson(a: std.mem.Allocator, block: u64, sequence: u64, r: Result) ![]u8 {
    return std.json.Stringify.valueAlloc(a, .{ .schema = "rv64-m8-gpu-native-request/v1", .block = block, .sequence = sequence, .request_wall_ns = r.request_wall_ns, .begin_ns = r.begin_ns, .proofs = r.outcome.proofs.len, .receipt = r.outcome.receipt, .scope = "host_waits/d2h counted by the driver; device_gpu_us = CUDA-event span per GPU (preamble start -> slab D2H end) [M]; host ns = CPU wall on the driver threads [M]" }, .{ .whitespace = .indent_1 });
}

/// Spool loop: up to two requests in flight (the next request's capture and
/// enqueue overlap the oldest request's proving); answers in FIFO order. A
/// refused request is answered {"ok":false}; a poisoned driver (device
/// fault) stops the service with the error after answering.
pub fn serveSpool(svc: *Service, spool_path: []const u8, init_ns: u64) !void {
    const a = svc.a;
    var spool = try Spool.open(a, spool_path);
    defer spool.close();
    try spool.ready(init_ns);
    std.debug.print("GPU_RESIDENT_SERVICE ready init_ns={} runtime=m8-gpu-native\n", .{init_ns});
    const Item = struct { stem: []const u8, block: u64, pending: *Pending, queue_ns: u64, out: std.fs.Dir };
    var queue: [2]Item = undefined;
    var queued: usize = 0;
    // Never leave a request in flight behind (error exits included).
    defer for (queue[0..queued]) |*it| {
        if (svc.finish(it.pending)) |res| {
            var r = res;
            r.outcome.deinit();
        } else |_| {}
        it.out.close();
    };
    var idle = try std.time.Timer.start();
    var stop = false;
    while (true) {
        if (queued < queue.len) if (try spool.next(&stop)) |n| {
            const queue_ns = idle.read();
            if (n.err) |err| {
                try spool.refuse(n.stem, err, null);
                continue;
            }
            var out = try spool.proofDir(n.stem, n.block);
            const p = svc.begin(n.block, out) catch |err| {
                out.close();
                std.debug.print("GPU_RESIDENT_SERVICE reject request={s} error={s}\n", .{ n.stem, @errorName(err) });
                try spool.refuse(n.stem, err, null);
                if (svc.driver.poisoned) return err;
                continue;
            };
            queue[queued] = .{ .stem = n.stem, .block = n.block, .pending = p, .queue_ns = queue_ns, .out = out };
            queued += 1;
            continue;
        };
        if (queued != 0) {
            const it = queue[0];
            std.mem.copyForwards(Item, queue[0 .. queued - 1], queue[1..queued]);
            queued -= 1;
            var out = it.out;
            defer out.close();
            const seq = spool.sequence;
            spool.sequence += 1;
            idle.reset();
            const res = svc.finish(it.pending) catch |err| {
                std.debug.print("GPU_RESIDENT_SERVICE failed request={s} error={s}\n", .{ it.stem, @errorName(err) });
                try spool.refuse(it.stem, err, seq);
                if (svc.driver.poisoned) return err;
                continue;
            };
            var r = res;
            defer r.outcome.deinit();
            const receipt = try receiptJson(a, it.block, seq, r);
            defer a.free(receipt);
            var buf: [300]u8 = undefined;
            try spool.dir.writeFile(.{ .sub_path = try std.fmt.bufPrint(&buf, "out/{s}/m8-jobs.json", .{it.stem}), .data = receipt });
            std.debug.print("GPU_RESIDENT_BLOCK block={d} trial=0 iteration={d} request_wall_ns={d} host_waits={d} d2h={d}\n", .{ it.block, seq, r.request_wall_ns, r.outcome.receipt.host_waits, r.outcome.receipt.d2h });
            var tb: [512]u8 = undefined;
            const text = try std.fmt.bufPrint(&tb, "{{\"ok\":true,\"block\":{d},\"sequence\":{d},\"request_wall_ns\":{d},\"queue_ns\":{d},\"host_waits\":{d},\"d2h\":{d}}}\n", .{ it.block, seq, r.request_wall_ns, it.queue_ns, r.outcome.receipt.host_waits, r.outcome.receipt.d2h });
            try spool.answer(it.stem, text);
            continue;
        }
        if (stop) break;
        std.Thread.sleep(2 * std.time.ns_per_ms);
    }
    std.debug.print("GPU_RESIDENT_SERVICE stop requests={}\n", .{spool.sequence});
}

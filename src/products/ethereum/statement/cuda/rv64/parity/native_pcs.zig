//! Unchanged OODS/PCS parity job, decoder and transcript comparison.
const CPU = @import("stwo_riscv_cpu_integration");
const DP = CPU.rv64_device_pcs;
const Done = @import("native_common.zig").Done;
const Events = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.cuda_events;
const NP = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_pcs;
const Peer = @import("native_common.zig").Peer;
const Slab = jobs.slab;
const W = jobs.worker;
const api = jobs.api;
const check = @import("native_common.zig").check;
const deepEql = @import("native_common.zig").deepEql;
const jobs = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.runtime;
const std = @import("std");

pub const PcsRow = struct {
    kind: []const u8,
    ordinal: u32,
    trees: usize,
    columns: usize,
    host_columns: usize,
    oods_equal: bool = false,
    proof_equal: bool = false,
    channel_equal: bool = false,
    pcs_status: u32 = 0xffff_ffff,
    gpu_ms: f32 = -1,
    legacy_ns: u64,
    job_enqueue_ns: u64 = 0,
    job_wait_ns: u64 = 0,
    host_waits: u32 = 0,
    arena_peak_words: u64 = 0,
    error_name: []const u8 = "",
};

pub const PcsParityJob = struct {
    a: std.mem.Allocator,
    pcs: *NP.PcsJob,
    sym: NP.Symbols,
    peer: Peer,
    request: DP.Request,
    seed: [9]u32,
    events: *const Events.Api,
    begin: ?*anyopaque = null,
    end: ?*anyopaque = null,
    gpu_ms: f32 = -1,
    layout: Slab.ProofLayout = .{},
    staged_seed: ?api.DeviceBuffer = null,
    staged_host: ?api.DeviceBuffer = null,
    pinned: []u32 = &.{},
    host_words: usize = 0,
    mirror_words: usize = 0,
    oods: [33]u32 = undefined,
    decoded: ?@import("stwo_riscv_cuda_integration").rv64.execution.pcs.hybrid_pcs.Decoded = null,
    decode_error: ?anyerror = null,
    pub fn classKey(_: *PcsParityJob) [32]u8 {
        var k: [32]u8 = @splat(0);
        @memcpy(k[0..14], "rv64-m8-pcsprt");
        return k;
    }
    pub fn count(self: *PcsParityJob) void {
        self.host_words = 0;
        self.mirror_words = 0;
        for (self.request.trees) |t| for (t.columns) |c| {
            if (c.device != null) self.mirror_words += @as(usize, 1) << @intCast(c.log_size) else self.host_words += c.coefficients.len;
        };
    }
    pub fn footprint(self: *PcsParityJob) api.Footprint {
        const g = 64;
        const staged = std.mem.alignForward(usize, self.host_words, g) + 2 * g;
        return .{ .device_words = staged + std.mem.alignForward(usize, self.mirror_words, g) + (5 << 29), .staged_words = staged, .slab_words = self.layout.words, .pinned_words = @as(usize, @intCast(self.pcs.ingressWords())) + self.host_words + 2 * g };
    }
    pub fn stage(self: *PcsParityJob, s: *api.Stager) !void {
        if (self.events.create(&self.begin, 0) != 0 or self.events.create(&self.end, 0) != 0 or self.begin == null or self.end == null) return error.CudaTimingFailed;
        const seed = try s.alloc(9);
        try s.upload(seed, &self.seed);
        self.staged_seed = seed;
        if (self.host_words != 0) {
            const host = try s.alloc(self.host_words);
            var at: usize = 0;
            for (self.request.trees, 0..) |t, ti| for (t.columns, 0..) |c, ci| if (c.device == null) {
                const words = @as([*]const u32, @ptrCast(c.coefficients.ptr))[0..c.coefficients.len];
                try s.upload(try host.slice(at, words.len), words);
                try self.pcs.bindColumn(ti, ci, host.ptr + at);
                at += words.len;
            };
            self.staged_host = host;
        }
        self.pinned = try s.pinned(@intCast(self.pcs.ingressWords()));
    }
    pub fn enqueue(self: *PcsParityJob, e: *api.Enqueue) !void {
        try e.slab.bind(&self.layout);
        if (self.mirror_words != 0) {
            const mirror = try e.alloc(self.mirror_words);
            var at: usize = 0;
            for (self.request.trees, 0..) |t, ti| for (t.columns, 0..) |c, ci| if (c.device) |d| {
                const n = @as(usize, 1) << @intCast(c.log_size);
                try self.peer.mirror(e, mirror.ptr + at, d.words, n);
                try self.pcs.bindColumn(ti, ci, mirror.ptr + at);
                at += n;
            };
        }
        try e.channel.initFromCheckpoint(self.staged_seed.?);
        if (self.events.record(self.begin.?, e.stream()) != 0) return error.CudaTimingFailed;
        try self.pcs.enqueueOpening(self.sym, e, self.pinned, try e.slab.field(.opaque_words, 0), try e.slab.field(.opaque_words, 1));
        if (self.events.record(self.end.?, e.stream()) != 0) return error.CudaTimingFailed;
    }
    pub fn finish(self: *PcsParityJob, view: api.SlabView) !void {
        @memcpy(&self.oods, try Slab.read(view, .opaque_words, 0));
        if (self.events.elapsed(&self.gpu_ms, self.begin.?, self.end.?) != 0) self.gpu_ms = -1;
        const words = try Slab.read(view, .opaque_words, 1);
        const roots = try self.a.alloc([32]u8, self.request.trees.len);
        defer self.a.free(roots);
        for (self.request.trees, roots) |t, *r| r.* = t.root;
        self.decoded = self.pcs.decode(self.a, words, roots) catch |err| blk: {
            self.decode_error = err;
            break :blk null;
        };
    }
    pub fn abort(_: *PcsParityJob) void {}
    pub fn deinit(self: *PcsParityJob) void {
        if (self.begin) |ev| _ = self.events.destroy(ev);
        if (self.end) |ev| _ = self.events.destroy(ev);
    }
};

pub const PcsDecorator = struct {
    a: std.mem.Allocator,
    inner: *const DP.Stage,
    kind: []const u8,
    worker: *W.Worker,
    sym: NP.Symbols,
    peer: Peer,
    events: *const Events.Api,
    wide: bool,
    mutex: *std.Thread.Mutex,
    rows: *std.ArrayListUnmanaged(PcsRow),
    pub fn stage(self: *PcsDecorator) DP.Stage {
        return .{ .context = self, .prove = prove };
    }
    pub fn prove(raw: *anyopaque, a: std.mem.Allocator, request: DP.Request, channel: *DP.Channel) anyerror!DP.P.ExtendedCommitmentSchemeProof(DP.H) {
        const self: *PcsDecorator = @ptrCast(@alignCast(raw));
        const before = channel.*;
        // The job runs FIRST: the legacy PCS is the last consumer of these
        // trees and the owner may recycle them as soon as it returns.
        self.mutex.lock();
        defer self.mutex.unlock();
        var columns: usize = 0;
        var host_columns: usize = 0;
        for (request.trees) |t| for (t.columns) |c| {
            columns += 1;
            host_columns += @intFromBool(c.device == null);
        };
        var row = PcsRow{ .kind = self.kind, .ordinal = if (request.scope) |sc| sc.ordinal else 0xffff_ffff, .trees = request.trees.len, .columns = columns, .host_columns = host_columns, .legacy_ns = 0 };
        var job_result: ?@import("stwo_riscv_cuda_integration").rv64.execution.pcs.hybrid_pcs.Decoded = null;
        defer if (job_result) |*d| d.proof.deinit(self.a);
        self.check(request, before, &row, &job_result) catch |err| {
            row.error_name = @errorName(err);
        };
        var timer = try std.time.Timer.start();
        const legacy = try self.inner.prove(self.inner.context, a, request, channel);
        row.legacy_ns = timer.read();
        if (job_result) |*decoded| {
            row.proof_equal = deepEql(decoded.proof, legacy.proof);
            row.channel_equal = std.meta.eql(decoded.channel.inner.digest, channel.inner.digest) and decoded.channel.inner.n_draws == channel.inner.n_draws;
        }
        std.debug.print("GPU_M8_NATIVE_PCS_PARITY kind={s} ordinal={} trees={} columns={} host_columns={} oods_equal={} proof_equal={} channel_equal={} gpu_ms={d:.3} legacy_ns={} job_enqueue_ns={} job_wait_ns={} host_waits={} arena_peak_words={} error={s}\n", .{ row.kind, row.ordinal, row.trees, row.columns, row.host_columns, row.oods_equal, row.proof_equal, row.channel_equal, row.gpu_ms, row.legacy_ns, row.job_enqueue_ns, row.job_wait_ns, row.host_waits, row.arena_peak_words, row.error_name });
        try self.rows.append(self.a, row);
        return legacy;
    }
    pub fn check(self: *PcsDecorator, request: DP.Request, before: DP.Channel, row: *PcsRow, result: *?@import("stwo_riscv_cuda_integration").rv64.execution.pcs.hybrid_pcs.Decoded) !void {
        const a = self.a;
        // Pre-OODS checkpoint: the OODS draw is the last op before the PCS (one
        // draw step, digest unchanged).
        if (before.inner.n_draws == 0) return error.PcsParityNoOodsDraw;
        var pre = before;
        pre.inner.n_draws -= 1;
        var replay = pre;
        const oods = try @import("stwo_core").circle.randomSecureFieldPointFor(DP.O, &replay);
        if (!std.meta.eql(replay.inner.digest, before.inner.digest) or replay.inner.n_draws != before.inner.n_draws) return error.PcsParityOodsCheckpoint;
        // Framing at a placeholder point (same mask offsets).
        const placeholder = try NP.placeholderPoint();
        const trees = try a.alloc([][]DP.Point, request.points.items.len);
        defer a.free(trees);
        var made: usize = 0;
        defer for (trees[0..made]) |t| {
            for (t) |c| a.free(c);
            a.free(t);
        };
        for (request.points.items, trees) |tree, *out| {
            out.* = try a.alloc([]DP.Point, tree.len);
            made += 1;
            for (tree, out.*) |column, *o| {
                o.* = try a.alloc(DP.Point, column.len);
                for (column, o.*) |point, *q| q.* = point.sub(oods).add(placeholder);
            }
        }
        const framed = DP.Request{ .scope = request.scope, .allocation_observer_domain = request.allocation_observer_domain, .config = request.config, .lifting_log_size = request.lifting_log_size, .trees = request.trees, .points = .{ .items = trees } };
        var pcs = try NP.PcsJob.prepare(a, self.sym, framed, placeholder, self.wide);
        defer pcs.deinit(a);
        var seed: [9]u32 = undefined;
        for (0..8) |i| seed[i] = std.mem.readInt(u32, pre.inner.digest[4 * i ..][0..4], .little);
        seed[8] = pre.inner.n_draws;
        var job = PcsParityJob{ .a = a, .pcs = &pcs, .sym = self.sym, .peer = self.peer, .request = request, .seed = seed, .events = self.events };
        defer job.deinit();
        defer if (job.decoded) |*d| d.proof.deinit(a);
        job.count();
        _ = try job.layout.add(.opaque_words, 0, NP.oods_field_words);
        _ = try job.layout.add(.opaque_words, 1, @intCast(pcs.outputWords()));
        var done = Done{};
        try self.worker.submit(api.Job.from(PcsParityJob, &job), .{ .ctx = &done, .done = Done.call });
        while (!@atomicLoad(bool, &done.done, .acquire)) std.Thread.sleep(50 * std.time.ns_per_us);
        try done.result;
        const r = done.receipt;
        row.job_enqueue_ns = r.enqueue_ns;
        row.job_wait_ns = r.wait_ns;
        row.host_waits = r.host_waits;
        row.arena_peak_words = r.arena_peak_words;
        row.gpu_ms = job.gpu_ms;
        row.pcs_status = job.oods[32];
        var oods_equal = job.oods[32] == 0;
        for (oods.x.toM31Array(), 0..) |m, i| oods_equal = oods_equal and job.oods[i] == m.v;
        for (oods.y.toM31Array(), 0..) |m, i| oods_equal = oods_equal and job.oods[8 + i] == m.v;
        row.oods_equal = oods_equal;
        if (job.decode_error) |err| return err;
        result.* = job.decoded orelse return error.PcsParityNotDecoded;
        job.decoded = null;
    }
};

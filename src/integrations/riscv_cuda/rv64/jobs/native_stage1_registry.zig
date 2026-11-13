//! Install/request registry owner: class warming, pending witnesses and release.
const up = @import("native_stage1_job.zig").up;
const Schema = @import("native_device_stage1.zig");
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const Timing = @import("job_timing.zig").Timing;
const W = @import("worker.zig");
const ND = @import("native_device.zig");
const NP = @import("native_pack.zig");
const Done = struct {
    event: std.Thread.ResetEvent = .{},
    result: anyerror!void = {},
    fn call(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        self.result = c.result;
        self.event.set();
    }
};

/// ClassCache builder of a Stage-1 entry: the plan is the registry's Class
/// (borrowed; the registry destroys it), Stage-1 constants filled in.
const EntryBuilder = struct {
    class: *Schema.Class,
    devices: u32,
    fn build(raw: *anyopaque, _: std.mem.Allocator, key: G.ClassKey) anyerror!G.ClassEntry {
        const self: *EntryBuilder = @ptrCast(@alignCast(raw));
        var entry = G.ClassEntry{ .key = key, .plan = self.class, .destroy = noop };
        self.class.fill(&entry, self.devices);
        return entry;
    }
    fn noop(_: *anyopaque) void {}
};

pub const Registry = struct {
    a: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    specs: std.AutoArrayHashMapUnmanaged(G.ClassKey, Schema.Spec) = .empty,
    classes: std.AutoArrayHashMapUnmanaged(G.ClassKey, *Schema.Class) = .empty,
    /// Segment rows -> class (class_of from capture geometry).
    by_rows: std.AutoHashMapUnmanaged(u64, G.ClassKey) = .empty,
    /// Per (request generation, segment): the request words and the chunks.
    requests: std.AutoHashMapUnmanaged(u64, *Pending) = .empty,
    sym: ?*const Schema.Symbols = null,
    timing: ?*const Timing = null,
    /// gn-pack: host ROM words for the v2 programs' persistent ROM regions
    /// (filled by native_pack_capture.pack on the capture thread).
    roms: ?*NP.Roms = null,
    /// Workers by driver device index (WarmJob per class and GPU at install).
    workers: []const *W.Worker = &.{},
    /// GPUs the service runs (set before warm): `held_words` is reserved on
    /// each of them. 0 = `workers.len`; a class registered with neither set
    /// refuses to warm (it would budget only GPU 0).
    devices: u32 = 0,
    /// Devices the warmed entries reserved held words on.
    warmed_devices: u32 = 0,
    sealed: bool = false,

    /// native_device.Native.stage1_hooks of this registry.
    pub fn hooks(self: *Registry) ND.Stage1Hooks {
        return .{ .ctx = self, .warm = hWarm, .installed = hInstalled, .class_of = hClassOf, .stage1 = hStage1, .chunk = hChunk };
    }
    fn reg(raw: *anyopaque) *Registry {
        return @ptrCast(@alignCast(raw));
    }
    fn hWarm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
        const self = reg(raw);
        return self.warm(cache, if (self.devices != 0) self.devices else @intCast(self.workers.len));
    }
    fn hInstalled(raw: *anyopaque, info: *const G.Installed) anyerror!void {
        const self = reg(raw);
        if (self.workers.len < info.devices) return error.NativeStage1WorkersNotBound;
        if (self.classes.count() != 0 and info.devices > self.warmed_devices) return error.NativeStage1DevicesNotWarmed;
        try self.warmDevices(self.workers[0..info.devices]);
        self.seal();
    }
    fn hClassOf(raw: *anyopaque, rows: u64) anyerror!G.ClassKey {
        return reg(raw).classOf(rows);
    }
    fn hStage1(raw: *anyopaque, ctx: *const G.RequestContext, segment: u32, device: u32) anyerror!api.Job {
        if (ctx.native_classes.len != 0) return reg(raw).deferred(ctx, segment, device);
        return reg(raw).stage1(ctx, segment, device);
    }
    fn hChunk(raw: *anyopaque, ctx: *const G.RequestContext, c: G.TraceChunk) anyerror!void {
        return reg(raw).chunk(ctx, c);
    }

    pub const Pending = struct {
        key: ?G.ClassKey = null,
        words: ?Schema.RequestWords = null,
        publics: []Schema.PublicWords = &.{},
        chunks: std.ArrayListUnmanaged(G.TraceChunk) = .empty,
        device: ?[]const [*]const u32 = null,
        job: ?*Schema.Stage1Job = null,
        deferred_job: ?*Deferred = null,
    };

    pub fn init(a: std.mem.Allocator) Registry {
        return .{ .a = a };
    }
    pub fn deinit(self: *Registry) void {
        var it = self.requests.valueIterator();
        while (it.next()) |p| self.dropPending(p.*);
        self.requests.deinit(self.a);
        for (self.classes.values()) |c| c.deinit();
        self.classes.deinit(self.a);
        self.specs.deinit(self.a);
        self.by_rows.deinit(self.a);
    }
    fn dropPending(self: *Registry, p: *Pending) void {
        if (p.deferred_job) |j| self.a.destroy(j);
        if (p.job) |j| {
            j.deinit();
            self.a.destroy(j);
        }
        p.chunks.deinit(self.a);
        self.a.free(p.publics);
        self.a.destroy(p);
    }
    fn pendingKey(generation: u64, segment: u32) u64 {
        return (generation << 16) | segment;
    }

    /// Install time: register a class (same key twice must be the same spec).
    pub fn register(self: *Registry, spec: Schema.Spec, rows: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.sealed) return error.GpuNativeClassBuildOnRequestPath;
        if (self.specs.get(spec.key)) |old| {
            if (old.gkr != spec.gkr or old.fixed_shapes.ptr != spec.fixed_shapes.ptr or old.main_shapes.ptr != spec.main_shapes.ptr) return error.GpuNativeClassKeyMismatch;
        } else try self.specs.put(self.a, spec.key, spec);
        if (self.by_rows.get(rows)) |k| {
            if (!std.mem.eql(u8, &k, &spec.key)) return error.GpuNativeClassKeyMismatch;
        } else try self.by_rows.put(self.a, rows, spec.key);
    }
    /// Warm: build every registered class (host plans) and fill its entry.
    pub fn warm(self: *Registry, cache: *G.ClassCache, devices: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.specs.count() != 0 and devices == 0) return error.NativeStage1DevicesNotBound;
        self.warmed_devices = @min(devices, G.max_devices);
        for (self.specs.values()) |spec| {
            const cl = if (self.classes.get(spec.key)) |c| c else blk: {
                const c = try Schema.Class.init(self.a, spec);
                errdefer c.deinit();
                try self.classes.put(self.a, spec.key, c);
                break :blk c;
            };
            var builder = EntryBuilder{ .class = cl, .devices = devices };
            _ = try cache.warm(spec.key, .{ .ctx = &builder, .build = EntryBuilder.build });
        }
    }
    /// Install (after the memory plan, before the cache seals): one WarmJob
    /// per (class, GPU) on that GPU's worker, waited here (install time).
    pub fn warmDevices(self: *Registry, workers: []const *W.Worker) !void {
        const sym = self.sym orelse return error.NativeStage1SymbolsNotBound;
        for (self.classes.values()) |cl| for (workers) |w| {
            var job = Schema.WarmJob{ .a = self.a, .class = cl, .sym = sym };
            try job.init();
            defer job.deinit();
            var done = Done{};
            while (true) {
                w.submit(api.Job.from(Schema.WarmJob, &job), .{ .ctx = &done, .done = Done.call }) catch |err| switch (err) {
                    error.WorkerBusy => {
                        std.Thread.sleep(20 * std.time.ns_per_us);
                        continue;
                    },
                    else => return err,
                };
                break;
            }
            done.event.wait();
            try done.result;
        };
    }
    pub fn seal(self: *Registry) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.sealed = true;
    }
    pub fn classOf(self: *Registry, rows: u64) !G.ClassKey {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.by_rows.get(rows) orelse error.GpuNativeClassNotWarmed;
    }
    pub fn class(self: *Registry, key: G.ClassKey) !*const Schema.Class {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.classes.get(key) orelse error.GpuNativeClassNotWarmed;
    }
    fn pending(self: *Registry, generation: u64, segment: u32) !*Pending {
        const gop = try self.requests.getOrPut(self.a, pendingKey(generation, segment));
        if (!gop.found_existing) {
            const p = try self.a.create(Pending);
            p.* = .{};
            gop.value_ptr.* = p;
        }
        return gop.value_ptr.*;
    }
    /// Service, per request and segment: the challenge-free request words.
    pub fn setRequest(self: *Registry, generation: u64, segment: u32, key: G.ClassKey, words: Schema.RequestWords) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.classes.contains(key)) return error.GpuNativeClassNotWarmed;
        const p = try self.pending(generation, segment);
        if (p.key) |expected| if (!std.mem.eql(u8, &expected, &key)) return error.GpuNativeClassKeyMismatch;
        if (p.words != null) return error.NativeStage1RequestWordsTwice;
        p.key = key;
        p.publics = try self.a.dupe(Schema.PublicWords, words.publics);
        p.words = .{ .statement = words.statement, .seed = words.seed, .prefix = words.prefix, .publics = p.publics };
    }
    /// Parity/upstream producers: MAIN columns already on device.
    pub fn setDeviceWitness(self: *Registry, generation: u64, segment: u32, columns: []const [*]const u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const p = try self.pending(generation, segment);
        if (p.chunks.items.len != 0 or p.device != null) return error.NativeStage1WitnessTwice;
        p.device = columns;
    }
    /// Capture thread (NativeFactory.chunk): record the chunk (no GPU work).
    pub fn chunk(self: *Registry, ctx: *const G.RequestContext, c: G.TraceChunk) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const p = try self.pending(ctx.generation, c.segment);
        if (p.device != null) return error.NativeStage1WitnessTwice;
        if (p.job != null) return error.GpuNativeCaptureChunkAfterSeal;
        if (c.sequence != p.chunks.items.len) return error.GpuNativeCaptureGeometryMismatch;
        if (NP.isV2(c.words)) {
            if (c.words[1] != NP.version) return error.NativeStage1ChunkFormat;
        } else _ = try Schema.chunkRuns(c.words);
        try p.chunks.append(self.a, c);
    }
    /// NativeFactory.stage1: the job (owned by the registry until `release`).
    /// Construction precedes capture. The worker's segment-ready gate fires
    /// before `stage`, so only then may the job consume chunks/public words.
    pub fn deferred(self: *Registry, ctx: *const G.RequestContext, segment: u32, device: u32) !api.Job {
        if (segment >= ctx.native_classes.len) return error.GpuNativeSegmentOutOfRange;
        const key = ctx.native_classes[segment];
        self.mutex.lock();
        defer self.mutex.unlock();
        const cl = self.classes.get(key) orelse return error.GpuNativeClassNotWarmed;
        const p = try self.pending(ctx.generation, segment);
        if (p.deferred_job != null or p.job != null) return error.NativeStage1JobTwice;
        if (p.key) |expected| if (!std.mem.eql(u8, &expected, &key)) return error.GpuNativeClassKeyMismatch;
        const j = try self.a.create(Deferred);
        j.* = .{ .registry = self, .ctx = ctx, .segment = segment, .device = device, .class = cl };
        p.key = key;
        p.deferred_job = j;
        return api.Job.from(Deferred, j);
    }

    pub const Deferred = struct {
        registry: *Registry,
        ctx: *const G.RequestContext,
        segment: u32,
        device: u32,
        class: *const Schema.Class,
        inner: ?api.Job = null,
        pub fn classKey(self: *Deferred) [32]u8 {
            var k = self.class.spec.key;
            k[0] ^= 0x51;
            return k;
        }
        pub fn footprint(self: *Deferred) api.Footprint {
            const c = self.class;
            return .{ .device_words = c.jobWords(), .staged_words = up(9) + Schema.granule + c.spec.gkr.stagedWords(true) + up(c.main.stagedWords(0)) + @as(usize, @intCast(c.spec.compact_words)), .pinned_words = c.requestPinnedWords() };
        }
        pub fn stage(self: *Deferred, s: *api.Stager) !void {
            const job = try self.registry.stage1(self.ctx, self.segment, self.device);
            self.inner = job;
            // The class budget is fixed before capture, never enlarged on a
            // request. An unexpectedly large witness fails before upload.
            if (job.footprint().device_words > self.footprint().device_words) return error.NativeStage1CompactExceedsPlan;
            try job.vtable.stage(job.ctx, s);
        }
        pub fn enqueue(self: *Deferred, e: *api.Enqueue) !void {
            const j = self.inner orelse return error.NativeStage1WitnessMissing;
            try j.vtable.enqueue(j.ctx, e);
        }
        pub fn finish(self: *Deferred, v: api.SlabView) !void {
            const j = self.inner orelse return error.NativeStage1WitnessMissing;
            try j.vtable.finish(j.ctx, v);
        }
        pub fn abort(self: *Deferred) void {
            if (self.inner) |j| j.vtable.abort(j.ctx);
        }
    };

    pub fn stage1(self: *Registry, ctx: *const G.RequestContext, segment: u32, device: u32) !api.Job {
        const sym = self.sym orelse return error.NativeStage1SymbolsNotBound;
        self.mutex.lock();
        defer self.mutex.unlock();
        const p = try self.pending(ctx.generation, segment);
        if (p.job != null) return error.NativeStage1JobTwice;
        const words = p.words orelse return error.NativeStage1RequestWordsMissing;
        const cl = self.classes.get(p.key.?) orelse return error.GpuNativeClassNotWarmed;
        const witness: Schema.Witness = if (p.device) |d| .{ .device = d } else if (p.chunks.items.len != 0)
            (if (try Schema.chunksAreV2(p.chunks.items)) .{ .compact = .{ .chunks = p.chunks.items, .roms = self.roms } } else .{ .chunks = p.chunks.items })
        else
            return error.NativeStage1WitnessMissing;
        const job = try self.a.create(Schema.Stage1Job);
        errdefer self.a.destroy(job);
        job.* = .{ .a = self.a, .class = cl, .sym = sym, .ctx = ctx, .segment = segment, .device = device, .words = words, .witness = witness, .timing = self.timing, .timing_storage = .installed };
        try job.init();
        p.job = job;
        return api.Job.from(Schema.Stage1Job, job);
    }
    /// GPU span of a segment's Stage 1 [M] (after the request's wait), or -1.
    pub fn gpuMs(self: *Registry, generation: u64, segment: u32) f32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const p = self.requests.get(pendingKey(generation, segment)) orelse return -1;
        return if (p.job) |j| j.span.gpu_ms else -1;
    }
    /// Request end (success or abort): drop every pending record of it.
    pub fn release(self: *Registry, generation: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var doomed: std.ArrayListUnmanaged(u64) = .empty;
        defer doomed.deinit(self.a);
        var it = self.requests.iterator();
        while (it.next()) |kv| if (kv.key_ptr.* >> 16 == generation) doomed.append(self.a, kv.key_ptr.*) catch {};
        for (doomed.items) |k| if (self.requests.fetchRemove(k)) |kv| self.dropPending(kv.value);
    }
};

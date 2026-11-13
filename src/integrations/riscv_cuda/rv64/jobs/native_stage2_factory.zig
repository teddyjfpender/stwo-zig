//! Install/request owner: framing pools, warming, seal custody and factory hooks.
const Schema = @import("native_device_stage2.zig");
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const MW = @import("native_manifest_wire.zig");
const Worker = @import("worker.zig").Worker;
const C = @import("native_commit.zig");
const Gl = @import("native_global.zig");
const Hooks = @import("native_device.zig").Stage2Hooks;
const CPU = @import("stwo_riscv_cpu_integration");
pub const Factory = struct {
    a: std.mem.Allocator,
    sym: *const Schema.Symbols,
    mutex: std.Thread.Mutex = .{},
    classes: std.AutoHashMapUnmanaged(G.ClassKey, *Pool) = .empty,
    segment_class: std.AutoHashMapUnmanaged(u32, G.ClassKey) = .empty,
    requests: std.AutoHashMapUnmanaged(u64, *Request) = .empty,
    /// chain.versionIdentity of the service policy (seal chain IV input).
    identity: [32]u8,
    /// The GPU the driver runs the seal on (driver Config.seal_device): the
    /// publisher of the seal slot every Stage-2 job awaits.
    seal_device: u32 = 0,

    /// Exclusive instances of one class (see Stage2Job.lease). A job holds
    /// one from its `stage` to the end of its `enqueue`, and each worker has
    /// at most two jobs in that window (one staged, one enqueuing), so warm
    /// registers `instances_per_device * devices` instances per class.
    /// Exhaustion fails closed (never blocks a worker thread).
    pub const Pool = struct {
        instances: std.ArrayListUnmanaged(*Schema.ClassFraming) = .empty,
        busy: std.ArrayListUnmanaged(bool) = .empty,
        fn deinit(self: *Pool, a: std.mem.Allocator) void {
            self.instances.deinit(a);
            self.busy.deinit(a);
        }
    };
    pub const instances_per_device: usize = 2;

    pub const Request = struct {
        roster: []const Schema.RosterEntry,
        execution: [32]u8,
        inputs: []const Schema.RequestInputs, // per segment
        /// Flat policy (v1-flat, the D2 profile): the manifest entries the
        /// flat digest frames (roster order) and the manifest PROFILE; the
        /// seal then runs the digest script instead of the chi chain.
        flat: ?[]const Schema.FlatEntry = null,
        profile: []const u8 = CPU.rv64_gkr_manifest.PROFILE,
    };

    pub fn deinit(self: *Factory) void {
        var it = self.classes.valueIterator();
        while (it.next()) |p| {
            p.*.deinit(self.a);
            self.a.destroy(p.*);
        }
        self.classes.deinit(self.a);
        self.segment_class.deinit(self.a);
        self.requests.deinit(self.a);
    }
    /// Warm: register one instance of a segment class (the framing stays
    /// owned by the caller for the factory's life). Register
    /// `instances_per_device * devices` instances of every class; the first
    /// is the class prototype the class cache hands out.
    pub fn register(self: *Factory, framing: *Schema.ClassFraming) !void {
        try framing.validate();
        try self.registerUnchecked(framing);
    }
    fn registerUnchecked(self: *Factory, framing: *Schema.ClassFraming) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const got = try self.classes.getOrPut(self.a, framing.key);
        if (!got.found_existing) {
            const p = self.a.create(Pool) catch |err| {
                self.classes.removeByPtr(got.key_ptr);
                return err;
            };
            p.* = .{};
            got.value_ptr.* = p;
        }
        const pool = got.value_ptr.*;
        for (pool.instances.items) |f| if (f == framing) return error.NativeStage2ClassConflict;
        if (pool.instances.items.len != 0 and pool.instances.items[0].deviceWords() != framing.deviceWords()) return error.NativeStage2ClassConflict;
        try pool.instances.append(self.a, framing);
        pool.busy.append(self.a, false) catch |err| {
            _ = pool.instances.pop();
            return err;
        };
    }
    /// An exclusive instance of `class`'s class (Stage2Job.stage).
    pub fn acquire(self: *Factory, class: *const Schema.ClassFraming) !*Schema.ClassFraming {
        self.mutex.lock();
        defer self.mutex.unlock();
        const pool = self.classes.get(class.key) orelse return error.GpuNativeClassNotWarmed;
        for (pool.instances.items, pool.busy.items) |f, *b| if (!b.*) {
            b.* = true;
            return f;
        };
        return error.NativeStage2FramingBusy;
    }
    pub fn releaseFraming(self: *Factory, framing: *Schema.ClassFraming) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const pool = self.classes.get(framing.key) orelse return;
        for (pool.instances.items, pool.busy.items) |f, *b| if (f == framing) {
            b.* = false;
            return;
        };
    }
    pub fn bindSegment(self: *Factory, segment: u32, key: G.ClassKey) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.segment_class.put(self.a, segment, key);
    }
    /// Insert every registered class into the cache (warm phase only).
    pub fn warm(self: *Factory, cache: *G.ClassCache) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.classes.valueIterator();
        while (it.next()) |p| {
            const f = p.*.instances.items[0];
            const Builder = struct {
                fn build(raw: *anyopaque, _: std.mem.Allocator, key: G.ClassKey) anyerror!G.ClassEntry {
                    const fr: *Schema.ClassFraming = @ptrCast(@alignCast(raw));
                    var words = std.mem.alignForward(usize, fr.deviceWords(), 64) + fr.composition.persistentWords() + fr.inter.twiddleWords();
                    for (fr.slots) |slot| if (slot.global) |g| {
                        words += g.plan.rows;
                    };
                    return .{ .key = key, .plan = fr, .destroy = noop, .max_encoded_bytes = fr.program.max_encoded_bytes + 4 * fr.leaf_suffix_words, .main_resident_words = fr.main_words, .claims_per_segment = fr.claim_count, .held_words = @splat(words) };
                }
                fn noop(_: *anyopaque) void {}
            };
            _ = try cache.warm(f.key, .{ .ctx = f, .build = Builder.build });
        }
    }
    pub fn warmDevices(self: *Factory, workers: []const *Worker) !void {
        var it = self.classes.valueIterator();
        while (it.next()) |pool| {
            const c = pool.*.instances.items[0];
            for (workers) |worker| {
                var job = WarmClass{ .a = self.a, .class = c, .sym = self.sym };
                var done = WarmDone{};
                try worker.submit(api.Job.from(WarmClass, &job), .{ .ctx = &done, .done = WarmDone.call });
                done.event.wait();
                try done.result;
            }
            for (pool.*.instances.items) |f| {
                f.resources_warmed = true;
                f.inter.require_warm = true;
            }
        }
    }
    pub fn beginRequest(self: *Factory, request: u64, r: *Request) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.requests.put(self.a, request, r);
    }
    pub fn endRequest(self: *Factory, request: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.requests.remove(request);
    }
    fn requestOf(self: *Factory, request: u64) !*Request {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.requests.get(request) orelse error.NativeStage2RequestNotBegun;
    }
    fn classFor(self: *Factory, ctx: *const G.RequestContext, segment: u32) !*Schema.ClassFraming {
        self.mutex.lock();
        const key = if (ctx.native_classes.len != 0) blk: {
            if (segment >= ctx.native_classes.len) {
                self.mutex.unlock();
                return error.GpuNativeSegmentOutOfRange;
            }
            break :blk Schema.framingKey(ctx.native_classes[segment]);
        } else self.segment_class.get(segment);
        self.mutex.unlock();
        const k = key orelse return error.GpuNativeClassNotWarmed;
        const entry = try ctx.classes.get(k);
        return @ptrCast(@alignCast(entry.plan));
    }
    pub fn seal(self: *Factory, ctx: *const G.RequestContext, device: u32) !api.Job {
        // The Stage-2 jobs await the seal slot from `seal_device`.
        if (device != self.seal_device) return error.GpuNativeSealDeviceMismatch;
        const r = try self.requestOf(ctx.request);
        const job = try self.a.create(SealOwned);
        errdefer self.a.destroy(job);
        const entries = try Schema.sealEntries(self.a, r.roster, ctx.exchange);
        errdefer self.a.free(entries);
        const awaits = try Schema.truthAwaits(self.a, r.roster, ctx.exchange, ctx.segments.len);
        errdefer self.a.free(awaits);
        var flat: ?*Schema.FlatScript = null;
        if (r.flat) |fe| {
            const fs = try self.a.create(Schema.FlatScript);
            errdefer self.a.destroy(fs);
            fs.* = try Schema.FlatScript.build(self.a, r.profile, r.execution, fe, ctx.exchange);
            flat = fs;
        }
        errdefer if (flat) |f| {
            f.deinit();
            self.a.destroy(f);
        };
        var manifest: ?*MW.Program = null;
        if (ctx.exchange.child_wire_words != 0) {
            const m = try self.a.create(MW.Program);
            errdefer self.a.destroy(m);
            m.* = try MW.build(self.a, r.execution, r.flat orelse return error.GlobalGkrManifestProfile, ctx.exchange);
            manifest = m;
        }
        job.* = .{ .factory = self, .job = .{ .a = self.a, .sym = &self.sym.seal, .ctx = ctx, .device = device, .entries = entries, .truth_awaits = awaits, .flat = flat, .manifest = manifest, .constants = Schema.sealConstants(self.identity, r.execution, @intCast(entries.len), G.Exchange.flagTag(ctx.generation)) } };
        return api.Job.from(SealOwned, job);
    }
    pub fn stage2(self: *Factory, ctx: *const G.RequestContext, segment: u32, device: u32) !api.Job {
        const r = try self.requestOf(ctx.request);
        const class = try self.classFor(ctx, segment);
        if (segment >= r.inputs.len) return error.NativeStage2NoRequestInputs;
        if (self.seal_device >= ctx.segments.len or device >= ctx.segments.len) return error.GpuNativeSealDeviceOutOfRange;
        const job = try self.a.create(Schema.Stage2Job);
        job.* = .{ .a = self.a, .sym = self.sym, .ctx = ctx, .class = class, .segment = segment, .device = device, .seal_device = self.seal_device, .constants = Schema.sealConstants(self.identity, r.execution, @intCast(r.roster.len), G.Exchange.flagTag(ctx.generation)), .inputs = r.inputs[segment], .owner = self };
        return api.Job.from(Schema.Stage2Job, job);
    }
    /// The native_device.zig seam (no import of this file from there: the
    /// light driver test root cannot build the Stage-2 dependencies).
    pub fn hooks(self: *Factory) Hooks {
        return .{ .ctx = self, .seal = sealHook, .stage2 = stage2Hook };
    }
    fn sealHook(raw: *anyopaque, ctx: *const G.RequestContext, device: u32) anyerror!api.Job {
        const self: *Factory = @ptrCast(@alignCast(raw));
        return self.seal(ctx, device);
    }
    fn stage2Hook(raw: *anyopaque, ctx: *const G.RequestContext, segment: u32, device: u32) anyerror!api.Job {
        const self: *Factory = @ptrCast(@alignCast(raw));
        return self.stage2(ctx, segment, device);
    }
    pub fn releaseStage2(self: *Factory, job: *Schema.Stage2Job) void {
        self.a.destroy(job);
    }
};

const WarmDone = struct {
    event: std.Thread.ResetEvent = .{},
    result: anyerror!void = {},
    fn call(raw: *anyopaque, c: api.Completion) void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.result = c.result;
        self.event.set();
    }
};
const WarmClass = struct {
    a: std.mem.Allocator,
    class: *Schema.ClassFraming,
    sym: *const Schema.Symbols,
    pub fn classKey(self: *WarmClass) [32]u8 {
        var key = self.class.key;
        key[0] ^= 0x57;
        return key;
    }
    pub fn footprint(self: *WarmClass) api.Footprint {
        const c = self.class;
        var staged = c.inter.stagedWords(0) + c.composition.stagedWords() + 1024;
        var pinned = c.deviceWords() + c.inter.twiddleWords() + 8 * c.inter.logs.len + c.composition.pinnedWords() + 1024;
        for (c.slots) |slot| if (slot.global) |g| {
            staged += g.plan.stagedWords(false);
            pinned += g.plan.pinnedWords(false);
        };
        return .{ .device_words = staged, .staged_words = staged, .pinned_words = pinned };
    }
    pub fn stage(self: *WarmClass, s: *api.Stager) !void {
        const c = self.class;
        const image = try s.persistent(Schema.imageKey(c.key), c.deviceWords());
        if (image.fresh) {
            const words = try c.image(self.a);
            defer self.a.free(words);
            try s.upload(image.buffer, words);
        }
        const fixed = try s.persistent(c.fixed_key, if (c.fixed_region_words != 0) c.fixed_region_words else c.fixed_words);
        if (fixed.fresh) return error.GpuNativeFixedNotWarmed;
        for (c.slots) |slot| if (slot.global) |g| {
            var global = Gl.Global{ .plan = g.plan, .sym = &self.sym.global };
            try global.stage(self.a, s, &.{});
        };
        try c.composition.stage(s);
        const inputs = try self.a.alloc(C.Input, c.inter.shapes.len);
        defer self.a.free(inputs);
        @memset(inputs, .{ .device = @ptrFromInt(@alignOf(u32)) });
        try c.inter.stage(s, inputs);
    }
    pub fn enqueue(_: *WarmClass, _: *api.Enqueue) !void {}
    pub fn finish(_: *WarmClass, _: api.SlabView) !void {}
    pub fn abort(_: *WarmClass) void {}
};

/// A factory-owned seal job (freed after finish/abort).
const SealOwned = struct {
    factory: *Factory,
    job: Schema.SealJob,
    pub fn classKey(self: *SealOwned) [32]u8 {
        return self.job.classKey();
    }
    pub fn footprint(self: *SealOwned) api.Footprint {
        return self.job.footprint();
    }
    pub fn stage(self: *SealOwned, s: *api.Stager) !void {
        return self.job.stage(s);
    }
    pub fn enqueue(self: *SealOwned, e: *api.Enqueue) !void {
        return self.job.enqueue(e);
    }
    pub fn finish(self: *SealOwned, _: api.SlabView) !void {
        self.release();
    }
    pub fn abort(self: *SealOwned) void {
        self.release();
    }
    fn release(self: *SealOwned) void {
        const a = self.factory.a;
        a.free(self.job.entries);
        a.free(self.job.truth_awaits);
        if (self.job.flat) |f| {
            @constCast(f).deinit();
            a.destroy(@constCast(f));
        }
        if (self.job.manifest) |m| {
            m.deinit();
            a.destroy(m);
        }
        a.destroy(self);
    }
};

test "factory: concurrent blocks resolve segment zero from their own native classes" {
    const a = std.testing.allocator;
    var f = Factory{ .a = a, .sym = undefined, .identity = @splat(0) };
    defer f.deinit();
    var cache = G.ClassCache.init(a);
    defer cache.deinit();
    var x: Schema.ClassFraming = undefined;
    var y: Schema.ClassFraming = undefined;
    const kx: G.ClassKey = @splat(11);
    const ky: G.ClassKey = @splat(12);
    const CacheBuilder = struct {
        fn build(raw: *anyopaque, _: std.mem.Allocator, key: G.ClassKey) anyerror!G.ClassEntry {
            return .{ .key = key, .plan = raw, .destroy = noop };
        }
        fn noop(_: *anyopaque) void {}
    };
    _ = try cache.warm(Schema.framingKey(kx), .{ .ctx = &x, .build = CacheBuilder.build });
    _ = try cache.warm(Schema.framingKey(ky), .{ .ctx = &y, .build = CacheBuilder.build });
    cache.seal();
    var cx: G.RequestContext = undefined;
    cx.classes = &cache;
    cx.native_classes = &.{kx};
    var cy = cx;
    cy.native_classes = &.{ky};
    // A legacy/global binding for ordinal 0 must not redirect either request.
    try f.bindSegment(0, Schema.framingKey(ky));
    try std.testing.expectEqual(&x, try f.classFor(&cx, 0));
    try std.testing.expectEqual(&y, try f.classFor(&cy, 0));
    try std.testing.expectError(error.GpuNativeSegmentOutOfRange, f.classFor(&cx, 1));
}

test "factory framing pool: exclusive leases per instance, exhaustion fails closed" {
    const a = std.testing.allocator;
    var f = Factory{ .a = a, .sym = undefined, .identity = @splat(0) };
    defer f.deinit();
    var inst: [2]Schema.ClassFraming = undefined;
    for (&inst) |*x| {
        x.key = @splat(7);
        x.program = .{ .a = a, .words = &.{}, .max_encoded_bytes = 0, .pcs_words = 0 };
        x.global_patches = &.{};
        x.comp_patches = .{};
        x.oods = null;
    }
    try f.registerUnchecked(&inst[0]);
    try f.registerUnchecked(&inst[1]);
    try std.testing.expectError(error.NativeStage2ClassConflict, f.registerUnchecked(&inst[1]));
    const x = try f.acquire(&inst[0]);
    const y = try f.acquire(&inst[0]);
    try std.testing.expect(x != y);
    try std.testing.expectError(error.NativeStage2FramingBusy, f.acquire(&inst[0]));
    f.releaseFraming(x);
    try std.testing.expectEqual(x, try f.acquire(&inst[0]));
    var other = inst[0];
    other.key = @splat(8);
    try std.testing.expectError(error.GpuNativeClassNotWarmed, f.acquire(&other));
}

test "stage2 / seal jobs and the factory seam type-check against the api" {
    _ = api.Job.from(Schema.Stage2Job, undefined);
    _ = api.Job.from(Schema.SealJob, undefined);
    _ = api.Job.from(SealOwned, undefined);
    _ = &Factory.stage2;
    _ = &Factory.seal;
    _ = &Factory.hooks;
    _ = &Factory.warm;
    _ = &Factory.register;
    _ = &Schema.ClassFraming.views;
    _ = &Schema.ClassFraming.image;
}

//! GPU-native truth factory (recursion stream, piece r-truth): the
//! RecursionFactory `truth` / `truth_stage2` entries over TruthJob
//! (truth_job.zig), and the class side the driver's memory plan reads.
//!
//!   install  `addClass` per truth class of the manifest's mix (K.build:
//!            host plans, framing, programs) -> `warm` publishes one
//!            gpu_native.ClassEntry per class: the stage-2 arena peak (the
//!            measured class peak once a receipt exists, else the declared
//!            one), held_words (the class-persistent FIXED tree and
//!            twiddles each worker keeps), extra checks (truth_root,
//!            root_match), the encoded-bytes bound.
//!   request  `begin(request, truths)` with the per-request host values
//!            (compact inputs packed from the capture, span, seed); then
//!            `stage1(rc, t, device)` writes the MAIN root into this GPU's
//!            Exchange.truthRoot(t) replica and publishes it to the peers,
//!            `stage2(rc, t, device)` reads the seal digest and that root from
//!            the same replica (the driver's DAG awaits both slots first), and
//!            every verdict lands in the request slab (gpu_native.publish).
//!            `end(request)` frees the request's jobs after publication.
//!
//! gn-truth: stage 2 runs in `encode = .device` (default): the OODS
//! constraint check (Check.truth_oods) and the WP.encodePhysical bytes are
//! produced on device into the truth's request-slab entry (encoded region,
//! encode_bounds, pcs_status); finish reads nothing the publication needs.
//!
//! Remaining host work per truth (listed in the receipt): compact packing
//! from the capture advice and the seed (worker_protocol.begin over the
//! request's statement: a few Blake2s), the per-job host table and the
//! stage-2 enqueue (launch-bound).
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const K = @import("truth_class.zig");
const TJ = @import("truth_job.zig");
const Warm = @import("truth_warm.zig");
const LF = @import("native_leaf_wire.zig");
const Worker = @import("worker.zig").Worker;

pub const Request = struct {
    leaf_program: ?*const LF.Program = null,
    class: G.ClassKey,
    calls: u32,
    first_id: u32,
    /// Packed compact inputs (K.packCompact); owned by the caller until `end`.
    compact: []const u32,
    seed: [9]u32,
};

pub const Factory = struct {
    a: std.mem.Allocator,
    sym: *const TJ.Symbols,
    workers: []const *Worker = &.{},
    mutex: std.Thread.Mutex = .{},
    classes: std.AutoHashMapUnmanaged(G.ClassKey, Entry) = .empty,
    /// Planning is serial, but two requests can execute concurrently. The
    /// selected request is only for classOf; jobs always resolve by rc.request.
    request: u64 = 0,
    requests: std.AutoHashMapUnmanaged(u64, *RequestState) = .empty,
    /// Stage-2 proof production: `.device` (GPU-native publication) or the
    /// r-truth host assembly (`.host`, bytes via `bytes()`).
    encode: TJ.Encode = .device,

    pub const RequestState = struct {
        truths: []Request,
        stage1_jobs: std.ArrayListUnmanaged(*TJ.Stage1) = .empty,
        stage2_jobs: std.ArrayListUnmanaged(*TJ.Stage2) = .empty,
        deferred: std.ArrayListUnmanaged(*Deferred) = .empty,
        captured: bool = false,
    };

    pub const Entry = struct {
        class: *K.Class,
        /// Measured stage-2 arena peak (receipt arena_peak_words), 0 = unmeasured.
        measured_peak_words: usize = 0,
        max_encoded_bytes: usize,
        devices: u8 = 0b11,
        planned_reuse: bool = false,
    };

    pub fn deinit(self: *Factory) void {
        var requests = self.requests.valueIterator();
        while (requests.next()) |r| self.releaseRequest(r.*);
        self.requests.deinit(self.a);
        var it = self.classes.valueIterator();
        while (it.next()) |e| {
            e.class.deinit();
            self.a.destroy(e.class);
        }
        self.classes.deinit(self.a);
    }

    /// Install time: take ownership of a built class (K.build + bindLaunches).
    /// `max_encoded_bytes`: the class bound (the PCS output plane bounds the
    /// proof: every proof word comes from it or from class geometry).
    pub fn addClass(self: *Factory, class: *K.Class, measured_peak_words: usize) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.classes.contains(class.key)) return error.TruthClassAlreadyAdded;
        const bound = encodedBound(class);
        try self.classes.put(self.a, class.key, .{ .class = class, .measured_peak_words = measured_peak_words, .max_encoded_bytes = bound });
    }

    /// Plan-time device words one worker holds for a class outside the arena:
    /// the persistent FIXED tree (coefficients + root) and the persistent
    /// twiddle towers it stages (commit plans, interaction logs, composition).
    pub fn heldWords(class: *const K.Class) u64 {
        var words: u64 = class.fixed_plan.coefficient_cells + 8;
        words += class.composition.persistentWords();
        for ([_]*const @import("native_commit.zig").CommitPlan{ &class.fixed_plan, &class.main_plan, &class.inter_plan }) |p| words += p.tw.twiddles.len + p.tw.itwiddles.len;
        for (class.roles) |r| words += r.interaction.twiddleWords();
        // gn-truth: the device OODS descriptor and encode program.
        words += class.oods.words.len + class.encode.words.len;
        return words;
    }

    /// The encoded-bytes capacity of a class: the device encoder's worst
    /// case (native_encode.Program, from the PCS shape), so the request-slab
    /// region is exactly the encoder's region.
    pub fn encodedBound(class: *const K.Class) usize {
        return class.encode.max_encoded_bytes;
    }

    /// RecursionFactory.warm for the truth classes.
    pub fn warm(self: *Factory, cache: *G.ClassCache) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.classes.iterator();
        while (it.next()) |kv| {
            kv.value_ptr.planned_reuse = self.workers.len != 0;
            for (self.workers) |worker| kv.value_ptr.planned_reuse = kv.value_ptr.planned_reuse and worker.config.reuse_frees;
            const Builder = struct {
                fn build(raw: *anyopaque, _: std.mem.Allocator, key: G.ClassKey) anyerror!G.ClassEntry {
                    const e: *Entry = @ptrCast(@alignCast(raw));
                    const c = e.class;
                    // Declared stage-2 peak for the largest supported span is the
                    // class's arena budget until a measured receipt replaces it.
                    const declared = TJ.stage2Footprint(c, maxCalls(c), 0, @intCast(c.pcs.outputWords()), @intCast(c.pcs.ingressWords())).device_words;
                    var held: [G.max_devices]u64 = @splat(0);
                    for (&held, 0..) |*h, d| {
                        if (d < 8 and (e.devices >> @intCast(d)) & 1 == 1) h.* = heldWords(c);
                    }
                    // The previous empirical PCS term undershot: measured/declared stage-2
                    // peak 0.68..1.48 over the 7 classes of 26235156 [M]
                    // (runs/m8-gpu-r-truth/parity-4, keccak log13 0.998e9 vs
                    // 0.676e9 words). Unmeasured classes budget 3/2 declared.
                    // [E] Reuse-mode guard, calibrated against the seven real
                    // classes in truth-reuse-1 (receipt checkpoint-1957.json).
                    // Their measured peaks stay below declared + max(MAIN,
                    // eight composition planes), including the lookup-heavy
                    // small Keccak classes. Unknown classes still require the
                    // full request gate; allocations remain arena-bounded.
                    const reuse_bound = declared + @max(c.mainEvalWords(), 8 * c.composition.coefficientWords());
                    const budget = if (e.measured_peak_words != 0) e.measured_peak_words else if (e.planned_reuse) reuse_bound else declared / 2 * 3;
                    std.debug.print("GPU_M8_TRUTH_CLASS_BOUND class={s} pcs_workspace_words={d} declared_words={d} reuse_padding_words={d} budget_words={d} physical_peak=false\n", .{ std.fmt.bytesToHex(key[0..6], .lower), c.pcs_workspace_words, declared, reuse_bound - declared, budget });
                    return .{ .key = key, .plan = c, .destroy = noDestroy, .max_encoded_bytes = e.max_encoded_bytes, .extra_checks = &K.Class.extra_checks, .arena_peak_words = budget, .resource_words = try Warm.resourceWords(c), .phase_a_peak_words = TJ.stage1Footprint(c, maxCalls(c), 0).device_words + 1024, .phase_b = true, .held_words = held, .cost_us = 1, .needs_capture_end = true };
                }
            };
            _ = try cache.warm(kv.key_ptr.*, .{ .ctx = kv.value_ptr, .build = Builder.build });
        }
    }
    fn noDestroy(_: *anyopaque) void {} // the factory owns the class
    pub fn installed(self: *Factory) !void {
        var it = self.classes.valueIterator();
        while (it.next()) |entry| {
            var job = Warm.Job{ .a = self.a, .class = entry.class, .sym = self.sym };
            try job.init();
            defer job.deinit();
            for (self.workers, 0..) |worker, d| {
                if (d >= 8 or (entry.devices >> @intCast(d)) & 1 == 0) continue;
                var done = struct {
                    n: std.atomic.Value(usize) = .init(0),
                    err: ?anyerror = null,
                    fn call(raw: *anyopaque, c: api.Completion) void {
                        const me: *@This() = @ptrCast(@alignCast(raw));
                        if (c.result) |_| {} else |err| me.err = err;
                        _ = me.n.fetchAdd(1, .seq_cst);
                    }
                }{};
                try worker.submit(api.Job.from(Warm.Job, &job), .{ .ctx = &done, .done = @TypeOf(done).call });
                while (done.n.load(.seq_cst) == 0) std.Thread.yield() catch {};
                if (done.err) |err| return err;
            }
        }
    }

    /// Install-only allocation measurement, after immutable resources are warm.
    /// Every enqueue allocation is determined by the class geometry; calls and
    /// values affect only the compact staging span and device contents. Run the
    /// complete device path with one synthetic call on both placement sides,
    /// then charge the largest class compact span. These are memory probes:
    /// their synthetic verdicts/proofs are discarded, never published or used
    /// as correctness evidence. Real requests retain every acceptance check.
    pub fn measureWarmPeaks(self: *Factory, cache: *G.ClassCache) !void {
        if (self.encode != .device or self.workers.len == 0) return;
        for (self.workers) |w| if (!w.config.reuse_frees) return;
        var it = self.classes.iterator();
        while (it.next()) |kv| {
            const c = kv.value_ptr.class;
            const compact = try self.a.alloc(u32, c.compactWords(1));
            defer self.a.free(compact);
            @memset(compact, 0);
            var probe = MemoryProbe{ .inner = .{ .a = self.a, .class = c, .sym = self.sym, .ordinal = 0, .calls = 1, .first_id = 1, .compact = compact, .seed = @splat(0), .digest_words = @splat(0), .encode = .device, .assemble_on_finish = false } };
            try probe.inner.init();
            defer probe.inner.deinit();
            var peak: u64 = 0;
            for (self.workers, 0..) |worker, device| {
                if (device >= 8 or (kv.value_ptr.devices >> @intCast(device)) & 1 == 0) continue;
                // peakOf adds the worker's channel-state allocation beyond
                // device_words. Reserve that prefix when taking the window.
                probe.window = std.math.sub(usize, worker.arenaWords(), @import("plan.zig").peakOf(.{ .device_words = 0 })) catch return error.InvalidArena;
                var sides: u8 = 0;
                for (0..2) |_| {
                    var done = struct {
                        event: std.Thread.ResetEvent = .{},
                        result: anyerror!void = {},
                        fn call(raw: *anyopaque, completion: api.Completion) void {
                            const me: *@This() = @ptrCast(@alignCast(raw));
                            me.result = completion.result;
                            me.event.set();
                        }
                    }{};
                    try worker.submit(api.Job.from(MemoryProbe, &probe), .{ .ctx = &done, .done = @TypeOf(done).call });
                    done.event.wait();
                    try done.result;
                    peak = @max(peak, probe.receipt.arena_peak_words);
                    sides |= @as(u8, 1) << @intCast(@intFromEnum(probe.receipt.placement));
                    std.debug.print("GPU_M9_TRUTH_MEMORY_PROBE class={s} device={d} side={s} arena_high_words={d} calls=1 correctness_claim=0\n", .{ std.fmt.bytesToHex(c.key[0..6], .lower), device, @tagName(probe.receipt.placement), probe.receipt.arena_peak_words });
                }
                if (sides != 3) return error.TruthMemoryProbePlacementMissing;
            }
            if (peak == 0) return error.TruthMemoryProbeMissing;
            const declared = TJ.stage2Footprint(c, maxCalls(c), 0, @intCast(c.pcs.outputWords()), @intCast(c.pcs.ingressWords())).device_words;
            // Keep the probe's private encoded region and slab in the bound,
            // although the request's encoded region is outside the arena.
            // Include staging granules, channel state and private fields.
            const compact_delta = std.mem.alignForward(usize, c.compactWords(maxCalls(c)), 64) - std.mem.alignForward(usize, compact.len, 64);
            const budget = @max(declared, peak + compact_delta) + 1024;
            kv.value_ptr.measured_peak_words = @intCast(budget);
            const entry = cache.map.get(kv.key_ptr.*) orelse return error.GpuNativeClassNotWarmed;
            entry.arena_peak_words = @intCast(budget);
            std.debug.print("GPU_M9_TRUTH_MEMORY_BUDGET class={s} measured_words={d} compact_delta_words={d} declared_words={d} budget_words={d}\n", .{ std.fmt.bytesToHex(c.key[0..6], .lower), peak, compact_delta, declared, budget });
        }
    }

    const MemoryProbe = struct {
        inner: TJ.Stage2,
        window: usize = 0,
        receipt: api.Receipt = .{},
        pub fn classKey(self: *MemoryProbe) [32]u8 {
            return self.inner.classKey();
        }
        pub fn footprint(self: *MemoryProbe) api.Footprint {
            var fp = self.inner.footprint();
            fp.device_words = self.window;
            fp.slab_words = 0;
            return fp;
        }
        pub fn stage(self: *MemoryProbe, s: *api.Stager) !void {
            try self.inner.stage(s);
        }
        pub fn enqueue(self: *MemoryProbe, e: *api.Enqueue) !void {
            const saved = e.slab.*;
            defer e.slab.* = saved;
            e.slab.* = .{ .device = try e.alloc(self.inner.layout.words) };
            try self.inner.enqueue(e);
        }
        pub fn finish(self: *MemoryProbe, view: api.SlabView) !void {
            self.receipt = view.receipt;
        }
        pub fn abort(_: *MemoryProbe) void {}
    };

    /// Largest call count a class's log admits (rows = 2^log; keccak packs
    /// several calls per row group, but compact words scale with calls only
    /// in staging, which is a small term of the footprint).
    fn maxCalls(c: *const K.Class) u32 {
        return @intCast(@as(u64, 1) << @intCast(c.log));
    }

    /// RecursionFactory.class_of for a truth: the class registered for its
    /// ordinal in the current request.
    pub fn classOf(self: *Factory, ordinal: u32) !G.ClassKey {
        self.mutex.lock();
        defer self.mutex.unlock();
        const r = self.requests.get(self.request) orelse return error.GpuNativeTruthUnknown;
        if (ordinal >= r.truths.len) return error.GpuNativeTruthUnknown;
        return r.truths[ordinal].class;
    }

    /// Per-request host values (the driver: from the capture and the statement).
    pub fn begin(self: *Factory, request: u64, truths: []const Request) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.requests.contains(request)) return error.TruthFactoryRequestOpen;
        for (truths) |t| if (!self.classes.contains(t.class)) return error.GpuNativeClassNotWarmed;
        const r = try self.a.create(RequestState);
        errdefer self.a.destroy(r);
        r.* = .{ .truths = try self.a.dupe(Request, truths) };
        errdefer self.a.free(r.truths);
        try self.requests.put(self.a, request, r);
        self.request = request;
    }
    /// After publication: free the request's jobs (their bytes/claims too).
    pub fn end(self: *Factory, request: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const r = self.requests.fetchRemove(request) orelse return error.TruthFactoryRequestMismatch;
        self.releaseRequest(r.value);
        if (self.request == request) self.request = 0;
    }
    /// Capture-end handoff. Metadata admitted at begin is immutable; only
    /// witness words are supplied now, before any deferred job is staged.
    pub fn setCaptured(self: *Factory, request: u64, truths: []const Request) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const r = self.requests.get(request) orelse return error.TruthFactoryRequestMismatch;
        if (r.captured or r.truths.len != truths.len) return error.TruthCaptureShape;
        for (r.truths, truths) |old, new| {
            if (!std.mem.eql(u8, &old.class, &new.class) or old.calls != new.calls or old.first_id != new.first_id or !std.mem.eql(u32, &old.seed, &new.seed)) return error.TruthCaptureShape;
            const class = self.classes.get(old.class) orelse return error.GpuNativeClassNotWarmed;
            if (new.compact.len != class.class.compactWords(new.calls)) return error.TruthCompactShape;
        }
        for (r.truths, truths) |*old, new| old.compact = new.compact;
        r.captured = true;
    }
    fn releaseRequest(self: *Factory, r: *RequestState) void {
        for (r.stage1_jobs.items) |j| {
            j.deinit();
            self.a.destroy(j);
        }
        for (r.stage2_jobs.items) |j| {
            if (j.bytes.len != 0) self.a.free(j.bytes);
            if (j.out_claims.len != 0) self.a.free(j.out_claims);
            if (j.device_bytes.len != 0) self.a.free(j.device_bytes);
            j.deinit();
            self.a.destroy(j);
        }
        r.stage1_jobs.deinit(self.a);
        r.stage2_jobs.deinit(self.a);
        for (r.deferred.items) |d| self.a.destroy(d);
        r.deferred.deinit(self.a);
        self.a.free(r.truths);
        self.a.destroy(r);
    }

    fn lookup(self: *Factory, r: *const RequestState, ordinal: u32) !struct { req: Request, class: *const K.Class } {
        if (ordinal >= r.truths.len) return error.GpuNativeTruthUnknown;
        const req = r.truths[ordinal];
        const e = self.classes.getPtr(req.class) orelse return error.GpuNativeClassNotWarmed;
        return .{ .req = req, .class = e.class };
    }

    /// Device views of one GPU's request-slab segment.
    pub const Views = struct {
        root: api.DeviceBuffer,
        seal_digest: api.DeviceBuffer,
        truth_root_slot: G.Exchange.Slot,
        verdicts: TJ.Verdicts,
        /// The truth's encoded region (length word + bytes).
        encoded: api.DeviceBuffer,
    };
    pub fn views(rc: *const G.RequestContext, ordinal: u32, device: u32) !Views {
        if (device >= rc.segments.len or device >= rc.layout.segments.len) return error.GpuNativeProofDeviceOutOfRange;
        const segment = rc.segments[device];
        const layout = &rc.layout.segments[device];
        const exchange = try layout.exchangeBuffer(segment);
        const slot = try rc.exchange.truthRoot(ordinal);
        const seal = rc.exchange.seal();
        const id = G.ProofId{ .kind = .truth, .ordinal = ordinal };
        return .{
            .root = try exchange.slice(slot.offset, slot.words),
            .seal_digest = try exchange.slice(seal.offset, G.Exchange.seal_digest_words),
            .truth_root_slot = slot,
            .verdicts = .{
                .truth_root = try layout.statusBuffer(segment, id, .truth_root),
                .truth_status = try layout.statusBuffer(segment, id, .truth_status),
                .root_match = try layout.statusBuffer(segment, id, .root_match),
                .channel_order = try layout.statusBuffer(segment, id, .channel_order),
                .pcs_status = try layout.statusBuffer(segment, id, .pcs_status),
                .truth_oods = try layout.statusBuffer(segment, id, .truth_oods),
                .encode_bounds = try layout.statusBuffer(segment, id, .encode_bounds),
            },
            .encoded = try layout.encodedBuffer(segment, id),
        };
    }

    /// RecursionFactory.truth (stage 1).
    pub fn stage1(self: *Factory, rc: *const G.RequestContext, ordinal: u32, device: u32) !api.Job {
        return self.deferJob(rc, ordinal, device, false);
    }
    pub fn stage2(self: *Factory, rc: *const G.RequestContext, ordinal: u32, device: u32) !api.Job {
        if (self.encode != .device) return self.makeStage2(rc, ordinal, device);
        return self.deferJob(rc, ordinal, device, true);
    }
    fn deferJob(self: *Factory, rc: *const G.RequestContext, ordinal: u32, device: u32, second: bool) !api.Job {
        self.mutex.lock();
        defer self.mutex.unlock();
        const r = self.requests.get(rc.request) orelse return error.TruthFactoryRequestMismatch;
        const found = try self.lookup(r, ordinal);
        var fp = if (second) TJ.stage2RequestFootprint(found.class, found.req.calls, @intCast(found.class.pcs.outputWords()), @intCast(found.class.pcs.ingressWords())) else TJ.stage1Footprint(found.class, found.req.calls, 0);
        fp.device_words += 1024; // private diagnostic fields, device-only
        if (second) {
            // Pair admission must see the same measured bound as the driver's
            // phase plan, not the older PCS estimate in stage2Footprint.
            const entry = self.classes.get(found.req.class) orelse return error.GpuNativeClassNotWarmed;
            fp.device_words = @max(fp.device_words, entry.measured_peak_words);
        }
        const d = try self.a.create(Deferred);
        errdefer self.a.destroy(d);
        d.* = .{ .factory = self, .ctx = rc, .ordinal = ordinal, .device = device, .second = second, .budget = fp, .key = found.req.class };
        try r.deferred.append(self.a, d);
        return api.Job.from(Deferred, d);
    }
    const Deferred = struct {
        factory: *Factory,
        ctx: *const G.RequestContext,
        ordinal: u32,
        device: u32,
        second: bool,
        budget: api.Footprint,
        key: G.ClassKey,
        inner: ?api.Job = null,
        pub fn classKey(self: *Deferred) [32]u8 {
            var key = self.key;
            key[0] ^= if (self.second) @as(u8, 0x72) else @as(u8, 0x71);
            return key;
        }
        pub fn footprint(self: *Deferred) api.Footprint {
            return self.budget;
        }
        pub fn stage(self: *Deferred, stager: *api.Stager) !void {
            if (self.inner != null) return error.TruthJobAlreadyStaged;
            const job = if (self.second) try self.factory.makeStage2(self.ctx, self.ordinal, self.device) else try self.factory.makeStage1(self.ctx, self.ordinal, self.device);
            self.inner = job;
            const actual = job.vtable.footprint(job.ctx);
            if (actual.device_words > self.budget.device_words or actual.staged_words > self.budget.staged_words or actual.pinned_words > self.budget.pinned_words or actual.slab_words != 0) return error.TruthFootprintExceedsClass;
            try job.vtable.stage(job.ctx, stager);
        }
        pub fn enqueue(self: *Deferred, e: *api.Enqueue) !void {
            const job = self.inner orelse return error.TruthJobNotStaged;
            try job.vtable.enqueue(job.ctx, e);
        }
        pub fn finish(self: *Deferred, view: api.SlabView) !void {
            const job = self.inner orelse return error.TruthJobNotStaged;
            try job.vtable.finish(job.ctx, view);
        }
        pub fn abort(self: *Deferred) void {
            if (self.inner) |job| job.vtable.abort(job.ctx);
        }
    };
    fn makeStage1(self: *Factory, rc: *const G.RequestContext, ordinal: u32, device: u32) !api.Job {
        self.mutex.lock();
        defer self.mutex.unlock();
        const r = self.requests.get(rc.request) orelse return error.TruthFactoryRequestMismatch;
        const found = try self.lookup(r, ordinal);
        const v = try views(rc, ordinal, device);
        const job = try self.a.create(TJ.Stage1);
        errdefer self.a.destroy(job);
        job.* = .{ .a = self.a, .class = found.class, .sym = self.sym, .ordinal = ordinal, .calls = found.req.calls, .first_id = found.req.first_id, .compact = found.req.compact, .root_out = v.root, .publish = .{ .peer = rc.peer, .device = device, .slot = v.truth_root_slot }, .verdicts = .{ .truth_root = v.verdicts.truth_root }, .request_slab_only = true };
        try job.init();
        errdefer job.deinit();
        try r.stage1_jobs.append(self.a, job);
        return job.job();
    }

    /// RecursionFactory.truth_stage2 (after the device seal, same GPU).
    fn makeStage2(self: *Factory, rc: *const G.RequestContext, ordinal: u32, device: u32) !api.Job {
        self.mutex.lock();
        defer self.mutex.unlock();
        const r = self.requests.get(rc.request) orelse return error.TruthFactoryRequestMismatch;
        const found = try self.lookup(r, ordinal);
        const v = try views(rc, ordinal, device);
        var verdicts = v.verdicts;
        verdicts.truth_root = null; // stage 1's word
        if (self.encode == .host) {
            // r-truth host path: no device OODS / encoder words are written.
            verdicts.truth_oods = null;
            verdicts.encode_bounds = null;
        }
        const job = try self.a.create(TJ.Stage2);
        errdefer self.a.destroy(job);
        job.* = .{ .a = self.a, .class = found.class, .sym = self.sym, .ordinal = ordinal, .calls = found.req.calls, .first_id = found.req.first_id, .compact = found.req.compact, .seed = found.req.seed, .digest = v.seal_digest, .stage1_root = v.root, .verdicts = verdicts, .encode = self.encode, .encoded = if (self.encode == .host) null else v.encoded, .request_slab_only = self.encode == .device, .leaf_program = found.req.leaf_program };
        try job.init();
        errdefer job.deinit();
        try r.stage2_jobs.append(self.a, job);
        return job.job();
    }

    /// The truth's legacy proof bytes after its stage-2 finish (host
    /// assembly), null before; valid until `end`. Always null in the default
    /// `encode = .device`: the bytes are the truth's request-slab encoded
    /// region (gpu_native publication), never assembled on the host.
    pub fn bytes(self: *Factory, ordinal: u32) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const r = self.requests.get(self.request) orelse return null;
        for (r.stage2_jobs.items) |j| if (j.ordinal == ordinal and j.bytes.len != 0) return j.bytes;
        return null;
    }
};

const testing = std.testing;

test "truth factory: two requests retain separate inputs and teardown" {
    const a = testing.allocator;
    var f = Factory{ .a = a, .sym = undefined };
    defer f.deinit();
    var class: K.Class = undefined;
    const ka: G.ClassKey = @splat(1);
    const kb: G.ClassKey = @splat(2);
    try f.classes.put(a, ka, .{ .class = &class, .max_encoded_bytes = 64 });
    defer _ = f.classes.remove(ka);
    try f.classes.put(a, kb, .{ .class = &class, .max_encoded_bytes = 64 });
    defer _ = f.classes.remove(kb);
    var first = [_]Request{.{ .class = ka, .calls = 3, .first_id = 1, .compact = &.{}, .seed = @splat(11) }};
    const second = [_]Request{.{ .class = kb, .calls = 5, .first_id = 7, .compact = &.{}, .seed = @splat(22) }};
    try f.begin(1, &first);
    first[0].seed = @splat(99); // Factory owns the metadata snapshot.
    try f.begin(2, &second);
    try testing.expectError(error.TruthFactoryRequestOpen, f.begin(1, &first));
    try testing.expectEqual(@as(u32, 11), (try f.lookup(f.requests.get(1).?, 0)).req.seed[0]);
    try testing.expectEqual(@as(u32, 22), (try f.lookup(f.requests.get(2).?, 0)).req.seed[0]);
    try testing.expectEqualSlices(u8, &kb, &try f.classOf(0));
    try f.end(1);
    try testing.expect(f.requests.contains(2));
    try testing.expectEqualSlices(u8, &kb, &try f.classOf(0));
    try f.end(2);
    try testing.expectEqual(@as(usize, 0), f.requests.count());
}

test "truth views address this GPU's exchange replica and the request-slab verdict words" {
    const a = testing.allocator;
    const exchange = G.Exchange{ .segments = 2, .claims_per_segment = 1, .devices = 2, .truths = 3, .capacity_truths = 4 };
    const proofs = [_]G.ProofSpec{
        .{ .id = .{ .kind = .request, .ordinal = 0 }, .device = 0, .max_encoded_bytes = 0 },
        .{ .id = .{ .kind = .truth, .ordinal = 0 }, .device = 0, .max_encoded_bytes = 4096, .extra_checks = &K.Class.extra_checks },
        .{ .id = .{ .kind = .truth, .ordinal = 2 }, .device = 1, .max_encoded_bytes = 4096, .extra_checks = &K.Class.extra_checks },
    };
    var layout = try G.RequestLayout.build(a, 2, &proofs, exchange);
    defer layout.deinit();
    var mem: [2][]u32 = undefined;
    for (&mem, layout.segments) |*m, s| m.* = try a.alloc(u32, s.words);
    defer for (mem) |m| a.free(m);
    const segments = [2]api.DeviceBuffer{ .{ .ptr = mem[0].ptr, .words = mem[0].len }, .{ .ptr = mem[1].ptr, .words = mem[1].len } };
    var cache = G.ClassCache.init(a);
    defer cache.deinit();
    const peer = G.PeerExchange{ .ctx = undefined, .vtable = undefined };
    const rc = G.RequestContext{ .request = 9, .layout = &layout, .exchange = exchange, .peer = peer, .classes = &cache, .segments = &segments };
    const v = try Factory.views(&rc, 2, 1);
    const ex = layout.segments[1].exchange_offset;
    try testing.expectEqual(@intFromPtr(mem[1].ptr + ex + (try exchange.truthRoot(2)).offset), @intFromPtr(v.root.ptr));
    try testing.expectEqual(@intFromPtr(mem[1].ptr + ex + exchange.seal().offset), @intFromPtr(v.seal_digest.ptr));
    // The encoded region is truth 2's directory region: length word + capacity.
    try testing.expectEqual(@as(usize, 1 + 4096 / 4), v.encoded.words);
    try testing.expect(@intFromPtr(v.encoded.ptr) >= @intFromPtr(mem[1].ptr + layout.segments[1].encoded_offset));
    try testing.expectEqual(@as(usize, 8), v.seal_digest.words);
    // Every verdict is a distinct status word of truth 2's directory entry.
    const words = [_]api.DeviceBuffer{ v.verdicts.truth_root.?, v.verdicts.truth_status.?, v.verdicts.root_match.?, v.verdicts.channel_order.?, v.verdicts.pcs_status.?, v.verdicts.truth_oods.?, v.verdicts.encode_bounds.? };
    for (words, 0..) |w, i| {
        try testing.expectEqual(@as(usize, 1), w.words);
        for (words[0..i]) |x| try testing.expect(x.ptr != w.ptr);
    }
    // A truth this GPU's segment does not hold (ordinal 0 lives on GPU 0) has no words here.
    try testing.expectError(error.GpuNativeUnknownProof, Factory.views(&rc, 0, 1));
    try testing.expectError(error.GpuNativeExchangeSlot, Factory.views(&rc, 3, 1));
    try testing.expectError(error.GpuNativeProofDeviceOutOfRange, Factory.views(&rc, 2, 2));
}

test "factory refuses requests over unknown classes and mismatched request ids" {
    var sym: TJ.Symbols = undefined;
    var f = Factory{ .a = testing.allocator, .sym = &sym };
    defer f.deinit();
    const unknown = [_]Request{.{ .class = @splat(7), .calls = 1, .first_id = 1, .compact = &.{}, .seed = @splat(0) }};
    try testing.expectError(error.GpuNativeClassNotWarmed, f.begin(1, &unknown));
    try f.begin(2, &.{});
    try testing.expectError(error.GpuNativeTruthUnknown, f.classOf(0));
    try testing.expectError(error.TruthFactoryRequestMismatch, f.end(3));
    try f.end(2);
}

test "factory entry points are fully analyzed" {
    _ = &Factory.warm;
    _ = &Factory.stage1;
    _ = &Factory.stage2;
    _ = &Factory.bytes;
    _ = &Factory.addClass;
    _ = &Factory.heldWords;
}

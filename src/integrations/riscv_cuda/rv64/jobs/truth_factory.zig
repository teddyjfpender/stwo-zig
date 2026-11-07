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

pub const Request = struct {
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
    mutex: std.Thread.Mutex = .{},
    classes: std.AutoHashMapUnmanaged(G.ClassKey, Entry) = .empty,
    request: u64 = 0,
    truths: []const Request = &.{},
    stage1_jobs: std.ArrayListUnmanaged(*TJ.Stage1) = .empty,
    stage2_jobs: std.ArrayListUnmanaged(*TJ.Stage2) = .empty,
    /// Stage-2 proof production: `.device` (GPU-native publication) or the
    /// r-truth host assembly (`.host`, bytes via `bytes()`).
    encode: TJ.Encode = .device,

    pub const Entry = struct {
        class: *K.Class,
        /// Measured stage-2 arena peak (receipt arena_peak_words), 0 = unmeasured.
        measured_peak_words: usize = 0,
        max_encoded_bytes: usize,
        devices: u8 = 0b11,
    };

    pub fn deinit(self: *Factory) void {
        self.releaseJobs();
        var it = self.classes.valueIterator();
        while (it.next()) |e| {
            e.class.deinit();
            self.a.destroy(e.class);
        }
        self.classes.deinit(self.a);
        self.stage1_jobs.deinit(self.a);
        self.stage2_jobs.deinit(self.a);
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
                    // The declared PCS term undershoots: measured/declared stage-2
                    // peak 0.68..1.48 over the 7 classes of 26235156 [M]
                    // (runs/m8-gpu-r-truth/parity-4, keccak log13 0.998e9 vs
                    // 0.676e9 words). Unmeasured classes budget 3/2 declared.
                    const budget = if (e.measured_peak_words != 0) e.measured_peak_words else declared / 2 * 3;
                    return .{ .key = key, .plan = c, .destroy = noDestroy, .max_encoded_bytes = e.max_encoded_bytes, .extra_checks = &K.Class.extra_checks, .arena_peak_words = budget, .held_words = held, .cost_us = 1 };
                }
            };
            _ = try cache.warm(kv.key_ptr.*, .{ .ctx = kv.value_ptr, .build = Builder.build });
        }
    }
    fn noDestroy(_: *anyopaque) void {} // the factory owns the class

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
        if (ordinal >= self.truths.len) return error.GpuNativeTruthUnknown;
        return self.truths[ordinal].class;
    }

    /// Per-request host values (the driver: from the capture and the statement).
    pub fn begin(self: *Factory, request: u64, truths: []const Request) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.stage1_jobs.items.len != 0 or self.stage2_jobs.items.len != 0) return error.TruthFactoryRequestOpen;
        for (truths) |t| if (!self.classes.contains(t.class)) return error.GpuNativeClassNotWarmed;
        self.request = request;
        self.truths = truths;
    }
    /// After publication: free the request's jobs (their bytes/claims too).
    pub fn end(self: *Factory, request: u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (request != self.request) return error.TruthFactoryRequestMismatch;
        self.releaseJobs();
        self.truths = &.{};
    }
    fn releaseJobs(self: *Factory) void {
        for (self.stage1_jobs.items) |j| {
            j.deinit();
            self.a.destroy(j);
        }
        for (self.stage2_jobs.items) |j| {
            if (j.bytes.len != 0) self.a.free(j.bytes);
            if (j.out_claims.len != 0) self.a.free(j.out_claims);
            if (j.device_bytes.len != 0) self.a.free(j.device_bytes);
            j.deinit();
            self.a.destroy(j);
        }
        self.stage1_jobs.clearRetainingCapacity();
        self.stage2_jobs.clearRetainingCapacity();
    }

    fn lookup(self: *Factory, ordinal: u32) !struct { req: Request, class: *const K.Class } {
        if (ordinal >= self.truths.len) return error.GpuNativeTruthUnknown;
        const req = self.truths[ordinal];
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
        self.mutex.lock();
        defer self.mutex.unlock();
        if (rc.request != self.request) return error.TruthFactoryRequestMismatch;
        const found = try self.lookup(ordinal);
        const v = try views(rc, ordinal, device);
        const job = try self.a.create(TJ.Stage1);
        errdefer self.a.destroy(job);
        job.* = .{ .a = self.a, .class = found.class, .sym = self.sym, .ordinal = ordinal, .calls = found.req.calls, .first_id = found.req.first_id, .compact = found.req.compact, .root_out = v.root, .publish = .{ .peer = rc.peer, .device = device, .slot = v.truth_root_slot }, .verdicts = .{ .truth_root = v.verdicts.truth_root } };
        try job.init();
        errdefer job.deinit();
        try self.stage1_jobs.append(self.a, job);
        return job.job();
    }

    /// RecursionFactory.truth_stage2 (after the device seal, same GPU).
    pub fn stage2(self: *Factory, rc: *const G.RequestContext, ordinal: u32, device: u32) !api.Job {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (rc.request != self.request) return error.TruthFactoryRequestMismatch;
        const found = try self.lookup(ordinal);
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
        job.* = .{ .a = self.a, .class = found.class, .sym = self.sym, .ordinal = ordinal, .calls = found.req.calls, .first_id = found.req.first_id, .compact = found.req.compact, .seed = found.req.seed, .digest = v.seal_digest, .stage1_root = v.root, .verdicts = verdicts, .encode = self.encode, .encoded = if (self.encode == .host) null else v.encoded };
        try job.init();
        errdefer job.deinit();
        try self.stage2_jobs.append(self.a, job);
        return job.job();
    }

    /// The truth's legacy proof bytes after its stage-2 finish (host
    /// assembly), null before; valid until `end`.
    pub fn bytes(self: *Factory, ordinal: u32) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.stage2_jobs.items) |j| if (j.ordinal == ordinal and j.bytes.len != 0) return j.bytes;
        return null;
    }
};

const testing = std.testing;

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

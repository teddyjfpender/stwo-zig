//! M8 GPU-native native Stage 2 and the device global seal (stream native,
//! piece n-stage2; rv64-m8-gpu-native.md §3.2, §3.5, §3.6; inventory H8-H13).
//! native_device.zig's `stage2` / `seal` vtable entries come here.
//!
//! Seal (one job on the seal GPU, after every segment's MAIN root slot has
//! landed in its exchange replica): the manifest chi chain over the roster
//! (native_seal_chi.cu: MAIN-only rho, chain step, chi) -> the 16-word seal
//! slot (chi, then 0) peer-published to the other GPUs; Check.global_seal.
//! The host never reads a root, a digest or a challenge.
//!
//! Stage 2 (per segment, on the segment's GPU, after the seal slot landed):
//!   channel <- the segment's Stage-1 checkpoint (handoff region)
//!   shared  <- drawShared(seal chi) on device (native_seal_chi.cu)
//!   patch   global projection parameters and the composition table's
//!           shared / local / binding / hc / public parameters on device from
//!           the shared draws, the Stage-1 semantic handoff and the segment's
//!           public statement input (class tables, validated at warm)
//!   globals -> claims; mixManifestAndClaims(chi, claims) on the device channel
//!   INTER commit, alpha, composition, OODS, enqueue-only PCS (job arena)
//!   checks  global_status, composition_accept, public_claims, root_match,
//!           pcs_status, channel_order, encode_bounds -> request slab words
//!   encode  the exact WP.encodePhysical bytes into the slab (native_encode)
//! with the class framing (globals/INTER/composition plans, PcsJob framing,
//! encode program, patch tables) from the class cache only (`Classes`).
//!
//! NOT on device yet (fails closed: the status word stays `unset`, so
//! publication refuses): Check.oods_constraint (the point-eval instance of
//! the AOT composition codegen). See remaining host work in the receipt.
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const NE = @import("native_encode.zig");
const C = @import("native_commit.zig");
const N = @import("native_pcs.zig");
const S2 = @import("native_stage2.zig");
const NComp = @import("native_composition.zig");
const Gl = @import("native_global.zig");
const HJ = @import("native_hybrid_jobs.zig");
const B = @import("native_binding.zig");
const JP = @import("../joined_parameters.zig");

// ---------------------------------------------------------------------------
// Seal: constants and roster
// ---------------------------------------------------------------------------

pub const SealEntry = extern struct {
    k: u32,
    family: u32,
    rung: u32,
    root_offset: u32 = std.math.maxInt(u32),
    flag_offset: u32 = std.math.maxInt(u32),
    reserved: [3]u32 = @splat(0),
    vkhash: [8]u32,
    stmt: [8]u32,
    s_in: [8]u32,
    s_out: [8]u32,
    main_const: [8]u32 = @splat(0),
};
pub const SealConstants = extern struct {
    rho_tag: [8]u32,
    seg_tag: [8]u32,
    chi_tag: [8]u32,
    m0: [8]u32,
    execution: [8]u32,
    channel_init: [8]u32,
    ram_header: u32 = 14,
    kio_header: u32 = 11,
    wire_header: u32 = 35,
    ram_draws: u32 = JP.ram_count,
    kio_draws: u32 = JP.kio_count,
    wire_draws: u32 = JP.wire_count,
    entries: u32,
    tag: u32,
    /// secp256k1 equations WireFor.draw mixes this word before drawing.
    wire_pre: u32 = 0x53575031,
    reserved: u32 = 0,
};
comptime {
    if (@sizeOf(SealEntry) != 48 * 4 or @sizeOf(SealConstants) != 58 * 4) @compileError("seal ABI changed");
}
/// Shared felts drawn per request, in the joined-parameter shared namespace
/// order (RAM offset+14, KIO offset+arity, Wire offset+arity) = JP.ram..JP.claims.
pub const shared_felts: u32 = JP.ram_count + JP.kio_count + JP.wire_count;

pub fn words8(d: [32]u8) [8]u32 {
    var w: [8]u32 = undefined;
    for (&w, 0..) |*x, i| x.* = std.mem.readInt(u32, d[4 * i ..][0..4], .little);
    return w;
}
const Blake = std.crypto.hash.blake2.Blake2s256;
/// canon_native Tag.digest: Blake2s-256(tag name).
pub fn tagDigest(name: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Blake.hash(name, &out, .{});
    return out;
}
/// canon_native.chainIv(identity) = H(iv, identity).
pub fn chainIv(identity: [32]u8) [32]u8 {
    var h = Blake.init(.{});
    h.update(&tagDigest("rv64-m5-chain-iv/v1"));
    h.update(&identity);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}
/// Om31Channel.init() digest (the shared-draw channel's initial state).
pub fn om31InitDigest() [32]u8 {
    const Ch = @import("stwo_core").channel.raw_mod_m31.Om31Channel;
    return Ch.init().inner.digest;
}

/// `identity`: chain.versionIdentity(version) of the service policy (a
/// constant of the service); `execution`: the request statement digest (chi
/// input); `tag`: the request's exchange flag tag.
pub fn sealConstants(identity: [32]u8, execution: [32]u8, entries: u32, tag: u32) SealConstants {
    return .{
        .rho_tag = words8(tagDigest("rv64-m5-rho/v1")),
        .seg_tag = words8(tagDigest("rv64-m5-seg")),
        .chi_tag = words8(tagDigest("rv64-m5-chi")),
        .m0 = words8(chainIv(identity)),
        .execution = words8(execution),
        .channel_init = words8(om31InitDigest()),
        .entries = entries,
        .tag = tag,
    };
}

/// One roster entry (Manifest.ExpectedWorker chain fields, in roster order).
/// `segment`: the native segment whose MAIN root slot carries this entry's
/// root; null: `root` is a constant known before the request (a truth whose
/// root is not exchanged yet; see INTERFACES m8-gpu-n-stage2).
pub const RosterEntry = struct {
    family: u32,
    rung: u32,
    vkhash: [32]u8,
    stmt: [32]u8,
    s_in: [32]u8,
    s_out: [32]u8,
    segment: ?u32 = null,
    root: [32]u8 = @splat(0),
};
pub fn sealEntries(a: std.mem.Allocator, roster: []const RosterEntry, exchange: G.Exchange) ![]SealEntry {
    const out = try a.alloc(SealEntry, roster.len);
    errdefer a.free(out);
    for (roster, out, 0..) |r, *e, k| {
        e.* = .{ .k = @intCast(k), .family = r.family, .rung = r.rung, .vkhash = words8(r.vkhash), .stmt = words8(r.stmt), .s_in = words8(r.s_in), .s_out = words8(r.s_out), .main_const = words8(r.root) };
        if (r.segment) |s| {
            const slot = try exchange.root(s);
            e.root_offset = @intCast(slot.offset);
            e.flag_offset = @intCast(slot.flag);
        }
    }
    return out;
}

pub const SealFn = *const fn (*anyopaque, u32, [*]const SealEntry, [*]const u32, u64, *const SealConstants, [*]u32, [*]u32, [*]const SealEntry) callconv(.c) c_int;
pub const SharedFn = *const fn (*anyopaque, u32, [*]const u32, *const SealConstants, [*]u32, u64) callconv(.c) c_int;
pub const SealSymbols = struct {
    seal: SealFn,
    shared: SharedFn,
    pub fn load(addon: *std.DynLib) !SealSymbols {
        return .{
            .seal = addon.lookup(SealFn, "stwo_rv64_native_seal_chi_v1_on") orelse return error.MissingNativeSealSymbol,
            .shared = addon.lookup(SharedFn, "stwo_rv64_native_seal_shared_v1_on") orelse return error.MissingNativeSealSymbol,
        };
    }
};

pub fn rcOf(code: c_int) !void {
    return rc(code);
}
fn rc(code: c_int) !void {
    if (code != 0) return error.CudaEnqueueFailed;
}

/// Replica of the exchange region on `device` (inside its slab segment).
pub fn replica(ctx: *const G.RequestContext, device: u32) !api.DeviceBuffer {
    return ctx.layout.segments[device].exchangeBuffer(ctx.segments[device]);
}

/// The seal job (NativeFactory.seal). Footprint: the entries (staged) only.
pub const SealJob = struct {
    a: std.mem.Allocator,
    sym: *const SealSymbols,
    ctx: *const G.RequestContext,
    device: u32,
    entries: []const SealEntry,
    constants: SealConstants,
    staged: ?api.DeviceBuffer = null,

    pub fn classKey(_: *SealJob) [32]u8 {
        return tagDigest("rv64-m8-gpu-native-seal/v1");
    }
    pub fn footprint(self: *SealJob) api.Footprint {
        const w = std.mem.alignForward(usize, self.entries.len * 48, 64);
        return .{ .device_words = w, .staged_words = w, .pinned_words = w };
    }
    pub fn stage(self: *SealJob, s: *api.Stager) !void {
        const b = try s.alloc(self.entries.len * 48);
        try s.upload(b, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(self.entries)));
        self.staged = b;
    }
    pub fn enqueue(self: *SealJob, e: *api.Enqueue) !void {
        const ctx = self.ctx;
        const staged = self.staged orelse return error.NativeSealNotStaged;
        // Every segment's MAIN root slot, from whichever GPU produced it.
        for (ctx.segment_device, 0..) |src, s| try ctx.peer.awaitSlot(self.device, src, try ctx.exchange.root(@intCast(s)));
        const x = try replica(ctx, self.device);
        const seal = ctx.exchange.seal();
        const slot = try x.slice(seal.offset, seal.words);
        const verdict = try ctx.layout.segments[self.device].statusBuffer(ctx.segments[self.device], .{ .kind = .request, .ordinal = 0 }, .global_seal);
        try rc(self.sym.seal(e.ctx(), 0, @ptrCast(staged.ptr), x.ptr, x.words, &self.constants, slot.ptr, verdict.ptr, self.entries.ptr));
        try ctx.peer.publish(self.device, seal);
    }
    pub fn finish(_: *SealJob, _: api.SlabView) !void {}
    pub fn abort(_: *SealJob) void {}
};

// ---------------------------------------------------------------------------
// Stage-1 -> Stage-2 handoff (contract with piece n-stage1; INTERFACES)
// ---------------------------------------------------------------------------

/// Request-retained regions Stage1 creates (Stager/Enqueue.retain) and Stage2
/// finds (Stager.retained), keyed by segment:
///   checkpoint  9 words: the post-MAIN/GKR channel digest[8], draws
///               (CpuWorker.channel before mixManifestAndClaims)
///   binding     the binding plan's output words (16 coefficient columns per
///               binding instance, native_binding.Plan layout)
///   semantic    felts (8 words each): the joined-parameter local + binding
///               namespaces (JP.local .. JP.eta + 4), then every role's hc
///               rows (16 * trace_log words per hc role, role order)
pub const Handoff = enum(u8) { checkpoint = 1, binding = 2, semantic = 3 };
pub fn handoffName(kind: Handoff, segment: u32) [32]u8 {
    var n: [32]u8 = @splat(0);
    @memcpy(n[0..16], "rv64-gn-s1-hand.");
    n[16] = @intFromEnum(kind);
    std.mem.writeInt(u32, n[20..24], segment, .little);
    return n;
}
pub const checkpoint_words: usize = 9;
/// Felts of the semantic handoff before the hc rows.
pub const semantic_felts: u32 = JP.eta + 4 - JP.local;

// ---------------------------------------------------------------------------
// Device parameter patches (class tables)
// ---------------------------------------------------------------------------

/// A patch table: out[dst[i] .. +8] = src[8 * index[i] .. +8].
pub const Patch = struct {
    dst: []u32 = &.{},
    index: []u32 = &.{},
    pub fn deinit(self: *Patch, a: std.mem.Allocator) void {
        a.free(self.dst);
        a.free(self.index);
    }
    pub fn len(self: Patch) usize {
        return self.dst.len;
    }
    /// Fail closed at warm on a table the patch kernel would skip or that
    /// writes outside its target (the kernel's bounds guard only keeps a bad
    /// table in memory; a skipped entry would leave a warm-time value in a
    /// per-request parameter, i.e. a wrong proof with every check accepting).
    pub fn check(self: Patch, src_felts: usize, target_words: usize) !void {
        if (self.dst.len != self.index.len) return error.NativeStage2PatchTable;
        for (self.dst, self.index) |d, i| if (i >= src_felts or @as(usize, d) + 8 > target_words) return error.NativeStage2PatchTable;
    }
};
/// Device sources of per-request parameter values:
///   shared    drawShared(chi) on device (JP.ram .. JP.claims)
///   semantic  the Stage-1 semantic handoff (JP.local .. JP.eta + 4, then hc rows)
///   public    the segment's public namespace (JP slots < JP.local: cpu_steps,
///             pcs, epoch, rows, calls, first ids, source public such as the
///             sponge first id), request statement data uploaded with the job
pub const Source = enum { shared, semantic, public };
pub const sources = [_]Source{ .shared, .semantic, .public };
/// Felts of the public request input (JP slots [0, JP.local)).
pub const public_felts: u32 = JP.local;
const m31_modulus: u32 = 0x7fff_ffff;
/// Which parameter slots come from which device source. Every slot of a
/// per-request namespace maps to a source; only the claims namespace (mixed,
/// never a parameter value here) returns null.
pub fn sourceOf(slot: u32) ?struct { source: Source, index: u32 } {
    if (slot < JP.local) return .{ .source = .public, .index = slot };
    if (slot >= JP.ram and slot < JP.claims) return .{ .source = .shared, .index = slot - JP.ram };
    if (slot >= JP.local and slot < JP.eta + 4) return .{ .source = .semantic, .index = slot - JP.local };
    return null;
}
/// The patch tables of one parameter vector, one per source.
pub const PatchSet = struct {
    shared: Patch = .{},
    semantic: Patch = .{},
    public: Patch = .{},
    pub fn get(self: PatchSet, source: Source) Patch {
        return switch (source) {
            .shared => self.shared,
            .semantic => self.semantic,
            .public => self.public,
        };
    }
    pub fn words(self: PatchSet) usize {
        return 2 * (self.shared.len() + self.semantic.len() + self.public.len());
    }
    pub fn deinit(self: *PatchSet, a: std.mem.Allocator) void {
        self.shared.deinit(a);
        self.semantic.deinit(a);
        self.public.deinit(a);
    }
    pub fn check(self: PatchSet, semantic_words: usize, target_words: usize) !void {
        try self.shared.check(shared_felts, target_words);
        try self.semantic.check(semantic_words / 8, target_words);
        try self.public.check(public_felts, target_words);
    }
};
/// Patches of one packed parameter vector (`slots` = artifact parameter
/// slots, 8 words per slot starting at `base`), for one source.
pub fn appendSlots(a: std.mem.Allocator, dst: *std.ArrayListUnmanaged(u32), index: *std.ArrayListUnmanaged(u32), slots: []const u32, base: u32, source: Source) !void {
    for (slots, 0..) |slot, i| if (sourceOf(slot)) |s| if (s.source == source) {
        try dst.append(a, base + 8 * @as(u32, @intCast(i)));
        try index.append(a, s.index);
    };
}
pub fn patchOf(a: std.mem.Allocator, dst: *std.ArrayListUnmanaged(u32), index: *std.ArrayListUnmanaged(u32)) !Patch {
    return .{ .dst = try dst.toOwnedSlice(a), .index = try index.toOwnedSlice(a) };
}

// ---------------------------------------------------------------------------
// Class framing (built once per class at warm; never per request)
// ---------------------------------------------------------------------------

/// Everything Stage 2 of one segment class needs, owned by the class cache
/// entry (ClassEntry.plan). Built at warm by the native factory from the
/// class geometry (the framing cache's builders: native_framing_cache.zig);
/// the per-request values it held on the hybrid path are device patches here.
pub const ClassFraming = struct {
    a: std.mem.Allocator,
    key: G.ClassKey,
    claim_count: u32,
    slots: []const HJ.Slot,
    inter: *C.CommitPlan,
    composition: *NComp.Plan,
    pcs: *N.PcsJob,
    program: NE.Program,
    fixed_root: [32]u8,
    fixed_key: [32]u8,
    fixed_host: []const []const u32,
    fixed_offsets: []const usize,
    fixed_words: usize,
    main_offsets: []const usize,
    main_words: usize,
    bind_plan: *const B.Plan,
    /// Per global plan (slot order of `slots` with a global), the patches of
    /// its parameter vector (shared draws, public request values).
    global_patches: []PatchSet,
    /// Composition table patches (shared draws, Stage-1 semantic incl. hc
    /// rows, public request values).
    comp_patches: PatchSet,
    /// Words of the Stage-1 semantic handoff region of this class: the
    /// `semantic_felts` namespace felts, then every hc role's rows.
    semantic_words: usize = 8 * @as(usize, semantic_felts),
    /// RAM boundary claim slots (core initial / terminal), or null.
    initial_claim: ?u32 = null,
    terminal_claim: ?u32 = null,
    /// Class-cache device tables (per GPU) holding program + patch tables;
    /// see `deviceWords` / `writeDevice`.
    destroy_fn: ?*const fn (*ClassFraming) void = null,

    /// Every patch table in bounds of its source and target (warm, once).
    pub fn validate(self: *const ClassFraming) !void {
        if (self.semantic_words < 8 * @as(usize, semantic_felts) or self.semantic_words % 8 != 0) return error.NativeStage2PatchTable;
        var k: usize = 0;
        for (self.slots) |s| if (s.global) |g| {
            if (k >= self.global_patches.len) return error.NativeStage2PatchTable;
            try self.global_patches[k].check(self.semantic_words, g.plan.parameters.len);
            k += 1;
        };
        if (k != self.global_patches.len) return error.NativeStage2PatchTable;
        try self.comp_patches.check(self.semantic_words, self.composition.table.len);
    }
    pub fn uses(self: *const ClassFraming, source: Source) bool {
        if (self.comp_patches.get(source).len() != 0) return true;
        for (self.global_patches) |p| if (p.get(source).len() != 0) return true;
        return false;
    }
    pub fn deviceWords(self: *const ClassFraming) usize {
        var n = self.program.words.len;
        for (self.global_patches) |p| n += p.words();
        return n + self.comp_patches.words();
    }
    /// The class-cache image: program, then per patch set (globals in order,
    /// then the composition) per source (`sources` order) the dst and index
    /// tables.
    pub fn image(self: *const ClassFraming, a: std.mem.Allocator) ![]u32 {
        const out = try a.alloc(u32, self.deviceWords());
        var at: usize = 0;
        @memcpy(out[0..self.program.words.len], self.program.words);
        at += self.program.words.len;
        const all = [_][]const PatchSet{ self.global_patches, &.{self.comp_patches} };
        for (all) |group| for (group) |set| for (sources) |source| {
            const p = set.get(source);
            @memcpy(out[at..][0..p.len()], p.dst);
            at += p.len();
            @memcpy(out[at..][0..p.len()], p.index);
            at += p.len();
        };
        std.debug.assert(at == out.len);
        return out;
    }
    pub const PatchView = struct { dst: api.DeviceBuffer, index: api.DeviceBuffer };
    pub const SetView = [sources.len]PatchView;
    pub const Views = struct {
        program: api.DeviceBuffer,
        globals: []SetView,
        composition: SetView,
    };
    pub fn views(self: *const ClassFraming, a: std.mem.Allocator, device: api.DeviceBuffer) !Views {
        if (device.words < self.deviceWords()) return error.NativeStage2ClassImage;
        var at: usize = self.program.words.len;
        const g = try a.alloc(SetView, self.global_patches.len);
        errdefer a.free(g);
        const take = struct {
            fn f(d: api.DeviceBuffer, cursor: *usize, set: PatchSet) !SetView {
                var v: SetView = undefined;
                for (sources, &v) |source, *pv| {
                    const n = set.get(source).len();
                    pv.* = .{ .dst = try d.slice(cursor.*, n), .index = try d.slice(cursor.* + n, n) };
                    cursor.* += 2 * n;
                }
                return v;
            }
        }.f;
        for (self.global_patches, g) |p, *v| v.* = try take(device, &at, p);
        const comp = try take(device, &at, self.comp_patches);
        return .{ .program = try device.slice(0, self.program.words.len), .globals = g, .composition = comp };
    }
};

/// Per-request inputs Stage 2 reads that are request public data (known on
/// the host before proving, uploaded with the job): the RAM boundary tuples
/// (capture output: 14 canonical words per cell).
pub const RequestInputs = struct {
    initial_tuples: []const u32 = &.{},
    terminal_tuples: []const u32 = &.{},
    /// The segment's public parameter namespace (`public_felts` x 8 canonical
    /// words, JP slot order): its statement values from capture. Required
    /// when the class patches any public slot (ClassFraming.uses(.public)).
    public: []const u32 = &.{},
};

pub const Symbols = struct {
    encode: NE.Symbols,
    seal: SealSymbols,
    commit: C.Symbols,
    pcs: N.Symbols,
    composition: NComp.Symbols,
    global: Gl.Symbols,
};

/// Stage 2 of one segment (NativeFactory.stage2), fully enqueued: no host
/// wait, no readback, writes only device memory and the request slab.
pub const Stage2Job = struct {
    a: std.mem.Allocator,
    sym: *const Symbols,
    ctx: *const G.RequestContext,
    /// The class prototype: read-only class constants (footprint, key).
    class: *ClassFraming,
    /// The instance this job stages and enqueues with, held EXCLUSIVELY from
    /// `stage` to the end of `enqueue` (CommitPlan.stage, Plan.stage and
    /// PcsJob.bindColumn write per-job state into it; the worker stages job
    /// N+1 before it enqueues job N, and both GPUs run the same classes).
    /// From the owner's pool; `class` itself when there is no owner.
    lease: ?*ClassFraming = null,
    /// The class image on this GPU (worker-persistent, keyed by class: filled
    /// by the first job of the class on the GPU, never per request).
    class_device: api.DeviceBuffer = undefined,
    /// Owner to release this job to after finish/abort (null: caller owns).
    owner: ?*Factory = null,
    segment: u32,
    device: u32,
    /// GPU that ran the seal job (publishes the seal slot).
    seal_device: u32 = 0,
    constants: SealConstants,
    inputs: RequestInputs = .{},
    // staged
    staged_header: ?api.DeviceBuffer = null,
    checkpoint: ?api.DeviceBuffer = null,
    bind: ?api.DeviceBuffer = null,
    semantic: ?api.DeviceBuffer = null,
    fixed: ?api.DeviceBuffer = null,
    tuples: [2]?api.DeviceBuffer = .{ null, null },
    public: ?api.DeviceBuffer = null,
    globals: []Gl.Global = &.{},
    inter_inputs: []C.Input = &.{},
    pinned: []u32 = &.{},

    pub fn id(self: *const Stage2Job) G.ProofId {
        return .{ .kind = .native_segment, .ordinal = self.segment };
    }
    pub fn classKey(self: *Stage2Job) [32]u8 {
        return self.class.key;
    }
    fn globalCount(self: *const Stage2Job) usize {
        var n: usize = 0;
        for (self.class.slots) |s| n += @intFromBool(s.global != null);
        return n;
    }
    pub fn footprint(self: *Stage2Job) api.Footprint {
        const g = 64;
        const c = self.class;
        var staged: usize = 4 * g + c.inter.stagedWords(0) + c.composition.stagedWords() + std.mem.alignForward(usize, self.inputs.initial_tuples.len, g) + std.mem.alignForward(usize, self.inputs.terminal_tuples.len, g) + std.mem.alignForward(usize, self.inputs.public.len, g);
        var globals: usize = 0;
        for (c.slots) |s| if (s.global) |gs| {
            staged += gs.plan.stagedWords(false) + g;
            globals += std.mem.alignForward(usize, gs.plan.outputWords(), g) + gs.plan.enqueueWords();
        };
        // PCS peak: measured segment-scale class 2.14e9 words [M]
        // (memory-plan-p2) + 7%, as native_hybrid_jobs.Stage2Job.
        const pcs: usize = 2_300_000_000;
        // public_claims scratch grows with the boundary cells (8 + 8 per
        // 256-cell block, up to 4104 words): sized here, not in the slack.
        const pscratch = std.mem.alignForward(usize, @intCast(self.sym.encode.public_scratch(@intCast(self.inputs.initial_tuples.len / 14), @intCast(self.inputs.terminal_tuples.len / 14))), g);
        const fields = 8 * g + @as(usize, c.claim_count) * 8 + @as(usize, @intCast(c.pcs.outputWords())) + NE.scratch_words + 8 * shared_felts + 8 * (1 + self.globalCount()) + pscratch + 4096;
        const work = globals + c.inter.deviceWords() + c.composition.coefficientWords() + c.composition.enqueueWords() + pcs + fields;
        const fresh = c.fixed_words + c.composition.persistentWords();
        return .{ .device_words = staged + work + 16 * g, .staged_words = staged, .slab_words = 0, .pinned_words = @as(usize, @intCast(c.pcs.ingressWords())) + c.composition.pinnedWords() + fresh + 64 * g + self.inputs.initial_tuples.len + self.inputs.terminal_tuples.len + self.inputs.public.len };
    }

    fn acquire(self: *Stage2Job) !*ClassFraming {
        if (self.lease) |l| return l;
        const l = if (self.owner) |f| try f.acquire(self.class) else self.class;
        self.lease = l;
        return l;
    }
    fn releaseLease(self: *Stage2Job) void {
        const l = self.lease orelse return;
        self.lease = null;
        if (self.owner) |f| f.releaseFraming(l);
    }

    pub fn stage(self: *Stage2Job, s: *api.Stager) !void {
        const c = try self.acquire();
        const ctx = self.ctx;
        const req = ctx.request;
        self.checkpoint = try s.retained(req, handoffName(.checkpoint, self.segment), checkpoint_words);
        self.bind = try s.retained(req, handoffName(.binding, self.segment), c.bind_plan.output_words);
        if (c.uses(.semantic)) self.semantic = try s.retained(req, handoffName(.semantic, self.segment), c.semantic_words);
        if (c.uses(.public)) {
            if (self.inputs.public.len != 8 * @as(usize, public_felts)) return error.NativeStage2NoPublic;
            for (self.inputs.public) |w| if (w >= m31_modulus) return error.NativeStage2NoncanonicalPublic;
            const b = try s.alloc(self.inputs.public.len);
            try s.upload(b, self.inputs.public);
            self.public = b;
        }
        const image = try s.persistent(imageKey(c.key), c.deviceWords());
        if (image.fresh) {
            const words = try c.image(self.a);
            defer self.a.free(words);
            try s.upload(image.buffer, words);
        }
        self.class_device = image.buffer;
        const fixed = try s.persistent(c.fixed_key, c.fixed_words);
        if (fixed.fresh) for (c.fixed_host, c.fixed_offsets) |h, off| try s.upload(try fixed.buffer.slice(off, h.len), h);
        self.fixed = fixed.buffer;
        // [0,3) mixManifestAndClaims header (the digest comes from the seal
        // slot), [3,11) the class FIXED root (root_match), [11] a zero word.
        const hdr = try s.alloc(12);
        var words: [12]u32 = undefined;
        words[0..3].* = .{ S2.manifest_header[0], S2.manifest_header[1], c.claim_count };
        words[3..11].* = words8(c.fixed_root);
        words[11] = 0;
        try s.upload(hdr, &words);
        self.staged_header = hdr;
        for ([2][]const u32{ self.inputs.initial_tuples, self.inputs.terminal_tuples }, &self.tuples) |t, *out| if (t.len != 0) {
            const b = try s.alloc(t.len);
            try s.upload(b, t);
            out.* = b;
        };
        self.globals = try self.a.alloc(Gl.Global, self.globalCount());
        var k: usize = 0;
        for (c.slots) |slot| if (slot.global) |gs| {
            self.globals[k] = .{ .plan = gs.plan, .sym = &self.sym.global };
            try self.globals[k].stage(self.a, s, &.{});
            k += 1;
        };
        try c.composition.stage(s);
        self.inter_inputs = try self.a.alloc(C.Input, c.inter.shapes.len);
        @memset(self.inter_inputs, .{ .device = @ptrFromInt(@alignOf(u32)) });
        try c.inter.stage(s, self.inter_inputs);
        self.pinned = try s.pinned(@intCast(c.pcs.ingressWords()));
    }

    fn status(self: *const Stage2Job, check: G.Check) !api.DeviceBuffer {
        const ctx = self.ctx;
        return ctx.layout.segments[self.device].statusBuffer(ctx.segments[self.device], self.id(), check);
    }

    /// out <- every source's patch of one parameter vector (stream order).
    fn applyPatches(self: *const Stage2Job, e: *api.Enqueue, set: ClassFraming.SetView, shared: api.DeviceBuffer, out: api.DeviceBuffer) !void {
        for (sources, set) |source, v| {
            if (v.dst.words == 0) continue;
            const src = switch (source) {
                .shared => shared,
                .semantic => self.semantic orelse return error.NativeStage2NoSemantic,
                .public => self.public orelse return error.NativeStage2NoPublic,
            };
            try NE.patchFelts(&self.sym.encode, e.ctx(), src, v.index, v.dst, out);
        }
    }

    pub fn enqueue(self: *Stage2Job, e: *api.Enqueue) !void {
        // The lease ends with the enqueue: everything below reads the
        // instance's host state at call time only (device work captured the
        // pointers it staged), so the next job may restage the instance.
        defer self.releaseLease();
        const c = self.lease orelse return error.NativeStage2NotStaged;
        const ctx = self.ctx;
        const sym = self.sym;
        const fixed = self.fixed orelse return error.NativeStage2NotStaged;
        if (self.segment >= ctx.main_resident.len) return error.NativeStage2NoResidentMain;
        const main = ctx.main_resident[self.segment];
        if (main.words < c.main_words) return error.NativeStage2ResidentMainShape;
        const bind = self.bind.?;
        const views = try c.views(self.a, self.class_device);
        defer self.a.free(views.globals);
        // ---- seal slot (chi) on this GPU, then the shared draws
        const seal = ctx.exchange.seal();
        try ctx.peer.awaitSlot(self.device, self.seal_device, seal);
        const x = try replica(ctx, self.device);
        const chi = try x.slice(seal.offset, 8);
        const shared = try e.alloc(8 * shared_felts);
        try rc(sym.seal.shared(e.ctx(), 0, chi.ptr, &self.constants, shared.ptr, shared.words));
        // ---- device parameters: globals and composition table, from the
        // shared draws, the Stage-1 semantic handoff and the public inputs
        if (views.globals.len != self.globals.len) return error.NativeStage2PatchTable;
        for (self.globals, views.globals) |*gl, set| try self.applyPatches(e, set, shared, gl.staged.?);
        const table = c.composition.table_device orelse return error.NativeStage2NotStaged;
        try self.applyPatches(e, views.composition, shared, table);
        var k: usize = 0;
        // ---- transcript from the Stage-1 checkpoint
        try e.channel.initFromCheckpoint(self.checkpoint.?);
        const claims = try e.alloc(@max(1, @as(usize, c.claim_count) * 8));
        const gstatus = try e.alloc(@max(1, self.globals.len));
        const roots = try e.alloc(32);
        const alpha = try e.alloc(8);
        const comp_status = try e.alloc(1);
        const oods = try e.alloc(N.oods_field_words);
        const pcs_out = try e.alloc(@intCast(c.pcs.outputWords()));
        // ---- global interaction of every slot
        const outputs = try self.a.alloc(?api.DeviceBuffer, c.slots.len);
        defer self.a.free(outputs);
        @memset(outputs, null);
        var pointers: std.ArrayListUnmanaged([*]const u32) = .empty;
        defer pointers.deinit(self.a);
        k = 0;
        for (c.slots, outputs) |slot, *out| if (slot.global) |g| {
            const p = g.plan;
            pointers.clearRetainingCapacity();
            for (0..p.fixed_count) |i| try pointers.append(self.a, fixed.ptr + c.fixed_offsets[g.fixed_first + i]);
            for (0..p.main_count) |i| try pointers.append(self.a, main.ptr + c.main_offsets[g.main_first + i]);
            const output = try e.alloc(p.outputWords());
            out.* = output;
            try self.globals[k].enqueue(e, pointers.items[0..p.fixed_count], pointers.items[p.fixed_count..], .{ .output = output, .claims = try p.claimsIn(claims, g.claim_offset), .status = try gstatus.slice(k, 1) });
            k += 1;
        };
        for (c.slots, outputs) |slot, out| {
            var at = slot.inter_offset;
            const rows = @as(usize, 1) << @intCast(slot.log);
            if (slot.binding_index) |bi| {
                const cols = try c.bind_plan.columns(bind, bi);
                if (cols.words != 16 * rows) return error.NativeStage2BindingShape;
                for (0..16) |col| self.inter_inputs[at + col] = .{ .device = cols.ptr + col * rows };
                at += 16;
            }
            if (slot.global) |g| for (0..g.plan.width) |col| {
                self.inter_inputs[at + col] = .{ .device = try g.plan.columnPointer(out.?, col) };
            };
        }
        // ---- mixManifestAndClaims (chi from the seal slot), INTER, alpha
        const mixed = try claims.slice(0, @as(usize, c.claim_count) * 8);
        const hdr = self.staged_header orelse return error.NativeStage2NotStaged;
        try e.channel.mixWords(try hdr.slice(0, 3));
        try e.channel.mixWords(chi);
        try e.channel.mixFelts(mixed);
        const inter = try c.inter.enqueue(sym.commit, e, self.inter_inputs, try roots.slice(16, 8), true);
        var i = outputs.len;
        while (i > 0) {
            i -= 1;
            if (outputs[i]) |o| e.free(o);
        }
        try e.channel.drawSecureFelts(1, alpha);
        // ---- composition, OODS, PCS
        const inter_views = S2.Composition.Committed.of(c.inter, inter);
        const fixed_view = S2.Composition.Committed{ .offsets = c.fixed_offsets, .tree = .{ .coefficients = fixed, .root = fixed.ptr } };
        const main_view = S2.Composition.Committed{ .offsets = c.main_offsets, .tree = .{ .coefficients = main, .root = main.ptr } };
        var producer = S2.NativeComposition{ .plan = c.composition, .sym = sym.composition };
        const seam = producer.producer();
        const comp = try seam.enqueue(seam.ctx, e, .{ .alpha = alpha, .claims = mixed, .status = comp_status, .root_out = try roots.slice(24, 8), .trees = .{ fixed_view, main_view, inter_views } });
        try e.channel.mixRootFromTree(try roots.slice(24, 8));
        const trees = [4]S2.Composition.Committed{ fixed_view, main_view, inter_views, comp };
        for (trees, 0..) |t, index| for (t.offsets, 0..) |offset, original| try c.pcs.bindColumn(index, original, t.tree.coefficients.ptr + offset);
        try c.pcs.enqueueOpening(sym.pcs, e, self.pinned, oods, pcs_out);
        e.free(comp.tree.coefficients);
        e.free(inter.coefficients);
        // ---- device acceptance checks -> request slab status words
        // No global slot: nothing can reject; the check reads the staged zero word.
        try NE.wordsZero(&sym.encode, e.ctx(), if (self.globals.len != 0) gstatus else try hdr.slice(11, 1), .global_status, try self.status(.global_status));
        try NE.wordsZero(&sym.encode, e.ctx(), comp_status, .composition_accept, try self.status(.composition_accept));
        try NE.wordsZero(&sym.encode, e.ctx(), try e.channel.stateBuffer().slice(10, 1), .channel_order, try self.status(.channel_order));
        // root_match: FIXED vs the class authority; MAIN vs this segment's exchange root slot.
        const main_root = try x.slice((try ctx.exchange.root(self.segment)).offset, 8);
        // The committed FIXED tree is the class tree (persistent), so its
        // committed root is the class root staged above; MAIN is the root
        // Stage 1 published; INTER / composition are this job's commits.
        try NE.rootMatch(&sym.encode, e.ctx(), pcs_out, &.{ try hdr.slice(3, 8), main_root, try roots.slice(16, 8), try roots.slice(24, 8) }, c.fixed_root, try self.status(.root_match));
        // public_claims (device RAM boundary reduction)
        const bi: ?NE.BoundaryInput = if (c.initial_claim) |cl| .{ .claim = cl, .tuples = self.tuples[0] orelse return error.NativeStage2NoBoundary, .cells = @intCast(self.inputs.initial_tuples.len / 14) } else null;
        const bt: ?NE.BoundaryInput = if (c.terminal_claim) |cl| .{ .claim = cl, .tuples = self.tuples[1] orelse return error.NativeStage2NoBoundary, .cells = @intCast(self.inputs.terminal_tuples.len / 14) } else null;
        const pscratch = try e.alloc(NE.publicClaimsScratch(&sym.encode, bi, bt));
        try NE.publicClaims(&sym.encode, e.ctx(), mixed, c.claim_count, try shared.slice(0, 15 * 8), bi, bt, pscratch, try self.status(.public_claims));
        // ---- device encoding into the slab region (+ pcs_status, encode_bounds)
        const scratch = try e.alloc(NE.scratch_words);
        var enc = NE.Encoder{ .sym = &sym.encode, .program = views.program, .host = &c.program, .pcs = pcs_out, .scratch = scratch, .pcs_status = try self.status(.pcs_status) };
        try enc.encoder().run(e, &ctx.layout.segments[self.device], ctx.segments[self.device], self.id());
        // Stream-ordered frees after the last readers.
        for ([_]api.DeviceBuffer{ scratch, pscratch, pcs_out, oods, comp_status, alpha, roots, gstatus, claims, shared }) |b| e.free(b);
    }

    pub fn finish(self: *Stage2Job, _: api.SlabView) !void {
        self.release();
    }
    pub fn abort(self: *Stage2Job) void {
        self.release();
    }
    fn release(self: *Stage2Job) void {
        const owner = self.owner;
        self.releaseLease(); // abort between stage and enqueue
        self.deinit();
        if (owner) |f| f.releaseStage2(self);
    }
    pub fn deinit(self: *Stage2Job) void {
        self.a.free(self.globals);
        self.a.free(self.inter_inputs);
        self.globals = &.{};
        self.inter_inputs = &.{};
    }
};

pub const Hooks = @import("native_device.zig").Stage2Hooks;

pub fn imageKey(class: G.ClassKey) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-m8-gn-stage2-image/v1");
    h.update(&class);
    return h.finalResult();
}

// ---------------------------------------------------------------------------
// Factory: class registry (warm) + per-request inputs -> jobs
// ---------------------------------------------------------------------------

/// What native_device.zig delegates `warm` (Stage-2 classes), `seal` and
/// `stage2` to. Classes are registered by the warm path (one ClassFraming per
/// segment class, built from the class geometry) and inserted into the
/// ClassCache; after `ClassCache.seal` an unknown class fails closed
/// (GpuNativeClassNotWarmed). Per request, the driver hands the roster and
/// the request public inputs (`beginRequest`) before submitting jobs.
pub const Factory = struct {
    a: std.mem.Allocator,
    sym: *const Symbols,
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
        instances: std.ArrayListUnmanaged(*ClassFraming) = .empty,
        busy: std.ArrayListUnmanaged(bool) = .empty,
        fn deinit(self: *Pool, a: std.mem.Allocator) void {
            self.instances.deinit(a);
            self.busy.deinit(a);
        }
    };
    pub const instances_per_device: usize = 2;

    pub const Request = struct {
        roster: []const RosterEntry,
        execution: [32]u8,
        inputs: []const RequestInputs, // per segment
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
    pub fn register(self: *Factory, framing: *ClassFraming) !void {
        try framing.validate();
        try self.registerUnchecked(framing);
    }
    fn registerUnchecked(self: *Factory, framing: *ClassFraming) !void {
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
    pub fn acquire(self: *Factory, class: *const ClassFraming) !*ClassFraming {
        self.mutex.lock();
        defer self.mutex.unlock();
        const pool = self.classes.get(class.key) orelse return error.GpuNativeClassNotWarmed;
        for (pool.instances.items, pool.busy.items) |f, *b| if (!b.*) {
            b.* = true;
            return f;
        };
        return error.NativeStage2FramingBusy;
    }
    pub fn releaseFraming(self: *Factory, framing: *ClassFraming) void {
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
                    const fr: *ClassFraming = @ptrCast(@alignCast(raw));
                    return .{ .key = key, .plan = fr, .destroy = noop, .max_encoded_bytes = fr.program.max_encoded_bytes, .main_resident_words = fr.main_words, .claims_per_segment = fr.claim_count };
                }
                fn noop(_: *anyopaque) void {}
            };
            _ = try cache.warm(f.key, .{ .ctx = f, .build = Builder.build });
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
    fn classFor(self: *Factory, ctx: *const G.RequestContext, segment: u32) !*ClassFraming {
        self.mutex.lock();
        const key = self.segment_class.get(segment);
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
        const entries = try sealEntries(self.a, r.roster, ctx.exchange);
        job.* = .{ .factory = self, .job = .{ .a = self.a, .sym = &self.sym.seal, .ctx = ctx, .device = device, .entries = entries, .constants = sealConstants(self.identity, r.execution, @intCast(entries.len), G.Exchange.flagTag(ctx.generation)) } };
        return api.Job.from(SealOwned, job);
    }
    pub fn stage2(self: *Factory, ctx: *const G.RequestContext, segment: u32, device: u32) !api.Job {
        const r = try self.requestOf(ctx.request);
        const class = try self.classFor(ctx, segment);
        if (segment >= r.inputs.len) return error.NativeStage2NoRequestInputs;
        if (self.seal_device >= ctx.segments.len or device >= ctx.segments.len) return error.GpuNativeSealDeviceOutOfRange;
        const job = try self.a.create(Stage2Job);
        job.* = .{ .a = self.a, .sym = self.sym, .ctx = ctx, .class = class, .segment = segment, .device = device, .seal_device = self.seal_device, .constants = sealConstants(self.identity, r.execution, @intCast(r.roster.len), G.Exchange.flagTag(ctx.generation)), .inputs = r.inputs[segment], .owner = self };
        return api.Job.from(Stage2Job, job);
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
    fn releaseStage2(self: *Factory, job: *Stage2Job) void {
        self.a.destroy(job);
    }
};

/// A factory-owned seal job (freed after finish/abort).
const SealOwned = struct {
    factory: *Factory,
    job: SealJob,
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
        a.destroy(self);
    }
};

// ---------------------------------------------------------------------------
// Host tests (no GPU)
// ---------------------------------------------------------------------------

const CPU = @import("stwo_riscv_cpu_integration");
const Manifest = CPU.rv64_gkr_manifest;

/// Host mirror of the device seal (exactly the kernel's word streams), used to
/// pin the constants against the manifest authority without a GPU.
pub fn hostChi(constants: SealConstants, entries: []const SealEntry, roots: []const [8]u32) [8]u32 {
    const H2 = struct {
        fn h(tag: [8]u32, words: []const u32) [8]u32 {
            var b = Blake.init(.{});
            b.update(std.mem.sliceAsBytes(&tag));
            b.update(std.mem.sliceAsBytes(words));
            var out: [32]u8 = undefined;
            b.final(&out);
            return words8(out);
        }
    };
    var m = constants.m0;
    for (entries, 0..) |e, k| {
        var pre: [18]u32 = @splat(0);
        pre[0..8].* = if (e.root_offset == std.math.maxInt(u32)) e.main_const else roots[k];
        const rho = H2.h(constants.rho_tag, &pre);
        var step: [51]u32 = undefined;
        step[0..8].* = m;
        step[8] = e.k;
        step[9] = e.family;
        step[10] = e.rung;
        step[11..19].* = e.vkhash;
        step[19..27].* = e.stmt;
        step[27..35].* = e.s_in;
        step[35..43].* = e.s_out;
        step[43..51].* = rho;
        m = H2.h(constants.seg_tag, &step);
    }
    var fin: [16]u32 = undefined;
    fin[0..8].* = constants.execution;
    fin[8..16].* = m;
    return H2.h(constants.chi_tag, &fin);
}

pub fn testRoster(seed: u8, n: usize, roster: []RosterEntry, workers: []Manifest.ExpectedWorker, stages: []Manifest.StageOne) void {
    for (0..n) |k| {
        const b: u8 = seed +% @as(u8, @intCast(k)) *% 7;
        roster[k] = .{ .family = @intCast(k % 3), .rung = @intCast(k % 2), .vkhash = @splat(b +% 1), .stmt = @splat(b +% 2), .s_in = @splat(b +% 3), .s_out = @splat(b +% 4), .segment = @intCast(k), .root = @splat(b +% 5) };
        const kind: Manifest.Kind = if (k == 0) .cpu else .cpu;
        workers[k] = .{ .kind = kind, .global_relations = .{ .ram = true, .kio = false, .wire = false }, .mass = .{ .ram = 0, .kio = 0, .wire = 0 }, .ordinal = @intCast(k), .statement = roster[k].stmt, .fixed = @splat(9), .local_instances = null, .chain = .{ .family = roster[k].family, .rung = roster[k].rung, .vkhash = roster[k].vkhash, .stmt = roster[k].stmt, .s_in = roster[k].s_in, .s_out = roster[k].s_out } };
        stages[k] = .{ .main = roster[k].root, .local = null };
    }
}

test "device seal word streams reproduce the manifest chi chain (m6_v2_gkr) and drawShared inputs" {
    const a = std.testing.allocator;
    const Chain = CPU.rv64_gkr_chain;
    const identity = try Chain.versionIdentity(.m6_v2_gkr);
    const execution: [32]u8 = @splat(0x42);
    var roster: [5]RosterEntry = undefined;
    var workers: [5]Manifest.ExpectedWorker = undefined;
    var stages: [5]Manifest.StageOne = undefined;
    testRoster(3, 5, &roster, &workers, &stages);
    var pending = try Manifest.verifyAndSealFor(.m6_v2_gkr, a, execution, &workers, &stages);
    defer pending.deinit(a);
    const ex = G.Exchange{ .segments = 5, .claims_per_segment = 2, .devices = 2 };
    const entries = try sealEntries(a, &roster, ex);
    defer a.free(entries);
    var roots: [5][8]u32 = undefined;
    for (&roots, roster) |*r, e| r.* = words8(e.root);
    const k = sealConstants(identity, execution, 5, 1);
    try std.testing.expectEqualSlices(u32, &words8(pending.digest), &hostChi(k, entries, &roots));
    // drawShared layout: the shared namespace order of the joined parameters.
    try std.testing.expectEqual(@as(u32, 15), k.ram_draws);
    try std.testing.expectEqual(JP.kio - JP.ram, k.ram_draws);
    try std.testing.expectEqual(JP.wire - JP.kio, k.kio_draws);
    try std.testing.expectEqual(JP.claims - JP.wire, k.wire_draws);
    const shared = Manifest.drawShared(pending.digest);
    try std.testing.expectEqual(@as(usize, k.kio_draws - 1), shared.kio.coefficients.len);
    try std.testing.expectEqual(@as(usize, k.wire_draws - 1), shared.wire.coefficients.len);
    // Root slots point into the exchange data, flags at the slot's flag word.
    for (entries, 0..) |e, s| {
        const slot = try ex.root(@intCast(s));
        try std.testing.expectEqual(@as(u32, @intCast(slot.offset)), e.root_offset);
        try std.testing.expectEqual(@as(u32, @intCast(slot.flag)), e.flag_offset);
    }
}

test "handoff names are distinct per kind and segment; patch sources partition the namespaces" {
    try std.testing.expect(!std.mem.eql(u8, &handoffName(.checkpoint, 1), &handoffName(.binding, 1)));
    try std.testing.expect(!std.mem.eql(u8, &handoffName(.checkpoint, 1), &handoffName(.checkpoint, 2)));
    try std.testing.expectEqual(Source.shared, sourceOf(JP.ram).?.source);
    try std.testing.expectEqual(@as(u32, shared_felts - 1), sourceOf(JP.claims - 1).?.index);
    try std.testing.expect(sourceOf(JP.claims) == null);
    // Per-segment statement values are patched from the public input.
    try std.testing.expectEqual(Source.public, sourceOf(JP.cpu_steps).?.source);
    try std.testing.expectEqual(@as(u32, JP.local - 1), sourceOf(JP.local - 1).?.index);
    for (0..JP.claims) |slot| try std.testing.expect(sourceOf(@intCast(slot)) != null);
    try std.testing.expectEqual(Source.semantic, sourceOf(JP.local).?.source);
    try std.testing.expectEqual(semantic_felts - 1, sourceOf(JP.eta + 3).?.index);
    const a = std.testing.allocator;
    var dst: std.ArrayListUnmanaged(u32) = .empty;
    var idx: std.ArrayListUnmanaged(u32) = .empty;
    try appendSlots(a, &dst, &idx, &.{ JP.cpu_steps, JP.ram + 2, JP.local + 1, JP.wire }, 40, .shared);
    var p = try patchOf(a, &dst, &idx);
    defer p.deinit(a);
    try std.testing.expectEqualSlices(u32, &.{ 40 + 8, 40 + 24 }, p.dst);
    try std.testing.expectEqualSlices(u32, &.{ 2, JP.wire - JP.ram }, p.index);
    try appendSlots(a, &dst, &idx, &.{ JP.cpu_steps, JP.ram + 2, JP.first_id }, 0, .public);
    var q = try patchOf(a, &dst, &idx);
    defer q.deinit(a);
    try std.testing.expectEqualSlices(u32, &.{ 0, 16 }, q.dst);
    try std.testing.expectEqualSlices(u32, &.{ JP.cpu_steps, JP.first_id }, q.index);
}

test "patch tables fail closed on an out-of-range source felt or target word" {
    var dst = [_]u32{ 0, 16 };
    var idx = [_]u32{ 1, shared_felts - 1 };
    const p = Patch{ .dst = &dst, .index = &idx };
    try p.check(shared_felts, 24);
    try std.testing.expectError(error.NativeStage2PatchTable, p.check(shared_felts, 23));
    try std.testing.expectError(error.NativeStage2PatchTable, p.check(shared_felts - 1, 24));
    // hc rows beyond the namespace felts are in range only when the class
    // declares them in semantic_words.
    var hdst = [_]u32{0};
    var hidx = [_]u32{semantic_felts + 3};
    const set = PatchSet{ .semantic = .{ .dst = &hdst, .index = &hidx } };
    try std.testing.expectError(error.NativeStage2PatchTable, set.check(8 * @as(usize, semantic_felts), 8));
    try set.check(8 * (@as(usize, semantic_felts) + 4), 8);
}

test "factory framing pool: exclusive leases per instance, exhaustion fails closed" {
    const a = std.testing.allocator;
    var f = Factory{ .a = a, .sym = undefined, .identity = @splat(0) };
    defer f.deinit();
    var inst: [2]ClassFraming = undefined;
    for (&inst) |*x| {
        x.key = @splat(7);
        x.program = .{ .a = a, .words = &.{}, .max_encoded_bytes = 0, .pcs_words = 0 };
        x.global_patches = &.{};
        x.comp_patches = .{};
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

test "class image and views agree on the per-set, per-source table layout" {
    const a = std.testing.allocator;
    var prog = [_]u32{ 1, 2, 3 };
    var d0 = [_]u32{ 8, 16 };
    var x0 = [_]u32{ 4, 5 };
    var d1 = [_]u32{24};
    var x1 = [_]u32{6};
    var d2 = [_]u32{ 32, 40, 48 };
    var x2 = [_]u32{ 7, 8, 9 };
    var globals = [_]PatchSet{.{ .shared = .{ .dst = &d0, .index = &x0 }, .public = .{ .dst = &d1, .index = &x1 } }};
    var fr: ClassFraming = undefined;
    fr.program = .{ .a = a, .words = &prog, .max_encoded_bytes = 0, .pcs_words = 0 };
    fr.global_patches = &globals;
    fr.comp_patches = .{ .semantic = .{ .dst = &d2, .index = &x2 } };
    const img = try fr.image(a);
    defer a.free(img);
    try std.testing.expectEqual(fr.deviceWords(), img.len);
    const v = try fr.views(a, .{ .ptr = img.ptr, .words = img.len });
    defer a.free(v.globals);
    const at = struct {
        fn f(b: api.DeviceBuffer) []const u32 {
            return b.ptr[0..b.words];
        }
    }.f;
    try std.testing.expectEqualSlices(u32, &prog, at(v.program));
    try std.testing.expectEqualSlices(u32, &d0, at(v.globals[0][0].dst));
    try std.testing.expectEqualSlices(u32, &x0, at(v.globals[0][0].index));
    try std.testing.expectEqual(@as(usize, 0), v.globals[0][1].dst.words);
    try std.testing.expectEqualSlices(u32, &d1, at(v.globals[0][2].dst));
    try std.testing.expectEqualSlices(u32, &x1, at(v.globals[0][2].index));
    try std.testing.expectEqualSlices(u32, &d2, at(v.composition[1].dst));
    try std.testing.expectEqualSlices(u32, &x2, at(v.composition[1].index));
    try std.testing.expectEqual(@as(usize, 0), v.composition[0].dst.words);
}

test "stage2 / seal jobs and the factory seam type-check against the api" {
    _ = api.Job.from(Stage2Job, undefined);
    _ = api.Job.from(SealJob, undefined);
    _ = api.Job.from(SealOwned, undefined);
    _ = &Factory.stage2;
    _ = &Factory.seal;
    _ = &Factory.hooks;
    _ = &Factory.warm;
    _ = &Factory.register;
    _ = &ClassFraming.views;
    _ = &ClassFraming.image;
}

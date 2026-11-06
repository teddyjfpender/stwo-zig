//! M8 native hybrid (STWO_RV64_M8_NATIVE_JOBS=1; unset = today's path,
//! byte for byte). The legacy resident orchestration keeps admission, the
//! cross-segment global-chi barrier, truth proofs, recursion and publication.
//! Each CPU segment's proving moves onto the persistent per-GPU job workers:
//!
//!   stage one  the legacy local-GKR NumericalStage is this file's: one
//!              Stage1Job (jobs/native_hybrid_jobs.zig) runs the local GKR +
//!              Eq/prefix binding on the segment's GPU, after copying the
//!              committed MAIN coefficients into a REQUEST-RETAINED device
//!              region (jobs/retained.zig). The binding output is retained too.
//!   stage two  coordinator.NativeStageTwo (the one legacy hook): one Stage2Job
//!              runs the global interaction of every slot, INTER commit,
//!              composition (device coefficient + device claim slots), OODS
//!              and the enqueue-only PCS on one device transcript, reading the
//!              retained regions. The host here builds the class framing,
//!              decodes the PCS words and assembles exactly the bytes and
//!              claims CpuWorker.complete returns (publicClaims and the OODS
//!              constraint check included).
//!
//! The legacy MAIN commit (prepareMain) still runs on the legacy owner: its
//! root is the manifest authority and the replay frees its MAIN right after
//! stage one, which is why the job keeps its own retained copy.
//!
//! Workers: one per STWO_RV64_GPU_DEVICES entry (jobs.WorkerSet), arena
//! window cap STWO_RV64_M8_JOBS_ARENA_BYTES (default 20 GiB), pinned cap
//! STWO_RV64_M8_JOBS_PINNED_BYTES (default 4 GiB cap, lazy). The workers stay
//! PARKED: each job unparks a window sized to its declaration (plus room for
//! its outside allocations), runs, and parks again (runWindowed), so the
//! legacy MAIN commits, truths and recursion share the process arena.
//! Retained regions are released per segment after its stage two and per
//! request at `endRequest` (abort path included).
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_riscv_cpu_integration");
const jobs = @import("jobs/mod.zig");
const api = jobs.api;
const W = jobs.worker;
const HJ = @import("jobs/native_hybrid_jobs.zig");
const NG = @import("jobs/native_gkr.zig");
const NB = @import("jobs/native_binding.zig");
const NC = @import("jobs/native_commit.zig");
const NGl = @import("jobs/native_global.zig");
const NP = @import("jobs/native_pcs.zig");
const NS1 = @import("jobs/native_stage1.zig");
const S2 = @import("jobs/native_stage2.zig");
const NComp = @import("jobs/native_composition.zig");
const Sources = @import("gkr_sources.zig");
const RC = @import("resident_composition.zig");
const CompRoles = @import("m8_native_composition_roles.zig");
const Events = @import("cuda_events.zig");
const FC = @import("jobs/native_framing_cache.zig");
const PcsScope = @import("pcs_scope.zig");
const Child = CPU.rv64_gkr_child;
const CW = CPU.rv64_gkr_cpu_worker;
const Manifest = CPU.rv64_gkr_manifest;
const Components = CPU.rv64_gkr_cpu_components;
const WP = CPU.rv64_gkr_worker_protocol;
const DP = CPU.rv64_device_pcs;
const DG = CW.DeviceGlobal;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const CP = engine.air.component_prover.ForField(O);
pub const NativeStageTwo = @FieldType(CPU.rv64_ethereum_gkr_main.ResidentStages, "native_stage_two");

pub fn selected() !bool {
    const v = std.posix.getenv("STWO_RV64_M8_NATIVE_JOBS") orelse return false;
    if (std.mem.eql(u8, v, "1")) return true;
    if (std.mem.eql(u8, v, "0")) return false;
    return error.InvalidM8NativeJobsEnvironment;
}

fn envBytes(name: []const u8, default: usize) !usize {
    const v = std.posix.getenv(name) orelse return default;
    return std.fmt.parseUnsigned(usize, v, 10) catch error.InvalidM8NativeJobsEnvironment;
}

/// Completion latch for one submitted job (Sink callbacks run on the worker thread).
const Done = struct {
    event: std.Thread.ResetEvent = .{},
    result: anyerror!void = {},
    receipt: api.Receipt = .{},
    fn sink(self: *Done) W.Sink {
        return .{ .ctx = self, .done = call };
    }
    fn call(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        self.result = c.result;
        self.receipt = c.receipt;
        self.event.set();
    }
};

/// Per-job arena window: the worker stays parked (no static arena next to
/// the legacy native window, whose MAIN-commit LDE needs ~10 GB of the same
/// process arena [M] h1), and unparks to the job's declared footprint for
/// exactly one job. park/unpark is a VMM arena release/acquire [M]
/// runtime-persist-p3: 0.03-0.08 ms. One window per GPU at a time.
fn runWindowed(self: *Hybrid, index: usize, comptime T: type, value: *T) !api.Receipt {
    const fp = value.footprint();
    const g = W.Arena.granule;
    const want = std.mem.alignForward(usize, fp.device_words + fp.slab_words + 4 * g, g);
    const win_words = @min(want, self.arena_words);
    self.windows[index].lock();
    defer self.windows[index].unlock();
    const w = self.workers[index];
    // The legacy owners share the process arena: when the declared window
    // does not map, shrink it (7/8 per step) down to the job's own
    // declaration of enqueue work; the job then fails closed on a real overrun.
    // Probe with the window PLUS the job's outside allocations (retained /
    // persistent regions, the reused global kernels' scratch), then keep
    // only the window: they must still map after the window is taken
    // (CudaEnqueueFailed in stage when they did not [M] h17/h21).
    const scratch = std.mem.alignForward(usize, try envBytes("STWO_RV64_M8_NATIVE_JOBS_HEADROOM", 1 << 30) / 4, g);
    const extra = std.mem.alignForward(usize, value.outsideWords(), g) + scratch;
    const floor = std.mem.alignForward(usize, @min(fp.device_words, want) / 2, g);
    var probe = win_words + extra;
    var size = win_words;
    while (true) {
        if (w.unpark(probe)) |_| {
            _ = try w.park(.{});
            size = @min(win_words, probe - extra);
            _ = try w.unpark(size);
            break;
        } else |err| {
            if (probe <= floor + extra) return err;
            probe = @max(floor + extra, std.mem.alignBackward(usize, probe / 8 * 7, g));
        }
    }
    // The job declares at most the window it got (allocation beyond it
    // fails closed inside the job, never in the legacy owners).
    value.window_words = size - @min(size, fp.slab_words + 4 * g);
    if (size != win_words) std.debug.print("GPU_M8_NATIVE_HYBRID event=window_shrunk device_index={} declared_words={} window_words={}\n", .{ index, win_words, size });
    const job = api.Job.from(T, value);
    defer _ = w.park(.{}) catch |err| std.log.err("M8 native hybrid park failed: {s}", .{@errorName(err)});
    return run(w, job);
}

fn run(worker: *W.Worker, job: api.Job) !api.Receipt {
    var done = Done{};
    while (true) {
        worker.submit(job, done.sink()) catch |err| switch (err) {
            error.WorkerBusy => {
                std.Thread.sleep(20 * std.time.ns_per_us);
                continue;
            },
            else => return err,
        };
        break;
    }
    done.event.wait();
    done.result catch |err| {
        std.debug.print("GPU_M8_NATIVE_HYBRID event=job_failed device={} error={s} arena_words={} arena_peak_words={} staged_words={} enqueue_ns={}\n", .{ worker.device_ordinal, @errorName(err), worker.config.arena_words, done.receipt.arena_peak_words, done.receipt.staged_words, done.receipt.enqueue_ns });
        return err;
    };
    return done.receipt;
}

fn words(bytes: [32]u8) [8]u32 {
    var out: [8]u32 = undefined;
    for (&out, 0..) |*w, i| w.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return out;
}
fn bytesOf(w: []const u32) [32]u8 {
    var out: [32]u8 = undefined;
    for (w[0..8], 0..) |v, i| std.mem.writeInt(u32, out[4 * i ..][0..4], v, .little);
    return out;
}
fn felt(w: []const u32) !O {
    var limbs: [8]M = undefined;
    for (&limbs, w[0..8]) |*l, v| {
        if (v >= core.fields.m31.Modulus) return error.NoncanonicalWideCpuClaim;
        l.* = M.fromCanonical(v);
    }
    return O.fromM31Array(limbs);
}
fn coefficientWords(values: []const M) []const u32 {
    return @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
}

/// FIXED host coefficients are class-immutable: the worker keeps them in one
/// persistent region (the GKR's host_key layout: original order, contiguous).
fn fixedKey(fixed_root: [32]u8, host_words: usize) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-m8-gkr-host-fixed");
    h.update(&fixed_root);
    h.update(std.mem.asBytes(&host_words));
    return h.finalResult();
}

/// Stage-2 class framing (M8 GPU-native §3.1, inventory H9): everything
/// stageTwoInner built per segment from the class geometry (global plans,
/// INTER shapes/plan, composition plan, mask points -> PcsJob framing). The
/// request words inside it (composition parameters/hc, global challenges,
/// PCS scope identity and expected roots) are rebound on every checkout
/// (`rebindFraming`). Owned by the Hybrid's framing pool or by one segment.
const Framing = struct {
    a: std.mem.Allocator,
    comp_log: u32,
    split: u32,
    total: u32,
    mask_log: u32,
    slots: []HJ.Slot = &.{},
    gplans: std.ArrayListUnmanaged(NGl.Plan) = .empty,
    inter_shapes: []NC.Shape = &.{},
    inter_logs: []u32 = &.{},
    inter_plan: ?NC.CommitPlan = null,
    comp_plan: ?NComp.Plan = null,
    pcs: ?NP.PcsJob = null,
    /// The PCS coefficient table as `prepare` left it (placeholder columns).
    /// Stage2 `bindColumn`s every column to job-arena addresses; a cached
    /// framing restores this copy on every checkout, so a column the next job
    /// fails to bind still fails the PCS custody check instead of reading the
    /// previous job's freed arena.
    pristine_columns: []PcsColumn = &.{},
    pub fn destroy(self: *Framing) void {
        const a = self.a;
        a.free(self.pristine_columns);
        if (self.pcs) |*p| p.deinit(a);
        if (self.comp_plan) |*p| p.deinit();
        if (self.inter_plan) |*p| p.deinit();
        a.free(self.inter_logs);
        a.free(self.inter_shapes);
        for (self.gplans.items) |*p| p.deinit();
        self.gplans.deinit(a);
        a.free(self.slots);
        a.destroy(self);
    }
};

/// What the framing builders read for one segment (request values included:
/// `specs` carry this request's parameters, `pending.shared` its challenges).
const FramingInputs = struct {
    worker: *CW.CpuWorker,
    pending: *const Manifest.PendingManifest,
    seg: *const Segment,
    fixed_logs: []const u32,
    provers: CP.ComponentProvers,
    specs: []const NComp.RoleSpec,
    comp_log: u32,
    split: u32,
    total: u32,
    mask_log: u32,
};

const PcsColumn = @typeInfo(@TypeOf(@as(NP.PcsJob, undefined).prepared.coefficients)).pointer.child;

const FramingLease = struct {
    framing: *Framing,
    pooled: bool,
    /// Row.stage2_framing: 0 built, 1 hit, 2 hit + check build.
    mode: u32,
};

/// The global item of one slot (null: the slot has no global claims).
fn globalItem(a: std.mem.Allocator, worker: *CW.CpuWorker, slot: anytype, fixed_coefficients: anytype, main_logs: []const u32, item_fixed: *std.ArrayListUnmanaged(DP.Column), item_main: *std.ArrayListUnmanaged(DP.Column)) !?DG.Item {
    const n = CPU.rv64_gkr_global_cpu.claimCount(slot.origin);
    if (n == 0) return null;
    const descriptor = CPU.rv64_gkr_source.Descriptor{ .origin = slot.origin };
    const shape = try CPU.rv64_gkr_constraints.shape(descriptor);
    if (slot.fixed_offset + shape.fixed > fixed_coefficients.len or slot.main_offset + shape.main > main_logs.len) return error.InvalidWideGlobalShape;
    item_fixed.clearRetainingCapacity();
    for (fixed_coefficients[slot.fixed_offset..][0..shape.fixed]) |c| try item_fixed.append(a, .{ .log_size = c.logSize(), .coefficients = c.coefficients() });
    item_main.clearRetainingCapacity();
    for (main_logs[slot.main_offset..][0..shape.main]) |l| try item_main.append(a, NP.placeholderColumn(l));
    const sponge_first_id: u32 = if (slot.origin == .sponge) (worker.source.sponge[@intFromEnum(slot.origin.sponge)] orelse return error.MissingLocalGkrBridge).first_id else 0;
    return DG.Item{ .descriptor = descriptor, .log_size = slot.log, .fixed = item_fixed.items, .fixed_offset = slot.fixed_offset, .main = item_main.items, .sponge_first_id = sponge_first_id };
}

/// The PCS framing's request words: section 15 (expected tree roots, as
/// prepareMode packs them) and the worker scope identity (requestScope).
fn pcsRequestWords(pcs: *NP.PcsJob, pristine: []const PcsColumn, scope: anytype, roots: [4][32]u8) !void {
    const p = &pcs.prepared;
    if (pristine.len != p.coefficients.len) return error.HybridFramingPcsShape;
    @memcpy(p.coefficients, pristine);
    if (!p.section_owned[15] or p.section_storage[15].len != roots.len * 8) return error.HybridFramingPcsShape;
    const s15 = @constCast(p.section_storage[15]);
    for (roots, 0..) |r, t| for (0..8) |i| {
        s15[t * 8 + i] = std.mem.readInt(u32, r[4 * i ..][0..4], .little);
    };
    p.scope = if (scope) |sc| PcsScope.identity(sc) else @splat(0);
    pcs.descriptor = p.descriptor();
}

/// Check mode (N1): a rebound cached framing equals a fresh build, word for
/// word (every PCS section incl. 15, scope, composition table, global
/// parameters, INTER shapes, slot wiring). The first difference fails closed.
fn sameFraming(x: *const Framing, y: *const Framing) !void {
    const Diff = struct {
        fn fail(what: []const u8) error{NativeFramingCacheMismatch} {
            std.debug.print("GPU_M8_NATIVE_HYBRID event=framing_cache_mismatch field={s}\n", .{what});
            return error.NativeFramingCacheMismatch;
        }
    };
    if (x.comp_log != y.comp_log or x.split != y.split or x.total != y.total or x.mask_log != y.mask_log) return Diff.fail("geometry");
    if (x.slots.len != y.slots.len) return Diff.fail("slots");
    for (x.slots, y.slots) |p, q| {
        if (p.log != q.log or p.inter_offset != q.inter_offset or !std.meta.eql(p.binding_index, q.binding_index) or (p.global == null) != (q.global == null)) return Diff.fail("slot");
        if (p.global) |g| {
            const h = q.global.?;
            if (g.claim_offset != h.claim_offset or g.fixed_first != h.fixed_first or g.main_first != h.main_first) return Diff.fail("slot.global");
        }
    }
    if (x.gplans.items.len != y.gplans.items.len) return Diff.fail("gplans");
    for (x.gplans.items, y.gplans.items) |p, q| {
        if (p.entry != q.entry or p.log != q.log or p.fixed_count != q.fixed_count or p.main_count != q.main_count or p.width != q.width or !std.mem.eql(u32, &p.groups, &q.groups)) return Diff.fail("gplan.geometry");
        if (!std.mem.eql(u32, p.parameters, q.parameters)) return Diff.fail("gplan.parameters");
    }
    if (x.inter_shapes.len != y.inter_shapes.len) return Diff.fail("inter_shapes");
    for (x.inter_shapes, y.inter_shapes) |p, q| if (!std.meta.eql(p, q)) return Diff.fail("inter_shape");
    if (!std.mem.eql(u32, x.inter_logs, y.inter_logs)) return Diff.fail("inter_logs");
    const cx = &x.comp_plan.?;
    const cy = &y.comp_plan.?;
    if (!std.mem.eql(u8, &cx.key, &cy.key)) return Diff.fail("composition.key");
    if (!std.mem.eql(u32, cx.table, cy.table)) return Diff.fail("composition.table");
    const px = &x.pcs.?;
    const py = &y.pcs.?;
    for (px.prepared.section_storage, py.prepared.section_storage) |p, q| if (!std.mem.eql(u32, p, q)) return Diff.fail("pcs.section");
    if (!std.mem.eql(u8, std.mem.asBytes(&px.plan), std.mem.asBytes(&py.plan))) return Diff.fail("pcs.plan");
    if (!px.base_shift.eql(py.base_shift)) return Diff.fail("pcs.base_shift");
    if (!std.mem.eql(u32, &px.prepared.scope, &py.prepared.scope) or !std.mem.eql(u32, &px.descriptor.scope, &py.descriptor.scope)) return Diff.fail("pcs.scope");
    if (px.prepared.coefficients.len != py.prepared.coefficients.len) return Diff.fail("pcs.coefficients");
    // Whole column records (kind, address, custody token): a rebound framing
    // carries only `prepare`'s placeholders, never a previous job's bindings.
    for (px.prepared.coefficients, py.prepared.coefficients) |p, q| if (!std.mem.eql(u8, std.mem.asBytes(&p), std.mem.asBytes(&q))) return Diff.fail("pcs.column");
    for (px.prepared.metadata.shape.trees, py.prepared.metadata.shape.trees) |p, q| {
        if (!std.mem.eql(u32, p.coefficient_logs, q.coefficient_logs) or !std.mem.eql(u32, p.sorted_to_original, q.sorted_to_original) or !std.mem.eql(u32, p.sample_counts, q.sample_counts)) return Diff.fail("pcs.shape");
    }
}

/// Per-segment state between the two stages (one request).
const Segment = struct {
    a: std.mem.Allocator,
    request: u64,
    ordinal: u32,
    device_index: usize,
    main_root: [32]u8,
    main_logs: []u32,
    main_offsets: []usize,
    main_words: usize,
    bind_plan: NB.Plan,
    bind_region: api.DeviceBuffer,
    authority: []u32,
    columns: []DP.Column = &.{},
    stage1_receipt: api.Receipt = .{},
    stage1_gpu_ms: f32 = -1,
    fn deinit(self: *Segment) void {
        self.a.free(self.main_logs);
        self.a.free(self.main_offsets);
        self.a.free(self.authority);
        self.bind_plan.deinit();
        self.a.destroy(self);
    }
};

pub const Row = struct {
    request: u64,
    ordinal: u32,
    device: u32,
    stage1_wait_ns: u64 = 0,
    stage1_enqueue_ns: u64 = 0,
    stage1_gpu_ms: f32 = -1,
    stage1_arena_peak_words: u64 = 0,
    stage1_host_ns: u64 = 0,
    stage2_prep_ns: u64 = 0,
    stage2_wait_ns: u64 = 0,
    stage2_enqueue_ns: u64 = 0,
    stage2_gpu_ms: f32 = -1,
    stage2_arena_peak_words: u64 = 0,
    stage2_assemble_ns: u64 = 0,
    /// Split of stage2_prep_ns / stage2_assemble_ns [M] (host, monotonic clock).
    stage2_restore_ns: u64 = 0,
    stage2_set_ns: u64 = 0,
    stage2_framing_ns: u64 = 0,
    /// 0 = built (policy off or class miss), 1 = cache hit (rebound), 2 = hit + check build.
    stage2_framing: u32 = 0,
    stage2_decode_ns: u64 = 0,
    stage2_oods_ns: u64 = 0,
    stage2_encode_ns: u64 = 0,
    host_waits: u32 = 0,
    proof_bytes: usize = 0,
};

pub const Hybrid = struct {
    a: std.mem.Allocator,
    set: *jobs.WorkerSet,
    /// Pool device ids (router endpoint i serves ordinals i mod n).
    ids: [8]u32 = undefined,
    device_count: usize = 0,
    workers: [8]*W.Worker = undefined,
    compositions: [8]*const RC.Context = undefined,
    /// Legacy per-device PCS service and the router's numerical stage: the
    /// hybrid closes each CPU scope's legacy custody (router record, retained
    /// MAIN / admission entries) itself, since the legacy PCS never runs.
    natives: [8]*@import("pcs_native.zig").Context = undefined,
    legacy_numerical: Child.NumericalStage = undefined,
    router: *const @import("resident_router.zig").Router,
    gsym: NG.Symbols,
    bsym: NB.Symbols,
    csym: NC.Symbols,
    glsym: NGl.Symbols,
    compsym: NComp.Symbols,
    psym: NP.Symbols,
    copy: HJ.CopyAsync,
    events: Events.Api,
    timing: HJ.Timing,
    catalogue: Sources.Catalogue,
    gcatalogue: NGl.Catalogue,
    gmutex: std.Thread.Mutex = .{},
    windows: [8]std.Thread.Mutex = @splat(.{}),
    wide: bool,
    arena_words: usize,
    request: u64 = 0,
    mutex: std.Thread.Mutex = .{},
    segments: std.AutoHashMapUnmanaged(u32, *Segment) = .empty,
    rows: std.ArrayListUnmanaged(Row) = .empty,
    expected_cpu: usize = 0,
    completed_cpu: usize = 0,
    numerical: Child.NumericalStage = undefined,
    /// Stage-2 class framing cache (STWO_RV64_M8_NATIVE_FRAMING_CACHE, H9).
    framing_policy: FC.Policy = .off,
    framings: FC.Pool(Framing) = undefined,

    /// Boot the workers (before the legacy pool claims device memory).
    pub fn create(a: std.mem.Allocator, library: []const u8) !*Hybrid {
        var config = try jobs.Config.fromEnv();
        config.arena_words = std.mem.alignBackward(usize, try envBytes("STWO_RV64_M8_JOBS_ARENA_BYTES", 20 << 30) / 4, W.Arena.granule);
        // Cap (lazy slots): the segment-scale PCS ingress measured 338.2M words [M] memory-plan-p2.
        config.pinned_slot_words = try envBytes("STWO_RV64_M8_JOBS_PINNED_BYTES", 4 << 30) / 4;
        // Boot (self-test) on a small arena, then park: every job unparks
        // its own window (runWindowed); the cap is the env arena size.
        const cap_words = config.arena_words;
        config.reuse_frees = true;
        config.arena_words = std.mem.alignBackward(usize, (256 << 20) / 4, W.Arena.granule);
        const set = try jobs.WorkerSet.startParked(a, library, config);
        config.arena_words = cap_words;
        errdefer set.stop(a);
        // Parsed before the catalogues below (which the errdefers here do not
        // release): a bad value fails without leaking them.
        const framing_policy = try FC.policyFromEnv();
        // Bounds: one instance per class per job in flight; the hybrid runs one
        // stage-two window per GPU, so 2 per class covers 2 GPUs. 32 classes
        // hold the 7 + 4 segment classes of 24628607 and 26235156 with room.
        const framing_max = try envBytes("STWO_RV64_M8_NATIVE_FRAMING_CACHE_MAX", 32);
        const self = try a.create(Hybrid);
        errdefer a.destroy(self);
        const Version = *const fn () callconv(.c) u32;
        self.* = .{
            .a = a,
            .set = set,
            .router = undefined,
            .gsym = try NG.Symbols.load(&set.libs.base),
            .bsym = try NB.Symbols.load(&set.libs.base),
            .csym = try NC.Symbols.load(&set.libs.base),
            .glsym = try NGl.Symbols.load(&set.libs.base),
            .compsym = try NComp.Symbols.load(&set.libs.base, &set.libs.addon),
            .psym = try NP.Symbols.load(&set.libs.addon),
            .copy = set.libs.addon.lookup(HJ.CopyAsync, "stwo_rv64_jobs_copy_async") orelse return error.MissingJobsRuntimeSymbol,
            .events = try Events.Api.load(&set.libs.base),
            .timing = undefined,
            .catalogue = try Sources.Catalogue.init(a),
            .gcatalogue = NGl.Catalogue.init(a, &set.libs.base),
            .wide = if (set.libs.base.lookup(Version, "stwo_rv64_pcs_request_version")) |version| version() >= 3 else false,
            .arena_words = config.arena_words,
        };
        self.timing = .{ .ctx = self, .create = tCreate, .record = tRecord, .elapsed = tElapsed, .destroy = tDestroy };
        self.framing_policy = framing_policy;
        self.framings = FC.Pool(Framing).init(a, framing_max, 2);
        self.numerical = .{ .context = self, .prove = prove, .bind = bind, .abort = abortScope, .replay_binding = replay };
        std.debug.print("GPU_M8_NATIVE_HYBRID event=boot workers={} arena_words={} wide={} framing_cache={s}\n", .{ set.count, config.arena_words, self.wide, @tagName(self.framing_policy) });
        return self;
    }
    /// After the pool exists: map router endpoints to workers and composition contexts.
    pub fn bindPool(self: *Hybrid, pool: anytype) !void {
        self.router = &pool.router;
        if (pool.router.endpoints.len != pool.devices.len or pool.devices.len > 8) return error.M8NativeJobsPoolShape;
        self.device_count = pool.devices.len;
        self.legacy_numerical = pool.numerical;
        for (pool.devices, 0..) |*d, i| {
            self.compositions[i] = &d.composition;
            self.natives[i] = &d.native;
            const id = pool.router.endpoints[i].device;
            self.ids[i] = id;
            self.workers[i] = for (self.set.slice()) |w| {
                if (w.device_ordinal == id) break w;
            } else return error.M8NativeJobsWorkerForDeviceMissing;
        }
    }
    pub fn destroy(self: *Hybrid) void {
        self.framings.deinit();
        self.dropSegments();
        self.segments.deinit(self.a);
        self.rows.deinit(self.a);
        self.catalogue.deinit();
        self.gcatalogue.deinit();
        self.set.stop(self.a);
        self.a.destroy(self);
    }

    /// Install into the legacy stage table: the local GKR numerical stage and
    /// the stage-two seam. Everything else in `stages` is unchanged.
    pub fn install(self: *Hybrid, stages: anytype) void {
        stages.numerical = &self.numerical;
        stages.native_stage_two = .{ .context = self, .stage_two = stageTwo };
    }

    pub fn beginRequest(self: *Hybrid, cpu_segments: usize) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.request += 1;
        self.expected_cpu = cpu_segments;
        self.completed_cpu = 0;
    }
    /// Request end (success or abort): release every retained region of the
    /// request, park the workers (arena back to the legacy recursion window
    /// or the next request), and write the per-segment report.
    pub fn endRequest(self: *Hybrid, out_dir: ?[]const u8) void {
        self.mutex.lock();
        const request = self.request;
        self.mutex.unlock();
        for (self.set.slice()) |w| _ = w.releaseRequestAndWait(request) catch |err| std.log.err("M8 native hybrid release failed: {s}", .{@errorName(err)});
        self.dropSegments();
        if (out_dir) |dir| self.writeReport(dir) catch |err| std.log.err("M8 native hybrid report failed: {s}", .{@errorName(err)});
        self.mutex.lock();
        self.rows.clearRetainingCapacity();
        self.mutex.unlock();
    }
    fn dropSegments(self: *Hybrid) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.segments.valueIterator();
        while (it.next()) |s| s.*.deinit();
        self.segments.clearRetainingCapacity();
    }
    fn writeReport(self: *Hybrid, dir: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var text: std.Io.Writer.Allocating = .init(self.a);
        defer text.deinit();
        try std.json.Stringify.value(.{ .schema = "rv64-m8-native-hybrid/v2", .request = self.request, .arena_words = self.arena_words, .framing_cache = @tagName(self.framing_policy), .framing_stats = self.framings.snapshot(), .segments = self.rows.items }, .{ .whitespace = .indent_1 }, &text.writer);
        const path = try std.fs.path.join(self.a, &.{ dir, "m8-native-hybrid.json" });
        defer self.a.free(path);
        try std.fs.cwd().writeFile(.{ .sub_path = path, .data = text.written() });
    }

    fn indexFor(self: *const Hybrid, ordinal: u32) usize {
        return ordinal % self.device_count;
    }
    fn workerFor(self: *const Hybrid, ordinal: u32) *W.Worker {
        return self.workers[self.indexFor(ordinal)];
    }
    fn addRow(self: *Hybrid, row: Row) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.rows.items) |*r| if (r.request == row.request and r.ordinal == row.ordinal) {
            inline for (.{ "stage2_prep_ns", "stage2_wait_ns", "stage2_enqueue_ns", "stage2_gpu_ms", "stage2_arena_peak_words", "stage2_assemble_ns", "stage2_restore_ns", "stage2_set_ns", "stage2_framing_ns", "stage2_framing", "stage2_decode_ns", "stage2_oods_ns", "stage2_encode_ns", "proof_bytes" }) |f| @field(r, f) = @field(row, f);
            r.host_waits += row.host_waits;
            return;
        };
        self.rows.append(self.a, row) catch {};
    }

    // ---- CUDA-event timing (base image entry points) ----
    fn tCreate(raw: ?*anyopaque, out: *?*anyopaque) c_int {
        const self: *Hybrid = @ptrCast(@alignCast(raw.?));
        return self.events.create(out, 0);
    }
    fn tRecord(raw: ?*anyopaque, ev: *anyopaque, stream: *anyopaque) c_int {
        const self: *Hybrid = @ptrCast(@alignCast(raw.?));
        return self.events.record(ev, stream);
    }
    fn tElapsed(raw: ?*anyopaque, ms: *f32, b: *anyopaque, e: *anyopaque) c_int {
        const self: *Hybrid = @ptrCast(@alignCast(raw.?));
        return self.events.elapsed(ms, b, e);
    }
    fn tDestroy(raw: ?*anyopaque, ev: *anyopaque) void {
        const self: *Hybrid = @ptrCast(@alignCast(raw.?));
        _ = self.events.destroy(ev);
    }

    // ---------------- stage one: the local GKR + binding job ----------------

    fn prove(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request) anyerror!NG.Proof {
        const self: *Hybrid = @ptrCast(@alignCast(raw));
        var host_timer = try std.time.Timer.start();
        const ha = self.a;
        const ordinal: u32 = request.scope.ordinal;
        const native = request.native_source orelse return error.NativeGkrSourceRequired;
        var gplan = try NG.Plan.init(ha, &self.catalogue, request.scope, request.instances, native, request.native_fixed_columns, request.native_main_columns, request.byte_cap, 0);
        defer gplan.deinit();
        var gkr = try NG.Gkr.init(ha, &gplan, &self.gsym);
        defer gkr.deinit();
        const nf = request.native_fixed_columns.len;
        const nm = request.native_main_columns.len;
        const fixed_host = try ha.alloc([]const u32, nf);
        defer ha.free(fixed_host);
        var fixed_words: usize = 0;
        for (request.native_fixed_columns, fixed_host) |c, *h| {
            if (c.device != null) return error.HybridExpectsHostFixed;
            h.* = coefficientWords(c.coefficients);
            fixed_words += h.len;
        }
        gkr.host_key = fixedKey(request.scope.fixed, fixed_words);
        const legacy = try ha.alloc([*]const u32, nm);
        defer ha.free(legacy);
        const logs = try ha.alloc(u32, nm);
        errdefer ha.free(logs);
        const offsets = try ha.alloc(usize, nm);
        errdefer ha.free(offsets);
        var main_words: usize = 0;
        for (request.native_main_columns, legacy, logs, offsets) |c, *p, *l, *o| {
            const d = c.device orelse return error.HybridExpectsDeviceMain;
            if (d.count != @as(u64, 1) << @intCast(c.log_size)) return error.HybridMainColumnShape;
            p.* = d.words;
            l.* = c.log_size;
            o.* = main_words;
            main_words += @as(usize, 1) << @intCast(c.log_size);
        }
        var bplan = try NB.Plan.init(ha, request.instances, gplan.traversal.layers);
        errdefer bplan.deinit();
        var binding = NB.Binding{ .plan = &bplan, .sym = self.bsym };
        const inputs = try ha.alloc(NG.Input, nf + nm);
        defer ha.free(inputs);
        const worker = self.workerFor(ordinal);
        const windex = self.indexFor(ordinal);
        self.mutex.lock();
        const req = self.request;
        self.mutex.unlock();
        // MAIN retention across the barrier is not selectable: on 24628607 the
        // retained copies displaced a 14.75 GB legacy truth-composition lease
        // (CudaAllocationFailed [M] j24). Stage two takes MAIN from the legacy owner.
        var job = HJ.Stage1Job{ .retain_main = false, .a = ha, .request = req, .ordinal = ordinal, .gkr = &gkr, .binding = &binding, .copy = self.copy, .fixed_host = fixed_host, .legacy_main = legacy, .main_logs = logs, .main_offsets = offsets, .main_words = main_words, .main_root = words(request.scope.main), .timing = &self.timing, .inputs = inputs };
        try job.init();
        defer job.deinit();
        const prep_ns = host_timer.lap();
        const receipt = try runWindowed(self, windex, HJ.Stage1Job, &job);
        if (job.verdict != 0) return error.NativeBindingRejected;
        const section = &(job.section orelse return error.NativeGkrSectionMissing);
        const proof = try section.proof(a, &gplan);
        errdefer {
            var p = proof;
            p.deinit(a);
        }
        const seg = try ha.create(Segment);
        errdefer ha.destroy(seg);
        seg.* = .{ .a = ha, .request = req, .ordinal = ordinal, .device_index = self.indexFor(ordinal), .main_root = request.scope.main, .main_logs = logs, .main_offsets = offsets, .main_words = main_words, .bind_plan = bplan, .bind_region = job.bind_region.?, .authority = try ha.dupe(u32, job.authority), .stage1_receipt = receipt, .stage1_gpu_ms = job.span.gpu_ms };
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.segments.fetchRemove(ordinal)) |old| old.value.deinit();
            try self.segments.put(self.a, ordinal, seg);
        }
        const host_ns = prep_ns + host_timer.read();
        self.addRow(.{ .request = req, .ordinal = ordinal, .device = worker.device_ordinal, .stage1_wait_ns = receipt.wait_ns, .stage1_enqueue_ns = receipt.enqueue_ns, .stage1_gpu_ms = job.span.gpu_ms, .stage1_arena_peak_words = receipt.arena_peak_words, .stage1_host_ns = host_ns, .host_waits = receipt.host_waits });
        std.debug.print("GPU_M8_NATIVE_HYBRID stage=1 request={} ordinal={} device={} gpu_ms={d:.3} enqueue_ns={} wait_ns={} host_prep_ns={} arena_peak_words={} main_words={} host_waits={}\n", .{ req, ordinal, worker.device_ordinal, job.span.gpu_ms, receipt.enqueue_ns, receipt.wait_ns, prep_ns, receipt.arena_peak_words, main_words, receipt.host_waits });
        return proof;
    }

    fn segment(self: *Hybrid, ordinal: u32) !*Segment {
        self.mutex.lock();
        defer self.mutex.unlock();
        const s = self.segments.get(ordinal) orelse return error.HybridSegmentMissing;
        if (s.request != self.request) return error.HybridSegmentStale;
        return s;
    }

    fn bind(raw: *anyopaque, a: std.mem.Allocator, request: Child.DeviceBinding.Request) anyerror!Child.DeviceBinding.Owner {
        const self: *Hybrid = @ptrCast(@alignCast(raw));
        const seg = try self.segment(request.scope.ordinal);
        // The legacy validateArtifact, moved to the host after the job: the
        // device GKR terminal state equals the host partial verification.
        try NB.checkAuthority(&seg.bind_plan, seg.authority, request.artifact.claims_to_verify_by_instance, request.artifact.ood_point, request.eta);
        _ = a;
        return .{ .context = seg, .scope = request.scope, .receipt_digest = request.receipt_digest, .authority_digest = try Child.DeviceBinding.authority(request), .retained_bytes = seg.bind_plan.output_words * 4, .park_fn = parkBinding, .finalize_fn = finalizeBinding, .release_fn = releaseBinding };
    }
    /// The retained region stays (the stage-two job reads it): nothing to park.
    fn parkBinding(raw: *anyopaque) anyerror!usize {
        const seg: *Segment = @ptrCast(@alignCast(raw));
        return seg.bind_plan.output_words * 4;
    }
    /// Legacy finalize (non-deferred binding): device views of the retained
    /// binding columns. Only a legacy stage two would read them; the hybrid's
    /// stage two reads the region itself.
    fn finalizeBinding(raw: *anyopaque, a: std.mem.Allocator, request: Child.DeviceBinding.Request) anyerror!Child.DeviceBinding.Completion {
        const seg: *Segment = @ptrCast(@alignCast(raw));
        const columns = try a.alloc(DP.Column, 16 * request.instances.len);
        errdefer a.free(columns);
        for (request.instances, 0..) |instance, i| {
            const cols = try seg.bind_plan.columns(seg.bind_region, i);
            const rows = @as(usize, 1) << @intCast(instance.row_log);
            for (columns[16 * i ..][0..16], 0..) |*c, k| c.* = .{ .log_size = instance.row_log, .device = .{ .words = cols.ptr + k * rows, .count = rows, .context_token = 1, .generation = 1 } };
        }
        return .{ .columns = columns, .retained_bytes = seg.bind_plan.output_words * 4 };
    }
    fn releaseBinding(_: *anyopaque) void {}
    fn abortScope(raw: *anyopaque, scope: NG.Scope) void {
        const self: *Hybrid = @ptrCast(@alignCast(raw));
        self.releaseSegment(scope.ordinal);
    }
    /// The legacy replay restore (MAIN back for stage two) replays the
    /// binding too: the hybrid's binding output is request-retained, so the
    /// replay only un-parks the owner.
    fn replay(raw: *anyopaque, _: std.mem.Allocator, request: Child.NumericalStage.Request, owner: *Child.DeviceBinding.Owner) anyerror!void {
        const self: *Hybrid = @ptrCast(@alignCast(raw));
        const seg = try self.segment(request.scope.ordinal);
        if (owner.context != @as(*anyopaque, seg)) return error.HybridBindingOwnerMismatch;
        owner.parked = false;
    }
    fn releaseSegment(self: *Hybrid, ordinal: u32) void {
        self.mutex.lock();
        const req = self.request;
        const removed = self.segments.fetchRemove(ordinal);
        self.mutex.unlock();
        const w = self.workerFor(ordinal);
        w.releaseRetained(req, HJ.mainName(ordinal)) catch {};
        w.releaseRetained(req, HJ.bindName(ordinal)) catch {};
        w.releaseRetained(req, HJ.interName(ordinal)) catch {};
        w.releaseRetained(req, HJ.compName(ordinal)) catch {};
        if (removed) |kv| kv.value.deinit();
    }

    // ---------------- stage two: the Stage2 chain job ----------------

    fn stageTwo(raw: *anyopaque, a: std.mem.Allocator, worker: *CW.CpuWorker, pending: *const Manifest.PendingManifest, index: usize, global_budget: usize) anyerror!CW.CpuEncoded {
        const self: *Hybrid = @ptrCast(@alignCast(raw));
        _ = global_budget;
        const ordinal: u32 = @intCast(index);
        // Close the legacy scope whatever the outcome (the legacy PCS stage,
        // which normally does it, never runs for a hybrid CPU segment).
        defer self.closeLegacyScope(worker, ordinal);
        const out = self.stageTwoInner(a, worker, pending, ordinal) catch |err| {
            self.releaseSegment(ordinal);
            return err;
        };
        self.releaseSegment(ordinal);
        self.mutex.lock();
        self.completed_cpu += 1;
        self.mutex.unlock();
        return out;
    }

    fn closeLegacyScope(self: *Hybrid, worker: *CW.CpuWorker, ordinal: u32) void {
        const scope = worker.scheme.device_om31_scope orelse return;
        self.natives[self.indexFor(ordinal)].finishProofScopeChecked(scope) catch |err| std.log.err("M8 native hybrid legacy scope release failed: {s}", .{@errorName(err)});
        if (self.legacy_numerical.abort) |abort| abort(self.legacy_numerical.context, .{ .statement = scope.statement, .fixed = scope.fixed, .main = scope.main, .ordinal = scope.ordinal });
    }

    // ---------------- stage two: class framing (H9) ----------------

    /// The class key: every input the framing builders read except the
    /// request values that `rebindFraming` rewrites. Mask offsets and
    /// component degrees are functions of (case id, trace log, eval log),
    /// which the role geometry carries; `check` mode verifies the claim.
    fn framingKey(self: *const Hybrid, in: FramingInputs) FC.ClassKey {
        var k = FC.Key.init("rv64-m8-native-framing/v1");
        const worker = in.worker;
        k.value(self.wide);
        k.value(worker.config);
        k.bytes(&worker.expected.fixed);
        k.value(in.fixed_logs);
        k.value(@as([]const u32, in.seg.main_logs));
        k.value(@as([]const @TypeOf(worker.plan.slots[0]), worker.plan.slots));
        k.value(worker.plan.inter_columns);
        k.value(worker.plan.claim_count);
        k.value(worker.plan.binding_count);
        k.value(in.comp_log);
        k.value(in.split);
        k.value(in.total);
        k.value(in.mask_log);
        k.value(in.specs.len);
        for (in.specs) |rs| {
            k.value(rs.id);
            k.value(rs.kernel);
            k.value(rs.trace_log);
            k.value(rs.eval_log);
            k.value(rs.widths);
            k.value(rs.offsets);
            k.value(rs.fixed_indices);
            k.value(rs.aux);
            k.value(rs.hc.len);
            k.value(rs.parameters.len);
            k.value(rs.mask_columns);
            k.value(rs.constraints);
            k.value(rs.claim_slots);
        }
        return k.final();
    }

    fn framingFor(self: *Hybrid, in: FramingInputs) !FramingLease {
        if (self.framing_policy == .off) return .{ .framing = try self.buildFraming(in), .pooled = false, .mode = 0 };
        const key = self.framingKey(in);
        switch (try self.framings.checkout(key)) {
            .hit => |fr| {
                errdefer self.framings.discard(fr);
                try self.rebindFraming(fr, in);
                if (self.framing_policy == .check) {
                    const fresh = try self.buildFraming(in);
                    defer fresh.destroy();
                    try sameFraming(fr, fresh);
                    return .{ .framing = fr, .pooled = true, .mode = 2 };
                }
                return .{ .framing = fr, .pooled = true, .mode = 1 };
            },
            .miss => {
                const fr = try self.buildFraming(in);
                const pooled = self.framings.insert(key, fr) catch |err| {
                    fr.destroy();
                    return err;
                };
                return .{ .framing = fr, .pooled = pooled, .mode = 0 };
            },
        }
    }
    fn releaseFraming(self: *Hybrid, lease: FramingLease) void {
        if (lease.pooled) self.framings.checkin(lease.framing) else lease.framing.destroy();
    }

    /// Build one segment's framing (the code stageTwoInner ran per segment).
    fn buildFraming(self: *Hybrid, in: FramingInputs) !*Framing {
        const ha = self.a;
        const worker = in.worker;
        const plan = &worker.plan;
        const seg = in.seg;
        const config = worker.config;
        const beta = config.fri_config.log_blowup_factor;
        const fixed_coefficients = worker.scheme.trees.items[0].coefficients orelse return error.DeviceGkrCoefficientsRequired;
        const fr = try ha.create(Framing);
        fr.* = .{ .a = ha, .comp_log = in.comp_log, .split = in.split, .total = in.total, .mask_log = in.mask_log };
        errdefer fr.destroy();
        // Global interaction plans + INTER shapes, in slot order.
        fr.slots = try ha.alloc(HJ.Slot, plan.slots.len);
        try fr.gplans.ensureTotalCapacity(ha, plan.slots.len);
        fr.inter_shapes = try ha.alloc(NC.Shape, plan.inter_columns);
        var item_fixed: std.ArrayListUnmanaged(DP.Column) = .empty;
        defer item_fixed.deinit(ha);
        var item_main: std.ArrayListUnmanaged(DP.Column) = .empty;
        defer item_main.deinit(ha);
        for (plan.slots, fr.slots) |slot, *out| {
            out.* = .{ .log = slot.log, .inter_offset = slot.inter_offset, .binding_index = slot.binding_index };
            var at = slot.inter_offset;
            if (slot.binding_index != null) {
                for (fr.inter_shapes[at..][0..16]) |*s| s.* = .{ .log_size = slot.log, .encoding = .coefficients };
                at += 16;
            }
            const item = (try globalItem(ha, worker, slot, fixed_coefficients, seg.main_logs, &item_fixed, &item_main)) orelse continue;
            {
                self.gmutex.lock();
                defer self.gmutex.unlock();
                fr.gplans.appendAssumeCapacity(try NGl.Plan.init(ha, &self.gcatalogue, item, in.pending.shared));
            }
            const gp = &fr.gplans.items[fr.gplans.items.len - 1];
            for (fr.inter_shapes[at..][0..gp.width]) |*s| s.* = .{ .log_size = slot.log, .encoding = .evaluations };
            out.global = .{ .plan = gp, .claim_offset = @intCast(slot.claim_offset), .fixed_first = slot.fixed_offset, .main_first = slot.main_offset };
        }
        fr.inter_plan = try NC.CommitPlan.init(ha, fr.inter_shapes, beta);
        fr.inter_logs = try ha.alloc(u32, fr.inter_shapes.len);
        for (fr.inter_shapes, fr.inter_logs) |s, *l| l.* = s.log_size;
        fr.comp_plan = try NComp.Plan.init(ha, .{ .roles = in.specs, .log = in.comp_log, .split = in.split, .total = in.total, .beta = beta, .tree_logs = .{ in.fixed_logs, seg.main_logs, fr.inter_logs } });
        // The cached plan must not borrow the request's Roles storage.
        try fr.comp_plan.?.detach();
        const comp_plan = &fr.comp_plan.?;
        // PCS framing at the placeholder OODS point (challenge independent).
        const placeholder = try NP.placeholderPoint();
        var view = try in.provers.componentsView(ha);
        defer view.deinit(ha);
        var points = try view.maskPointsWithWorkCapture(ha, placeholder, in.mask_log, false, null);
        defer points.deinitDeep(ha);
        const n_comp = core.verifier_types.compositionColumnCount(in.split, 8) orelse return error.InvalidStructure;
        if (n_comp != comp_plan.outputColumns() or points.items.len != 3) return error.HybridCompositionShape;
        const comp_tree = try ha.alloc([]DP.Point, n_comp);
        var comp_made: usize = 0;
        defer {
            for (comp_tree[0..comp_made]) |c| ha.free(c);
            ha.free(comp_tree);
        }
        for (comp_tree) |*c| {
            c.* = try ha.alloc(DP.Point, 1);
            c.*[0] = placeholder;
            comp_made += 1;
        }
        var tree_points = [4][][]DP.Point{ points.items[0], points.items[1], points.items[2], comp_tree };
        var tree_columns: [4][]DP.Column = undefined;
        var made_trees: usize = 0;
        defer for (tree_columns[0..made_trees]) |t| ha.free(t);
        const tree_logs = [4][]const u32{ in.fixed_logs, seg.main_logs, fr.inter_logs, &.{} };
        for (0..4) |t| {
            const count = if (t == 3) n_comp else tree_logs[t].len;
            tree_columns[t] = try ha.alloc(DP.Column, count);
            made_trees += 1;
            for (tree_columns[t], 0..) |*c, i| c.* = NP.placeholderColumn(if (t == 3) comp_plan.chunkLog() else tree_logs[t][i]);
        }
        const trees = [4]DP.Tree{
            .{ .root = worker.expected.fixed, .columns = tree_columns[0] },
            .{ .root = seg.main_root, .columns = tree_columns[1] },
            .{ .root = @splat(0), .columns = tree_columns[2] },
            .{ .root = @splat(0), .columns = tree_columns[3] },
        };
        const pcs_request = DP.Request{ .scope = worker.scheme.device_om31_scope, .config = config, .lifting_log_size = comp_plan.chunkLog() + beta, .trees = &trees, .points = .{ .items = &tree_points } };
        fr.pcs = try NP.PcsJob.prepare(ha, self.psym, pcs_request, placeholder, self.wide);
        fr.pristine_columns = try ha.dupe(PcsColumn, fr.pcs.?.prepared.coefficients);
        return fr;
    }

    /// A cache hit: rewrite this request's words into the class framing.
    fn rebindFraming(self: *Hybrid, fr: *Framing, in: FramingInputs) !void {
        const ha = self.a;
        const worker = in.worker;
        const fixed_coefficients = worker.scheme.trees.items[0].coefficients orelse return error.DeviceGkrCoefficientsRequired;
        try fr.comp_plan.?.rebind(in.specs);
        var item_fixed: std.ArrayListUnmanaged(DP.Column) = .empty;
        defer item_fixed.deinit(ha);
        var item_main: std.ArrayListUnmanaged(DP.Column) = .empty;
        defer item_main.deinit(ha);
        var k: usize = 0;
        for (worker.plan.slots) |slot| {
            const item = (try globalItem(ha, worker, slot, fixed_coefficients, in.seg.main_logs, &item_fixed, &item_main)) orelse continue;
            if (k >= fr.gplans.items.len) return error.NativeFramingCacheMismatch;
            try fr.gplans.items[k].rebind(item, in.pending.shared);
            k += 1;
        }
        if (k != fr.gplans.items.len) return error.NativeFramingCacheMismatch;
        try pcsRequestWords(&fr.pcs.?, fr.pristine_columns, worker.scheme.device_om31_scope, .{ worker.expected.fixed, in.seg.main_root, @splat(0), @splat(0) });
    }

    fn stageTwoInner(self: *Hybrid, a: std.mem.Allocator, worker: *CW.CpuWorker, pending: *const Manifest.PendingManifest, ordinal: u32) !CW.CpuEncoded {
        var timer = try std.time.Timer.start();
        var restore_ns: u64 = 0;
        const ha = self.a;
        const seg = try self.segment(ordinal);
        const expected = worker.expected;
        // MAIN: the stage-one retained copy, else the legacy owner's device
        // tree (restored by the legacy replay when it parked MAIN at stage one).
        const retained_main = false;
        var legacy_main: []const [*]const u32 = &.{};
        defer if (legacy_main.len != 0) ha.free(legacy_main);
        if (!retained_main) {
            var restore_timer = try std.time.Timer.start();
            defer restore_ns = restore_timer.read();
            if (worker.replay) |*owner| try owner.restore(owner.context, worker);
            const tree = worker.scheme.device_om31_trace_trees[1] orelse return error.ResidentGlobalMainRequired;
            if (tree.columns.len != seg.main_logs.len) return error.HybridMainColumnShape;
            const ptrs = try ha.alloc([*]const u32, tree.columns.len);
            for (tree.columns, seg.main_logs, ptrs) |c, l, *p| {
                const d = c.device orelse {
                    ha.free(ptrs);
                    return error.HybridExpectsDeviceMain;
                };
                if (c.log_size != l or d.count != @as(u64, 1) << @intCast(l)) {
                    ha.free(ptrs);
                    return error.HybridMainColumnShape;
                }
                p.* = d.words;
            }
            legacy_main = ptrs;
        }
        // CpuWorker.complete's checks, in its order.
        if (!worker.sealed or worker.consumed) return error.WideCpuPhase;
        try pending.checkPhysicalRoots(ordinal, expected.fixed, seg.main_root);
        if (ordinal != expected.ordinal or !std.mem.eql(u8, &pending.entries[ordinal].scope.statement, &expected.statement)) return error.WideCpuStatementMismatch;
        const local = &(pending.entries[ordinal].local orelse return error.WideCpuLocalRequired);
        const plan = &worker.plan;
        // FIXED: the host tree's coefficients (original order).
        const fixed_coefficients = worker.scheme.trees.items[0].coefficients orelse return error.DeviceGkrCoefficientsRequired;
        const nf = fixed_coefficients.len;
        const fixed_host = try ha.alloc([]const u32, nf);
        defer ha.free(fixed_host);
        const fixed_logs = try ha.alloc(u32, nf);
        defer ha.free(fixed_logs);
        const fixed_offsets = try ha.alloc(usize, nf);
        defer ha.free(fixed_offsets);
        var fixed_words: usize = 0;
        for (fixed_coefficients, fixed_host, fixed_logs, fixed_offsets) |c, *h, *l, *o| {
            h.* = coefficientWords(c.coefficients());
            l.* = c.logSize();
            o.* = fixed_words;
            fixed_words += h.len;
        }
        // Components (claims zero: the composition's claim parameters are
        // patched on device from the Stage2 claims buffer). The Set and the
        // composition roles carry this request's values (row counts, GKR
        // artifact hc rows, shared challenges, public inputs); the framing
        // built from them below is class geometry plus those values.
        var phase = try std.time.Timer.start();
        const zero_claims = try ha.alloc(O, plan.claim_count);
        defer ha.free(zero_claims);
        @memset(zero_claims, O.zero());
        var set = try Components.Set.init(ha, worker.setup, worker.request, worker.first, plan, local, pending.shared, zero_claims);
        defer set.deinit();
        const handles = try set.provers(ha);
        defer ha.free(handles);
        const provers = CP.ComponentProvers{ .components = handles, .n_preprocessed_columns = nf };
        const comp_log = provers.compositionLogDegreeBound();
        const split = try provers.compositionLogSplit();
        const total = provers.totalConstraints();
        const mask_log = core.verifier_types.compositionMaskLogSize(comp_log, split) orelse return error.InvalidStructure;
        var roles = try CompRoles.Roles.fromItemsWith(ha, self.compositions[seg.device_index], set.items, true);
        defer roles.deinit();
        if (roles.claim_count != plan.claim_count) return error.HybridClaimLayoutMismatch;
        const set_ns = phase.lap();
        const fin = FramingInputs{ .worker = worker, .pending = pending, .seg = seg, .fixed_logs = fixed_logs, .provers = provers, .specs = roles.specs, .comp_log = @intCast(comp_log), .split = @intCast(split), .total = @intCast(total), .mask_log = @intCast(mask_log) };
        const lease = try self.framingFor(fin);
        defer self.releaseFraming(lease);
        const fr = lease.framing;
        const framing_ns = phase.lap();
        const slots = fr.slots;
        const pcs = &fr.pcs.?;
        // INTER placeholders (every INTER column is device-resident at enqueue).
        const inter_inputs = try ha.alloc(NC.Input, fr.inter_shapes.len);
        defer ha.free(inter_inputs);
        @memset(inter_inputs, .{ .device = @ptrFromInt(@alignOf(u32)) });
        self.mutex.lock();
        const req = self.request;
        self.mutex.unlock();
        var job = HJ.Stage2Job{
            .a = ha,
            .request = req,
            .ordinal = ordinal,
            .seed = NS1.seedOf(worker.channel),
            .manifest = pending.digest,
            .fixed_key = fixedKey(expected.fixed, fixed_words),
            .fixed_host = fixed_host,
            .fixed_offsets = fixed_offsets,
            .fixed_words = fixed_words,
            .main_offsets = seg.main_offsets,
            .main_words = seg.main_words,
            .legacy_main = legacy_main,
            .main_logs = seg.main_logs,
            .bind_plan = &seg.bind_plan,
            .slots = slots,
            .stage2 = .{ .inter = &fr.inter_plan.?, .pcs = pcs, .csym = self.csym, .nsym = self.psym, .claim_count = @intCast(plan.claim_count) },
            .composition = &fr.comp_plan.?,
            .comp_sym = self.compsym,
            .gsym = &self.glsym,
            .inter_inputs = inter_inputs,
            .copy = self.copy,
            .timing = &self.timing,
        };
        try job.init();
        defer job.deinit();
        const prep_ns = timer.lap();
        const w = self.workers[seg.device_index];
        const receipt = try runWindowed(self, seg.device_index, HJ.Stage2Job, &job);
        // finish-time acceptance, in the legacy order.
        for (job.global_status) |st| if (st != 0) return error.CudaGlobalWitnessRejected;
        try S2.accept(job.composition_status);
        const claims = try a.alloc(O, plan.claim_count);
        errdefer a.free(claims);
        for (claims, 0..) |*c, i| c.* = try felt(job.claims[8 * i ..][0..8]);
        try CW.publicClaims(worker.request, plan, pending.shared, claims);
        const roots = [4][32]u8{ expected.fixed, seg.main_root, bytesOf(job.roots[16..24]), bytesOf(job.roots[24..32]) };
        if (std.posix.getenv("STWO_RV64_M8_NATIVE_JOBS_REPLAY")) |_| {
            // Diagnostic: the legacy host transcript from the same checkpoint.
            var ch = worker.channel;
            WP.mixManifestAndClaims(&ch, pending.digest, claims);
            WP.MC.mixRoot(&ch, roots[2]);
            const alpha_host = ch.drawSecureFelt();
            WP.MC.mixRoot(&ch, roots[3]);
            const oods_host = try core.circle.randomSecureFieldPointFor(O, &ch);
            const oods_dev = DP.Point{ .x = try felt(job.oods[0..8]), .y = try felt(job.oods[8..16]) };
            std.debug.print("GPU_M8_NATIVE_HYBRID event=replay ordinal={} alpha_equal={} oods_equal={} oods_status={}\n", .{ ordinal, alpha_host.eql(try felt(&job.alpha)), oods_host.x.eql(oods_dev.x) and oods_host.y.eql(oods_dev.y), job.oods[32] });
            const C0 = @TypeOf(fixed_coefficients[0]);
            if (comptime @hasDecl(C0, "evalAtPointFor")) {
                const host0 = fixed_coefficients[0].evalAtPointFor(O, oods_host);
                const host1 = fixed_coefficients[1].evalAtPointFor(O, oods_host);
                const sv = decoded_dbg: {
                    var probe = try pcs.decode(ha, job.pcs_words, &roots);
                    defer probe.proof.deinit(ha);
                    break :decoded_dbg .{ probe.proof.sampled_values.items[0][0][0], probe.proof.sampled_values.items[0][1][0], probe.proof.sampled_values.items[0][0].len };
                };
                std.debug.print("GPU_M8_NATIVE_HYBRID event=fixed_eval ordinal={} col0_equal={} col1_equal={} points_col0={} host0={any} pcs0={any}\n", .{ ordinal, host0.eql(sv[0]), host1.eql(sv[1]), sv[2], host0.toM31Array(), sv[0].toM31Array() });
            } else std.debug.print("GPU_M8_NATIVE_HYBRID event=fixed_eval unavailable type={s}\n", .{@typeName(C0)});
        }
        phase.reset();
        var decoded = try pcs.decode(ha, job.pcs_words, &roots);
        defer decoded.proof.deinit(ha);
        const decode_ns = phase.lap();
        // The engine's final OODS constraint check with the real claims.
        {
            var real = try Components.Set.init(ha, worker.setup, worker.request, worker.first, plan, local, pending.shared, claims);
            defer real.deinit();
            const real_handles = try real.provers(ha);
            defer ha.free(real_handles);
            const real_provers = CP.ComponentProvers{ .components = real_handles, .n_preprocessed_columns = nf };
            var real_view = try real_provers.componentsView(ha);
            defer real_view.deinit(ha);
            const oods = DP.Point{ .x = try felt(job.oods[0..8]), .y = try felt(job.oods[8..16]) };
            const proof = WP.Proof{ .commitment_scheme_proof = decoded.proof };
            const extracted = proof.extractCompositionOodsEvalWithSplit(oods, mask_log + split, split) orelse return error.InvalidStructure;
            const expected_eval = try real_view.evalCompositionPolynomialAtPointWithWorkCapture(ha, oods, &decoded.proof.sampled_values, try felt(&job.alpha), mask_log, mask_log + split, split, null);
            if (!extracted.eql(expected_eval)) {
                std.debug.print("GPU_M8_NATIVE_HYBRID event=oods_mismatch ordinal={} extracted={any} expected={any}\n", .{ ordinal, extracted.toM31Array(), expected_eval.toM31Array() });
                return error.ConstraintsNotSatisfied;
            }
        }
        const oods_ns = phase.lap();
        const bytes = try WP.encodePhysical(a, .{ .commitment_scheme_proof = decoded.proof });
        const encode_ns = phase.lap();
        if (std.posix.getenv("STWO_RV64_M8_NATIVE_JOBS_DUMP")) |dir| {
            var name_buf: [64]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buf, "hybrid-cpu-{d}.bin", .{ordinal});
            var d = try std.fs.cwd().makeOpenPath(dir, .{});
            defer d.close();
            try d.writeFile(.{ .sub_path = name, .data = bytes });
        }
        // The worker's scheme/channel are consumed exactly as complete() would.
        worker.consumed = true;
        const assemble_ns = timer.read();
        self.addRow(.{ .request = req, .ordinal = ordinal, .device = w.device_ordinal, .stage2_prep_ns = prep_ns, .stage2_wait_ns = receipt.wait_ns, .stage2_enqueue_ns = receipt.enqueue_ns, .stage2_gpu_ms = job.span.gpu_ms, .stage2_arena_peak_words = receipt.arena_peak_words, .stage2_assemble_ns = assemble_ns, .stage2_restore_ns = restore_ns, .stage2_set_ns = set_ns, .stage2_framing_ns = framing_ns, .stage2_framing = lease.mode, .stage2_decode_ns = decode_ns, .stage2_oods_ns = oods_ns, .stage2_encode_ns = encode_ns, .host_waits = receipt.host_waits, .proof_bytes = bytes.len });
        std.debug.print("GPU_M8_NATIVE_HYBRID stage=2 request={} ordinal={} device={} gpu_ms={d:.3} enqueue_ns={} wait_ns={} host_prep_ns={} restore_ns={} set_ns={} framing_ns={} framing={} assemble_ns={} decode_ns={} oods_ns={} encode_ns={} arena_peak_words={} slots={} globals={} proof_bytes={} host_waits={}\n", .{ req, ordinal, w.device_ordinal, job.span.gpu_ms, receipt.enqueue_ns, receipt.wait_ns, prep_ns, restore_ns, set_ns, framing_ns, lease.mode, assemble_ns, decode_ns, oods_ns, encode_ns, receipt.arena_peak_words, plan.slots.len, job.global_count, bytes.len, receipt.host_waits });
        return .{ .bytes = bytes, .claims = claims };
    }
};

//! M8 GPU-native install-time native class builder (stream gn-shape;
//! rv64-m8-gpu-native.md §3.1, §3.2, inventory H4/H9; contract gpu_native.zig
//! NativeFactory.shape).
//!
//! The legacy hybrid path (native_hybrid.zig) built, PER SEGMENT OF EVERY
//! REQUEST, from a CpuWorker:
//!   Stage 1  NG.Plan.init(scope, instances, native source, FIXED host
//!            coefficients, MAIN columns, byte_cap) + NB.Plan (prove, l.589)
//!   Stage 2  the class framing (global plans, INTER shapes/plan, composition
//!            plan, mask points -> PcsJob.prepare) (buildFraming, l.834-922)
//! This file builds the same objects ONCE per class at install, with NO
//! CpuWorker: from the block's warm capture (`fromCapture`: the capture
//! owner's declarations -> setup keys -> FIXED authority -> request views,
//! exactly gkr_main's inventory), it derives per segment the inputs the
//! hybrid read from the worker (`Inputs`) and runs the hybrid's builders on
//! them (`build`). The outputs are a native_device_stage1.Spec (registered
//! with Registry.register) and a native_device_stage2.ClassFraming (with
//! its device patch tables; registered with Factory.register).
//!
//! What is per request (never in a class; rebound / patched per job):
//!   Stage 1  the GKR child prefix (scope: statement + MAIN root) and every
//!            source item's public words (RequestWords.prefix / .publics);
//!   Stage 2  global shared draws + the segment's public namespace + the
//!            Stage-1 semantic handoff (the patch tables), the PCS expected
//!            MAIN root (section 15) and the scope identity.
//! The class builder fills those with placeholders; `Fingerprint` digests
//! every field and masks exactly these words, so the install-built class
//! can be compared field by field with the class built from the legacy
//! per-segment inputs (rv64_m8_class_build_parity_main.zig, real blocks).
//!
//! Class key: SHA-256 over every class field digest (`Fingerprint.key`), so
//! two segments share a class iff their class fields are identical.
//!
//! Class miss on a new block: `Builder.shape` builds and registers the
//! block's classes from its capture while the registry is open (install);
//! after the registry sealed, `Builder.missBlock` builds the class on the
//! miss path and records it (`misses`), never failing closed for a new block
//! (the device warm of a missed class is the factory's next `installed`).
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_riscv_cpu_integration");
const G = @import("gpu_native.zig");
const S1 = @import("native_device_stage1.zig");
const S2 = @import("native_device_stage2.zig");
const ND = @import("native_device.zig");
const NG = @import("native_gkr.zig");
const NB = @import("native_binding.zig");
const NC = @import("native_commit.zig");
const NGl = @import("native_global.zig");
const NP = @import("native_pcs.zig");
const NComp = @import("native_composition.zig");
const NE = @import("native_encode.zig");
const HJ = @import("native_hybrid_jobs.zig");
const FC = @import("native_framing_cache.zig");
const Sources = @import("../gkr_sources.zig");
const JP = @import("../joined_parameters.zig");

const CW = CPU.rv64_gkr_cpu_worker;
const Components = CPU.rv64_gkr_cpu_components;
const Child = CPU.rv64_gkr_child;
const Manifest = CPU.rv64_gkr_manifest;
const DP = CPU.rv64_device_pcs;
const WP = CPU.rv64_gkr_worker_protocol;
const DG = CW.DeviceGlobal;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const CP = engine.air.component_prover.ForField(O);

pub const Setup = std.meta.Child(@FieldType(CW.CpuWorker, "setup"));
pub const Request = @FieldType(CW.CpuWorker, "request");
pub const FirstIds = @FieldType(CW.CpuWorker, "first");
pub const Config = @FieldType(CW.CpuWorker, "config");
pub const NativeSources = @FieldType(CW.CpuWorker, "source");
pub const Pending = Child.Pending;
pub const Shared = Manifest.Shared;
const PcsColumn = @typeInfo(@TypeOf(@as(NP.PcsJob, undefined).prepared.coefficients)).pointer.child;

// ---------------------------------------------------------------------------
// Build environment (service constants, never per request)
// ---------------------------------------------------------------------------

/// The composition roles of a segment's component set (the hybrid's
/// CompRoles.Roles.fromItemsWith(context, items, device_claims = true)) and
/// the composition artifacts' parameter slots. Injected: the implementation
/// reads the legacy composition context's kernel metadata, which the sync
/// lint forbids under rv64/jobs/ (rv64/m8_class_build_composition.zig).
pub const RolesOut = struct {
    specs: []const NComp.RoleSpec,
    claim_count: u32,
    ctx: *anyopaque,
    release: *const fn (*anyopaque) void,
};
pub const Composition = struct {
    ctx: *const anyopaque,
    roles: *const fn (*const anyopaque, std.mem.Allocator, []const Components.Item) anyerror!RolesOut,
    parameter_slots: *const fn (*const anyopaque, id: u32) []const u32,
};

pub const Env = struct {
    a: std.mem.Allocator,
    /// Local-GKR source catalogue (Sources.Catalogue.init; host only).
    catalogue: *const Sources.Catalogue,
    /// Global-interaction catalogue (base library; entries built lazily).
    gcatalogue: *NGl.Catalogue,
    gmutex: *std.Thread.Mutex,
    /// PCS framing symbols (jobs addon).
    psym: NP.Symbols,
    /// Composition roles + artifact parameter slots (m8_class_build_composition.zig).
    composition: Composition,
    /// stwo_rv64_pcs_request_version() >= 3 (the hybrid's `wide`).
    wide: bool,
    config: Config,
    /// The local GKR traversal byte cap (legacy: the coordinator's gkr_budget).
    byte_cap: usize,
    /// Pinned capture words per segment row (ClassEntry.capture_words =
    /// rows * this; 0 = the class uses no ring; gn-pack's format sets it).
    capture_words_per_row: u64 = 0,
};

// ---------------------------------------------------------------------------
// Per-segment inputs: exactly what the hybrid read from the CpuWorker
// ---------------------------------------------------------------------------

pub const Inputs = struct {
    ordinal: u32,
    setup: *const Setup,
    request: Request,
    first: FirstIds,
    /// FIXED tree coefficient columns, original order (host, borrowed).
    fixed: []const DP.Column,
    fixed_root: [32]u8,
    /// MAIN tree column logs, original order.
    main_logs: []const u32,
    /// Local GKR instances (roster.fromSetup; the worker's `instances`).
    instances: []const NG.Instance,
    /// The GKR source the plan reads (u8_pairs, compact, publics, sponge
    /// first ids): the worker's real source, or a `stubSource`.
    native: *const NativeSources,
    /// Per-request (patched / rebound) values; placeholders at install.
    statement: [32]u8 = @splat(0),
    main_root: [32]u8 = @splat(0),
    pending: *const Pending,
    shared: Shared,
};

/// A GKR source view holding exactly the fields NG.Plan.init /
/// Sources.Plan.init and the hybrid's globalItem read (cpu.u8_pairs,
/// cpu.compact, cpu.epoch, cpu.public, sponge[k].first_id). Everything else
/// is undefined: never deinit it, never hand it to a prover.
pub fn stubSource(setup: *const Setup, request: Request) NativeSources {
    var s: NativeSources = undefined;
    s.device_generated = false;
    s.device_main = null;
    s.core.cpu.u8_pairs = setup.materials.geometry.cpu_u8_pairs;
    s.core.cpu.compact = setup.materials.geometry.cpu_compact_decode;
    s.core.cpu.epoch = request.base.epoch;
    s.core.cpu.public = request.base.cpu;
    s.sponge = @splat(null);
    for (&s.sponge, 0..) |*slot, k| if (setup.bridges.sponge.at(@enumFromInt(k)) != null) {
        slot.* = @as(@typeInfo(@TypeOf(slot.*)).optional.child, undefined);
        slot.*.?.first_id = request.sponge.first_id;
    };
    return s;
}

/// Placeholder local-GKR artifact of the instance shapes (zero claims/point,
/// zero challenges): the framing builders read only its shape (claims per
/// instance, variable counts); the values are per request (semantic patch).
pub fn placeholderPending(a: std.mem.Allocator, instances: []const NG.Instance) !Pending {
    const n = instances.len;
    const vars = try a.alloc(usize, n);
    errdefer a.free(vars);
    var max: usize = 0;
    for (instances, vars) |inst, *v| {
        v.* = @intCast(try inst.variables());
        max = @max(max, v.*);
    }
    const point = try a.alloc(O, max);
    errdefer a.free(point);
    @memset(point, O.zero());
    const claims = try a.alloc([]O, n);
    errdefer a.free(claims);
    var made: usize = 0;
    errdefer for (claims[0..made]) |c| a.free(c);
    for (claims) |*c| {
        c.* = try a.alloc(O, 2);
        @memset(c.*, O.zero());
        made += 1;
    }
    return .{ .artifact = .{ .ood_point = point, .claims_to_verify_by_instance = claims, .n_variables_by_instance = vars }, .challenges = std.mem.zeroes(@FieldType(Pending, "challenges")), .eta = O.zero(), .digest = @splat(0) };
}

pub fn placeholderShared() Shared {
    return std.mem.zeroes(Shared);
}

fn coefficientWords(values: []const M) []const u32 {
    return @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
}

// ---------------------------------------------------------------------------
// The class (owned; Spec + ClassFraming views borrow it)
// ---------------------------------------------------------------------------

pub const Class = struct {
    a: std.mem.Allocator,
    key: G.ClassKey = @splat(0),
    rows: u64 = 0,
    // ---- Stage 1 ----
    gkr: NG.Plan,
    instances: []NG.Instance,
    fixed_shapes: []NC.Shape,
    main_shapes: []NC.Shape,
    fixed_host: [][]const u32,
    /// Owned copy of the FIXED coefficients (the capture-side leases die).
    fixed_storage: []u32,
    fixed_root: [32]u8,
    beta: u32,
    capture_words: u64 = 0,
    // ---- Stage 2 (the hybrid Framing, plus the n-stage2 extras) ----
    comp_log: u32,
    split: u32,
    total: u32,
    mask_log: u32,
    claim_count: u32,
    slots: []HJ.Slot = &.{},
    gplans: std.ArrayListUnmanaged(NGl.Plan) = .empty,
    /// Per global plan: the artifact parameter slots (patch derivation).
    gslots: [][]const u32 = &.{},
    inter_shapes: []NC.Shape = &.{},
    inter_logs: []u32 = &.{},
    inter_plan: ?NC.CommitPlan = null,
    comp_plan: ?NComp.Plan = null,
    /// Per composition role: its artifact parameter slots.
    role_slots: [][]const u32 = &.{},
    pcs: ?NP.PcsJob = null,
    pristine_columns: []PcsColumn = &.{},
    program: ?NE.Program = null,
    bind_plan: NB.Plan,
    fixed_offsets: []usize = &.{},
    fixed_words: usize = 0,
    main_offsets: []usize = &.{},
    main_words: usize = 0,
    global_patches: []S2.PatchSet = &.{},
    comp_patches: S2.PatchSet = .{},
    semantic_words: usize = 0,
    framing: ?S2.ClassFraming = null,

    pub fn deinit(self: *Class) void {
        const a = self.a;
        if (self.framing) |*f| f.global_patches = &.{};
        for (self.global_patches) |*p| p.deinit(a);
        a.free(self.global_patches);
        self.comp_patches.deinit(a);
        a.free(self.main_offsets);
        a.free(self.fixed_offsets);
        self.bind_plan.deinit();
        if (self.program) |*p| p.deinit();
        a.free(self.pristine_columns);
        if (self.pcs) |*p| p.deinit(a);
        a.free(self.role_slots);
        if (self.comp_plan) |*p| p.deinit();
        if (self.inter_plan) |*p| p.deinit();
        a.free(self.inter_logs);
        a.free(self.inter_shapes);
        for (self.gplans.items) |*p| p.deinit();
        self.gplans.deinit(a);
        a.free(self.gslots);
        a.free(self.slots);
        a.free(self.fixed_storage);
        a.free(self.fixed_host);
        a.free(self.main_shapes);
        a.free(self.fixed_shapes);
        a.free(self.instances);
        self.gkr.deinit();
        a.destroy(self);
    }

    pub fn spec(self: *const Class) S1.Spec {
        return .{ .key = self.key, .gkr = &self.gkr, .instances = self.instances, .fixed_shapes = self.fixed_shapes, .fixed_host = self.fixed_host, .fixed_root = S2.words8(self.fixed_root), .main_shapes = self.main_shapes, .beta = self.beta, .capture_words = self.capture_words };
    }
    /// native_device_stage1 Class.fixed_key of this class (the worker-
    /// persistent FIXED region Stage 2 reads).
    pub fn fixedKey(self: *const Class) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-n1-fixed-v1");
        h.update(&self.key);
        return h.finalResult();
    }
    /// The Stage-2 framing's class-cache key (distinct from the Stage-1
    /// key: one ClassCache entry per key, and the two stages own different
    /// plan types). Factory.bindSegment(segment, framingKey(class key)).
    pub fn framingKey(key: G.ClassKey) G.ClassKey {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-gn-shape-framing/v1");
        h.update(&key);
        return h.finalResult();
    }
};

/// Stage 1 of `build`: the hybrid prove()'s plan construction, verbatim
/// (NG.Plan.init on the segment's FIXED host / MAIN shapes; NB.Plan). The
/// plan keeps views of its host FIXED columns (staged by the GKR job), so it
/// is built on the class's OWN copy (`fixed_storage`), never on the
/// capture-side lease.
fn buildStage1(env: *const Env, in: Inputs, cl: *Class) !void {
    const a = env.a;
    const scope = NG.Scope{ .statement = in.statement, .fixed = in.fixed_root, .main = in.main_root, .ordinal = in.ordinal };
    const fixed_cols = try a.alloc(DP.Column, cl.fixed_host.len);
    defer a.free(fixed_cols);
    for (fixed_cols, cl.fixed_host, cl.fixed_shapes) |*c, h, sh| c.* = .{ .log_size = sh.log_size, .coefficients = @as([*]const M, @ptrCast(h.ptr))[0..h.len] };
    // MAIN as device placeholders (the request's MAIN is device-resident).
    const main_cols = try a.alloc(DP.Column, in.main_logs.len);
    defer a.free(main_cols);
    for (main_cols, in.main_logs) |*c, l| c.* = NP.placeholderColumn(l);
    cl.gkr = try NG.Plan.init(a, env.catalogue, scope, in.instances, in.native, fixed_cols, main_cols, env.byte_cap, 0);
}

/// Build one segment's class (Stage 1 spec + Stage 2 framing) from `in`.
pub fn build(env: *const Env, in: Inputs) !*Class {
    const a = env.a;
    const beta = env.config.fri_config.log_blowup_factor;
    const cl = try a.create(Class);
    errdefer a.destroy(cl);
    cl.a = a;
    cl.instances = try a.dupe(NG.Instance, in.instances);
    errdefer a.free(cl.instances);
    // FIXED: owned copy of the host coefficients (original order).
    var fixed_words: usize = 0;
    for (in.fixed) |c| fixed_words += c.coefficients.len;
    cl.fixed_storage = try a.alloc(u32, fixed_words);
    errdefer a.free(cl.fixed_storage);
    cl.fixed_host = try a.alloc([]const u32, in.fixed.len);
    errdefer a.free(cl.fixed_host);
    cl.fixed_shapes = try a.alloc(NC.Shape, in.fixed.len);
    errdefer a.free(cl.fixed_shapes);
    cl.fixed_offsets = try a.alloc(usize, in.fixed.len);
    errdefer a.free(cl.fixed_offsets);
    {
        var at: usize = 0;
        for (in.fixed, cl.fixed_host, cl.fixed_shapes, cl.fixed_offsets) |c, *h, *s, *o| {
            const w = coefficientWords(c.coefficients);
            @memcpy(cl.fixed_storage[at..][0..w.len], w);
            h.* = cl.fixed_storage[at..][0..w.len];
            s.* = .{ .log_size = c.log_size, .encoding = .coefficients };
            o.* = at;
            at += w.len;
        }
        cl.fixed_words = at;
    }
    try buildStage1(env, in, cl);
    errdefer cl.gkr.deinit();
    cl.main_shapes = try a.alloc(NC.Shape, in.main_logs.len);
    errdefer a.free(cl.main_shapes);
    cl.main_offsets = try a.alloc(usize, in.main_logs.len);
    errdefer a.free(cl.main_offsets);
    {
        var at: usize = 0;
        for (in.main_logs, cl.main_shapes, cl.main_offsets) |l, *s, *o| {
            s.* = .{ .log_size = l, .encoding = .evaluations };
            o.* = at;
            at += @as(usize, 1) << @intCast(l);
        }
        cl.main_words = at;
    }
    cl.fixed_root = in.fixed_root;
    cl.beta = beta;
    cl.rows = @as(u64, 1) << @intCast(in.setup.materials.geometry.cpu_log);
    cl.capture_words = env.capture_words_per_row * cl.rows;
    cl.bind_plan = try NB.Plan.init(a, in.instances, cl.gkr.traversal.layers);
    errdefer cl.bind_plan.deinit();
    // Remaining Stage-2 fields start empty (deinit-safe from here on).
    cl.slots = &.{};
    cl.gplans = .empty;
    cl.gslots = &.{};
    cl.inter_shapes = &.{};
    cl.inter_logs = &.{};
    cl.inter_plan = null;
    cl.comp_plan = null;
    cl.role_slots = &.{};
    cl.pcs = null;
    cl.pristine_columns = &.{};
    cl.program = null;
    cl.global_patches = &.{};
    cl.comp_patches = .{};
    cl.framing = null;
    cl.key = @splat(0);
    errdefer {
        // Stage-1 parts are released by the errdefers above.
        for (cl.global_patches) |*p| p.deinit(a);
        a.free(cl.global_patches);
        cl.comp_patches.deinit(a);
        if (cl.program) |*p| p.deinit();
        a.free(cl.pristine_columns);
        if (cl.pcs) |*p| p.deinit(a);
        a.free(cl.role_slots);
        if (cl.comp_plan) |*p| p.deinit();
        if (cl.inter_plan) |*p| p.deinit();
        a.free(cl.inter_logs);
        a.free(cl.inter_shapes);
        for (cl.gplans.items) |*p| p.deinit();
        cl.gplans.deinit(a);
        a.free(cl.gslots);
        a.free(cl.slots);
    }
    try buildStage2(env, in, cl);
    var fp = try Fingerprint.of(a, cl);
    defer fp.deinit();
    cl.key = fp.key();
    cl.framing = classFraming(cl);
    try cl.framing.?.validate();
    return cl;
}

/// The global item of one slot (the hybrid's globalItem; sponge first id
/// from the source view).
fn globalItem(a: std.mem.Allocator, native: *const NativeSources, slot: anytype, fixed: []const DP.Column, main_logs: []const u32, item_fixed: *std.ArrayListUnmanaged(DP.Column), item_main: *std.ArrayListUnmanaged(DP.Column)) !?DG.Item {
    const n = CPU.rv64_gkr_global_cpu.claimCount(slot.origin);
    if (n == 0) return null;
    const descriptor = CPU.rv64_gkr_source.Descriptor{ .origin = slot.origin };
    const shape = try CPU.rv64_gkr_constraints.shape(descriptor);
    if (slot.fixed_offset + shape.fixed > fixed.len or slot.main_offset + shape.main > main_logs.len) return error.InvalidWideGlobalShape;
    item_fixed.clearRetainingCapacity();
    for (fixed[slot.fixed_offset..][0..shape.fixed]) |c| try item_fixed.append(a, .{ .log_size = c.log_size, .coefficients = c.coefficients });
    item_main.clearRetainingCapacity();
    for (main_logs[slot.main_offset..][0..shape.main]) |l| try item_main.append(a, NP.placeholderColumn(l));
    const sponge_first_id: u32 = if (slot.origin == .sponge) (native.sponge[@intFromEnum(slot.origin.sponge)] orelse return error.MissingLocalGkrBridge).first_id else 0;
    return DG.Item{ .descriptor = descriptor, .log_size = slot.log, .fixed = item_fixed.items, .fixed_offset = slot.fixed_offset, .main = item_main.items, .sponge_first_id = sponge_first_id };
}

/// Stage 2 of `build`: the hybrid's stageTwoInner component set + buildFraming,
/// verbatim, then the n-stage2 extras (encode program, patch tables).
fn buildStage2(env: *const Env, in: Inputs, cl: *Class) !void {
    const a = env.a;
    const beta = cl.beta;
    var plan = try Components.Plan.init(a, in.setup);
    defer plan.deinit();
    cl.claim_count = @intCast(plan.claim_count);
    const fixed_logs = try a.alloc(u32, in.fixed.len);
    defer a.free(fixed_logs);
    for (in.fixed, fixed_logs) |c, *l| l.* = c.log_size;
    // Components with zero claims (the hybrid's: claim parameters are device patches).
    const zero_claims = try a.alloc(O, plan.claim_count);
    defer a.free(zero_claims);
    @memset(zero_claims, O.zero());
    var set = try Components.Set.init(a, in.setup, in.request, in.first, &plan, in.pending, in.shared, zero_claims);
    defer set.deinit();
    const handles = try set.provers(a);
    defer a.free(handles);
    const provers = CP.ComponentProvers{ .components = handles, .n_preprocessed_columns = in.fixed.len };
    const comp_log = provers.compositionLogDegreeBound();
    const split = try provers.compositionLogSplit();
    const total = provers.totalConstraints();
    const mask_log = core.verifier_types.compositionMaskLogSize(comp_log, split) orelse return error.InvalidStructure;
    const roles = try env.composition.roles(env.composition.ctx, a, set.items);
    defer roles.release(roles.ctx);
    if (roles.claim_count != plan.claim_count) return error.HybridClaimLayoutMismatch;
    cl.comp_log = @intCast(comp_log);
    cl.split = @intCast(split);
    cl.total = @intCast(total);
    cl.mask_log = @intCast(mask_log);

    // ---- hybrid buildFraming ----
    cl.slots = try a.alloc(HJ.Slot, plan.slots.len);
    try cl.gplans.ensureTotalCapacity(a, plan.slots.len);
    cl.gslots = try a.alloc([]const u32, plan.slots.len);
    var n_globals: usize = 0;
    cl.inter_shapes = try a.alloc(NC.Shape, plan.inter_columns);
    var item_fixed: std.ArrayListUnmanaged(DP.Column) = .empty;
    defer item_fixed.deinit(a);
    var item_main: std.ArrayListUnmanaged(DP.Column) = .empty;
    defer item_main.deinit(a);
    for (plan.slots, cl.slots) |slot, *out| {
        out.* = .{ .log = slot.log, .inter_offset = slot.inter_offset, .binding_index = slot.binding_index };
        var at = slot.inter_offset;
        if (slot.binding_index != null) {
            for (cl.inter_shapes[at..][0..16]) |*s| s.* = .{ .log_size = slot.log, .encoding = .coefficients };
            at += 16;
        }
        const item = (try globalItem(a, in.native, slot, in.fixed, in.main_logs, &item_fixed, &item_main)) orelse continue;
        {
            env.gmutex.lock();
            defer env.gmutex.unlock();
            cl.gplans.appendAssumeCapacity(try NGl.Plan.init(a, env.gcatalogue, item, in.shared));
        }
        const gp = &cl.gplans.items[cl.gplans.items.len - 1];
        cl.gslots[n_globals] = gp.entry.artifact.parameter_slots;
        n_globals += 1;
        for (cl.inter_shapes[at..][0..gp.width]) |*s| s.* = .{ .log_size = slot.log, .encoding = .evaluations };
        out.global = .{ .plan = gp, .claim_offset = @intCast(slot.claim_offset), .fixed_first = slot.fixed_offset, .main_first = slot.main_offset };
    }
    cl.gslots = try a.realloc(cl.gslots, n_globals);
    cl.inter_plan = try NC.CommitPlan.init(a, cl.inter_shapes, beta);
    cl.inter_logs = try a.alloc(u32, cl.inter_shapes.len);
    for (cl.inter_shapes, cl.inter_logs) |s, *l| l.* = s.log_size;
    cl.comp_plan = try NComp.Plan.init(a, .{ .roles = roles.specs, .log = cl.comp_log, .split = cl.split, .total = cl.total, .beta = beta, .tree_logs = .{ fixed_logs, in.main_logs, cl.inter_logs } });
    // The cached plan must not borrow the request's Roles storage.
    try cl.comp_plan.?.detach();
    const comp_plan = &cl.comp_plan.?;
    cl.role_slots = try a.alloc([]const u32, roles.specs.len);
    for (roles.specs, cl.role_slots) |rs, *rsl| rsl.* = env.composition.parameter_slots(env.composition.ctx, rs.id);
    // PCS framing at the placeholder OODS point (challenge independent).
    const placeholder = try NP.placeholderPoint();
    var view = try provers.componentsView(a);
    defer view.deinit(a);
    var points = try view.maskPointsWithWorkCapture(a, placeholder, cl.mask_log, false, null);
    defer points.deinitDeep(a);
    const n_comp = core.verifier_types.compositionColumnCount(cl.split, 8) orelse return error.InvalidStructure;
    if (n_comp != comp_plan.outputColumns() or points.items.len != 3) return error.HybridCompositionShape;
    const comp_tree = try a.alloc([]DP.Point, n_comp);
    var comp_made: usize = 0;
    defer {
        for (comp_tree[0..comp_made]) |c| a.free(c);
        a.free(comp_tree);
    }
    for (comp_tree) |*c| {
        c.* = try a.alloc(DP.Point, 1);
        c.*[0] = placeholder;
        comp_made += 1;
    }
    var tree_points = [4][][]DP.Point{ points.items[0], points.items[1], points.items[2], comp_tree };
    var tree_columns: [4][]DP.Column = undefined;
    var made_trees: usize = 0;
    defer for (tree_columns[0..made_trees]) |t| a.free(t);
    const tree_logs = [4][]const u32{ fixed_logs, in.main_logs, cl.inter_logs, &.{} };
    for (0..4) |t| {
        const count = if (t == 3) n_comp else tree_logs[t].len;
        tree_columns[t] = try a.alloc(DP.Column, count);
        made_trees += 1;
        for (tree_columns[t], 0..) |*c, i| c.* = NP.placeholderColumn(if (t == 3) comp_plan.chunkLog() else tree_logs[t][i]);
    }
    const trees = [4]DP.Tree{
        .{ .root = in.fixed_root, .columns = tree_columns[0] },
        .{ .root = in.main_root, .columns = tree_columns[1] },
        .{ .root = @splat(0), .columns = tree_columns[2] },
        .{ .root = @splat(0), .columns = tree_columns[3] },
    };
    const scope = DP.Scope{ .statement = in.statement, .fixed = in.fixed_root, .main = in.main_root, .ordinal = in.ordinal };
    const pcs_request = DP.Request{ .scope = scope, .config = env.config, .lifting_log_size = comp_plan.chunkLog() + beta, .trees = &trees, .points = .{ .items = &tree_points } };
    cl.pcs = try NP.PcsJob.prepare(a, env.psym, pcs_request, placeholder, env.wide);
    cl.pristine_columns = try a.dupe(PcsColumn, cl.pcs.?.prepared.coefficients);

    // ---- n-stage2 extras: encode program + device patch tables ----
    cl.program = try NE.Program.build(a, cl.pcs.?.prepared.metadata.shape);
    cl.global_patches = try a.alloc(S2.PatchSet, n_globals);
    for (cl.global_patches) |*p| p.* = .{};
    for (cl.gslots, cl.global_patches) |slots, *ps| ps.* = try patchSet(a, &.{.{ .slots = slots, .base = 0 }}, &.{});
    // Composition: every role's parameter slots at its table offset, and
    // every hc role's rows from the semantic handoff (after the namespace felts).
    var groups: std.ArrayListUnmanaged(SlotGroup) = .empty;
    defer groups.deinit(a);
    var hc: std.ArrayListUnmanaged(HcRun) = .empty;
    defer hc.deinit(a);
    var semantic_felts: u32 = S2.semantic_felts;
    for (comp_plan.roles, cl.role_slots) |r, slots| {
        try groups.append(a, .{ .slots = slots, .base = @intCast(r.t_params) });
        if (r.spec.aux == .hc) {
            const felts: u32 = @intCast(r.spec.hc.len / 8);
            try hc.append(a, .{ .dst = @intCast(r.t_hc), .first = semantic_felts, .felts = felts });
            semantic_felts += felts;
        }
    }
    cl.comp_patches = try patchSet(a, groups.items, hc.items);
    cl.semantic_words = 8 * @as(usize, semantic_felts);
}

pub const SlotGroup = struct { slots: []const u32, base: u32 };
pub const HcRun = struct { dst: u32, first: u32, felts: u32 };

pub fn patchSet(a: std.mem.Allocator, groups: []const SlotGroup, hc: []const HcRun) !S2.PatchSet {
    var set = S2.PatchSet{};
    errdefer set.deinit(a);
    inline for (S2.sources) |source| {
        var dst: std.ArrayListUnmanaged(u32) = .empty;
        defer dst.deinit(a);
        var index: std.ArrayListUnmanaged(u32) = .empty;
        defer index.deinit(a);
        for (groups) |g| try S2.appendSlots(a, &dst, &index, g.slots, g.base, source);
        if (source == .semantic) for (hc) |run| for (0..run.felts) |k| {
            try dst.append(a, run.dst + 8 * @as(u32, @intCast(k)));
            try index.append(a, run.first + @as(u32, @intCast(k)));
        };
        @field(set, @tagName(source)) = try S2.patchOf(a, &dst, &index);
    }
    return set;
}

pub fn classFraming(self: *Class) S2.ClassFraming {
    return .{
        .a = self.a,
        .key = Class.framingKey(self.key),
        .claim_count = self.claim_count,
        .slots = self.slots,
        .inter = &self.inter_plan.?,
        .composition = &self.comp_plan.?,
        .pcs = &self.pcs.?,
        .program = self.program.?,
        .fixed_root = self.fixed_root,
        .fixed_key = self.fixedKey(),
        .fixed_host = self.fixed_host,
        .fixed_offsets = self.fixed_offsets,
        .fixed_words = self.fixed_words,
        .main_offsets = self.main_offsets,
        .main_words = self.main_words,
        .bind_plan = &self.bind_plan,
        .global_patches = self.global_patches,
        .comp_patches = self.comp_patches,
        .semantic_words = self.semantic_words,
    };
}

// ---------------------------------------------------------------------------
// Field-by-field fingerprint (class fields vs per-request fields)
// ---------------------------------------------------------------------------

pub const Field = struct {
    name: []const u8,
    /// true: part of the class (must be equal for equal classes);
    /// false: per-request value (rebound / patched; reported only).
    class: bool,
    digest: [32]u8,
};

pub const Fingerprint = struct {
    a: std.mem.Allocator,
    fields: std.ArrayListUnmanaged(Field) = .empty,

    pub fn deinit(self: *Fingerprint) void {
        self.fields.deinit(self.a);
    }
    pub fn key(self: *const Fingerprint) G.ClassKey {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-gn-shape-class/v1");
        for (self.fields.items) |f| if (f.class) {
            h.update(f.name);
            h.update(&f.digest);
        };
        return h.finalResult();
    }
    fn put(self: *Fingerprint, name: []const u8, class: bool, k: *FC.Key) !void {
        try self.fields.append(self.a, .{ .name = name, .class = class, .digest = k.final() });
    }
    fn value(self: *Fingerprint, name: []const u8, class: bool, v: anytype) !void {
        var k = FC.Key.init(name);
        k.value(v);
        try self.put(name, class, &k);
    }
    fn words(self: *Fingerprint, name: []const u8, class: bool, w: []const u32) !void {
        var k = FC.Key.init(name);
        k.bytes(std.mem.sliceAsBytes(w));
        try self.put(name, class, &k);
    }
    /// `w` with the 8-word felts at `masked` dst offsets zeroed (class part)
    /// and the masked words alone (request part).
    fn maskedWords(self: *Fingerprint, name: []const u8, request_name: []const u8, w: []const u32, masked: []const u32) !void {
        const copy = try self.a.dupe(u32, w);
        defer self.a.free(copy);
        var req = FC.Key.init(request_name);
        for (masked) |d| {
            const n = @min(8, copy.len -| d);
            req.bytes(std.mem.sliceAsBytes(copy[d..][0..n]));
            @memset(copy[d..][0..n], 0);
        }
        try self.words(name, true, copy);
        try self.put(request_name, false, &req);
    }

    pub fn of(a: std.mem.Allocator, cl: *const Class) !Fingerprint {
        var fp = try ofStage1(a, cl);
        errdefer fp.deinit();
        try fp.addStage2(cl);
        return fp;
    }
    /// Stage-1 fields only (the Spec + binding plan).
    pub fn ofStage1(a: std.mem.Allocator, cl: *const Class) !Fingerprint {
        var fp = Fingerprint{ .a = a };
        errdefer fp.deinit();
        try fp.addStage1(cl);
        return fp;
    }
    fn addStage1(fp: *Fingerprint, cl: *const Class) !void {
        // ---- Stage 1: Spec ----
        const g = &cl.gkr;
        try fp.value("s1.gkr.variables", true, g.variables);
        try fp.value("s1.gkr.traversal", true, g.traversal);
        try fp.value("s1.gkr.v3", true, g.v3);
        try fp.value("s1.gkr.relation_count", true, g.relation_count);
        try fp.value("s1.gkr.byte_cap", true, g.byte_cap);
        try fp.value("s1.gkr.fixed_count", true, g.fixed_count);
        try fp.value("s1.gkr.constants", true, g.constants);
        try fp.value("s1.gkr.instances", true, g.instances);
        try fp.value("s1.gkr.order", true, g.order);
        try fp.value("s1.gkr.logs", true, g.logs);
        try fp.value("s1.gkr.instance_mixes", true, g.instance_mixes);
        try fp.value("s1.gkr.child_steps", true, g.child_steps);
        try fp.value("s1.gkr.staged_words", true, g.staged_words);
        try fp.value("s1.gkr.item_offsets", true, g.item_offsets);
        try fp.value("s1.gkr.twiddle_words", true, g.twiddle_words);
        try fp.value("s1.gkr.host_column_words", true, g.host_column_words);
        try fp.value("s1.gkr.fields", true, g.fields);
        {
            var k = FC.Key.init("s1.gkr.source");
            const s = &g.source;
            for (s.columns) |c| k.int(c.log_size);
            k.value(s.groups);
            k.value(s.offsets);
            k.int(s.fixed_count);
            k.int(s.cells);
            k.int(s.max_log);
            for (s.items) |it| {
                k.int(it.kernel);
                k.value(it.offsets);
                k.int(it.log);
                k.int(it.terms);
                k.int(it.lanes);
                k.int(it.facts);
            }
            try fp.put("s1.gkr.source", true, &k);
            var p = FC.Key.init("s1.request.publics");
            for (s.items) |it| p.value(it.public);
            try fp.put("s1.request.publics", false, &p);
        }
        try fp.value("s1.request.prefix", false, g.prefix);
        try fp.value("s1.instances", true, cl.instances);
        try fp.value("s1.fixed_shapes", true, cl.fixed_shapes);
        try fp.words("s1.fixed_host", true, cl.fixed_storage);
        try fp.value("s1.fixed_root", true, cl.fixed_root);
        try fp.value("s1.main_shapes", true, cl.main_shapes);
        try fp.value("s1.beta", true, cl.beta);
        try fp.value("s1.capture_words", true, cl.capture_words);
        try fp.value("s1.binding.row_logs", true, cl.bind_plan.row_logs);
        try fp.value("s1.binding.lane_logs", true, cl.bind_plan.lane_logs);
        try fp.value("s1.binding.offsets", true, cl.bind_plan.offsets);
        try fp.value("s1.binding.output_words", true, cl.bind_plan.output_words);
    }
    fn addStage2(fp: *Fingerprint, cl: *const Class) !void {
        const a = fp.a;
        // ---- Stage 2: framing ----
        try fp.value("s2.geometry", true, [_]u32{ cl.comp_log, cl.split, cl.total, cl.mask_log, cl.claim_count });
        {
            var k = FC.Key.init("s2.slots");
            for (cl.slots) |s| {
                k.int(s.log);
                k.int(s.inter_offset);
                k.value(s.binding_index);
                if (s.global) |gl| {
                    k.int(1);
                    k.int(gl.claim_offset);
                    k.int(gl.fixed_first);
                    k.int(gl.main_first);
                } else k.int(0);
            }
            try fp.put("s2.slots", true, &k);
        }
        {
            var k = FC.Key.init("s2.gplans.geometry");
            for (cl.gplans.items) |p| {
                k.bytes(&p.entry.artifact.program.identity);
                k.int(p.log);
                k.int(p.rows);
                k.int(p.fixed_count);
                k.int(p.main_count);
                k.value(p.groups);
                k.int(p.group_count);
                k.int(p.pairs);
                k.int(p.width);
                k.int(p.scan_words);
            }
            try fp.put("s2.gplans.geometry", true, &k);
        }
        // One (class, request) pair per global plan, in slot order.
        for (cl.gplans.items, cl.global_patches) |p, set| {
            const masked = try maskOf(a, set);
            defer a.free(masked);
            try fp.maskedWords("s2.gplan.parameters", "s2.request.gplan.parameters", p.parameters, masked);
        }
        try fp.value("s2.inter_shapes", true, cl.inter_shapes);
        try fp.value("s2.inter_logs", true, cl.inter_logs);
        {
            const cp = &cl.comp_plan.?;
            try fp.value("s2.composition.key", true, cp.key);
            const masked = try maskOf(a, cl.comp_patches);
            defer a.free(masked);
            try fp.maskedWords("s2.composition.table", "s2.request.composition.table", cp.table, masked);
        }
        {
            const px = &cl.pcs.?;
            var k = FC.Key.init("s2.pcs.sections");
            for (px.prepared.section_storage, 0..) |s, i| if (i != 15) k.bytes(std.mem.sliceAsBytes(s));
            try fp.put("s2.pcs.sections", true, &k);
            try fp.words("s2.request.pcs.section15", false, px.prepared.section_storage[15]);
            try fp.value("s2.request.pcs.scope", false, px.prepared.scope);
            var pl = FC.Key.init("s2.pcs.plan");
            pl.bytes(std.mem.asBytes(&px.plan));
            try fp.put("s2.pcs.plan", true, &pl);
            try fp.value("s2.pcs.base_shift", true, [2]u32{ px.base_shift.x.v, px.base_shift.y.v });
            var cols = FC.Key.init("s2.pcs.columns");
            for (cl.pristine_columns) |c| cols.bytes(std.mem.asBytes(&c));
            try fp.put("s2.pcs.columns", true, &cols);
            var sh = FC.Key.init("s2.pcs.shape");
            for (px.prepared.metadata.shape.trees) |t| {
                sh.value(t.coefficient_logs);
                sh.value(t.sorted_to_original);
                sh.value(t.sample_counts);
            }
            try fp.put("s2.pcs.shape", true, &sh);
        }
        try fp.words("s2.program", true, cl.program.?.words);
        try fp.value("s2.program.max_encoded_bytes", true, cl.program.?.max_encoded_bytes);
        try fp.value("s2.fixed_offsets", true, cl.fixed_offsets);
        try fp.value("s2.main_offsets", true, cl.main_offsets);
        try fp.value("s2.main_words", true, cl.main_words);
        {
            var k = FC.Key.init("s2.patches");
            for (cl.global_patches) |p| hashPatchSet(&k, p);
            hashPatchSet(&k, cl.comp_patches);
            k.int(cl.semantic_words);
            try fp.put("s2.patches", true, &k);
        }
    }
    pub fn get(self: *const Fingerprint, name: []const u8, nth: usize) ?Field {
        var seen: usize = 0;
        for (self.fields.items) |f| if (std.mem.eql(u8, f.name, name)) {
            if (seen == nth) return f;
            seen += 1;
        };
        return null;
    }
};

fn hashPatchSet(k: *FC.Key, set: S2.PatchSet) void {
    inline for (S2.sources) |source| {
        const p = set.get(source);
        k.value(@as([]const u32, p.dst));
        k.value(@as([]const u32, p.index));
    }
}

/// Every patched dst offset of a patch set (sorted, unique).
pub fn maskOf(a: std.mem.Allocator, set: S2.PatchSet) ![]u32 {
    var out: std.ArrayListUnmanaged(u32) = .empty;
    errdefer out.deinit(a);
    inline for (S2.sources) |source| try out.appendSlice(a, set.get(source).dst);
    std.mem.sort(u32, out.items, {}, std.sort.asc(u32));
    return out.toOwnedSlice(a);
}

pub const Mismatch = struct { name: []const u8, ordinal: usize };

/// Class fields of `x` and `y` in order; the first `out.len` differences.
/// `y` may be a prefix (a Stage-1-only fingerprint): only its fields compare.
pub fn compare(x: *const Fingerprint, y: *const Fingerprint, out: []Mismatch) !usize {
    if (x.fields.items.len < y.fields.items.len) return error.GnShapeFingerprintShape;
    var n: usize = 0;
    for (x.fields.items[0..y.fields.items.len], y.fields.items, 0..) |p, q, i| {
        if (!std.mem.eql(u8, p.name, q.name) or p.class != q.class) return error.GnShapeFingerprintShape;
        if (!p.class or std.mem.eql(u8, &p.digest, &q.digest)) continue;
        if (n < out.len) out[n] = .{ .name = p.name, .ordinal = i };
        n += 1;
    }
    return n;
}

// ---------------------------------------------------------------------------
// From the legacy per-segment inputs (recorder side: the hybrid's sources)
// ---------------------------------------------------------------------------

/// The legacy Stage-1 class of one segment, from exactly the request the
/// hybrid prove() received (native_hybrid.zig l.589: NG.Plan.init on the
/// request's scope, instances, native source, FIXED host and MAIN device
/// columns, byte cap; NB.Plan on its instances and traversal layers). Only
/// the Stage-1 fields are set; fingerprint it with `Fingerprint.ofStage1`.
pub fn stage1FromNumerical(env: *const Env, request: Child.NumericalStage.Request) !*Class {
    const a = env.a;
    const native = request.native_source orelse return error.NativeGkrSourceRequired;
    const cl = try a.create(Class);
    errdefer a.destroy(cl);
    cl.* = .{ .a = a, .gkr = undefined, .instances = &.{}, .fixed_shapes = &.{}, .main_shapes = &.{}, .fixed_host = &.{}, .fixed_storage = &.{}, .fixed_root = request.scope.fixed, .beta = env.config.fri_config.log_blowup_factor, .comp_log = 0, .split = 0, .total = 0, .mask_log = 0, .claim_count = 0, .bind_plan = undefined };
    cl.instances = try a.dupe(NG.Instance, request.instances);
    errdefer a.free(cl.instances);
    var words: usize = 0;
    for (request.native_fixed_columns) |c| {
        if (c.device != null) return error.HybridExpectsHostFixed;
        words += c.coefficients.len;
    }
    cl.fixed_storage = try a.alloc(u32, words);
    errdefer a.free(cl.fixed_storage);
    cl.fixed_host = try a.alloc([]const u32, request.native_fixed_columns.len);
    errdefer a.free(cl.fixed_host);
    cl.fixed_shapes = try a.alloc(NC.Shape, request.native_fixed_columns.len);
    errdefer a.free(cl.fixed_shapes);
    var at: usize = 0;
    for (request.native_fixed_columns, cl.fixed_host, cl.fixed_shapes) |c, *h, *sh| {
        const w = coefficientWords(c.coefficients);
        @memcpy(cl.fixed_storage[at..][0..w.len], w);
        h.* = cl.fixed_storage[at..][0..w.len];
        sh.* = .{ .log_size = c.log_size, .encoding = .coefficients };
        at += w.len;
    }
    cl.main_shapes = try a.alloc(NC.Shape, request.native_main_columns.len);
    errdefer a.free(cl.main_shapes);
    for (request.native_main_columns, cl.main_shapes) |c, *sh| sh.* = .{ .log_size = c.log_size, .encoding = .evaluations };
    // The legacy call, on the class's own FIXED copy (the plan keeps views)
    // and the legacy request's MAIN device columns (shape only).
    const fixed_cols = try a.alloc(DP.Column, cl.fixed_host.len);
    defer a.free(fixed_cols);
    for (fixed_cols, cl.fixed_host, cl.fixed_shapes) |*c, h, sh| c.* = .{ .log_size = sh.log_size, .coefficients = @as([*]const M, @ptrCast(h.ptr))[0..h.len] };
    cl.gkr = try NG.Plan.init(a, env.catalogue, request.scope, request.instances, native, fixed_cols, request.native_main_columns, request.byte_cap, 0);
    errdefer cl.gkr.deinit();
    cl.bind_plan = try NB.Plan.init(a, request.instances, cl.gkr.traversal.layers);
    // capture_words: not a legacy input (the ring is GPU-native only); the
    // caller sets it from the class rows when comparing.
    return cl;
}

/// The inputs the hybrid had for one segment: the stage-two CpuWorker +
/// pending manifest (FIXED from the worker scheme, MAIN logs from the setup).
/// `fixed` must stay valid for the call (the worker's FIXED tree).
pub fn inputsFromWorker(a: std.mem.Allocator, worker: *const CW.CpuWorker, pending: *const Manifest.PendingManifest, ordinal: u32, fixed: []DP.Column, native: *const NativeSources) !struct { inputs: Inputs, main_logs: []u32 } {
    const fixed_coefficients = worker.scheme.trees.items[0].coefficients orelse return error.DeviceGkrCoefficientsRequired;
    if (fixed.len != fixed_coefficients.len) return error.GnShapeFixedShape;
    for (fixed_coefficients, fixed) |c, *d| d.* = .{ .log_size = c.logSize(), .coefficients = c.coefficients() };
    const main_logs = try worker.setup.logs(a, 1);
    const local = &(pending.entries[ordinal].local orelse return error.WideCpuLocalRequired);
    return .{ .main_logs = main_logs, .inputs = .{
        .ordinal = ordinal,
        .setup = worker.setup,
        .request = worker.request,
        .first = worker.first,
        .fixed = fixed,
        .fixed_root = worker.expected.fixed,
        .main_logs = main_logs,
        .instances = worker.instances,
        .native = native,
        .statement = worker.expected.statement,
        .main_root = worker.preparedMainRoot() catch @splat(0),
        .pending = local,
        .shared = pending.shared,
    } };
}

// ---------------------------------------------------------------------------
// From a warm capture (install; no CpuWorker)
// ---------------------------------------------------------------------------

const Capture = CPU.rv64_ethereum_capture;
const Plan = CPU.rv64_ethereum_plan;
const Image = CPU.rv64_expected_image;
const Keys = CPU.rv64_ethereum_keys.Owner;
const FixedAuthority = CPU.rv64_gkr_fixed_authority;
const FixedSet = CPU.rv64_gkr_fixed_authority_set.Set;
const Coordinator = CPU.rv64_gkr_coordinator;
const Execution = CPU.rv64_gkr_execution;
const LocalRoster = CPU.rv64_gkr_local_roster;
const Suite = CPU.rv64_pcs_suite.Suite;
const RequestConfig = CPU.rv64_ethereum_request.Config;

/// One block's install-time inventory: gkr_main's declarations -> keys ->
/// FIXED authority -> request views, for the block's warm capture (the
/// same calls, the same order; truths are not needed for the native classes).
pub const Inventory = struct {
    a: std.mem.Allocator,
    keys: Keys,
    fixed_cache: FixedAuthority.Fixed.Cache,
    fixed_set: FixedSet,
    requests: []Request,
    first_ids: []FirstIds,

    pub fn init(a: std.mem.Allocator, capture: G.CaptureEnd, config: Config, fixed_setup_bytes: usize) !*Inventory {
        const owner: *const Capture.Owner = @ptrCast(@alignCast(capture.owner));
        const image: *const Image.Owner = @ptrCast(@alignCast(capture.image));
        const rconfig: *const RequestConfig = @ptrCast(@alignCast(capture.config));
        const layout = Plan.CpuLayout.forGkrProfile(rconfig.execution_profile);
        const cpu = try Plan.cpus(a, owner, layout);
        defer a.free(cpu);
        const strict = (try CPU.rv64_native_policy.current()).strictRoster();
        const canon_flag = if (std.posix.getenv("STWO_RV64_CANON_RUNGS")) |flag| std.mem.eql(u8, flag, "1") else false;
        if (strict or canon_flag) {
            const classes = try a.alloc(Plan.CanonClass, cpu.len);
            defer a.free(classes);
            try Plan.canonicalCpusMode(owner, layout, cpu, CPU.rv64_ethereum_canon_rungs, classes, strict);
        }
        const self = try a.create(Inventory);
        errdefer a.destroy(self);
        self.a = a;
        self.keys = try Keys.initWithSuiteAndCaches(a, image, cpu, &.{}, true, Suite.experimentalFold4(), .{});
        errdefer self.keys.deinit();
        self.fixed_cache = try FixedAuthority.Fixed.Cache.init(a, fixed_setup_bytes);
        errdefer self.fixed_cache.deinit();
        self.fixed_set = try FixedSet.init(a, &self.fixed_cache, self.keys.cpus, self.keys.truths, config);
        errdefer self.fixed_set.deinit();
        const n = owner.native.items.len;
        if (n != self.keys.cpus.len or n != capture.segments) return error.GnShapeInventoryShape;
        self.requests = try a.alloc(Request, n);
        errdefer a.free(self.requests);
        for (self.requests, 0..) |*r, i| {
            r.* = try Coordinator.requestView(owner.native.items, &owner.advice, i);
            try Coordinator.routeDword(r, self.keys.cpus[i].bridges, owner.advice.events[i]);
        }
        try Coordinator.assignSpongeIds(self.requests);
        self.first_ids = try a.alloc(FirstIds, n);
        errdefer a.free(self.first_ids);
        // Execution.Inventory's first ids: per family, 1 + the calls before.
        var next: [@typeInfo(FirstIds).array.len]u64 = @splat(1);
        for (self.requests, self.first_ids) |r, *f| {
            for (next, f) |id, *out| out.* = std.math.cast(u32, id) orelse return error.GlobalGkrManifestOrdinal;
            for (&next, r.calls) |*id, calls| id.* = try std.math.add(u64, id.*, calls);
        }
        return self;
    }
    pub fn deinit(self: *Inventory) void {
        const a = self.a;
        a.free(self.first_ids);
        a.free(self.requests);
        self.fixed_set.deinit();
        self.fixed_cache.deinit();
        self.keys.deinit();
        a.destroy(self);
    }
    pub fn count(self: *const Inventory) usize {
        return self.requests.len;
    }
};

/// Build segment `i` of an inventory (FIXED via the authority binding into a
/// throwaway scheme, exactly CpuWorker.prepareMain's append).
pub fn buildFromInventory(env: *const Env, inv: *const Inventory, i: usize) !*Class {
    const a = env.a;
    const setup = inv.keys.cpus[i];
    const binding = inv.fixed_set.at(i);
    var scheme = try WP.Prover.init(a, env.config);
    defer scheme.deinit(a);
    scheme.setCompactPolynomialStorage(1);
    const expected = try Execution.localCpuExpected(a, setup, inv.requests[i], @intCast(i), inv.first_ids[i], env.config, binding);
    defer a.free(expected.local_instances.?);
    var ch = binding.begin(env.config, expected);
    try binding.append(a, &setup.key, expected.fixed, &scheme, &ch);
    const coefficients = scheme.trees.items[0].coefficients orelse return error.DeviceGkrCoefficientsRequired;
    const fixed = try a.alloc(DP.Column, coefficients.len);
    defer a.free(fixed);
    for (coefficients, fixed) |c, *d| d.* = .{ .log_size = c.logSize(), .coefficients = c.coefficients() };
    const main_logs = try setup.logs(a, 1);
    defer a.free(main_logs);
    const instances = try LocalRoster.fromSetup(a, setup);
    defer a.free(instances);
    var native = stubSource(setup, inv.requests[i]);
    var pending = try placeholderPending(a, instances);
    defer pending.deinit(a);
    return build(env, .{
        .ordinal = @intCast(i),
        .setup = setup,
        .request = inv.requests[i],
        .first = inv.first_ids[i],
        .fixed = fixed,
        .fixed_root = expected.fixed,
        .main_logs = main_logs,
        .instances = instances,
        .native = &native,
        .pending = &pending,
        .shared = placeholderShared(),
    });
}

// ---------------------------------------------------------------------------
// The shape hook: install-time class mix per block
// ---------------------------------------------------------------------------

pub const BlockRecord = struct {
    block: u64,
    keys: []G.ClassKey,
    rows: []u64,
    /// Host wall of the block's class build at install [M].
    build_ns: u64,
    miss: bool,
};

/// The native factory's install-time class builder. Owns every class it
/// built; registers each class ONCE with the Stage-1 registry and the
/// Stage-2 factory (when bound). `shape` is NativeFactory.shape.
pub const Builder = struct {
    a: std.mem.Allocator,
    env: Env,
    registry: ?*S1.Registry = null,
    factory: ?*S2.Factory = null,
    /// Stage-2 instances per class (Factory.instances_per_device * GPUs).
    framing_instances: usize = 2,
    fixed_setup_bytes: usize = 4 << 30,
    mutex: std.Thread.Mutex = .{},
    classes: std.AutoArrayHashMapUnmanaged(G.ClassKey, *Class) = .empty,
    /// Extra Stage-2 framing instances (pool members beyond the prototype).
    extra: std.ArrayListUnmanaged(*S2.ClassFraming) = .empty,
    blocks: std.ArrayListUnmanaged(BlockRecord) = .empty,
    misses: u64 = 0,

    pub fn deinit(self: *Builder) void {
        for (self.blocks.items) |b| {
            self.a.free(b.keys);
            self.a.free(b.rows);
        }
        self.blocks.deinit(self.a);
        for (self.extra.items) |f| self.a.destroy(f);
        self.extra.deinit(self.a);
        for (self.classes.values()) |c| c.deinit();
        self.classes.deinit(self.a);
    }

    /// ND.Native.shape_hooks of this builder.
    pub fn hooks(self: *Builder) ND.ShapeHooks {
        return .{ .ctx = self, .shape = hShape, .class_of = hClassOf };
    }
    fn of(raw: *anyopaque) *Builder {
        return @ptrCast(@alignCast(raw));
    }
    fn hShape(raw: *anyopaque, a: std.mem.Allocator, wb: G.WarmBlock) anyerror![]u64 {
        return of(raw).shape(a, wb);
    }
    fn hClassOf(raw: *anyopaque, block: ?u64, segment: u32, rows: u64) anyerror!G.ClassKey {
        return of(raw).classOf(block, segment, rows);
    }

    /// NativeFactory.shape: build (or reuse) every segment class of the
    /// block from its warm capture, register them, return the segment rows.
    pub fn shape(self: *Builder, a: std.mem.Allocator, wb: G.WarmBlock) ![]u64 {
        const rec = try self.buildBlock(wb, false);
        return a.dupe(u64, rec.rows);
    }

    /// Class miss on a new block after install: the same build on the miss
    /// path, receipted (`misses`, BlockRecord.miss). Classes already known
    /// are reused; new ones are returned for the factory's device warm.
    pub fn missBlock(self: *Builder, wb: G.WarmBlock) !BlockRecord {
        return self.buildBlock(wb, true);
    }

    fn buildBlock(self: *Builder, wb: G.WarmBlock, miss: bool) !BlockRecord {
        var timer = try std.time.Timer.start();
        for (self.blocks.items) |b| if (b.block == wb.block) return b;
        const inv = try Inventory.init(self.a, wb.capture, self.env.config, self.fixed_setup_bytes);
        defer inv.deinit();
        const n = inv.count();
        const keys = try self.a.alloc(G.ClassKey, n);
        errdefer self.a.free(keys);
        const rows = try self.a.alloc(u64, n);
        errdefer self.a.free(rows);
        for (0..n) |i| {
            const cl = try buildFromInventory(&self.env, inv, i);
            var owned = true;
            errdefer if (owned) cl.deinit();
            keys[i] = cl.key;
            rows[i] = cl.rows;
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.classes.get(cl.key)) |_| {
                cl.deinit();
                owned = false;
                continue;
            }
            try self.classes.put(self.a, cl.key, cl);
            owned = false;
            try self.registerClass(cl, miss);
        }
        const rec = BlockRecord{ .block = wb.block, .keys = keys, .rows = rows, .build_ns = timer.read(), .miss = miss };
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.blocks.append(self.a, rec);
        if (miss) self.misses += 1;
        return rec;
    }

    fn registerClass(self: *Builder, cl: *Class, miss: bool) !void {
        if (self.registry) |r| {
            // Registry.by_rows is keyed by rows only: classes are resolved
            // through `classOf` (block, segment) here, so the registry gets
            // a per-class token instead of the (ambiguous) row count.
            r.register(cl.spec(), rowsToken(cl.key)) catch |err| if (!(miss and err == error.GpuNativeClassBuildOnRequestPath)) return err;
        }
        if (self.factory) |f| {
            try f.register(&cl.framing.?);
            // Pool members beyond the prototype (Stage2Job leases one each).
            for (1..self.framing_instances) |_| {
                const copy = try self.a.create(S2.ClassFraming);
                errdefer self.a.destroy(copy);
                copy.* = cl.framing.?;
                try f.register(copy);
                try self.extra.append(self.a, copy);
            }
        }
    }

    /// Class of `segment` (rows checked). With the block (preferred), exact;
    /// without, the unique class of (segment, rows) over every warmed block.
    pub fn classOf(self: *Builder, block: ?u64, segment: u32, rows: u64) !G.ClassKey {
        self.mutex.lock();
        defer self.mutex.unlock();
        var found: ?G.ClassKey = null;
        for (self.blocks.items) |b| {
            if (block) |want| if (b.block != want) continue;
            if (segment >= b.keys.len or b.rows[segment] != rows) continue;
            if (found) |k| {
                if (!std.mem.eql(u8, &k, &b.keys[segment])) return error.GnShapeClassAmbiguous;
            } else found = b.keys[segment];
        }
        return found orelse error.GpuNativeClassNotWarmed;
    }
    pub fn class(self: *Builder, key: G.ClassKey) ?*Class {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.classes.get(key);
    }
};

/// The Stage-1 registry's row token of a class (see registerClass).
pub fn rowsToken(key: G.ClassKey) u64 {
    return std.mem.readInt(u64, key[0..8], .little) | (@as(u64, 1) << 63);
}

//! M8 GPU-native install-time native class builder (stream gn-shape;
//! rv64-m8-gpu-native.md §3.1, §3.2, inventory H4/H9; contract gpu_native.zig
//! NativeFactory.shape).
//!
//! The retired native hybrid path built, PER SEGMENT OF EVERY
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
//! after the registry sealed, `Builder.missBlock` (or `shape`) builds the
//! block's classes on the miss path, reopens the registry + class cache,
//! warms the new classes on host and device (WarmJob per class and GPU) and
//! reseals, receipted (`misses`, `missed_classes`, BlockRecord) - a new
//! block never fails closed for lack of a warmed class.
const ProductCPU = @import("ethereum_cpu_component");
const ND = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device;
const FC = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_framing_cache;
const WP = CPU.rv64_gkr_worker_protocol;
const M = core.fields.m31.M31;
const fillFelts = @import("native_class_inputs.zig").fillFelts;
const hashPatchSet = @import("native_class_fingerprint.zig").hashPatchSet;
const Capture = @import("native_class_inventory.zig").Capture;
const Plan = @import("native_class_inventory.zig").Plan;
const Image = @import("native_class_inventory.zig").Image;
const Keys = @import("native_class_inventory.zig").Keys;
const FixedAuthority = @import("native_class_inventory.zig").FixedAuthority;
const FixedSet = @import("native_class_inventory.zig").FixedSet;
const Coordinator = @import("native_class_inventory.zig").Coordinator;
const Execution = @import("native_class_inventory.zig").Execution;
const LocalRoster = @import("native_class_inventory.zig").LocalRoster;
const Suite = @import("native_class_inventory.zig").Suite;
const RequestConfig = @import("native_class_inventory.zig").RequestConfig;
const std = @import("std");
const Semantic = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_semantic;
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_riscv_cpu_integration");
const G = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.gpu_native;
const S1 = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device_stage1;
const S2 = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device_stage2;
const NG = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_gkr;
const NB = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_binding;
const NC = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_commit;
const NGl = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_global;
const NP = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_pcs;
const NComp = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_composition;
const NE = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_encode;
const Sources = @import("stwo_riscv_cuda_integration").rv64.execution.source.gkr_sources;
const JP = @import("stwo_riscv_cuda_integration").rv64.execution.composition.joined_parameters;

const CW = CPU.rv64_gkr_cpu_worker;
const Components = CPU.rv64_gkr_cpu_components;
const Child = CPU.rv64_gkr_child;
const Manifest = CPU.rv64_gkr_manifest;
const DP = CPU.rv64_device_pcs;
const DG = CW.DeviceGlobal;
const O = core.fields.om31.OM31;
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
    oods: ?*const fn (*const anyopaque, std.mem.Allocator, *const NComp.Plan, []const []const u32, u32) anyerror![]u32 = null,
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
    /// Stage-2 framing instances per class (prototype + replicas; Builder
    /// sets it from Builder.framing_instances).
    framing_instances: usize = 1,
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
pub const stubSource = @import("native_class_inputs.zig").stubSource;
pub const placeholderPending = @import("native_class_inputs.zig").placeholderPending;
pub const placeholderShared = @import("native_class_inputs.zig").placeholderShared;
const coefficientWords = @import("native_class_fingerprint.zig").coefficientWords;

// ---------------------------------------------------------------------------
// The class (owned; Spec + ClassFraming views borrow it)
// ---------------------------------------------------------------------------

pub const Class = struct {
    a: std.mem.Allocator,
    key: G.ClassKey = @splat(0),
    rows: u64 = 0,
    /// Host wall of this class's build at install, and of it the setup keys
    /// + FIXED authority (CPU FIXED commit) [M].
    build_ns: u64 = 0,
    setup_ns: u64 = 0,
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
    slots: []NGl.Slot = &.{},
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
    oods_program: []u32 = &.{},
    bind_plan: NB.Plan,
    fixed_offsets: []usize = &.{},
    fixed_words: usize = 0,
    main_offsets: []usize = &.{},
    main_words: usize = 0,
    global_patches: []S2.PatchSet = &.{},
    comp_patches: S2.PatchSet = .{},
    semantic_words: usize = 0,
    /// RAM boundary claim slots of the class (Components.Plan core slots
    /// with role initial / terminal: their claim_offset), the device
    /// `public_claims` check's boundary relations (cpu_worker.publicClaims).
    initial_claim: ?u32 = null,
    terminal_claim: ?u32 = null,
    framing: ?S2.ClassFraming = null,
    /// Extra Stage-2 framing instances (Factory pool members beyond this
    /// prototype). Each owns its Stage-2 mutable state (INTER CommitPlan,
    /// composition Plan, PcsJob, global plans: Stage2Job.stage/enqueue
    /// write per-job state into them, so pool instances must not share
    /// them); its Stage-1 fields are borrowed from `proto`.
    replicas: []*Class = &.{},
    /// Set on a replica: the prototype whose Stage-1 fields it borrows.
    proto: ?*const Class = null,
    /// Registration state (Builder.registerClass is idempotent, so a block
    /// whose registration or miss-path warm failed can be retried).
    s1_registered: bool = false,
    s2_registered: usize = 0,
    /// Request values in flattened role-local patch order, excluded from key.
    public_values: []u32 = &.{},

    pub fn deinit(self: *Class) void {
        const a = self.a;
        for (self.replicas) |r| r.deinit();
        a.free(self.replicas);
        self.deinitStage2();
        if (self.proto == null) {
            a.free(self.main_offsets);
            a.free(self.fixed_offsets);
            self.bind_plan.deinit();
            a.free(self.fixed_storage);
            a.free(self.fixed_host);
            a.free(self.main_shapes);
            a.free(self.fixed_shapes);
            a.free(self.instances);
            self.gkr.deinit();
        }
        a.destroy(self);
    }
    /// Releases the Stage-2 fields (each empty / null when unbuilt).
    fn deinitStage2(self: *Class) void {
        const a = self.a;
        a.free(self.public_values);
        for (self.global_patches) |*p| p.deinit(a);
        a.free(self.global_patches);
        self.comp_patches.deinit(a);
        if (self.program) |*p| p.deinit();
        a.free(self.oods_program);
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
    }
    /// Every Stage-2 field empty (deinitStage2-safe), before buildStage2.
    fn resetStage2(self: *Class) void {
        self.public_values = &.{};
        self.slots = &.{};
        self.gplans = .empty;
        self.gslots = &.{};
        self.inter_shapes = &.{};
        self.inter_logs = &.{};
        self.inter_plan = null;
        self.comp_plan = null;
        self.role_slots = &.{};
        self.pcs = null;
        self.pristine_columns = &.{};
        self.program = null;
        self.oods_program = &.{};
        self.global_patches = &.{};
        self.comp_patches = .{};
        self.semantic_words = 0;
        self.initial_claim = null;
        self.terminal_claim = null;
        self.framing = null;
    }
    /// The prototype plus its replicas: the Stage-2 framing instances.
    pub fn framingInstances(self: *const Class) usize {
        return 1 + self.replicas.len;
    }
    pub fn framingInstance(self: *Class, i: usize) *S2.ClassFraming {
        return if (i == 0) &self.framing.? else &self.replicas[i - 1].framing.?;
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
        return S2.framingKey(key);
    }
};

/// Stage 1 of `build`: the hybrid prove()'s plan construction, verbatim
/// (NG.Plan.init on the segment's FIXED host / MAIN shapes; NB.Plan). The
/// plan keeps views of its host FIXED columns (staged by the GKR job), so it
/// is built on the class's OWN copy (`fixed_storage`), never on the
/// capture-side lease.
const buildStage1 = @import("native_class_inputs.zig").buildStage1;

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
    cl.resetStage2();
    cl.replicas = &.{};
    cl.proto = null;
    cl.s1_registered = false;
    cl.s2_registered = 0;
    cl.key = @splat(0);
    cl.build_ns = 0;
    cl.setup_ns = 0;
    // Stage-1 parts are released by the errdefers above.
    errdefer cl.deinitStage2();
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
    // RAM boundary relations of the device public_claims check (exactly
    // the slots cpu_worker.publicClaims checks against the request memory).
    for (plan.slots) |slot| switch (slot.origin) {
        .core => |role| if (role == .initial or role == .terminal) {
            const at: *?u32 = if (role == .initial) &cl.initial_claim else &cl.terminal_claim;
            if (at.* != null) return error.GnShapeBoundaryClaimTwice;
            at.* = std.math.cast(u32, slot.claim_offset) orelse return error.GnShapeBoundaryClaimTwice;
        },
        else => {},
    };
    cl.split = @intCast(split);
    cl.total = @intCast(total);
    cl.mask_log = @intCast(mask_log);

    // ---- hybrid buildFraming ----
    cl.slots = try a.alloc(NGl.Slot, plan.slots.len);
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
    var sample_counts: [4][]const u32 = undefined;
    for (cl.pcs.?.prepared.metadata.shape.trees, &sample_counts) |tree, *counts| counts.* = tree.sample_counts;
    const build_oods = env.composition.oods orelse return error.NativeStage2OodsProgramMissing;
    cl.oods_program = try build_oods(env.composition.ctx, a, comp_plan, &sample_counts, cl.mask_log);
    try S2.NO.validate(cl.oods_program);
    cl.global_patches = try a.alloc(S2.PatchSet, n_globals);
    for (cl.global_patches) |*p| p.* = .{};
    for (cl.gslots, cl.global_patches) |slots, *ps| ps.* = try patchSet(a, &.{.{ .slots = slots, .base = 0 }}, &.{});
    // Composition: every role's parameter slots at its table offset, and
    // every hc role's rows from the semantic handoff (after the namespace felts).
    var groups: std.ArrayListUnmanaged(SlotGroup) = .empty;
    defer groups.deinit(a);
    var hc: std.ArrayListUnmanaged(HcRun) = .empty;
    defer hc.deinit(a);
    for (comp_plan.roles, cl.role_slots, plan.slots) |r, slots, slot| {
        const binding_base: ?u32 = if (slot.binding_index) |i| @intCast((try Semantic.instanceOffset(cl.bind_plan.row_logs, i)) / 8) else null;
        try groups.append(a, .{ .slots = slots, .base = @intCast(r.t_params), .binding_base = binding_base });
        if (r.spec.aux == .hc) {
            const felts: u32 = @intCast(r.spec.hc.len / 8);
            try hc.append(a, .{ .dst = @intCast(r.t_hc), .first = (binding_base orelse return error.NativeSemanticInstance) + 260, .felts = felts });
        }
    }
    cl.comp_patches = try patchSet(a, groups.items, hc.items);
    cl.semantic_words = Semantic.words(cl.bind_plan.row_logs);
    var public_values: std.ArrayListUnmanaged(u32) = .empty;
    defer public_values.deinit(a);
    for (cl.global_patches, cl.gplans.items) |*p, gp| try flattenPublic(a, &p.public, gp.parameters, &public_values);
    try flattenPublic(a, &cl.comp_patches.public, cl.comp_plan.?.table, &public_values);
    cl.public_values = try public_values.toOwnedSlice(a);
}

/// Preserve each role's public parameter value even when slots share the
/// same JP name. Device patch indices address the concatenated request plane.
pub fn flattenPublic(a: std.mem.Allocator, patch: *S2.Patch, table: []const u32, values: *std.ArrayListUnmanaged(u32)) !void {
    if (patch.dst.len != patch.index.len) return error.NativeStage2PatchTable;
    for (patch.dst, patch.index) |d, *index| {
        if (@as(usize, d) + 8 > table.len) return error.NativeStage2PatchTable;
        index.* = std.math.cast(u32, values.items.len / 8) orelse return error.NativeStage2PatchTable;
        try values.appendSlice(a, table[d..][0..8]);
    }
}

pub const SlotGroup = struct { slots: []const u32, base: u32, binding_base: ?u32 = null };
pub const HcRun = struct { dst: u32, first: u32, felts: u32 };

pub fn patchSet(a: std.mem.Allocator, groups: []const SlotGroup, hc: []const HcRun) !S2.PatchSet {
    var set = S2.PatchSet{};
    errdefer set.deinit(a);
    inline for (S2.sources) |source| {
        var dst: std.ArrayListUnmanaged(u32) = .empty;
        defer dst.deinit(a);
        var index: std.ArrayListUnmanaged(u32) = .empty;
        defer index.deinit(a);
        for (groups) |g| {
            const first = index.items.len;
            try S2.appendSlots(a, &dst, &index, g.slots, g.base, source);
            if (source == .semantic) if (g.binding_base) |base| {
                for (index.items[first..]) |*i| if (i.* >= JP.local_count) {
                    i.* = base + i.* - JP.local_count;
                };
            };
        }
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
        .bind_plan = if (self.proto) |p| &p.bind_plan else &self.bind_plan,
        .global_patches = self.global_patches,
        .comp_patches = self.comp_patches,
        .semantic_words = self.semantic_words,
        .public_input_felts = @intCast(self.public_values.len / 8),
        .initial_claim = self.initial_claim,
        .terminal_claim = self.terminal_claim,
        .oods = self.oods_program,
    };
}

/// One extra Stage-2 framing instance of `proto` (see Class.replicas):
/// buildStage2 rerun on the same inputs into the replica's own state, its
/// Stage-1 fields borrowed. Fails closed unless every Stage-2 class field
/// equals the prototype's.
pub fn buildReplica(env: *const Env, in: Inputs, proto: *Class) !*Class {
    const a = env.a;
    const r = try a.create(Class);
    errdefer a.destroy(r);
    r.* = proto.*;
    r.proto = proto;
    r.replicas = &.{};
    r.s1_registered = false;
    r.s2_registered = 0;
    r.resetStage2();
    errdefer r.deinitStage2();
    try buildStage2(env, in, r);
    var fr = try @import("native_class_fingerprint.zig").stage2Fingerprint(a, r);
    defer fr.deinit();
    var fp = try @import("native_class_fingerprint.zig").stage2Fingerprint(a, proto);
    defer fp.deinit();
    var mm: [1]Mismatch = undefined;
    if (try compare(&fp, &fr, &mm) != 0) return error.GnShapeReplicaMismatch;
    r.framing = classFraming(r);
    try r.framing.?.validate();
    return r;
}

/// `n` replicas of `cl` (built in parallel; the inputs are read-only).
pub fn addReplicas(env: *const Env, in: Inputs, cl: *Class, n: usize) !void {
    if (n == 0) return;
    const a = env.a;
    const out = try a.alloc(?*Class, n);
    defer a.free(out);
    @memset(out, null);
    const errs = try a.alloc(?anyerror, n);
    defer a.free(errs);
    @memset(errs, null);
    const threads = try a.alloc(?std.Thread, n);
    defer a.free(threads);
    @memset(threads, null);
    const Run = struct {
        fn run(e: *const Env, inputs: *const Inputs, proto: *Class, slot: *?*Class, err: *?anyerror) void {
            slot.* = buildReplica(e, inputs.*, proto) catch |x| {
                err.* = x;
                return;
            };
        }
    };
    for (threads, out, errs) |*t, *o, *e| t.* = std.Thread.spawn(.{ .stack_size = 64 << 20 }, Run.run, .{ env, &in, cl, o, e }) catch blk: {
        Run.run(env, &in, cl, o, e);
        break :blk null;
    };
    for (threads) |t| if (t) |th| th.join();
    var failed: ?anyerror = null;
    for (errs) |e| if (e) |x| {
        failed = x;
        break;
    };
    if (failed) |x| {
        for (out) |o| if (o) |r| r.deinit();
        return x;
    }
    const owned = try a.alloc(*Class, n);
    for (out, owned) |o, *d| d.* = o.?;
    cl.replicas = owned;
}

// ---------------------------------------------------------------------------
// Field-by-field fingerprint (class fields vs per-request fields)
// ---------------------------------------------------------------------------

pub const Field = @import("native_class_fingerprint.zig").Field;
pub const Fingerprint = @import("native_class_fingerprint.zig").Fingerprint;
pub const maskOf = @import("native_class_fingerprint.zig").maskOf;
pub const Mismatch = @import("native_class_fingerprint.zig").Mismatch;
pub const compare = @import("native_class_fingerprint.zig").compare;
pub const stage1FromNumerical = @import("native_class_inputs.zig").stage1FromNumerical;
pub const inputsFromWorker = @import("native_class_inputs.zig").inputsFromWorker;
pub const Inventory = @import("native_class_inventory.zig").Inventory;
pub const buildFromInventory = @import("native_class_inventory.zig").buildFromInventory;
pub const BlockRecord = @import("native_class_inventory.zig").BlockRecord;
pub const Builder = @import("native_class_inventory.zig").Builder;
pub const rowsToken = @import("native_class_inventory.zig").rowsToken;

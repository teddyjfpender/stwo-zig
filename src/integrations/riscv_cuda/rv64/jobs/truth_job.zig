//! TruthJob (stream recursion, piece r-truth): a truth/service proof as two
//! api.Jobs inside the GPU's memory plan (job arena + class-persistent
//! regions), replacing the legacy truth stages behind owner callbacks and
//! their ~14.75 GB outside-arena composition lease [M]. Design:
//! rv64-m8-gpu-native.md §3.3, M8-INTERFACES "m8-gpu-r-truth".
//!
//! A truth's MAIN root is framed in the manifest digest and its stage 2
//! starts from that digest, so a truth is two jobs on the same GPU:
//!
//!   Stage1 (fills the seal barrier)
//!     compact inputs (staged) -> legacy device witness kernel -> MAIN commit
//!     -> root into the caller's root field (Exchange.truthRoot slot);
//!     verdict Check.truth_root (witness status).
//!   Stage2 (after the device seal), the legacy TruthWorker.complete order:
//!     channel from the host seed (worker_protocol.begin [+ binding])
//!     FIXED (class-persistent tree) root mixed       [appendFixed]
//!     MAIN replayed from compact inputs, root mixed  [legacy replay_main]
//!     local challenges drawn on device               [truth_challenges]
//!     shared challenges from the seal digest         [manifest.drawShared]
//!     interaction witnesses (params gathered on device)
//!     mixManifestAndClaims (digest + claims from device buffers)
//!     INTER commit, composition coefficient, composition (truth kernel),
//!     OODS + enqueue-only PCS
//!     checks: truth_status, root_match (FIXED vs class, MAIN vs stage 1),
//!     channel_order, pcs_status.
//!   device encode (gn-truth; `encode = .device`): the OODS constraint
//!     check on device (truth_oods.zig: Check.truth_oods) and the exact
//!     WP.encodePhysical bytes written on device (native_encode.zig Encoder:
//!     Check.encode_bounds, its pcs_status merged into Check.pcs_status) into
//!     the truth's request-slab encoded region. The PCS image stays in the
//!     job arena; finish reads verdict words only.
//!   finish (`encode = .host`, the r-truth path): PCS decode, the engine's
//!     OODS constraint check and WP.encodePhysical on the host. `.check`
//!     runs both and compares (parity harness).
//!
//! No value the transcript depends on reaches the host before finish.
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const Slab = @import("slab.zig");
const C = @import("native_commit.zig");
const NC = @import("native_composition.zig");
const NP = @import("native_pcs.zig");
const X = @import("truth_challenges.zig");
const I = @import("truth_interaction.zig");
const K = @import("truth_class.zig");
const TO = @import("truth_oods.zig");
const NE = @import("native_encode.zig");
const LF = @import("native_leaf_wire.zig");

// ---------------------------------------------------------------------------
// Symbols
// ---------------------------------------------------------------------------

/// rv64/truth_source.zig packets (frozen base-image ABI).
pub const KeccakPacket = extern struct { inputs: [*]const u32, main: [*]u32, chi: [*]u32, xor5: [*]u32, status: [*]u32, input_words: u64, main_words: u64, calls: u32, first_id: u32, log: u32, policy: u32 = 0 };
pub const ShaPacket = extern struct { inputs: [*]const u32, main: [*]u32, status: [*]u32, input_words: u64, main_words: u64, calls: u32, first_id: u32, log: u32, reserved: u32 = 0 };
pub const ArithPacket = extern struct { inputs: [*]const u32, main: [*]u32, byte_counts: [*]u32, status: [*]u32, input_words: u64, main_words: u64, calls: u32, first_id: u32, log: u32, reserved: u32 = 0 };
pub const SecpPacket = extern struct { inputs: [*]const u32, main: [*]u32, byte_counts: [*]u32, status: [*]u32, input_words: u64, main_words: u64, calls: u32, first_id: u32, log: u32, kind: u32 };
const KeccakFn = *const fn (*anyopaque, u32, *const KeccakPacket) callconv(.c) c_int;
const ShaFn = *const fn (*anyopaque, u32, *const ShaPacket) callconv(.c) c_int;
const ArithFn = *const fn (*anyopaque, u32, *const ArithPacket) callconv(.c) c_int;
const SecpFn = *const fn (*anyopaque, u32, *const SecpPacket) callconv(.c) c_int;
const CopyD2d = *const fn (*anyopaque, *anyopaque, *const anyopaque, usize) callconv(.c) c_int;
const Memset = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;
// NAT/rv64/jobs/truth_ops.cu
const GatherFn = *const fn (*anyopaque, u32, [*]const u32, ?[*]const u32, [*]const u32, ?[*]const u32, *const anyopaque, u32, *const [4]u32, [*]u32, [*]u32) callconv(.c) c_int;
const StatusFn = *const fn (*anyopaque, u32, [*]const u32, ?[*]const u32, ?[*]const u32, *const StatusConstants, [*]u32) callconv(.c) c_int;
const RootMatchFn = *const fn (*anyopaque, u32, [*]const u32, [*]const u32, u32, u32, [*]u32) callconv(.c) c_int;
const OrderFn = *const fn (*anyopaque, u32, [*]const u32, u32, u64, [*]u32) callconv(.c) c_int;
const PcsStatusFn = *const fn (*anyopaque, u32, [*]const u32, u64, [*]const u32, *const PcsExpect, [*]u32) callconv(.c) c_int;
// NAT/rv64/jobs/truth_oods.cu: out = the first non-accepted word of `words` (unset rejects).
const MergeFn = *const fn (*anyopaque, u32, [*]const u32, u32, u32, [*]u32) callconv(.c) c_int;

pub const StatusConstants = extern struct { n_status: u32, n_claims: u32, n_zero: u32, classic: u32, check: u32, reserved: [3]u32 = @splat(0) };
pub const PcsExpect = extern struct { header: [14]u32, header_mask: u32, trees: u32, reserved: [2]u32 = @splat(0) };
comptime {
    if (@sizeOf(StatusConstants) != 32 or @sizeOf(PcsExpect) != 72) @compileError("truth_ops ABI");
}

pub const Symbols = struct {
    keccak: ?KeccakFn,
    sha: ?ShaFn,
    arith: ?ArithFn,
    secp: ?SecpFn,
    curve: ?SecpFn,
    copy_d2d: CopyD2d,
    memset: Memset,
    commit: C.Symbols,
    composition: NC.Symbols,
    pcs: NP.Symbols,
    interaction: I.Symbols,
    gather: GatherFn,
    status: StatusFn,
    root_match: RootMatchFn,
    order: OrderFn,
    pcs_status: PcsStatusFn,
    /// gn-truth device encode (null with an addon that predates it; the
    /// `.device` / `.check` modes then refuse at init).
    oods: ?TO.Symbols = null,
    encode: ?NE.Symbols = null,
    merge: ?MergeFn = null,
    leaf: ?LF.EncodeFn = null,
    pub fn load(base: *std.DynLib, addon: *std.DynLib) !Symbols {
        return .{
            .keccak = base.lookup(KeccakFn, "stwo_rv64_keccak_witness_on"),
            .sha = base.lookup(ShaFn, "stwo_rv64_sha256_witness_on"),
            .arith = base.lookup(ArithFn, "stwo_rv64_arith256_witness_on"),
            .secp = base.lookup(SecpFn, "stwo_rv64_secp_witness_on"),
            .curve = base.lookup(SecpFn, "stwo_rv64_curve_witness_on"),
            .copy_d2d = base.lookup(CopyD2d, "stwo_exec_context_memcpy_d2d_async") orelse return error.MissingTruthJobSymbol,
            .memset = base.lookup(Memset, "stwo_exec_context_memset_async") orelse return error.MissingTruthJobSymbol,
            .commit = try C.Symbols.load(base),
            .composition = try NC.Symbols.load(base, addon),
            .pcs = try NP.Symbols.load(addon),
            .interaction = try I.Symbols.load(base),
            .gather = addon.lookup(GatherFn, "stwo_rv64_truth_params_gather_v1_on") orelse return error.MissingTruthOpsSymbol,
            .status = addon.lookup(StatusFn, "stwo_rv64_truth_status_v1_on") orelse return error.MissingTruthOpsSymbol,
            .root_match = addon.lookup(RootMatchFn, "stwo_rv64_truth_root_match_v1_on") orelse return error.MissingTruthOpsSymbol,
            .order = addon.lookup(OrderFn, "stwo_rv64_truth_channel_order_v1_on") orelse return error.MissingTruthOpsSymbol,
            .pcs_status = addon.lookup(PcsStatusFn, "stwo_rv64_truth_pcs_status_v1_on") orelse return error.MissingTruthOpsSymbol,
            .oods = TO.Symbols.load(addon) catch null,
            .encode = NE.Symbols.load(addon) catch null,
            .merge = addon.lookup(MergeFn, "stwo_rv64_truth_verdict_merge_v1_on"),
            .leaf = LF.load(addon) catch null,
        };
    }
};

const check = @import("truth_stage2_job.zig").check;
/// STWO_RV64_M8_TRUTH_TRACE=1: one line per enqueue phase (debugging only).
const trace = @import("truth_stage2_job.zig").trace;
const feltWords = @import("truth_stage2_job.zig").feltWords;

/// Where a check's verdict word lives: a request-slab status word (GPU-native
/// publication) or, when null, a word of this job's own slab (finish reads it).
pub const Verdicts = struct {
    truth_root: ?api.DeviceBuffer = null,
    truth_status: ?api.DeviceBuffer = null,
    root_match: ?api.DeviceBuffer = null,
    channel_order: ?api.DeviceBuffer = null,
    pcs_status: ?api.DeviceBuffer = null,
    truth_oods: ?api.DeviceBuffer = null,
    encode_bounds: ?api.DeviceBuffer = null,
};
/// Own (job-slab) status words of stage 2: the published checks (when no
/// request-slab word is given), then the two raw PCS words the device-encode
/// path merges into pcs_status (truth_pcs_status kernel, encoder).
pub const Own = struct {
    pub const truth_status = 0;
    pub const root_match = 1;
    pub const channel_order = 2;
    pub const pcs_status = 3;
    pub const truth_oods = 4;
    pub const encode_bounds = 5;
    pub const pcs_truth = 6;
    pub const pcs_encoder = 7;
    pub const words = 8;
};

pub const Fault = enum {
    none,
    parameter_program,
    class_root,
    stage1_root,
    absent_claim,
    channel_cursor,
    pcs_header,
    // gn-truth (device encode): one read trace sample (truth_oods), one
    // composition sample (truth_oods), an encoded region one word short
    // (encode_bounds), a noncanonical queried value (encode_bounds).
    oods_sample,
    oods_composition,
    encode_capacity,
    encode_value,
};

/// Where finish's proof bytes come from.
pub const Encode = enum {
    /// r-truth: host PCS decode + engine OODS check + WP.encodePhysical.
    host,
    /// gn-truth: device OODS check + device encoder; no host assembly.
    device,
    /// Both; finish compares device bytes / OODS values with the host's.
    check,
};

const Events = @import("../cuda_events.zig");
/// CUDA events around a job's enqueue (exec stream); read after the worker's wait.
pub const Span = struct {
    begin: ?*anyopaque = null,
    end: ?*anyopaque = null,
    gpu_ms: f32 = -1,
    fn open(self: *Span, events: ?*const Events.Api) !void {
        const ev = events orelse return;
        if (self.begin == null and ev.create(&self.begin, 0) != 0) return error.CudaTimingFailed;
        if (self.end == null and ev.create(&self.end, 0) != 0) return error.CudaTimingFailed;
    }
    fn mark(self: *Span, events: ?*const Events.Api, end: bool, stream: *anyopaque) !void {
        const ev = events orelse return;
        if (ev.record((if (end) self.end else self.begin) orelse return error.CudaTimingFailed, stream) != 0) return error.CudaTimingFailed;
    }
    fn read(self: *Span, events: ?*const Events.Api) void {
        const ev = events orelse return;
        if (self.begin == null or self.end == null or ev.elapsed(&self.gpu_ms, self.begin.?, self.end.?) != 0) self.gpu_ms = -1;
    }
    fn close(self: *Span, events: ?*const Events.Api) void {
        const ev = events orelse return;
        if (self.begin) |b| _ = ev.destroy(b);
        if (self.end) |b| _ = ev.destroy(b);
        self.begin = null;
        self.end = null;
    }
};

/// Stage-1 root publication (Exchange.truthRoot slot) once the root landed.
pub const Publish = struct {
    peer: G.PeerExchange,
    device: u32,
    slot: G.Exchange.Slot,
};

// ---------------------------------------------------------------------------
// Witness + MAIN (shared by both stages)
// ---------------------------------------------------------------------------

/// MAIN evaluation layout: MAIN columns (width x rows), then (classic) the
/// chi and xor5 multiplicity tables, ORIGINAL column order of the MAIN tree.
const mainInputs = @import("truth_stage2_job.zig").mainInputs;

const enqueueWitness = @import("truth_stage2_job.zig").enqueueWitness;

const statusVerdict = @import("truth_stage2_job.zig").statusVerdict;

/// Placeholder device inputs for `CommitPlan.stage` (every column is a device
/// view at enqueue).
const placeholders = @import("truth_stage2_job.zig").placeholders;

// ---------------------------------------------------------------------------
// Stage 1
// ---------------------------------------------------------------------------

pub const Stage1 = struct {
    a: std.mem.Allocator,
    class: *const K.Class,
    sym: *const Symbols,
    ordinal: u32,
    calls: u32,
    first_id: u32,
    /// Host compact inputs (K.packCompact); must outlive `stage`.
    compact: []const u32,
    /// Device root destination (8 words; e.g. this GPU's Exchange.truthRoot
    /// slot); null = the job slab's root field only.
    root_out: ?api.DeviceBuffer = null,
    publish: ?Publish = null,
    verdicts: Verdicts = .{},
    timing: ?*const Events.Api = null,
    span: Span = .{},
    // phase state
    main_plan: C.CommitPlan = undefined,
    plan_live: bool = false,
    staged_compact: ?api.DeviceBuffer = null,
    layout: Slab.ProofLayout = .{},
    /// finish: the job-slab copies.
    root: [8]u32 = undefined,
    verdict: u32 = G.Verdict.unset,
    /// GPU-native request: scratch stays on device; publication reads only
    /// the external request slab. Piece harnesses retain their diagnostics.
    request_slab_only: bool = false,

    pub fn init(self: *Stage1) !void {
        if (self.request_slab_only and (self.root_out == null or self.publish == null or self.verdicts.truth_root == null)) return error.TruthRequestVerdictsMissing;
        if (self.compact.len != self.class.compactWords(self.calls) or self.calls == 0) return error.TruthCompactShape;
        self.main_plan = try K.jobPlan(self.a, &self.class.main_plan);
        self.main_plan.require_warm = self.request_slab_only;
        self.plan_live = true;
        _ = try self.layout.add(.root, 0, 8);
        _ = try self.layout.add(.status, 0, 2); // [0] witness status, [1] own verdict
    }
    pub fn deinit(self: *Stage1) void {
        self.span.close(self.timing);
        if (self.plan_live) K.freeJobPlan(self.a, &self.main_plan);
        self.plan_live = false;
    }
    pub fn classKey(self: *Stage1) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-gpu-truth-stage1/v1\x00");
        h.update(&self.class.key);
        return h.finalResult();
    }
    pub fn footprint(self: *Stage1) api.Footprint {
        var fp = stage1Footprint(self.class, self.calls, if (self.request_slab_only) 0 else self.layout.words);
        if (self.request_slab_only) fp.device_words += self.layout.words;
        return fp;
    }
    pub fn stage(self: *Stage1, s: *api.Stager) !void {
        const b = try s.alloc(self.compact.len);
        try s.upload(b, self.compact);
        self.staged_compact = b;
        const inputs = try placeholders(self.a, self.class.main_logs.len);
        defer self.a.free(inputs);
        try self.main_plan.stage(s, inputs);
        try self.span.open(self.timing);
    }
    pub fn enqueue(self: *Stage1, e: *api.Enqueue) !void {
        var trace_label: [80]u8 = undefined;
        var trace_range = try e.trace(.truth_stage1, self.ordinal, &trace_label);
        defer trace_range.deinit();
        const saved = e.slab.*;
        defer e.slab.* = saved;
        if (self.request_slab_only) e.slab.* = .{ .device = try e.alloc(self.layout.words) };
        try e.slab.bind(&self.layout);
        try self.span.mark(self.timing, false, e.stream());
        const compact = self.staged_compact orelse return error.TruthJobNotStaged;
        const status = try e.slab.field(.status, 0);
        try check(self.sym.memset(e.ctx(), status.ptr, 0, 4));
        const main = try e.alloc(self.class.mainEvalWords());
        const bytes = try enqueueWitness(self.class, self.sym, e, compact, main, status.ptr, self.calls, self.first_id);
        trace("s1.witness", self.ordinal);
        const ins = try self.a.alloc(C.Input, self.class.main_logs.len);
        defer self.a.free(ins);
        try mainInputs(self.class, main, ins);
        const slab_root = try e.slab.field(.root, 0);
        const committed = try self.main_plan.enqueue(self.sym.commit, e, ins, slab_root, false);
        trace("s1.commit", self.ordinal);
        if (self.root_out) |r| try check(self.sym.copy_d2d(e.ctx(), r.ptr, slab_root.ptr, 32));
        e.free(committed.coefficients);
        if (bytes) |b| e.free(b);
        e.free(main);
        const verdict = self.verdicts.truth_root orelse try status.slice(1, 1);
        try statusVerdict(self.sym, e, try status.slice(0, 1), null, null, .{ .n_status = 1, .n_claims = 0, .n_zero = 0, .classic = 0, .check = @intFromEnum(G.Check.truth_root) }, verdict);
        if (self.publish) |p| try p.peer.publish(p.device, p.slot);
        try self.span.mark(self.timing, true, e.stream());
    }
    pub fn finish(self: *Stage1, view: api.SlabView) !void {
        self.span.read(self.timing);
        if (self.request_slab_only) return;
        @memcpy(&self.root, try Slab.read(view, .root, 0));
        const st = try Slab.read(view, .status, 0);
        if (self.verdicts.truth_root == null) {
            self.verdict = st[1];
            if (self.verdict != G.Verdict.accepted) return error.DeviceTruthWitnessRejected;
        }
    }
    pub fn abort(_: *Stage1) void {}
    pub fn job(self: *Stage1) api.Job {
        return api.Job.from(Stage1, self);
    }
};

/// Stage-1 arena words of a class (staged compact + MAIN witness + commit).
pub fn stage1Footprint(class: *const K.Class, calls: u32, slab_words: usize) api.Footprint {
    const g = 64;
    const compact = class.compactWords(calls);
    const staged = std.mem.alignForward(usize, compact, g) + class.main_plan.stagedWords(0) + 4 * g;
    const work = std.mem.alignForward(usize, class.mainEvalWords(), g) + class.main_plan.deviceWords() + 2 * g + 256;
    // MAIN logs and addressed LDE descriptors scale with the column count;
    // wide truth classes exceed the fixed small-metadata allowance alone.
    return .{ .device_words = staged + work, .staged_words = staged, .slab_words = slab_words, .pinned_words = compact + class.main_plan.stagedWords(0) + 64 * g };
}

// ---------------------------------------------------------------------------
// Stage 2
// ---------------------------------------------------------------------------

/// Status block of the stage-2 producers (truth_status inputs), in order.
pub const StatusIndex = struct {
    pub const witness = 0;
    pub const params = 1;
    pub const composition = 2;
    pub const first_role = 3;
};

pub const Stage2 = @import("truth_stage2_job.zig").Stage2;

pub fn encodeKey(c: *const K.Class) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-m8-gn-truth-encode/v1\x00");
    h.update(&c.key);
    return h.finalResult();
}

/// Staged word table offsets of a class.
const tableOf = @import("truth_stage2_job.zig").tableOf;

/// The staged words of one job (host): scripts, request span, manifest
/// header, gather programs, class FIXED root, PCS expectation.
const fillTable = @import("truth_stage2_job.zig").fillTable;

/// Stage-2 arena words of a class: staged table + plans, then the largest of
/// the five phases (witness+MAIN commit, interactions, INTER commit,
/// composition, PCS). The PCS peak is not declared by its producer; this
/// estimate [E] is replaced by the measured class peak through the memory
/// policy (Enqueue.footprint) once a receipt exists.
pub fn stage2Footprint(c: *const K.Class, calls: u32, slab_words: usize, pcs_output: usize, pcs_ingress: usize) api.Footprint {
    const g = 64;
    const al = struct {
        fn f(x: usize) usize {
            return std.mem.alignForward(usize, x, 64);
        }
    }.f;
    const t = tableOf(c);
    const staged = al(t.words) + al(c.compactWords(calls)) + c.main_plan.stagedWords(0) + c.inter_plan.stagedWords(0) + c.composition.stagedWords() + 8 * g;
    var outputs: usize = 0;
    var role_peak: usize = 0;
    for (c.roles) |r| {
        outputs += al(r.interaction.outputWords());
        role_peak = @max(role_peak, r.interaction.enqueueWords() + al(r.interaction.program.len * 8));
    }
    const main_coeffs = al(c.main_plan.coefficient_cells);
    const phase_witness = al(c.mainEvalWords()) + c.main_plan.deviceWords() + 256 + g;
    const phase_interactions = main_coeffs + outputs + role_peak;
    const phase_inter = main_coeffs + outputs + c.inter_plan.deviceWords();
    const phase_comp = main_coeffs + al(c.inter_plan.coefficient_cells) + c.composition.enqueueWords();
    const pcs_estimate = 2 * @max(c.main_plan.eval_cells, @max(c.inter_plan.eval_cells, c.fixed_plan.eval_cells)) + pcs_output;
    const phase_pcs = main_coeffs + al(c.inter_plan.coefficient_cells) + al(c.composition.coefficientWords()) + pcs_estimate;
    const small = 4 * al(feltWords(X.shared_felts)) + @import("channel.zig").state_words + 16 * g;
    // gn-truth device encode. The arena is LIFO by default (worker
    // reuse_frees off): the tree coefficients are freed before the device
    // phase but sit beneath the PCS image (allocated after them in `.device`),
    // so they stay resident under the OODS node scratch and encoder scratch.
    const phase_device = main_coeffs + al(c.inter_plan.coefficient_cells) + al(c.composition.coefficientWords()) + al(pcs_output) + al(c.oods.scratch_words) + al(NE.scratch_words) + 4 * g;
    const peak = @max(@max(@max(phase_witness, phase_interactions), phase_device), @max(@max(phase_inter, phase_comp), phase_pcs));
    return .{ .device_words = staged + peak + small, .staged_words = staged, .slab_words = slab_words, .pinned_words = pcs_ingress + c.composition.pinnedWords() + t.words + c.compactWords(calls) + c.fixed_words + 2 * (@as(usize, 1) << @intCast(c.inter_plan.eval_log)) + 64 * g };
}
/// Compact request inputs, tables, descriptors and PCS ingress only. FIXED,
/// twiddles and the OODS/encode descriptors were uploaded by truth_warm.
pub fn stage2RequestFootprint(c: *const K.Class, calls: u32, pcs_output: usize, pcs_ingress: usize) api.Footprint {
    var fp = stage2Footprint(c, calls, 0, pcs_output, pcs_ingress);
    fp.pinned_words = pcs_ingress + c.composition.table.len + tableOf(c).words + c.compactWords(calls) + 8 * (c.main_logs.len + c.inter_logs.len) + 2048;
    return fp;
}

/// The PCS output header words the class framing fixes (hybrid_pcs.decodeWords):
/// magic, version, trees.
pub fn pcsExpect(pcs: *const NP.PcsJob) PcsExpect {
    const shape = pcs.prepared.metadata.shape;
    var x = PcsExpect{ .header = @splat(0), .header_mask = 0, .trees = @intCast(shape.trees.len) };
    x.header[0] = 0x52564d4f;
    x.header[1] = 2;
    x.header[7] = @intCast(shape.trees.len);
    x.header_mask = (1 << 0) | (1 << 1) | (1 << 7);
    return x;
}

// ---------------------------------------------------------------------------
// Tests (host): contract additions and job wiring.
// ---------------------------------------------------------------------------

test "truth stage1: wide MAIN staging fits its declared pinned budget and rejects the old fixed allowance" {
    const W = @import("worker.zig");
    const Fake = @import("fake.zig");
    const a = std.testing.allocator;
    const shapes = [_]C.Shape{.{ .log_size = 3, .encoding = .evaluations }} ** 700;
    var plan = try C.CommitPlan.init(a, &shapes, 2);
    defer plan.deinit();
    // This probe runs the real Stage1.stage path without witness/proof
    // kernels. Only the class fields read by staging/footprint are needed.
    var class: K.Class = undefined;
    class.compact_words_per_call = 4;
    class.main_plan = plan;
    class.main_logs = plan.logs;
    const compact = [_]u32{ 1, 2, 3, 4 };
    const Probe = struct {
        truth: Stage1,
        budget: api.Footprint,
        pub fn classKey(_: *@This()) [32]u8 {
            return @splat(19);
        }
        pub fn footprint(self: *@This()) api.Footprint {
            return self.budget;
        }
        pub fn stage(self: *@This(), s: *api.Stager) !void {
            try self.truth.stage(s);
        }
        pub fn enqueue(_: *@This(), _: *api.Enqueue) !void {}
        pub fn finish(_: *@This(), _: api.SlabView) !void {}
        pub fn abort(_: *@This()) void {}
    };
    const Done = struct {
        event: std.Thread.ResetEvent = .{},
        result: anyerror!void = {},
        fn call(raw: *anyopaque, c: api.Completion) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.result = c.result;
            self.event.set();
        }
    };
    for ([_]bool{ true, false }) |old_budget| {
        var fp = stage1Footprint(&class, 1, 0);
        if (old_budget) fp.pinned_words = compact.len + 4096;
        const worker = try W.Worker.create(a, &Fake.ops, .{ .device = 0, .arena_words = 1 << 18, .pinned_slot_words = fp.pinned_words, .plan_from_env = false });
        defer worker.destroy();
        var probe = Probe{ .truth = .{ .a = a, .class = &class, .sym = undefined, .ordinal = 0, .calls = 1, .first_id = 1, .compact = &compact, .main_plan = plan }, .budget = fp };
        var done = Done{};
        try worker.submit(api.Job.from(Probe, &probe), .{ .ctx = &done, .done = Done.call });
        done.event.wait();
        if (old_budget) try std.testing.expectError(error.JobFootprintExceedsPinned, done.result) else try done.result;
    }
}

test "truth jobs type-check against the api" {
    _ = api.Job.from(Stage1, undefined);
    _ = api.Job.from(Stage2, undefined);
    _ = &Symbols.load;
    _ = &Stage2.assemble;
    _ = &Stage2.enqueue;
    _ = &Stage1.enqueue;
    _ = &fillTable;
    _ = &stage2Footprint;
}

test "exchange truth slots: version-2 layout unchanged without truths, dense flags with them" {
    const base = G.Exchange{ .segments = 3, .claims_per_segment = 2, .devices = 2, .capacity_segments = 4, .capacity_claims = 3 };
    var with = base;
    with.truths = 2;
    with.capacity_truths = 5;
    // Without truths every slot keeps its version-2 offset (the version-2
    // expression, spelled out).
    const v2_words = std.mem.alignForward(usize, 1 + 2 + 2 * 4, 8) + 4 * 8 + 4 * 3 * 8 + 2 * 8 + 16;
    try std.testing.expectEqual(v2_words, base.words());
    try std.testing.expectError(error.GpuNativeExchangeSlot, base.truthRoot(0));
    try with.validate();
    // Truth flags follow the request's segment flags: the request's flags stay the prefix.
    try std.testing.expectEqual(with.flagWords() - 2, (try with.truthRoot(0)).flag);
    try std.testing.expectEqual(with.flagWords() - 1, (try with.truthRoot(1)).flag);
    try std.testing.expect(with.flagWords() <= with.flagCapacity());
    // Truth root data after the seal, inside the region, disjoint from every other slot.
    const seal = with.seal();
    const t0 = try with.truthRoot(0);
    const t1 = try with.truthRoot(1);
    try std.testing.expectEqual(seal.offset + seal.words, t0.offset);
    try std.testing.expectEqual(t0.offset + 8, t1.offset);
    try std.testing.expect(t1.offset + 8 <= with.words());
    try std.testing.expect(t0.offset >= std.mem.alignForward(usize, with.flagCapacity(), 8));
    try std.testing.expectError(error.GpuNativeExchangeSlot, with.truthRoot(2));
    var over = with;
    over.truths = 6;
    try std.testing.expectError(error.GpuNativeExchangeExceedsCapacity, over.validate());
}

test "truth_root is in the recursion range and decodes" {
    const w = G.Verdict.reject(.truth_root, 3);
    try std.testing.expectEqual(G.Check.truth_root, G.Verdict.checkOf(w).?);
    try std.testing.expectEqual(@as(u16, 0x0307), @intFromEnum(G.Check.truth_root));
}

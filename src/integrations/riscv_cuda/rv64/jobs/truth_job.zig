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
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_riscv_cpu_integration");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const Slab = @import("slab.zig");
const C = @import("native_commit.zig");
const NC = @import("native_composition.zig");
const NP = @import("native_pcs.zig");
const S1 = @import("native_stage1.zig");
const X = @import("truth_challenges.zig");
const P = @import("truth_params.zig");
const I = @import("truth_interaction.zig");
const K = @import("truth_class.zig");
const T = @import("../truth_codegen.zig");
const TO = @import("truth_oods.zig");
const NE = @import("native_encode.zig");
const LF = @import("native_leaf_wire.zig");

const D = CPU.rv64_device_pcs;
const WP = CPU.rv64_gkr_worker_protocol;
const O = D.O;
const CP = engine.air.component_prover.ForField(O);

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

fn check(code: c_int) !void {
    if (code != 0) return error.CudaEnqueueFailed;
}
/// STWO_RV64_M8_TRUTH_TRACE=1: one line per enqueue phase (debugging only).
fn trace(comptime what: []const u8, ordinal: u32) void {
    const on = struct {
        var value: ?bool = null;
    };
    if (on.value == null) on.value = if (std.posix.getenv("STWO_RV64_M8_TRUTH_TRACE")) |v| std.mem.eql(u8, v, "1") else false;
    if (on.value.?) std.debug.print("GPU_M8_TRUTH_TRACE ordinal={} at={s} host_ns={}\n", .{ ordinal, what, std.time.nanoTimestamp() });
}
fn feltWords(n: u32) usize {
    return @as(usize, n) * 8;
}

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
const verdict_names = [_][]const u8{ "truth_status", "root_match", "channel_order", "pcs_status", "truth_oods", "encode_bounds" };
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
fn mainInputs(class: *const K.Class, buffer: api.DeviceBuffer, out: []C.Input) !void {
    if (out.len != class.main_logs.len or buffer.words < class.mainEvalWords()) return error.TruthMainShape;
    var at: usize = 0;
    for (class.main_logs, out) |l, *input| {
        input.* = .{ .device = buffer.ptr + at };
        at += @as(usize, 1) << @intCast(l);
    }
}

fn enqueueWitness(class: *const K.Class, sym: *const Symbols, e: *api.Enqueue, compact: api.DeviceBuffer, main: api.DeviceBuffer, status: [*]u32, calls: u32, first_id: u32) !?api.DeviceBuffer {
    const ctx = e.ctx();
    const rows = @as(usize, 1) << @intCast(class.log);
    const main_words = class.main_width * rows;
    var bytes: ?api.DeviceBuffer = null;
    switch (class.witness) {
        .keccak => |k| {
            const chi = main.ptr + main_words;
            const xor5 = chi + (@as(usize, 1) << @intCast(k.chi_log));
            const packet = KeccakPacket{ .inputs = compact.ptr, .main = main.ptr, .chi = chi, .xor5 = xor5, .status = status, .input_words = compact.words, .main_words = main_words, .calls = calls, .first_id = first_id, .log = class.log, .policy = k.policy };
            try check((sym.keccak orelse return error.MissingDeviceTruthSymbol)(ctx, 0, &packet));
        },
        .sha256 => {
            const packet = ShaPacket{ .inputs = compact.ptr, .main = main.ptr, .status = status, .input_words = compact.words, .main_words = main_words, .calls = calls, .first_id = first_id, .log = class.log };
            try check((sym.sha orelse return error.MissingDeviceTruthSymbol)(ctx, 0, &packet));
        },
        .arith256_mod => {
            const b = try e.alloc(256);
            bytes = b;
            const packet = ArithPacket{ .inputs = compact.ptr, .main = main.ptr, .byte_counts = b.ptr, .status = status, .input_words = compact.words, .main_words = main_words, .calls = calls, .first_id = first_id, .log = class.log };
            try check((sym.arith orelse return error.MissingDeviceTruthSymbol)(ctx, 0, &packet));
        },
        .secp => |s| {
            const b = try e.alloc(256);
            bytes = b;
            const packet = SecpPacket{ .inputs = compact.ptr, .main = main.ptr, .byte_counts = b.ptr, .status = status, .input_words = compact.words, .main_words = main_words, .calls = calls, .first_id = first_id, .log = class.log, .kind = s.kind };
            try check(((if (s.curve) sym.curve else sym.secp) orelse return error.MissingDeviceTruthSymbol)(ctx, 0, &packet));
        },
    }
    return bytes;
}

fn statusVerdict(sym: *const Symbols, e: *api.Enqueue, status: api.DeviceBuffer, claims: ?api.DeviceBuffer, zero: ?api.DeviceBuffer, c: StatusConstants, verdict: api.DeviceBuffer) !void {
    try check(sym.status(e.ctx(), 0, status.ptr, if (claims) |b| b.ptr else null, if (zero) |b| b.ptr else null, &c, verdict.ptr));
}

/// Placeholder device inputs for `CommitPlan.stage` (every column is a device
/// view at enqueue).
fn placeholders(a: std.mem.Allocator, n: usize) ![]C.Input {
    const inputs = try a.alloc(C.Input, n);
    @memset(inputs, .{ .device = @ptrFromInt(@alignOf(u32)) });
    return inputs;
}

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

const Table = struct {
    local: usize = 0,
    shared: usize = 0,
    consts: usize = 0,
    header: usize = 0,
    programs: [6]usize = @splat(0),
    roots: usize = 0, // 16 words: class FIXED root, then the expected MAIN root (filled on device)
    expect: usize = 0,
    host_digest: usize = 0, // 8 words (Stage2.digest_words)
    host_root: usize = 0, // 8 words (Stage2.stage1_root_words)
    words: usize = 0,
};

pub const Stage2 = struct {
    leaf_program: ?*const LF.Program = null,
    leaf_device: ?api.DeviceBuffer = null,
    a: std.mem.Allocator,
    class: *const K.Class,
    sym: *const Symbols,
    ordinal: u32,
    calls: u32,
    first_id: u32,
    compact: []const u32,
    /// worker_protocol.begin(config, expected) [+ binding] (K.seed).
    seed: [9]u32,
    /// Device manifest digest (8 words: the seal slot's first words), or
    /// null with `digest_words` (host words staged with the job: harnesses
    /// and the hybrid driver, where the seal ran on the host).
    digest: ?api.DeviceBuffer = null,
    digest_words: ?[8]u32 = null,
    /// Device stage-1 MAIN root (8 words) the replay must reproduce; null =
    /// compared on the host instead (parity harness vs the legacy root).
    stage1_root: ?api.DeviceBuffer = null,
    /// As `stage1_root`, from host words (staged).
    stage1_root_words: ?[8]u32 = null,
    /// CUDA-event GPU span of the job's enqueue (begin..end on the exec stream).
    timing: ?*const Events.Api = null,
    /// Negative tests: corrupt exactly one check input (each must fire its check).
    fault: Fault = .none,
    verdicts: Verdicts = .{},
    /// Skip the host assembly in finish (timing runs of the host path).
    assemble_on_finish: bool = true,
    /// gn-truth: device OODS + device encoder (`.device`), or both paths
    /// compared (`.check`). `.host` is the r-truth path unchanged.
    encode: Encode = .host,
    /// Request-slab encoded region of this truth (length word + bytes);
    /// null = a job-slab field (finish copies the bytes: harnesses).
    encoded: ?api.DeviceBuffer = null,
    request_slab_only: bool = false,
    // per-job plan copies
    fixed_plan: C.CommitPlan = undefined,
    main_plan: C.CommitPlan = undefined,
    inter_plan: C.CommitPlan = undefined,
    composition: NC.Plan = undefined,
    pcs: NP.PcsJob = undefined,
    fixed_tree: S1.FixedTree = undefined,
    live: bool = false,
    layout: Slab.ProofLayout = .{},
    table: Table = .{},
    // staged
    staged: ?api.DeviceBuffer = null,
    staged_seed: ?api.DeviceBuffer = null,
    staged_compact: ?api.DeviceBuffer = null,
    pinned: []u32 = &.{},
    twiddles: [3]?api.DeviceBuffer = @splat(null),
    /// Class-persistent device programs (device modes).
    oods_program: ?api.DeviceBuffer = null,
    encode_program: ?api.DeviceBuffer = null,
    // finish copies
    roots: [32]u32 = undefined,
    alpha: [8]u32 = undefined,
    status_words: [8]u32 = @splat(0),
    claims: [40]u32 = @splat(0),
    oods: [NP.oods_field_words]u32 = undefined,
    local_felts: [X.classic_felts * 8]u32 = @splat(0),
    shared_felts: [X.shared_felts * 8]u32 = undefined,
    pcs_words: []u32 = &.{},
    verdict_words: [verdict_names.len]u32 = @splat(G.Verdict.unset),
    /// Device OODS diagnostic [evaluated(8) | extracted(8)] (device modes).
    oods_diag: [16]u32 = @splat(0),
    /// Host OODS values (`.check`): evaluated, extracted.
    host_oods: [16]u32 = @splat(0),
    /// Device-encoded bytes copied from the job slab (`encoded == null`;
    /// caller frees) and whether they equal the host bytes (`.check`).
    device_bytes: []u8 = &.{},
    device_equal: bool = false,
    /// CUDA-event GPU span of the device OODS check + encoder.
    device_span: Span = .{},
    /// CUDA-event GPU span of the device OODS check alone (inside device_span).
    oods_span: Span = .{},
    /// Host time of finish (verdict reads + copies; + assembly on the host path).
    finish_ns: u64 = 0,
    channel_steps: u32 = 0,
    /// finish output: the legacy proof bytes and claims (caller frees).
    bytes: []u8 = &.{},
    out_claims: []O = &.{},
    span: Span = .{},
    /// pcs_status expectation (host struct; the launcher copies it by value).
    expect: PcsExpect = undefined,
    /// Host finish (assembly) time of the last finish.
    assemble_ns: u64 = 0,

    pub fn init(self: *Stage2) !void {
        if (self.request_slab_only) {
            if (self.encode != .device or self.encoded == null) return error.TruthRequestVerdictsMissing;
            inline for (verdict_names) |name| if (@field(self.verdicts, name) == null) return error.TruthRequestVerdictsMissing;
        }
        const c = self.class;
        if (self.compact.len != c.compactWords(self.calls) or self.calls == 0) return error.TruthCompactShape;
        // `.check` compares the device bytes it copies out of the job slab;
        // a request-slab region would leave nothing to compare.
        if (self.encode == .check and self.encoded != null) return error.TruthCheckNeedsJobSlabRegion;
        if (self.encoded) |r| if (r.words < c.encode.regionWords()) {
            // A region below the class capacity: the encoder fails closed
            // (encode_bounds); `.encode_capacity` negatives exercise it.
            if (self.fault != .encode_capacity) return error.TruthEncodedRegionTooSmall;
        };
        if (self.digest) |d| {
            if (d.words < G.Exchange.seal_digest_words) return error.TruthDigestShape;
        } else if (self.digest_words == null) return error.TruthDigestRequired;
        if (self.stage1_root != null and self.stage1_root_words != null) return error.TruthStage1RootAmbiguous;
        self.fixed_plan = try K.jobPlan(self.a, &c.fixed_plan);
        errdefer K.freeJobPlan(self.a, &self.fixed_plan);
        self.main_plan = try K.jobPlan(self.a, &c.main_plan);
        errdefer K.freeJobPlan(self.a, &self.main_plan);
        self.inter_plan = try K.jobPlan(self.a, &c.inter_plan);
        errdefer K.freeJobPlan(self.a, &self.inter_plan);
        self.main_plan.require_warm = self.request_slab_only;
        self.inter_plan.require_warm = self.request_slab_only;
        self.composition = c.composition;
        self.composition.table_device = null;
        self.composition.tw_device = null;
        self.pcs = try K.clonePcs(self.a, c);
        errdefer self.a.free(self.pcs.prepared.coefficients);
        self.pcs_words = try self.a.alloc(u32, @intCast(self.pcs.outputWords()));
        errdefer self.a.free(self.pcs_words);
        self.fixed_tree = .{ .plan = &self.fixed_plan, .key = c.fixed_key };
        self.table = tableOf(c);
        self.live = true;
        const n_status: u32 = StatusIndex.first_role + @as(u32, @intCast(c.roles.len));
        _ = try self.layout.add(.root, 0, 32);
        _ = try self.layout.add(.opaque_words, 0, 8); // alpha
        _ = try self.layout.add(.status, 0, n_status);
        _ = try self.layout.add(.status, 1, Own.words); // own verdicts + raw PCS words
        _ = try self.layout.add(.claims, 0, feltWords(c.claim_count));
        _ = try self.layout.add(.claims, 1, @max(8, feltWords(c.zero_count)));
        _ = try self.layout.add(.opaque_words, 1, NP.oods_field_words);
        if (self.encode != .host) {
            const sym = self.sym;
            if (sym.oods == null or sym.encode == null or sym.merge == null) return error.TruthDeviceEncodeSymbolsMissing;
            _ = try self.layout.add(.opaque_words, 5, 16); // OODS diagnostic
            if (self.encoded == null) _ = try self.layout.add(.opaque_words, 6, c.encode.regionWords());
        }
        // The PCS image enters the job slab only for host decoding.
        if (self.encode != .device) _ = try self.layout.add(.opaque_words, 2, self.pcs_words.len);
        _ = try self.layout.add(.opaque_words, 3, feltWords(c.localScript().felts));
        _ = try self.layout.add(.opaque_words, 4, feltWords(X.shared_felts));
        _ = try self.layout.add(.channel_state, 0, @import("channel.zig").snapshot_words);
    }
    pub fn deinit(self: *Stage2) void {
        self.span.close(self.timing);
        self.device_span.close(self.timing);
        self.oods_span.close(self.timing);
        if (!self.live) return;
        K.freeJobPlan(self.a, &self.fixed_plan);
        K.freeJobPlan(self.a, &self.main_plan);
        K.freeJobPlan(self.a, &self.inter_plan);
        self.a.free(self.pcs.prepared.coefficients);
        self.a.free(self.pcs_words);
        self.live = false;
    }
    pub fn classKey(self: *Stage2) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-gpu-truth-stage2/v1\x00");
        h.update(&self.class.key);
        return h.finalResult();
    }
    pub fn footprint(self: *Stage2) api.Footprint {
        var fp = if (self.request_slab_only) stage2RequestFootprint(self.class, self.calls, @intCast(self.pcs.outputWords()), @intCast(self.pcs.ingressWords())) else stage2Footprint(self.class, self.calls, self.layout.words, @intCast(self.pcs.outputWords()), @intCast(self.pcs.ingressWords()));
        if (self.request_slab_only) fp.device_words += self.layout.words;
        return fp;
    }

    pub fn stage(self: *Stage2, s: *api.Stager) !void {
        const c = self.class;
        if (self.leaf_program) |program| {
            const p = try s.persistent(program.key(), program.words.len);
            if (p.fresh) return error.NativeLeafProgramNotWarmed;
            self.leaf_device = p.buffer;
        }
        const t = self.table;
        const table = try s.pinned(t.words);
        try fillTable(c, &self.pcs, t, self.calls, self.first_id, table);
        if (self.digest_words) |w| @memcpy(table[t.host_digest..][0..8], &w);
        if (self.stage1_root_words) |w| @memcpy(table[t.host_root..][0..8], &w);
        switch (self.fault) {
            .none, .absent_claim, .channel_cursor => {},
            .parameter_program => table[t.programs[0] + 1] = c.bounds().staged + 1000, // out-of-range gather entry
            .class_root => table[t.roots] ^= 1,
            .stage1_root => table[t.host_root] ^= 1,
            .pcs_header => {},
            .oods_sample, .oods_composition, .encode_capacity, .encode_value => if (self.encode == .host) return error.TruthFaultNeedsDeviceEncode,
        }
        self.expect = pcsExpect(&self.pcs);
        if (self.fault == .pcs_header) self.expect.header[0] ^= 1;
        if (self.fault == .stage1_root and self.stage1_root_words == null) return error.TruthFaultNeedsStage1Root;
        try self.span.open(self.timing);
        const staged = try s.alloc(t.words);
        try s.upload(staged, table);
        self.staged = staged;
        const seed = try s.alloc(9);
        try s.upload(seed, &self.seed);
        self.staged_seed = seed;
        const compact = try s.alloc(self.compact.len);
        try s.upload(compact, self.compact);
        self.staged_compact = compact;
        // FIXED: class-persistent, filled by the first job of the class.
        const fixed_inputs = try self.a.alloc(C.Input, c.fixed_host.len);
        defer self.a.free(fixed_inputs);
        for (fixed_inputs, c.fixed_host) |*i, h| i.* = .{ .host = h };
        if (self.request_slab_only) {
            const region = try s.persistent(c.fixed_key, self.fixed_tree.words());
            if (region.fresh) return error.TruthClassNotWarmed;
            self.fixed_tree.persistent = region;
        } else try self.fixed_tree.stage(s, fixed_inputs);
        const inputs = try placeholders(self.a, @max(c.main_logs.len, c.inter_logs.len));
        defer self.a.free(inputs);
        try self.main_plan.stage(s, inputs[0..c.main_logs.len]);
        try self.inter_plan.stage(s, inputs[0..c.inter_logs.len]);
        for (c.roles, 0..) |r, i| self.twiddles[i] = try I.stageTwiddles(self.a, s, r.interaction.log);
        try self.composition.stage(s);
        self.pinned = try s.pinned(@intCast(self.pcs.ingressWords()));
        if (self.encode != .host) {
            // Class-persistent per worker: uploaded by the first job of the class.
            const od = try s.persistent(c.oods.key(c.key), c.oods.words.len);
            if (od.fresh and self.request_slab_only) return error.TruthClassNotWarmed;
            if (od.fresh) try s.upload(od.buffer, c.oods.words);
            self.oods_program = od.buffer;
            const ep = try s.persistent(encodeKey(c), c.encode.words.len);
            if (ep.fresh and self.request_slab_only) return error.TruthClassNotWarmed;
            if (ep.fresh) try s.upload(ep.buffer, c.encode.words);
            self.encode_program = ep.buffer;
            try self.device_span.open(self.timing);
            try self.oods_span.open(self.timing);
        }
    }

    pub fn enqueue(self: *Stage2, e: *api.Enqueue) !void {
        var trace_label: [80]u8 = undefined;
        var trace_range = try e.trace(.truth_stage2, self.ordinal, &trace_label);
        defer trace_range.deinit();
        const saved = e.slab.*;
        defer e.slab.* = saved;
        if (self.request_slab_only) e.slab.* = .{ .device = try e.alloc(self.layout.words) };
        const c = self.class;
        const sym = self.sym;
        const ctx = e.ctx();
        const t = self.table;
        try e.slab.bind(&self.layout);
        trace("s2.begin", self.ordinal);
        const staged = self.staged orelse return error.TruthJobNotStaged;
        const compact = self.staged_compact.?;
        const roots = try e.slab.field(.root, 0);
        const status = try e.slab.field(.status, 0);
        const own = try e.slab.field(.status, 1);
        const claims = try e.slab.field(.claims, 0);
        const zero = try e.slab.field(.claims, 1);
        const local = try e.slab.field(.opaque_words, 3);
        const shared = try e.slab.field(.opaque_words, 4);
        try check(sym.memset(ctx, status.ptr, 0, status.words * 4));
        try check(sym.memset(ctx, claims.ptr, 0, claims.words * 4));
        try check(sym.memset(ctx, zero.ptr, 0, zero.words * 4));
        // Transcript prefix: begin [+ binding] (host seed), FIXED root, MAIN root.
        const digest = self.digest orelse try staged.slice(t.host_digest, 8);
        const stage1_root: ?api.DeviceBuffer = self.stage1_root orelse if (self.stage1_root_words != null) try staged.slice(t.host_root, 8) else null;
        try self.span.mark(self.timing, false, e.stream());
        try e.channel.initFromCheckpoint(self.staged_seed.?);
        const fixed_inputs = try self.a.alloc(C.Input, c.fixed_host.len);
        defer self.a.free(fixed_inputs);
        for (fixed_inputs, c.fixed_host) |*i, h| i.* = .{ .host = h };
        const fixed = try self.fixed_tree.enqueue(sym.commit, e, fixed_inputs, try roots.slice(0, 8));
        trace("s2.fixed", self.ordinal);
        const main_eval = try e.alloc(c.mainEvalWords());
        const bytes = try enqueueWitness(c, sym, e, compact, main_eval, status.ptr + StatusIndex.witness, self.calls, self.first_id);
        const main_inputs = try self.a.alloc(C.Input, c.main_logs.len);
        defer self.a.free(main_inputs);
        try mainInputs(c, main_eval, main_inputs);
        const main = try self.main_plan.enqueue(sym.commit, e, main_inputs, try roots.slice(8, 8), true);
        trace("s2.main", self.ordinal);
        if (bytes) |b| e.free(b);
        e.free(main_eval);
        // Local challenges (proof channel), shared challenges (fresh channel over the digest).
        try X.run(c.localScript(), e.channel, try staged.slice(t.local, X.stagedWords(c.localScript())), null, local);
        trace("s2.local", self.ordinal);
        const state = try e.alloc(@import("channel.zig").state_words);
        var fresh = api.DeviceChannel.init(e.channel.worker, e.channel.exec, ctx, e.stream(), state, 0);
        try X.run(X.shared, &fresh, try staged.slice(t.shared, X.stagedWords(X.shared)), digest, shared);
        e.free(state);
        trace("s2.shared", self.ordinal);
        // Interaction witnesses.
        const consts = try staged.slice(t.consts, feltWords(c.stagedFelts()));
        const b = c.bounds();
        const bounds = [4]u32{ b.staged, b.local, b.shared, b.claim };
        var outputs: [3]api.DeviceBuffer = undefined;
        var max_fixed: usize = 0;
        var max_main: usize = 0;
        for (c.roles) |r| {
            max_fixed = @max(max_fixed, r.interaction.fixed_count);
            max_main = @max(max_main, r.interaction.main_count);
        }
        const fixed_ptrs = try self.a.alloc([*]const u32, max_fixed);
        defer self.a.free(fixed_ptrs);
        const main_ptrs = try self.a.alloc([*]const u32, max_main);
        defer self.a.free(main_ptrs);
        for (c.roles, 0..) |*r, i| {
            const p = &r.interaction;
            const params = try e.alloc(p.program.len * 8);
            try check(sym.gather(ctx, 0, consts.ptr, local.ptr, shared.ptr, null, @ptrCast(staged.ptr + t.programs[2 * i]), @intCast(p.program.len), &bounds, params.ptr, status.ptr + StatusIndex.params));
            for (0..p.fixed_count) |k| fixed_ptrs[k] = fixed.coefficients.ptr + c.fixed_offsets[p.fixed_first + k];
            for (0..p.main_count) |k| main_ptrs[k] = main.coefficients.ptr + self.main_plan.offsets[p.main_first + k];
            outputs[i] = try e.alloc(p.outputWords());
            try I.enqueue(p, &sym.interaction, e, .{ .fixed = fixed_ptrs[0..p.fixed_count], .main = main_ptrs[0..p.main_count], .parameters = params, .twiddles = self.twiddles[i].? }, .{ .output = outputs[i], .claims = claims, .zero = zero, .status = try status.slice(StatusIndex.first_role + i, 1) });
            e.free(params);
            trace("s2.role", self.ordinal);
        }
        // mixManifestAndClaims (worker_protocol): header, digest, claims.
        try e.channel.mixWords(try staged.slice(t.header, 3));
        try e.channel.mixWords(try digest.slice(0, 8));
        try e.channel.mixFelts(claims);
        trace("s2.mixed", self.ordinal);
        // INTER commit over the roles' published columns; the witnesses die after it.
        const inter_inputs = try self.a.alloc(C.Input, c.inter_logs.len);
        defer self.a.free(inter_inputs);
        {
            var at: usize = 0;
            for (c.roles, 0..) |*r, i| for (0..r.interaction.width()) |col| {
                inter_inputs[at] = .{ .device = try r.interaction.columnPointer(outputs[i].ptr, col) };
                at += 1;
            };
        }
        const inter = try self.inter_plan.enqueue(sym.commit, e, inter_inputs, try roots.slice(16, 8), true);
        trace("s2.inter", self.ordinal);
        var k = c.roles.len;
        while (k > 0) {
            k -= 1;
            e.free(outputs[k]);
        }
        // Composition: coefficient drawn on device, role parameters gathered on device.
        const alpha = try e.slab.field(.opaque_words, 0);
        try e.channel.drawSecureFelts(1, alpha);
        const table = (self.composition.table_device orelse return error.NativeCompositionNotStaged).ptr;
        for (c.roles, self.composition.roles, 0..) |*r, rp, i| {
            if (rp.spec.parameters.len != r.composition_program.len * 8) return error.TruthCompositionShape;
            try check(sym.gather(ctx, 0, consts.ptr, local.ptr, shared.ptr, claims.ptr, @ptrCast(staged.ptr + t.programs[2 * i + 1]), @intCast(r.composition_program.len), &bounds, table + rp.t_params, status.ptr + StatusIndex.params));
        }
        const fixed_cols = NC.Columns{ .base = fixed.coefficients.ptr, .offsets = c.fixed_offsets };
        const main_cols = NC.Columns{ .base = main.coefficients.ptr, .offsets = self.main_plan.offsets };
        const inter_cols = NC.Columns{ .base = inter.coefficients.ptr, .offsets = self.inter_plan.offsets };
        const comp = try self.composition.enqueueWithClaims(sym.composition, e, .{ fixed_cols, main_cols, inter_cols }, alpha.ptr, null, try roots.slice(24, 8), status.ptr + StatusIndex.composition);
        try e.channel.mixRootFromTree(try roots.slice(24, 8));
        trace("s2.composition", self.ordinal);
        // OODS + enqueue-only PCS over the four trees.
        const trees = [4]struct { base: [*]const u32, offsets: []const usize }{
            .{ .base = fixed.coefficients.ptr, .offsets = c.fixed_offsets },
            .{ .base = main.coefficients.ptr, .offsets = self.main_plan.offsets },
            .{ .base = inter.coefficients.ptr, .offsets = self.inter_plan.offsets },
            .{ .base = comp.coefficients.ptr, .offsets = self.composition.offsets },
        };
        for (trees, 0..) |tree, index| for (tree.offsets, 0..) |offset, original| try self.pcs.bindColumn(index, original, tree.base + offset);
        const pcs_out = if (self.encode == .device) try e.alloc(self.pcs_words.len) else try e.slab.field(.opaque_words, 2);
        try self.pcs.enqueueOpening(sym.pcs, e, self.pinned, try e.slab.field(.opaque_words, 1), pcs_out);
        trace("s2.pcs", self.ordinal);
        e.free(comp.coefficients);
        e.free(inter.coefficients);
        e.free(main.coefficients);
        if (self.fault == .absent_claim) {
            // A nonzero word in the absent claim (classic) / the local closing
            // group (delegated): truth_status must reject it.
            const target = if (c.kind == .classic) try claims.slice(32, 1) else try zero.slice(0, 1);
            try check(sym.memset(ctx, target.ptr, 1, 1));
        }
        // Device acceptance checks (one Verdict word each).
        try statusVerdict(sym, e, status, claims, if (c.zero_count != 0) zero else null, .{ .n_status = @intCast(status.words), .n_claims = c.claim_count, .n_zero = c.zero_count, .classic = @intFromBool(c.kind == .classic), .check = @intFromEnum(G.Check.truth_status) }, self.verdicts.truth_status orelse try own.slice(0, 1));
        // Expected roots: the class FIXED root (staged), then the stage-1 MAIN
        // root (device) or, without one, the replay itself (host-compared).
        const expected = try staged.slice(t.roots, 16);
        try check(sym.copy_d2d(ctx, expected.ptr + 8, (stage1_root orelse try roots.slice(8, 8)).ptr, 32));
        try check(sym.root_match(ctx, 0, roots.ptr, expected.ptr, 2, @intFromEnum(G.Check.root_match), (self.verdicts.root_match orelse try own.slice(1, 1)).ptr));
        self.channel_steps = e.channel.step;
        try e.channel.snapshot(e.slab, (try self.layout.get(.channel_state, 0)).offset);
        const cursor = e.channel.step + @intFromBool(self.fault == .channel_cursor);
        try check(sym.order(ctx, 0, e.channel.stateBuffer().ptr, cursor, e.channel.expectedChain(e.channel.step), (self.verdicts.channel_order orelse try own.slice(2, 1)).ptr));
        // The launcher reads the expectation on the host (by value into the kernel).
        const pcs_verdict = if (self.encode == .host) self.verdicts.pcs_status orelse try own.slice(Own.pcs_status, 1) else try own.slice(Own.pcs_truth, 1);
        try check(sym.pcs_status(ctx, 0, pcs_out.ptr, pcs_out.words, roots.ptr, &self.expect, pcs_verdict.ptr));
        trace("s2.checks", self.ordinal);
        if (self.encode != .host) try self.enqueueDevice(e, pcs_out, own);
        if (self.leaf_program) |program| {
            const region = self.encoded orelse return error.NativeLeafRegionBounds;
            const leaf_device = self.leaf_device orelse return error.NativeLeafProgramNotWarmed;
            const sources_: [6]?LF.Buffer = .{ null, null, .{ .ptr = digest.ptr, .words = digest.words }, null, .{ .ptr = claims.ptr, .words = claims.words }, .{ .ptr = pcs_out.ptr, .words = pcs_out.words } };
            const verdict = self.verdicts.encode_bounds orelse return error.NativeLeafRegionBounds;
            try LF.enqueue(sym.leaf orelse return error.MissingNativeLeafEncoder, sym.copy_d2d, ctx, program, .{ .ptr = leaf_device.ptr, .words = leaf_device.words }, sources_, .{ .ptr = region.ptr, .words = region.words }, verdict.ptr, @as(u32, @intFromEnum(G.Check.encode_bounds)) << 16);
        }
        trace("s2.device_encode", self.ordinal);
        if (self.encode == .device) e.free(pcs_out);
        try self.span.mark(self.timing, true, e.stream());
    }

    /// Device OODS constraint check + device encoder (gn-truth), after the
    /// PCS and its status check. Verdicts: truth_oods, encode_bounds, and
    /// pcs_status = merge(truth_pcs_status, encoder pcs_status).
    fn enqueueDevice(self: *Stage2, e: *api.Enqueue, pcs_out: api.DeviceBuffer, own: api.DeviceBuffer) !void {
        const c = self.class;
        const sym = self.sym;
        const ctx = e.ctx();
        const osym = sym.oods.?;
        const esym = sym.encode.?;
        try self.device_span.mark(self.timing, false, e.stream());
        switch (self.fault) {
            .oods_sample, .oods_composition, .encode_value => {
                const word = try self.faultWord();
                try check(sym.memset(ctx, pcs_out.ptr + word, if (self.fault == .encode_value) 0xff else 0x01, 4));
            },
            else => {},
        }
        // OODS constraint check over the PCS samples and the gathered parameters.
        const scratch = try e.alloc(c.oods.scratch_words);
        try check(sym.memset(ctx, scratch.ptr + c.oods.words[TO.H.partials_at], 0, TO.partial_words * TO.max_roles * 4));
        const table = (self.composition.table_device orelse return error.NativeCompositionNotStaged);
        var params: [TO.max_roles]?api.DeviceBuffer = @splat(null);
        for (self.composition.roles, 0..) |rp, i| params[i] = try table.slice(rp.t_params, rp.spec.parameters.len);
        try self.oods_span.mark(self.timing, false, e.stream());
        try TO.enqueue(&osym, ctx, &c.oods, .{
            .desc = self.oods_program orelse return error.TruthJobNotStaged,
            .pcs = pcs_out,
            .trees = 4,
            .params = params,
            .alpha = try e.slab.field(.opaque_words, 0),
            .point = try e.slab.field(.opaque_words, 1),
            .scratch = scratch,
            .verdict = self.verdicts.truth_oods orelse try own.slice(Own.truth_oods, 1),
            .diag = try e.slab.field(.opaque_words, 5),
        });
        try self.oods_span.mark(self.timing, true, e.stream());
        e.free(scratch);
        // Encoder: WP.encodePhysical bytes into the encoded region.
        const escratch = try e.alloc(NE.scratch_words);
        var region = self.encoded orelse try e.slab.field(.opaque_words, 6);
        if (self.fault == .encode_capacity) region = try region.slice(0, 2);
        var enc = NE.Encoder{ .sym = &esym, .program = self.encode_program orelse return error.TruthJobNotStaged, .host = &c.encode, .pcs = pcs_out, .scratch = escratch, .pcs_status = try own.slice(Own.pcs_encoder, 1) };
        try enc.enqueue(ctx, region, self.verdicts.encode_bounds orelse try own.slice(Own.encode_bounds, 1));
        e.free(escratch);
        try check(sym.merge.?(ctx, 0, (try own.slice(Own.pcs_truth, 2)).ptr, 2, @intFromEnum(G.Check.pcs_status), (self.verdicts.pcs_status orelse try own.slice(Own.pcs_status, 1)).ptr));
        try self.device_span.mark(self.timing, true, e.stream());
    }

    /// The PCS-image word a device-encode fault corrupts.
    fn faultWord(self: *const Stage2) !usize {
        const d = self.class.oods.words;
        return switch (self.fault) {
            .oods_sample => blk: {
                const row = d[TO.H.header_words..][0..TO.R.words];
                for (0..row[TO.R.n_nodes]) |i| {
                    const w = d[row[TO.R.nodes_at] + TO.node_words * i ..][0..TO.node_words];
                    if (w[0] == @intFromEnum(TO.Op.input)) break :blk TO.samplesOffset(4) + 8 * @as(usize, w[1]);
                }
                return error.TruthFaultNoInput;
            },
            .oods_composition => TO.samplesOffset(4) + 8 * (@as(usize, d[TO.H.composition_sample]) + 9),
            .encode_value => blk: {
                // native_encode Program tree table, tree 0 record word 4: the
                // PCS offset of tree 0's queried values.
                const p = self.class.encode.words;
                break :blk p[p[@intFromEnum(NE.H.tree_table)] + 4];
            },
            else => error.TruthFaultNotDevice,
        };
    }

    pub fn finish(self: *Stage2, view: api.SlabView) !void {
        var finish_timer = try std.time.Timer.start();
        defer self.finish_ns = finish_timer.read();
        self.span.read(self.timing);
        self.device_span.read(self.timing);
        self.oods_span.read(self.timing);
        if (self.request_slab_only) return;
        @memcpy(&self.roots, try Slab.read(view, .root, 0));
        @memcpy(&self.alpha, try Slab.read(view, .opaque_words, 0));
        const st = try Slab.read(view, .status, 0);
        @memcpy(self.status_words[0..st.len], st);
        const cl = try Slab.read(view, .claims, 0);
        @memcpy(self.claims[0..cl.len], cl);
        @memcpy(&self.oods, try Slab.read(view, .opaque_words, 1));
        if (self.encode != .device) @memcpy(self.pcs_words, try Slab.read(view, .opaque_words, 2));
        const lf = try Slab.read(view, .opaque_words, 3);
        @memcpy(self.local_felts[0..lf.len], lf);
        @memcpy(&self.shared_felts, try Slab.read(view, .opaque_words, 4));
        @memcpy(&self.verdict_words, (try Slab.read(view, .status, 1))[0..verdict_names.len]);
        if (self.encode != .host) {
            @memcpy(&self.oods_diag, try Slab.read(view, .opaque_words, 5));
            if (self.encoded == null) {
                const region = try Slab.read(view, .opaque_words, 6);
                const len: usize = region[0];
                if (len > 4 * (region.len - 1)) return error.TruthEncodedLengthOverrun;
                self.device_bytes = try self.a.dupe(u8, std.mem.sliceAsBytes(region[1..])[0..len]);
            }
        }
        // Own verdict words (request-slab ones are gpu_native.publish's); the
        // device-encode words exist only in the device modes.
        const ran = if (self.encode == .host) 4 else verdict_names.len;
        inline for (verdict_names, 0..) |name, i| {
            if (i < ran and @field(self.verdicts, name) == null and self.verdict_words[i] != G.Verdict.accepted) {
                std.debug.print("GPU_M8_TRUTH_JOB event=rejected ordinal={} check={s} word=0x{x}\n", .{ self.ordinal, name, self.verdict_words[i] });
                return error.DeviceTruthCheckRejected;
            }
        }
        if (self.encode != .device and self.assemble_on_finish) {
            var timer = try std.time.Timer.start();
            try self.assemble();
            self.assemble_ns = timer.read();
            if (self.encode == .check) self.device_equal = std.mem.eql(u8, self.device_bytes, self.bytes) and std.mem.eql(u32, &self.oods_diag, &self.host_oods);
        }
    }

    /// Host assembly (the legacy W.Prover tail): PCS decode, the engine's
    /// OODS constraint check with the device claims/challenges, encodePhysical.
    pub fn assemble(self: *Stage2) !void {
        const c = self.class;
        const a = self.a;
        var root_bytes: [4][32]u8 = undefined;
        for (&root_bytes, 0..) |*r, tr| for (0..8) |i| std.mem.writeInt(u32, r[4 * i ..][0..4], self.roots[8 * tr + i], .little);
        var decoded = try self.pcs.decode(a, self.pcs_words, &root_bytes);
        defer decoded.proof.deinit(a);
        const claims = try a.alloc(O, c.claim_count);
        errdefer a.free(claims);
        for (claims, 0..) |*v, i| v.* = try felt(self.claims[8 * i ..][0..8]);
        const shared_values = try felts(X.shared_felts, &self.shared_felts);
        const shared = try X.sharedFrom(&shared_values);
        var classic: [3]T.Role.Component = undefined;
        var delegated: T.V3Role.Component = undefined;
        var handles: [3]CP.ComponentProver = undefined;
        const provers_slice: []const CP.ComponentProver = if (c.kind == .classic) blk: {
            const local_values = try felts(X.classic_felts, &self.local_felts);
            const local = try X.classicFrom(&local_values);
            const kinds = [3]T.Role.Kind{ .keccak, .chi, .xor5 };
            var offsets: [3]usize = .{ 0, 0, 0 };
            for (&classic, kinds, 0..) |*comp, kd, i| {
                const r = c.roles[i];
                comp.* = .{ .kind = kd, .log_size = r.interaction.log, .calls = if (i == 0) self.calls else 0, .first_id = if (i == 0) self.first_id else 1, .keccak_policy = c.keccakPolicy(), .local = local, .shared = shared, .claim = claims[i], .global_claim = if (i == 0) claims[3] else O.zero(), .split = 2 };
                comp.offsets = offsets;
                for (comp.widths(), 0..) |w, tr| offsets[tr] += w;
                handles[i] = comp.asProverComponent();
            }
            break :blk handles[0..3];
        } else blk: {
            delegated = .{ .truth = K.withSpan(c.truth, self.calls, self.first_id), .wire = shared.wire, .bytes = try felt(self.local_felts[0..8]), .claim = claims[0] };
            handles[0] = delegated.asProverComponent();
            break :blk handles[0..1];
        };
        const provers = CP.ComponentProvers{ .components = provers_slice, .n_preprocessed_columns = c.fixed_logs.len };
        var view = try provers.componentsView(a);
        defer view.deinit(a);
        const oods = D.Point{ .x = try felt(self.oods[0..8]), .y = try felt(self.oods[8..16]) };
        const proof = WP.Proof{ .commitment_scheme_proof = decoded.proof };
        const extracted = proof.extractCompositionOodsEvalWithSplit(oods, c.mask_log + c.split, c.split) orelse return error.InvalidStructure;
        const expected_eval = try view.evalCompositionPolynomialAtPointWithWorkCapture(a, oods, &decoded.proof.sampled_values, try felt(&self.alpha), c.mask_log, c.mask_log + c.split, c.split, null);
        @memcpy(self.host_oods[0..8], &X.words(expected_eval));
        @memcpy(self.host_oods[8..16], &X.words(extracted));
        if (!extracted.eql(expected_eval)) return error.ConstraintsNotSatisfied;
        self.bytes = try WP.encodePhysical(a, .{ .commitment_scheme_proof = decoded.proof });
        self.out_claims = claims;
    }
    pub fn abort(_: *Stage2) void {}
    pub fn job(self: *Stage2) api.Job {
        return api.Job.from(Stage2, self);
    }
};

/// Persistent-region key of a class's encode program on a worker.
pub fn encodeKey(c: *const K.Class) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rv64-m8-gn-truth-encode/v1\x00");
    h.update(&c.key);
    return h.finalResult();
}

/// Staged word table offsets of a class.
fn tableOf(c: *const K.Class) Table {
    var t = Table{};
    var n: usize = 0;
    t.local = n;
    n += X.stagedWords(c.localScript());
    t.shared = n;
    n += X.stagedWords(X.shared);
    n = std.mem.alignForward(usize, n, 8);
    t.consts = n;
    n += feltWords(c.stagedFelts());
    t.header = n;
    n += 3;
    for (c.roles, 0..) |r, i| {
        t.programs[2 * i] = n;
        n += 2 * r.interaction.program.len;
        t.programs[2 * i + 1] = n;
        n += 2 * r.composition_program.len;
    }
    t.roots = n;
    n += 16;
    t.expect = n;
    n += @sizeOf(PcsExpect) / 4;
    t.host_digest = n;
    n += 8;
    t.host_root = n;
    n += 8;
    t.words = n;
    return t;
}

/// The staged words of one job (host): scripts, request span, manifest
/// header, gather programs, class FIXED root, PCS expectation.
fn fillTable(c: *const K.Class, pcs: *const NP.PcsJob, t: Table, calls: u32, first_id: u32, out: []u32) !void {
    if (out.len < t.words) return error.TruthStageTableTooSmall;
    @memset(out[0..t.words], 0);
    try X.stageWords(c.localScript(), out[t.local..]);
    try X.stageWords(X.shared, out[t.shared..]);
    var spans: [3]P.Span = undefined;
    for (c.roles, 0..) |r, i| spans[i] = r.span;
    spans[0] = .{ .calls = calls, .first_id = first_id }; // the crypto role carries the request span
    try P.stageConstants(spans[0..c.roles.len], out[t.consts..]);
    const H = @import("native_stage2.zig").manifest_header;
    out[t.header] = H[0];
    out[t.header + 1] = H[1];
    out[t.header + 2] = c.claim_count;
    for (c.roles, 0..) |r, i| for ([2][]const P.Entry{ r.interaction.program, r.composition_program }, 0..) |prog, j| {
        try P.validate(prog, c.bounds());
        for (prog, 0..) |entry, k| {
            out[t.programs[2 * i + j] + 2 * k] = entry.source;
            out[t.programs[2 * i + j] + 2 * k + 1] = entry.index;
        }
    };
    for (0..8) |i| out[t.roots + i] = std.mem.readInt(u32, c.fixed_root[4 * i ..][0..4], .little);
    const expect = pcsExpect(pcs);
    @memcpy(out[t.expect..][0 .. @sizeOf(PcsExpect) / 4], std.mem.bytesAsSlice(u32, std.mem.asBytes(&expect)));
}

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

fn felt(words: []const u32) !O {
    if (words.len < 8) return error.InvalidFelt;
    var limbs: [8]core.fields.m31.M31 = undefined;
    for (&limbs, words[0..8]) |*l, w| {
        if (w >= core.fields.m31.Modulus) return error.NoncanonicalFelt;
        l.* = core.fields.m31.M31.fromCanonical(w);
    }
    return O.fromM31Array(limbs);
}
fn felts(comptime n: usize, words: []const u32) ![n]O {
    var out: [n]O = undefined;
    for (&out, 0..) |*v, i| v.* = try felt(words[8 * i ..][0..8]);
    return out;
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

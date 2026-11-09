//! M8 GPU-native Stage-2 tail real-block parity harness (pod only, opt-in
//! binary; stream native, piece gn-s2).
//!
//! Runs the unchanged legacy resident pipeline on a real block (the gate's
//! manifest) with byte-neutral pass-through decorators that RECORD the legacy
//! Stage-2 inputs and outputs of every native CPU segment:
//!   * resident_composition: the composition coefficient alpha, the roles
//!     (CompRoles.fromItemsWith: parameters, hc rows, geometry) and the items
//!     (for the host OODS check);
//!   * pcs (cpu): the REAL enqueue-only PCS image (native_pcs.PcsJob run on
//!     the job GPU from the legacy PCS request, BEFORE the legacy call, as the
//!     native-parity harness does) + its device OODS field, then the legacy
//!     proof (whose encodePhysical bytes the pipeline writes as cpu-<k>.bin);
//!   * native_stage_two: the pending manifest (digest, shared draws, every
//!     entry's flat-digest fields incl. local receipt digests and marginals).
//! Post hoc, per segment, ONE job on the job GPU runs the Stage-2 tail back to
//! back on device from those recorded inputs only:
//!   seal (flat v1-flat digest script over an exchange replica holding the
//!   recorded MAIN / truth roots, receipt digests and marginals) -> shared
//!   draws -> Check.oods_constraint (native_encode_oods) -> ProofEncoder ->
//!   root_match, and compares every output:
//!   seal digest == pending.digest, shared == pending.shared, oods verdict 0
//!   with [evaluated | extracted] == the host engine's values
//!   (evalCompositionPolynomialAtPoint / extractCompositionOodsEvalWithSplit),
//!   encoder bytes == the pipeline's cpu-<k>.bin (byte identity), pcs_status /
//!   encode_bounds / root_match 0.
//! Negatives (every segment): one fault per run, the named word must reject
//! and every other word must accept. CUDA-event GPU time per tail stage and
//! the host time per step are reported [M]. Results: <out>/gn-s2-parity.json.
//!
//! usage: rv64-m8-gn-s2-parity <manifest.json> <out-dir>
//! env: the gate's service environment (STWO_RV64_GPU_LIBRARY, legacy on
//!   STWO_RV64_GPU_DEVICES=0), plus
//!   STWO_RV64_M8_JOBS_LIBRARY        the jobs addon (with native_encode_oods.cu)
//!   STWO_RV64_M8_PARITY_DEVICE       job GPU (default 1)
//!   STWO_RV64_M8_PARITY_SOURCE_DEVICE legacy GPU the PCS mirror reads (default 0)
//!   STWO_RV64_M8_JOBS_ARENA_BYTES    job arena (default 20 GiB)
//!   STWO_RV64_M8_JOBS_PINNED_BYTES   pinned slot (default 1 GiB)
//!   STWO_RV64_M8_GN_S2_NEGATIVES     1 (default) / 0
//!   STWO_RV64_M8_GN_S2_REPEAT        timed warm repeats per segment (default 3)
const std = @import("std");
const core = @import("stwo_core");
const CPU = @import("stwo_riscv_cpu_integration");
const Main = CPU.rv64_ethereum_gkr_main;
const Pool = @import("rv64/resident_pool.zig").Pool;
const Router = @import("rv64/resident_router.zig");
const jobs = @import("rv64/jobs/mod.zig");
const W = jobs.worker;
const api = jobs.api;
const G = @import("rv64/jobs/gpu_native.zig");
const NP = @import("rv64/jobs/native_pcs.zig");
const NE = @import("rv64/jobs/native_encode.zig");
const NO = @import("rv64/jobs/native_encode_oods.zig");
const S2D = @import("rv64/jobs/native_device_stage2.zig");
const CompRoles = @import("rv64/m8_native_composition_roles.zig");
const RC = @import("rv64/resident_composition.zig");
const JG = @import("rv64/joined_codegen.zig");
const Oracle = @import("rv64/joined_fixture_support.zig");
const Events = @import("rv64/cuda_events.zig");
const Slab = jobs.slab;
const Worker = CPU.rv64_gkr_cpu_worker;
const Components = CPU.rv64_gkr_cpu_components;
const WP = CPU.rv64_gkr_worker_protocol;
const ManifestM = CPU.rv64_gkr_manifest;
const DP = CPU.rv64_device_pcs;
const O = core.fields.om31.OM31;
const M31 = core.fields.m31.M31;
const Point = core.circle.CirclePoint(O);

const Block = struct { request: []const u8, jobs: []const u8 = "-", prefix_count: u32 = 0, expected_cpu_segments: usize };
const Manifest = struct {
    schema: []const u8,
    blocks: std.json.ArrayHashMap(Block),
    execution_order: []const u64,
    resources: std.json.Value,
    profile: []const u8 = "conjectured128_b2_q108_p20_fold4",
    immutable_host_key_bytes: usize = 4 << 30,
    immutable_device_bytes: u64 = 512 << 20,
};

fn env(name: []const u8) ?[]const u8 {
    return std.posix.getenv(name);
}
fn envBytes(name: []const u8, default: usize) !usize {
    const text = env(name) orelse return default;
    return std.fmt.parseUnsigned(usize, text, 10) catch error.InvalidParityEnvironment;
}
fn words8(x: O) [8]u32 {
    var w: [8]u32 = undefined;
    for (x.toM31Array(), &w) |m, *o| o.* = m.toU32();
    return w;
}
fn feltOf(w: []const u32) !O {
    var limbs: [8]M31 = undefined;
    for (&limbs, w[0..8]) |*l, x| {
        if (x >= core.fields.m31.Modulus) return error.NoncanonicalFelt;
        l.* = M31.fromCanonical(x);
    }
    return O.fromM31Array(limbs);
}

// ---------------------------------------------------------------------------
// Legacy device inputs live on the legacy GPU: mirror them (peer copy).
// ---------------------------------------------------------------------------
const PeerCopy = *const fn (*anyopaque, c_int, *const anyopaque, c_int, usize, *anyopaque) callconv(.c) c_int;
const Peer = struct {
    copy: PeerCopy,
    source_device: c_int,
    fn mirror(self: Peer, e: *api.Enqueue, dst: [*]u32, src: [*]const u32, words: usize) !void {
        if (self.copy(dst, @intCast(e.device()), src, self.source_device, words * 4, e.stream()) != 0) return error.ParityPeerCopyFailed;
    }
    /// Same-device D2D (staged buffer -> slab).
    fn local(self: Peer, e: *api.Enqueue, dst: [*]u32, src: [*]const u32, words: usize) !void {
        if (self.copy(dst, @intCast(e.device()), src, @intCast(e.device()), words * 4, e.stream()) != 0) return error.ParityPeerCopyFailed;
    }
};

const Done = struct {
    done: bool = false,
    result: anyerror!void = {},
    receipt: api.Receipt = .{},
    fn call(raw: *anyopaque, c: api.Completion) void {
        const d: *@This() = @ptrCast(@alignCast(raw));
        d.receipt = c.receipt;
        d.result = c.result;
        @atomicStore(bool, &d.done, true, .release);
    }
};
fn run(worker: *W.Worker, job: api.Job) !api.Receipt {
    var done = Done{};
    try worker.submit(job, .{ .ctx = &done, .done = Done.call });
    while (!@atomicLoad(bool, &done.done, .acquire)) std.Thread.sleep(50 * std.time.ns_per_us);
    try done.result;
    return done.receipt;
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

const Seg = struct {
    ordinal: u32,
    alpha: O,
    log: u32,
    split: u32,
    roles: CompRoles.Roles,
    items: []Components.Item,
    n_preprocessed: usize = 0,
    // PCS stage
    words: []u32 = &.{},
    oods_field: [33]u32 = @splat(0),
    oods_replay_equal: bool = false,
    roots: [4][32]u8 = undefined,
    shape_counts: [][]u32 = &.{},
    encode: ?NE.Program = null,
    desc: []u32 = &.{},
    table: []u32 = &.{},
    mask_log: u32 = 0,
    host_eval: [8]u32 = @splat(0),
    host_extracted: [8]u32 = @splat(0),
    host_accept: bool = false,
    mirror_word: u32 = G.Verdict.unset,
    mirror_eval_equal: bool = false,
    pcs_gpu_ms: f32 = -1,
    host_check_ns: u64 = 0,
    class_build_ns: u64 = 0,
    error_name: []const u8 = "",
};

const Recorder = struct {
    a: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    segs: std.AutoHashMapUnmanaged(u32, *Seg) = .empty,
    context: *const RC.Context,
    programs: std.AutoHashMapUnmanaged(u32, *NO.Program) = .empty,
    // pending manifest (native_stage_two)
    pending_digest: ?[32]u8 = null,
    pending_shared: [8 * S2D.shared_felts]u32 = @splat(0),
    flat: []S2D.FlatEntry = &.{},
    receipts: [][32]u8 = &.{},
    mains: [][32]u8 = &.{},
    marginals: [][]u32 = &.{},
    digest_conflict: bool = false,
    /// inventory.execution_identity (stage-one.bin bytes [8, 40)).
    execution: [32]u8 = @splat(0),

    fn program(self: *Recorder, id: u32) !*NO.Program {
        if (self.programs.get(id)) |p| return p;
        const d = Oracle.descriptors()[id];
        var art = try JG.record(self.a, d);
        // The recorded DAG is the one the AOT kernel of this case was built from.
        if (!std.mem.eql(u8, &art.program.identity, &self.context.artifacts[id].program.identity)) return error.ParityProgramIdentityMismatch;
        const p = try self.a.create(NO.Program);
        p.* = art.program;
        art.program = undefined;
        self.a.free(art.parameter_slots);
        try self.programs.put(self.a, id, p);
        return p;
    }
};

// ---- resident composition: alpha + roles + items -------------------------
const CompositionDecorator = struct {
    rec: *Recorder,
    inner: *const Worker.ResidentCompositionStage,
    fn stage(self: *CompositionDecorator) Worker.ResidentCompositionStage {
        return .{ .context = self, .evaluate_and_commit = evaluate, .evaluate_and_commit_at_blowup = evaluateAtBlowup };
    }
    fn evaluate(raw: *anyopaque, a: std.mem.Allocator, items: []const Components.Item, alpha: O, log: u32, split: u32, total: usize, trace: *const anyopaque, scope: DP.Scope) anyerror!DP.Tree {
        const self: *CompositionDecorator = @ptrCast(@alignCast(raw));
        return evaluateAtBlowup(raw, a, items, alpha, log, split, total, trace, scope, self.rec.context.log_blowup);
    }
    fn evaluateAtBlowup(raw: *anyopaque, a: std.mem.Allocator, items: []const Components.Item, alpha: O, log: u32, split: u32, total: usize, trace: *const anyopaque, scope: DP.Scope, beta: u32) anyerror!DP.Tree {
        const self: *CompositionDecorator = @ptrCast(@alignCast(raw));
        const tree = if (self.inner.evaluate_and_commit_at_blowup) |f| try f(self.inner.context, a, items, alpha, log, split, total, trace, scope, beta) else try self.inner.evaluate_and_commit(self.inner.context, a, items, alpha, log, split, total, trace, scope);
        const r = self.rec;
        const seg = try r.a.create(Seg);
        seg.* = .{ .ordinal = scope.ordinal, .alpha = alpha, .log = log, .split = split, .roles = try CompRoles.Roles.fromItemsWith(r.a, r.context, items, false), .items = try r.a.dupe(Components.Item, items) };
        r.mutex.lock();
        defer r.mutex.unlock();
        try r.segs.put(r.a, scope.ordinal, seg);
        return tree;
    }
};

// ---- PCS (cpu): the real enqueue-only PCS image, then the legacy proof ---
const PcsCaptureJob = struct {
    a: std.mem.Allocator,
    pcs: *NP.PcsJob,
    sym: NP.Symbols,
    peer: Peer,
    request: DP.Request,
    seed: [9]u32,
    events: *const Events.Api,
    begin: ?*anyopaque = null,
    end: ?*anyopaque = null,
    gpu_ms: f32 = -1,
    layout: Slab.ProofLayout = .{},
    staged_seed: ?api.DeviceBuffer = null,
    staged_host: ?api.DeviceBuffer = null,
    pinned: []u32 = &.{},
    host_words: usize = 0,
    mirror_words: usize = 0,
    oods: [33]u32 = undefined,
    words: []u32 = &.{},
    pub fn classKey(_: *PcsCaptureJob) [32]u8 {
        var k: [32]u8 = @splat(0);
        @memcpy(k[0..14], "rv64-gn-s2-pcs");
        return k;
    }
    fn count(self: *PcsCaptureJob) void {
        for (self.request.trees) |t| for (t.columns) |c| {
            if (c.device != null) self.mirror_words += @as(usize, 1) << @intCast(c.log_size) else self.host_words += c.coefficients.len;
        };
    }
    pub fn footprint(self: *PcsCaptureJob) api.Footprint {
        const g = 64;
        const staged = std.mem.alignForward(usize, self.host_words, g) + 2 * g;
        return .{ .device_words = staged + std.mem.alignForward(usize, self.mirror_words, g) + (5 << 29), .staged_words = staged, .slab_words = self.layout.words, .pinned_words = @as(usize, @intCast(self.pcs.ingressWords())) + self.host_words + 2 * g };
    }
    pub fn stage(self: *PcsCaptureJob, s: *api.Stager) !void {
        if (self.events.create(&self.begin, 0) != 0 or self.events.create(&self.end, 0) != 0 or self.begin == null or self.end == null) return error.CudaTimingFailed;
        const seed = try s.alloc(9);
        try s.upload(seed, &self.seed);
        self.staged_seed = seed;
        if (self.host_words != 0) {
            const host = try s.alloc(self.host_words);
            var at: usize = 0;
            for (self.request.trees, 0..) |t, ti| for (t.columns, 0..) |c, ci| if (c.device == null) {
                const w = @as([*]const u32, @ptrCast(c.coefficients.ptr))[0..c.coefficients.len];
                try s.upload(try host.slice(at, w.len), w);
                try self.pcs.bindColumn(ti, ci, host.ptr + at);
                at += w.len;
            };
            self.staged_host = host;
        }
        self.pinned = try s.pinned(@intCast(self.pcs.ingressWords()));
    }
    pub fn enqueue(self: *PcsCaptureJob, e: *api.Enqueue) !void {
        try e.slab.bind(&self.layout);
        if (self.mirror_words != 0) {
            const mirror = try e.alloc(self.mirror_words);
            var at: usize = 0;
            for (self.request.trees, 0..) |t, ti| for (t.columns, 0..) |c, ci| if (c.device) |d| {
                const n = @as(usize, 1) << @intCast(c.log_size);
                try self.peer.mirror(e, mirror.ptr + at, d.words, n);
                try self.pcs.bindColumn(ti, ci, mirror.ptr + at);
                at += n;
            };
        }
        try e.channel.initFromCheckpoint(self.staged_seed.?);
        if (self.events.record(self.begin.?, e.stream()) != 0) return error.CudaTimingFailed;
        try self.pcs.enqueueOpening(self.sym, e, self.pinned, try e.slab.field(.opaque_words, 0), try e.slab.field(.opaque_words, 1));
        if (self.events.record(self.end.?, e.stream()) != 0) return error.CudaTimingFailed;
    }
    pub fn finish(self: *PcsCaptureJob, view: api.SlabView) !void {
        @memcpy(&self.oods, try Slab.read(view, .opaque_words, 0));
        if (self.events.elapsed(&self.gpu_ms, self.begin.?, self.end.?) != 0) self.gpu_ms = -1;
        self.words = try self.a.dupe(u32, try Slab.read(view, .opaque_words, 1));
    }
    pub fn abort(_: *PcsCaptureJob) void {}
    fn deinit(self: *PcsCaptureJob) void {
        if (self.begin) |ev| _ = self.events.destroy(ev);
        if (self.end) |ev| _ = self.events.destroy(ev);
    }
};

const PcsDecorator = struct {
    rec: *Recorder,
    inner: *const DP.Stage,
    worker: *W.Worker,
    sym: NP.Symbols,
    peer: Peer,
    events: *const Events.Api,
    wide: bool,
    mutex: std.Thread.Mutex = .{},
    fn stage(self: *PcsDecorator) DP.Stage {
        return .{ .context = self, .prove = prove };
    }
    fn prove(raw: *anyopaque, a: std.mem.Allocator, request: DP.Request, channel: *DP.Channel) anyerror!DP.P.ExtendedCommitmentSchemeProof(DP.H) {
        const self: *PcsDecorator = @ptrCast(@alignCast(raw));
        const before = channel.*;
        self.mutex.lock();
        defer self.mutex.unlock();
        const ordinal = if (request.scope) |sc| sc.ordinal else 0xffff_ffff;
        self.rec.mutex.lock();
        const seg_opt = self.rec.segs.get(ordinal);
        self.rec.mutex.unlock();
        var pcs: ?NP.PcsJob = null;
        defer if (pcs) |*p| p.deinit(self.rec.a);
        if (seg_opt) |seg| capture(self, request, before, seg, &pcs) catch |err| {
            seg.error_name = @errorName(err);
        };
        const legacy = try self.inner.prove(self.inner.context, a, request, channel);
        if (seg_opt) |seg| if (seg.error_name.len == 0) self.afterLegacy(request, seg, &legacy, &pcs.?) catch |err| {
            seg.error_name = @errorName(err);
        };
        return legacy;
    }
    /// The job runs FIRST: the legacy PCS is the last consumer of its trees.
    fn capture(self: *PcsDecorator, request: DP.Request, before: DP.Channel, seg: *Seg, out: *?NP.PcsJob) !void {
        const a = self.rec.a;
        if (before.inner.n_draws == 0) return error.ParityNoOodsDraw;
        var pre = before;
        pre.inner.n_draws -= 1;
        var replay = pre;
        const oods = try core.circle.randomSecureFieldPointFor(O, &replay);
        const placeholder = try NP.placeholderPoint();
        const trees = try a.alloc([][]DP.Point, request.points.items.len);
        defer a.free(trees);
        var made: usize = 0;
        defer for (trees[0..made]) |t| {
            for (t) |c| a.free(c);
            a.free(t);
        };
        for (request.points.items, trees) |tree, *o| {
            o.* = try a.alloc([]DP.Point, tree.len);
            made += 1;
            for (tree, o.*) |column, *q| {
                q.* = try a.alloc(DP.Point, column.len);
                for (column, q.*) |p, *r| r.* = p.sub(oods).add(placeholder);
            }
        }
        const framed = DP.Request{ .scope = request.scope, .allocation_observer_domain = request.allocation_observer_domain, .config = request.config, .lifting_log_size = request.lifting_log_size, .trees = request.trees, .points = .{ .items = trees } };
        out.* = try NP.PcsJob.prepare(a, self.sym, framed, placeholder, self.wide);
        const pcs = &out.*.?;
        var seed: [9]u32 = undefined;
        for (0..8) |i| seed[i] = std.mem.readInt(u32, pre.inner.digest[4 * i ..][0..4], .little);
        seed[8] = pre.inner.n_draws;
        var job = PcsCaptureJob{ .a = a, .pcs = pcs, .sym = self.sym, .peer = self.peer, .request = request, .seed = seed, .events = self.events };
        defer job.deinit();
        job.count();
        _ = try job.layout.add(.opaque_words, 0, NP.oods_field_words);
        _ = try job.layout.add(.opaque_words, 1, @intCast(pcs.outputWords()));
        _ = try run(self.worker, api.Job.from(PcsCaptureJob, &job));
        seg.words = job.words;
        seg.oods_field = job.oods;
        seg.pcs_gpu_ms = job.gpu_ms;
        var eq = job.oods[32] == 0;
        for (oods.x.toM31Array(), 0..) |m, i| eq = eq and job.oods[i] == m.v;
        for (oods.y.toM31Array(), 0..) |m, i| eq = eq and job.oods[8 + i] == m.v;
        seg.oods_replay_equal = eq;
        for (request.trees, 0..) |t, i| seg.roots[i] = t.root;
        seg.n_preprocessed = request.trees[0].columns.len;
    }
    /// Class programs (warm-time work, timed) + the host OODS check.
    fn afterLegacy(self: *PcsDecorator, request: DP.Request, seg: *Seg, legacy: *const DP.P.ExtendedCommitmentSchemeProof(DP.H), pcs: *NP.PcsJob) !void {
        _ = request;
        const a = self.rec.a;
        var timer = try std.time.Timer.start();
        const shape = pcs.prepared.metadata.shape;
        seg.encode = try NE.Program.build(a, shape);
        seg.shape_counts = try a.alloc([]u32, shape.trees.len);
        for (shape.trees, seg.shape_counts) |t, *o| o.* = try a.dupe(u32, t.sample_counts);
        // Host engine geometry (the hybrid check's mask_log).
        const set = Components.Set{ .allocator = a, .items = seg.items };
        const handles = try set.verifiers(a);
        defer a.free(handles);
        const comps = core.air.components.ForField(O).Components{ .components = handles, .n_preprocessed_columns = seg.n_preprocessed };
        const comp_log = comps.compositionLogDegreeBound();
        const split = try comps.compositionLogSplit();
        seg.mask_log = core.verifier_types.compositionMaskLogSize(comp_log, split) orelse return error.InvalidStructure;
        if (split != seg.split) return error.ParitySplitMismatch;
        // Composition table: every role's parameters then its hc rows.
        const specs = seg.roles.specs;
        var table: std.ArrayListUnmanaged(u32) = .empty;
        const inputs = try a.alloc(NO.RoleInput, specs.len);
        defer a.free(inputs);
        for (specs, inputs) |s, *in| {
            const p = try self.rec.program(s.id);
            if (s.parameters.len != 8 * p.parameters.len or s.constraints != p.roots.len) return error.ParityRoleShape;
            const params_at: u32 = @intCast(table.items.len);
            try table.appendSlice(a, s.parameters);
            const hc_at: u32 = @intCast(table.items.len);
            try table.appendSlice(a, s.hc);
            in.* = .{ .program = p, .trace_log = s.trace_log, .widths = s.widths, .offsets = s.offsets, .fixed_indices = s.fixed_indices, .aux = s.aux == .hc, .params_at = params_at, .hc_at = if (s.aux == .hc) hc_at else NO.no_table };
        }
        seg.table = try table.toOwnedSlice(a);
        const counts = try a.alloc([]const u32, seg.shape_counts.len);
        defer a.free(counts);
        for (seg.shape_counts, counts) |c, *o| o.* = c;
        seg.desc = try NO.build(a, inputs, .{ .global_log = seg.mask_log, .split = seg.split, .sample_counts = counts, .table_words = seg.table.len });
        seg.class_build_ns = timer.read();
        // Host engine check (the hybrid assembly's), timed.
        timer.reset();
        const point = Point{ .x = try feltOf(seg.oods_field[0..8]), .y = try feltOf(seg.oods_field[8..16]) };
        const expected = try comps.evalCompositionPolynomialAtPoint(point, &legacy.proof.sampled_values, seg.alpha, seg.mask_log);
        const proof = WP.Proof{ .commitment_scheme_proof = legacy.proof };
        const extracted = proof.extractCompositionOodsEvalWithSplit(point, seg.mask_log + split, split) orelse return error.InvalidStructure;
        seg.host_check_ns = timer.read();
        seg.host_eval = words8(expected);
        seg.host_extracted = words8(extracted);
        seg.host_accept = expected.eql(extracted);
        // Host mirror of the kernel on the recorded image.
        const enc = &seg.encode.?;
        const samples = seg.words[enc.get(.off_samples)..][0 .. 8 * @as(usize, enc.get(.sample_count))];
        const m = try NO.hostCheck(a, seg.desc, samples, seg.table, &words8(seg.alpha), &seg.oods_field);
        seg.mirror_word = m.word;
        seg.mirror_eval_equal = m.evaluated != null and m.evaluated.?.eql(expected) and m.extracted.?.eql(extracted);
    }
};

// ---- native_stage_two: the pending manifest ------------------------------
const NativeStageTwo = @typeInfo(@FieldType(Main.ResidentStages, "native_stage_two")).optional.child;
const StageTwoFn = @typeInfo(@FieldType(NativeStageTwo, "stage_two")).pointer.child;
const StageTwoParams = @typeInfo(StageTwoFn).@"fn".params;
const PendingHook = struct {
    rec: *Recorder,
    fn hook(self: *PendingHook) NativeStageTwo {
        return .{ .context = self, .stage_two = stageTwo };
    }
    fn stageTwo(raw: *anyopaque, a: std.mem.Allocator, worker: StageTwoParams[2].type.?, pending: StageTwoParams[3].type.?, index: usize, budget: usize) @typeInfo(StageTwoFn).@"fn".return_type.? {
        const self: *PendingHook = @ptrCast(@alignCast(raw));
        self.capture(pending) catch |err| std.debug.print("GPU_M8_GN_S2 event=pending_capture_failed error={s}\n", .{@errorName(err)});
        // Exactly the legacy CPU stage two (coordinator.stageTwo without the hook).
        if (worker.replay) |*owner| try owner.restore(owner.context, worker);
        return worker.complete(a, pending, index, budget);
    }
    fn capture(self: *PendingHook, pending: anytype) !void {
        const r = self.rec;
        r.mutex.lock();
        defer r.mutex.unlock();
        if (r.pending_digest) |d| {
            if (!std.mem.eql(u8, &d, &pending.digest)) r.digest_conflict = true;
            return;
        }
        r.pending_digest = pending.digest;
        var at: usize = 0;
        const sh = pending.shared;
        inline for (.{ "ram", "kio", "wire" }) |name| {
            const part = @field(sh, name);
            r.pending_shared[8 * at ..][0..8].* = words8(part.offset);
            at += 1;
            for (part.coefficients) |c| {
                r.pending_shared[8 * at ..][0..8].* = words8(c);
                at += 1;
            }
        }
        if (at != S2D.shared_felts) return error.ParitySharedShape;
        const n = pending.entries.len;
        r.flat = try r.a.alloc(S2D.FlatEntry, n);
        r.receipts = try r.a.alloc([32]u8, n);
        r.mains = try r.a.alloc([32]u8, n);
        r.marginals = try r.a.alloc([]u32, n);
        for (pending.entries, 0..) |e, k| {
            const rel = e.global_relations;
            const bits: u32 = @as(u32, @intFromBool(rel.ram)) | (@as(u32, @intFromBool(rel.kio)) << 1) | (@as(u32, @intFromBool(rel.wire)) << 2);
            r.flat[k] = .{ .kind = @intFromEnum(e.kind), .relations = bits, .mass = .{ e.mass.ram, e.mass.kio, e.mass.wire }, .ordinal = e.scope.ordinal, .statement = e.scope.statement, .fixed = e.scope.fixed };
            r.mains[k] = e.scope.main;
            r.receipts[k] = @splat(0);
            r.marginals[k] = &.{};
            if (e.local) |l| {
                r.receipts[k] = l.digest;
                const m = l.artifact.claims_to_verify_by_instance;
                var w = try r.a.alloc(u32, 16 * m.len);
                for (m, 0..) |values, i| {
                    if (values.len != 2) return error.ParityMarginalShape;
                    w[16 * i ..][0..8].* = words8(values[0]);
                    w[16 * i + 8 ..][0..8].* = words8(values[1]);
                }
                r.marginals[k] = w;
                r.flat[k].local_instances = @intCast(m.len);
            }
        }
    }
};

// ---------------------------------------------------------------------------
// The Stage-2 tail job: seal -> shared -> oods_constraint -> encoder -> root_match
// ---------------------------------------------------------------------------

pub const Fault = enum { none, sample, parameter, hc_row, alpha, point_status, noncanonical_sample, composition_sample, descriptor, pcs_header, seal_flag, seal_receipt };
/// Slab words of the tail job.
const T = struct {
    const oods = 0;
    const pcs_status = 1;
    const encode = 2;
    const seal = 3;
    const root_match = 4;
    const diag = 8; // 16
    const shared = 64; // 8 * shared_felts
    const replica = 1024;
};

const TailJob = struct {
    a: std.mem.Allocator,
    seg: *const Seg,
    rec: *const Recorder,
    esym: *const NE.Symbols,
    osym: *const NO.Symbols,
    ssym: *const S2D.SealSymbols,
    events: *const Events.Api,
    peer: Peer,
    fault: Fault = .none,
    // replica + script (host)
    exchange: G.Exchange,
    replica: []u32,
    script: S2D.FlatScript,
    constants: S2D.SealConstants,
    tag: u32,
    region_at: usize = 0,
    // staged
    s_desc: ?api.DeviceBuffer = null,
    s_table: ?api.DeviceBuffer = null,
    s_words: ?api.DeviceBuffer = null,
    s_prog: ?api.DeviceBuffer = null,
    s_alpha: ?api.DeviceBuffer = null,
    s_point: ?api.DeviceBuffer = null,
    s_replica: ?api.DeviceBuffer = null,
    s_ops: ?api.DeviceBuffer = null,
    s_pool: ?api.DeviceBuffer = null,
    s_roots: ?api.DeviceBuffer = null,
    ev: [8]?*anyopaque = @splat(null),
    // results
    out: []u32 = &.{},
    ms: [3]f32 = .{ -1, -1, -1 }, // seal+shared, oods, encode

    pub fn classKey(_: *TailJob) [32]u8 {
        var k: [32]u8 = @splat(0);
        @memcpy(k[0..15], "rv64-gn-s2-tail");
        return k;
    }
    fn regionWords(self: *const TailJob) usize {
        return self.seg.encode.?.regionWords();
    }
    pub fn footprint(self: *TailJob) api.Footprint {
        const g = 64;
        const staged = self.seg.desc.len + self.seg.table.len + self.seg.words.len + self.seg.encode.?.words.len + self.replica.len + self.script.ops.len + self.script.pool.len + 32 + 64 + 40 + 10 * g;
        return .{ .device_words = staged + NO.scratchWords(self.seg.desc) + NE.scratch_words + 8 * S2D.shared_felts + 64 * g, .staged_words = staged, .slab_words = self.region_at + self.regionWords(), .pinned_words = staged };
    }
    fn up(s: *api.Stager, w: []const u32) !api.DeviceBuffer {
        const b = try s.alloc(@max(1, w.len));
        if (w.len != 0) try s.upload(try b.slice(0, w.len), w);
        return try b.slice(0, w.len);
    }
    pub fn stage(self: *TailJob, s: *api.Stager) !void {
        for (&self.ev) |*e| if (self.events.create(e, 0) != 0 or e.* == null) return error.CudaTimingFailed;
        const a = self.a;
        const seg = self.seg;
        const enc = &seg.encode.?;
        // Faults are applied to private copies of the recorded inputs.
        const desc = try a.dupe(u32, seg.desc);
        defer a.free(desc);
        const table = try a.dupe(u32, seg.table);
        defer a.free(table);
        const words = try a.dupe(u32, seg.words);
        defer a.free(words);
        var alpha = words8(seg.alpha);
        var point = seg.oods_field;
        const samples_at = enc.get(.off_samples);
        const first_role = desc[NO.H.header_words..][0..NO.Role.words];
        switch (self.fault) {
            .sample => {
                // The first sample read by the first role.
                const ins = desc[first_role[NO.Role.inputs_at]..];
                var idx: ?u32 = null;
                for (0..first_role[NO.Role.n_inputs]) |i| if (ins[2 * i] == @intFromEnum(NO.InputKind.sample)) {
                    idx = ins[2 * i + 1];
                    break;
                };
                const at = samples_at + 8 * (idx orelse return error.ParityNoSampleRead);
                words[at] = (words[at] + 1) % core.fields.m31.Modulus;
            },
            .parameter => {
                var done = false;
                var r: usize = 0;
                while (r < desc[NO.H.roles] and !done) : (r += 1) {
                    const row = desc[NO.H.header_words + r * NO.Role.words ..][0..NO.Role.words];
                    if (row[NO.Role.n_params] == 0) continue;
                    // A parameter the program reads (first .parameter node).
                    const nodes = desc[row[NO.Role.nodes_at]..];
                    for (0..row[NO.Role.n_nodes]) |k| if (nodes[4 * k] == @intFromEnum(NO.ir.Op.parameter)) {
                        const at = row[NO.Role.params_at] + 8 * nodes[4 * k + 3];
                        table[at] = (table[at] + 1) % core.fields.m31.Modulus;
                        done = true;
                        break;
                    };
                }
                if (!done) return error.ParityNoParameterRead;
            },
            .hc_row => {
                var r: usize = 0;
                while (r < desc[NO.H.roles]) : (r += 1) {
                    const row = desc[NO.H.header_words + r * NO.Role.words ..][0..NO.Role.words];
                    if (row[NO.Role.flags] & NO.flag_aux == 0) continue;
                    table[row[NO.Role.hc_at]] = (table[row[NO.Role.hc_at]] + 1) % core.fields.m31.Modulus;
                    break;
                } else return error.ParityNoAuxRole;
            },
            .alpha => alpha[0] = (alpha[0] + 1) % core.fields.m31.Modulus,
            .point_status => point[32] = 1,
            .noncanonical_sample => {
                const ins = desc[first_role[NO.Role.inputs_at]..];
                for (0..first_role[NO.Role.n_inputs]) |i| if (ins[2 * i] == @intFromEnum(NO.InputKind.sample)) {
                    words[samples_at + 8 * ins[2 * i + 1] + 3] = core.fields.m31.Modulus;
                    break;
                };
            },
            .composition_sample => {
                const at = samples_at + 8 * desc[NO.H.composition_sample];
                words[at] = (words[at] + 1) % core.fields.m31.Modulus;
            },
            .descriptor => desc[NO.H.header_words + NO.Role.regs_at] = 0x7fff_0000,
            .pcs_header => words[0] ^= 1,
            .seal_flag, .seal_receipt, .none => {},
        }
        self.s_desc = try up(s, desc);
        self.s_table = try up(s, table);
        self.s_words = try up(s, words);
        self.s_prog = try up(s, enc.words);
        self.s_alpha = try up(s, &alpha);
        self.s_point = try up(s, &point);
        self.s_replica = try up(s, self.replica);
        self.s_ops = try up(s, self.script.ops);
        self.s_pool = try up(s, self.script.pool);
        var roots: [32]u32 = undefined;
        for (seg.roots, 0..) |r, t| roots[8 * t ..][0..8].* = S2D.words8(r);
        self.s_roots = try up(s, &roots);
    }
    fn mark(self: *TailJob, e: *api.Enqueue, i: usize) !void {
        if (self.events.record(self.ev[i].?, e.stream()) != 0) return error.CudaTimingFailed;
    }
    pub fn enqueue(self: *TailJob, e: *api.Enqueue) !void {
        const slab = e.slab.device;
        const seg = self.seg;
        const enc = &seg.encode.?;
        // Replica into the slab (the seal slot must lie inside its replica).
        const x = try slab.slice(T.replica, self.replica.len);
        try self.peer.local(e, x.ptr, self.s_replica.?.ptr, self.replica.len);
        // ---- seal (flat digest script) + shared draws
        try self.mark(e, 0);
        const seal = self.exchange.seal();
        try S2D.sealFlat(try self.ssym.flatFn(), e.ctx(), self.s_ops.?, self.s_pool.?, self.script.pool_bytes, x, self.tag, try x.slice(seal.offset, 16), try slab.slice(T.seal, 1), self.script.ops);
        try S2D.rcOf(self.ssym.shared(e.ctx(), 0, (try x.slice(seal.offset, 8)).ptr, &self.constants, (try slab.slice(T.shared, 8 * S2D.shared_felts)).ptr, 8 * S2D.shared_felts));
        try self.mark(e, 1);
        // ---- oods_constraint
        try self.mark(e, 2);
        const samples = try self.s_words.?.slice(enc.get(.off_samples), 8 * @as(usize, enc.get(.sample_count)));
        const scratch = try e.alloc(NO.scratchWords(seg.desc));
        try NO.enqueue(self.osym, e.ctx(), self.s_desc.?, samples, self.s_table.?, self.s_alpha.?, self.s_point.?, scratch, try slab.slice(T.oods, 1), try slab.slice(T.diag, 16));
        try self.mark(e, 3);
        // ---- encoder (+ pcs_status, encode_bounds)
        try self.mark(e, 4);
        const escratch = try e.alloc(NE.scratch_words);
        var encoder = NE.Encoder{ .sym = self.esym, .program = self.s_prog.?, .host = enc, .pcs = self.s_words.?, .scratch = escratch, .pcs_status = try slab.slice(T.pcs_status, 1) };
        try encoder.enqueue(e.ctx(), try slab.slice(self.region_at, self.regionWords()), try slab.slice(T.encode, 1));
        try self.mark(e, 5);
        // ---- root_match: the image's tree roots vs the recorded roots
        const r = self.s_roots.?;
        try NE.rootMatch(self.esym, e.ctx(), self.s_words.?, &.{ try r.slice(0, 8), try r.slice(8, 8), try r.slice(16, 8), try r.slice(24, 8) }, seg.roots[0], try slab.slice(T.root_match, 1));
        e.free(escratch);
        e.free(scratch);
    }
    pub fn finish(self: *TailJob, v: api.SlabView) !void {
        self.out = try self.a.dupe(u32, v.words);
        for (0..3) |i| if (self.events.elapsed(&self.ms[i], self.ev[2 * i].?, self.ev[2 * i + 1].?) != 0) {
            self.ms[i] = -1;
        };
    }
    pub fn abort(_: *TailJob) void {}
    fn deinit(self: *TailJob) void {
        for (self.ev) |e| if (e) |x| {
            _ = self.events.destroy(x);
        };
        self.a.free(self.out);
    }
};

/// The exchange replica + flat script of the recorded manifest (every CPU
/// entry a segment, every other entry a two-stage truth root slot).
fn sealInputs(a: std.mem.Allocator, rec: *const Recorder, cpu: usize, tag: u32, fault: Fault) !struct { exchange: G.Exchange, replica: []u32, script: S2D.FlatScript } {
    const n = rec.flat.len;
    var max_claims: u32 = 0;
    for (rec.flat) |e| if (e.local_instances) |m| {
        max_claims = @max(max_claims, 2 * m);
    };
    const ex = G.Exchange{ .segments = @intCast(cpu), .claims_per_segment = @max(1, max_claims), .devices = 1, .truths = @intCast(n - cpu), .receipts = true };
    try ex.validate();
    const x = try a.alloc(u32, ex.words());
    @memset(x, 0);
    const entries = try a.dupe(S2D.FlatEntry, rec.flat);
    defer a.free(entries);
    for (entries, 0..) |*e, k| {
        if (k < cpu) {
            e.segment = @intCast(k);
            const root = try ex.root(@intCast(k));
            x[root.flag] = tag;
            @memcpy(x[root.offset..][0..8], &S2D.words8(rec.mains[k]));
            const rcpt = try ex.receipt(@intCast(k));
            x[rcpt.flag] = tag;
            @memcpy(x[rcpt.offset..][0..8], &S2D.words8(rec.receipts[k]));
            const cl = try ex.claims(@intCast(k));
            x[cl.flag] = tag;
            @memcpy(x[cl.offset..][0..rec.marginals[k].len], rec.marginals[k]);
        } else {
            if (e.local_instances != null) return error.ParityTruthWithLocal;
            e.truth = @intCast(k - cpu);
            const tr = try ex.truthRoot(@intCast(k - cpu));
            x[tr.flag] = tag;
            @memcpy(x[tr.offset..][0..8], &S2D.words8(rec.mains[k]));
        }
    }
    switch (fault) {
        .seal_flag => x[(try ex.truthRoot(0)).flag] = tag +% 1,
        .seal_receipt => x[(try ex.receipt(0)).offset] ^= 1,
        else => {},
    }
    return .{ .exchange = ex, .replica = x, .script = try S2D.FlatScript.build(a, ManifestM.PROFILE, rec.execution, entries, ex) };
}

const NegativeRow = struct { fault: []const u8, expected: []const u8, fired: bool, words: [5]u32, error_name: []const u8 = "" };
const Row = struct {
    ordinal: u32,
    roles: usize,
    nodes: usize,
    samples: u32,
    mask_log: u32,
    split: u32,
    oods_replay_equal: bool,
    host_accept: bool,
    mirror_word: u32,
    mirror_eval_equal: bool,
    words: [5]u32 = @splat(G.Verdict.unset),
    diag_equal: bool = false,
    seal_digest_equal: bool = false,
    shared_equal: bool = false,
    bytes_equal: bool = false,
    legacy_bytes: usize = 0,
    device_bytes: usize = 0,
    seal_shared_gpu_ms: [4]f32 = @splat(-1),
    oods_gpu_ms: [4]f32 = @splat(-1),
    encode_gpu_ms: [4]f32 = @splat(-1),
    stage_ns: [4]u64 = @splat(0),
    enqueue_ns: [4]u64 = @splat(0),
    wait_ns: [4]u64 = @splat(0),
    host_waits: u32 = 0,
    pcs_gpu_ms: f32 = -1,
    host_check_ns: u64 = 0,
    class_build_ns: u64 = 0,
    flat_script_ns: u64 = 0,
    negatives: []const NegativeRow = &.{},
    error_name: []const u8 = "",
};

pub fn main() !void {
    const a = std.heap.page_allocator;
    const argv = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, argv);
    if (argv.len != 3) return error.ExpectedManifestAndOutput;
    const library = env("STWO_RV64_GPU_LIBRARY") orelse return error.ParityRequiresNativeLibrary;
    const addon = env("STWO_RV64_M8_JOBS_LIBRARY") orelse return error.ParityRequiresJobsAddon;
    const out_dir = argv[2];
    try std.fs.cwd().makePath(out_dir);
    const raw = try std.fs.cwd().readFileAlloc(a, argv[1], 1 << 20);
    var parsed = try std.json.parseFromSlice(Manifest, a, raw, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const manifest = parsed.value;
    const block = manifest.execution_order[0];
    var name_buf: [24]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "{d}", .{block});
    const item = manifest.blocks.map.get(name) orelse return error.MissingResidentBatchBlock;

    var libs = try jobs.ops.Libraries.open(library, addon);
    defer libs.close();
    const device = std.fmt.parseUnsigned(u32, env("STWO_RV64_M8_PARITY_DEVICE") orelse "1", 10) catch return error.InvalidParityEnvironment;
    const arena_bytes = try envBytes("STWO_RV64_M8_JOBS_ARENA_BYTES", 20 << 30);
    const worker = try W.Worker.create(a, &libs.ops, .{ .device = device, .arena_words = std.mem.alignBackward(usize, arena_bytes / 4, W.Arena.granule), .pinned_slot_words = try envBytes("STWO_RV64_M8_JOBS_PINNED_BYTES", 1 << 30) / 4 });
    defer worker.destroy();
    const events = try Events.Api.load(&libs.base);
    const esym = try NE.Symbols.load(&libs.addon);
    const osym = try NO.Symbols.load(&libs.addon);
    const ssym = try S2D.SealSymbols.load(&libs.addon);
    _ = try ssym.flatFn();
    const peer = Peer{ .copy = libs.addon.lookup(PeerCopy, "stwo_rv64_jobs_native_peer_copy_v1") orelse return error.ParityRequiresPeerCopy, .source_device = std.fmt.parseUnsigned(c_int, env("STWO_RV64_M8_PARITY_SOURCE_DEVICE") orelse "0", 10) catch return error.InvalidParityEnvironment };
    const Version = *const fn () callconv(.c) u32;
    const wide = if (libs.base.lookup(Version, "stwo_rv64_pcs_request_version")) |v| v() >= 3 else false;
    std.debug.print("GPU_M8_GN_S2 phase=worker_ready device={} wide={}\n", .{ device, wide });

    var config = try Router.Config.fromEnv(a);
    defer config.deinit(a);
    var recycler = Main.Recycler.init(std.heap.smp_allocator, 1 << 30);
    defer recycler.deinit();
    var session = try Main.ResidentSession.init(recycler.allocator(), manifest.immutable_host_key_bytes);
    defer session.deinit();
    const pool = try Pool.createWithBinding(a, library, config, item.expected_cpu_segments, true);
    defer pool.deinit();
    try pool.stages().requireFullyResident();
    var stages = pool.stages();
    var rec = Recorder{ .a = a, .context = &pool.devices[0].composition };
    var comp = CompositionDecorator{ .rec = &rec, .inner = stages.resident_composition orelse return error.ParityRequiresResidentComposition };
    const wrapped_comp = comp.stage();
    stages.resident_composition = &wrapped_comp;
    var pcs = PcsDecorator{ .rec = &rec, .inner = stages.pcs orelse return error.ParityRequiresDevicePcs, .worker = worker, .sym = try NP.Symbols.load(&libs.addon), .peer = peer, .events = &events, .wide = wide };
    const wrapped_pcs = pcs.stage();
    stages.pcs = &wrapped_pcs;
    var hook = PendingHook{ .rec = &rec };
    if (stages.native_stage_two != null) return error.ParityNativeStageTwoAlreadySet;
    stages.native_stage_two = hook.hook();

    const resource_json = try std.json.Stringify.valueAlloc(a, manifest.resources, .{});
    const resources = try std.fs.path.join(a, &.{ out_dir, "resources.json" });
    try std.fs.cwd().writeFile(.{ .sub_path = resources, .data = resource_json });
    const request = try std.fs.path.resolve(a, &.{ std.fs.path.dirname(argv[1]) orelse ".", item.request });
    const proof = try std.fs.path.join(a, &.{ out_dir, "proof" });
    const parts = [_][]const u8{ "rv64-resident", "--security-profile", manifest.profile, "produce-candidate", request, "-", proof, "0", resources };
    var args: [parts.len][:0]u8 = undefined;
    for (parts, &args) |part, *arg| arg.* = try a.dupeZ(u8, part);
    var identity: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("rv64-m8-gn-s2-parity", &identity, .{});
    for (pool.devices, config.caps) |*d, cap| try d.native.beginBlock(identity, .{ .device_bytes = cap, .immutable_bytes = manifest.immutable_device_bytes, .max_scopes = config.scope_limit });
    var timer = try std.time.Timer.start();
    std.debug.print("GPU_M8_GN_S2 phase=legacy_start block={}\n", .{block});
    try Main.runWithResidentArgs(&recycler, &args, stages, &session);
    const legacy_ns = timer.read();
    for (pool.devices) |*d| try d.native.endBlock(identity);
    const digest = rec.pending_digest orelse return error.ParityPendingNotObserved;
    if (rec.digest_conflict) return error.ParityDigestConflict;
    {
        const path = try std.fs.path.join(a, &.{ proof, "stage-one.bin" });
        const bytes = try std.fs.cwd().readFileAlloc(a, path, 1 << 30);
        if (bytes.len < 40 or !std.mem.eql(u8, bytes[0..8], "RV64MGK1")) return error.ParityStageOneShape;
        @memcpy(&rec.execution, bytes[8..40]);
    }
    const cpu = item.expected_cpu_segments;
    std.debug.print("GPU_M8_GN_S2 event=legacy_done block={} segments={} entries={} legacy_ns={}\n", .{ block, rec.segs.count(), rec.flat.len, legacy_ns });
    const tag = G.Exchange.flagTag(1);
    // Host mirror of the flat seal == the pipeline's manifest digest.
    var flat_ns: u64 = 0;
    const host_flat_equal = blk: {
        timer.reset();
        var si = try sealInputs(a, &rec, cpu, tag, .none);
        flat_ns = timer.read();
        defer si.script.deinit();
        defer a.free(si.replica);
        break :blk switch (si.script.hostDigest(si.replica, tag)) {
            .digest => |d| std.mem.eql(u8, &d, &digest),
            .refuse => false,
        };
    };
    std.debug.print("GPU_M8_GN_S2 event=flat_host digest_equal={} script_ns={}\n", .{ host_flat_equal, flat_ns });
    const repeat = std.fmt.parseUnsigned(usize, "3", 10) catch return error.InvalidParityEnvironment;
    const negatives = !std.mem.eql(u8, "1", "0");
    const constants = S2D.sealConstants(@splat(0), rec.execution, @intCast(rec.flat.len), tag);
    var rows: std.ArrayListUnmanaged(Row) = .empty;
    var ordinals: std.ArrayListUnmanaged(u32) = .empty;
    var it = rec.segs.keyIterator();
    while (it.next()) |k| try ordinals.append(a, k.*);
    std.mem.sort(u32, ordinals.items, {}, std.sort.asc(u32));
    for (ordinals.items) |ordinal| {
        const seg = rec.segs.get(ordinal).?;
        var nodes: usize = 0;
        for (0..if (seg.desc.len != 0) seg.desc[NO.H.roles] else 0) |r| nodes += seg.desc[NO.H.header_words + r * NO.Role.words + NO.Role.n_nodes];
        var row = Row{ .ordinal = ordinal, .roles = seg.roles.specs.len, .nodes = nodes, .samples = if (seg.desc.len != 0) seg.desc[NO.H.samples] else 0, .mask_log = seg.mask_log, .split = seg.split, .oods_replay_equal = seg.oods_replay_equal, .host_accept = seg.host_accept, .mirror_word = seg.mirror_word, .mirror_eval_equal = seg.mirror_eval_equal, .pcs_gpu_ms = seg.pcs_gpu_ms, .host_check_ns = seg.host_check_ns, .class_build_ns = seg.class_build_ns, .flat_script_ns = flat_ns, .error_name = seg.error_name };
        if (row.error_name.len == 0) tailOne(a, worker, &rec, seg, &esym, &osym, &ssym, &events, peer, constants, cpu, tag, digest, proof, repeat, negatives, &row) catch |err| {
            row.error_name = @errorName(err);
        };
        std.debug.print("GPU_M8_GN_S2 ordinal={} roles={} nodes={} words={any} diag={} seal={} shared={} bytes={} legacy_bytes={} device_bytes={} oods_ms={any} encode_ms={any} seal_ms={any} host_check_ns={} class_build_ns={} error={s}\n", .{ row.ordinal, row.roles, row.nodes, row.words, row.diag_equal, row.seal_digest_equal, row.shared_equal, row.bytes_equal, row.legacy_bytes, row.device_bytes, row.oods_gpu_ms, row.encode_gpu_ms, row.seal_shared_gpu_ms, row.host_check_ns, row.class_build_ns, row.error_name });
        try rows.append(a, row);
    }
    var all = rows.items.len == cpu and host_flat_equal;
    var negatives_all = true;
    for (rows.items) |r| {
        all = all and r.error_name.len == 0 and r.oods_replay_equal and r.host_accept and r.mirror_word == G.Verdict.accepted and r.mirror_eval_equal and r.diag_equal and r.seal_digest_equal and r.shared_equal and r.bytes_equal and r.host_waits == 1;
        for (r.words) |w| all = all and w == G.Verdict.accepted;
        for (r.negatives) |n| negatives_all = negatives_all and n.fired;
    }
    var text: std.Io.Writer.Allocating = .init(a);
    try std.json.Stringify.value(.{ .schema = "rv64-m8-gn-s2-parity/v1", .block = block, .legacy_native_wall_ns = legacy_ns, .job_device = device, .wide_framing = wide, .native_version = env("STWO_RV64_NATIVE_VERSION") orelse "", .flat_host_digest_equal = host_flat_equal, .all_equal = all, .negatives_all_fired = negatives_all, .segments = rows.items }, .{ .whitespace = .indent_1 }, &text.writer);
    const report = try std.fs.path.join(a, &.{ out_dir, "gn-s2-parity.json" });
    try std.fs.cwd().writeFile(.{ .sub_path = report, .data = text.written() });
    std.debug.print("GPU_M8_GN_S2_DONE block={} segments={} all_equal={} negatives_all_fired={} report={s}\n", .{ block, rows.items.len, all, negatives_all, report });
    if (!all) return error.GnS2ParityMismatch;
    if (negatives and !negatives_all) return error.GnS2NegativeNotFired;
}

fn runTail(a: std.mem.Allocator, worker: *W.Worker, rec: *const Recorder, seg: *const Seg, esym: *const NE.Symbols, osym: *const NO.Symbols, ssym: *const S2D.SealSymbols, events: *const Events.Api, peer: Peer, constants: S2D.SealConstants, cpu: usize, tag: u32, fault: Fault) !struct { job: TailJob, receipt: api.Receipt } {
    const si = try sealInputs(a, rec, cpu, tag, fault);
    var job = TailJob{ .a = a, .seg = seg, .rec = rec, .esym = esym, .osym = osym, .ssym = ssym, .events = events, .peer = peer, .fault = fault, .exchange = si.exchange, .replica = si.replica, .script = si.script, .constants = constants, .tag = tag };
    job.region_at = std.mem.alignForward(usize, T.replica + si.replica.len, 64);
    errdefer {
        job.script.deinit();
        a.free(job.replica);
        job.deinit();
    }
    const receipt = try run(worker, api.Job.from(TailJob, &job));
    return .{ .job = job, .receipt = receipt };
}
fn freeTail(a: std.mem.Allocator, job: *TailJob) void {
    job.script.deinit();
    a.free(job.replica);
    job.deinit();
}

fn tailOne(a: std.mem.Allocator, worker: *W.Worker, rec: *const Recorder, seg: *const Seg, esym: *const NE.Symbols, osym: *const NO.Symbols, ssym: *const S2D.SealSymbols, events: *const Events.Api, peer: Peer, constants: S2D.SealConstants, cpu: usize, tag: u32, digest: [32]u8, proof_dir: []const u8, repeat: usize, negatives: bool, row: *Row) !void {
    if (seg.encode == null or seg.desc.len == 0 or seg.words.len == 0) return error.ParitySegmentNotRecorded;
    var nb: [64]u8 = undefined;
    const path = try std.fs.path.join(a, &.{ proof_dir, try std.fmt.bufPrint(&nb, "cpu-{d}.bin", .{seg.ordinal}) });
    const legacy = try std.fs.cwd().readFileAlloc(a, path, 1 << 30);
    defer a.free(legacy);
    row.legacy_bytes = legacy.len;
    for (0..@max(1, @min(repeat, 4))) |k| {
        var t = try runTail(a, worker, rec, seg, esym, osym, ssym, events, peer, constants, cpu, tag, .none);
        defer freeTail(a, &t.job);
        row.seal_shared_gpu_ms[k] = t.job.ms[0];
        row.oods_gpu_ms[k] = t.job.ms[1];
        row.encode_gpu_ms[k] = t.job.ms[2];
        row.stage_ns[k] = t.receipt.stage_ns;
        row.enqueue_ns[k] = t.receipt.enqueue_ns;
        row.wait_ns[k] = t.receipt.wait_ns;
        row.host_waits = t.receipt.host_waits;
        if (k != 0) continue;
        const out = t.job.out;
        row.words = .{ out[T.oods], out[T.pcs_status], out[T.encode], out[T.seal], out[T.root_match] };
        row.diag_equal = std.mem.eql(u32, out[T.diag..][0..8], &seg.host_eval) and std.mem.eql(u32, out[T.diag + 8 ..][0..8], &seg.host_extracted);
        const seal = t.job.exchange.seal();
        row.seal_digest_equal = std.mem.eql(u32, out[T.replica + seal.offset ..][0..8], &S2D.words8(digest));
        row.shared_equal = std.mem.eql(u32, out[T.shared..][0 .. 8 * S2D.shared_felts], &rec.pending_shared);
        const region = out[t.job.region_at..];
        const n = region[0];
        row.device_bytes = n;
        row.bytes_equal = n == legacy.len and std.mem.eql(u8, std.mem.sliceAsBytes(region[1..])[0..n], legacy);
    }
    if (!negatives) return;
    // index: oods, pcs_status, encode_bounds, global_seal, root_match
    const Case = struct { fault: Fault, expect: u5, allow: u5 = 0, name: []const u8 };
    const cases = [_]Case{
        .{ .fault = .sample, .expect = 1, .name = "oods_constraint" },
        .{ .fault = .parameter, .expect = 1, .name = "oods_constraint" },
        .{ .fault = .hc_row, .expect = 1, .name = "oods_constraint" },
        .{ .fault = .alpha, .expect = 1, .name = "oods_constraint" },
        .{ .fault = .point_status, .expect = 1, .name = "oods_constraint" },
        // The encoder refuses non-canonical image values too (encode_bounds).
        .{ .fault = .noncanonical_sample, .expect = 1, .allow = 4, .name = "oods_constraint" },
        .{ .fault = .composition_sample, .expect = 1, .name = "oods_constraint" },
        .{ .fault = .descriptor, .expect = 1, .name = "oods_constraint" },
        .{ .fault = .pcs_header, .expect = 2, .allow = 4 | 16, .name = "pcs_status" },
        .{ .fault = .seal_flag, .expect = 8, .name = "global_seal" },
        .{ .fault = .seal_receipt, .expect = 0, .name = "seal digest != manifest digest" },
    };
    var list: std.ArrayListUnmanaged(NegativeRow) = .empty;
    for (cases) |c| {
        var neg = NegativeRow{ .fault = @tagName(c.fault), .expected = c.name, .fired = false, .words = @splat(G.Verdict.unset) };
        if (runTail(a, worker, rec, seg, esym, osym, ssym, events, peer, constants, cpu, tag, c.fault)) |res| {
            var t = res;
            defer freeTail(a, &t.job);
            const out = t.job.out;
            neg.words = .{ out[T.oods], out[T.pcs_status], out[T.encode], out[T.seal], out[T.root_match] };
            var ok = true;
            for (neg.words, 0..) |w, i| {
                const bit = @as(u5, 1) << @intCast(i);
                if (c.expect & bit != 0) ok = ok and w != G.Verdict.accepted and w != G.Verdict.unset else if (c.allow & bit == 0) ok = ok and w == G.Verdict.accepted;
            }
            if (c.fault == .seal_receipt) ok = ok and !std.mem.eql(u32, out[T.replica + t.job.exchange.seal().offset ..][0..8], &S2D.words8(digest));
            neg.fired = ok;
        } else |err| neg.error_name = @errorName(err);
        // A fault the segment cannot express (no aux role) is skipped, not counted.
        if (std.mem.eql(u8, neg.error_name, "ParityNoAuxRole")) continue;
        std.debug.print("GPU_M8_GN_S2_NEGATIVE ordinal={} fault={s} expected={s} fired={} words={any} error={s}\n", .{ seg.ordinal, neg.fault, neg.expected, neg.fired, neg.words, neg.error_name });
        try list.append(a, neg);
    }
    row.negatives = list.items;
}

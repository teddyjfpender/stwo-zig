//! Unchanged legacy composition/PCS capture and Stage-2 semantic observation.
const CPU = @import("stwo_riscv_cpu_integration");
const CompRoles = @import("stwo_riscv_cuda_integration").rv64.execution.composition.roles;
const Components = CPU.rv64_gkr_cpu_components;
const DP = CPU.rv64_device_pcs;
const Events = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.cuda_events;
const G = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.gpu_native;
const JG = @import("stwo_riscv_cuda_integration").rv64.execution.composition.joined_codegen;
const Main = ProductCPU.rv64_ethereum_gkr_main;
const NE = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_encode;
const NO = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_encode_oods;
const NP = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_pcs;
const O = core.fields.om31.OM31;
const Oracle = @import("stwo_riscv_cuda_integration").rv64.execution.composition.sources;
const Peer = @import("gn_s2_common.zig").Peer;
const Point = core.circle.CirclePoint(O);
const ProductCPU = @import("ethereum_cpu_component");
const RC = @import("stwo_riscv_cuda_integration").rv64.resident_composition;
const S2D = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_device_stage2;
const Slab = jobs.slab;
const W = jobs.worker;
const WP = CPU.rv64_gkr_worker_protocol;
const Worker = CPU.rv64_gkr_cpu_worker;
const api = jobs.api;
const core = @import("stwo_core");
const feltOf = @import("gn_s2_common.zig").feltOf;
const jobs = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.runtime;
const run = @import("gn_s2_common.zig").run;
const std = @import("std");
const words8 = @import("gn_s2_common.zig").words8;

pub const Seg = struct {
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

pub const Recorder = struct {
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

    pub fn program(self: *Recorder, id: u32) !*NO.Program {
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
pub const CompositionDecorator = struct {
    rec: *Recorder,
    inner: *const Worker.ResidentCompositionStage,
    pub fn stage(self: *CompositionDecorator) Worker.ResidentCompositionStage {
        return .{ .context = self, .evaluate_and_commit = evaluate, .evaluate_and_commit_at_blowup = evaluateAtBlowup };
    }
    pub fn evaluate(raw: *anyopaque, a: std.mem.Allocator, items: []const Components.Item, alpha: O, log: u32, split: u32, total: usize, trace: *const anyopaque, scope: DP.Scope) anyerror!DP.Tree {
        const self: *CompositionDecorator = @ptrCast(@alignCast(raw));
        return evaluateAtBlowup(raw, a, items, alpha, log, split, total, trace, scope, self.rec.context.log_blowup);
    }
    pub fn evaluateAtBlowup(raw: *anyopaque, a: std.mem.Allocator, items: []const Components.Item, alpha: O, log: u32, split: u32, total: usize, trace: *const anyopaque, scope: DP.Scope, beta: u32) anyerror!DP.Tree {
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
pub const PcsCaptureJob = struct {
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
    pub fn count(self: *PcsCaptureJob) void {
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
    pub fn deinit(self: *PcsCaptureJob) void {
        if (self.begin) |ev| _ = self.events.destroy(ev);
        if (self.end) |ev| _ = self.events.destroy(ev);
    }
};

pub const PcsDecorator = struct {
    rec: *Recorder,
    inner: *const DP.Stage,
    worker: *W.Worker,
    sym: NP.Symbols,
    peer: Peer,
    events: *const Events.Api,
    wide: bool,
    mutex: std.Thread.Mutex = .{},
    pub fn stage(self: *PcsDecorator) DP.Stage {
        return .{ .context = self, .prove = prove };
    }
    pub fn prove(raw: *anyopaque, a: std.mem.Allocator, request: DP.Request, channel: *DP.Channel) anyerror!DP.P.ExtendedCommitmentSchemeProof(DP.H) {
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
    pub fn capture(self: *PcsDecorator, request: DP.Request, before: DP.Channel, seg: *Seg, out: *?NP.PcsJob) !void {
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
    pub fn afterLegacy(self: *PcsDecorator, request: DP.Request, seg: *Seg, legacy: *const DP.P.ExtendedCommitmentSchemeProof(DP.H), pcs: *NP.PcsJob) !void {
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
pub const NativeStageTwo = @typeInfo(@FieldType(Main.ResidentStages, "native_stage_two")).optional.child;
pub const StageTwoFn = @typeInfo(@FieldType(NativeStageTwo, "stage_two")).pointer.child;
pub const StageTwoParams = @typeInfo(StageTwoFn).@"fn".params;
pub const PendingHook = struct {
    rec: *Recorder,
    pub fn hook(self: *PendingHook) NativeStageTwo {
        return .{ .context = self, .stage_two = stageTwo };
    }
    pub fn stageTwo(raw: *anyopaque, a: std.mem.Allocator, worker: StageTwoParams[2].type.?, pending: StageTwoParams[3].type.?, index: usize, budget: usize) @typeInfo(StageTwoFn).@"fn".return_type.? {
        const self: *PendingHook = @ptrCast(@alignCast(raw));
        self.capture(pending) catch |err| std.debug.print("GPU_M8_GN_S2 event=pending_capture_failed error={s}\n", .{@errorName(err)});
        // Exactly the legacy CPU stage two (coordinator.stageTwo without the hook).
        if (worker.replay) |*owner| try owner.restore(owner.context, worker);
        return worker.complete(a, pending, index, budget);
    }
    pub fn capture(self: *PendingHook, pending: anytype) !void {
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

//! Unchanged composition parity jobs for CPU and service components.
const CPU = @import("stwo_riscv_cpu_integration");
const CompRoles = @import("stwo_riscv_cuda_integration").rv64.execution.composition.roles;
const Compare = @import("native_common.zig").Compare;
const DP = CPU.rv64_device_pcs;
const Done = @import("native_common.zig").Done;
const Events = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.cuda_events;
const GlobalDecorator = @import("native_global_commit.zig").GlobalDecorator;
const NComp = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_composition;
const O = @import("stwo_core").fields.om31.OM31;
const Peer = @import("native_common.zig").Peer;
const RC = @import("stwo_riscv_cuda_integration").rv64.resident_composition;
const S2 = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_stage2;
const Slab = jobs.slab;
const Trace = @import("stwo_prover_engine").air.component_prover.ForField(O).Trace;
const TruthComposition = CPU.rv64_gkr_truth_device_composition;
const W = jobs.worker;
const Worker = CPU.rv64_gkr_cpu_worker;
const api = jobs.api;
const check = @import("native_common.zig").check;
const jobs = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.runtime;
const std = @import("std");
const wordsEqual = @import("native_gkr.zig").wordsEqual;

pub const CompositionRow = struct {
    kind: []const u8 = "cpu",
    ordinal: u32,
    /// Claim slots patched on the device (roles x claim parameters present).
    device_claims: usize = 0,
    /// Claims in the Stage2 claims buffer (native_claims.Layout.count).
    claim_count: u32 = 0,
    /// Where the device claims buffer came from: "native_global" (the
    /// native_global jobs' output for this segment, in the Stage2 layout),
    /// "host" (the roles builder's host mirror) or "none".
    claims_source: []const u8 = "none",
    /// The native_global claims equal the host claims of the items, word for
    /// word, in the Stage2 layout (only with claims_source=native_global).
    claims_match_host: bool = false,
    /// The job ran the producer through Stage2's composition seam
    /// (S2.NativeComposition.producer(), S2.Composition.Inputs).
    through_seam: bool = false,
    /// CUDA-event GPU time of the composition producer (mirrors excluded).
    gpu_ms: f32 = -1,
    roles: usize,
    log: u32,
    split: u32,
    beta: u32,
    total: usize,
    columns: [3]usize,
    host_columns: usize,
    root_equal: bool = false,
    coefficient_mismatches: u32 = 0xffffffff,
    first_mismatch: u32 = 0,
    status: u32 = 0xffffffff,
    legacy_ns: u64 = 0,
    job_stage_ns: u64 = 0,
    job_enqueue_ns: u64 = 0,
    job_wait_ns: u64 = 0,
    host_waits: u32 = 0,
    arena_peak_words: u64 = 0,
    declared_device_words: u64 = 0,
    error_name: []const u8 = "",
};

/// One segment's native composition as a job (jobs/native_composition.zig):
/// the legacy FIXED/MAIN/INTER coefficients mirrored into the job arena (host
/// columns staged), the legacy host alpha staged as the "device-drawn"
/// coefficient (Stage2 draws it on the device channel; the producer only ever
/// sees the device buffer), then root (slab) and the kept coefficient chunks
/// compared on device with the legacy output.
pub const CompositionParityJob = struct {
    plan: *NComp.Plan,
    sym: NComp.Symbols,
    compare: Compare,
    peer: Peer,
    /// Per tree, per original column: legacy device pointer or host words.
    device: [3][]const ?[*]const u32,
    host: [3][]const []const u32,
    logs: [3][]const u32,
    alpha: [8]u32,
    legacy_output: [*]const u32,
    a: std.mem.Allocator,
    /// The device claims buffer contents (Stage2 layout), staged in phase 1:
    /// the native_global jobs' output for this segment, or the host mirror.
    claims: []const u32 = &.{},
    /// CUDA events around the producer's enqueued work (after the mirrors,
    /// before the comparison): GPU time of the composition itself.
    /// Created in `stage` (the worker thread: the job device's context is current).
    events: *const Events.Api,
    begin: ?*anyopaque = null,
    end: ?*anyopaque = null,
    gpu_ms: f32 = -1,
    layout: Slab.ProofLayout = .{},
    staged_alpha: ?api.DeviceBuffer = null,
    staged_claims: ?api.DeviceBuffer = null,
    staged_host: ?api.DeviceBuffer = null,
    host_offsets: [3][]usize = .{ &.{}, &.{}, &.{} },
    /// Per tree, per original column: offset in the job's combined column
    /// buffer (S2.Composition.Committed views, as Stage2 hands them over).
    view_offsets: [3][]usize = .{ &.{}, &.{}, &.{} },
    root: [8]u32 = undefined,
    status: u32 = 0xffffffff,
    mismatch: [2]u32 = .{ 0xffffffff, 0 },
    pub fn hostWords(self: *const CompositionParityJob) usize {
        var words: usize = 0;
        for (self.host) |tree| for (tree) |h| {
            words += h.len;
        };
        return words;
    }
    pub fn mirrorWords(self: *const CompositionParityJob) usize {
        var words: usize = 0;
        for (self.device, self.logs) |tree, logs| for (tree, logs) |d, log| if (d != null) {
            words += @as(usize, 1) << @intCast(log);
        };
        return words;
    }
    pub fn classKey(self: *CompositionParityJob) [32]u8 {
        return self.plan.classKey();
    }
    pub fn footprint(self: *CompositionParityJob) api.Footprint {
        const g = 64;
        const host = std.mem.alignForward(usize, self.hostWords(), g);
        const staged = self.plan.stagedWords() + host + std.mem.alignForward(usize, self.claims.len, g) + 3 * g;
        const mirror = std.mem.alignForward(usize, self.mirrorWords() + self.hostWords(), g) + std.mem.alignForward(usize, self.plan.coefficientWords(), g);
        return .{ .device_words = staged + self.plan.persistentWords() + mirror + self.plan.enqueueWords() + 8 * g, .staged_words = staged, .slab_words = self.layout.words, .pinned_words = self.plan.pinnedWords() + self.hostWords() + self.claims.len + 64 };
    }
    pub fn stage(self: *CompositionParityJob, s: *api.Stager) !void {
        if (self.events.create(&self.begin, 0) != 0 or self.events.create(&self.end, 0) != 0 or self.begin == null or self.end == null) return error.CudaTimingFailed;
        try self.plan.stage(s);
        const alpha = try s.alloc(8);
        try s.upload(alpha, &self.alpha);
        self.staged_alpha = alpha;
        if (self.claims.len != 0) {
            const claims = try s.alloc(self.claims.len);
            try s.upload(claims, self.claims);
            self.staged_claims = claims;
        }
        const words = self.hostWords();
        if (words != 0) {
            const staged = try s.alloc(words);
            var at: usize = 0;
            for (self.host, 0..) |tree, t| {
                self.host_offsets[t] = try self.a.alloc(usize, tree.len);
                for (tree, self.host_offsets[t]) |h, *o| {
                    o.* = at;
                    if (h.len != 0) try s.upload(try staged.slice(at, h.len), h);
                    at += h.len;
                }
            }
            self.staged_host = staged;
        }
    }
    pub fn enqueue(self: *CompositionParityJob, e: *api.Enqueue) !void {
        try e.slab.bind(&self.layout);
        // One buffer holds every column (legacy device columns peer-mirrored,
        // host columns copied from their staged words), so each tree is a
        // Committed view (base + offsets) exactly as Stage2 passes it.
        const mirror = try e.alloc(@max(self.mirrorWords() + self.hostWords(), 1));
        var host_at = self.mirrorWords();
        var pointers: [3][][*]const u32 = undefined;
        var made: usize = 0;
        defer for (pointers[0..made]) |p| self.a.free(p);
        var at: usize = 0;
        for (0..3) |t| {
            pointers[t] = try self.a.alloc([*]const u32, self.device[t].len);
            made += 1;
            self.view_offsets[t] = try self.a.alloc(usize, self.device[t].len);
            var c: usize = 0;
            while (c < self.device[t].len) {
                const log = self.logs[t][c];
                if (self.device[t][c]) |first| {
                    // One peer copy per run of adjacent legacy columns.
                    var end = c + 1;
                    var words: usize = @as(usize, 1) << @intCast(log);
                    while (end < self.device[t].len) : (end += 1) {
                        const next = self.device[t][end] orelse break;
                        if (next != first + words) break;
                        words += @as(usize, 1) << @intCast(self.logs[t][end]);
                    }
                    try self.peer.mirror(e, mirror.ptr + at, first, words);
                    var offset: usize = 0;
                    for (c..end) |k| {
                        pointers[t][k] = mirror.ptr + at + offset;
                        offset += @as(usize, 1) << @intCast(self.logs[t][k]);
                    }
                    at += words;
                    c = end;
                } else {
                    const words = @as(usize, 1) << @intCast(log);
                    const from = (self.staged_host orelse return error.CompositionParityHostNotStaged).ptr + self.host_offsets[t][c];
                    try check(self.sym.copy_d2d(e.ctx(), mirror.ptr + host_at, from, words * 4));
                    pointers[t][c] = mirror.ptr + host_at;
                    host_at += words;
                    c += 1;
                }
            }
            for (pointers[t], self.view_offsets[t]) |p, *o| o.* = (@intFromPtr(p) - @intFromPtr(mirror.ptr)) / 4;
        }
        const status = try e.slab.field(.status, 0);
        // Poison the status: the producer must clear it itself.
        try check(self.sym.memset(e.ctx(), status.ptr, 0xff, 4));
        var views: [3]S2.Composition.Committed = undefined;
        for (&views, self.view_offsets) |*v, offsets| v.* = .{ .offsets = offsets, .tree = .{ .coefficients = mirror, .root = mirror.ptr } };
        var producer = S2.NativeComposition{ .plan = self.plan, .sym = self.sym };
        const seam = producer.producer();
        const claims = self.staged_claims orelse api.DeviceBuffer{ .ptr = mirror.ptr, .words = 0 };
        if (self.events.record(self.begin.?, e.stream()) != 0) return error.CudaTimingFailed;
        const committed = try seam.enqueue(seam.ctx, e, .{ .alpha = self.staged_alpha.?, .claims = claims, .status = status, .root_out = try e.slab.field(.root, 0), .trees = views });
        const out = committed.tree;
        if (self.events.record(self.end.?, e.stream()) != 0) return error.CudaTimingFailed;
        const reference = try e.alloc(self.plan.coefficientWords());
        try self.peer.mirror(e, reference.ptr, self.legacy_output, self.plan.coefficientWords());
        try check(self.compare(e.ctx(), 0, reference.ptr, out.coefficients.ptr, self.plan.coefficientWords(), (try e.slab.field(.opaque_words, 0)).ptr));
    }
    pub fn finish(self: *CompositionParityJob, view: api.SlabView) !void {
        @memcpy(&self.root, try Slab.read(view, .root, 0));
        self.status = (try Slab.read(view, .status, 0))[0];
        @memcpy(&self.mismatch, (try Slab.read(view, .opaque_words, 0))[0..2]);
        if (self.events.elapsed(&self.gpu_ms, self.begin.?, self.end.?) != 0) self.gpu_ms = -1;
    }
    pub fn abort(_: *CompositionParityJob) void {}
    pub fn deinit(self: *CompositionParityJob) void {
        if (self.begin) |ev| _ = self.events.destroy(ev);
        if (self.end) |ev| _ = self.events.destroy(ev);
        for (self.host_offsets) |o| if (o.len != 0) self.a.free(o);
        for (self.view_offsets) |o| if (o.len != 0) self.a.free(o);
    }
};

pub const CompositionDecorator = struct {
    a: std.mem.Allocator,
    inner: *const Worker.ResidentCompositionStage,
    truth_inner: ?TruthComposition.Stage = null,
    events: *const Events.Api,
    /// STWO_RV64_M8_PARITY_DEVICE_CLAIMS=1: claim parameters are zeroed in
    /// the staged table and patched on the device from the Stage2 claims
    /// buffer (native_claims.Layout).
    device_claims: bool = false,
    /// Source of that buffer: the native_global jobs of the same segment
    /// (installed decorator), else the roles builder's host mirror.
    global: ?*GlobalDecorator = null,
    /// The legacy composition backend (kernel metadata) of the pool's device.
    context: *const RC.Context,
    worker: *W.Worker,
    symbols: NComp.Symbols,
    compare: Compare,
    peer: Peer,
    mutex: std.Thread.Mutex = .{},
    rows: std.ArrayListUnmanaged(CompositionRow) = .empty,
    pub fn stage(self: *CompositionDecorator) Worker.ResidentCompositionStage {
        return .{ .context = self, .evaluate_and_commit = evaluate, .evaluate_and_commit_at_blowup = evaluateAtBlowup };
    }
    pub fn evaluate(raw: *anyopaque, a: std.mem.Allocator, items: []const CPU.rv64_gkr_cpu_components.Item, alpha: O, log: u32, split: u32, total: usize, trace: *const anyopaque, scope: DP.Scope) anyerror!DP.Tree {
        const self: *CompositionDecorator = @ptrCast(@alignCast(raw));
        return evaluateAtBlowup(raw, a, items, alpha, log, split, total, trace, scope, self.context.log_blowup);
    }
    pub fn evaluateAtBlowup(raw: *anyopaque, a: std.mem.Allocator, items: []const CPU.rv64_gkr_cpu_components.Item, alpha: O, log: u32, split: u32, total: usize, trace_raw: *const anyopaque, scope: DP.Scope, beta: u32) anyerror!DP.Tree {
        const self: *CompositionDecorator = @ptrCast(@alignCast(raw));
        var timer = try std.time.Timer.start();
        const tree = if (self.inner.evaluate_and_commit_at_blowup) |f| try f(self.inner.context, a, items, alpha, log, split, total, trace_raw, scope, beta) else try self.inner.evaluate_and_commit(self.inner.context, a, items, alpha, log, split, total, trace_raw, scope);
        const legacy_ns = timer.read();
        self.mutex.lock();
        defer self.mutex.unlock();
        var row = CompositionRow{ .ordinal = scope.ordinal, .roles = items.len, .log = log, .split = split, .beta = beta, .total = total, .columns = .{ 0, 0, 0 }, .host_columns = 0, .legacy_ns = legacy_ns };
        var produced: ?GlobalDecorator.Produced = if (self.device_claims) if (self.global) |g| g.take(scope.ordinal) else null else null;
        defer if (produced) |*p| p.words.deinit(self.a);
        if (CompRoles.Roles.fromItemsWith(self.a, self.context, items, self.device_claims)) |roles| {
            var owned = roles;
            defer owned.deinit();
            for (owned.specs) |spec| row.device_claims += spec.claim_slots.len;
            row.claim_count = owned.claim_count;
            var claims: []const u32 = &.{};
            if (self.device_claims) {
                claims = owned.claims.items;
                row.claims_source = "host";
                if (produced) |p| {
                    if (!p.complete or p.words.items.len != owned.claims.items.len) {
                        row.error_name = "CompositionParityProducedClaimsShape";
                    } else {
                        claims = p.words.items;
                        row.claims_source = "native_global";
                        row.claims_match_host = std.mem.eql(u32, p.words.items, owned.claims.items);
                    }
                }
            }
            row.through_seam = true;
            if (row.error_name.len == 0) self.check(owned.specs, claims, alpha, log, split, total, @ptrCast(@alignCast(trace_raw)), beta, tree, &row) catch |err| {
                row.error_name = @errorName(err);
            };
        } else |err| row.error_name = @errorName(err);
        std.debug.print("GPU_M8_NATIVE_COMPOSITION_PARITY kind={s} ordinal={} roles={} log={} beta={} claim_slots={} claim_count={} claims_source={s} claims_match_host={} through_seam={} root_equal={} coefficient_mismatches={} status={} gpu_ms={d:.3} legacy_ns={} job_enqueue_ns={} job_wait_ns={} host_waits={} arena_peak_words={} error={s}\n", .{ row.kind, row.ordinal, row.roles, row.log, row.beta, row.device_claims, row.claim_count, row.claims_source, row.claims_match_host, row.through_seam, row.root_equal, row.coefficient_mismatches, row.status, row.gpu_ms, row.legacy_ns, row.job_enqueue_ns, row.job_wait_ns, row.host_waits, row.arena_peak_words, row.error_name });
        try self.rows.append(self.a, row);
        return tree;
    }
    pub fn truthStage(self: *CompositionDecorator) TruthComposition.Stage {
        return .{ .context = self, .evaluate_and_commit = truthEvaluate, .evaluate_and_commit_at_blowup = truthEvaluateAtBlowup };
    }
    pub fn truthEvaluate(raw: *anyopaque, a: std.mem.Allocator, bound: TruthComposition.Roles, alpha: O, log: u32, split: u32, total: usize, trace: *const anyopaque, scope: DP.Scope) anyerror!DP.Tree {
        const self: *CompositionDecorator = @ptrCast(@alignCast(raw));
        return truthEvaluateAtBlowup(raw, a, bound, alpha, log, split, total, trace, scope, self.context.log_blowup);
    }
    pub fn truthEvaluateAtBlowup(raw: *anyopaque, a: std.mem.Allocator, bound: TruthComposition.Roles, alpha: O, log: u32, split: u32, total: usize, trace_raw: *const anyopaque, scope: DP.Scope, beta: u32) anyerror!DP.Tree {
        const self: *CompositionDecorator = @ptrCast(@alignCast(raw));
        const inner = self.truth_inner.?;
        var timer = try std.time.Timer.start();
        const tree = if (inner.evaluate_and_commit_at_blowup) |f| try f(inner.context, a, bound, alpha, log, split, total, trace_raw, scope, beta) else try inner.evaluate_and_commit(inner.context, a, bound, alpha, log, split, total, trace_raw, scope);
        const legacy_ns = timer.read();
        self.mutex.lock();
        defer self.mutex.unlock();
        const count: usize = switch (bound) {
            .classic => |v| v.len,
            .delegated => 1,
        };
        var row = CompositionRow{ .kind = if (bound == .classic) "truth-classic" else "truth-delegated", .ordinal = scope.ordinal, .roles = count, .log = log, .split = split, .beta = beta, .total = total, .columns = .{ 0, 0, 0 }, .host_columns = 0, .legacy_ns = legacy_ns };
        if (CompRoles.Roles.fromTruth(self.a, self.context, bound)) |roles| {
            var owned = roles;
            defer owned.deinit();
            row.through_seam = true;
            self.check(owned.specs, &.{}, alpha, log, split, total, @ptrCast(@alignCast(trace_raw)), beta, tree, &row) catch |err| {
                row.error_name = @errorName(err);
            };
        } else |err| row.error_name = @errorName(err);
        std.debug.print("GPU_M8_NATIVE_COMPOSITION_PARITY kind={s} ordinal={} roles={} log={} beta={} root_equal={} coefficient_mismatches={} status={} gpu_ms={d:.3} legacy_ns={} job_enqueue_ns={} job_wait_ns={} host_waits={} arena_peak_words={} error={s}\n", .{ row.kind, row.ordinal, row.roles, row.log, row.beta, row.root_equal, row.coefficient_mismatches, row.status, row.gpu_ms, row.legacy_ns, row.job_enqueue_ns, row.job_wait_ns, row.host_waits, row.arena_peak_words, row.error_name });
        try self.rows.append(self.a, row);
        return tree;
    }
    pub fn check(self: *CompositionDecorator, specs: []const NComp.RoleSpec, claims: []const u32, alpha: O, log: u32, split: u32, total: usize, trace: *const Trace, beta: u32, tree: DP.Tree, row: *CompositionRow) !void {
        const a = self.a;
        if (trace.polys.items.len != 3) return error.CompositionParityTraceShape;
        var logs: [3][]u32 = undefined;
        var device: [3][]?[*]const u32 = undefined;
        var host: [3][][]const u32 = undefined;
        var made: usize = 0;
        defer for (0..made) |t| {
            a.free(logs[t]);
            a.free(device[t]);
            a.free(host[t]);
        };
        for (0..3) |t| {
            const polys = trace.polys.items[t];
            logs[t] = try a.alloc(u32, polys.len);
            device[t] = try a.alloc(?[*]const u32, polys.len);
            host[t] = try a.alloc([]const u32, polys.len);
            made += 1;
            row.columns[t] = polys.len;
            for (polys, 0..) |poly, i| {
                if (poly.device) |d| {
                    logs[t][i] = std.math.log2_int(u64, d.count);
                    device[t][i] = d.words;
                    host[t][i] = &.{};
                } else {
                    const p = poly.coefficients orelse return error.CompositionParityMissingCoefficients;
                    const values = p.coefficients();
                    logs[t][i] = p.logSize();
                    device[t][i] = null;
                    host[t][i] = @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
                    row.host_columns += 1;
                }
            }
        }
        var plan = try NComp.Plan.init(a, .{ .roles = specs, .log = log, .split = split, .total = @intCast(total), .beta = beta, .tree_logs = .{ logs[0], logs[1], logs[2] } });
        defer plan.deinit();
        if (tree.columns.len != plan.outputColumns()) return error.CompositionParityOutputShape;
        const legacy_output = (tree.columns[0].device orelse return error.CompositionParityLegacyOutputNotDevice).words;
        var alpha_words: [8]u32 = undefined;
        for (alpha.toM31Array(), &alpha_words) |m, *w| w.* = m.v;
        var job = CompositionParityJob{ .events = self.events, .plan = &plan, .sym = self.symbols, .compare = self.compare, .peer = self.peer, .device = .{ device[0], device[1], device[2] }, .host = .{ host[0], host[1], host[2] }, .logs = .{ logs[0], logs[1], logs[2] }, .alpha = alpha_words, .legacy_output = legacy_output, .a = a, .claims = claims };
        defer job.deinit();
        _ = try job.layout.add(.root, 0, 8);
        _ = try job.layout.add(.status, 0, 1);
        _ = try job.layout.add(.opaque_words, 0, 2);
        row.declared_device_words = job.footprint().device_words;
        var done = Done{};
        try self.worker.submit(api.Job.from(CompositionParityJob, &job), .{ .ctx = &done, .done = Done.call });
        while (!@atomicLoad(bool, &done.done, .acquire)) std.Thread.sleep(50 * std.time.ns_per_us);
        try done.result;
        row.root_equal = wordsEqual(&job.root, tree.root);
        row.coefficient_mismatches = job.mismatch[0];
        row.first_mismatch = job.mismatch[1];
        row.status = job.status;
        const r = done.receipt;
        row.job_stage_ns = r.stage_ns;
        row.job_enqueue_ns = r.enqueue_ns;
        row.job_wait_ns = r.wait_ns;
        row.host_waits = r.host_waits;
        row.arena_peak_words = r.arena_peak_words;
        row.gpu_ms = job.gpu_ms;
    }
};

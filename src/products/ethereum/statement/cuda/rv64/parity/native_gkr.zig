//! Unchanged GKR, Stage-1 and binding parity jobs and observation.
const A = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.abi;
const CPU = @import("stwo_riscv_cpu_integration");
const Child = CPU.rv64_gkr_child;
const Done = @import("native_common.zig").Done;
const Events = @import("stwo_riscv_cuda_integration").rv64.execution.runtime.cuda_events;
const NB = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_binding;
const NC = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_commit;
const NG = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_gkr;
const NS1 = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_stage1;
const Peer = @import("native_common.zig").Peer;
const Slab = jobs.slab;
const Sources = @import("stwo_riscv_cuda_integration").rv64.execution.source.gkr_sources;
const W = jobs.worker;
const api = jobs.api;
const check = @import("native_common.zig").check;
const deepEql = @import("native_common.zig").deepEql;
const jobs = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.runtime;
const native_beta = &@import("native_common.zig").native_beta;
const std = @import("std");

pub const GkrParityJob = struct {
    inner: NG.GkrJob,
    legacy: []const NG.Input,
    local: []NG.Input,
    peer: Peer,
    pub fn classKey(self: *GkrParityJob) [32]u8 {
        return self.inner.classKey();
    }
    pub fn footprint(self: *GkrParityJob) api.Footprint {
        var f = self.inner.footprint();
        f.device_words += Peer.deviceWords(NG.Input, self.legacy, self.inner.gkr.plan.logs);
        return f;
    }
    pub fn stage(self: *GkrParityJob, s: *api.Stager) !void {
        try self.inner.stage(s);
    }
    pub fn enqueue(self: *GkrParityJob, e: *api.Enqueue) !void {
        try self.peer.mirrorInputs(e, NG.Input, self.legacy, self.inner.gkr.plan.logs, self.local);
        self.inner.inputs = self.local;
        try self.inner.enqueue(e);
    }
    pub fn finish(self: *GkrParityJob, view: api.SlabView) !void {
        try self.inner.finish(view);
    }
    pub fn abort(self: *GkrParityJob) void {
        self.inner.abort();
    }
};

pub const Row = struct {
    ordinal: u32,
    instances: usize,
    columns: usize,
    host_columns: usize,
    cells: usize,
    facts: u64,
    channel_equal: bool,
    proof_equal: bool,
    legacy_ns: u64,
    job_stage_ns: u64,
    job_enqueue_ns: u64,
    job_wait_ns: u64,
    host_waits: u32,
    d2h_bytes: u64,
    arena_peak_words: u64,
    declared_device_words: u64,
    launches: u64,
    error_name: []const u8 = "",
    /// Composed NativeStage1 job (FIXED adoption + MAIN commit + local GKR, one job).
    stage1_fixed_root_equal: bool = false,
    stage1_main_root_equal: bool = false,
    stage1_channel_equal: bool = false,
    stage1_proof_equal: bool = false,
    stage1_enqueue_ns: u64 = 0,
    stage1_wait_ns: u64 = 0,
    stage1_host_waits: u32 = 0,
    stage1_arena_peak_words: u64 = 0,
    stage1_error: []const u8 = "",
    /// Enqueue-only binding (native_binding.zig) in the Stage1 job, right
    /// after the traversal; compared at the legacy Owner.finalize with
    /// per-instance trace-tree roots of the 16 coefficient columns.
    binding_instances: usize = 0,
    binding_verdict: u32 = 0xffff_ffff,
    binding_roots_equal: bool = false,
    binding_checked: bool = false,
    binding_launches: u64 = 0,
    stage1_gpu_ms: f32 = -1,
    binding_error: []const u8 = "",
};

/// Per-instance root of 16 binding columns (rows words each, contiguous):
/// the existing trace tree kernel over one mixed segment; root into `out`.
pub fn bindingRoots(csym: NC.Symbols, e: *api.Enqueue, plan: *const NB.Plan, columns: [*]const u32, out: api.DeviceBuffer) !void {
    var tree_words: usize = 0;
    for (plan.row_logs) |rl| tree_words = @max(tree_words, ((@as(usize, 2) << @intCast(rl)) - 1) * 8);
    const tree = try e.alloc(tree_words);
    for (plan.row_logs, 0..) |rl, i| {
        const rows = @as(usize, 1) << @intCast(rl);
        const segment = A.MixedSegment{ .columns = columns + plan.offsets[i], .stride_words = rows, .capacity_words = rows * 16, .source_size = @intCast(rows) };
        const words = (rows * 2 - 1) * 8;
        if (csym.tree(e.ctx(), 0, @ptrCast(&segment), 1, rl, tree.ptr, words) != 0) return error.CudaEnqueueFailed;
        if (csym.copy_d2d(e.ctx(), out.ptr + 8 * i, tree.ptr + words - 8, 32) != 0) return error.CudaEnqueueFailed;
    }
    e.free(tree);
}
pub fn bindingTreeWords(plan: *const NB.Plan) usize {
    return ((@as(usize, 2) << @intCast(plan.max_log)) - 1) * 8;
}

/// Legacy binding columns (Owner.finalize Completion, GPU0) mirrored, rooted.
pub const BindingCheckJob = struct {
    plan: *const NB.Plan,
    csym: NC.Symbols,
    peer: Peer,
    legacy: [*]const u32,
    layout: Slab.ProofLayout = .{},
    roots: []u32,
    pub fn classKey(_: *BindingCheckJob) [32]u8 {
        var k: [32]u8 = @splat(0);
        @memcpy(k[0..14], "rv64-m8-bindck");
        return k;
    }
    pub fn footprint(self: *BindingCheckJob) api.Footprint {
        return .{ .device_words = self.plan.output_words + bindingTreeWords(self.plan) + 4 * 64, .staged_words = 0, .slab_words = self.layout.words, .pinned_words = 64 };
    }
    pub fn stage(_: *BindingCheckJob, _: *api.Stager) !void {}
    pub fn enqueue(self: *BindingCheckJob, e: *api.Enqueue) !void {
        try e.slab.bind(&self.layout);
        const local = try e.alloc(self.plan.output_words);
        try self.peer.mirror(e, local.ptr, self.legacy, self.plan.output_words);
        try bindingRoots(self.csym, e, self.plan, local.ptr, try e.slab.field(.opaque_words, 0));
        e.free(local);
    }
    pub fn finish(self: *BindingCheckJob, view: api.SlabView) !void {
        @memcpy(self.roots, try Slab.read(view, .opaque_words, 0));
    }
    pub fn abort(_: *BindingCheckJob) void {}
};

/// The legacy owner, wrapped so its finalize also checks the job binding.
pub const BindingOwner = struct {
    decorator: *Decorator,
    inner: Child.DeviceBinding.Owner,
    ordinal: u32,
    pub fn wrap(self: *BindingOwner) Child.DeviceBinding.Owner {
        var out = self.inner;
        out.context = self;
        out.park_fn = if (self.inner.park_fn != null) park else null;
        out.finalize_fn = finalize;
        out.release_fn = release;
        return out;
    }
    pub fn park(raw: *anyopaque) anyerror!usize {
        const self: *BindingOwner = @ptrCast(@alignCast(raw));
        return self.inner.park_fn.?(self.inner.context);
    }
    pub fn finalize(raw: *anyopaque, a: std.mem.Allocator, request: Child.DeviceBinding.Request) anyerror!Child.DeviceBinding.Completion {
        const self: *BindingOwner = @ptrCast(@alignCast(raw));
        const completed = try self.inner.finalize_fn(self.inner.context, a, request);
        self.decorator.checkBinding(self.ordinal, request, completed);
        return completed;
    }
    pub fn release(raw: *anyopaque) void {
        const self: *BindingOwner = @ptrCast(@alignCast(raw));
        self.inner.release_fn(self.inner.context);
        self.decorator.a.destroy(self);
    }
};

/// NativeStage1 as one job: seed, FIXED (class-persistent, committed on device
/// by the first job of the class), MAIN commit (legacy committed coefficients,
/// mirrored), local GKR on the job's own coefficient views and device MAIN root.
pub const Stage1ParityJob = struct {
    s1: NS1.Stage1,
    fixed_inputs: []const NC.Input,
    main_inputs: []const NC.Input,
    local: []NC.Input,
    main_logs: []const u32,
    fixed_host_words: usize,
    peer: Peer,
    layout: Slab.ProofLayout = .{},
    roots: [16]u32 = undefined,
    section: ?NG.Section = null,
    binding: ?*NB.Binding = null,
    binding_verdict: u32 = 0xffff_ffff,
    binding_roots: []u32 = &.{},
    events: ?*const Events.Api = null,
    begin: ?*anyopaque = null,
    end: ?*anyopaque = null,
    stage1_gpu_ms: f32 = -1,
    pub fn classKey(self: *Stage1ParityJob) [32]u8 {
        return NG.classKeyOf(self.s1.gkr.?.plan);
    }
    pub fn footprint(self: *Stage1ParityJob) api.Footprint {
        const g = self.s1.gkr.?.plan;
        const fixed = self.s1.fixed.plan;
        const mp = self.s1.main;
        const staged = 64 + fixed.stagedWords(self.fixed_host_words) + mp.stagedWords(0) + g.stagedWords(true) + 8 * 64;
        const mirror = Peer.deviceWords(NC.Input, self.main_inputs, self.main_logs);
        const bind_words = if (self.binding) |b| b.plan.output_words + b.plan.enqueueWords() + bindingTreeWords(b.plan) + 4 * 64 else 0;
        const peak = @max(fixed.deviceWords(), @max(mp.deviceWords(), mp.coefficient_cells + 64 + g.enqueueWords() + bind_words));
        const bind_pinned = if (self.binding) |b| b.plan.pinnedWords() else 0;
        return .{ .device_words = staged + mirror + peak + 8 * 64, .staged_words = staged, .slab_words = self.layout.words, .pinned_words = self.fixed_host_words + 2 * (fixed.tw.twiddles.len + fixed.tw.itwiddles.len + mp.tw.twiddles.len + mp.tw.itwiddles.len) + 8 * (fixed.logs.len + mp.logs.len) + g.pinnedWords() + bind_pinned + 256 };
    }
    pub fn stage(self: *Stage1ParityJob, s: *api.Stager) !void {
        try self.s1.stage(s, self.fixed_inputs, self.main_inputs);
        if (self.events) |ev| if (ev.create(&self.begin, 0) != 0 or ev.create(&self.end, 0) != 0 or self.begin == null or self.end == null) return error.CudaTimingFailed;
    }
    pub fn enqueue(self: *Stage1ParityJob, e: *api.Enqueue) !void {
        try e.slab.bind(&self.layout);
        try self.peer.mirrorInputs(e, NC.Input, self.main_inputs, self.main_logs, self.local);
        if (self.binding) |b| {
            // Stage1's own binding step (enqueueWithBinding). CUDA events span
            // the whole Stage1 enqueue (FIXED, MAIN, GKR, binding; not the mirrors).
            const verdict = try e.slab.field(.opaque_words, 0);
            try check(self.s1.gkr.?.sym.memset(e.ctx(), verdict.ptr, 0, 4));
            if (self.events) |ev| if (ev.record(self.begin.?, e.stream()) != 0) return error.CudaTimingFailed;
            const committed = try self.s1.enqueueWithBinding(e, self.fixed_inputs, self.local, try e.slab.field(.root, 0), verdict);
            if (self.events) |ev| if (ev.record(self.end.?, e.stream()) != 0) return error.CudaTimingFailed;
            const out = committed.binding orelse return error.Stage1BindingMissing;
            try bindingRoots(self.s1.csym, e, b.plan, out.ptr, try e.slab.field(.opaque_words, 1));
            e.free(out);
            return;
        }
        _ = try self.s1.enqueue(e, self.fixed_inputs, self.local, try e.slab.field(.root, 0));
    }
    pub fn finish(self: *Stage1ParityJob, view: api.SlabView) !void {
        @memcpy(&self.roots, try Slab.read(view, .root, 0));
        self.section = try NG.Section.read(self.s1.gkr.?.a, self.s1.gkr.?, view);
        if (self.binding != null) {
            self.binding_verdict = (try Slab.read(view, .opaque_words, 0))[0];
            @memcpy(self.binding_roots, try Slab.read(view, .opaque_words, 1));
            if (self.events) |ev| if (ev.elapsed(&self.stage1_gpu_ms, self.begin.?, self.end.?) != 0) {
                self.stage1_gpu_ms = -1;
            };
        }
    }
    pub fn abort(_: *Stage1ParityJob) void {}
};

pub fn wordsEqual(words: []const u32, bytes: [32]u8) bool {
    for (words, 0..) |w, i| if (w != std.mem.readInt(u32, bytes[4 * i ..][0..4], .little)) return false;
    return true;
}

pub const Decorator = struct {
    a: std.mem.Allocator,
    inner: Child.NumericalStage,
    worker: *W.Worker,
    symbols: NG.Symbols,
    catalogue: Sources.Catalogue,
    arena_bytes: usize,
    peer: Peer,
    csym: NC.Symbols,
    mutex: std.Thread.Mutex = .{},
    rows: std.ArrayListUnmanaged(Row) = .empty,
    /// STWO_RV64_M8_PARITY_BINDING (default 1 with stage 1): run the
    /// enqueue-only binding in the Stage1 job; roots kept per ordinal until
    /// the legacy Owner.finalize of that scope.
    bsym: ?NB.Symbols = null,
    events: ?*const Events.Api = null,
    pending_binding: std.AutoHashMapUnmanaged(u32, []u32) = .empty,

    pub fn stage(self: *Decorator) Child.NumericalStage {
        var out = self.inner;
        out.context = self;
        out.prove = prove;
        // bind/abort/replay keep the legacy owner (they take the inner context).
        out.bind = if (self.inner.bind != null) bind else null;
        out.abort = if (self.inner.abort != null) abortScope else null;
        out.replay_binding = if (self.inner.replay_binding != null) replay else null;
        return out;
    }
    pub fn bind(raw: *anyopaque, a: std.mem.Allocator, request: Child.DeviceBinding.Request) anyerror!Child.DeviceBinding.Owner {
        const self: *Decorator = @ptrCast(@alignCast(raw));
        const owner = try self.inner.bind.?(self.inner.context, a, request);
        if (self.bsym == null) return owner;
        const wrapper = self.a.create(BindingOwner) catch |err| {
            owner.release_fn(owner.context);
            return err;
        };
        wrapper.* = .{ .decorator = self, .inner = owner, .ordinal = request.scope.ordinal };
        return wrapper.wrap();
    }
    /// At the legacy Owner.finalize: root the legacy columns on the job worker
    /// and compare with the roots the Stage1 job's binding produced.
    pub fn checkBinding(self: *Decorator, ordinal: u32, request: Child.DeviceBinding.Request, completed: Child.DeviceBinding.Completion) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const row = for (self.rows.items) |*r| {
            if (r.ordinal == ordinal) break r;
        } else return;
        if (row.binding_checked) return;
        row.binding_checked = true;
        self.checkBindingInner(ordinal, request, completed, row) catch |err| {
            row.binding_error = @errorName(err);
        };
        std.debug.print("GPU_M8_NATIVE_BINDING_PARITY ordinal={} instances={} verdict={} roots_equal={} stage1_gpu_ms={d:.3} launches={} error={s}\n", .{ ordinal, row.binding_instances, row.binding_verdict, row.binding_roots_equal, row.stage1_gpu_ms, row.binding_launches, row.binding_error });
    }
    pub fn checkBindingInner(self: *Decorator, ordinal: u32, request: Child.DeviceBinding.Request, completed: Child.DeviceBinding.Completion, row: *Row) !void {
        const job_roots = self.pending_binding.get(ordinal) orelse return error.BindingJobRootsMissing;
        defer {
            _ = self.pending_binding.remove(ordinal);
            self.a.free(job_roots);
        }
        if (row.binding_error.len != 0) return error.BindingJobFailed;
        var plan = try NB.Plan.init(self.a, request.instances, @intCast(request.artifact.ood_point.len));
        defer plan.deinit();
        if (completed.columns.len != 16 * request.instances.len) return error.BindingColumnShape;
        const base = (completed.columns[0].device orelse return error.BindingColumnShape).words;
        // Legacy Completion columns are one contiguous lease: [Eq 8 | prefix 8] per instance.
        for (completed.columns, 0..) |c, k| {
            const i = k / 16;
            const d = c.device orelse return error.BindingColumnShape;
            const rows = @as(usize, 1) << @intCast(plan.row_logs[i]);
            if (d.words != base + plan.offsets[i] + (k % 16) * rows or d.count != rows) return error.BindingColumnNotContiguous;
        }
        const roots = try self.a.alloc(u32, 8 * request.instances.len);
        defer self.a.free(roots);
        var job = BindingCheckJob{ .plan = &plan, .csym = self.csym, .peer = self.peer, .legacy = base, .roots = roots };
        _ = try job.layout.add(.opaque_words, 0, roots.len);
        var done = Done{};
        try self.worker.submit(api.Job.from(BindingCheckJob, &job), .{ .ctx = &done, .done = Done.call });
        while (!@atomicLoad(bool, &done.done, .acquire)) std.Thread.sleep(50 * std.time.ns_per_us);
        try done.result;
        row.binding_roots_equal = std.mem.eql(u32, roots, job_roots);
    }
    pub fn abortScope(raw: *anyopaque, scope: NG.Scope) void {
        const self: *Decorator = @ptrCast(@alignCast(raw));
        self.inner.abort.?(self.inner.context, scope);
    }
    pub fn replay(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request, owner: *Child.DeviceBinding.Owner) anyerror!void {
        const self: *Decorator = @ptrCast(@alignCast(raw));
        if (owner.finalize_fn != BindingOwner.finalize) return self.inner.replay_binding.?(self.inner.context, a, request, owner);
        // Parked/replayed legacy owner (memory pressure on the legacy GPU): the
        // legacy replay must see ITS owner; the wrapper keeps the result.
        const wrapper: *BindingOwner = @ptrCast(@alignCast(owner.context));
        var inner = owner.*;
        inner.context = wrapper.inner.context;
        inner.park_fn = wrapper.inner.park_fn;
        inner.finalize_fn = wrapper.inner.finalize_fn;
        inner.release_fn = wrapper.inner.release_fn;
        defer {
            wrapper.inner = inner;
            owner.* = wrapper.wrap();
        }
        return self.inner.replay_binding.?(self.inner.context, a, request, &inner);
    }
    pub fn prove(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request) anyerror!NG.Proof {
        const self: *Decorator = @ptrCast(@alignCast(raw));
        var timer = try std.time.Timer.start();
        const legacy = try self.inner.prove(self.inner.context, a, request);
        const legacy_ns = timer.read();
        // One job at a time on the parity worker (segments run in parallel lanes).
        self.mutex.lock();
        defer self.mutex.unlock();
        const row = self.compare(request, &legacy, legacy_ns) catch |err| Row{ .ordinal = request.scope.ordinal, .instances = request.instances.len, .columns = 0, .host_columns = 0, .cells = 0, .facts = 0, .channel_equal = false, .proof_equal = false, .legacy_ns = legacy_ns, .job_stage_ns = 0, .job_enqueue_ns = 0, .job_wait_ns = 0, .host_waits = 0, .d2h_bytes = 0, .arena_peak_words = 0, .declared_device_words = 0, .launches = 0, .error_name = @errorName(err) };
        var full = row;
        const stage1_flag = "1";
        if (!std.mem.eql(u8, stage1_flag, "0")) self.stage1(request, &legacy, &full) catch |err| {
            full.stage1_error = @errorName(err);
        };
        std.debug.print("GPU_M8_NATIVE_GKR_PARITY ordinal={} channel_equal={} proof_equal={} legacy_ns={} job_enqueue_ns={} job_wait_ns={} host_waits={} arena_peak_words={} error={s}\n", .{ row.ordinal, row.channel_equal, row.proof_equal, row.legacy_ns, row.job_enqueue_ns, row.job_wait_ns, row.host_waits, row.arena_peak_words, row.error_name });
        std.debug.print("GPU_M8_NATIVE_STAGE1_PARITY ordinal={} fixed_root_equal={} main_root_equal={} channel_equal={} proof_equal={} enqueue_ns={} wait_ns={} host_waits={} arena_peak_words={} error={s}\n", .{ full.ordinal, full.stage1_fixed_root_equal, full.stage1_main_root_equal, full.stage1_channel_equal, full.stage1_proof_equal, full.stage1_enqueue_ns, full.stage1_wait_ns, full.stage1_host_waits, full.stage1_arena_peak_words, full.stage1_error });
        try self.rows.append(self.a, full);
        return legacy;
    }
    pub fn stage1(self: *Decorator, request: Child.NumericalStage.Request, legacy: *const NG.Proof, row: *Row) !void {
        const a = self.a;
        const beta = native_beta.load(.acquire);
        if (beta == 0) return error.Stage1ParityNeedsCommitBeta;
        const native = request.native_source orelse return error.NativeGkrSourceRequired;
        var gplan = try NG.Plan.init(a, &self.catalogue, request.scope, request.instances, native, request.native_fixed_columns, request.native_main_columns, self.arena_bytes, 0);
        defer gplan.deinit();
        const nf = request.native_fixed_columns.len;
        const nm = request.native_main_columns.len;
        const fixed_shapes = try a.alloc(NC.Shape, nf);
        defer a.free(fixed_shapes);
        const fixed_inputs = try a.alloc(NC.Input, nf);
        defer a.free(fixed_inputs);
        var fixed_host_words: usize = 0;
        for (request.native_fixed_columns, fixed_shapes, fixed_inputs) |c, *s, *i| {
            s.* = .{ .log_size = c.log_size, .encoding = .coefficients };
            if (c.device != null) return error.Stage1ParityExpectsHostFixed;
            i.* = .{ .host = @as([*]const u32, @ptrCast(c.coefficients.ptr))[0..c.coefficients.len] };
            fixed_host_words += c.coefficients.len;
        }
        const main_shapes = try a.alloc(NC.Shape, nm);
        defer a.free(main_shapes);
        const main_inputs = try a.alloc(NC.Input, nm);
        defer a.free(main_inputs);
        const main_logs = try a.alloc(u32, nm);
        defer a.free(main_logs);
        for (request.native_main_columns, main_shapes, main_inputs, main_logs) |c, *s, *i, *l| {
            s.* = .{ .log_size = c.log_size, .encoding = .coefficients };
            i.* = .{ .device = (c.device orelse return error.Stage1ParityExpectsDeviceMain).words };
            l.* = c.log_size;
        }
        var fixed_plan = try NC.CommitPlan.init(a, fixed_shapes, beta);
        defer fixed_plan.deinit();
        var main_plan = try NC.CommitPlan.init(a, main_shapes, beta);
        defer main_plan.deinit();
        var key = std.crypto.hash.sha2.Sha256.init(.{});
        key.update("rv64-m8-stage1-fixed");
        key.update(&request.scope.fixed);
        key.update(std.mem.asBytes(&beta));
        var fixed_tree = NS1.FixedTree{ .plan = &fixed_plan, .key = key.finalResult() };
        var gkr = try NG.Gkr.init(a, &gplan, &self.symbols);
        defer gkr.deinit();
        const local = try a.alloc(NC.Input, nm);
        defer a.free(local);
        var job = Stage1ParityJob{ .s1 = .{ .fixed = &fixed_tree, .main = &main_plan, .csym = self.csym, .seed = @splat(0), .gkr = &gkr, .binding = null }, .fixed_inputs = fixed_inputs, .main_inputs = main_inputs, .local = local, .main_logs = main_logs, .fixed_host_words = fixed_host_words, .peer = self.peer };
        defer if (job.section) |*s| s.deinit();
        _ = try job.layout.add(.root, 0, 16);
        try gplan.addFields(&job.layout);
        var bplan: ?NB.Plan = null;
        defer if (bplan) |*p| p.deinit();
        var binding: NB.Binding = undefined;
        defer if (job.begin) |ev| {
            _ = self.events.?.destroy(ev);
        };
        defer if (job.end) |ev| {
            _ = self.events.?.destroy(ev);
        };
        if (self.bsym) |bsym| {
            bplan = try NB.Plan.init(a, request.instances, gplan.traversal.layers);
            binding = .{ .plan = &bplan.?, .sym = bsym };
            job.binding = &binding;
            job.s1.binding = &binding;
            job.binding_roots = try a.alloc(u32, 8 * request.instances.len);
            _ = try job.layout.add(.opaque_words, 0, 1);
            _ = try job.layout.add(.opaque_words, 1, job.binding_roots.len);
            row.binding_instances = request.instances.len;
            job.events = self.events;
        }
        var keep_roots = false;
        defer if (!keep_roots and job.binding_roots.len != 0) a.free(job.binding_roots);
        var done = Done{};
        try self.worker.submit(api.Job.from(Stage1ParityJob, &job), .{ .ctx = &done, .done = Done.call });
        while (!@atomicLoad(bool, &done.done, .acquire)) std.Thread.sleep(50 * std.time.ns_per_us);
        try done.result;
        const section = &(job.section orelse return error.NativeGkrSectionMissing);
        row.stage1_fixed_root_equal = wordsEqual(job.roots[0..8], request.scope.fixed);
        row.stage1_main_root_equal = wordsEqual(job.roots[8..16], request.scope.main);
        var channel_equal = section.snapshot.draws == request.channel.inner.n_draws;
        for (section.snapshot.digest, 0..) |w, i| channel_equal = channel_equal and w == std.mem.readInt(u32, request.channel.inner.digest[4 * i ..][0..4], .little);
        row.stage1_channel_equal = channel_equal;
        var proof = try section.proof(a, &gplan);
        defer proof.deinit(a);
        row.stage1_proof_equal = deepEql(proof, legacy.*);
        row.stage1_enqueue_ns = done.receipt.enqueue_ns;
        row.stage1_wait_ns = done.receipt.wait_ns;
        row.stage1_host_waits = done.receipt.host_waits;
        row.stage1_arena_peak_words = done.receipt.arena_peak_words;
        if (job.binding != null) {
            row.binding_verdict = job.binding_verdict;
            row.binding_launches = binding.launches;
            row.stage1_gpu_ms = job.stage1_gpu_ms;
            try self.pending_binding.put(self.a, request.scope.ordinal, job.binding_roots);
            keep_roots = true;
        }
    }
    pub fn compare(self: *Decorator, request: Child.NumericalStage.Request, legacy: *const NG.Proof, legacy_ns: u64) !Row {
        const a = self.a;
        const native = request.native_source orelse return error.NativeGkrSourceRequired;
        var plan = try NG.Plan.init(a, &self.catalogue, request.scope, request.instances, native, request.native_fixed_columns, request.native_main_columns, self.arena_bytes, 0);
        defer plan.deinit();
        const total = request.native_fixed_columns.len + request.native_main_columns.len;
        const inputs = try a.alloc(NG.Input, total);
        defer a.free(inputs);
        var host_columns: usize = 0;
        var main_host = false;
        for (inputs, 0..) |*input, i| {
            const column = if (i < request.native_fixed_columns.len) request.native_fixed_columns[i] else request.native_main_columns[i - request.native_fixed_columns.len];
            if (column.device) |d| {
                input.* = .{ .device = d.words };
            } else {
                input.* = .{ .host = @as([*]const u32, @ptrCast(column.coefficients.ptr))[0..column.coefficients.len] };
                host_columns += 1;
                main_host = main_host or i >= request.native_fixed_columns.len;
            }
        }
        const local = try a.alloc(NG.Input, total);
        defer a.free(local);
        var parity = GkrParityJob{ .inner = try NG.GkrJob.init(a, &plan, &self.symbols, inputs), .legacy = inputs, .local = local, .peer = self.peer };
        defer parity.inner.deinit();
        const job = &parity.inner;
        var root: [8]u32 = undefined;
        for (&root, 0..) |*w, i| w.* = std.mem.readInt(u32, request.scope.main[4 * i ..][0..4], .little);
        job.main_root_host = root;
        // FIXED coefficients are class-immutable: keep them warm on the worker,
        // keyed by the FIXED root and their size (only when MAIN is all device).
        if (!main_host and host_columns != 0) {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update("rv64-m8-gkr-host-fixed");
            h.update(&request.scope.fixed);
            h.update(std.mem.asBytes(&plan.host_column_words));
            job.gkr.host_key = h.finalResult();
        }
        var done = Done{};
        const footprint = parity.footprint();
        try self.worker.submit(api.Job.from(GkrParityJob, &parity), .{ .ctx = &done, .done = Done.call });
        while (!@atomicLoad(bool, &done.done, .acquire)) std.Thread.sleep(50 * std.time.ns_per_us);
        try done.result;
        const section = &(job.section orelse return error.NativeGkrSectionMissing);
        var channel_equal = section.snapshot.draws == request.channel.inner.n_draws;
        for (section.snapshot.digest, 0..) |w, i| channel_equal = channel_equal and w == std.mem.readInt(u32, request.channel.inner.digest[4 * i ..][0..4], .little);
        var proof = try section.proof(a, &plan);
        defer proof.deinit(a);
        var facts: u64 = 0;
        for (plan.source.items) |item| facts += item.facts;
        const r = done.receipt;
        return .{ .ordinal = request.scope.ordinal, .instances = request.instances.len, .columns = total, .host_columns = host_columns, .cells = plan.source.cells, .facts = facts, .channel_equal = channel_equal, .proof_equal = deepEql(proof, legacy.*), .legacy_ns = legacy_ns, .job_stage_ns = r.stage_ns, .job_enqueue_ns = r.enqueue_ns, .job_wait_ns = r.wait_ns, .host_waits = r.host_waits, .d2h_bytes = r.d2h_bytes, .arena_peak_words = r.arena_peak_words, .declared_device_words = footprint.device_words, .launches = job.gkr.launches };
    }
};

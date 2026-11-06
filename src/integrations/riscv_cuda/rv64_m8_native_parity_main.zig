//! M8 native-producers real-block parity harness (pod only, opt-in binary).
//!
//! Runs the unchanged legacy resident native pipeline on a real block (the
//! same manifest/request the gate writes) with ONE difference: the pool's
//! local-GKR NumericalStage is wrapped. The wrapper calls the legacy stage,
//! then proves the same segment's local GKR again as an M8 job
//! (jobs/native_gkr.zig GkrJob) on a DeviceWorker on another GPU, reading the
//! legacy MAIN coefficients by device pointer and the host FIXED coefficients
//! through the stager, and compares:
//!   * the job's device child transcript after the relation draws with the
//!     legacy request channel (digest + draws);
//!   * the decoded GKR proof with the legacy proof (every sumcheck round
//!     polynomial, layer mask and output claim).
//! The legacy proof is returned unchanged, so the pipeline (and its proof
//! bytes) is not affected. Results: <out>/native-gkr-parity.json.
//!
//! usage: rv64-m8-native-parity <manifest.json> <out-dir>
//! env:   the gate's service environment (STWO_RV64_GPU_LIBRARY, ...), plus
//!        STWO_RV64_M8_JOBS_LIBRARY (addon), STWO_RV64_M8_PARITY_DEVICE (job
//!        GPU, default 1; the legacy pool should use STWO_RV64_GPU_DEVICES=0),
//!        STWO_RV64_M8_JOBS_ARENA_BYTES, STWO_RV64_M8_JOBS_PINNED_BYTES.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Main = CPU.rv64_ethereum_gkr_main;
const Child = CPU.rv64_gkr_child;
const Pool = @import("rv64/resident_pool.zig").Pool;
const Router = @import("rv64/resident_router.zig");
const jobs = @import("rv64/jobs/mod.zig");
const W = jobs.worker;
const api = jobs.api;
const NG = @import("rv64/jobs/native_gkr.zig");
const Sources = @import("rv64/gkr_sources.zig");
const NGl = @import("rv64/jobs/native_global.zig");
const NC = @import("rv64/jobs/native_commit.zig");
const DP = CPU.rv64_device_pcs;
const Slab = jobs.slab;
const DG = CPU.rv64_gkr_cpu_worker.DeviceGlobal;
const O = @import("stwo_core").fields.om31.OM31;
const Compare = *const fn (*anyopaque, u32, [*]const u32, [*]const u32, u64, [*]u32) callconv(.c) c_int;
const PeerCopy = *const fn (*anyopaque, c_int, *const anyopaque, c_int, usize, *anyopaque) callconv(.c) c_int;

/// Legacy outputs live on the legacy pool's GPU; the job worker is on another
/// GPU. A parity job first mirrors them into its own arena on its exec stream.
const Peer = struct {
    copy: PeerCopy,
    source_device: c_int,
    fn mirror(self: Peer, e: *api.Enqueue, dst: [*]u32, src: [*]const u32, words: usize) !void {
        if (self.copy(dst, @intCast(e.device()), src, self.source_device, words * 4, e.stream()) != 0) return error.ParityPeerCopyFailed;
    }
    /// Replace every device input by an arena mirror (host inputs untouched).
    fn mirrorInputs(self: Peer, e: *api.Enqueue, comptime T: type, inputs: []const T, logs: []const u32, out: []T) !void {
        var words: usize = 0;
        for (inputs, logs) |input, log| if (input.device != null) {
            words += @as(usize, 1) << @intCast(log);
        };
        @memcpy(out, inputs);
        if (words == 0) return;
        const buffer = try e.alloc(words);
        var at: usize = 0;
        for (inputs, logs, out) |input, log, *o| if (input.device) |d| {
            const n = @as(usize, 1) << @intCast(log);
            try self.mirror(e, buffer.ptr + at, d, n);
            o.* = .{ .device = buffer.ptr + at };
            at += n;
        };
    }
    fn deviceWords(comptime T: type, inputs: []const T, logs: []const u32) usize {
        var words: usize = 64;
        for (inputs, logs) |input, log| if (input.device != null) {
            words += @as(usize, 1) << @intCast(log);
        };
        return words;
    }
};

/// NG.GkrJob with the legacy device columns mirrored into the job arena.
const GkrParityJob = struct {
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

const Row = struct {
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
};

const Decorator = struct {
    a: std.mem.Allocator,
    inner: Child.NumericalStage,
    worker: *W.Worker,
    symbols: NG.Symbols,
    catalogue: Sources.Catalogue,
    arena_bytes: usize,
    peer: Peer,
    mutex: std.Thread.Mutex = .{},
    rows: std.ArrayListUnmanaged(Row) = .empty,

    fn stage(self: *Decorator) Child.NumericalStage {
        var out = self.inner;
        out.context = self;
        out.prove = prove;
        // bind/abort/replay keep the legacy owner (they take the inner context).
        out.bind = if (self.inner.bind != null) bind else null;
        out.abort = if (self.inner.abort != null) abortScope else null;
        out.replay_binding = if (self.inner.replay_binding != null) replay else null;
        return out;
    }
    fn bind(raw: *anyopaque, a: std.mem.Allocator, request: Child.DeviceBinding.Request) anyerror!Child.DeviceBinding.Owner {
        const self: *Decorator = @ptrCast(@alignCast(raw));
        return self.inner.bind.?(self.inner.context, a, request);
    }
    fn abortScope(raw: *anyopaque, scope: NG.Scope) void {
        const self: *Decorator = @ptrCast(@alignCast(raw));
        self.inner.abort.?(self.inner.context, scope);
    }
    fn replay(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request, owner: *Child.DeviceBinding.Owner) anyerror!void {
        const self: *Decorator = @ptrCast(@alignCast(raw));
        return self.inner.replay_binding.?(self.inner.context, a, request, owner);
    }
    fn prove(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request) anyerror!NG.Proof {
        const self: *Decorator = @ptrCast(@alignCast(raw));
        var timer = try std.time.Timer.start();
        const legacy = try self.inner.prove(self.inner.context, a, request);
        const legacy_ns = timer.read();
        // One job at a time on the parity worker (segments run in parallel lanes).
        self.mutex.lock();
        defer self.mutex.unlock();
        const row = self.compare(request, &legacy, legacy_ns) catch |err| Row{ .ordinal = request.scope.ordinal, .instances = request.instances.len, .columns = 0, .host_columns = 0, .cells = 0, .facts = 0, .channel_equal = false, .proof_equal = false, .legacy_ns = legacy_ns, .job_stage_ns = 0, .job_enqueue_ns = 0, .job_wait_ns = 0, .host_waits = 0, .d2h_bytes = 0, .arena_peak_words = 0, .declared_device_words = 0, .launches = 0, .error_name = @errorName(err) };
        std.debug.print("GPU_M8_NATIVE_GKR_PARITY ordinal={} channel_equal={} proof_equal={} legacy_ns={} job_enqueue_ns={} job_wait_ns={} host_waits={} arena_peak_words={} error={s}\n", .{ row.ordinal, row.channel_equal, row.proof_equal, row.legacy_ns, row.job_enqueue_ns, row.job_wait_ns, row.host_waits, row.arena_peak_words, row.error_name });
        try self.rows.append(self.a, row);
        return legacy;
    }
    fn compare(self: *Decorator, request: Child.NumericalStage.Request, legacy: *const NG.Proof, legacy_ns: u64) !Row {
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

const GlobalRow = struct {
    ordinal: u32,
    origin: []const u8,
    log: u32,
    width: usize,
    claims_equal: bool,
    verdict: u32,
    witness_mismatches: u32,
    first_mismatch: u32,
    legacy_ns: u64,
    job_enqueue_ns: u64,
    job_wait_ns: u64,
    host_waits: u32,
    arena_peak_words: u64,
    error_name: []const u8 = "",
};

/// One slot's global witness as a job, plus an on-device word comparison of
/// its INTER witness with the legacy witness (copied into the job arena).
const GlobalParityJob = struct {
    global: NGl.Global,
    plan: *const NGl.Plan,
    compare: Compare,
    fixed_host: []const []const u32,
    fixed_device: []const [*]const u32,
    main: []const [*]const u32,
    legacy_columns: []const [*]const u32,
    peer: Peer,
    layout: Slab.ProofLayout = .{},
    claims: [16]u32 = undefined,
    status: u32 = 0,
    mismatch: [2]u32 = .{ 0, 0 },
    a: std.mem.Allocator,
    pub fn classKey(self: *GlobalParityJob) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-native-global-parity");
        h.update(std.mem.asBytes(&[_]u64{ self.plan.log, self.plan.width, self.plan.fixed_count, self.plan.main_count }));
        return h.finalResult();
    }
    pub fn footprint(self: *GlobalParityJob) api.Footprint {
        const p = self.plan;
        const staged = p.stagedWords(self.fixed_host.len != 0) + 64;
        const mirrors = (self.fixed_device.len + self.main.len) * p.rows + 128;
        return .{ .device_words = staged + p.enqueueWords() + 2 * std.mem.alignForward(usize, p.outputWords(), 64) + mirrors + 256, .staged_words = staged, .slab_words = self.layout.words, .pinned_words = p.parameters.len + p.fixed_count * p.rows + 64 };
    }
    pub fn stage(self: *GlobalParityJob, s: *api.Stager) !void {
        try self.global.stage(self.a, s, self.fixed_host);
    }
    pub fn enqueue(self: *GlobalParityJob, e: *api.Enqueue) !void {
        try e.slab.bind(&self.layout);
        const p = self.plan;
        const columns = self.fixed_device.len + self.main.len;
        const mirror = try e.alloc(columns * p.rows);
        var local: [256][*]const u32 = undefined;
        if (columns > local.len) return error.GlobalParityTooManyColumns;
        for (self.fixed_device, 0..) |c, i| {
            try self.peer.mirror(e, mirror.ptr + i * p.rows, c, p.rows);
            local[i] = mirror.ptr + i * p.rows;
        }
        for (self.main, 0..) |c, i| {
            const at = self.fixed_device.len + i;
            try self.peer.mirror(e, mirror.ptr + at * p.rows, c, p.rows);
            local[at] = mirror.ptr + at * p.rows;
        }
        const output = try e.alloc(p.outputWords());
        try self.global.enqueue(e, local[0..self.fixed_device.len], local[self.fixed_device.len..columns], .{ .output = output, .claims = try e.slab.field(.claims, 0), .status = try e.slab.field(.status, 0) });
        const reference = try e.alloc(p.outputWords());
        for (self.legacy_columns, 0..) |column, i| try self.peer.mirror(e, reference.ptr + i * p.rows, column, p.rows);
        try check(self.compare(e.ctx(), 0, reference.ptr, output.ptr, p.outputWords(), (try e.slab.field(.opaque_words, 0)).ptr));
    }
    pub fn finish(self: *GlobalParityJob, view: api.SlabView) !void {
        const claims = try Slab.read(view, .claims, 0);
        @memcpy(self.claims[0..claims.len], claims);
        self.status = (try Slab.read(view, .status, 0))[0];
        @memcpy(&self.mismatch, (try Slab.read(view, .opaque_words, 0))[0..2]);
    }
    pub fn abort(_: *GlobalParityJob) void {}
};
fn check(code: c_int) !void {
    if (code != 0) return error.CudaEnqueueFailed;
}

const GlobalDecorator = struct {
    a: std.mem.Allocator,
    inner: DG.Stage,
    worker: *W.Worker,
    symbols: NGl.Symbols,
    catalogue: NGl.Catalogue,
    compare: Compare,
    peer: Peer,
    mutex: std.Thread.Mutex = .{},
    rows: std.ArrayListUnmanaged(GlobalRow) = .empty,
    fn stage(self: *GlobalDecorator) DG.Stage {
        return .{ .context = self, .generate = generate };
    }
    fn generate(raw: *anyopaque, a: std.mem.Allocator, scope: @import("stwo_riscv_cpu_integration").rv64_device_pcs.Scope, item: DG.Item, shared: DG.Shared, budget: usize) anyerror!DG.Witness {
        const self: *GlobalDecorator = @ptrCast(@alignCast(raw));
        var timer = try std.time.Timer.start();
        var legacy = try self.inner.generate(self.inner.context, a, scope, item, shared, budget);
        errdefer legacy.deinit();
        const legacy_ns = timer.read();
        self.mutex.lock();
        defer self.mutex.unlock();
        const row = self.check(scope, item, shared, &legacy, legacy_ns) catch |err| GlobalRow{ .ordinal = scope.ordinal, .origin = @tagName(item.descriptor.origin), .log = item.log_size, .width = legacy.columns.len, .claims_equal = false, .verdict = 0xffffffff, .witness_mismatches = 0xffffffff, .first_mismatch = 0, .legacy_ns = legacy_ns, .job_enqueue_ns = 0, .job_wait_ns = 0, .host_waits = 0, .arena_peak_words = 0, .error_name = @errorName(err) };
        std.debug.print("GPU_M8_NATIVE_GLOBAL_PARITY ordinal={} origin={s} log={} width={} claims_equal={} verdict={} mismatches={} job_wait_ns={} error={s}\n", .{ row.ordinal, row.origin, row.log, row.width, row.claims_equal, row.verdict, row.witness_mismatches, row.job_wait_ns, row.error_name });
        try self.rows.append(self.a, row);
        return legacy;
    }
    fn check(self: *GlobalDecorator, scope: @import("stwo_riscv_cpu_integration").rv64_device_pcs.Scope, item: DG.Item, shared: DG.Shared, legacy: *const DG.Witness, legacy_ns: u64) !GlobalRow {
        const a = self.a;
        var plan = try NGl.Plan.init(a, &self.catalogue, item, shared);
        defer plan.deinit();
        if (legacy.columns.len != plan.width) return error.GlobalParityWidthMismatch;
        const fixed_host = try a.alloc([]const u32, if (item.fixed.len != 0 and item.fixed[0].device == null) item.fixed.len else 0);
        defer a.free(fixed_host);
        const fixed_device = try a.alloc([*]const u32, if (fixed_host.len == 0) item.fixed.len else 0);
        defer a.free(fixed_device);
        for (item.fixed, 0..) |c, i| {
            if (fixed_host.len != 0) {
                if (c.device != null) return error.GlobalParityMixedFixed;
                fixed_host[i] = @as([*]const u32, @ptrCast(c.coefficients.ptr))[0..c.coefficients.len];
            } else fixed_device[i] = (c.device orelse return error.GlobalParityMixedFixed).words;
        }
        const main_columns = try a.alloc([*]const u32, item.main.len);
        defer a.free(main_columns);
        for (item.main, main_columns) |c, *m| m.* = (c.device orelse return error.ResidentGlobalMainRequired).words;
        const legacy_columns = try a.alloc([*]const u32, legacy.columns.len);
        defer a.free(legacy_columns);
        for (legacy.columns, legacy_columns) |c, *m| m.* = (c.device orelse return error.InvalidDeviceGlobalWitness).words;
        var job = GlobalParityJob{ .global = .{ .plan = &plan, .sym = &self.symbols }, .plan = &plan, .compare = self.compare, .fixed_host = fixed_host, .fixed_device = fixed_device, .main = main_columns, .legacy_columns = legacy_columns, .peer = self.peer, .a = a };
        if (fixed_host.len != 0) {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update("rv64-m8-glob-fixed");
            h.update(&scope.fixed);
            h.update(std.mem.asBytes(&[_]u64{ item.fixed_offset, item.log_size, item.fixed.len }));
            job.global.fixed_key = h.finalResult();
        }
        _ = try job.layout.add(.claims, 0, plan.claimWords());
        _ = try job.layout.add(.status, 0, 1);
        _ = try job.layout.add(.opaque_words, 0, 2);
        var done = Done{};
        try self.worker.submit(api.Job.from(GlobalParityJob, &job), .{ .ctx = &done, .done = Done.call });
        while (!@atomicLoad(bool, &done.done, .acquire)) std.Thread.sleep(50 * std.time.ns_per_us);
        try done.result;
        var claims_equal = legacy.claims.len == plan.group_count;
        if (claims_equal) for (legacy.claims, 0..) |claim, g| for (claim.toM31Array(), 0..) |m, j| {
            claims_equal = claims_equal and m.v == job.claims[8 * g + j];
        };
        const r = done.receipt;
        return .{ .ordinal = scope.ordinal, .origin = @tagName(item.descriptor.origin), .log = item.log_size, .width = plan.width, .claims_equal = claims_equal, .verdict = job.status, .witness_mismatches = job.mismatch[0], .first_mismatch = job.mismatch[1], .legacy_ns = legacy_ns, .job_enqueue_ns = r.enqueue_ns, .job_wait_ns = r.wait_ns, .host_waits = r.host_waits, .arena_peak_words = r.arena_peak_words };
    }
};

const CommitRow = struct {
    ordinal: u32,
    tree: u32,
    beta: u32,
    columns: usize,
    host_columns: usize,
    coefficient_cells: usize,
    root_equal: bool,
    legacy_ns: u64,
    job_enqueue_ns: u64,
    job_wait_ns: u64,
    host_waits: u32,
    arena_peak_words: u64,
    error_name: []const u8 = "",
};

/// One trace commitment (MAIN/INTER) as a job; the root goes to the slab.
const CommitParityJob = struct {
    plan: *NC.CommitPlan,
    sym: NC.Symbols,
    inputs: []const NC.Input,
    local: []NC.Input,
    logs: []const u32,
    peer: Peer,
    host_words: usize,
    layout: Slab.ProofLayout = .{},
    root: [8]u32 = undefined,
    pub fn classKey(self: *CommitParityJob) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-m8-native-commit-parity");
        h.update(std.mem.sliceAsBytes(self.plan.logs));
        h.update(std.mem.asBytes(&self.plan.beta));
        return h.finalResult();
    }
    pub fn footprint(self: *CommitParityJob) api.Footprint {
        const staged = self.plan.stagedWords(self.host_words) + 4 * 64;
        return .{ .device_words = staged + self.plan.deviceWords() + Peer.deviceWords(NC.Input, self.inputs, self.logs) + 4 * 64, .staged_words = staged, .slab_words = self.layout.words, .pinned_words = 8 * self.plan.logs.len + self.host_words + 2 * (self.plan.tw.twiddles.len + self.plan.tw.itwiddles.len) + 64 };
    }
    pub fn stage(self: *CommitParityJob, s: *api.Stager) !void {
        try self.plan.stage(s, self.inputs);
    }
    pub fn enqueue(self: *CommitParityJob, e: *api.Enqueue) !void {
        try e.slab.bind(&self.layout);
        try self.peer.mirrorInputs(e, NC.Input, self.inputs, self.logs, self.local);
        _ = try self.plan.enqueue(self.sym, e, self.local, try e.slab.field(.root, 0), false);
    }
    pub fn finish(self: *CommitParityJob, view: api.SlabView) !void {
        @memcpy(&self.root, try Slab.read(view, .root, 0));
    }
    pub fn abort(_: *CommitParityJob) void {}
};

const CommitDecorator = struct {
    a: std.mem.Allocator,
    inner: *const DP.TraceCommitStage,
    worker: *W.Worker,
    symbols: NC.Symbols,
    peer: Peer,
    mutex: std.Thread.Mutex = .{},
    rows: std.ArrayListUnmanaged(CommitRow) = .empty,
    fn stage(self: *CommitDecorator) DP.TraceCommitStage {
        return .{ .context = self, .commit = commit };
    }
    fn commit(raw: *anyopaque, a: std.mem.Allocator, request: DP.TraceCommitRequest) anyerror!DP.Tree {
        const self: *CommitDecorator = @ptrCast(@alignCast(raw));
        // The job runs FIRST: a legacy INTER commit may retire its inputs.
        var job_row: CommitRow = undefined;
        var job_root: ?[8]u32 = null;
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            job_row, job_root = self.runJob(request) catch |err| .{ CommitRow{ .ordinal = request.scope.ordinal, .tree = request.tree_index, .beta = request.config.fri_config.log_blowup_factor, .columns = request.columns.len, .host_columns = 0, .coefficient_cells = 0, .root_equal = false, .legacy_ns = 0, .job_enqueue_ns = 0, .job_wait_ns = 0, .host_waits = 0, .arena_peak_words = 0, .error_name = @errorName(err) }, null };
        }
        var timer = try std.time.Timer.start();
        const tree = try self.inner.commit(self.inner.context, a, request);
        job_row.legacy_ns = timer.read();
        if (job_root) |root| {
            var equal = true;
            for (root, 0..) |w, i| equal = equal and w == std.mem.readInt(u32, tree.root[4 * i ..][0..4], .little);
            job_row.root_equal = equal;
        }
        std.debug.print("GPU_M8_NATIVE_COMMIT_PARITY ordinal={} tree={} beta={} columns={} root_equal={} legacy_ns={} job_wait_ns={} error={s}\n", .{ job_row.ordinal, job_row.tree, job_row.beta, job_row.columns, job_row.root_equal, job_row.legacy_ns, job_row.job_wait_ns, job_row.error_name });
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.rows.append(self.a, job_row);
        return tree;
    }
    fn runJob(self: *CommitDecorator, request: DP.TraceCommitRequest) !struct { CommitRow, ?[8]u32 } {
        const a = self.a;
        const shapes = try a.alloc(NC.Shape, request.columns.len);
        defer a.free(shapes);
        const inputs = try a.alloc(NC.Input, request.columns.len);
        defer a.free(inputs);
        var host_columns: usize = 0;
        var host_words: usize = 0;
        for (request.columns, shapes, inputs) |c, *s, *i| {
            s.* = .{ .log_size = c.log_size, .encoding = if (c.encoding == .evaluations) .evaluations else .coefficients };
            if (c.device) |d| i.* = .{ .device = d.words } else {
                i.* = .{ .host = @as([*]const u32, @ptrCast(c.host.ptr))[0..c.host.len] };
                host_columns += 1;
                host_words += c.host.len;
            }
        }
        const beta = request.config.fri_config.log_blowup_factor;
        var plan = try NC.CommitPlan.init(a, shapes, beta);
        defer plan.deinit();
        const logs = try a.alloc(u32, shapes.len);
        defer a.free(logs);
        for (shapes, logs) |s, *l| l.* = s.log_size;
        const local = try a.alloc(NC.Input, shapes.len);
        defer a.free(local);
        var job = CommitParityJob{ .plan = &plan, .sym = self.symbols, .inputs = inputs, .local = local, .logs = logs, .peer = self.peer, .host_words = host_words };
        _ = try job.layout.add(.root, 0, 8);
        var done = Done{};
        try self.worker.submit(api.Job.from(CommitParityJob, &job), .{ .ctx = &done, .done = Done.call });
        while (!@atomicLoad(bool, &done.done, .acquire)) std.Thread.sleep(50 * std.time.ns_per_us);
        try done.result;
        const r = done.receipt;
        return .{ .{ .ordinal = request.scope.ordinal, .tree = request.tree_index, .beta = beta, .columns = request.columns.len, .host_columns = host_columns, .coefficient_cells = plan.coefficient_cells, .root_equal = false, .legacy_ns = 0, .job_enqueue_ns = r.enqueue_ns, .job_wait_ns = r.wait_ns, .host_waits = r.host_waits, .arena_peak_words = r.arena_peak_words }, job.root };
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

/// Structural equality of proof values. Polynomials compare their logical
/// coefficients (`coeffs[0..len]`); ownership flags are not proof content.
fn deepEql(x: anytype, y: @TypeOf(x)) bool {
    const T = @TypeOf(x);
    switch (@typeInfo(T)) {
        .pointer => |p| {
            if (p.size != .slice) return deepEql(x.*, y.*);
            if (x.len != y.len) return false;
            for (x, y) |u, v| if (!deepEql(u, v)) return false;
            return true;
        },
        .array => {
            for (x, y) |u, v| if (!deepEql(u, v)) return false;
            return true;
        },
        .@"struct" => |s| {
            if (comptime @hasField(T, "coeffs") and @hasField(T, "len")) {
                if (x.len != y.len or x.len > x.coeffs.len or y.len > y.coeffs.len) return false;
                return deepEql(x.coeffs[0..x.len], y.coeffs[0..y.len]);
            }
            inline for (s.fields) |f| {
                if (comptime std.mem.startsWith(u8, f.name, "owns")) continue;
                if (!deepEql(@field(x, f.name), @field(y, f.name))) return false;
            }
            return true;
        },
        else => return std.meta.eql(x, y),
    }
}

fn env(name: []const u8) ?[]const u8 {
    return std.posix.getenv(name);
}
fn envBytes(name: []const u8, default: usize) !usize {
    const text = env(name) orelse return default;
    return std.fmt.parseUnsigned(usize, text, 10) catch error.InvalidParityEnvironment;
}

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
    defer a.free(raw);
    var parsed = try std.json.parseFromSlice(Manifest, a, raw, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const manifest = parsed.value;
    const block = manifest.execution_order[0];
    var name_buf: [24]u8 = undefined;
    const name = try std.fmt.bufPrint(&name_buf, "{d}", .{block});
    const item = manifest.blocks.map.get(name) orelse return error.MissingResidentBatchBlock;

    // M8 worker first (its arena is carved before the legacy pool's arena).
    var libs = try jobs.ops.Libraries.open(library, addon);
    defer libs.close();
    const device = std.fmt.parseUnsigned(u32, env("STWO_RV64_M8_PARITY_DEVICE") orelse "1", 10) catch return error.InvalidParityEnvironment;
    const arena_bytes = try envBytes("STWO_RV64_M8_JOBS_ARENA_BYTES", 24 << 30);
    const worker = try W.Worker.create(a, &libs.ops, .{ .device = device, .arena_words = std.mem.alignBackward(usize, arena_bytes / 4, W.Arena.granule), .pinned_slot_words = try envBytes("STWO_RV64_M8_JOBS_PINNED_BYTES", 1 << 30) / 4 });
    defer worker.destroy();

    var config = try Router.Config.fromEnv(a);
    defer config.deinit(a);
    var recycler = Main.Recycler.init(std.heap.smp_allocator, 1 << 30);
    defer recycler.deinit();
    const base = recycler.allocator();
    var session = try Main.ResidentSession.init(base, manifest.immutable_host_key_bytes);
    defer session.deinit();
    const pool = try Pool.createWithBinding(a, library, config, item.expected_cpu_segments, true);
    defer pool.deinit();
    try pool.stages().requireFullyResident();
    const peer = Peer{ .copy = libs.addon.lookup(PeerCopy, "stwo_rv64_jobs_native_peer_copy_v1") orelse return error.ParityRequiresPeerCopy, .source_device = std.fmt.parseUnsigned(c_int, env("STWO_RV64_M8_PARITY_SOURCE_DEVICE") orelse "0", 10) catch return error.InvalidParityEnvironment };
    var decorator = Decorator{ .a = a, .inner = pool.stages().numerical.?.*, .worker = worker, .symbols = try NG.Symbols.load(&libs.base), .catalogue = try Sources.Catalogue.init(a), .arena_bytes = arena_bytes, .peer = peer };
    defer decorator.catalogue.deinit();
    defer decorator.rows.deinit(a);
    const wrapped = decorator.stage();
    var stages = pool.stages();
    stages.numerical = &wrapped;
    const compare = libs.addon.lookup(Compare, "stwo_rv64_jobs_native_compare_v1") orelse return error.ParityRequiresCompareKernel;
    var global = GlobalDecorator{ .a = a, .inner = stages.global_interaction orelse return error.ParityRequiresDeviceGlobal, .worker = worker, .symbols = try NGl.Symbols.load(&libs.base), .catalogue = NGl.Catalogue.init(a, &libs.base), .compare = compare, .peer = peer };
    defer global.catalogue.deinit();
    defer global.rows.deinit(a);
    stages.global_interaction = global.stage();
    var commits = CommitDecorator{ .a = a, .inner = stages.trace_commit orelse return error.ParityRequiresDeviceTraceCommit, .worker = worker, .symbols = try NC.Symbols.load(&libs.base), .peer = peer };
    defer commits.rows.deinit(a);
    const wrapped_commit = commits.stage();
    stages.trace_commit = &wrapped_commit;

    const resource_json = try std.json.Stringify.valueAlloc(a, manifest.resources, .{});
    defer a.free(resource_json);
    const resources = try std.fs.path.join(a, &.{ out_dir, "resources.json" });
    defer a.free(resources);
    try std.fs.cwd().writeFile(.{ .sub_path = resources, .data = resource_json });
    const request = try std.fs.path.resolve(a, &.{ std.fs.path.dirname(argv[1]) orelse ".", item.request });
    defer a.free(request);
    const proof = try std.fs.path.join(a, &.{ out_dir, "proof" });
    defer a.free(proof);
    const parts = [_][]const u8{ "rv64-resident", "--security-profile", manifest.profile, "produce-candidate", request, "-", proof, "0", resources };
    var args: [parts.len][:0]u8 = undefined;
    for (parts, &args) |part, *arg| arg.* = try a.dupeZ(u8, part);
    defer for (args) |arg| a.free(arg);
    var identity: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("rv64-m8-native-parity", &identity, .{});
    for (pool.devices, config.caps) |*d, cap| try d.native.beginBlock(identity, .{ .device_bytes = cap, .immutable_bytes = manifest.immutable_device_bytes, .max_scopes = config.scope_limit });
    var timer = try std.time.Timer.start();
    try Main.runWithResidentArgs(&recycler, &args, stages, &session);
    const wall_ns = timer.read();
    for (pool.devices) |*d| try d.native.endBlock(identity);

    var all = decorator.rows.items.len == item.expected_cpu_segments;
    for (decorator.rows.items) |row| all = all and row.channel_equal and row.proof_equal and row.host_waits == 1 and row.error_name.len == 0;
    var global_all = global.rows.items.len != 0;
    for (global.rows.items) |row| global_all = global_all and row.claims_equal and row.verdict == 0 and row.witness_mismatches == 0 and row.host_waits == 1 and row.error_name.len == 0;
    var commit_all = commits.rows.items.len != 0;
    for (commits.rows.items) |row| commit_all = commit_all and row.root_equal and row.host_waits == 1 and row.error_name.len == 0;
    var text: std.Io.Writer.Allocating = .init(a);
    defer text.deinit();
    try std.json.Stringify.value(.{ .schema = "rv64-m8-native-gkr-parity/v1", .block = block, .expected_segments = item.expected_cpu_segments, .legacy_native_wall_ns = wall_ns, .job_device = device, .all_equal = all, .segments = decorator.rows.items, .global_all_equal = global_all, .global_slots = global.rows.items, .commit_all_equal = commit_all, .commits = commits.rows.items }, .{ .whitespace = .indent_1 }, &text.writer);
    const report = try std.fs.path.join(a, &.{ out_dir, "native-gkr-parity.json" });
    defer a.free(report);
    try std.fs.cwd().writeFile(.{ .sub_path = report, .data = text.written() });
    std.debug.print("GPU_M8_NATIVE_GKR_PARITY_DONE block={} segments={} all_equal={} global_slots={} global_all_equal={} commits={} commit_all_equal={} report={s}\n", .{ block, decorator.rows.items.len, all, global.rows.items.len, global_all, commits.rows.items.len, commit_all, report });
    if (!all) return error.NativeGkrParityMismatch;
    if (!global_all) return error.NativeGlobalParityMismatch;
    if (!commit_all) return error.NativeCommitParityMismatch;
}

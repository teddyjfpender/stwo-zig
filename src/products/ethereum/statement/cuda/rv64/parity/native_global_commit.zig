//! Unchanged global interaction and trace-commit parity jobs.
const CPU = @import("stwo_riscv_cpu_integration");
const Compare = @import("native_common.zig").Compare;
const DG = CPU.rv64_gkr_cpu_worker.DeviceGlobal;
const DP = CPU.rv64_device_pcs;
const Done = @import("native_common.zig").Done;
const NC = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_commit;
const NClaims = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_claims;
const NGl = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_global;
const Peer = @import("native_common.zig").Peer;
const Slab = jobs.slab;
const W = jobs.worker;
const api = jobs.api;
const check = @import("native_common.zig").check;
const jobs = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.runtime;
const native_beta = &@import("native_common.zig").native_beta;
const std = @import("std");

pub const GlobalRow = struct {
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
pub const GlobalParityJob = struct {
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
        return .{ .device_words = staged + p.enqueueWords() + 2 * std.mem.alignForward(usize, p.outputWords(), 64) + mirrors + 256, .staged_words = staged, .slab_words = self.layout.words, .pinned_words = p.pinnedWords(self.fixed_host.len != 0) + 64 };
    }
    pub fn stage(self: *GlobalParityJob, s: *api.Stager) !void {
        try self.global.stage(self.a, s, self.fixed_host);
    }
    pub fn enqueue(self: *GlobalParityJob, e: *api.Enqueue) !void {
        try e.slab.bind(&self.layout);
        const p = self.plan;
        const columns = self.fixed_device.len + self.main.len;
        const mirror = try e.alloc(columns * p.rows);
        const local = try self.a.alloc([*]const u32, columns);
        defer self.a.free(local);
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

pub const GlobalDecorator = struct {
    a: std.mem.Allocator,
    inner: DG.Stage,
    worker: *W.Worker,
    symbols: NGl.Symbols,
    catalogue: NGl.Catalogue,
    compare: Compare,
    peer: Peer,
    mutex: std.Thread.Mutex = .{},
    rows: std.ArrayListUnmanaged(GlobalRow) = .empty,
    /// Per segment ordinal: the claims the native_global JOBS produced (slab
    /// readback), appended in slot order = the Stage2 claims buffer layout
    /// (native_claims.Layout: generate runs once per slot with claims, in
    /// slot order). The composition parity consumes them as its device claims.
    produced: std.AutoHashMapUnmanaged(u32, Produced) = .empty,
    pub const Produced = struct { words: std.ArrayListUnmanaged(u32) = .empty, slots: u32 = 0, complete: bool = true };
    pub fn deinit(self: *GlobalDecorator) void {
        var it = self.produced.valueIterator();
        while (it.next()) |p| p.words.deinit(self.a);
        self.produced.deinit(self.a);
        self.catalogue.deinit();
        self.rows.deinit(self.a);
    }
    /// The produced claims of `ordinal` (caller owns), or null.
    pub fn take(self: *GlobalDecorator, ordinal: u32) ?Produced {
        self.mutex.lock();
        defer self.mutex.unlock();
        const kv = self.produced.fetchRemove(ordinal) orelse return null;
        return kv.value;
    }
    pub fn stage(self: *GlobalDecorator) DG.Stage {
        return .{ .context = self, .generate = generate };
    }
    pub fn generate(raw: *anyopaque, a: std.mem.Allocator, scope: @import("stwo_riscv_cpu_integration").rv64_device_pcs.Scope, item: DG.Item, shared: DG.Shared, budget: usize) anyerror!DG.Witness {
        const self: *GlobalDecorator = @ptrCast(@alignCast(raw));
        var timer = try std.time.Timer.start();
        var legacy = try self.inner.generate(self.inner.context, a, scope, item, shared, budget);
        errdefer legacy.deinit();
        const legacy_ns = timer.read();
        self.mutex.lock();
        defer self.mutex.unlock();
        var produced: [16]u32 = undefined;
        var produced_words: usize = 0;
        const row = self.check(scope, item, shared, &legacy, legacy_ns, &produced, &produced_words) catch |err| GlobalRow{ .ordinal = scope.ordinal, .origin = @tagName(item.descriptor.origin), .log = item.log_size, .width = legacy.columns.len, .claims_equal = false, .verdict = 0xffffffff, .witness_mismatches = 0xffffffff, .first_mismatch = 0, .legacy_ns = legacy_ns, .job_enqueue_ns = 0, .job_wait_ns = 0, .host_waits = 0, .arena_peak_words = 0, .error_name = @errorName(err) };
        std.debug.print("GPU_M8_NATIVE_GLOBAL_PARITY ordinal={} origin={s} log={} width={} claims_equal={} verdict={} mismatches={} job_wait_ns={} error={s}\n", .{ row.ordinal, row.origin, row.log, row.width, row.claims_equal, row.verdict, row.witness_mismatches, row.job_wait_ns, row.error_name });
        try self.rows.append(self.a, row);
        const entry = try self.produced.getOrPut(self.a, scope.ordinal);
        if (!entry.found_existing) entry.value_ptr.* = .{};
        entry.value_ptr.slots += 1;
        if (row.error_name.len != 0 or produced_words != 8 * NClaims.Slot.of(item.descriptor.origin, 0).count) entry.value_ptr.complete = false else try entry.value_ptr.words.appendSlice(self.a, produced[0..produced_words]);
        return legacy;
    }
    pub fn check(self: *GlobalDecorator, scope: @import("stwo_riscv_cpu_integration").rv64_device_pcs.Scope, item: DG.Item, shared: DG.Shared, legacy: *const DG.Witness, legacy_ns: u64, produced: *[16]u32, produced_words: *usize) !GlobalRow {
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
        @memcpy(produced[0..plan.claimWords()], job.claims[0..plan.claimWords()]);
        produced_words.* = plan.claimWords();
        var claims_equal = legacy.claims.len == plan.group_count;
        if (claims_equal) for (legacy.claims, 0..) |claim, g| for (claim.toM31Array(), 0..) |m, j| {
            claims_equal = claims_equal and m.v == job.claims[8 * g + j];
        };
        const r = done.receipt;
        return .{ .ordinal = scope.ordinal, .origin = @tagName(item.descriptor.origin), .log = item.log_size, .width = plan.width, .claims_equal = claims_equal, .verdict = job.status, .witness_mismatches = job.mismatch[0], .first_mismatch = job.mismatch[1], .legacy_ns = legacy_ns, .job_enqueue_ns = r.enqueue_ns, .job_wait_ns = r.wait_ns, .host_waits = r.host_waits, .arena_peak_words = r.arena_peak_words };
    }
};

pub const CommitRow = struct {
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
pub const CommitParityJob = struct {
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

pub const CommitDecorator = struct {
    a: std.mem.Allocator,
    inner: *const DP.TraceCommitStage,
    worker: *W.Worker,
    symbols: NC.Symbols,
    peer: Peer,
    mutex: std.Thread.Mutex = .{},
    rows: std.ArrayListUnmanaged(CommitRow) = .empty,
    pub fn stage(self: *CommitDecorator) DP.TraceCommitStage {
        return .{ .context = self, .commit = commit };
    }
    pub fn commit(raw: *anyopaque, a: std.mem.Allocator, request: DP.TraceCommitRequest) anyerror!DP.Tree {
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
    pub fn runJob(self: *CommitDecorator, request: DP.TraceCommitRequest) !struct { CommitRow, ?[8]u32 } {
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
        if (request.tree_index == 1) native_beta.store(beta, .release);
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

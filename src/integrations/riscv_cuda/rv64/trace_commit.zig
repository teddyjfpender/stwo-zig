//! Resident MAIN/INTER commitment. One ingress, explicit evaluation/coefficient
//! encodings, GPU interpolation/LDE/hash, and a 32-byte root readback. The
//! compact coefficient lease outlives transform scratch and is consumed by PCS.
const std = @import("std");
const DeviceCopy = @import("scoped_device_copy.zig");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const A = @import("abi.zig");
const Native = @import("pcs_native_abi.zig");
const Service = @import("pcs_native.zig");
const SC = @import("session_context.zig");
const StreamPlan = @import("trace_stream_plan.zig");
pub const AdmissionPlan = @import("trace_commit_cost.zig");
const Global = @import("global_admission.zig");
const Admission = @import("admission_runtime.zig");
const M = D.M;
const N2b = *const fn ([*]u32, usize, ?*const anyopaque, u32, usize, u32, [*]const u32, u32, u32, *anyopaque, u32, *u32) callconv(.c) c_int;
const N2bColumns = *const @TypeOf(@import("stwo_cuda_backend").abi.stages.transform.stwo_lde_n2b_columns_on);
const MixedSeeded = *const fn (u32, u32, [*]const A.MixedSegment, u32, u32, ?*const anyopaque, ?*anyopaque, ?*anyopaque, *anyopaque) callconv(.c) c_int;
const Layer = *const fn (*const anyopaque, u32, *anyopaque, *anyopaque) callconv(.c) c_int;
const PoolCurrent = *const fn (*anyopaque, *usize, *usize) callconv(.c) c_int;
const LiveLeases = *const fn (*anyopaque, *[5]u64, *u64) callconv(.c) c_int;
/// Streaming is the default whenever the loaded image exports the primitives.
/// STWO_RV64_TRACE_STREAM=0 restores the established full-LDE arena;
/// STWO_RV64_TRACE_STREAM_CHUNK_WORDS bounds one evaluation chunk. Neither
/// changes any committed word: the root is schedule-independent.
fn streamBudget() ?usize {
    if (std.posix.getenv("STWO_RV64_TRACE_STREAM")) |v| if (std.mem.eql(u8, v, "0")) return null;
    if (std.posix.getenv("STWO_RV64_TRACE_STREAM_CHUNK_WORDS")) |v| {
        const words = std.fmt.parseInt(usize, v, 10) catch return StreamPlan.default_chunk_words;
        return if (words == 0) StreamPlan.default_chunk_words else words;
    }
    return StreamPlan.default_chunk_words;
}
const B2n = *const fn ([*]const u32, usize, [*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
fn sym(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse error.MissingTraceCommitSymbol;
}
fn check(status: c_int) !void {
    if (status != 0) {
        std.debug.print("GPU_TRACE_COMMIT native_status={}\n", .{status});
        return error.CudaTraceCommitFailed;
    }
}
pub const Context = struct {
    admission_domain: Global.Domain = .native_packet,
    host_allocator: std.mem.Allocator = std.heap.page_allocator,
    /// Early MAIN preflights the complete Source+TC envelope before capture
    /// completes. Preserve that selected allocation schedule even while the
    /// whole-request admission endpoint is disabled. Immutable after init.
    freeze_allocation_plan: bool = false,
    // Production MAIN/INTER must be produced on device. A qualification-only
    // mixed-encoding oracle may explicitly opt out; production never does.
    require_device_input: bool = true,
    service: *Service.Context,
    api: SC.Api,
    n2b: N2b,
    n2b_columns: ?N2bColumns,
    b2n: B2n,
    copy: Native.CopyDevice,
    tree: *const @TypeOf(A.stwo_rv64_trace_tree_on),
    prefix_workspace: ?*const fn ([*]const A.MixedSegment, u32, *u64) callconv(.c) c_int = null,
    rebind: Native.LeaseRebind,
    mixed_seeded: ?MixedSeeded = null,
    layer: ?Layer = null,
    pool_current: ?PoolCurrent = null,
    live_leases: ?LiveLeases = null,
    returned: std.ArrayList([]D.Column) = .empty,
    twiddles: [29]?engine.poly.twiddles.TwiddleTree([]M) = @splat(null),
    mutex: std.Thread.Mutex = .{},
    pub fn init(service: *Service.Context) !Context {
        if (service.admission) |endpoint| try endpoint.planner.registerCoverage(endpoint.physical, .native_trace);
        return .{ .freeze_allocation_plan = if (std.posix.getenv("STWO_RV64_EARLY_NATIVE_MAIN")) |value| std.mem.eql(u8, value, "1") else false, .service = service, .api = .{
            .allocation_guard = &service.early_allocations,
            .allocate = service.lease_allocate,
            .release = service.lease_release,
            .validate_range = service.lease_validate_range,
            .upload = try sym(Native.Upload, &service.library, "stwo_exec_context_memcpy_h2d_async"),
            .download = try sym(Native.Download, &service.library, "stwo_exec_context_memcpy_d2h_async"),
            .sync = try sym(Native.Sync, &service.library, "stwo_exec_context_sync"),
            .lane_stream = try sym(Native.LaneStream, &service.library, "stwo_exec_context_lane_stream"),
        }, .n2b = try sym(N2b, &service.library, "stwo_lde_n2b_addressed_on"), .n2b_columns = service.library.lookup(N2bColumns, "stwo_lde_n2b_columns_on"), .b2n = try sym(B2n, &service.library, "stwo_ntt_b2n_columns_compact_on"), .copy = try sym(Native.CopyDevice, &service.library, "stwo_exec_context_memcpy_d2d_async"), .tree = try sym(*const @TypeOf(A.stwo_rv64_trace_tree_on), &service.library, "stwo_rv64_trace_tree_on"), .prefix_workspace = service.library.lookup(*const fn ([*]const A.MixedSegment, u32, *u64) callconv(.c) c_int, "stwo_rv64_trace_prefix_workspace_words"), .rebind = try sym(Native.LeaseRebind, &service.library, "stwo_rv64_gpu_lease_rebind"), .mixed_seeded = service.library.lookup(MixedSeeded, "stwo_blake2s_mixed_seeded_eager_on") orelse service.library.lookup(MixedSeeded, "stwo_blake2s_mixed_seeded_on"), .layer = service.library.lookup(Layer, "stwo_blake2s_layer_on"), .pool_current = service.library.lookup(PoolCurrent, "stwo_exec_context_pool_current"), .live_leases = service.library.lookup(LiveLeases, "stwo_rv64_gpu_session_live_leases") };
    }
    pub fn deinit(self: *Context) void {
        for (self.returned.items) |columns| self.host_allocator.free(columns);
        self.returned.deinit(self.host_allocator);
        for (&self.twiddles) |*cached| if (cached.*) |*value| engine.poly.twiddles.deinitM31(self.host_allocator, value);
        self.* = undefined;
    }
    fn tw(self: *Context, log: u32) !*const engine.poly.twiddles.TwiddleTree([]M) {
        if (self.twiddles[log] == null) self.twiddles[log] = try engine.poly.twiddles.precomputeM31(self.host_allocator, core.poly.circle.canonic.CanonicCoset.new(log).circleDomain().half_coset);
        return &self.twiddles[log].?;
    }
    pub fn stage(self: *Context) D.TraceCommitStage {
        return .{ .context = self, .commit = commit };
    }
    pub fn registerAdmissionCoverage(self: *Context) !void {
        if (self.service.admission) |endpoint| try endpoint.planner.registerCoverage(endpoint.physical, if (self.admission_domain == .recursion_node) .recursion_trace else .native_trace);
    }
    fn commit(raw: *anyopaque, a: std.mem.Allocator, request: D.TraceCommitRequest) !D.Tree {
        const self: *Context = @ptrCast(@alignCast(raw));
        return self.commitImpl(a, request, false);
    }
    /// Explicit fixed-prover setup; ordinary MAIN/INTER admission is unchanged.
    pub fn commitFixed(self: *Context, a: std.mem.Allocator, request: D.TraceCommitRequest) !D.Tree {
        return self.commitImpl(a, request, true);
    }
    /// Host-only allocation plan. An admitted execution freezes this stream
    /// schedule; owner-thread per-session pressure cannot silently change it.
    pub fn allocationOptions(self: *const Context, beta: u32) AdmissionPlan.Input {
        const separate = beta == 1 and self.n2b_columns != null;
        return .{ .logs = &.{}, .beta = beta, .separate_coefficients = separate, .stream_budget = if (separate and self.mixed_seeded != null and self.layer != null) streamBudget() else null, .exact_prefix_banks = self.prefix_workspace != null };
    }
    pub fn allocationPlan(self: *const Context, a: std.mem.Allocator, request: D.TraceCommitRequest) !AdmissionPlan.Plan {
        const logs = try a.alloc(u32, request.columns.len);
        defer a.free(logs);
        for (request.columns, logs) |column, *log| log.* = column.log_size;
        var input = self.allocationOptions(request.config.fri_config.log_blowup_factor);
        input.logs = logs;
        return AdmissionPlan.init(a, input);
    }
    fn commitImpl(self: *Context, a: std.mem.Allocator, request: D.TraceCommitRequest, fixed: bool) !D.Tree {
        if ((fixed and request.tree_index != 0) or (!fixed and request.tree_index < 1) or request.tree_index > 2 or request.columns.len == 0 or request.columns.len > 65535) return error.InvalidTraceCommitRequest;
        if (request.expected_main_root) |expected| {
            if (request.tree_index != 1 or std.mem.allEqual(u8, &expected, 0) or (!std.mem.allEqual(u8, &request.scope.main, 0) and !std.mem.eql(u8, &request.scope.main, &expected))) return error.InvalidTraceReplayScope;
        } else if (request.tree_index == 1 and !std.mem.allEqual(u8, &request.scope.main, 0)) return error.InvalidTraceCommitRequest;
        const beta = request.config.fri_config.log_blowup_factor;
        if (request.retire_input) |retirement| {
            if (request.tree_index != 2 or beta != 1 or self.n2b_columns == null or !std.meta.eql(retirement.scope, request.scope)) return error.InvalidTraceInputRetirementScope;
        }
        if (beta < 1 or beta > 4) return error.InvalidTraceCommitRequest;
        for (request.columns) |column| {
            try column.validate();
            if (self.require_device_input and column.device == null) return error.HostWitnessDisallowedInResidentProof;
            if (column.log_size + beta > 28) return error.InvalidTraceCommitRequest;
        }
        const allocation_plan = if (self.freeze_allocation_plan or self.service.admission != null) try self.allocationPlan(a, request) else null;
        var permit: ?Admission.Permit = null;
        var successor: Global.Footprint = .{};
        if (self.service.admission) |endpoint| {
            if (request.tree_index == 0) return error.GlobalFixedTracePlanUnavailable;
            successor = try self.service.admissionSuccessor(request.scope, if (request.tree_index == 1) .main_commit else .inter_commit);
            const plan = &allocation_plan.?;
            permit = try endpoint.reserve(.{ .owner = .{ .request = std.mem.readInt(u64, request.scope.statement[0..8], .little), .domain = self.admission_domain, .ordinal = request.scope.ordinal }, .stage = .trace_commit, .temporary = try plan.footprint(), .successor = successor, .known = true, .host_known = plan.host_cost_known, .host_peak_bytes = plan.host_peak_bytes });
        }
        defer if (permit) |*active| if (!active.closed) {
            active.endpoint.planner.poisonPhysical(active.endpoint.physical);
            active.finish(.{}) catch {};
        };
        self.mutex.lock();
        defer self.mutex.unlock();
        if (request.tree_index == 1) try self.service.early_allocations.advance(@import("pcs_scope.zig").identity(request.scope), .commit);
        try self.returned.ensureUnusedCapacity(self.host_allocator, 1);
        var job = Job{ .backend = self, .a = a, .request = request, .admission_plan = allocation_plan, .permit = if (permit) |*active| active else null };
        const status = self.service.submit(self.service.session, Job.callback, &job);
        if (job.failure) |err| return err;
        try check(status);
        const result = job.result orelse return error.CudaTraceCommitFailed;
        if (permit) |*active| {
            var final_scope = request.scope;
            if (request.tree_index == 1) final_scope.main = result.root;
            self.service.completeAdmission(active, final_scope, successor) catch |err| {
                self.service.finishProofScope(final_scope);
                return err;
            };
        }
        self.returned.appendAssumeCapacity(@constCast(result.columns));
        return result;
    }
};
const Job = struct {
    backend: *Context,
    a: std.mem.Allocator,
    request: D.TraceCommitRequest,
    result: ?D.Tree = null,
    failure: ?anyerror = null,
    admission_plan: ?AdmissionPlan.Plan = null,
    allocation_index: usize = 0,
    permit: ?*Admission.Permit = null,
    fn callback(raw: *anyopaque, token: u64, user: ?*anyopaque) callconv(.c) c_int {
        const self: *Job = @ptrCast(@alignCast(user orelse return 1));
        if (self.permit) |permit| permit.enterOwner(raw) catch |err| {
            self.failure = err;
            return 1;
        };
        self.run(raw, token) catch |err| {
            self.failure = err;
        };
        if (self.admission_plan) |plan| if (self.allocation_index != plan.allocation_count) {
            if (self.failure == null) self.failure = error.TraceAllocationPlanMismatch;
        };
        if (self.permit) |permit| permit.leaveOwner(raw) catch |err| {
            if (self.failure == null) self.failure = err;
        };
        return if (self.failure == null) 0 else 1;
    }
    fn allocate(self: *Job, ctx: *SC.Context, words: usize, kind: u32, phase: []const u8) !Native.Lease {
        if (self.admission_plan) |*plan| {
            const bytes = try std.math.mul(u64, words, 4);
            if (self.allocation_index >= plan.allocation_count or plan.allocations[self.allocation_index] != bytes) return error.TraceAllocationPlanMismatch;
        }
        const lease = ctx.allocate(words, kind) catch |err| {
            // Capture the live peak before run's deferred lease cleanup. A
            // callback-level snapshot would describe the unwound allocation set.
            std.debug.print("GPU_TRACE_ALLOCATION_FAILURE tree={} columns={} phase={s} requested_words={} kind={} error={s}\n", .{ self.request.tree_index, self.request.columns.len, phase, words, kind, @errorName(err) });
            self.backend.service.logMemoryFailure(ctx.native_context, "trace_commit");
            return err;
        };
        self.allocation_index += 1;
        return lease;
    }
    fn copyInputs(self: *Job, ctx: *SC.Context, destination: @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32), coefficient_ptr: [*]u32, order: []const usize, offsets: []const usize) !void {
        const b = self.backend;
        var pending_copy: ?DeviceCopy.Run = null;
        for (order) |original| {
            const column = self.request.columns[original];
            const count = @as(usize, 1) << @intCast(column.log_size);
            if (column.device) |device| {
                if (device.count != count) return error.InvalidDeviceTraceColumn;
                const next = try DeviceCopy.Run.init(@intFromPtr(device.words), offsets[original], count, device.context_token, device.generation);
                if (pending_copy) |*copy_run| {
                    if (!try copy_run.append(next)) {
                        try DeviceCopy.execute(ctx, b.copy, destination, copy_run.*);
                        pending_copy = next;
                    }
                } else pending_copy = next;
            } else {
                if (pending_copy) |copy_run| try DeviceCopy.execute(ctx, b.copy, destination, copy_run);
                pending_copy = null;
                try check(b.api.upload(ctx.native_context, coefficient_ptr + offsets[original], column.host.ptr, count * 4));
            }
        }
        if (pending_copy) |copy_run| try DeviceCopy.execute(ctx, b.copy, destination, copy_run);
    }
    /// Device occupancy at this commit's peak point: every scratch lease is
    /// live and nothing has been released yet. Optional exports only.
    fn samplePeak(self: *Job, ctx: *SC.Context, mode: []const u8, scratch_bytes: usize, legacy_bytes: usize, coefficient_bytes: usize, calls: usize) void {
        const b = self.backend;
        var used: usize = 0;
        var reserved: usize = 0;
        var kinds: [5]u64 = @splat(0);
        var lease_bytes: u64 = 0;
        const pool_status: c_int = if (b.pool_current) |query| query(ctx.native_context, &used, &reserved) else -1;
        const lease_status: c_int = if (b.live_leases) |query| query(b.service.session, &kinds, &lease_bytes) else -1;
        std.debug.print("GPU_DEVICE_PEAK stage=trace_commit tree={} mode={s} columns={} calls={} coefficient_bytes={} scratch_bytes={} legacy_scratch_bytes={} live_lease_bytes={} live_kinds={any} pool_used_bytes={} pool_reserved_bytes={} pool_status={} lease_status={}\n", .{ self.request.tree_index, mode, self.request.columns.len, calls, coefficient_bytes, scratch_bytes, legacy_bytes, lease_bytes, kinds, used, reserved, pool_status, lease_status });
    }
    fn streamPays(self: *Job, order: []const usize, beta: u32, tw: *const engine.poly.twiddles.TwiddleTree([]M), budget: usize) !bool {
        const rows = try self.a.alloc(u32, order.len);
        defer self.a.free(rows);
        for (order, rows) |original, *row| row.* = @as(u32, 1) << @intCast(self.request.columns[original].log_size + beta);
        var p = try StreamPlan.plan(self.a, rows, budget);
        defer p.deinit(self.a);
        const aux = tw.twiddles.len + tw.itwiddles.len + 7 * order.len;
        return StreamPlan.alignUp(aux) + p.scratchWords() < StreamPlan.legacyScratchWords(rows, aux);
    }
    fn liveLeaseBytes(self: *Job) ?u64 {
        const query = self.backend.live_leases orelse return null;
        var kinds: [5]u64 = @splat(0);
        var bytes: u64 = 0;
        return if (query(self.backend.service.session, &kinds, &bytes) == 0) bytes else null;
    }
    /// Chunked LDE -> Merkle commit. Only the compact coefficient lease, one
    /// bounded evaluation chunk and two progressive-state banks are ever live;
    /// the tree is built in the bank that is dead after the final absorption.
    fn streamRoot(self: *Job, ctx: *SC.Context, raw: *anyopaque, order: []const usize, offsets: []const usize, coefficient_ptr: [*]u32, beta: u32, tw: *const engine.poly.twiddles.TwiddleTree([]M), budget: usize) ![32]u8 {
        const b = self.backend;
        const a = self.a;
        const r = self.request;
        // Kernels stream: the streamed chain below is self-contained (each
        // seed is its previous call's prefix bank, seed_size == previous
        // size), so it may use the eager-state entry when the image has it.
        const mixed = b.mixed_seeded.?;
        const layer = b.layer.?;
        const rows = try a.alloc(u32, order.len);
        defer a.free(rows);
        const logs = try a.alloc(u32, order.len);
        defer a.free(logs);
        var coefficient_cells: usize = 0;
        for (order, rows, logs) |original, *row, *log| {
            log.* = r.columns[original].log_size;
            row.* = @as(u32, 1) << @intCast(log.* + beta);
            coefficient_cells += @as(usize, 1) << @intCast(log.*);
        }
        const inverse_base = tw.twiddles.len;
        const logs_base = inverse_base + tw.itwiddles.len;
        const aux_words = StreamPlan.alignUp(logs_base + logs.len);
        // Admission by predicted peak: the chunk is the only schedule-free
        // term, so shrink it (never below one column) until the predicted
        // scratch fits beside the live leases under the device byte cap.
        const live = self.liveLeaseBytes();
        const admissible: ?usize = if (live) |bytes| (if (b.service.byte_cap > bytes) @intCast((b.service.byte_cap - bytes) / 4) else 0) else null;
        var chunk_budget = budget;
        var p = try StreamPlan.plan(a, rows, chunk_budget);
        defer p.deinit(a);
        while (if (self.admission_plan == null) admissible else null) |limit| {
            if (aux_words + p.scratchWords() <= limit or chunk_budget <= rows[0]) break;
            chunk_budget /= 2;
            const smaller = try StreamPlan.plan(a, rows, chunk_budget);
            p.deinit(a);
            p = smaller;
        }
        const total = try std.math.add(usize, aux_words, p.scratchWords());
        // Lifetime-shaped leases: no request is larger than one bank, so a
        // fragmented pool reservation can still serve the commit.
        var leases = [3]Native.Lease{ .{}, .{}, .{} };
        defer for (&leases) |*lease| if (lease.words != null) {
            ctx.join() catch {};
            _ = b.api.release(b.service.session, lease);
        };
        leases[0] = try self.allocate(ctx, aux_words + @max(p.chunk_words, 1), 0, "stream_aux_chunk");
        for (0..2) |k| if (p.bank_words[k] != 0) {
            leases[k + 1] = try self.allocate(ctx, p.bank_words[k], 0, "stream_bank");
        };
        for (leases) |lease| if (lease.words != null) {
            _ = try ctx.borrow(lease);
        };
        const base = leases[0].words.?;
        const chunk = base + aux_words;
        const banks = [2][*]u32{ leases[1].words orelse base, leases[2].words orelse base };
        try check(b.api.upload(raw, base, tw.twiddles.ptr, tw.twiddles.len * 4));
        try check(b.api.upload(raw, base + inverse_base, tw.itwiddles.ptr, tw.itwiddles.len * 4));
        try check(b.api.upload(raw, base + logs_base, logs.ptr, logs.len * 4));
        // M6 enqueue: LDE/hash kernels run on lane 0 (the context stream) right
        // behind the staged uploads and the coefficient copies, so neither the
        // ingress join nor the pre-readback join is needed; the root readback
        // is ordered after the last layer on the same lane. Same words.
        const lane = try computeLane(b, raw);
        var launches: u32 = 0;
        // Interpolate evaluation-encoded inputs in place, exactly as the
        // established path does (same batching over adjacent equal heights).
        var interpolation_first: usize = 0;
        while (interpolation_first < order.len) {
            const column = r.columns[order[interpolation_first]];
            if (column.encoding != .evaluations) {
                interpolation_first += 1;
                continue;
            }
            var interpolation_end = interpolation_first + 1;
            while (interpolation_end < order.len and
                r.columns[order[interpolation_end]].log_size == column.log_size and
                r.columns[order[interpolation_end]].encoding == .evaluations) : (interpolation_end += 1)
            {}
            const n = @as(usize, 1) << @intCast(column.log_size);
            const inverse_offset = inverse_base + tw.itwiddles.len - n / 2;
            const at = coefficient_ptr + offsets[order[interpolation_first]];
            try check(b.b2n(at, n, at, n, column.log_size, @intCast(interpolation_end - interpolation_first), base + inverse_offset, @intCast(n / 2), @intCast(n / 2), lane, &launches));
            interpolation_first = interpolation_end;
        }
        var hashes: [*]u32 = banks[0];
        for (p.calls) |c| {
            var segments: [StreamPlan.max_segments]A.MixedSegment = undefined;
            var count: u32 = 0;
            var cursor: usize = 0;
            var i: usize = c.first;
            while (i < c.end) {
                var j = i + 1;
                while (j < c.end and rows[j] == rows[i]) : (j += 1) {}
                const lde_rows: usize = rows[i];
                const n = lde_rows >> @intCast(beta);
                const destination = chunk + cursor;
                try check(b.n2b_columns.?(coefficient_ptr + offsets[order[i]], n, base + logs_base + i, destination, lde_rows, logs[i] + beta, @intCast(j - i), base + tw.twiddles.len - lde_rows / 2, @intCast(lde_rows / 2), @intCast(lde_rows / 2), lane, &launches));
                segments[count] = .{ .columns = destination, .stride_words = lde_rows, .capacity_words = lde_rows * (j - i), .source_size = @intCast(lde_rows) };
                count += 1;
                cursor += lde_rows * (j - i);
                i = j;
            }
            const seed: ?*const anyopaque = if (c.seed_bank) |bank| @ptrCast(banks[bank]) else null;
            const out: *anyopaque = @ptrCast(banks[c.out_bank]);
            try check(mixed(c.size, count, &segments, c.absorbed, c.seed_size, seed, if (c.final) null else out, if (c.final) out else null, lane));
            if (c.final) hashes = banks[c.out_bank];
        }
        // Merkle layers above the leaves, in the same dead bank. Identical to
        // stwo_rv64_trace_tree_on's layer loop.
        var offset: usize = 0;
        var next_offset: usize = p.leaves;
        var nodes: usize = p.leaves;
        while (nodes > 1) : (nodes >>= 1) {
            try check(layer(@ptrCast(hashes + offset * 8), @intCast(nodes / 2), @ptrCast(hashes + next_offset * 8), lane));
            offset = next_offset;
            next_offset += nodes / 2;
        }
        const legacy = StreamPlan.legacyScratchWords(rows, tw.twiddles.len + tw.itwiddles.len + 7 * order.len);
        self.samplePeak(ctx, "stream", total * 4, legacy * 4, coefficient_cells * 4, p.calls.len);
        var root_words: [8]u32 = undefined;
        try check(b.api.download(raw, &root_words, hashes + p.tree_words - 8, 32));
        try ctx.join();
        var root: [32]u8 = undefined;
        for (root_words, 0..) |v, k| std.mem.writeInt(u32, root[4 * k ..][0..4], v, .little);
        std.debug.print("GPU_TRACE_STREAM tree={} columns={} leaves={} calls={} chunk_budget_words={} chunk_words={} bank_words={any} aux_words={} scratch_words={} legacy_scratch_words={}\n", .{ r.tree_index, order.len, p.leaves, p.calls.len, chunk_budget, p.chunk_words, p.bank_words, aux_words, total, legacy });
        return root;
    }
    fn publish(self: *Job, ctx: *SC.Context, root: [32]u8, coefficients: *Native.Lease, offsets: []const usize, scope: [8]u32, coefficient_cells: usize, transferred: *bool) !void {
        const b = self.backend;
        const r = self.request;
        if (r.expected_main_root) |expected| if (!std.mem.eql(u8, &root, &expected)) return error.DeviceMainReplayRootMismatch;
        var final_scope = r.scope;
        if (r.tree_index == 1) final_scope.main = root;
        const promoted = @import("pcs_scope.zig").identity(final_scope);
        std.debug.print("GPU_TRACE_OWNERSHIP tree={} coefficient_words={} scratch_words={} final_coefficient_copy_words={}\n", .{ r.tree_index, coefficient_cells, 0, @as(usize, 0) });
        const columns = try b.host_allocator.alloc(D.Column, r.columns.len);
        errdefer b.host_allocator.free(columns);
        for (columns, r.columns, 0..) |*column, input, i| column.* = .{ .log_size = input.log_size, .device = .{ .words = coefficients.words.? + offsets[i], .count = @as(u64, 1) << @intCast(input.log_size), .context_token = coefficients.context_token, .generation = coefficients.generation } };
        try check(b.rebind(b.service.session, coefficients, &scope, &promoted));
        try b.service.retainDeviceLease(promoted, coefficients.*);
        transferred.* = true;
        _ = ctx;
        self.result = .{ .root = root, .columns = columns };
    }
    fn run(self: *Job, raw: *anyopaque, token: u64) !void {
        var range = try @import("nvtx_stage.zig").Range.begin(&self.backend.service.library, raw, switch (self.request.tree_index) {
            0 => "rv64/TC/FIXED",
            1 => "rv64/TC/MAIN",
            else => "rv64/TC/INTER",
        });
        defer range.deinit();
        const b = self.backend;
        const a = self.a;
        const r = self.request;
        const beta = r.config.fri_config.log_blowup_factor;
        const scope = @import("pcs_scope.zig").identity(r.scope);
        var ctx = SC.Context{ .session = b.service.session, .native_context = raw, .token = token, .scope = scope, .api = &b.api };
        const order = try a.alloc(usize, r.columns.len);
        defer a.free(order);
        const offsets = try a.alloc(usize, r.columns.len);
        defer a.free(offsets);
        for (order, 0..) |*i, k| i.* = k;
        const Sort = struct {
            columns: []const D.TraceColumn,
            fn less(s: @This(), x: usize, y: usize) bool {
                return s.columns[x].log_size < s.columns[y].log_size or (s.columns[x].log_size == s.columns[y].log_size and x < y);
            }
        };
        std.mem.sort(usize, order, Sort{ .columns = r.columns }, Sort.less);
        var coefficient_cells: usize = 0;
        var max_log: u32 = 0;
        for (order) |original| {
            offsets[original] = coefficient_cells;
            coefficient_cells = try std.math.add(usize, coefficient_cells, @as(usize, 1) << @intCast(r.columns[original].log_size));
            max_log = @max(max_log, r.columns[original].log_size);
        }
        const eval_cells = try std.math.mul(usize, coefficient_cells, @as(usize, 1) << @intCast(beta));
        const eval_log = max_log + beta;
        const tw = try b.tw(eval_log);
        // The established column LDE ABI accepts a compact coefficient stride
        // when beta=1. Keep these coefficients in their final owned lease:
        // committing must not allocate and copy a second full coefficient slab.
        const separate_coefficients = beta == 1 and b.n2b_columns != null;
        var coefficients = Native.Lease{};
        var transferred = false;
        defer if (!transferred and coefficients.words != null) {
            ctx.join() catch {};
            _ = b.api.release(b.service.session, &coefficients);
        };
        if (separate_coefficients) coefficients = try self.allocate(&ctx, coefficient_cells, 2, "coefficients");
        // The source's INTER evaluations are dead after joined coefficient
        // ingress. Retire them before the much larger LDE/tree scratch exists.
        if (r.retire_input) |retirement| {
            try self.copyInputs(&ctx, try ctx.borrow(coefficients), coefficients.words.?, order, offsets);
            try retireJoinedInput(&ctx, retirement, r.scope);
        }
        const stream_budget: ?usize = if (separate_coefficients and b.mixed_seeded != null and b.layer != null) streamBudget() else null;
        // Predicted-peak selection: a narrow tree's two state banks can exceed
        // its whole LDE. Both paths commit identical words; take the smaller.
        const streamed_budget: ?usize = if (self.admission_plan) |plan| plan.selected_stream_budget else if (stream_budget) |budget| (if (try self.streamPays(order, beta, tw, budget)) budget else null) else null;
        if (streamed_budget) |budget| {
            if (r.retire_input == null) try self.copyInputs(&ctx, try ctx.borrow(coefficients), coefficients.words.?, order, offsets);
            const root = try self.streamRoot(&ctx, raw, order, offsets, coefficients.words.?, beta, tw, budget);
            try self.publish(&ctx, root, &coefficients, offsets, scope, coefficient_cells, &transferred);
            return;
        }
        const tw_base = try std.math.add(usize, if (separate_coefficients) 0 else coefficient_cells, eval_cells);
        const inverse_base = try std.math.add(usize, tw_base, tw.twiddles.len);
        const desc_base = std.mem.alignForward(usize, try std.math.add(usize, inverse_base, tw.itwiddles.len), 2);
        const arena_cells = try std.math.add(usize, desc_base, try std.math.mul(usize, r.columns.len, 7));
        var arena = try self.allocate(&ctx, arena_cells, 0, "lde_arena");
        defer {
            ctx.join() catch {};
            _ = b.api.release(b.service.session, &arena);
        }
        const ptr = arena.words.?;
        const arena_slice = try ctx.borrow(arena);
        const coefficient_slice = if (separate_coefficients) try ctx.borrow(coefficients) else arena_slice;
        const coefficient_ptr = if (separate_coefficients) coefficients.words.? else ptr;
        const descriptors = try a.alloc(u32, 7 * order.len);
        defer a.free(descriptors);
        var eval_offset: usize = if (separate_coefficients) 0 else coefficient_cells;
        var segments: std.ArrayList(A.MixedSegment) = .empty;
        defer segments.deinit(a);
        if (r.retire_input == null) try self.copyInputs(&ctx, coefficient_slice, coefficient_ptr, order, offsets);
        for (order, 0..) |original, i| {
            const column = r.columns[original];
            const count = @as(usize, 1) << @intCast(column.log_size);
            const rows = count << @intCast(beta);
            descriptors[6 * order.len + i] = column.log_size;
            descriptors[6 * i ..][0..6].* = .{ @truncate(offsets[original]), @truncate(@as(u64, offsets[original]) >> 32), @truncate(eval_offset), @truncate(@as(u64, eval_offset) >> 32), column.log_size, 0 };
            if (segments.items.len != 0 and segments.items[segments.items.len - 1].source_size == rows) segments.items[segments.items.len - 1].capacity_words += rows else try segments.append(a, .{ .columns = ptr + eval_offset, .stride_words = rows, .capacity_words = rows, .source_size = @intCast(rows), .reserved = 0 });
            eval_offset += rows;
        }
        try check(b.api.upload(raw, ptr + tw_base, tw.twiddles.ptr, tw.twiddles.len * 4));
        try check(b.api.upload(raw, ptr + inverse_base, tw.itwiddles.ptr, tw.itwiddles.len * 4));
        try check(b.api.upload(raw, ptr + desc_base, descriptors.ptr, descriptors.len * 4));
        // M6 enqueue: same lane-0 ordering as streamRoot (no ingress join).
        const lane = try computeLane(b, raw);
        var launches: u32 = 0;
        var interpolation_first: usize = 0;
        while (interpolation_first < order.len) {
            const original = order[interpolation_first];
            const column = r.columns[original];
            if (column.encoding != .evaluations) {
                interpolation_first += 1;
                continue;
            }
            // Sorting preserves native order within a height. Batch only
            // adjacent evaluation columns; a coefficient column splits a run
            // and must never be interpolated a second time.
            var interpolation_end = interpolation_first + 1;
            while (interpolation_end < order.len and
                r.columns[order[interpolation_end]].log_size == column.log_size and
                r.columns[order[interpolation_end]].encoding == .evaluations) : (interpolation_end += 1)
            {}
            const rows = @as(usize, 1) << @intCast(column.log_size);
            const inverse_offset = inverse_base + tw.itwiddles.len - rows / 2;
            try check(b.b2n(coefficient_ptr + offsets[original], rows, coefficient_ptr + offsets[original], rows, column.log_size, @intCast(interpolation_end - interpolation_first), ptr + inverse_offset, @intCast(rows / 2), @intCast(rows / 2), lane, &launches));
            interpolation_first = interpolation_end;
        }
        var first: usize = 0;
        while (first < order.len) {
            const log = r.columns[order[first]].log_size + beta;
            var end = first + 1;
            while (end < order.len and r.columns[order[end]].log_size + beta == log) : (end += 1) {}
            const rows = @as(usize, 1) << @intCast(log);
            const destination = @as(u64, descriptors[6 * first + 2]) | (@as(u64, descriptors[6 * first + 3]) << 32);
            if (separate_coefficients) {
                const count = @as(usize, 1) << @intCast(r.columns[order[first]].log_size);
                try check(b.n2b_columns.?(coefficient_ptr + offsets[order[first]], count, ptr + desc_base + 6 * order.len + first, ptr + @as(usize, @intCast(destination)), rows, log, @intCast(end - first), ptr + tw_base + tw.twiddles.len - rows / 2, @intCast(rows / 2), @intCast(rows / 2), lane, &launches));
            } else try check(b.n2b(ptr, arena.count, ptr + desc_base + 6 * first, @intCast(end - first), @intCast(destination), log, ptr + tw_base + tw.twiddles.len - rows / 2, @intCast(rows / 2), @intCast(rows / 2), lane, 1, &launches));
            first = end;
        }
        const tree_words = ((@as(usize, 2) << @intCast(eval_log)) - 1) * 8;
        // Two 96-byte native prefix-state banks at the largest nonfinal
        // height. This scratch is admitted with the tree lease, so it shares
        // the context pool and idle-PCS eviction rather than cudaMallocAsync's
        // unrelated default pool.
        var prefix_rows: usize = 0;
        for (segments.items[0 .. segments.items.len - 1]) |segment| prefix_rows = @max(prefix_rows, segment.source_size);
        var prefix_words = try std.math.mul(usize, prefix_rows, 48);
        // Older images need two equal-size banks. Shrink only when the loaded
        // runtime explicitly supplies its exact scratch geometry, so it cannot
        // fall back to an untracked allocation because of a smaller caller tail.
        if (b.prefix_workspace) |query| {
            var words: u64 = 0;
            try check(query(segments.items.ptr, @intCast(segments.items.len), &words));
            if (words > prefix_words) return error.InvalidTracePrefixWorkspace;
            prefix_words = std.math.cast(usize, words) orelse return error.SizeOverflow;
        }
        const tree_capacity = try std.math.add(usize, tree_words, prefix_words);
        var tree = try self.allocate(&ctx, tree_capacity, 0, "merkle_tree_and_prefix");
        defer {
            ctx.join() catch {};
            _ = b.api.release(b.service.session, &tree);
        }
        self.samplePeak(&ctx, "legacy", (arena_cells + tree_capacity) * 4, (arena_cells + tree_capacity) * 4, coefficient_cells * 4, 0);
        try check(b.tree(raw, compute_lane_index, @ptrCast(segments.items.ptr), @intCast(segments.items.len), eval_log, tree.words.?, tree_capacity));
        var root_words: [8]u32 = undefined;
        try check(b.api.download(raw, &root_words, tree.words.? + tree_words - 8, 32));
        try ctx.join();
        var root: [32]u8 = undefined;
        for (root_words, 0..) |v, i| std.mem.writeInt(u32, root[4 * i ..][0..4], v, .little);
        if (r.expected_main_root) |expected| if (!std.mem.eql(u8, &root, &expected)) return error.DeviceMainReplayRootMismatch;
        var final_scope = r.scope;
        if (r.tree_index == 1) final_scope.main = root;
        const promoted = @import("pcs_scope.zig").identity(final_scope);
        if (!separate_coefficients) {
            coefficients = try self.allocate(&ctx, coefficient_cells, 2, "coefficients");
            try check(b.copy(raw, coefficients.words.?, ptr, coefficient_cells * 4));
            try ctx.join();
        }
        std.debug.print("GPU_TRACE_OWNERSHIP tree={} coefficient_words={} scratch_words={} final_coefficient_copy_words={}\n", .{ r.tree_index, coefficient_cells, arena_cells, if (separate_coefficients) @as(usize, 0) else coefficient_cells });
        const columns = try b.host_allocator.alloc(D.Column, r.columns.len);
        errdefer b.host_allocator.free(columns);
        for (columns, r.columns, 0..) |*column, input, i| column.* = .{ .log_size = input.log_size, .device = .{ .words = coefficients.words.? + offsets[i], .count = @as(u64, 1) << @intCast(input.log_size), .context_token = coefficients.context_token, .generation = coefficients.generation } };
        try check(b.rebind(b.service.session, &coefficients, &scope, &promoted));
        try b.service.retainDeviceLease(promoted, coefficients);
        transferred = true;
        self.result = .{ .root = root, .columns = columns };
    }
};
/// M6 enqueue: commitment kernels share lane 0 with the context's staged
/// copies, so stage ordering is a stream property instead of a host join.
const compute_lane_index: u32 = 0;
fn computeLane(b: *Context, raw: *anyopaque) !*anyopaque {
    var stream: ?*anyopaque = null;
    try check(b.api.lane_stream(raw, compute_lane_index, &stream));
    return stream orelse error.InvalidLane;
}
fn retireJoinedInput(ctx: *SC.Context, retirement: D.TraceInputRetirement, scope: D.Scope) !void {
    try ctx.join();
    try retirement.invoke(ctx.native_context, ctx.token, scope);
}

test "trace INTER input retirement waits for ingress join and propagates failures" {
    const Fake = struct {
        syncs: usize = 0,
        calls: usize = 0,
        fail_sync: bool = false,
        fail_retire: bool = false,
        fn sync(raw: *anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.syncs += 1;
            return if (self.fail_sync) 1 else 0;
        }
        fn retire(raw: *anyopaque, native: *anyopaque, token: u64, _: D.Scope) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            try std.testing.expect(raw == native and token == 7);
            try std.testing.expectEqual(self.syncs, self.calls + 1);
            self.calls += 1;
            if (self.fail_retire) return error.RetirementFailure;
        }
    };
    var fake: Fake = .{};
    var api: SC.Api = undefined;
    api.sync = Fake.sync;
    const scope = D.Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 4 };
    const retirement = D.TraceInputRetirement{ .context = &fake, .scope = scope, .retire = Fake.retire };
    var ctx = SC.Context{ .session = &fake, .native_context = &fake, .token = 7, .scope = @import("pcs_scope.zig").identity(scope), .api = &api };
    try retireJoinedInput(&ctx, retirement, scope);
    try std.testing.expectEqual(@as(usize, 1), fake.calls);
    fake.fail_retire = true;
    try std.testing.expectError(error.RetirementFailure, retireJoinedInput(&ctx, retirement, scope));
    try std.testing.expectEqual(@as(usize, 2), fake.calls);
    fake.fail_sync = true;
    try std.testing.expectError(error.CudaJoinFailed, retireJoinedInput(&ctx, retirement, scope));
    try std.testing.expectEqual(@as(usize, 2), fake.calls);
    var other = scope;
    other.ordinal += 1;
    try std.testing.expectError(error.InvalidTraceInputRetirementScope, retirement.invoke(&fake, 7, other));
    try std.testing.expectEqual(@as(usize, 2), fake.calls);
}

test "resident trace commitment instantiates the typed mixed-encoding callback" {
    std.testing.refAllDecls(Context);
}

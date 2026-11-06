//! Actual native CPU-worker composition on its persistent GPU owner. Coefficients
//! are ingress only; quotient buckets, interpolation and final coefficients never
//! return to the host. The sole numerical readback is the committed root.
const std = @import("std");
const N2bColumnsCompact = *const fn ([*]const u32, usize, [*]const u32, [*]u32, usize, u32, u32, [*]const u32, u32, u32, usize, ?*anyopaque, *u32) callconv(.c) c_int;
const CopyRun = @import("device_copy_run.zig").Run;
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_riscv_cpu_integration");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = CPU.rv64_device_pcs;
const Native = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const Service = @import("pcs_native.zig");
const G = @import("joined_codegen.zig");
const Oracle = @import("joined_fixture_support.zig");
const Hybrid = @import("real_composition.zig");
const Abi = @import("abi.zig");
const Events = @import("cuda_events.zig");
const Span = enum { coefficients, auxiliary, domain_fft, rows, finalize, commit_fft, commit_hash };
const Timing = Events.RecorderFor(Span);
const O = D.O;
const M = D.M;
const Items = CPU.rv64_gkr_cpu_components;
const Sparse = @import("composition_sparse_runtime.zig");
const AdmissionRuntime = @import("admission_runtime.zig");
const Admission = @import("global_admission.zig");
const WorkspaceCost = @import("composition_cost.zig");
const Columns = @import("composition_columns.zig");
const Trace = engine.air.component_prover.ForField(O).Trace;
const Twiddle = engine.poly.twiddles.TwiddleTree([]M);
const N2b = *const fn ([*]u32, usize, ?*const anyopaque, u32, usize, u32, [*]const u32, u32, u32, *anyopaque, u32, *u32) callconv(.c) c_int;
const B2n = *const fn ([*]const u32, usize, [*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
const Copy = Native.CopyDevice;
const Clear = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;
fn check(status: c_int) !void {
    if (status != 0) return error.CudaResidentCompositionFailed;
}
fn sym(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse {
        std.debug.print("GPU_COMPOSITION_MISSING_SYMBOL name={s}\n", .{name});
        return error.MissingResidentCompositionSymbol;
    };
}
fn words(values: []const M) []const u32 {
    return @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
}
fn felts(a: std.mem.Allocator, values: []const O) ![]u32 {
    const out = try a.alloc(u32, values.len * 8);
    for (values, 0..) |v, i| for (v.toM31Array(), 0..) |w, j| {
        out[i * 8 + j] = w.v;
    };
    return out;
}
fn sourceColumn(source: engine.air.component_prover.ForField(O).Poly) !D.Column {
    try source.validate();
    if (source.device) |device| {
        if (device.count == 0 or !std.math.isPowerOfTwo(device.count) or device.count > (@as(u64, 1) << 28)) return error.InvalidResidentSource;
        return .{ .log_size = std.math.log2_int(u64, device.count), .device = device };
    }
    const p = source.coefficients orelse return error.DevicePcsCoefficientsRequired;
    return .{ .log_size = p.logSize(), .coefficients = p.coefficients() };
}
// Retain only authenticated executable metadata, not the cold symbolic DAG.
pub const KernelMetadata = struct {
    chunks: ?@import("outer_chunks_runtime.zig").Runtime = null,
    allocator: std.mem.Allocator,
    program: struct { identity: [32]u8, inputs: []engine.air.secure_polynomial_program_v2.Input, roots: []u32 },
    parameter_slots: []u32,
    /// Transfer the authenticated immutable executable metadata only. The
    /// frontend releases the wide cold DAG immediately after constructing this.
    pub fn fromProgram(a: std.mem.Allocator, program: *@import("composition_codegen.zig").Program, slots: *[]u32) !KernelMetadata {
        try program.validate();
        if (program.parameters.len != slots.len) return error.InvalidResidentMetadata;
        const result = KernelMetadata{ .allocator = a, .program = .{ .identity = program.identity, .inputs = program.inputs, .roots = program.roots }, .parameter_slots = slots.* };
        program.inputs = &.{};
        program.roots = &.{};
        slots.* = &.{};
        return result;
    }
    fn take(wide: anytype) KernelMetadata {
        const out = KernelMetadata{ .allocator = wide.a, .program = .{ .identity = wide.program.identity, .inputs = wide.program.inputs, .roots = wide.program.roots }, .parameter_slots = wide.parameter_slots };
        wide.program.inputs = &.{};
        wide.program.roots = &.{};
        wide.parameter_slots = &.{};
        return out;
    }
    pub fn bytes(self: *const KernelMetadata) usize {
        return self.program.inputs.len * @sizeOf(engine.air.secure_polynomial_program_v2.Input) + self.program.roots.len * 4 + self.parameter_slots.len * 4 + (if (self.chunks) |*chunks| chunks.bytes() else 0);
    }
    pub fn deinit(self: *KernelMetadata) void {
        if (self.chunks) |*chunks| chunks.deinit();
        self.allocator.free(self.program.inputs);
        self.allocator.free(self.program.roots);
        self.allocator.free(self.parameter_slots);
    }
};
const TwiddleBorrow = struct {
    value: Twiddle,
    retained: bool,
    fn deinit(self: *@This(), a: std.mem.Allocator) void {
        if (!self.retained) engine.poly.twiddles.deinitM31(a, &self.value);
    }
};
const Geometry = struct {
    key: [32]u8,
    source_words: usize,
    eval_base: usize,
    tw_base: usize,
    desc_base: usize,
    arena_words: usize,
    descriptors: []u32,
    masks: []u64,
    denominators: []M,
    fn validate(self: *const @This(), log: u32) !void {
        if (log < 3 or log > 28 or self.descriptors.len % 6 != 0 or self.eval_base != self.source_words or self.desc_base % 2 != 0 or self.arena_words < self.desc_base + self.descriptors.len) return error.InvalidCompositionGeometry;
        const n = @as(u64, 1) << @intCast(log);
        for (0..self.descriptors.len / 6) |i| {
            const d = self.descriptors[i * 6 ..][0..6];
            const source = @as(u64, d[0]) | (@as(u64, d[1]) << 32);
            const destination = @as(u64, d[2]) | (@as(u64, d[3]) << 32);
            if (d[4] >= log or d[5] != 0 or source > self.eval_base or (@as(u64, 1) << @intCast(d[4])) > self.eval_base - source or destination != self.eval_base + i * n) return error.InvalidCompositionGeometry;
        }
    }
    fn bytes(self: *const @This()) usize {
        return self.descriptors.len * 4 + self.masks.len * 8 + self.denominators.len * 4;
    }
    fn deinit(self: *@This(), a: std.mem.Allocator) void {
        a.free(self.descriptors);
        a.free(self.masks);
        a.free(self.denominators);
    }
};
const GeometryBorrow = struct {
    value: Geometry,
    retained: bool,
    fn deinit(self: *@This(), a: std.mem.Allocator) void {
        if (!self.retained) self.value.deinit(a);
    }
};
pub const ClassRole = struct {
    namespace: enum { cpu, truth, outer },
    id: u32,
    artifact: *const KernelMetadata,
    trace_log: u32,
    eval_log: u32,
    widths: [3]usize,
    offsets: [3]usize,
    fixed_indices: ?[]const u32 = null,
    auxiliary: WorkspaceCost.Auxiliary = .none,
};
const PhasePoolTrim = @import("phase_pool_trim.zig");
pub const Context = struct {
    pool_trim: PhasePoolTrim.Policy = .{},
    direct_policy: bool = true,
    compact_policy: bool = true,
    enqueue_policy: bool = true,
    workspace_policy: bool = false,
    column_policy: bool = false,
    allocator: std.mem.Allocator,
    service: *Service.Context,
    session_api: SC.Api,
    timing: Events.Api,
    role: ?*const @TypeOf(Abi.stwo_rv64_composition_role_on),
    finish: *const @TypeOf(Abi.stwo_rv64_composition_finish_on),
    auxiliary: *const @TypeOf(Abi.stwo_rv64_composition_auxiliary_on),
    tree: *const @TypeOf(Abi.stwo_rv64_trace_tree_on),
    n2b: N2b,
    n2b_columns: ?*const @TypeOf(@import("stwo_cuda_backend").abi.stages.transform.stwo_lde_n2b_columns_on) = null,
    /// M5 platform: compact-source LDE (degree el-2 columns extended straight
    /// from their lease). Null on an older library: el-2 columns stay staged.
    n2b_columns_compact: ?N2bColumnsCompact = null,
    b2n: B2n,
    copy: Copy,
    clear: Clear,
    artifacts: [49]KernelMetadata,
    truth_artifacts: [15]?KernelMetadata = @splat(null),
    sparse_truth: ?Sparse.Runtime = null,
    truth_role: ?*const @TypeOf(Abi.stwo_rv64_composition_role_on) = null,
    twiddles: [29]?Twiddle = @splat(null),
    mutex: std.Thread.Mutex = .{},
    geometries: std.ArrayList(Geometry) = .empty,
    /// Per-owner retained setup cap. Oversized entries remain request-local.
    cache_limit_bytes: usize = 256 << 20,
    artifact_bytes: usize = 0,
    artifact_count: usize = 0,
    geometry_bytes: usize = 0,
    twiddle_bytes: usize = 0,
    uncached_geometries: u64 = 0,
    uncached_twiddles: u64 = 0,
    geometry_hits: u64 = 0,
    geometry_misses: u64 = 0,
    log_blowup: u32 = 1,
    result_columns: std.ArrayList([]D.Column) = .empty,
    pub fn initNumerical(a: std.mem.Allocator, service: *Service.Context) !Context {
        const result = Context{ .column_policy = if (std.posix.getenv("STWO_RV64_RC_COMPOSITION_COLUMNS")) |v| std.mem.eql(u8, v, "1") else false, .direct_policy = !(if (std.posix.getenv("STWO_RV64_COMPOSITION_DIRECT")) |v| std.mem.eql(u8, v, "0") else false), .compact_policy = !(if (std.posix.getenv("STWO_RV64_COMPOSITION_DIRECT_EL2")) |v| std.mem.eql(u8, v, "0") else false), .enqueue_policy = if (std.posix.getenv("STWO_RV64_COMPOSITION_ENQUEUE")) |v| !std.mem.eql(u8, v, "0") else true, .workspace_policy = if (std.posix.getenv("STWO_RV64_RC_ROLE_WORKSPACE")) |v| std.mem.eql(u8, v, "1") else false, .pool_trim = try PhasePoolTrim.Policy.init(try PhasePoolTrim.fromEnv(a), service.library.lookup(PhasePoolTrim.Trim, "stwo_exec_context_pool_trim")), .allocator = a, .service = service, .timing = try Events.Api.load(&service.library), .session_api = .{
            .allocate = service.lease_allocate,
            .release = service.lease_release,
            .validate_range = service.lease_validate_range,
            .upload = try sym(Native.Upload, &service.library, "stwo_exec_context_memcpy_h2d_async"),
            .download = try sym(Native.Download, &service.library, "stwo_exec_context_memcpy_d2h_async"),
            .sync = try sym(Native.Sync, &service.library, "stwo_exec_context_sync"),
            .lane_stream = try sym(Native.LaneStream, &service.library, "stwo_exec_context_lane_stream"),
        }, .role = service.library.lookup(*const @TypeOf(Abi.stwo_rv64_composition_role_on), "stwo_rv64_composition_role_on"), .finish = try sym(*const @TypeOf(Abi.stwo_rv64_composition_finish_on), &service.library, "stwo_rv64_composition_finish_on"), .auxiliary = try sym(*const @TypeOf(Abi.stwo_rv64_composition_auxiliary_on), &service.library, "stwo_rv64_composition_auxiliary_on"), .tree = try sym(*const @TypeOf(Abi.stwo_rv64_trace_tree_on), &service.library, "stwo_rv64_trace_tree_on"), .n2b = try sym(N2b, &service.library, "stwo_lde_n2b_addressed_on"), .n2b_columns = service.library.lookup(*const @TypeOf(@import("stwo_cuda_backend").abi.stages.transform.stwo_lde_n2b_columns_on), "stwo_lde_n2b_columns_on"), .n2b_columns_compact = service.library.lookup(N2bColumnsCompact, "stwo_lde_n2b_columns_compact_on"), .b2n = try sym(B2n, &service.library, "stwo_ntt_b2n_columns_compact_on"), .copy = try sym(Copy, &service.library, "stwo_exec_context_memcpy_d2d_async"), .clear = try sym(Clear, &service.library, "stwo_exec_context_memset_async"), .artifacts = undefined };
        if (service.admission) |endpoint| try endpoint.planner.registerCoverage(endpoint.physical, .recursion_composition);
        return result;
    }
    pub fn init(a: std.mem.Allocator, service: *Service.Context) !Context {
        var result = try initNumerical(a, service);
        if (result.role == null) return error.CpuCompositionNotInitialized;
        var made: usize = 0;
        errdefer for (result.artifacts[0..made]) |*item| item.deinit();
        for (Oracle.descriptors(), &result.artifacts) |d, *artifact| {
            var wide = try G.record(a, d);
            defer wide.deinit();
            artifact.* = KernelMetadata.take(&wide);
            result.artifact_bytes += artifact.bytes();
            made += 1;
            result.artifact_count = made;
        }
        if (result.artifact_bytes > result.cache_limit_bytes) return error.CompositionMetadataCacheCapExceeded;
        if (service.admission) |endpoint| try endpoint.planner.registerCoverage(endpoint.physical, .native_composition);
        return result;
    }
    pub fn deinit(self: *Context) void {
        if (self.sparse_truth) |*sparse| sparse.deinit();
        for (self.artifacts[0..self.artifact_count]) |*artifact| artifact.deinit();
        for (&self.truth_artifacts) |*artifact| if (artifact.*) |*value| value.deinit();
        for (&self.twiddles) |*cached| if (cached.*) |*value| engine.poly.twiddles.deinitM31(self.allocator, value);
        for (self.geometries.items) |*cached_geometry| cached_geometry.deinit(self.allocator);
        self.geometries.deinit(self.allocator);
        for (self.result_columns.items) |columns| self.allocator.free(columns);
        self.result_columns.deinit(self.allocator);
        self.* = undefined;
    }
    fn executeJob(self: *Context, a: std.mem.Allocator, job: *Job) !D.Tree {
        var permit: ?AdmissionRuntime.Permit = null;
        if (self.service.admission) |*endpoint| {
            var plan = try job.preflightPlan(a);
            defer plan.deinit(a);
            const successor = try self.service.admissionSuccessor(job.scope, .composition);
            @import("allocation_observer.zig").model(job.scope, if (job.outer_workspace) 1 else 2, .composition, plan.additional_peak, plan.retained_after, successor);
            permit = try endpoint.reserve(.{ .owner = .{ .request = std.mem.readInt(u64, job.scope.statement[0..8], .little), .domain = if (job.outer_workspace) .recursion_node else .native_packet, .ordinal = job.scope.ordinal }, .progress_key = Admission.progressKey(job.scope), .stage = .composition, .stage_retained_upper = plan.retained_after, .temporary = plan.additional_peak, .successor = successor, .known = true, .host_known = false });
            job.permit = &permit.?;
        }
        errdefer if (permit) |*claim| {
            if (!claim.closed) claim.finish(.{}) catch {
                claim.endpoint.planner.poisonPhysical(claim.endpoint.physical);
            };
        };
        // Every blocking reservation precedes this context lock and all owner
        // or immutable-cache locks reached by the callback.
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.service.submit(self.service.session, Job.callback, job) != 0) {
            if (permit) |*claim| claim.endpoint.planner.poisonPhysical(claim.endpoint.physical);
            return job.failure orelse error.CudaResidentCompositionFailed;
        }
        const result = job.result orelse return error.CudaResidentCompositionFailed;
        if (permit) |*claim| try self.service.completeAdmission(claim, job.scope, try self.service.admissionSuccessor(job.scope, .composition));
        self.result_columns.append(self.allocator, @constCast(result.columns)) catch |err| {
            self.allocator.free(@constCast(result.columns));
            return err;
        };
        return result;
    }
    /// Pure source-class geometry; no device pointers, locks or allocations on
    /// a GPU. All producer trees are promised compact resident coefficients.
    pub fn classAllocationPlan(self: *const Context, a: std.mem.Allocator, classes: []const ClassRole, tree_logs: [3][]const u32, log: u32, split: u32, total: usize, beta: u32, fixed_cold_words: u64, shared_arena: bool) !WorkspaceCost.Plan {
        const roles = try a.alloc(WorkspaceCost.Role, classes.len);
        defer a.free(roles);
        var made: usize = 0;
        defer for (roles[0..made]) |role| a.free(role.columns);
        const direct = self.n2b_columns != null and self.direct_policy;
        const compact = direct and self.n2b_columns_compact != null and self.compact_policy;
        for (classes, roles) |c, *out| {
            const columns = try a.alloc(WorkspaceCost.Column, c.widths[0] + c.widths[1] + c.widths[2]);
            errdefer a.free(columns);
            var at: usize = 0;
            for (0..3) |tree| for (0..c.widths[tree]) |column| {
                const index = if (tree == 0 and c.fixed_indices != null) blk: {
                    if (c.fixed_indices.?.len != c.widths[0]) return error.InvalidResidentCompositionRoles;
                    break :blk c.fixed_indices.?[column];
                } else try std.math.add(usize, c.offsets[tree], column);
                if (index >= tree_logs[tree].len) return error.InvalidResidentCompositionRoles;
                const degree = tree_logs[tree][index];
                columns[at] = .{ .log = degree, .direct = (direct and degree + 1 == c.eval_log) or (compact and degree + 2 == c.eval_log) };
                at += 1;
            };
            out.* = .{ .trace_log = c.trace_log, .eval_log = c.eval_log, .columns = columns, .auxiliary = c.auxiliary, .masks = c.artifact.program.inputs.len, .parameters = c.artifact.parameter_slots.len, .constraints = c.artifact.program.roots.len };
            if (!shared_arena) out.selected_columns = try self.selectedColumns(a, c.namespace == .outer, c.widths, c.artifact, out.*);
            if (self.sparse_truth) |*sparse| {
                var widths = c.widths;
                if (c.auxiliary == .last) widths[2] += 1;
                if (c.namespace == .truth and sparse.matches(c.artifact.program.identity, c.id, c.trace_log, c.eval_log, widths, c.artifact.program.inputs.len, c.artifact.program.roots.len, c.artifact.parameter_slots.len)) out.sparse = sparse.selection();
            }
            made += 1;
        }
        return WorkspaceCost.init(a, .{ .roles = roles, .shared_role_arena = shared_arena, .log = log, .split = split, .beta = beta, .separate_coefficients = (beta == 1 and self.n2b_columns != null) or (beta == 2 and self.n2b_columns_compact != null), .constraints = total, .fixed_cold_words = fixed_cold_words });
    }
    fn selectedColumns(self: *const Context, a: std.mem.Allocator, outer: bool, widths: [3]usize, artifact: *const KernelMetadata, role: WorkspaceCost.Role) !?usize {
        if (!self.column_policy or !outer or self.workspace_policy or !self.enqueue_policy or
            role.auxiliary != .none or !Columns.supportsGeometry(role.trace_log, role.eval_log) or
            artifact.program.inputs.len == 0) return null;
        for (role.columns) |column| if (!column.direct) return null;
        if (artifact.chunks != null) return 32;
        var selected = try Columns.Selection.init(a, widths, artifact.program.inputs);
        defer selected.deinit(a);
        if (selected.source_indices.len >= role.columns.len) return null;
        return selected.source_indices.len;
    }
    fn retainedBytes(self: *const Context) usize {
        return self.artifact_bytes + self.geometry_bytes + self.twiddle_bytes;
    }
    fn admitCache(self: *Context, bytes: usize, entry: bool) bool {
        // Only a new geometry can retire prior geometries. A twiddle request
        // may occur while the current geometry's arrays are still borrowed.
        if (!entry) return bytes <= self.cache_limit_bytes - @min(self.cache_limit_bytes, self.retainedBytes());
        while (self.geometries.items.len != 0 and (bytes > self.cache_limit_bytes - @min(self.cache_limit_bytes, self.retainedBytes()) or (entry and self.geometries.items.len >= 256))) {
            var old = self.geometries.swapRemove(0);
            self.geometry_bytes -= old.bytes();
            old.deinit(self.allocator);
        }
        return bytes <= self.cache_limit_bytes - @min(self.cache_limit_bytes, self.retainedBytes());
    }
    fn tw(self: *Context, log: u32) !TwiddleBorrow {
        if (self.twiddles[log]) |value| return .{ .value = value, .retained = true };
        const value = try engine.poly.twiddles.precomputeM31(self.allocator, core.poly.circle.canonic.CanonicCoset.new(log).circleDomain().half_coset);
        const bytes = (value.twiddles.len + value.itwiddles.len) * @sizeOf(M);
        if (!self.admitCache(bytes, false)) {
            self.uncached_twiddles += 1;
            return .{ .value = value, .retained = false };
        }
        self.twiddles[log] = value;
        self.twiddle_bytes += bytes;
        return .{ .value = value, .retained = true };
    }
    fn geometry(self: *Context, artifact: *const KernelMetadata, rl: u32, el: u32, widths: [3]usize, sources: []const D.Column, auxiliary_count: usize, twiddle_words: usize) !GeometryBorrow {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("rv64/cuda/composition-immutable-geometry/v1");
        hash.update(&artifact.program.identity);
        for ([_]usize{ rl, el, widths[0], widths[1], widths[2], auxiliary_count, twiddle_words }) |value| {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, value, .little);
            hash.update(&bytes);
        }
        for (sources) |source| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, source.log_size, .little);
            hash.update(&bytes);
        }
        const key = hash.finalResult();
        for (self.geometries.items) |*cached| if (std.mem.eql(u8, &cached.key, &key)) {
            self.geometry_hits += 1;
            return .{ .value = cached.*, .retained = true };
        };
        const a = self.allocator;
        const n = @as(usize, 1) << @intCast(el);
        const count = sources.len + auxiliary_count;
        const descriptors = try a.alloc(u32, count * 6);
        errdefer a.free(descriptors);
        var source_words: usize = 0;
        for (0..count) |i| {
            const degree = if (i < sources.len) sources[i].log_size else rl;
            if (degree > el) return error.InvalidResidentSource;
            const size = @as(usize, 1) << @intCast(degree);
            const dst = i * n;
            descriptors[i * 6 ..][0..6].* = .{ @truncate(source_words), @truncate(@as(u64, source_words) >> 32), @truncate(dst), @truncate(@as(u64, dst) >> 32), degree, 0 };
            source_words = try std.math.add(usize, source_words, size);
        }
        // Addressed LDE destinations are absolute arena offsets, not offsets
        // relative to the evaluation slab. Source extent is known only now.
        for (0..count) |i| {
            const destination = try std.math.add(usize, source_words, try std.math.mul(usize, i, n));
            descriptors[i * 6 + 2] = @truncate(destination);
            descriptors[i * 6 + 3] = @truncate(@as(u64, destination) >> 32);
        }
        const masks = try a.alloc(u64, artifact.program.inputs.len);
        errdefer a.free(masks);
        for (masks, artifact.program.inputs) |*off, input| off.* = @as(u64, input.column) * n;
        const denominators = try A.geometry.denominatorInverses(a, rl, el);
        errdefer a.free(denominators);
        const tw_base = try std.math.add(usize, source_words, try std.math.mul(usize, count, n));
        const desc_base = std.mem.alignForward(usize, tw_base + twiddle_words, 2);
        const value = Geometry{ .key = key, .source_words = source_words, .eval_base = source_words, .tw_base = tw_base, .desc_base = desc_base, .arena_words = desc_base + count * 6, .descriptors = descriptors, .masks = masks, .denominators = denominators };
        try value.validate(el);
        self.geometry_misses += 1;
        if (!self.admitCache(value.bytes(), true)) {
            self.uncached_geometries += 1;
            return .{ .value = value, .retained = false };
        }
        try self.geometries.append(a, value);
        self.geometry_bytes += value.bytes();
        return .{ .value = value, .retained = true };
    }

    /// Explicit opt-in: CPU-only use never requires service kernel symbols.
    pub fn truthStage(self: *Context) !CPU.rv64_gkr_truth_device_composition.Stage {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.truth_role == null) {
            const dispatch = try sym(*const @TypeOf(Abi.stwo_rv64_composition_role_on), &self.service.library, "stwo_rv64_truth_composition_role_on");
            for (&self.truth_artifacts, 0..) |*entry, id| if (entry.* == null) {
                var cold = try @import("truth_domain_fixtures.zig").record(self.allocator, @intCast(id));
                defer cold.artifact.deinit();
                if (id == 0) self.sparse_truth = try Sparse.Runtime.init(self.allocator, &cold.artifact.program);
                const bytes = cold.artifact.program.inputs.len * @sizeOf(engine.air.secure_polynomial_program_v2.Input) + cold.artifact.program.roots.len * 4 + cold.artifact.parameter_slots.len * 4;
                if (!self.admitCache(bytes, true)) return error.CompositionMetadataCacheCapExceeded;
                entry.* = KernelMetadata.take(&cold.artifact);
                self.artifact_bytes += bytes;
            };
            self.truth_role = dispatch;
        }
        return .{ .context = self, .evaluate_and_commit = evaluateTruth, .evaluate_and_commit_at_blowup = evaluateTruthAtBlowup };
    }
    fn evaluateTruth(raw: *anyopaque, a: std.mem.Allocator, bound: CPU.rv64_gkr_truth_device_composition.Roles, alpha: O, log: u32, split: u32, total: usize, trace: *const anyopaque, scope: D.Scope) !D.Tree {
        const self: *Context = @ptrCast(@alignCast(raw));
        return evaluateTruthAtBlowup(raw, a, bound, alpha, log, split, total, trace, scope, self.log_blowup);
    }
    fn evaluateTruthAtBlowup(raw: *anyopaque, a: std.mem.Allocator, bound: CPU.rv64_gkr_truth_device_composition.Roles, alpha: O, log: u32, split: u32, total: usize, trace: *const anyopaque, scope: D.Scope, beta: u32) !D.Tree {
        if (beta < 1 or beta > 4) return error.UnsupportedResidentCompositionBlowup;
        const self: *Context = @ptrCast(@alignCast(raw));
        const count: usize = switch (bound) {
            .classic => |v| v.len,
            .delegated => 1,
        };
        const roles = try a.alloc(RuntimeRole, count);
        defer a.free(roles);
        var made: usize = 0;
        defer for (roles[0..made]) |role| a.free(role.parameters);
        switch (bound) {
            .classic => |components| for (components, roles) |*c, *role| {
                const id = try @import("truth_codegen.zig").classicKernelId(c.keccak_policy, c.kind);
                role.* = try self.bindTruthRole(a, id, c.log_size, c.maxConstraintLogDegreeBound(), c.widths(), c.offsets, @import("truth_codegen.zig").nativeMetadata(c), c.nConstraints(), true);
                made += 1;
            },
            .delegated => |c| {
                const id: u32 = switch (c.truth.family()) {
                    .sha256 => 3,
                    .arith256_mod => 4,
                    .add => 5,
                    .double => 6,
                    .bn254_g1_add => 10,
                    .bn254_g1_double => 11,
                    .bn254_fp2_mul => 12,
                    .bls12_381_fp2_mul => 13,
                    .arith384_mont => 14,
                    else => return error.UnsupportedTruthCompositionRole,
                };
                const shape = c.mainShape();
                roles[0] = try self.bindTruthRole(a, id, c.logSize(), c.maxConstraintLogDegreeBound(), .{ shape.fixed, shape.main, c.interWidth() }, .{ c.offsets[0], c.offsets[1], c.inter_offset }, @import("truth_codegen.zig").nativeMetadataV3(c), c.nConstraints(), false);
                made = 1;
            },
        }
        var timer = try std.time.Timer.start();
        var job = Job{ .backend = self, .allocator = a, .roles = roles, .alpha = alpha, .log = log, .split = split, .total = total, .trace = @ptrCast(@alignCast(trace)), .scope = scope, .log_blowup = beta };
        const result = try self.executeJob(a, &job);
        std.debug.print("GPU_TRUTH_COMPOSITION_RESIDENT ordinal={} roles={} total_ns={} quotient_d2h_bytes=0 coefficient_d2h_bytes=0 root_d2h_bytes=32\n", .{ scope.ordinal, count, timer.read() });
        return result;
    }
    fn bindTruthRole(self: *Context, a: std.mem.Allocator, id: u32, trace_log: u32, eval_log: u32, widths: [3]usize, offsets: [3]usize, metadata: [@import("truth_codegen.zig").slots.count]O, constraints: usize, anchor: bool) !RuntimeRole {
        const artifact = &(self.truth_artifacts[id] orelse return error.TruthCompositionNotInitialized);
        if (artifact.program.roots.len != constraints) return error.WrongResidentConstraintCount;
        const parameters = try a.alloc(O, artifact.parameter_slots.len);
        for (parameters, artifact.parameter_slots) |*value, slot| value.* = metadata[slot];
        return .{ .id = id, .artifact = &self.truth_artifacts[id].?, .evaluate = self.truth_role orelse return error.TruthCompositionNotInitialized, .trace_log = trace_log, .eval_log = eval_log, .widths = widths, .offsets = offsets, .parameters = parameters, .auxiliary = if (anchor) .last else .none };
    }
    /// The numerical pipeline is shared by independently admitted frontend
    /// authorities. Parameters, column gathering and root order are explicit;
    /// caller-owned executable metadata must outlive this synchronous call.
    pub fn evaluateRoles(self: *Context, a: std.mem.Allocator, roles: []const RuntimeRole, alpha: O, log: u32, split: u32, total: usize, trace_raw: *const anyopaque, scope: D.Scope) !D.Tree {
        return self.evaluateRolesAtBlowup(a, roles, alpha, log, split, total, trace_raw, scope, self.log_blowup);
    }
    /// Per-call commitment blowup: a shared context serves native (beta 1) and
    /// outer recursion profiles (m3: beta 2/3) without mutating shared state.
    pub fn evaluateRolesAtBlowup(self: *Context, a: std.mem.Allocator, roles: []const RuntimeRole, alpha: O, log: u32, split: u32, total: usize, trace_raw: *const anyopaque, scope: D.Scope, log_blowup: u32) !D.Tree {
        return self.evaluateRolesImpl(a, roles, alpha, log, split, total, trace_raw, scope, log_blowup, false, null);
    }
    /// Only the outer authority explicitly opts this job into the role arena.
    /// The Context is shared with native stages and must never carry this flag.
    pub fn evaluateOuterRolesAtBlowup(self: *Context, a: std.mem.Allocator, roles: []const RuntimeRole, alpha: O, log: u32, split: u32, total: usize, trace_raw: *const anyopaque, scope: D.Scope, log_blowup: u32) !D.Tree {
        return self.evaluateRolesImpl(a, roles, alpha, log, split, total, trace_raw, scope, log_blowup, true, null);
    }
    pub fn evaluateOuterDevicePowersAtBlowup(self: *Context, a: std.mem.Allocator, roles: []const RuntimeRole, alpha: O, log: u32, split: u32, total: usize, trace_raw: *const anyopaque, scope: D.Scope, log_blowup: u32, device_powers: ?Native.Lease) !D.Tree {
        return self.evaluateRolesImpl(a, roles, alpha, log, split, total, trace_raw, scope, log_blowup, true, device_powers);
    }
    fn evaluateRolesImpl(self: *Context, a: std.mem.Allocator, roles: []const RuntimeRole, alpha: O, log: u32, split: u32, total: usize, trace_raw: *const anyopaque, scope: D.Scope, log_blowup: u32, outer_workspace: bool, device_powers: ?Native.Lease) !D.Tree {
        if (log_blowup < 1 or log_blowup > 4) return error.UnsupportedResidentCompositionBlowup;
        const trace: *const Trace = @ptrCast(@alignCast(trace_raw));
        if (trace.polys.items.len != 3 or roles.len == 0 or log < 5 or log > 28 or split < 1 or split > 2) return error.InvalidResidentCompositionRoles;
        var constraints: usize = 0;
        for (roles) |role| {
            if (role.trace_log < 4 or role.eval_log < role.trace_log + 1 or role.eval_log > role.trace_log + 2 or role.eval_log > log or role.artifact.program.roots.len == 0 or role.artifact.parameter_slots.len != role.parameters.len) return error.InvalidResidentCompositionRoles;
            constraints = try std.math.add(usize, constraints, role.artifact.program.roots.len);
            for (0..3) |tree| {
                if (tree == 0 and role.fixed_indices != null) {
                    const indices = role.fixed_indices.?;
                    if (indices.len != role.widths[0]) return error.InvalidResidentCompositionRoles;
                    for (indices) |index| if (index >= trace.polys.items[0].len) return error.InvalidResidentCompositionRoles;
                } else {
                    if (role.offsets[tree] > trace.polys.items[tree].len or role.widths[tree] > trace.polys.items[tree].len - role.offsets[tree]) return error.InvalidResidentCompositionRoles;
                }
            }
        }
        if (constraints != total) return error.WrongResidentConstraintCount;
        var job = Job{ .backend = self, .allocator = a, .roles = roles, .alpha = alpha, .log = log, .split = split, .total = total, .trace = trace, .scope = scope, .log_blowup = log_blowup, .outer_workspace = outer_workspace, .device_powers = device_powers };
        const result = try self.executeJob(a, &job);
        return result;
    }
    pub fn stage(self: *Context) CPU.rv64_gkr_cpu_worker.ResidentCompositionStage {
        return .{ .context = self, .evaluate_and_commit = evaluate, .evaluate_and_commit_at_blowup = evaluateAtBlowup };
    }
    fn evaluate(raw: *anyopaque, a: std.mem.Allocator, items: []const Items.Item, alpha: O, log: u32, split: u32, total: usize, trace_raw: *const anyopaque, scope: D.Scope) !D.Tree {
        const self: *Context = @ptrCast(@alignCast(raw));
        return evaluateAtBlowup(raw, a, items, alpha, log, split, total, trace_raw, scope, self.log_blowup);
    }
    fn evaluateAtBlowup(raw: *anyopaque, a: std.mem.Allocator, items: []const Items.Item, alpha: O, log: u32, split: u32, total: usize, trace_raw: *const anyopaque, scope: D.Scope, beta: u32) !D.Tree {
        if (beta < 1 or beta > 4) return error.UnsupportedResidentCompositionBlowup;
        const self: *Context = @ptrCast(@alignCast(raw));
        if (self.artifact_count != Oracle.count) return error.CpuCompositionNotInitialized;
        var timer = try std.time.Timer.start();
        const roles = try a.alloc(RuntimeRole, items.len);
        defer a.free(roles);
        var made: usize = 0;
        defer for (roles[0..made]) |role| a.free(role.parameters);
        for (items, roles) |*item, *role| switch (item.*) {
            inline else => |*c| {
                const T = @TypeOf(c.*);
                const descriptor = Hybrid.descriptor(T, c);
                const id = try Hybrid.caseId(descriptor);
                const artifact = &self.artifacts[id];
                if (artifact.program.roots.len != c.nConstraints()) return error.WrongResidentConstraintCount;
                const metadata = Hybrid.metadata(T, c, descriptor);
                const parameters = try a.alloc(O, artifact.parameter_slots.len);
                for (parameters, artifact.parameter_slots) |*value, slot| value.* = metadata[slot];
                const shape = c.mainShape();
                const offsets = c.columnOffsets();
                role.* = .{ .id = id, .artifact = artifact, .evaluate = self.role orelse return error.CpuCompositionNotInitialized, .trace_log = G.Authority.RoleGeometry.logSize(c), .eval_log = c.maxConstraintLogDegreeBound(), .widths = .{ shape.fixed, shape.main, G.Authority.RoleGeometry.interWidth(c) }, .offsets = .{ offsets[0], offsets[1], c.inter_offset }, .parameters = parameters };
                if (comptime @hasField(T, "data")) {
                    var hc: [2 * 27 * 8]u32 = undefined;
                    for (0..2) |half| for (0..role.trace_log) |i| for ((if (half == 0) c.data.point.hc0[i] else c.data.point.hc1[i]).toM31Array(), 0..) |word, j| {
                        hc[(half * role.trace_log + i) * 8 + j] = word.v;
                    };
                    role.auxiliary = .{ .hc = hc };
                }
                made += 1;
            },
        };
        var job = Job{ .backend = self, .allocator = a, .roles = roles, .alpha = alpha, .log = log, .split = split, .total = total, .trace = @ptrCast(@alignCast(trace_raw)), .scope = scope, .log_blowup = beta };
        const result = try self.executeJob(a, &job);
        std.debug.print("GPU_COMPOSITION_RESIDENT roles={} total_ns={} quotient_d2h_bytes=0 coefficient_d2h_bytes=0 root_d2h_bytes=32\n", .{ items.len, timer.read() });
        return result;
    }
};
// Frontend authorities bind runtime parameters and offsets once; the numerical
// pipeline is monomorphic for CPU and independently sized truth components.
pub const RuntimeRole = struct {
    id: u32,
    artifact: *const KernelMetadata,
    evaluate: *const @TypeOf(Abi.stwo_rv64_composition_role_on),
    trace_log: u32,
    eval_log: u32,
    widths: [3]usize,
    offsets: [3]usize,
    /// Original AIR-local FIXED reads may gather non-contiguous sorted columns.
    fixed_indices: ?[]const u32 = null,
    parameters: []O,
    auxiliary: union(enum) { none, hc: [2 * 27 * 8]u32, last } = .none,
};
const Job = struct {
    permit: ?*AdmissionRuntime.Permit = null,
    device_powers: ?Native.Lease = null,
    outer_workspace: bool = false,
    backend: *Context,
    allocator: std.mem.Allocator,
    roles: []const RuntimeRole,
    alpha: O,
    log: u32,
    split: u32,
    total: usize,
    trace: *const Trace,
    scope: D.Scope,
    log_blowup: ?u32 = null,
    result: ?D.Tree = null,
    failure: ?anyerror = null,
    active_role: u32 = 999,
    native_context: ?*anyopaque = null,
    fn checked(self: *Job, comptime operation: []const u8, status: c_int) !void {
        if (status != 0) {
            std.debug.print("GPU_COMPOSITION_FAILED ordinal={} role={} operation={s} native_status={}\n", .{ self.scope.ordinal, self.active_role, operation, status });
            if (self.native_context) |raw| self.backend.service.logMemoryFailure(raw, operation);
            return error.CudaResidentCompositionFailed;
        }
    }
    fn callback(raw: *anyopaque, token: u64, user: ?*anyopaque) callconv(.c) c_int {
        const self: *Job = @ptrCast(@alignCast(user orelse return 1));
        self.native_context = raw;
        defer self.native_context = null;
        if (self.permit) |claim| claim.enterOwner(raw) catch |err| {
            self.failure = err;
            return 1;
        };
        const Observer = @import("allocation_observer.zig");
        var observed = Observer.Range.begin(&self.backend.service.library, raw, self.scope, if (self.outer_workspace) 1 else 2, .composition, if (self.backend.enqueue_policy) 0 else 1) catch |err| {
            self.failure = err;
            return 1;
        };
        defer observed.deinit();
        self.run(raw, token) catch |err| {
            if (self.failure == null) self.failure = err;
        };
        if (self.permit) |claim| claim.leaveOwner(raw) catch |err| {
            if (self.failure == null) self.failure = err;
        };
        return @intFromBool(self.failure != null);
    }
    fn cleanupFailure(self: *Job, err: anyerror) void {
        if (self.failure == null) self.failure = err;
        if (self.permit) |claim| claim.endpoint.planner.poisonPhysical(claim.endpoint.physical);
    }
    fn preflightPlan(self: *const Job, a: std.mem.Allocator) !WorkspaceCost.Plan {
        if (self.trace.polys.items.len != 3) return error.InvalidResidentCompositionRoles;
        var logs: [3][]u32 = undefined;
        var made: usize = 0;
        defer for (logs[0..made]) |value| a.free(value);
        var cold_fixed: u64 = 0;
        var host_fixed = false;
        for (0..3) |tree| {
            logs[tree] = try a.alloc(u32, self.trace.polys.items[tree].len);
            made += 1;
            for (self.trace.polys.items[tree], logs[tree]) |poly, *log| {
                const column = try sourceColumn(poly);
                log.* = column.log_size;
                if (tree == 0) {
                    cold_fixed = try std.math.add(u64, cold_fixed, @as(u64, 1) << @intCast(column.log_size));
                    host_fixed = host_fixed or column.device == null;
                }
            }
        }
        const classes = try a.alloc(ClassRole, self.roles.len);
        defer a.free(classes);
        for (self.roles, classes) |role, *out| out.* = .{ .namespace = if (role.evaluate == self.backend.truth_role) .truth else if (self.outer_workspace) .outer else .cpu, .id = role.id, .artifact = role.artifact, .trace_log = role.trace_log, .eval_log = role.eval_log, .widths = role.widths, .offsets = role.offsets, .fixed_indices = role.fixed_indices, .auxiliary = switch (role.auxiliary) {
            .none => .none,
            .last => .last,
            .hc => .hc,
        } };
        const shared = self.outer_workspace and self.backend.workspace_policy;
        return self.backend.classAllocationPlan(a, classes, .{ logs[0], logs[1], logs[2] }, self.log, self.split, self.total, self.log_blowup orelse self.backend.log_blowup, if (host_fixed) cold_fixed else 0, shared);
    }

    fn copyRun(self: *Job, raw: *anyopaque, context: *SC.Context, arena: [*]u32, segment: CopyRun) !void {
        const b = self.backend;
        // Check the WHOLE merged range in this proof's namespace. Adjacency
        // alone is never allocation authority or permission to cross scopes.
        try self.checked("service.lease_validate_range", b.service.lease_validate_range(b.service.session, @ptrFromInt(segment.source), segment.words, segment.context_token, segment.generation, &context.scope));
        try self.checked("copy", b.copy(raw, @ptrCast(arena + segment.target_word), @ptrFromInt(segment.source), try std.math.mul(usize, segment.words, 4)));
    }
    fn workspacePlan(self: *Job, a: std.mem.Allocator, immutable_fixed: []const D.Column, scope: [8]u32) !WorkspaceCost.Plan {
        const roles = try a.alloc(WorkspaceCost.Role, self.roles.len);
        defer a.free(roles);
        var made: usize = 0;
        defer for (roles[0..made]) |role| a.free(role.columns);
        const b = self.backend;
        const direct_enabled = b.n2b_columns != null and b.direct_policy;
        const direct_el2 = direct_enabled and b.n2b_columns_compact != null and b.compact_policy;
        for (self.roles, roles) |role, *out| {
            const columns = try a.alloc(WorkspaceCost.Column, role.widths[0] + role.widths[1] + role.widths[2]);
            errdefer a.free(columns);
            var at: usize = 0;
            for (0..3) |tree| for (0..role.widths[tree]) |column| {
                const index = if (tree == 0 and role.fixed_indices != null) role.fixed_indices.?[column] else role.offsets[tree] + column;
                const original = try sourceColumn(self.trace.polys.items[tree][index]);
                const immutable = if (tree == 0 and original.device == null) immutable_fixed[index].device else null;
                const device = if (original.device != null) original.device else immutable orelse b.service.retainedColumn(scope, @intCast(tree), index, original);
                const n = @as(usize, 1) << @intCast(role.eval_log);
                const direct = (direct_enabled and original.log_size + 1 == role.eval_log and device != null and device.?.count == n / 2) or
                    (direct_el2 and original.log_size + 2 == role.eval_log and device != null and device.?.count == n / 4);
                columns[at] = .{ .log = original.log_size, .direct = direct };
                at += 1;
            };
            out.* = .{ .trace_log = role.trace_log, .eval_log = role.eval_log, .columns = columns, .auxiliary = switch (role.auxiliary) {
                .none => .none,
                .last => .last,
                .hc => .hc,
            }, .masks = role.artifact.program.inputs.len, .parameters = role.parameters.len, .constraints = role.artifact.program.roots.len };
            if (b.sparse_truth) |*sparse| {
                var widths = role.widths;
                if (role.auxiliary == .last) widths[2] += 1;
                if (role.evaluate == b.truth_role and sparse.matches(role.artifact.program.identity, role.id, role.trace_log, role.eval_log, widths, role.artifact.program.inputs.len, role.artifact.program.roots.len, role.parameters.len)) out.sparse = sparse.selection();
            }
            made += 1;
        }
        const beta = self.log_blowup orelse b.log_blowup;
        return WorkspaceCost.init(a, .{ .roles = roles, .shared_role_arena = true, .log = self.log, .split = self.split, .beta = beta, .separate_coefficients = (beta == 1 and b.n2b_columns != null) or (beta == 2 and b.n2b_columns_compact != null), .constraints = self.total });
    }
    // Each authenticated mask retains its tree identity and full-domain row
    // shift, but its column offset names a slot in one shared evaluation slab.
    fn runSelectedRole(self: *Job, raw: *anyopaque, context: *SC.Context, role: *const RuntimeRole, timing: *Timing, direct: []const ?D.DeviceCoefficients, selected: Columns.Selection, twiddles: []const u32, denominators: []const u32, powers: []const O, next: *usize, bucket: *?Native.Lease, leases: *std.ArrayList(Native.Lease), stream: *anyopaque) !usize {
        const a = self.allocator;
        const b = self.backend;
        const el = role.eval_log;
        const n = @as(usize, 1) << @intCast(el);
        const chunks = if (role.artifact.chunks) |*value| value else null;
        const count = if (chunks != null) 32 else selected.source_indices.len;
        const eval_words = try std.math.mul(usize, count, n);
        const arena_words = try Columns.arenaWords(count, el);
        if (twiddles.len < n / 2 or denominators.len != (@as(usize, 1) << @intCast(el - role.trace_log))) return error.InvalidCompositionGeometry;
        var arena = context.allocate(@intCast(arena_words), 0) catch |err| blk: {
            if (err != error.CudaAllocationFailed) return err;
            const cache = b.service.immutable_setup orelse return err;
            const freed = try cache.trimUnborrowed();
            std.debug.print("GPU_COMPOSITION_IMMUTABLE_TRIM ordinal={} role={} arena_words={} released_bytes={}\n", .{ self.scope.ordinal, role.id, arena_words, freed });
            if (freed == 0) return err;
            break :blk try context.allocate(@intCast(arena_words), 0);
        };
        defer context.release(&arena) catch |err| self.cleanupFailure(err);
        const base = arena.words.?;
        const logs = try a.alloc(u32, count);
        defer a.free(logs);
        @memset(logs, el - 1);
        if (chunks == null) for (selected.source_indices, logs) |index, *log| {
            const source = direct[index] orelse return error.MissingSelectedResidentSource;
            if (source.count != n / 2 and source.count != n / 4) return error.InvalidSelectedResidentSource;
            log.* = if (source.count == n / 2) el - 1 else el - 2;
        };
        const log_lease = try upload(a, context, leases, logs);
        const parameter_words = try felts(a, role.parameters);
        defer a.free(parameter_words);
        const parameters = try upload(a, context, leases, parameter_words);
        const roots = role.artifact.program.roots.len;
        if (roots > next.*) return error.NotEnoughCoefficients;
        next.* -= roots;
        const pw = if (self.device_powers) |all| blk: {
            var part = all;
            part.words = all.words.? + next.* * 8;
            part.count = roots * 8;
            _ = try context.borrow(part);
            std.debug.print("GPU_OUTER_DEVICE_FS rc_consumed ordinal={} role={} first={} count={} host_power_upload_words=0\n", .{ self.scope.ordinal, role.id, next.*, roots });
            break :blk part;
        } else blk: {
            const power_words = try felts(a, powers[next.*..][0..roots]);
            defer a.free(power_words);
            break :blk try upload(a, context, leases, power_words);
        };
        const masks_host = try a.alloc(u64, selected.mask_slots.len);
        defer a.free(masks_host);
        @memset(masks_host, 0);
        if (chunks == null) for (masks_host, selected.mask_slots) |*mask, slot| {
            mask.* = @as(u64, slot) * n;
        };
        const masks = try upload(a, context, leases, @as([*]const u32, @ptrCast(masks_host.ptr))[0 .. masks_host.len * 2]);
        const denom = try upload(a, context, leases, denominators);
        if (bucket.* == null) {
            bucket.* = try allocate(a, context, leases, 8 * n, 0);
            try self.checked("selected_bucket_clear", b.clear(raw, @ptrCast(bucket.*.?.words.?), 0, 8 * n * 4));
        }
        try self.checked("selected_twiddles", b.session_api.upload(raw, @ptrCast(base + eval_words), twiddles[twiddles.len - n / 2 ..].ptr, n / 2 * 4));
        inline for (.{ Span.coefficients, Span.auxiliary }) |span| {
            try timing.mark(span, false, stream);
            try timing.mark(span, true, stream);
        }
        if (try b.pool_trim.beforeTransform(raw, try std.math.mul(u64, arena.count, 4))) {
            std.debug.print("GPU_COMPOSITION_POOL_TRIM ordinal={} arena_bytes={} joined=true\n", .{ self.scope.ordinal, arena.count * 4 });
        }
        if (chunks) |chunk| {
            if (chunk.role != role.id or chunk.plan.input_columns.len != masks_host.len) return error.InvalidOuterChunksInvocation;
            // Verify every referenced source before any destructive refill.
            const bases = [_]usize{ 0, role.widths[0], role.widths[0] + role.widths[1] };
            for (chunk.plan.columns) |column| {
                if (column.tree >= 3 or column.column >= role.widths[column.tree]) return error.InvalidOuterChunksColumn;
                const source = direct[bases[column.tree] + column.column] orelse return error.MissingSelectedResidentSource;
                if (source.count != n / 2 and source.count != n / 4) return error.InvalidSelectedResidentSource;
                try self.checked("chunk_source_validate", context.api.validate_range(context.session, source.words, source.count, source.context_token, source.generation, &context.scope));
            }
            // Domain and row work interleave; report their combined span once.
            try timing.mark(.domain_fft, false, stream);
            for (chunk.plan.groups, chunk.cache.steps, 0..) |group, step, group_index| {
                for (step.loads) |load| {
                    const column = chunk.plan.columns[load.column];
                    const source = direct[bases[column.tree] + column.column].?;
                    const stride: usize = @intCast(source.count);
                    const log: u32 = if (stride == n / 2) el - 1 else el - 2;
                    try self.checked("chunk_log", context.api.upload(raw, @ptrCast(log_lease.words.? + load.slot), &log, 4));
                    var launches: u32 = 0;
                    if (stride == n / 2) {
                        try self.checked("chunk_n2b", b.n2b_columns.?(source.words, stride, log_lease.words.? + load.slot, base + @as(usize, load.slot) * n, n, el, 1, base + eval_words, @intCast(n / 2), @intCast(n / 2), stream, &launches));
                    } else {
                        try self.checked("chunk_n2b_compact", b.n2b_columns_compact.?(source.words, stride, log_lease.words.? + load.slot, base + @as(usize, load.slot) * n, n, el, 1, base + eval_words, @intCast(n / 2), @intCast(n / 2), stride, stream, &launches));
                    }
                }
                @memset(masks_host, 0);
                for (chunk.plan.input_columns, masks_host) |column, *offset| {
                    if (std.mem.indexOfScalar(u32, group.columns, column) != null) {
                        const slot = step.column_slots[column];
                        if (slot >= 32) return error.InvalidOuterChunksSlot;
                        offset.* = @as(u64, slot) * n;
                    }
                }
                try self.checked("chunk_masks", context.api.upload(raw, @ptrCast(masks.words.?), masks_host.ptr, masks_host.len * 8));
                const packet = Abi.CompositionRole{ .role = role.id, .trace_log = role.trace_log, .eval_log = el, .first_row = 0, .row_count = @intCast(n), .trees = .{ base, base, base }, .tree_words = .{ eval_words, eval_words, eval_words }, .column_offsets = @ptrCast(@alignCast(masks.words.?)), .mask_count = masks_host.len, .parameters = parameters.words.?, .parameter_count = role.parameters.len, .powers = pw.words.?, .constraint_count = roots, .denominator_inverses = denom.words.?, .output = bucket.*.?.words.? };
                var launches: u32 = 0;
                try self.checked("chunk_group", chunk.group(raw, 0, @intCast(group_index), &packet, &launches));
            }
            try timing.mark(.domain_fft, true, stream);
            try timing.mark(.rows, false, stream);
            try timing.mark(.rows, true, stream);
            std.debug.print("GPU_OUTER_CHUNKS ordinal={} role={} groups={} fills={} slots=32 arena_words={} combined_LDE_rows_span=true\n", .{ self.scope.ordinal, role.id, chunk.plan.groups.len, chunk.cache.fills, arena_words });
            return chunk.cache.fills * n;
        }
        try timing.mark(.domain_fft, false, stream);
        var column: usize = 0;
        while (column < count) {
            const first = direct[selected.source_indices[column]].?;
            const stride: usize = @intCast(first.count);
            var merged = try CopyRun.init(@intFromPtr(first.words), column * stride, stride, first.context_token, first.generation);
            var end = column + 1;
            while (end < count) : (end += 1) {
                const following = direct[selected.source_indices[end]].?;
                if (following.count != first.count) break;
                if (!try merged.append(try CopyRun.init(@intFromPtr(following.words), end * stride, stride, following.context_token, following.generation))) break;
            }
            try self.checked("selected_source_validate", b.service.lease_validate_range(b.service.session, @ptrFromInt(merged.source), merged.words, merged.context_token, merged.generation, &context.scope));
            var launches: u32 = 0;
            if (stride == n / 2) {
                try self.checked("selected_n2b", b.n2b_columns.?(@ptrFromInt(merged.source), stride, log_lease.words.? + column, base + column * n, n, el, @intCast(end - column), base + eval_words, @intCast(n / 2), @intCast(n / 2), stream, &launches));
            } else {
                try self.checked("selected_n2b_compact", b.n2b_columns_compact.?(@ptrFromInt(merged.source), stride, log_lease.words.? + column, base + column * n, n, el, @intCast(end - column), base + eval_words, @intCast(n / 2), @intCast(n / 2), stride, stream, &launches));
            }
            column = end;
        }
        try timing.mark(.domain_fft, true, stream);
        const packet = Abi.CompositionRole{ .role = role.id, .trace_log = role.trace_log, .eval_log = el, .first_row = 0, .row_count = @intCast(n), .trees = .{ base, base, base }, .tree_words = .{ eval_words, eval_words, eval_words }, .column_offsets = @ptrCast(@alignCast(masks.words.?)), .mask_count = masks_host.len, .parameters = parameters.words.?, .parameter_count = role.parameters.len, .powers = pw.words.?, .constraint_count = roots, .denominator_inverses = denom.words.?, .output = bucket.*.?.words.? };
        try timing.mark(.rows, false, stream);
        var launches: u32 = 0;
        try self.checked("selected_role", role.evaluate(raw, 0, &packet, &launches));
        try timing.mark(.rows, true, stream);
        std.debug.print("GPU_COMPOSITION_COLUMNS ordinal={} role={} original_columns={} active_columns={} eval_log={} arena_words={} bucket_layout_unchanged=true\n", .{ self.scope.ordinal, role.id, direct.len, count, el, arena_words });
        return eval_words;
    }
    fn run(self: *Job, raw: *anyopaque, token: u64) !void {
        var range = try @import("nvtx_stage.zig").Range.beginUnlessAdmitted(&self.backend.service.library, raw, "rv64/composition", self.permit != null);
        defer range.deinit();
        const a = self.allocator;
        const b = self.backend;
        var context = SC.Context{ .session = b.service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(self.scope), .api = &b.session_api };
        defer context.active = false;
        // One stream orders ingress, role transforms, quotient accumulation and
        // the final commitment. Keep each role's events until the root readback;
        // collecting timing is observational and must not drain the GPU per role.
        const enqueue = b.enqueue_policy;
        const compute_lane: u32 = if (enqueue) 0 else 1;
        var events = try Timing.init(&b.timing);
        defer events.deinit();
        const role_events = try a.alloc(Timing, self.roles.len);
        defer a.free(role_events);
        var made_events: usize = 0;
        defer for (role_events[0..made_events]) |*timing| timing.deinit();
        for (role_events) |*timing| {
            timing.* = try Timing.init(&b.timing);
            made_events += 1;
        }
        var spans: [std.meta.fields(Span).len]f64 = @splat(0);
        var stream0: ?*anyopaque = null;
        var stream1: ?*anyopaque = null;
        try self.checked("lane0", b.session_api.lane_stream(raw, 0, &stream0));
        try self.checked("lane1", b.session_api.lane_stream(raw, compute_lane, &stream1));
        // A whole FIXED forest is acquired once under its independently derived
        // root and ordered logs. Its read-only aliases live through native PCS.
        if (self.trace.polys.items.len == 0) return error.MissingResidentFixedTree;
        const fixed_columns = try a.alloc(D.Column, self.trace.polys.items[0].len);
        defer a.free(fixed_columns);
        for (self.trace.polys.items[0], fixed_columns) |column, *out| out.* = try sourceColumn(column);
        // Explicit device FIXED setup already owns scoped coefficients through
        // PCS. Do not clone its forest into a second immutable allocation.
        const all_fixed_device = @import("fixed_forest_policy.zig").isDeviceOnly(fixed_columns);
        if (self.permit != null) {
            for (1..3) |tree| for (self.trace.polys.items[tree], 0..) |poly, index| {
                const original = try sourceColumn(poly);
                const device = original.device orelse b.service.retainedColumn(context.scope, @intCast(tree), index, original) orelse return error.AdmissionRequiresResidentSource;
                try self.checked("admitted_source_validate", context.api.validate_range(context.session, device.words, device.count, device.context_token, device.generation, &context.scope));
            };
        }
        const immutable_fixed = if (all_fixed_device) fixed_columns else try b.service.immutableFixed(raw, self.scope, fixed_columns);
        var host_cells: u64 = 0;
        var device_cells: u64 = 0;
        var device_copy_calls: usize = 0;
        var domain_cells: u64 = 0;
        var leases: std.ArrayList(Native.Lease) = .empty;
        defer {
            context.join() catch |err| {
                self.cleanupFailure(err);
            };
            for (leases.items) |*lease| context.release(lease) catch |err| {
                self.cleanupFailure(err);
            };
            leases.deinit(a);
        }
        if (self.device_powers) |all| {
            const expected_words = try std.math.mul(usize, self.total, 8);
            if (all.count != expected_words) return error.InvalidOuterDeviceFsPowerCount;
            _ = try context.borrow(all);
        }
        var buckets: [29]?Native.Lease = @splat(null);
        const powers = try a.alloc(O, self.total);
        defer a.free(powers);
        var power = O.one();
        for (powers) |*p| {
            p.* = power;
            power = power.mul(self.alpha);
        }
        const reuse_workspace = self.outer_workspace and b.workspace_policy;
        var workspace: Native.Lease = .{};
        defer if (workspace.words != null) {
            context.join() catch |err| {
                self.cleanupFailure(err);
            };
            context.release(&workspace) catch |err| {
                self.cleanupFailure(err);
            };
        };
        if (reuse_workspace) {
            var plan = try self.workspacePlan(a, immutable_fixed, context.scope);
            defer plan.deinit(a);
            // Include the maximum arena held alongside ALL accumulated role
            // metadata/buckets; per-role peaks alone are not a valid bound.
            const Memory = @import("runtime_memory.zig");
            var actual = try Memory.query(&b.service.library, raw);
            var available = try actual.available();
            if (!available.contains(plan.additional_peak) or actual.largest_virtual_free < plan.workspace_words * 4) {
                // Match the established allocator's pressure recovery before
                // refusing. Only unused upper PCS blocks may be evicted; the
                // fresh all-context snapshot must still cover the FULL peak.
                if (try Memory.trimUnused(&b.service.library, b.service.session)) |released| {
                    actual = try Memory.query(&b.service.library, raw);
                    available = try actual.available();
                    std.debug.print("GPU_RC_WORKSPACE_PRESSURE_TRIM ordinal={} released_bytes={} available_large={} available_small={}\n", .{ self.scope.ordinal, released, available.large, available.small });
                }
            }
            if (!available.contains(plan.additional_peak) or actual.largest_virtual_free < plan.workspace_words * 4) {
                std.debug.print("GPU_RC_WORKSPACE_REFUSED ordinal={} required_large={} required_small={} available_large={} available_small={} workspace_words={}\n", .{ self.scope.ordinal, plan.additional_peak.large, plan.additional_peak.small, available.large, available.small, plan.workspace_words });
                return error.RoleWorkspaceExceedsPhysicalArena;
            }
            workspace = try context.allocate(@intCast(plan.workspace_words), 0);
            std.debug.print("GPU_RC_WORKSPACE_ADMITTED ordinal={} workspace_words={} phase_peak_large={} phase_peak_small={} snapshot_live_large={} snapshot_live_small={} retained_across_proofs=false\n", .{ self.scope.ordinal, plan.workspace_words, plan.additional_peak.large, plan.additional_peak.small, actual.live_large, actual.live_small });
        }
        var next = self.total;
        for (self.roles, role_events) |*role, *timing| {
            const id = role.id;
            self.active_role = id;
            const artifact = role.artifact;
            const rl = role.trace_log;
            const el = role.eval_log;
            if (el < rl + 1 or el > rl + 2 or el > self.log) return error.UnsupportedResidentCompositionDomain;
            const n = @as(usize, 1) << @intCast(el);
            const iw = role.widths[2];
            const aux: usize = switch (role.auxiliary) {
                .none => 0,
                .hc => 10,
                .last => 1,
            };
            var widths = role.widths;
            widths[2] += aux;
            const column_count = widths[0] + widths[1] + widths[2];
            var sources: std.ArrayList(engine.air.component_prover.ForField(O).Poly) = .empty;
            defer sources.deinit(a);
            const offsets = role.offsets;
            if (role.fixed_indices) |indices| {
                for (indices) |index| try sources.append(a, self.trace.polys.items[0][index]);
            } else try sources.appendSlice(a, self.trace.polys.items[0][offsets[0]..][0..widths[0]]);
            try sources.appendSlice(a, self.trace.polys.items[1][offsets[1]..][0..widths[1]]);
            try sources.appendSlice(a, self.trace.polys.items[2][offsets[2]..][0..iw]);
            const source_metadata = try a.alloc(D.Column, sources.items.len);
            defer a.free(source_metadata);
            for (source_metadata, sources.items) |*column, source| column.* = try sourceColumn(source);
            var tw_borrow = try b.tw(el);
            defer tw_borrow.deinit(b.allocator);
            const tw = &tw_borrow.value;
            var geometry_borrow = try b.geometry(artifact, rl, el, widths, source_metadata, aux, tw.twiddles.len);
            defer geometry_borrow.deinit(b.allocator);
            const geometry = &geometry_borrow.value;
            // Direct extension: a device column of degree el-1 is extended
            // straight from its retained lease (compact stride) instead of
            // first being copied into the arena. The row kernel reads only the
            // evaluations, so the arena keeps just a staging slab for host,
            // lower-degree and auxiliary columns. Exact field LDE: identical
            // evaluations, identical proof bytes. STWO_RV64_COMPOSITION_DIRECT=0
            // restores the full coefficient copy.
            const direct_enabled = b.n2b_columns != null and b.direct_policy;
            // M5 platform: degree el-2 device columns are extended directly too
            // (compact source, stride n/4). Same kernels, same evaluations;
            // removes their staged-coefficient copy from the arena (3.69 GB on
            // the 18.44 GB rl+2 truth role). STWO_RV64_COMPOSITION_DIRECT_EL2=0
            // keeps them staged.
            const direct_el2 = direct_enabled and b.n2b_columns_compact != null and b.compact_policy;
            const direct = try a.alloc(?D.DeviceCoefficients, column_count);
            defer a.free(direct);
            const staging_offsets = try a.alloc(usize, column_count);
            defer a.free(staging_offsets);
            var staging_words: usize = 0;
            var direct_columns: usize = 0;
            for (direct, staging_offsets, 0..) |*slot, *offset, i| {
                slot.* = null;
                offset.* = staging_words;
                if (i < source_metadata.len) {
                    const original = source_metadata[i];
                    const source_tree: u32 = if (i < widths[0]) 0 else if (i < widths[0] + widths[1]) 1 else 2;
                    const original_index = switch (source_tree) {
                        0 => if (role.fixed_indices) |indices| indices[i] else offsets[0] + i,
                        1 => offsets[1] + i - widths[0],
                        else => offsets[2] + i - widths[0] - widths[1],
                    };
                    const immutable = if (source_tree == 0 and original.device == null) immutable_fixed[original_index].device else null;
                    const device = if (original.device != null) original.device else immutable orelse b.service.retainedColumn(context.scope, source_tree, original_index, original);
                    if ((direct_enabled and original.log_size + 1 == el and device != null and device.?.count == (n / 2)) or
                        (direct_el2 and el >= 3 and original.log_size + 2 == el and device != null and device.?.count == (n / 4)))
                    {
                        slot.* = device;
                        direct_columns += 1;
                        continue;
                    }
                    staging_words += @as(usize, 1) << @intCast(original.log_size);
                } else staging_words += @as(usize, 1) << @intCast(rl);
            }
            if (b.column_policy and self.outer_workspace and !b.workspace_policy and enqueue and
                aux == 0 and direct_columns == column_count and Columns.supportsGeometry(rl, el) and
                artifact.program.inputs.len != 0)
            {
                var selected = try Columns.Selection.init(a, role.widths, artifact.program.inputs);
                defer selected.deinit(a);
                if (selected.source_indices.len < column_count) {
                    domain_cells += try self.runSelectedRole(raw, &context, role, timing, direct, selected, words(tw.twiddles), words(geometry.denominators), powers, &next, &buckets[el], &leases, stream0.?);
                    continue;
                }
            }
            if (b.sparse_truth) |*sparse| {
                if (role.evaluate == b.truth_role and id == 0 and rl == 18 and el == 20) {
                    if (!enqueue or !sparse.matches(artifact.program.identity, id, rl, el, widths, artifact.program.inputs.len, artifact.program.roots.len, role.parameters.len) or role.auxiliary != .last or self.device_powers != null) return error.UnsupportedSparseCompositionInvocation;
                    if (artifact.program.roots.len > next) return error.NotEnoughCoefficients;
                    next -= artifact.program.roots.len;
                    const parameter_words = try felts(a, role.parameters);
                    defer a.free(parameter_words);
                    const power_words = try felts(a, powers[next..][0..artifact.program.roots.len]);
                    defer a.free(power_words);
                    var role_tw_borrow = try b.tw(rl);
                    defer role_tw_borrow.deinit(b.allocator);
                    // Empty traditional spans; the rows span is explicitly
                    // reported as combined sparse LDE+row work below.
                    inline for (.{ Span.coefficients, Span.auxiliary, Span.domain_fft }) |span| {
                        try timing.mark(span, false, stream0.?);
                        try timing.mark(span, true, stream0.?);
                    }
                    try timing.mark(.rows, false, stream0.?);
                    try sparse.run(a, b, &context, artifact.program.inputs, direct, parameter_words, power_words, words(geometry.denominators), words(tw.twiddles), words(role_tw_borrow.value.itwiddles), &buckets[el], &leases);
                    try timing.mark(.rows, true, stream0.?);
                    std.debug.print("GPU_RC_SPARSE_ROLE ordinal={} role={} scope=truth combined_LDE_rows_span=true original_power_first={} original_roots={}\n", .{ self.scope.ordinal, id, next, artifact.program.roots.len });
                    domain_cells += sparse.cache.fills * n;
                    continue;
                }
            }
            const eval_base = staging_words;
            const tw_base = try std.math.add(usize, eval_base, try std.math.mul(usize, column_count, n));
            const desc_base = std.mem.alignForward(usize, tw_base + tw.twiddles.len, 2);
            const arena_words = desc_base + column_count * 6;
            const descriptors = try a.alloc(u32, column_count * 6);
            defer a.free(descriptors);
            for (0..column_count) |i| {
                const degree: u32 = if (i < source_metadata.len) source_metadata[i].log_size else rl;
                const destination = eval_base + i * n;
                descriptors[i * 6 ..][0..6].* = .{ @truncate(staging_offsets[i]), @truncate(@as(u64, staging_offsets[i]) >> 32), @truncate(destination), @truncate(@as(u64, destination) >> 32), degree, 0 };
            }
            std.debug.print("GPU_COMPOSITION_ARENA ordinal={} role={} arena_words={} legacy_arena_words={} direct_columns={} columns={} eval_log={}\n", .{ self.scope.ordinal, id, arena_words, geometry.arena_words, direct_columns, column_count, el });
            // M5 platform: under device pressure, release unborrowed immutable
            // setup (other nodes' PP/schedules kept by a resident service) and
            // retry once before failing. Scheduling only: misses re-upload.
            if (reuse_workspace and arena_words > workspace.count) return error.RoleWorkspacePlanMismatch;
            var arena = if (reuse_workspace) workspace else context.allocate(arena_words, 0) catch |err| blk: {
                if (err != error.CudaAllocationFailed) return err;
                const cache = b.service.immutable_setup orelse return err;
                const freed = try cache.trimUnborrowed();
                std.debug.print("GPU_COMPOSITION_IMMUTABLE_TRIM ordinal={} role={} arena_words={} released_bytes={}\n", .{ self.scope.ordinal, id, arena_words, freed });
                if (freed == 0) return err;
                break :blk try context.allocate(arena_words, 0);
            };
            defer {
                if (!enqueue) context.join() catch |err| {
                    self.cleanupFailure(err);
                };
                if (!reuse_workspace) context.release(&arena) catch |err| {
                    self.cleanupFailure(err);
                };
            }
            const arena_ptr = arena.words.?;
            var coefficient_offset: usize = 0;
            var copy_run: ?CopyRun = null;
            try timing.mark(.coefficients, false, stream0.?);
            for (source_metadata, 0..) |original, i| {
                if (direct[i] != null) continue;
                coefficient_offset = staging_offsets[i];
                const values = original.coefficients;
                const length: usize = if (original.device) |device| @intCast(device.count) else values.len;
                const target = arena_ptr + coefficient_offset;
                const source_tree: u32 = if (i < widths[0]) 0 else if (i < widths[0] + widths[1]) 1 else 2;
                const original_index = switch (source_tree) {
                    0 => if (role.fixed_indices) |indices| indices[i] else offsets[0] + i,
                    1 => offsets[1] + i - widths[0],
                    else => offsets[2] + i - widths[0] - widths[1],
                };
                const immutable = if (source_tree == 0 and original.device == null) immutable_fixed[original_index].device else null;
                if (if (original.device != null) original.device else immutable orelse b.service.retainedColumn(context.scope, source_tree, original_index, original)) |device| {
                    const next_run = try CopyRun.init(@intFromPtr(device.words), coefficient_offset, length, device.context_token, device.generation);
                    if (copy_run) |*pending| {
                        if (!try pending.append(next_run)) {
                            try self.copyRun(raw, &context, arena_ptr, pending.*);
                            device_copy_calls += 1;
                            copy_run = next_run;
                        }
                    } else copy_run = next_run;
                    device_cells += length;
                } else {
                    if (copy_run) |pending| {
                        try self.copyRun(raw, &context, arena_ptr, pending);
                        device_copy_calls += 1;
                        copy_run = null;
                    }
                    try self.checked("session_api.upload", b.session_api.upload(raw, @ptrCast(target), values.ptr, values.len * 4));
                    host_cells += values.len;
                }
                coefficient_offset += length;
            }
            if (copy_run) |pending| {
                try self.copyRun(raw, &context, arena_ptr, pending);
                device_copy_calls += 1;
            }
            coefficient_offset = if (source_metadata.len < column_count) staging_offsets[source_metadata.len] else staging_words;
            try timing.mark(.coefficients, true, stream0.?);
            if (aux != 0) {
                var role_tw_borrow = try b.tw(rl);
                defer role_tw_borrow.deinit(b.allocator);
                const role_tw = &role_tw_borrow.value;
                const it = try upload(a, &context, &leases, words(role_tw.itwiddles));
                if (!enqueue) try context.join();
                var stream: ?*anyopaque = null;
                try self.checked("session_api.lane_stream", b.session_api.lane_stream(raw, compute_lane, &stream));
                var launches: u32 = 0;
                try timing.mark(.auxiliary, false, stream.?);
                switch (role.auxiliary) {
                    .hc => |hc| {
                        const h = try upload(a, &context, &leases, hc[0 .. 16 * rl]);
                        if (!enqueue) try context.join();
                        try self.checked("auxiliary", b.auxiliary(raw, compute_lane, h.words.?, arena_ptr + coefficient_offset, rl, &launches));
                    },
                    .last => {
                        const size = @as(usize, 1) << @intCast(rl);
                        try self.checked("last_anchor_clear", b.clear(raw, @ptrCast(arena_ptr + coefficient_offset), 0, size * 4));
                        // Native truth last-anchor is logical last, physical row 1.
                        // Legacy lane 1 needs a join; enqueue mode interpolates on lane 0.
                        const one: u32 = 1;
                        try self.checked("last_anchor_set", b.session_api.upload(raw, @ptrCast(arena_ptr + coefficient_offset + 1), &one, 4));
                        if (!enqueue) try context.join();
                    },
                    .none => unreachable,
                }
                const rows = @as(usize, 1) << @intCast(rl);
                try self.checked("b2n", b.b2n(arena_ptr + coefficient_offset, rows, arena_ptr + coefficient_offset, rows, rl, @intCast(aux), it.words.?, @intCast(role_tw.itwiddles.len), @intCast(rows / 2), stream.?, &launches));
                try timing.mark(.auxiliary, true, stream.?);
            }
            try self.checked("session_api.upload", b.session_api.upload(raw, @ptrCast(arena_ptr + tw_base), tw.twiddles.ptr, tw.twiddles.len * 4));
            try self.checked("session_api.upload", b.session_api.upload(raw, @ptrCast(arena_ptr + desc_base), descriptors.ptr, descriptors.len * 4));
            const direct_logs = try a.alloc(u32, column_count);
            defer a.free(direct_logs);
            @memset(direct_logs, el - 1);
            for (direct, direct_logs) |slot, *log| {
                if (slot) |device| if (device.count == n / 4) {
                    log.* = el - 2;
                };
            }
            const direct_log_lease = try upload(a, &context, &leases, direct_logs);
            const parameter_words = try felts(a, role.parameters);
            defer a.free(parameter_words);
            const params = try upload(a, &context, &leases, parameter_words);
            if (artifact.program.roots.len > next) return error.NotEnoughCoefficients;
            next -= artifact.program.roots.len;
            const pw = if (self.device_powers) |all| blk: {
                var part = all;
                part.words = all.words.? + next * 8;
                part.count = artifact.program.roots.len * 8;
                _ = try context.borrow(part);
                std.debug.print("GPU_OUTER_DEVICE_FS rc_consumed ordinal={} role={} first={} count={} host_power_upload_words=0\n", .{ self.scope.ordinal, id, next, artifact.program.roots.len });
                break :blk part;
            } else blk: {
                const power_words = try felts(a, powers[next..][0..artifact.program.roots.len]);
                defer a.free(power_words);
                break :blk try upload(a, &context, &leases, power_words);
            };
            const mask_offsets = geometry.masks;
            const masks = try upload(a, &context, &leases, @as([*]const u32, @ptrCast(mask_offsets.ptr))[0 .. mask_offsets.len * 2]);
            const denom = try upload(a, &context, &leases, words(geometry.denominators));
            if (buckets[el] == null) {
                buckets[el] = try allocate(a, &context, &leases, 8 * n, 0);
                try self.checked("clear", b.clear(raw, @ptrCast(buckets[el].?.words.?), 0, 8 * n * 4));
            }
            if (!enqueue) try context.join();
            if (try b.pool_trim.beforeTransform(raw, try std.math.mul(u64, arena.count, 4))) {
                std.debug.print("GPU_COMPOSITION_POOL_TRIM ordinal={} arena_bytes={} joined=true\n", .{ self.scope.ordinal, arena.count * 4 });
            }
            var stream: ?*anyopaque = null;
            try self.checked("session_api.lane_stream", b.session_api.lane_stream(raw, compute_lane, &stream));
            var launches: u32 = 0;
            try timing.mark(.domain_fft, false, stream.?);
            var column: usize = 0;
            while (column < column_count) {
                var end = column + 1;
                if (direct[column]) |first| {
                    // Merge adjacent columns of one lease (and one degree) into
                    // one compact run.
                    const stride: usize = @intCast(first.count);
                    var merged = try CopyRun.init(@intFromPtr(first.words), column * stride, stride, first.context_token, first.generation);
                    while (end < column_count) : (end += 1) {
                        const following = direct[end] orelse break;
                        if (following.count != first.count) break;
                        if (!try merged.append(try CopyRun.init(@intFromPtr(following.words), end * stride, stride, following.context_token, following.generation))) break;
                    }
                    try self.checked("service.lease_validate_range", b.service.lease_validate_range(b.service.session, @ptrFromInt(merged.source), merged.words, merged.context_token, merged.generation, &context.scope));
                    if (stride == n / 2) {
                        try self.checked("n2b_columns", b.n2b_columns.?(@ptrFromInt(merged.source), n / 2, direct_log_lease.words.? + column, arena_ptr + eval_base + column * n, n, el, @intCast(end - column), arena_ptr + tw_base + tw.twiddles.len - n / 2, @intCast(n / 2), @intCast(n / 2), stream.?, &launches));
                    } else {
                        try self.checked("n2b_columns_compact", b.n2b_columns_compact.?(@ptrFromInt(merged.source), stride, direct_log_lease.words.? + column, arena_ptr + eval_base + column * n, n, el, @intCast(end - column), arena_ptr + tw_base + tw.twiddles.len - n / 2, @intCast(n / 2), @intCast(n / 2), stride, stream.?, &launches));
                    }
                } else {
                    while (end < column_count and direct[end] == null) : (end += 1) {}
                    try self.checked("n2b", b.n2b(arena_ptr, arena.count, arena_ptr + desc_base + 6 * column, @intCast(end - column), eval_base + column * n, el, arena_ptr + tw_base, @intCast(tw.twiddles.len), @intCast(n / 2), stream.?, 1, &launches));
                }
                column = end;
            }
            try timing.mark(.domain_fft, true, stream.?);
            const packet = Abi.CompositionRole{ .role = id, .trace_log = rl, .eval_log = el, .first_row = 0, .row_count = @intCast(n), .trees = .{ arena_ptr + eval_base, arena_ptr + eval_base + widths[0] * n, arena_ptr + eval_base + (widths[0] + widths[1]) * n }, .tree_words = .{ @max(@as(usize, 1), widths[0] * n), @max(@as(usize, 1), widths[1] * n), @max(@as(usize, 1), widths[2] * n) }, .column_offsets = @ptrCast(@alignCast(masks.words.?)), .mask_count = mask_offsets.len, .parameters = params.words.?, .parameter_count = role.parameters.len, .powers = pw.words.?, .constraint_count = artifact.program.roots.len, .denominator_inverses = denom.words.?, .output = buckets[el].?.words.? };
            try timing.mark(.rows, false, stream.?);
            try self.checked("role", role.evaluate(raw, compute_lane, &packet, &launches));
            try timing.mark(.rows, true, stream.?);
            if (!enqueue) try context.join();
            domain_cells += column_count * n;
        }
        if (next != 0) return error.UnusedCompositionCoefficients;
        if (workspace.words != null) try context.release(&workspace);
        const n = @as(usize, 1) << @intCast(self.log);
        const coeff_count = 8 * n;
        const chunk_log = self.log - self.split;
        const count = @as(usize, 8) << @intCast(self.split);
        const beta = self.log_blowup orelse b.log_blowup;
        if (beta < 1 or beta > 4) return error.UnsupportedResidentCompositionBlowup;
        const commit_log = chunk_log + beta;
        const commit_rows = @as(usize, 1) << @intCast(commit_log);
        const eval_words = count * commit_rows;
        if (commit_log > 28) return error.UnsupportedResidentCompositionBlowup;
        var commit_tw_borrow = try b.tw(commit_log);
        defer commit_tw_borrow.deinit(b.allocator);
        const tw = &commit_tw_borrow.value;
        var composition_tw_borrow = try b.tw(self.log);
        defer composition_tw_borrow.deinit(b.allocator);
        const composition_tw = &composition_tw_borrow.value;
        // PCS retains compact coefficients only. Commitment LDE/twiddles are
        // scratch and retire with this joined job, rather than sharing the
        // retained coefficient lease for the entire opening phase.
        const separate = (beta == 1 and b.n2b_columns != null) or (beta == 2 and b.n2b_columns_compact != null);
        const eval_base: usize = if (separate) 0 else coeff_count;
        const output_tw = eval_base + eval_words;
        const output_desc = std.mem.alignForward(usize, output_tw + tw.twiddles.len, 2);
        const scratch_words = output_desc + if (separate) count else count * 6;
        var output = try context.allocate(if (separate) coeff_count else scratch_words, 2);
        errdefer context.release(&output) catch |err| {
            self.cleanupFailure(err);
        };
        const scratch = if (separate) try allocate(a, &context, &leases, scratch_words, 0) else output;
        const accumulator = try allocate(a, &context, &leases, coeff_count, 0);
        const inv = try upload(a, &context, &leases, words(composition_tw.itwiddles));
        var list: std.ArrayList(Abi.CompositionBucket) = .empty;
        defer list.deinit(a);
        for (buckets, 0..) |bucket, log| if (bucket) |value| try list.append(a, .{ .words = value.words.?, .log = @intCast(log) });
        if (!enqueue) try context.join();
        var launches: u32 = 0;
        try events.mark(.finalize, false, stream1.?);
        try self.checked("finish", b.finish(raw, compute_lane, list.items.ptr, @intCast(list.items.len), accumulator.words.?, output.words.?, self.log, self.split, inv.words.?, @intCast(composition_tw.itwiddles.len), &launches));
        try events.mark(.finalize, true, stream1.?);
        var descriptors: std.ArrayList(u32) = .empty;
        defer descriptors.deinit(a);
        for (0..count) |i| {
            if (separate) {
                try descriptors.append(a, chunk_log);
            } else {
                const src = i * (@as(usize, 1) << @intCast(chunk_log));
                const dst = eval_base + i * commit_rows;
                try descriptors.appendSlice(a, &.{ @truncate(src), @truncate(@as(u64, src) >> 32), @truncate(dst), @truncate(@as(u64, dst) >> 32), chunk_log, 0 });
            }
        }
        try self.checked("session_api.upload", b.session_api.upload(raw, @ptrCast(scratch.words.? + output_tw), tw.twiddles.ptr, tw.twiddles.len * 4));
        try self.checked("session_api.upload", b.session_api.upload(raw, @ptrCast(scratch.words.? + output_desc), descriptors.items.ptr, descriptors.items.len * 4));
        if (!enqueue) try context.join();
        var stream: ?*anyopaque = null;
        try self.checked("session_api.lane_stream", b.session_api.lane_stream(raw, compute_lane, &stream));
        try events.mark(.commit_fft, false, stream.?);
        if (separate) {
            if (beta == 2) {
                const source_words = @as(usize, 1) << @intCast(chunk_log);
                try self.checked("n2b_columns_compact", b.n2b_columns_compact.?(output.words.?, source_words, scratch.words.? + output_desc, scratch.words.?, commit_rows, commit_log, @intCast(count), scratch.words.? + output_tw, @intCast(tw.twiddles.len), @intCast(commit_rows / 2), source_words, stream.?, &launches));
            } else try self.checked("n2b_columns", b.n2b_columns.?(output.words.?, @as(usize, 1) << @intCast(chunk_log), scratch.words.? + output_desc, scratch.words.?, commit_rows, commit_log, @intCast(count), scratch.words.? + output_tw, @intCast(tw.twiddles.len), @intCast(commit_rows / 2), stream.?, &launches));
        } else try self.checked("n2b", b.n2b(output.words.?, output.count, output.words.? + output_desc, @intCast(count), eval_base, commit_log, output.words.? + output_tw, @intCast(tw.twiddles.len), @intCast(commit_rows / 2), stream.?, 1, &launches));
        try events.mark(.commit_fft, true, stream.?);
        const tree_words = (2 * commit_rows - 1) * 8;
        const tree = try allocate(a, &context, &leases, tree_words, 0);
        const segment = Abi.MixedSegment{ .columns = scratch.words.? + eval_base, .stride_words = commit_rows, .capacity_words = eval_words, .source_size = @intCast(commit_rows), .reserved = 0 };
        try events.mark(.commit_hash, false, stream1.?);
        try self.checked("tree", b.tree(raw, compute_lane, @ptrCast(&segment), 1, commit_log, tree.words.?, tree_words));
        try events.mark(.commit_hash, true, stream1.?);
        if (!enqueue) try context.join();
        var root_words: [8]u32 = undefined;
        try self.checked("session_api.download", b.session_api.download(raw, &root_words, @ptrCast(tree.words.? + tree_words - 8), 32));
        try context.join();
        for (role_events, self.roles) |*timing, role| {
            spans[@intFromEnum(Span.coefficients)] += try timing.milliseconds(.coefficients);
            spans[@intFromEnum(Span.domain_fft)] += try timing.milliseconds(.domain_fft);
            spans[@intFromEnum(Span.rows)] += try timing.milliseconds(.rows);
            if (role.auxiliary != .none) spans[@intFromEnum(Span.auxiliary)] += try timing.milliseconds(.auxiliary);
        }
        spans[@intFromEnum(Span.finalize)] = try events.milliseconds(.finalize);
        spans[@intFromEnum(Span.commit_fft)] = try events.milliseconds(.commit_fft);
        spans[@intFromEnum(Span.commit_hash)] = try events.milliseconds(.commit_hash);
        var root: [32]u8 = undefined;
        for (root_words, 0..) |v, i| std.mem.writeInt(u32, root[i * 4 ..][0..4], v, .little);
        const columns = try b.allocator.alloc(D.Column, count);
        errdefer b.allocator.free(columns);
        for (columns, 0..) |*column, i| column.* = .{ .log_size = chunk_log, .device = .{ .words = output.words.? + i * (@as(usize, 1) << @intCast(chunk_log)), .count = @as(u64, 1) << @intCast(chunk_log), .context_token = output.context_token, .generation = output.generation } };
        try b.service.retainDeviceLease(context.scope, output);
        std.debug.print("GPU_COMPOSITION_OWNERSHIP ordinal={} retained_coefficient_words={} joined_commit_scratch_words={} separate_coefficients={} log_blowup={}\n", .{ self.scope.ordinal, output.count, if (separate) scratch.count else 0, separate, beta });
        self.result = .{ .root = root, .columns = columns };
        var kernel_ms: f64 = 0;
        for (spans[1..]) |value| kernel_ms += value;
        std.debug.print("GPU_COMPOSITION_TIMING ordinal={} coefficient_stream_ms={d:.3} auxiliary_ms={d:.3} domain_fft_ms={d:.3} rows_ms={d:.3} finalize_ms={d:.3} commit_fft_ms={d:.3} commit_hash_ms={d:.3} gpu_enqueued_kernel_spans_ms={d:.3} host_coefficient_cells={} device_coefficient_cells={} device_copy_calls={} domain_cells={} geometry_hits={} geometry_misses={} retained_setup_bytes={} retained_geometry_bytes={} retained_twiddle_bytes={} retained_artifact_bytes={} setup_cache_cap_bytes={} uncached_geometries={} uncached_twiddles={}\n", .{ self.scope.ordinal, spans[0], spans[1], spans[2], spans[3], spans[4], spans[5], spans[6], kernel_ms, host_cells, device_cells, device_copy_calls, domain_cells, b.geometry_hits, b.geometry_misses, b.retainedBytes(), b.geometry_bytes, b.twiddle_bytes, b.artifact_bytes, b.cache_limit_bytes, b.uncached_geometries, b.uncached_twiddles });
    }
};
fn allocate(a: std.mem.Allocator, c: *SC.Context, list: *std.ArrayList(Native.Lease), n: usize, kind: u32) !Native.Lease {
    var lease = try c.allocate(n, kind);
    errdefer c.release(&lease) catch {};
    try list.append(a, lease);
    return lease;
}
fn upload(a: std.mem.Allocator, c: *SC.Context, list: *std.ArrayList(Native.Lease), data: []const u32) !Native.Lease {
    const lease = try allocate(a, c, list, @max(@as(usize, 1), data.len), 0);
    if (data.len != 0) try check(c.api.upload(c.native_context, @ptrCast(lease.words.?), data.ptr, data.len * 4));
    return lease;
}

test "resident composition adapter binds the actual worker callback" {
    var context: Context = undefined;
    const stage = context.stage();
    try std.testing.expectEqual(@intFromPtr(&context), @intFromPtr(stage.context));
    _ = Context.init;
    _ = Job.callback;
}

test "resident composition accepts a scoped device polynomial without host reconstruction" {
    const T = engine.air.component_prover.ForField(O).Poly;
    var source = T{ .log_size = 8, .values = &.{}, .device = .{ .words = @ptrFromInt(4096), .count = 128, .context_token = 7, .generation = 3 } };
    const column = try sourceColumn(source);
    try std.testing.expectEqual(@as(u32, 7), column.log_size);
    try std.testing.expectEqual(@as(usize, 0), column.coefficients.len);
    try std.testing.expectEqual(@as(u64, 3), column.device.?.generation);
    source.device.?.count = 129;
    try std.testing.expectError(error.InvalidColumnLength, sourceColumn(source));
}

test "setup byte budget does not evict live geometry for a nested twiddle borrow" {
    const a = std.testing.allocator;
    // Only the metadata subsystem is exercised; no GPU/session fields are read.
    var setup: Context = undefined;
    setup.allocator = a;
    setup.geometries = .empty;
    setup.twiddles = @splat(null);
    setup.artifact_bytes = 0;
    setup.geometry_bytes = 0;
    setup.twiddle_bytes = 0;
    setup.uncached_twiddles = 0;
    setup.cache_limit_bytes = 8;
    defer setup.geometries.deinit(a);
    const descriptors = try a.alloc(u32, 1);
    const masks = try a.alloc(u64, 1);
    const denominators = try a.alloc(M, 1);
    try setup.geometries.append(a, .{ .key = @splat(0), .source_words = 0, .eval_base = 0, .tw_base = 0, .desc_base = 0, .arena_words = 0, .descriptors = descriptors, .masks = masks, .denominators = denominators });
    setup.geometry_bytes = setup.geometries.items[0].bytes();
    try std.testing.expect(!setup.admitCache(1, false));
    try std.testing.expectEqual(@as(usize, 1), setup.geometries.items.len);
    try std.testing.expect(setup.admitCache(1, true));
    try std.testing.expectEqual(@as(usize, 0), setup.geometry_bytes);
    var borrowed = try setup.tw(5);
    defer borrowed.deinit(a);
    try std.testing.expect(!borrowed.retained);
    try std.testing.expectEqual(@as(usize, 0), setup.twiddle_bytes);
    try std.testing.expectEqual(@as(u64, 1), setup.uncached_twiddles);
}

test "cold symbolic DAG is released while authenticated kernel metadata remains owned" {
    const a = std.testing.allocator;
    var wide = try G.record(a, .{ .origin = .{ .core = .alu } });
    const identity = wide.program.identity;
    const input_count = wide.program.inputs.len;
    const roots = wide.program.roots.len;
    var narrow = KernelMetadata.take(&wide);
    defer narrow.deinit();
    wide.deinit();
    try std.testing.expectEqualSlices(u8, &identity, &narrow.program.identity);
    try std.testing.expectEqual(input_count, narrow.program.inputs.len);
    try std.testing.expectEqual(roots, narrow.program.roots.len);
    try std.testing.expect(narrow.bytes() != 0);
}

test "LDE descriptor destinations include the coefficient arena prefix" {
    var descriptors = [_]u32{ 0, 0, 8, 0, 3, 0 };
    const geometry = Geometry{ .key = @splat(0), .source_words = 8, .eval_base = 8, .tw_base = 24, .desc_base = 32, .arena_words = 38, .descriptors = &descriptors, .masks = &.{}, .denominators = &.{} };
    try geometry.validate(4);
    descriptors[2] = 0;
    try std.testing.expectError(error.InvalidCompositionGeometry, geometry.validate(4));
    descriptors[2] = 8;
    descriptors[0] = 9;
    try std.testing.expectError(error.InvalidCompositionGeometry, geometry.validate(4));
}

test "truth stages retain typed authority with the same resident numerical pipeline" {
    const Source = CPU.rv64_gkr_truth_device_source;
    const columns = [_]D.Column{.{ .log_size = 5, .device = .{ .words = @ptrFromInt(4096), .count = 32, .context_token = 7, .generation = 9 } }};
    const tree = D.Tree{ .root = @splat(0), .columns = &columns };
    try Source.validateTree(tree, &.{5});
    try std.testing.expectError(error.DeviceTruthShapeMismatch, Source.validateTree(tree, &.{6}));
    var context: Context = undefined;
    const stage = CPU.rv64_gkr_truth_device_composition.Stage{ .context = &context, .evaluate_and_commit = Context.evaluateTruth };
    try std.testing.expectEqual(@intFromPtr(&context), @intFromPtr(stage.context));
    try std.testing.expect(@intFromPtr(stage.evaluate_and_commit) != 0);
    _ = Context.truthStage;
}

test {
    _ = @import("device_copy_run.zig");
}
test "frontend-neutral composition entry rejects absent authority roles before device submission" {
    var backend: Context = undefined;
    backend.log_blowup = 1;
    const trace = Trace{ .polys = .initOwned(&.{}) };
    const scope = D.Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
    try std.testing.expectError(error.InvalidResidentCompositionRoles, backend.evaluateRoles(std.testing.allocator, &.{}, O.one(), 5, 1, 0, &trace, scope));
}

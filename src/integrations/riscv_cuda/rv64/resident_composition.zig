//! Actual native CPU-worker composition on its persistent GPU owner. Coefficients
//! are ingress only; quotient buckets, interpolation and final coefficients never
//! return to the host. The sole numerical readback is the committed root.
const std = @import("std");
const N2bColumnsCompact = *const fn ([*]const u32, usize, [*]const u32, [*]u32, usize, u32, u32, [*]const u32, u32, u32, usize, ?*anyopaque, *u32) callconv(.c) c_int;
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
const O = D.O;
const M = D.M;
const Items = CPU.rv64_gkr_cpu_components;
const Trace = engine.air.component_prover.ForField(O).Trace;
const Twiddle = engine.poly.twiddles.TwiddleTree([]M);
const N2b = *const fn ([*]u32, usize, ?*const anyopaque, u32, usize, u32, [*]const u32, u32, u32, *anyopaque, u32, *u32) callconv(.c) c_int;
const B2n = *const fn ([*]const u32, usize, [*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
const Copy = Native.CopyDevice;
const Clear = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;
fn sym(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse {
        std.debug.print("GPU_COMPOSITION_MISSING_SYMBOL name={s}\n", .{name});
        return error.MissingResidentCompositionSymbol;
    };
}
const sourceColumn = @import("resident_composition_job.zig").sourceColumn;
// Retain only authenticated executable metadata, not the cold symbolic DAG.
pub const KernelMetadata = struct {
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
        return self.program.inputs.len * @sizeOf(engine.air.secure_polynomial_program_v2.Input) + self.program.roots.len * 4 + self.parameter_slots.len * 4;
    }
    pub fn deinit(self: *KernelMetadata) void {
        self.allocator.free(self.program.inputs);
        self.allocator.free(self.program.roots);
        self.allocator.free(self.parameter_slots);
    }
};
const TwiddleBorrow = struct {
    value: Twiddle,
    retained: bool,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
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
    pub fn validate(self: *const @This(), log: u32) !void {
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
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        a.free(self.descriptors);
        a.free(self.masks);
        a.free(self.denominators);
    }
};
const GeometryBorrow = struct {
    value: Geometry,
    retained: bool,
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        if (!self.retained) self.value.deinit(a);
    }
};
pub const Context = struct {
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
        const result = Context{ .allocator = a, .service = service, .timing = try Events.Api.load(&service.library), .session_api = .{
            .allocate = service.lease_allocate,
            .release = service.lease_release,
            .validate_range = service.lease_validate_range,
            .upload = try sym(Native.Upload, &service.library, "stwo_exec_context_memcpy_h2d_async"),
            .download = try sym(Native.Download, &service.library, "stwo_exec_context_memcpy_d2h_async"),
            .sync = try sym(Native.Sync, &service.library, "stwo_exec_context_sync"),
            .lane_stream = try sym(Native.LaneStream, &service.library, "stwo_exec_context_lane_stream"),
        }, .role = service.library.lookup(*const @TypeOf(Abi.stwo_rv64_composition_role_on), "stwo_rv64_composition_role_on"), .finish = try sym(*const @TypeOf(Abi.stwo_rv64_composition_finish_on), &service.library, "stwo_rv64_composition_finish_on"), .auxiliary = try sym(*const @TypeOf(Abi.stwo_rv64_composition_auxiliary_on), &service.library, "stwo_rv64_composition_auxiliary_on"), .tree = try sym(*const @TypeOf(Abi.stwo_rv64_trace_tree_on), &service.library, "stwo_rv64_trace_tree_on"), .n2b = try sym(N2b, &service.library, "stwo_lde_n2b_addressed_on"), .n2b_columns = service.library.lookup(*const @TypeOf(@import("stwo_cuda_backend").abi.stages.transform.stwo_lde_n2b_columns_on), "stwo_lde_n2b_columns_on"), .n2b_columns_compact = service.library.lookup(N2bColumnsCompact, "stwo_lde_n2b_columns_compact_on"), .b2n = try sym(B2n, &service.library, "stwo_ntt_b2n_columns_compact_on"), .copy = try sym(Copy, &service.library, "stwo_exec_context_memcpy_d2d_async"), .clear = try sym(Clear, &service.library, "stwo_exec_context_memset_async"), .artifacts = undefined };
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
        return result;
    }
    pub fn deinit(self: *Context) void {
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
        _ = a;
        // Every blocking reservation precedes this context lock and all owner
        // or immutable-cache locks reached by the callback.
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.service.submit(self.service.session, Job.callback, job) != 0) return job.failure orelse error.CudaResidentCompositionFailed;
        const result = job.result orelse return error.CudaResidentCompositionFailed;
        self.result_columns.append(self.allocator, @constCast(result.columns)) catch |err| {
            self.allocator.free(@constCast(result.columns));
            return err;
        };
        return result;
    }
    pub fn retainedBytes(self: *const Context) usize {
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
    pub fn tw(self: *Context, log: u32) !TwiddleBorrow {
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
    pub fn geometry(self: *Context, artifact: *const KernelMetadata, rl: u32, el: u32, widths: [3]usize, sources: []const D.Column, auxiliary_count: usize, twiddle_words: usize) !GeometryBorrow {
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
        return self.evaluateRolesImpl(a, roles, alpha, log, split, total, trace_raw, scope, log_blowup, false);
    }
    /// Only the outer authority explicitly opts this job into the role arena.
    /// The Context is shared with native stages and must never carry this flag.
    pub fn evaluateOuterRolesAtBlowup(self: *Context, a: std.mem.Allocator, roles: []const RuntimeRole, alpha: O, log: u32, split: u32, total: usize, trace_raw: *const anyopaque, scope: D.Scope, log_blowup: u32) !D.Tree {
        return self.evaluateRolesImpl(a, roles, alpha, log, split, total, trace_raw, scope, log_blowup, true);
    }
    fn evaluateRolesImpl(self: *Context, a: std.mem.Allocator, roles: []const RuntimeRole, alpha: O, log: u32, split: u32, total: usize, trace_raw: *const anyopaque, scope: D.Scope, log_blowup: u32, outer_workspace: bool) !D.Tree {
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
        var job = Job{ .backend = self, .allocator = a, .roles = roles, .alpha = alpha, .log = log, .split = split, .total = total, .trace = trace, .scope = scope, .log_blowup = log_blowup, .outer_workspace = outer_workspace };
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
const Job = @import("resident_composition_job.zig").Job;

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

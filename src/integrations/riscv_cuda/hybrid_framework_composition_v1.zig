//! Proof-owned exact framework CUDA evaluator. CPU Blake3 PCS and the original
//! polynomial-extension accumulator remain authoritative. No fallback or JIT.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const C = engine.air.component_prover;
const Acc = engine.air.accumulation.DomainEvaluationAccumulator;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Output = engine.secure_column.SecureColumnByCoords;
const R = @import("../../backends/cuda/abi/runtime.zig");
const Aot = @import("../../backends/cuda/abi/aot.zig");
const Types = @import("../../backends/cuda/abi/types.zig");
const Kernel = @import("../../backends/cuda/runtime/kernel.zig").Kernel;
const check = @import("../../backends/cuda/runtime/error.zig").check;
const Code = @import("../../backends/cuda/framework_polynomial_codegen_v1.zig");
const Executor = @import("../../frontends/riscv/recursion/blake3_parent_composition_executor_v1.zig").Executor;
const Geometry = core.poly.circle.quotient_geometry;
const Sources = @import("hybrid_framework_sources_v1.zig");
const Transform = @import("../../backends/cuda/abi/stages/transform.zig");
const Circle = engine.poly.circle;
pub const Limits = struct {
    max_device_bytes: usize = 16 * 1024 * 1024 * 1024,
    max_host_scratch_bytes: usize = 1024 * 1024 * 1024,
    max_device_expansion_scratch_bytes: usize = 128 * 1024 * 1024,
    materialization_workers: usize = 4,
    max_components: usize = 64,
    max_columns: usize = 65536,
    max_log: u32 = 26,
};
pub const Stats = struct {
    calls: usize = 0,
    components: usize = 0,
    source_columns: usize = 0,
    source_reuses: usize = 0,
    expanded_gpu_columns: usize = 0,
    expanded_cpu_columns: usize = 0,
    recovered_cpu_columns: usize = 0,
    expansion_kernel_launches: usize = 0,
    expansion_kernel_ns: u64 = 0,
    groups: usize = 0,
    kernel_launches: usize = 0,
    composition_kernel_launches: usize = 0,
    device_peak_bytes: usize = 0,
    host_metadata_peak_bytes: usize = 0,
    registers_per_thread_peak: usize = 0,
    local_bytes_peak: usize = 0,
    h2d_bytes: usize = 0,
    d2h_bytes: usize = 0,
    planning_ns: u64 = 0,
    source_materialization_cpu_ns: u64 = 0,
    upload_ns: u64 = 0,
    /// Synchronized launch wall time; not a device-event-only measurement.
    kernel_ns: u64 = 0,
    download_ns: u64 = 0,
    extension_cpu_ns: u64 = 0,
    total_ns: u64 = 0,
};
pub const Call = struct { index: usize, composition_log: u32, components: usize, delta: Stats };
pub const Observer = struct { context: *anyopaque, record: *const fn (*anyopaque, Call) anyerror!void };
pub const Owner = struct {
    handle: ?*anyopaque,
    stream: *anyopaque,
    loader: ?*anyopaque,
    limits: Limits,
    thread: std.Thread.Id,
    device: Types.DeviceSnapshot,
    platform: Types.PlatformSnapshot,
    module_identity: [32]u8,
    stats: Stats = .{},
    observer: ?Observer = null,
    poisoned: bool = false,
    original: []const C.ComponentProver = &.{},
    normalized: []const C.ComponentProver = &.{},
    bound: bool = false,
    evaluated: bool = false,
    pub fn open(device_ordinal: u32, expected_sm: u32, limits: Limits) !Owner {
        if (R.stwo_cuda_execution_provider() != 1) return error.ExecutionProviderMismatch;
        if (expected_sm == 0 or limits.max_device_bytes == 0 or limits.max_host_scratch_bytes == 0 or limits.max_components == 0 or limits.max_components > 64 or limits.max_log > 30 or limits.materialization_workers == 0 or limits.materialization_workers > 4 or limits.max_device_expansion_scratch_bytes == 0)
            return error.InvalidCudaCompositionPolicy;
        var handle: ?*anyopaque = null;
        try check(R.stwo_exec_context_create_options(&.{ .device_ordinal = device_ordinal }, &handle));
        errdefer if (handle) |h| {
            _ = R.stwo_exec_context_destroy(h);
        };
        const h = handle orelse return error.InvalidState;
        var stream: ?*anyopaque = null;
        try check(R.stwo_exec_context_stream(h, &stream));
        const accepted_stream = stream orelse return error.InvalidState;
        var device = Types.DeviceSnapshot{};
        try check(R.stwo_cuda_device_snapshot(&device.count, &device.current, &device.sm_major, &device.sm_minor));
        var platform = Types.PlatformSnapshot{};
        try check(R.stwo_cuda_platform_snapshot(&platform));
        if (device.count == 0 or device.current != device_ordinal or try device.sm() != expected_sm or !platform.isSane() or platform.device_ordinal != device.current) return error.DeviceArchitectureMismatch;
        var identity: [32]u8 = undefined;
        try check(R.stwo_static_cuda_module_build_identity(&identity));
        if (std.mem.allEqual(u8, &identity, 0)) return error.InvalidCudaModuleIdentity;
        var loader: ?*anyopaque = null;
        try check(Aot.stwo_native_aot_loader_create(h, &loader));
        return .{ .handle = h, .stream = accepted_stream, .loader = loader orelse return error.InvalidState, .limits = limits, .thread = std.Thread.getCurrentId(), .device = device, .platform = platform, .module_identity = identity };
    }
    pub fn deinit(self: *Owner) !void {
        try self.checkThread();
        if (self.bound) return error.CudaCompositionStillBound;
        if (self.loader) |l| {
            try check(Aot.stwo_native_aot_loader_destroy(l));
            self.loader = null;
        }
        if (self.handle) |h| {
            try check(R.stwo_exec_context_destroy(h));
            self.handle = null;
        }
    }
    fn checkThread(self: *const Owner) !void {
        if (self.thread != std.Thread.getCurrentId()) return error.ThreadOwnershipViolation;
    }
    pub fn executor(self: *Owner) Executor {
        return .{ .context = self, .bind = bind, .release = release };
    }
    fn bind(context: *anyopaque, original: []const C.ComponentProver, normalized: []const C.ComponentProver) !engine.air.device_composition.Stage {
        const self: *Owner = @ptrCast(@alignCast(context));
        try self.checkThread();
        if (self.poisoned or self.bound or self.handle == null) return error.InvalidState;
        try validateHandles(original, normalized, self.limits);
        self.original = original;
        self.normalized = normalized;
        self.bound = true;
        self.evaluated = false;
        return .{ .context = self, .evaluate = evaluate };
    }
    fn release(context: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(context));
        if (self.thread != std.Thread.getCurrentId() or !self.bound) self.poisoned = true;
        self.original = &.{};
        self.normalized = &.{};
        self.bound = false;
        self.evaluated = false;
    }
    fn evaluate(context: *anyopaque, allocator: std.mem.Allocator, alpha: Q, max_log: u32, count: usize, raw_trace: *const anyopaque, raw_output: *anyopaque) anyerror!bool {
        const self: *Owner = @ptrCast(@alignCast(context));
        try self.checkThread();
        if (self.poisoned or !self.bound or self.evaluated or self.handle == null) return error.InvalidState;
        errdefer self.poisoned = true;
        self.evaluated = true;
        const trace: *const C.Trace = @ptrCast(@alignCast(raw_trace));
        const output: *Output = @ptrCast(@alignCast(raw_output));
        if (trace.polys.items.len != 3 or max_log > self.limits.max_log) return error.UnsupportedCudaFrameworkTrace;
        try validateHandles(self.original, self.normalized, self.limits);
        var actual: usize = 0;
        var expected_max: u32 = 0;
        for (self.normalized) |c| {
            actual = try std.math.add(usize, actual, c.nConstraints());
            expected_max = @max(expected_max, c.maxConstraintLogDegreeBound());
        }
        if (actual != count or expected_max != max_log) return error.InvalidCudaFrameworkGeometry;
        const before = self.stats;
        var total = try std.time.Timer.start();
        var phase = try std.time.Timer.start();
        // This budget only backs temporary metadata/materialization. Returned
        // accumulator columns belong directly to the caller, never this stack.
        var budget = engine.host_budget_allocator.HostBudgetAllocator.init(allocator, self.limits.max_host_scratch_bytes);
        const a = budget.allocator();
        var jobs: std.ArrayList(Job) = .empty;
        defer {
            for (jobs.items) |*job| job.deinit();
            jobs.deinit(a);
        }
        var counts: [3]usize = undefined;
        for (trace.polys.items, &counts) |tree, *n| n.* = tree.len;
        var next = count;
        for (self.original, self.normalized) |original, normalized| {
            next -= original.nConstraints();
            var job = try Job.init(a, original, normalized, &counts, next);
            errdefer job.deinit();
            try jobs.append(a, job);
        }
        self.stats.planning_ns += phase.lap();
        var accumulator = try Acc.init(allocator, alpha, max_log, count);
        defer accumulator.deinit();
        // Allocate each canonical CPU bucket and consume coefficients in the
        // exact original component order. CUDA outputs are already folded.
        for (jobs.items) |*job| {
            if (job.delta != 0) try accumulator.beginPolynomialExtensionV2(job.delta);
            const cols = try accumulator.columns(a, &.{.{ .log_size = job.log, .n_cols = job.component.nConstraints() }});
            job.output = cols[0].col;
            a.free(cols);
            if (job.delta != 0) accumulator.endPolynomialExtensionV1();
        }
        for (1..max_log + 1) |log| {
            var any = false;
            for (jobs.items) |job| if (job.log == log) {
                any = true;
                break;
            };
            if (!any) continue;
            try self.evaluateGroup(a, trace, jobs.items, @intCast(log), accumulator.random_coeff_powers);
        }
        if (self.stats.composition_kernel_launches - before.composition_kernel_launches != jobs.items.len) return error.CudaCompositionCoverageMismatch;
        phase.reset();
        const result = try accumulator.finalize();
        errdefer {
            var owned = result;
            owned.deinit(allocator);
        }
        self.stats.extension_cpu_ns += phase.lap();
        self.stats.host_metadata_peak_bytes = @max(self.stats.host_metadata_peak_bytes, budget.peak_live_bytes);
        self.stats.components += jobs.items.len;
        self.stats.calls += 1;
        self.stats.total_ns += total.read();
        if (self.observer) |observer| {
            var delta: Stats = undefined;
            inline for (std.meta.fields(Stats)) |field| @field(delta, field.name) = @field(self.stats, field.name) - @field(before, field.name);
            try observer.record(observer.context, .{ .index = self.stats.calls - 1, .composition_log = max_log, .components = jobs.items.len, .delta = delta });
        }
        output.* = result;
        return true;
    }
    fn evaluateGroup(self: *Owner, a: std.mem.Allocator, trace: *const C.Trace, jobs: []Job, log: u32, powers: []const Q) !void {
        var buffers = Buffers{ .owner = self };
        defer buffers.deinit();
        var references: usize = 0;
        var sources: std.ArrayList(Source) = .empty;
        defer sources.deinit(a);
        for (jobs) |job| if (job.log == log) {
            for (job.program.inputs) |input| switch (input) {
                .trace_column => |column| {
                    references += 1;
                    try appendSource(a, &sources, column, self.limits);
                },
                .profile_parameter => {},
            };
            for (job.program.interaction_columns) |column| {
                references += 1;
                try appendSource(a, &sources, column, self.limits);
            }
        };
        const rows = @as(usize, 1) << @intCast(log);
        const words = try std.math.mul(usize, sources.items.len, rows);
        const device_sources = try buffers.alloc(words);
        var phase = try std.time.Timer.start();
        try self.materializeGroup(a, trace, sources.items, log, device_sources, &buffers);
        self.stats.source_columns += sources.items.len;
        self.stats.source_reuses += references - sources.items.len;
        // Separate output per exact polynomial-extension delta. Input columns
        // are shared across every component at this intrinsic domain.
        for (0..3) |delta| {
            var target: ?*Output = null;
            for (jobs) |job| if (job.log == log and job.delta == delta) {
                target = job.output;
                break;
            };
            const cpu = target orelse continue;
            const gpu = try buffers.alloc(rows * 4);
            try check(R.stwo_exec_context_memset_async(self.handle.?, gpu.ptr, 0, rows * 16));
            for (jobs) |*job| if (job.log == log and job.delta == delta) {
                try self.launch(a, &buffers, job, sources.items, device_sources, gpu, powers[job.power_start..][0..job.component.nConstraints()], rows);
            };
            phase.reset();
            for (0..4) |i| try check(R.stwo_exec_context_memcpy_d2h_async(self.handle.?, cpu.columns[i].ptr, gpu.ptr + i * rows, rows * 4));
            try check(R.stwo_exec_context_sync(self.handle.?));
            self.stats.d2h_bytes += rows * 16;
            for (cpu.columns) |column| for (column) |value| if (value.v >= core.fields.m31.Modulus) return error.NonCanonicalCudaComposition;
            self.stats.download_ns += phase.lap();
        }
        self.stats.groups += 1;
    }
    fn materializeGroup(self: *Owner, a: std.mem.Allocator, trace: *const C.Trace, sources: []const Source, log: u32, destination: []u32, buffers: *Buffers) !void {
        const rows = @as(usize, 1) << @intCast(log);
        var capacity: usize = 4;
        const coefficient_stride = rows / 2;
        if (log >= 3) {
            capacity = @min(capacity, self.limits.max_device_expansion_scratch_bytes / (coefficient_stride * 4));
            if (capacity == 0) return error.CudaCompositionResourceLimit;
        }
        const may_expand = blk: {
            for (sources) |source| {
                const poly = trace.polys.items[source.column.tree_index][source.column.column_index];
                if (log >= 3 and (poly.log_size != log or poly.values.len != rows)) break :blk true;
            }
            break :blk false;
        };
        var device_coefficients: []u32 = &.{};
        var device_logs: []u32 = &.{};
        var device_twiddles: []u32 = &.{};
        var phase = try std.time.Timer.start();
        if (may_expand) {
            var twiddles = try engine.poly.twiddles.precomputeM31Parallel(a, Circle.CanonicCoset.new(log).circleDomain().half_coset);
            defer engine.poly.twiddles.deinitM31(a, &twiddles);
            self.stats.planning_ns += phase.lap();
            device_coefficients = try buffers.alloc(capacity * coefficient_stride);
            device_logs = try buffers.alloc(capacity);
            device_twiddles = try buffers.upload(std.mem.sliceAsBytes(twiddles.twiddles));
            try check(R.stwo_exec_context_sync(self.handle.?));
            self.stats.upload_ns += phase.lap();
        }
        // Only immutable source recovery/evaluation runs on the existing pool;
        // all device API calls and uploads remain on the owner thread. Helpers
        // borrow a synchronized view of the same request-bounded allocator.
        var synchronized = std.heap.ThreadSafeAllocator{ .child_allocator = a };
        const worker_allocator = synchronized.allocator();
        var lease: ?engine.work_pool.WorkLease = null;
        if (engine.work_pool.currentScopedPool()) |pool| {
            const workers = @min(capacity, @min(self.limits.materialization_workers, pool.workerCount()));
            if (workers > 1) lease = pool.acquire(try engine.work_pool.WorkerBudget.init(workers)) catch null;
        }
        defer if (lease) |*l| l.deinit();
        const width = if (lease) |*l| l.workerCount() else 1;
        var first: usize = 0;
        while (first < sources.len) {
            const count = @min(width, sources.len - first);
            var pending: [4]Sources.Job = undefined;
            for (pending[0..count], sources[first..][0..count]) |*job, source| job.* = .{ .allocator = worker_allocator, .poly = trace.polys.items[source.column.tree_index][source.column.column_index], .log = log };
            defer for (pending[0..count]) |*job| if (job.result) |*value| value.deinit(a);
            phase.reset();
            var wait: std.Thread.WaitGroup = .{};
            {
                defer {
                    wait.wait();
                    if (lease) |*l| l.completeWave();
                }
                for (pending[0..count], 0..) |*job, i| {
                    if (lease != null and i + 1 < count) try lease.?.spawnWg(&wait, Sources.Job.run, .{job}) else job.run();
                }
            }
            self.stats.source_materialization_cpu_ns += phase.lap();
            for (pending[0..count]) |job| if (job.failure) |failure| return failure;
            var cursor: usize = 0;
            while (cursor < count) {
                const value = pending[cursor].result.?;
                if (value.kind == .evaluations) {
                    try buffers.copy(destination.ptr + (first + cursor) * rows, @ptrCast(value.values.ptr), rows * 4);
                    try check(R.stwo_exec_context_sync(self.handle.?));
                    self.stats.upload_ns += phase.lap();
                    if (value.owned != null) self.stats.expanded_cpu_columns += 1;
                    if (value.recovered) self.stats.recovered_cpu_columns += 1;
                    cursor += 1;
                    continue;
                }
                if (!may_expand) return error.InvalidCudaFrameworkGeometry;
                var stop = cursor;
                while (stop < count and pending[stop].result.?.kind == .coefficients) : (stop += 1) {}
                var logs: [4]u32 = undefined;
                for (pending[cursor..stop], 0..) |job, i| {
                    const coefficient = job.result.?;
                    if (coefficient.values.len > coefficient_stride or !std.math.isPowerOfTwo(coefficient.values.len)) return error.InvalidCudaFrameworkGeometry;
                    logs[i] = @intCast(std.math.log2_int(usize, coefficient.values.len));
                    try buffers.copy(device_coefficients.ptr + i * coefficient_stride, @ptrCast(coefficient.values.ptr), coefficient.values.len * 4);
                    if (coefficient.recovered) self.stats.recovered_cpu_columns += 1;
                }
                try buffers.copy(device_logs.ptr, &logs, (stop - cursor) * 4);
                try check(R.stwo_exec_context_sync(self.handle.?));
                self.stats.upload_ns += phase.lap();
                var launches: u32 = 0;
                try check(Transform.stwo_lde_n2b_columns_on(device_coefficients.ptr, coefficient_stride, device_logs.ptr, destination.ptr + (first + cursor) * rows, rows, log, @intCast(stop - cursor), device_twiddles.ptr, @intCast(device_twiddles.len), @intCast(coefficient_stride), self.stream, &launches));
                if (launches == 0) return error.InvalidCudaExpansionReceipt;
                try check(R.stwo_exec_context_sync(self.handle.?));
                self.stats.expansion_kernel_ns += phase.lap();
                self.stats.expansion_kernel_launches += launches;
                self.stats.kernel_launches += launches;
                self.stats.expanded_gpu_columns += stop - cursor;
                cursor = stop;
            }
            first += count;
        }
    }

    fn launch(self: *Owner, a: std.mem.Allocator, buffers: *Buffers, job: *Job, sources: []const Source, source_values: []u32, out: []u32, powers: []const Q, rows: usize) !void {
        var phase = try std.time.Timer.start();
        const offsets = try a.alloc(u64, job.program.inputs.len + job.program.interaction_columns.len);
        defer a.free(offsets);
        for (job.program.inputs, offsets[0..job.program.inputs.len]) |input, *offset| offset.* = switch (input) {
            .profile_parameter => 0,
            .trace_column => |column| try sourceOffset(sources, column, rows),
        };
        for (job.program.interaction_columns, offsets[job.program.inputs.len..]) |column, *offset| offset.* = try sourceOffset(sources, column, rows);
        const offset_words = try buffers.upload(std.mem.sliceAsBytes(offsets));
        const profile = try buffers.upload(std.mem.sliceAsBytes(job.profile));
        const relations = try buffers.upload(std.mem.sliceAsBytes(job.relations));
        const p = try a.alloc(u32, powers.len * 4);
        defer a.free(p);
        for (powers, 0..) |value, i| for (value.toM31Array(), 0..) |word, j| {
            p[i * 4 + j] = word.toU32();
        };
        const device_powers = try buffers.upload(std.mem.sliceAsBytes(p));
        const denominators = try Geometry.derive(job.trace_log, job.log);
        const denominator_words = Geometry.words(denominators);
        const device_denominators = try buffers.upload(std.mem.asBytes(&denominator_words));
        try check(R.stwo_exec_context_sync(self.handle.?));
        self.stats.upload_ns += phase.lap();
        var function: ?*anyopaque = null;
        const descriptor = Kernel{ .stage = .constraint_evaluation, .abi_schema = .framework_polynomial_composition_v1, .cache_key = Code.cacheKey(job.id), .name = job.name, .grid = .{ @intCast((rows + 127) / 128), 1, 1 }, .block = .{ 128, 1, 1 }, .argument_count = Code.ARGUMENT_COUNT };
        var receipt: Types.NativeAotFunctionReceipt = undefined;
        try check(Aot.stwo_native_aot_function_bind(self.loader.?, descriptor.cache_key, @intFromEnum(descriptor.abi_schema), descriptor.name.ptr, &descriptor.grid, &descriptor.block, 0, descriptor.argument_count, &function, &receipt));
        defer if (function) |f| {
            check(Aot.stwo_native_aot_function_destroy(f)) catch {
                self.poisoned = true;
            };
        };
        try descriptor.validateReceipt(receipt, self.device, self.stream);
        self.stats.registers_per_thread_peak = @max(self.stats.registers_per_thread_peak, receipt.registers_per_thread);
        self.stats.local_bytes_peak = @max(self.stats.local_bytes_peak, @as(usize, @intCast(receipt.local_bytes)));
        var tree = source_values.ptr;
        var off = offset_words.ptr;
        var prof = profile.ptr;
        var rel = relations.ptr;
        var pow = device_powers.ptr;
        var output = out.ptr;
        var row_count: u32 = @intCast(rows);
        var den = device_denominators.ptr;
        var den_count = denominators.count;
        const args = [_]?*anyopaque{ @ptrCast(&tree), @ptrCast(&tree), @ptrCast(&tree), @ptrCast(&off), @ptrCast(&prof), @ptrCast(&rel), @ptrCast(&pow), @ptrCast(&output), @ptrCast(&row_count), @ptrCast(&den), @ptrCast(&den_count) };
        phase.reset();
        try check(Aot.stwo_native_aot_function_launch(function orelse return error.InvalidState, &args, args.len));
        try check(R.stwo_exec_context_sync(self.handle.?));
        self.stats.kernel_ns += phase.lap();
        self.stats.kernel_launches += 1;
        self.stats.composition_kernel_launches += 1;
    }
};
pub fn validateHandles(original: []const C.ComponentProver, normalized: []const C.ComponentProver, limits: Limits) !void {
    if (original.len == 0 or original.len != normalized.len or original.len > limits.max_components) return error.InvalidCudaFrameworkRoster;
    for (original, normalized) |o, n| {
        if (o.ctx != n.ctx or o.vtable != n.vtable or o.profile_identity != n.profile_identity or o.composition_geometry_override_v1 != null or o.nConstraints() != n.nConstraints()) return error.InvalidCudaFrameworkGeometry;
        if (n.composition_geometry_override_v1) |geometry| try geometry.validate(o.maxConstraintLogDegreeBound());
        const delta = if (n.composition_geometry_override_v1) |geometry| geometry.max_constraint_log_degree_bound_delta else 0;
        if (delta > 2 or o.maxConstraintLogDegreeBound() + delta != n.maxConstraintLogDegreeBound() or n.maxConstraintLogDegreeBound() > limits.max_log) return error.InvalidCudaFrameworkGeometry;
        const cap = o.backend_composition_capability orelse return error.UnsupportedCudaFrameworkComponent;
        switch (cap) {
            .framework_polynomial_v1 => {},
            else => return error.UnsupportedCudaFrameworkComponent,
        }
    }
}
const Job = struct {
    allocator: std.mem.Allocator,
    component: C.ComponentProver,
    program: C.OwnedFrameworkPolynomialProgramV1,
    parameters: C.OwnedFrameworkPolynomialParametersV1,
    profile: []u32,
    relations: []u32,
    name: [:0]u8,
    id: [32]u8,
    log: u32,
    trace_log: u32,
    delta: u8,
    power_start: usize,
    output: *Output = undefined,
    fn init(a: std.mem.Allocator, c: C.ComponentProver, n: C.ComponentProver, counts: []const usize, power_start: usize) !Job {
        const cap = c.backend_composition_capability.?.framework_polynomial_v1;
        var program = try cap.export_program(c.ctx, a, counts);
        errdefer program.deinit();
        var parameters = try cap.export_parameters(c.ctx, a);
        errdefer parameters.deinit();
        try Code.validate(.{ .program = &program, .tree_column_counts = counts });
        try parameters.values.validate(&program);
        if (parameters.values.trace_log_size != cap.trace_log_size or c.nConstraints() != program.direct.roots.len + program.batches.len) return error.InvalidCudaFrameworkGeometry;
        _ = try Geometry.derive(cap.trace_log_size, c.maxConstraintLogDegreeBound());
        const profile = try a.alloc(u32, parameters.values.profile_values.len);
        errdefer a.free(profile);
        for (profile, parameters.values.profile_values) |*word, value| word.* = value.toU32();
        const relations = try a.alloc(u32, 4 * (parameters.values.relation_values.len + parameters.values.claimPayloadCount(&program)));
        errdefer a.free(relations);
        for (parameters.values.relation_values, 0..) |value, i| for (value.toM31Array(), 0..) |word, j| {
            relations[4 * i + j] = word.toU32();
        };
        for (0..parameters.values.claimPayloadCount(&program)) |i| for ((try parameters.values.claimPayload(&program, i)).toM31Array(), 0..) |word, j| {
            relations[4 * (parameters.values.relation_values.len + i) + j] = word.toU32();
        };
        const entry = Code.Entry{ .program = &program, .tree_column_counts = counts };
        const id = try Code.identity(a, entry);
        const name = try Code.kernelName(a, entry);
        return .{ .allocator = a, .component = c, .program = program, .parameters = parameters, .profile = profile, .relations = relations, .name = name, .id = id, .log = c.maxConstraintLogDegreeBound(), .trace_log = cap.trace_log_size, .delta = if (n.composition_geometry_override_v1) |g| g.max_constraint_log_degree_bound_delta else 0, .power_start = power_start };
    }
    fn deinit(self: *Job) void {
        self.allocator.free(self.name);
        self.allocator.free(self.relations);
        self.allocator.free(self.profile);
        self.parameters.deinit();
        self.program.deinit();
    }
};
const Source = struct { column: C.TypedPolynomialColumnV1 };
fn appendSource(a: std.mem.Allocator, sources: *std.ArrayList(Source), column: C.TypedPolynomialColumnV1, limits: Limits) !void {
    for (sources.items) |source| if (std.meta.eql(source.column, column)) return;
    if (sources.items.len >= limits.max_columns) return error.CudaCompositionResourceLimit;
    try sources.append(a, .{ .column = column });
}
fn sourceOffset(sources: []const Source, column: C.TypedPolynomialColumnV1, rows: usize) !u64 {
    for (sources, 0..) |source, i| if (std.meta.eql(source.column, column)) return std.math.mul(u64, i, rows);
    return error.InvalidCudaFrameworkTrace;
}
const Buffers = struct {
    owner: *Owner,
    pointers: [1024][*]u32 = undefined,
    count: usize = 0,
    bytes: usize = 0,
    fn alloc(self: *Buffers, count: usize) ![]u32 {
        const n = @max(count, 1);
        const bytes = try std.math.mul(usize, n, 4);
        const total = try std.math.add(usize, self.bytes, bytes);
        if (self.count == self.pointers.len or total > self.owner.limits.max_device_bytes) return error.CudaCompositionResourceLimit;
        var ptr: ?[*]u32 = null;
        try check(R.stwo_exec_context_alloc_u32(self.owner.handle.?, n, &ptr));
        const value = ptr orelse return error.InvalidState;
        self.pointers[self.count] = value;
        self.count += 1;
        self.bytes = total;
        self.owner.stats.device_peak_bytes = @max(self.owner.stats.device_peak_bytes, total);
        return value[0..n];
    }
    fn copy(self: *Buffers, dst: *anyopaque, src: *const anyopaque, bytes: usize) !void {
        if (bytes == 0) return;
        try check(R.stwo_exec_context_memcpy_h2d_async(self.owner.handle.?, dst, src, bytes));
        self.owner.stats.h2d_bytes += bytes;
    }
    fn upload(self: *Buffers, bytes: []const u8) ![]u32 {
        if (bytes.len % 4 != 0) return error.InvalidCudaFrameworkBuffer;
        const out = try self.alloc(bytes.len / 4);
        try self.copy(out.ptr, bytes.ptr, bytes.len);
        return out;
    }
    fn deinit(self: *Buffers) void {
        if (self.count == 0) return;
        check(R.stwo_exec_context_sync(self.owner.handle.?)) catch {
            self.owner.poisoned = true;
        };
        while (self.count != 0) {
            self.count -= 1;
            check(R.stwo_exec_context_free_u32(self.owner.handle.?, self.pointers[self.count])) catch {
                self.owner.poisoned = true;
            };
        }
    }
};

test "CUDA framework admission binds original handles and exact extension policy" {
    const Fake = struct {
        fn count(_: *const anyopaque) usize {
            return 3;
        }
        fn log(_: *const anyopaque) u32 {
            return 4;
        }
        const table = C.ComponentProverVTable{ .nConstraints = count, .maxConstraintLogDegreeBound = log, .traceLogDegreeBounds = undefined, .maskPoints = undefined, .preprocessedColumnIndices = undefined, .evaluateConstraintQuotientsAtPoint = undefined, .evaluateConstraintQuotientsOnDomain = undefined };
    };
    var marker: u32 = 1;
    var other: u32 = 2;
    const original = C.ComponentProver{ .ctx = &marker, .vtable = &Fake.table, .backend_composition_capability = .{ .framework_polynomial_v1 = .{ .trace_log_size = 3, .export_program = undefined, .export_parameters = undefined } } };
    for (0..3) |delta| {
        const normalized = try original.withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = @intCast(delta), .composition_log_split = 3 });
        try validateHandles(&.{original}, &.{normalized}, .{});
    }
    try std.testing.expectError(error.InvalidCudaFrameworkRoster, validateHandles(&.{}, &.{}, .{}));
    try std.testing.expectError(error.InvalidCudaFrameworkRoster, validateHandles(&.{original}, &.{}, .{}));
    var changed = original;
    changed.ctx = &other;
    try std.testing.expectError(error.InvalidCudaFrameworkGeometry, validateHandles(&.{original}, &.{changed}, .{}));
    changed = original;
    changed.composition_geometry_override_v1 = .{ .max_constraint_log_degree_bound_delta = 3, .composition_log_split = 3 };
    try std.testing.expectError(error.InvalidCudaFrameworkGeometry, validateHandles(&.{original}, &.{changed}, .{}));
    try std.testing.expectError(error.InvalidCudaFrameworkGeometry, validateHandles(&.{original}, &.{original}, .{ .max_log = 3 }));
    changed = original;
    changed.backend_composition_capability = null;
    try std.testing.expectError(error.UnsupportedCudaFrameworkComponent, validateHandles(&.{changed}, &.{changed}, .{}));
}
test "CUDA framework physical source deduplication retains exact tree identity and bounds" {
    const a = std.testing.allocator;
    var sources: std.ArrayList(Source) = .empty;
    defer sources.deinit(a);
    const first = C.TypedPolynomialColumnV1{ .tree_index = 0, .column_index = 3 };
    try appendSource(a, &sources, first, .{ .max_columns = 2 });
    try appendSource(a, &sources, first, .{ .max_columns = 2 });
    const second = C.TypedPolynomialColumnV1{ .tree_index = 1, .column_index = 3 };
    try appendSource(a, &sources, second, .{ .max_columns = 2 });
    try std.testing.expectEqual(@as(usize, 2), sources.items.len);
    try std.testing.expectEqual(@as(u64, 0), try sourceOffset(sources.items, first, 64));
    try std.testing.expectEqual(@as(u64, 64), try sourceOffset(sources.items, second, 64));
    const absent = C.TypedPolynomialColumnV1{ .tree_index = 2, .column_index = 3 };
    try std.testing.expectError(error.CudaCompositionResourceLimit, appendSource(a, &sources, absent, .{ .max_columns = 2 }));
    try std.testing.expectError(error.InvalidCudaFrameworkTrace, sourceOffset(sources.items, absent, 64));
}

//! Explicit CUDA DEEP numerical executor; host Blake3 PCS remains unchanged.
//! This is not a resident CUDA proof receipt. The same original verifier must
//! accept the resulting proof. Kernels are statically linked, never JIT-built.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const R = @import("../../backends/cuda/abi/runtime.zig");
const K = @import("../../backends/cuda/abi/stages/quotient.zig");
const Transform = @import("../../backends/cuda/abi/stages/transform.zig");
const Types = @import("../../backends/cuda/abi/types.zig");
const check = @import("../../backends/cuda/runtime/error.zig").check;
const Plan = @import("hybrid_quotient_plan_v1.zig");
const Provider = engine.pcs.quotient_ops.LazyQuotientProvider;
const Output = engine.secure_column.SecureColumnByCoords;
const M = core.fields.m31.M31;
pub const Limits = struct {
    plan: Plan.Limits = .{},
    /// Includes one reconstructed coefficient column and both twiddle tables.
    max_host_scratch_bytes: usize = 512 * 1024 * 1024,
    /// Reused coefficient staging only. Twiddles and all output arenas remain
    /// charged separately to plan.max_device_bytes.
    max_device_expansion_scratch_bytes: usize = 128 * 1024 * 1024,
};
pub const Stats = struct {
    calls: usize = 0,
    source_columns: usize = 0,
    terms: usize = 0,
    groups: usize = 0,
    device_peak_bytes: usize = 0,
    host_metadata_peak_bytes: usize = 0,
    h2d_bytes: usize = 0,
    d2h_bytes: usize = 0,
    kernel_launches: usize = 0,
    expansion_kernel_launches: usize = 0,
    expanded_gpu_columns: usize = 0,
    expanded_cpu_columns: usize = 0,
    expansion_kernel_ns: u64 = 0,
    planning_ns: u64 = 0,
    source_materialization_cpu_ns: u64 = 0,
    upload_ns: u64 = 0,
    kernel_ns: u64 = 0,
    download_ns: u64 = 0,
    total_ns: u64 = 0,
};
pub const Call = struct {
    index: usize,
    lifting_log: u32,
    source_columns: usize,
    coefficient_columns: usize,
    terms: usize,
    groups: usize,
    device_bytes: usize,
    metadata_bytes: usize,
    h2d_bytes: usize,
    d2h_bytes: usize,
    kernel_launches: usize,
    expansion_kernel_launches: usize,
    expanded_gpu_columns: usize,
    expanded_cpu_columns: usize,
    expansion_kernel_ns: u64,
    planning_ns: u64,
    source_materialization_cpu_ns: u64,
    upload_ns: u64,
    kernel_ns: u64,
    download_ns: u64,
    total_ns: u64,
};
pub const Observer = struct { context: *anyopaque, record: *const fn (*anyopaque, Call) anyerror!void };
pub const ExpansionGeometry = struct { max_log: u32, half_rows: usize, batch_capacity: usize, scratch_words: usize, extra_device_bytes: usize };
pub fn expansionGeometry(plan: *const Plan.Owned, limits: Limits) !ExpansionGeometry {
    var max_log: u32 = 0;
    for (plan.sources) |source| if (Plan.gpuExpandable(source)) {
        max_log = @max(max_log, source.log);
    };
    if (max_log == 0) return .{ .max_log = 0, .half_rows = 0, .batch_capacity = 0, .scratch_words = 0, .extra_device_bytes = 0 };
    const half_rows = @as(usize, 1) << @intCast(max_log - 1);
    const column_bytes = try std.math.mul(usize, half_rows, 4);
    const batch_capacity: usize = @min(@as(usize, 32), limits.max_device_expansion_scratch_bytes / column_bytes);
    if (batch_capacity == 0 or try std.math.mul(usize, column_bytes, 2) > limits.max_host_scratch_bytes)
        return error.CudaQuotientResourceLimit;
    const scratch_words = try std.math.mul(usize, half_rows, batch_capacity);
    const extra_bytes = try std.math.add(usize, try std.math.mul(usize, scratch_words, 4), try std.math.add(usize, column_bytes, batch_capacity * 4));
    if (try std.math.add(usize, plan.device_bytes, extra_bytes) > limits.plan.max_device_bytes)
        return error.CudaQuotientResourceLimit;
    return .{ .max_log = max_log, .half_rows = half_rows, .batch_capacity = batch_capacity, .scratch_words = scratch_words, .extra_device_bytes = extra_bytes };
}
pub const Owner = struct {
    handle: ?*anyopaque,
    stream: *anyopaque,
    limits: Limits,
    thread: std.Thread.Id,
    device: Types.DeviceSnapshot,
    platform: Types.PlatformSnapshot,
    module_identity: [32]u8,
    stats: Stats = .{},
    observer: ?Observer = null,
    poisoned: bool = false,

    pub fn open(device_ordinal: u32, expected_sm: u32, limits: Limits) !Owner {
        if (R.stwo_cuda_execution_provider() != 1) return error.ExecutionProviderMismatch;
        if (expected_sm == 0 or limits.plan.max_device_bytes == 0) return error.InvalidCudaQuotientPolicy;
        var handle: ?*anyopaque = null;
        const status = R.stwo_exec_context_create_options(&.{ .device_ordinal = device_ordinal }, &handle);
        errdefer if (handle) |h| {
            _ = R.stwo_exec_context_destroy(h);
        };
        try check(status);
        const h = handle orelse return error.InvalidState;
        var stream: ?*anyopaque = null;
        try check(R.stwo_exec_context_stream(h, &stream));
        var device = Types.DeviceSnapshot{};
        try check(R.stwo_cuda_device_snapshot(&device.count, &device.current, &device.sm_major, &device.sm_minor));
        var platform = Types.PlatformSnapshot{};
        try check(R.stwo_cuda_platform_snapshot(&platform));
        if (device.count == 0 or device.current != device_ordinal or try device.sm() != expected_sm or !platform.isSane() or platform.device_ordinal != device.current)
            return error.DeviceArchitectureMismatch;
        var identity: [32]u8 = undefined;
        try check(R.stwo_static_cuda_module_build_identity(&identity));
        if (std.mem.allEqual(u8, &identity, 0)) return error.InvalidCudaModuleIdentity;
        return .{ .handle = h, .stream = stream orelse return error.InvalidState, .limits = limits, .thread = std.Thread.getCurrentId(), .device = device, .platform = platform, .module_identity = identity };
    }
    pub fn deinit(self: *Owner) !void {
        if (self.thread != std.Thread.getCurrentId()) return error.ThreadOwnershipViolation;
        if (self.handle) |h| {
            try check(R.stwo_exec_context_destroy(h));
            self.handle = null;
        }
    }
    pub fn executor(self: *Owner) engine.pcs.QuotientExecutor {
        return .{ .context = self, .run = execute };
    }
    fn execute(context_ptr: *anyopaque, a: std.mem.Allocator, p: *Provider, out: *Output) anyerror!void {
        const self: *Owner = @ptrCast(@alignCast(context_ptr));
        if (self.thread != std.Thread.getCurrentId()) return error.ThreadOwnershipViolation;
        if (self.poisoned) return error.InvalidState;
        const h = self.handle orelse return error.ContextClosed;
        errdefer self.poisoned = true;
        if (out.len() != p.domain_size) return error.ShapeMismatch;
        const before = self.stats;
        var total = try std.time.Timer.start();
        var phase = try std.time.Timer.start();
        var plan = try Plan.Owned.init(a, p, self.limits.plan);
        defer plan.deinit();
        _ = try expansionGeometry(&plan, self.limits);
        for (plan.sources) |source| if (source.column.coefficient_values != null and !Plan.gpuExpandable(source)) {
            const bytes = std.math.mul(usize, @as(usize, 1) << @intCast(source.log), 16) catch return error.CudaQuotientResourceLimit;
            if (bytes > self.limits.max_host_scratch_bytes) return error.CudaQuotientResourceLimit;
        };
        self.stats.planning_ns += phase.lap();
        var buffers = Buffers{ .owner = self };
        defer buffers.deinit();
        const source_values = try buffers.alloc(u32, plan.source_words);
        const descriptors = try a.alloc(K.AddressedSourceDescriptor, plan.sources.len);
        defer {
            check(R.stwo_exec_context_sync(h)) catch {
                self.poisoned = true;
            };
            a.free(descriptors);
        }
        for (plan.sources, descriptors) |source, *descriptor| descriptor.* = .{ .address = @intFromPtr(source_values.ptr + source.offset), .stride_words = @intCast(@as(usize, 1) << @intCast(source.log)), .log_size = source.log };
        const d_sources = try buffers.upload(K.AddressedSourceDescriptor, descriptors);
        const d_terms = try buffers.upload(K.BatchTermDescriptor, plan.terms);
        const d_lines = try buffers.upload(@TypeOf(plan.lines[0]), plan.lines);
        const d_points = try buffers.upload(@TypeOf(plan.points[0]), plan.points);
        const d_first = try buffers.upload(@TypeOf(plan.first[0]), plan.first);
        const d_groups = try buffers.upload(u32, plan.group_offsets);
        const d_logs = try buffers.upload(u32, plan.group_logs);
        const d_offsets = try buffers.upload(u64, plan.output_offsets);
        var partial: [4][]u32 = undefined;
        var result: [4][]u32 = undefined;
        for (&partial, &result) |*part, *res| {
            part.* = try buffers.alloc(u32, plan.partial_words);
            res.* = try buffers.alloc(u32, plan.output_words);
        }
        for (plan.sources) |source| {
            const destination = source_values[source.offset..];
            if (Plan.gpuExpandable(source)) continue;
            if (source.column.coefficient_values) |coefficients| {
                try check(R.stwo_exec_context_sync(h));
                self.stats.upload_ns += phase.lap();
                const polynomial = try engine.poly.circle.poly.CircleCoefficients.initBorrowed(coefficients);
                const evaluation = try polynomial.evaluate(a, core.poly.circle.canonic.CanonicCoset.new(source.log).circleDomain());
                defer {
                    check(R.stwo_exec_context_sync(h)) catch {
                        self.poisoned = true;
                    };
                    a.free(evaluation.values);
                }
                self.stats.source_materialization_cpu_ns += phase.lap();
                self.stats.expanded_cpu_columns += 1;
                try buffers.copy(destination.ptr, evaluation.values.ptr, evaluation.values.len * @sizeOf(M));
                // The temporary coefficient expansion is released only after
                // the asynchronous transfer has consumed its immutable bytes.
                try check(R.stwo_exec_context_sync(h));
            } else if (source.column.log_size == 0) {
                const pair = [_]M{source.column.values[0]} ** 2;
                try buffers.copy(destination.ptr, &pair, @sizeOf(@TypeOf(pair)));
                try check(R.stwo_exec_context_sync(h));
            } else try buffers.copy(destination.ptr, source.column.values.ptr, source.column.values.len * @sizeOf(M));
        }
        try check(R.stwo_exec_context_sync(h));
        self.stats.upload_ns += phase.lap();
        try self.expandCoefficients(a, &plan, source_values, &buffers);
        phase.reset();
        const groups: u32 = @intCast(plan.group_logs.len);
        const terms: u32 = @intCast(plan.terms.len);
        try check(K.stwo_accumulate_quotient_numerator_addressed_on(d_groups.ptr, d_terms.ptr, terms, groups, @intCast(p.domain_size), d_sources.ptr, @intCast(plan.sources.len), d_lines.ptr, terms, d_logs.ptr, d_offsets.ptr, plan.partial_words, partial[0].ptr, partial[1].ptr, partial[2].ptr, partial[3].ptr, self.stream));
        try check(K.stwo_combine_quotients_from_compact_numerators_on(@intCast(p.domain.half_coset.initial_index.v), @intCast(p.domain.half_coset.step_size.v), @intCast(p.domain_size), p.lifting_log_size, d_points.ptr, groups, d_first.ptr, d_logs.ptr, d_offsets.ptr, plan.partial_words, partial[0].ptr, partial[1].ptr, partial[2].ptr, partial[3].ptr, result[0].ptr, result[1].ptr, result[2].ptr, result[3].ptr, self.stream));
        try check(R.stwo_exec_context_sync(h));
        self.stats.kernel_ns += phase.lap();
        self.stats.kernel_launches += 2;
        for (out.columns, result) |target, source| {
            try check(R.stwo_exec_context_memcpy_d2h_async(h, target.ptr, source.ptr, target.len * @sizeOf(M)));
            self.stats.d2h_bytes += target.len * @sizeOf(M);
        }
        try check(R.stwo_exec_context_sync(h));
        for (out.columns) |coordinate| for (coordinate) |value| if (value.v >= 0x7fffffff) return error.NonCanonicalCudaQuotient;
        self.stats.download_ns += phase.lap();
        self.stats.calls += 1;
        self.stats.source_columns += plan.sources.len;
        self.stats.terms += plan.terms.len;
        self.stats.groups += plan.group_logs.len;
        self.stats.device_peak_bytes = @max(self.stats.device_peak_bytes, buffers.bytes);
        self.stats.host_metadata_peak_bytes = @max(self.stats.host_metadata_peak_bytes, plan.metadata_bytes);
        buffers.deinit();
        if (self.poisoned) return error.InvalidState;
        self.stats.total_ns += total.read();
        if (self.observer) |observer| {
            var coefficient_columns: usize = 0;
            for (plan.sources) |source| if (source.column.coefficient_values != null) {
                coefficient_columns += 1;
            };
            try observer.record(observer.context, .{
                .index = self.stats.calls - 1,
                .lifting_log = p.lifting_log_size,
                .source_columns = plan.sources.len,
                .coefficient_columns = coefficient_columns,
                .terms = plan.terms.len,
                .groups = plan.group_logs.len,
                .device_bytes = buffers.bytes,
                .metadata_bytes = plan.metadata_bytes,
                .h2d_bytes = self.stats.h2d_bytes - before.h2d_bytes,
                .d2h_bytes = self.stats.d2h_bytes - before.d2h_bytes,
                .kernel_launches = self.stats.kernel_launches - before.kernel_launches,
                .expansion_kernel_launches = self.stats.expansion_kernel_launches - before.expansion_kernel_launches,
                .expanded_gpu_columns = self.stats.expanded_gpu_columns - before.expanded_gpu_columns,
                .expanded_cpu_columns = self.stats.expanded_cpu_columns - before.expanded_cpu_columns,
                .expansion_kernel_ns = self.stats.expansion_kernel_ns - before.expansion_kernel_ns,
                .planning_ns = self.stats.planning_ns - before.planning_ns,
                .source_materialization_cpu_ns = self.stats.source_materialization_cpu_ns - before.source_materialization_cpu_ns,
                .upload_ns = self.stats.upload_ns - before.upload_ns,
                .kernel_ns = self.stats.kernel_ns - before.kernel_ns,
                .download_ns = self.stats.download_ns - before.download_ns,
                .total_ns = self.stats.total_ns - before.total_ns,
            });
        }
    }

    fn expandCoefficients(self: *Owner, a: std.mem.Allocator, plan: *const Plan.Owned, destinations: []u32, buffers: *Buffers) !void {
        const geometry = try expansionGeometry(plan, self.limits);
        const max_log = geometry.max_log;
        if (max_log == 0) return;
        const batch_capacity = geometry.batch_capacity;
        var timer = try std.time.Timer.start();
        const domain = core.poly.circle.canonic.CanonicCoset.new(max_log).circleDomain();
        var twiddles = try engine.poly.twiddles.precomputeM31Parallel(a, domain.half_coset);
        defer {
            check(R.stwo_exec_context_sync(self.handle.?)) catch {
                self.poisoned = true;
            };
            engine.poly.twiddles.deinitM31(a, &twiddles);
        }
        self.stats.planning_ns += timer.lap();
        const d_coefficients = try buffers.alloc(u32, geometry.scratch_words);
        const d_logs = try buffers.alloc(u32, batch_capacity);
        const d_twiddles = try buffers.upload(M, twiddles.twiddles);
        try check(R.stwo_exec_context_sync(self.handle.?));
        self.stats.upload_ns += timer.lap();
        var selected: [32]Plan.Source = undefined;
        var logs: [32]u32 = undefined;
        for (3..max_log + 1) |log| {
            var count: usize = 0;
            for (plan.sources) |source| {
                if (source.log != log or !Plan.gpuExpandable(source)) continue;
                selected[count] = source;
                count += 1;
                if (count == batch_capacity) {
                    try self.expandBatch(&timer, buffers, destinations, d_coefficients, d_logs, d_twiddles, selected[0..count], &logs);
                    count = 0;
                }
            }
            if (count != 0) try self.expandBatch(&timer, buffers, destinations, d_coefficients, d_logs, d_twiddles, selected[0..count], &logs);
        }
    }

    fn expandBatch(self: *Owner, timer: *std.time.Timer, buffers: *Buffers, destinations: []u32, coefficients: []u32, device_logs: []u32, twiddles: []M, sources: []const Plan.Source, logs: *[32]u32) !void {
        const log = sources[0].log;
        const rows = @as(usize, 1) << @intCast(log);
        const stride = rows / 2;
        for (sources, 0..) |source, i| {
            if (source.log != log or source.offset != sources[0].offset + i * rows) return error.InvalidCudaQuotientPlan;
            const values = source.column.coefficient_values.?;
            logs[i] = @intCast(std.math.log2_int(usize, values.len));
            try buffers.copy(coefficients.ptr + i * stride, values.ptr, values.len * @sizeOf(M));
        }
        try buffers.copy(device_logs.ptr, logs, sources.len * @sizeOf(u32));
        try check(R.stwo_exec_context_sync(self.handle.?));
        self.stats.upload_ns += timer.lap();
        var launches: u32 = 0;
        try check(Transform.stwo_lde_n2b_columns_on(coefficients.ptr, stride, device_logs.ptr, destinations.ptr + sources[0].offset, rows, log, @intCast(sources.len), @ptrCast(twiddles.ptr), @intCast(twiddles.len), @intCast(stride), self.stream, &launches));
        if (launches == 0) return error.InvalidCudaExpansionReceipt;
        try check(R.stwo_exec_context_sync(self.handle.?));
        self.stats.expansion_kernel_ns += timer.lap();
        self.stats.expansion_kernel_launches += launches;
        self.stats.kernel_launches += launches;
        self.stats.expanded_gpu_columns += sources.len;
    }
};
const Buffers = struct {
    owner: *Owner,
    pointers: [24][*]u32 = undefined,
    count: usize = 0,
    bytes: usize = 0,
    fn alloc(self: *Buffers, comptime T: type, count: usize) ![]T {
        const bytes = std.math.mul(usize, @sizeOf(T), count) catch return error.CudaQuotientResourceLimit;
        if (bytes == 0 or bytes % 4 != 0 or self.count == self.pointers.len) return error.InvalidCudaQuotientPlan;
        const next = std.math.add(usize, self.bytes, bytes) catch return error.CudaQuotientResourceLimit;
        if (next > self.owner.limits.plan.max_device_bytes) return error.CudaQuotientResourceLimit;
        var ptr: ?[*]u32 = null;
        try check(R.stwo_exec_context_alloc_u32(self.owner.handle.?, bytes / 4, &ptr));
        const accepted = ptr orelse return error.InvalidState;
        self.pointers[self.count] = accepted;
        self.count += 1;
        self.bytes = next;
        return @as([*]T, @ptrCast(@alignCast(accepted)))[0..count];
    }
    fn copy(self: *Buffers, dst: *anyopaque, src: *const anyopaque, bytes: usize) !void {
        try check(R.stwo_exec_context_memcpy_h2d_async(self.owner.handle.?, dst, src, bytes));
        self.owner.stats.h2d_bytes += bytes;
    }
    fn upload(self: *Buffers, comptime T: type, values: []const T) ![]T {
        const target = try self.alloc(T, values.len);
        try self.copy(target.ptr, values.ptr, values.len * @sizeOf(T));
        return target;
    }
    fn deinit(self: *Buffers) void {
        if (self.count == 0) return;
        // Join even on errors before releasing staging or device allocations.
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

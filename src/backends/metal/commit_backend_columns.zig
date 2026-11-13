//! Metal column transforms, batched LDE lifetime and sampled-value dispatch.
const std = @import("std");
const work_profile = @import("stwo_prover_api").work_profile;
const metal_runtime = @import("runtime.zig");
const shared_runtime = @import("shared_runtime.zig");
const telemetry = @import("telemetry.zig");
const circle_lde_output_parity = @import("circle_lde_output_parity.zig");
const admitHostProving = @import("execution_policy.zig").admitHost;

pub const CircleLdeBatch = struct {
    lease: shared_runtime.CallLease,
    runtime_batch: metal_runtime.CircleLdeBatch,
    parity_groups: std.ArrayList(circle_lde_output_parity.GroupCaptureV1) = .empty,
    parity_allocator: ?std.mem.Allocator = null,

    pub fn init() !CircleLdeBatch {
        var lease = try shared_runtime.acquire();
        errdefer lease.deinit();
        const runtime_batch = try lease.runtime.beginCircleLdeBatch();
        return .{ .lease = lease, .runtime_batch = runtime_batch };
    }

    pub fn initWithAllocator(a: std.mem.Allocator) !CircleLdeBatch {
        var lease = try shared_runtime.acquire();
        errdefer lease.deinit();
        const runtime_batch = try lease.runtime.beginCircleLdeBatchWithAllocator(a);
        return .{ .lease = lease, .runtime_batch = runtime_batch };
    }

    pub fn deinit(self: *CircleLdeBatch) void {
        if (self.parity_allocator) |allocator| {
            for (self.parity_groups.items) |*group| group.deinit(allocator);
            self.parity_groups.deinit(allocator);
        }
        self.lease.runtime.destroyCircleLdeBatch(&self.runtime_batch);
        self.lease.deinit();
        self.* = undefined;
    }

    pub fn finish(self: *CircleLdeBatch) !void {
        const stats = try self.lease.runtime.finishCircleLdeBatch(&self.runtime_batch);
        if (circle_lde_output_parity.enabled()) {
            const allocator = self.parity_allocator orelse
                return error.MetalCircleLdeParityMissingRoute;
            const result = try circle_lde_output_parity.compareBatch(
                allocator,
                self.parity_groups.items,
            );
            switch (result) {
                .exact => |receipt| std.debug.print(
                    "METAL_RETAINED_LDE_PARITY=exact groups={} rebased_groups={} dispatches={} selected_columns={} coefficient_values={} extended_values={} sha256={x}\n",
                    .{
                        receipt.group_count,
                        receipt.rebased_group_count,
                        receipt.dispatch_count,
                        receipt.selected_column_count,
                        receipt.coefficient_values,
                        receipt.extended_values,
                        receipt.actual_sha256,
                    },
                ),
                .mismatch => |mismatch| {
                    std.debug.print(
                        "METAL_RETAINED_LDE_PARITY=mismatch group={} column={} phase={s} row={} expected={} actual={}\n",
                        .{
                            mismatch.group_index,
                            mismatch.group_column_index,
                            @tagName(mismatch.phase),
                            mismatch.row,
                            mismatch.expected.v,
                            mismatch.actual.v,
                        },
                    );
                    return error.MetalCircleLdeOutputParityMismatch;
                },
            }
        }
        std.log.debug(
            "Metal circle LDE batch: {} direct groups, {d:.3}ms GPU",
            .{ stats.encoded_operations, stats.gpu_milliseconds },
        );
        if (std.posix.getenv("STWO_METAL_PROFILE_LDE") != null)
            std.debug.print(
                "metal_circle_lde groups={} gpu_ms={d:.3}\n",
                .{ stats.encoded_operations, stats.gpu_milliseconds },
            );
    }

    fn captureParityGroup(
        self: *CircleLdeBatch,
        allocator: std.mem.Allocator,
        source_values: []const []const @import("stwo_core").fields.m31.M31,
        base_values: []const []@import("stwo_core").fields.m31.M31,
        extended_values: []const []@import("stwo_core").fields.m31.M31,
        transform_buffer: []@import("stwo_core").fields.m31.M31,
        extended_start: usize,
        extended_stride: usize,
        base_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
        base_twiddles: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
        extended_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
        extended_twiddles: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
    ) !void {
        if (!circle_lde_output_parity.enabled()) return;
        if (self.parity_allocator) |prior| {
            if (prior.ptr != allocator.ptr or prior.vtable != allocator.vtable)
                return error.MetalCircleLdeParityAllocatorMismatch;
        } else {
            self.parity_allocator = allocator;
        }
        var capture = try circle_lde_output_parity.GroupCaptureV1.init(
            allocator,
            source_values,
            base_values,
            extended_values,
            transform_buffer.len,
            extended_start,
            extended_stride,
            base_domain,
            base_twiddles,
            extended_domain,
            extended_twiddles,
        );
        errdefer capture.deinit(allocator);
        try self.parity_groups.append(allocator, capture);
    }
};
pub fn evaluateCoefficientPlans(
    allocator: std.mem.Allocator,
    coefficients: anytype,
    tree_values: anytype,
    plans: anytype,
) !void {
    if (plans.len == 0) return;
    var lease = try shared_runtime.acquire();
    defer lease.deinit();
    const gpu_ms = try lease.runtime.evaluateCoefficientPlansUnprofiled(
        allocator,
        coefficients,
        tree_values,
        plans,
    );
    telemetry.record(.metal_sampled_value_dispatch);
    std.log.debug("Metal sampled-value kernel: {d:.3}ms", .{gpu_ms});
}

pub fn evaluateCoefficientPlansWithReceipt(
    allocator: std.mem.Allocator,
    coefficients: anytype,
    tree_values: anytype,
    plans: anytype,
) !work_profile.SampledCoefficientExecution {
    if (plans.len == 0) return emptySampledCoefficientExecution();
    var lease = try shared_runtime.acquire();
    defer lease.deinit();
    const result = try lease.runtime.evaluateCoefficientPlans(
        allocator,
        coefficients,
        tree_values,
        plans,
    );
    telemetry.record(.metal_sampled_value_dispatch);
    std.log.debug("Metal sampled-value kernel: {d:.3}ms", .{result.gpu_ms});
    return result.execution;
}

pub fn evaluateCoefficientTreePlans(
    allocator: std.mem.Allocator,
    tree_plans: anytype,
) !void {
    if (tree_plans.len == 0) return;
    var lease = try shared_runtime.acquire();
    defer lease.deinit();
    const gpu_ms = try lease.runtime.evaluateCoefficientTreePlansUnprofiled(
        allocator,
        tree_plans,
    );
    telemetry.record(.metal_sampled_value_dispatch);
    std.log.debug("Metal sampled-value batch epoch: {d:.3}ms", .{gpu_ms});
}

pub fn evaluateCoefficientTreePlansWithReceipt(
    allocator: std.mem.Allocator,
    tree_plans: anytype,
) !work_profile.SampledCoefficientExecution {
    if (tree_plans.len == 0) return emptySampledCoefficientExecution();
    var lease = try shared_runtime.acquire();
    defer lease.deinit();
    const result = try lease.runtime.evaluateCoefficientTreePlans(allocator, tree_plans);
    telemetry.record(.metal_sampled_value_dispatch);
    std.log.debug("Metal sampled-value batch epoch: {d:.3}ms", .{result.gpu_ms});
    return result.execution;
}

/// Host staging holds whole columns in a bounded 64 MiB slab. Larger
/// individual columns retain the generic fallback until row tiling exists.
pub fn supportsMixedSampledEvaluation() bool {
    return !std.process.hasEnvVarConstant("STWO_ZIG_CPU_HOST_BARYCENTRIC");
}

/// The PCS planner can keep resident and staged trees in separate epochs.
/// Host slab limits then apply only to trees that actually need an upload.
pub const supportsBarycentricResidencyEpochs = true;

pub fn supportsHostBarycentricColumns(columns: anytype) bool {
    if (!supportsMixedSampledEvaluation()) return false;
    for (columns) |column| if (column.log_size > 24) return false;
    return true;
}

pub fn evaluateBarycentricTreePlans(
    allocator: std.mem.Allocator,
    tree_plans: anytype,
) !void {
    if (tree_plans.len == 0) return;
    var lease = try shared_runtime.acquire();
    defer lease.deinit();
    const result = try lease.runtime.evaluateBarycentricTreePlans(
        allocator,
        tree_plans,
    );
    telemetry.record(.metal_sampled_value_dispatch);
    std.log.debug(
        "Metal sampled-value barycentric epoch: {d:.3}ms",
        .{result.gpu_ms},
    );
}

pub fn evaluateBarycentricTreePlansWithReceipt(
    allocator: std.mem.Allocator,
    tree_plans: anytype,
) !work_profile.SampledBarycentricExecution {
    if (tree_plans.len == 0) return emptySampledBarycentricExecution();
    var lease = try shared_runtime.acquire();
    defer lease.deinit();
    const result = try lease.runtime.evaluateBarycentricTreePlans(
        allocator,
        tree_plans,
    );
    telemetry.record(.metal_sampled_value_dispatch);
    std.log.debug(
        "Metal sampled-value barycentric epoch: {d:.3}ms",
        .{result.gpu_ms},
    );
    return result.execution;
}

fn emptySampledBarycentricExecution() work_profile.SampledBarycentricExecution {
    return .{
        .point_plan_count = 0,
        .domain_plan_count = 0,
        .evaluation_task_count = 0,
        .weight_value_count = 0,
        .dot_product_terms = 0,
        .domain_circle_multiplications = 0,
        .scale_double_count = 0,
        .inverse_tree_block_count = 0,
        .direct_inversion_count = 0,
        .reduction_addition_count = 0,
        .constant_addition_count = 0,
        .constant_multiplication_count = 0,
        .constant_inversion_count = 0,
    };
}

fn emptySampledCoefficientExecution() work_profile.SampledCoefficientExecution {
    return .{
        .plan_count = 0,
        .basis_task_count = 0,
        .evaluation_task_count = 0,
        .evaluation_coefficient_terms = 0,
        .basis_multiplications = 0,
        .basis_threadgroup_width = 0,
        .evaluation_threadgroup_width = 0,
    };
}

pub fn interpolateCircleBuffers(
    allocator: std.mem.Allocator,
    values: []const []@import("stwo_core").fields.m31.M31,
    domain: @import("stwo_core").poly.circle.domain.CircleDomain,
    twiddle_tree: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
) !work_profile.M31InterpolationExecution {
    if (values.len == 0) return error.InvalidColumns;
    if (domain.logSize() < 3) {
        try admitHostProving(.circle_interpolation);
        try @import("stwo_prover_engine").poly.circle.poly.interpolateBuffersWithTwiddles(values, domain, twiddle_tree);
        telemetry.record(.cpu_small_circle_interpolation);
        const execution = work_profile.M31InterpolationExecution{
            .log_size = domain.logSize(),
            .column_count = @intCast(values.len),
            // One host fallback call shares its normalization inverse.
            .batch_count = 1,
        };
        try execution.validate();
        return execution;
    }
    var lease = try shared_runtime.acquire();
    defer lease.deinit();
    _ = try lease.runtime.transformCircle(
        allocator,
        values,
        twiddle_tree.itwiddles,
        domain.logSize(),
        true,
    );
    telemetry.record(.metal_circle_transform_dispatch);
    const execution = work_profile.M31InterpolationExecution{
        .log_size = domain.logSize(),
        .column_count = @intCast(values.len),
        // The device dispatch shares one scale factor across every column.
        .batch_count = 1,
    };
    try execution.validate();
    return execution;
}

pub const foldCoefficientContributions = @import("runtime/native_coefficient_fold.zig").fold;

pub fn evaluateCircleBuffers(
    allocator: std.mem.Allocator,
    values: []const []@import("stwo_core").fields.m31.M31,
    domain: @import("stwo_core").poly.circle.domain.CircleDomain,
    twiddle_tree: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
) !work_profile.M31ForwardFftExecution {
    if (values.len == 0) return error.InvalidColumns;
    if (domain.logSize() < 3) {
        try admitHostProving(.circle_evaluation);
        try @import("stwo_prover_engine").poly.circle.poly.evaluateBuffersWithTwiddles(values, domain, twiddle_tree);
        telemetry.record(.cpu_small_circle_evaluation);
        const execution = work_profile.M31ForwardFftExecution{
            .log_size = domain.logSize(),
            .column_count = @intCast(values.len),
        };
        try execution.validate();
        return execution;
    }
    var lease = try shared_runtime.acquire();
    defer lease.deinit();
    _ = try lease.runtime.transformCircle(
        allocator,
        values,
        twiddle_tree.twiddles,
        domain.logSize(),
        false,
    );
    telemetry.record(.metal_circle_transform_dispatch);
    const execution = work_profile.M31ForwardFftExecution{
        .log_size = domain.logSize(),
        .column_count = @intCast(values.len),
        // Standalone evaluation materializes every layer on device.
        .skipped_layers = 0,
    };
    try execution.validate();
    return execution;
}

pub fn interpolateAndEvaluateCircleBuffers(
    allocator: std.mem.Allocator,
    source_values: []const []const @import("stwo_core").fields.m31.M31,
    base_values: []const []@import("stwo_core").fields.m31.M31,
    extended_values: []const []@import("stwo_core").fields.m31.M31,
    transform_buffer: []@import("stwo_core").fields.m31.M31,
    extended_start: usize,
    extended_stride: usize,
    base_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
    base_twiddles: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
    extended_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
    extended_twiddles: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
) !work_profile.M31CircleLdeExecution {
    return interpolateAndEvaluateCircleBuffersImpl(
        null,
        allocator,
        source_values,
        base_values,
        extended_values,
        transform_buffer,
        extended_start,
        extended_stride,
        base_domain,
        base_twiddles,
        extended_domain,
        extended_twiddles,
    );
}

pub fn interpolateAndEvaluateCircleBuffersBatched(
    batch: *CircleLdeBatch,
    allocator: std.mem.Allocator,
    source_values: []const []const @import("stwo_core").fields.m31.M31,
    base_values: []const []@import("stwo_core").fields.m31.M31,
    extended_values: []const []@import("stwo_core").fields.m31.M31,
    transform_buffer: []@import("stwo_core").fields.m31.M31,
    extended_start: usize,
    extended_stride: usize,
    base_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
    base_twiddles: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
    extended_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
    extended_twiddles: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
) !work_profile.M31CircleLdeExecution {
    return interpolateAndEvaluateCircleBuffersImpl(
        batch,
        allocator,
        source_values,
        base_values,
        extended_values,
        transform_buffer,
        extended_start,
        extended_stride,
        base_domain,
        base_twiddles,
        extended_domain,
        extended_twiddles,
    );
}

fn interpolateAndEvaluateCircleBuffersImpl(
    batch: ?*CircleLdeBatch,
    allocator: std.mem.Allocator,
    source_values: []const []const @import("stwo_core").fields.m31.M31,
    base_values: []const []@import("stwo_core").fields.m31.M31,
    extended_values: []const []@import("stwo_core").fields.m31.M31,
    transform_buffer: []@import("stwo_core").fields.m31.M31,
    extended_start: usize,
    extended_stride: usize,
    base_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
    base_twiddles: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
    extended_domain: @import("stwo_core").poly.circle.domain.CircleDomain,
    extended_twiddles: @import("stwo_prover_engine").poly.twiddles.TwiddleTree([]const @import("stwo_core").fields.m31.M31),
) !work_profile.M31CircleLdeExecution {
    if (source_values.len == 0 or source_values.len != base_values.len or
        base_values.len != extended_values.len)
    {
        return error.InvalidColumns;
    }
    if (base_domain.logSize() < 3) {
        try admitHostProving(.circle_lde);
        for (source_values, base_values, extended_values) |source, base, extended| {
            if (source.len != base_domain.size() or base.len != base_domain.size() or
                extended.len != extended_domain.size() or extended.len < base.len)
                return error.InvalidColumns;
            if (source.ptr != base.ptr) {
                const source_address = @intFromPtr(source.ptr);
                const base_address = @intFromPtr(base.ptr);
                const separation = if (source_address < base_address) base_address - source_address else source_address - base_address;
                if (separation < source.len * @sizeOf(@import("stwo_core").fields.m31.M31))
                    return error.InvalidColumns;
            }
        }
        // The owned-source arena may already be this group's coefficient
        // buffer. The device path supports that exact alias; small host
        // transforms must preserve the same ownership contract.
        for (source_values, base_values) |source, base| {
            if (source.ptr != base.ptr) @memcpy(base, source);
        }
        try @import("stwo_prover_engine").poly.circle.poly.interpolateBuffersWithTwiddles(
            base_values,
            base_domain,
            base_twiddles,
        );
        for (base_values, extended_values) |base, extended| {
            @memcpy(extended[0..base.len], base);
            @memset(extended[base.len..], @import("stwo_core").fields.m31.M31.zero());
        }
        try @import("stwo_prover_engine").poly.circle.poly.evaluateBuffersWithTwiddles(
            extended_values,
            extended_domain,
            extended_twiddles,
        );
        telemetry.record(.cpu_small_circle_lde);
        return .{
            .interpolation = .{
                .log_size = base_domain.logSize(),
                .column_count = @intCast(source_values.len),
                // The host fallback submits every column as one batch.
                .batch_count = 1,
            },
            .forward = .{
                .log_size = extended_domain.logSize(),
                .column_count = @intCast(source_values.len),
            },
        };
    }
    if (batch) |active| try active.captureParityGroup(
        allocator,
        source_values,
        base_values,
        extended_values,
        transform_buffer,
        extended_start,
        extended_stride,
        base_domain,
        base_twiddles,
        extended_domain,
        extended_twiddles,
    );
    const result = if (batch) |active|
        try active.lease.runtime.transformCircleLdeIntoBatch(
            &active.runtime_batch,
            allocator,
            source_values,
            base_values,
            extended_values,
            transform_buffer,
            extended_start,
            extended_stride,
            base_twiddles.itwiddles,
            extended_twiddles.twiddles,
            base_domain.logSize(),
            extended_domain.logSize(),
        )
    else blk: {
        var lease = try shared_runtime.acquire();
        defer lease.deinit();
        break :blk try lease.runtime.transformCircleLdeInto(
            allocator,
            source_values,
            base_values,
            extended_values,
            transform_buffer,
            extended_start,
            extended_stride,
            base_twiddles.itwiddles,
            extended_twiddles.twiddles,
            base_domain.logSize(),
            extended_domain.logSize(),
        );
    };
    telemetry.record(.metal_circle_lde_dispatch);
    std.log.debug("Metal circle IFFT+RFFT: {d:.3}ms", .{result.gpu_milliseconds});
    return result.execution;
}

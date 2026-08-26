//! Device-side sampled-coefficient evaluation and exact work receipts.

const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");
const work_profile = @import("stwo_prover_api").work_profile;

const MetalError = runtime.MetalError;
const Runtime = runtime.Runtime;
const QuotientCoefficientTask = runtime.QuotientCoefficientTask;

pub const SampledCoefficientEvaluationResult = struct {
    gpu_ms: f64,
    execution: work_profile.SampledCoefficientExecution,
};

pub fn evaluateCoefficientPlans(
    self: *Runtime,
    allocator: std.mem.Allocator,
    coefficients: anytype,
    tree_values: anytype,
    plans: anytype,
) (MetalError || std.mem.Allocator.Error)!SampledCoefficientEvaluationResult {
    const TreePlan = struct {
        coefficients: @TypeOf(coefficients),
        tree_values: @TypeOf(tree_values),
        plans: @TypeOf(plans),
    };
    const tree_plans = [_]TreePlan{.{
        .coefficients = coefficients,
        .tree_values = tree_values,
        .plans = plans,
    }};
    return evaluateCoefficientTreePlansInternal(
        self,
        allocator,
        &tree_plans,
        true,
    );
}

pub fn evaluateCoefficientPlansUnprofiled(
    self: *Runtime,
    allocator: std.mem.Allocator,
    coefficients: anytype,
    tree_values: anytype,
    plans: anytype,
) (MetalError || std.mem.Allocator.Error)!f64 {
    const TreePlan = struct {
        coefficients: @TypeOf(coefficients),
        tree_values: @TypeOf(tree_values),
        plans: @TypeOf(plans),
    };
    const tree_plans = [_]TreePlan{.{
        .coefficients = coefficients,
        .tree_values = tree_values,
        .plans = plans,
    }};
    return (try evaluateCoefficientTreePlansInternal(
        self,
        allocator,
        &tree_plans,
        false,
    )).gpu_ms;
}

pub fn evaluateCoefficientTreePlans(
    self: *Runtime,
    allocator: std.mem.Allocator,
    tree_plans: anytype,
) (MetalError || std.mem.Allocator.Error)!SampledCoefficientEvaluationResult {
    return evaluateCoefficientTreePlansInternal(
        self,
        allocator,
        tree_plans,
        true,
    );
}

pub fn evaluateCoefficientTreePlansUnprofiled(
    self: *Runtime,
    allocator: std.mem.Allocator,
    tree_plans: anytype,
) (MetalError || std.mem.Allocator.Error)!f64 {
    return (try evaluateCoefficientTreePlansInternal(
        self,
        allocator,
        tree_plans,
        false,
    )).gpu_ms;
}

fn evaluateCoefficientTreePlansInternal(
    self: *Runtime,
    allocator: std.mem.Allocator,
    tree_plans: anytype,
    capture_execution: bool,
) (MetalError || std.mem.Allocator.Error)!SampledCoefficientEvaluationResult {
    var coefficient_column_count: usize = 0;
    var coefficient_count: usize = 0;
    var factor_word_count: usize = 0;
    var task_count: usize = 0;
    var basis_task_count: usize = 0;
    var basis_count: usize = 0;
    var output_count: usize = 0;
    for (tree_plans) |tree_plan| {
        if (tree_plan.coefficients.len != tree_plan.tree_values.len)
            return MetalError.PolynomialEvaluationFailed;
        coefficient_column_count += tree_plan.coefficients.len;
        for (tree_plan.coefficients) |coefficient| {
            coefficient_count += std.mem.sliceAsBytes(coefficient.coefficients()).len / @sizeOf(u32);
        }
        for (tree_plan.plans) |plan| {
            factor_word_count += plan.flat_factors.len * 4;
            task_count += plan.column_indices.items.len * plan.normalized_points.len;
            basis_task_count += plan.normalized_points.len;
            basis_count += plan.normalized_points.len * (@as(usize, 1) << @intCast(plan.coeff_log_size));
        }
        for (tree_plan.tree_values) |values| output_count += values.len;
    }
    if (coefficient_column_count == 0 or task_count == 0) return .{
        .gpu_ms = 0,
        .execution = emptySampledCoefficientExecution(),
    };

    const coefficient_offsets = try allocator.alloc(u32, coefficient_column_count);
    defer allocator.free(coefficient_offsets);
    const coefficient_ptrs = try allocator.alloc([*]const u32, coefficient_column_count);
    defer allocator.free(coefficient_ptrs);
    const coefficient_lengths = try allocator.alloc(usize, coefficient_column_count);
    defer allocator.free(coefficient_lengths);
    var coefficient_cursor: usize = 0;
    var coefficient_word_cursor: usize = 0;
    for (tree_plans) |tree_plan| {
        for (tree_plan.coefficients) |coefficient| {
            const words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(coefficient.coefficients()));
            coefficient_offsets[coefficient_cursor] = @intCast(coefficient_word_cursor);
            coefficient_ptrs[coefficient_cursor] = words.ptr;
            coefficient_lengths[coefficient_cursor] = words.len;
            coefficient_cursor += 1;
            coefficient_word_cursor += words.len;
        }
    }
    std.debug.assert(coefficient_cursor == coefficient_column_count);
    std.debug.assert(coefficient_word_cursor == coefficient_count);

    const factor_words = try allocator.alloc(u32, factor_word_count);
    defer allocator.free(factor_words);
    const task_words = try allocator.alloc(u32, task_count * 5);
    defer allocator.free(task_words);
    const task_columns = try allocator.alloc(u32, task_count);
    defer allocator.free(task_columns);
    const basis_task_words = try allocator.alloc(u32, basis_task_count * 4);
    defer allocator.free(basis_task_words);

    const output_offsets = try allocator.alloc(u32, coefficient_column_count);
    defer allocator.free(output_offsets);
    var output_column_cursor: usize = 0;
    var output_cursor: usize = 0;
    for (tree_plans) |tree_plan| {
        for (tree_plan.tree_values) |values| {
            output_offsets[output_column_cursor] = @intCast(output_cursor);
            output_column_cursor += 1;
            output_cursor += values.len;
        }
    }
    std.debug.assert(output_column_cursor == coefficient_column_count);
    std.debug.assert(output_cursor == output_count);

    var factor_cursor: usize = 0;
    var task_cursor: usize = 0;
    var basis_task_cursor: usize = 0;
    var basis_cursor: usize = 0;
    var tree_column_base: usize = 0;
    for (tree_plans) |tree_plan| {
        for (tree_plan.plans) |plan| {
            const plan_factor_start = factor_cursor;
            for (plan.flat_factors) |factor| {
                const coordinates = factor.toM31Array();
                inline for (0..4) |coordinate| {
                    factor_words[factor_cursor] = coordinates[coordinate].v;
                    factor_cursor += 1;
                }
            }
            for (0..plan.normalized_points.len) |point_index| {
                const base = basis_task_cursor * 4;
                const coefficient_length = @as(usize, 1) << @intCast(plan.coeff_log_size);
                basis_task_words[base..][0..4].* = .{
                    @intCast(plan_factor_start + point_index * plan.coeff_log_size * 4),
                    plan.coeff_log_size,
                    @intCast(basis_cursor),
                    @intCast(coefficient_length),
                };
                basis_task_cursor += 1;
                basis_cursor += coefficient_length;
            }
            const coefficient_length = @as(usize, 1) << @intCast(plan.coeff_log_size);
            const plan_basis_start = basis_cursor - plan.normalized_points.len * coefficient_length;
            for (plan.column_indices.items) |column_index| {
                if (column_index >= tree_plan.coefficients.len)
                    return MetalError.PolynomialEvaluationFailed;
                const global_column = tree_column_base + column_index;
                for (0..plan.normalized_points.len) |point_index| {
                    const base = task_cursor * 5;
                    task_words[base..][0..5].* = .{
                        coefficient_offsets[global_column],
                        @intCast(tree_plan.coefficients[column_index].coefficients().len),
                        @intCast(plan_basis_start + point_index * coefficient_length),
                        plan.coeff_log_size,
                        output_offsets[global_column] + @as(u32, @intCast(point_index)),
                    };
                    task_columns[task_cursor] = @intCast(global_column);
                    task_cursor += 1;
                }
            }
        }
        tree_column_base += tree_plan.coefficients.len;
    }
    std.debug.assert(factor_cursor == factor_word_count);
    std.debug.assert(task_cursor == task_count);
    std.debug.assert(basis_task_cursor == basis_task_count);
    std.debug.assert(basis_cursor == basis_count);

    const output_words = try allocator.alloc(u32, output_count * 4);
    defer allocator.free(output_words);
    var gpu_ms: f64 = 0;
    var basis_threadgroup_width: u32 = 0;
    var evaluation_threadgroup_width: u32 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_eval_polynomials(
        self.handle,
        coefficient_ptrs.ptr,
        coefficient_lengths.ptr,
        @intCast(coefficient_column_count),
        coefficient_count,
        factor_words.ptr,
        factor_words.len,
        @ptrCast(basis_task_words.ptr),
        @intCast(basis_task_count),
        @intCast(basis_count),
        @ptrCast(task_words.ptr),
        task_columns.ptr,
        @intCast(task_count),
        @intCast(output_count),
        output_words.ptr,
        &basis_threadgroup_width,
        &evaluation_threadgroup_width,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal polynomial evaluation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.PolynomialEvaluationFailed;
    }
    output_column_cursor = 0;
    for (tree_plans) |tree_plan| {
        for (tree_plan.tree_values) |values| {
            const output_offset = output_offsets[output_column_cursor];
            for (values, 0..) |*value, point_index| {
                var coordinates: [4]@import("stwo_core").fields.m31.M31 = undefined;
                inline for (0..4) |coordinate| {
                    coordinates[coordinate].v = output_words[(@as(usize, output_offset) + point_index) * 4 + coordinate];
                }
                value.* = @import("stwo_core").fields.qm31.QM31.fromM31Array(coordinates);
            }
            output_column_cursor += 1;
        }
    }
    const execution = if (capture_execution)
        deriveSampledCoefficientExecution(
            tree_plans,
            basis_threadgroup_width,
            evaluation_threadgroup_width,
        ) catch return MetalError.PolynomialEvaluationFailed
    else
        emptySampledCoefficientExecution();
    return .{ .gpu_ms = gpu_ms, .execution = execution };
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

fn deriveSampledCoefficientExecution(
    tree_plans: anytype,
    basis_threadgroup_width: u32,
    evaluation_threadgroup_width: u32,
) work_profile.Error!work_profile.SampledCoefficientExecution {
    var plan_count: u64 = 0;
    var basis_task_count: u64 = 0;
    var evaluation_task_count: u64 = 0;
    var evaluation_coefficient_terms: u64 = 0;
    var basis_multiplications: u64 = 0;

    for (tree_plans) |tree_plan| {
        for (tree_plan.plans) |plan| {
            plan_count = try addSampledCount(plan_count, 1);
            const point_count = std.math.cast(u64, plan.normalized_points.len) orelse
                return error.CounterOverflow;
            basis_task_count = try addSampledCount(basis_task_count, point_count);
            const column_count = std.math.cast(u64, plan.column_indices.items.len) orelse
                return error.CounterOverflow;
            evaluation_task_count = try addSampledCount(
                evaluation_task_count,
                try multiplySampledCount(point_count, column_count),
            );
            const basis_per_point = try sampledBasisMultiplications(
                plan.coeff_log_size,
                basis_threadgroup_width,
            );
            basis_multiplications = try addSampledCount(
                basis_multiplications,
                try multiplySampledCount(point_count, basis_per_point),
            );
            for (plan.column_indices.items) |column_index| {
                if (column_index >= tree_plan.coefficients.len)
                    return error.InvalidCounterGroup;
                const coefficient_count = std.math.cast(
                    u64,
                    tree_plan.coefficients[column_index].coefficients().len,
                ) orelse return error.CounterOverflow;
                evaluation_coefficient_terms = try addSampledCount(
                    evaluation_coefficient_terms,
                    try multiplySampledCount(point_count, coefficient_count),
                );
            }
        }
    }

    const execution = work_profile.SampledCoefficientExecution{
        .plan_count = plan_count,
        .basis_task_count = basis_task_count,
        .evaluation_task_count = evaluation_task_count,
        .evaluation_coefficient_terms = evaluation_coefficient_terms,
        .basis_multiplications = basis_multiplications,
        .basis_threadgroup_width = basis_threadgroup_width,
        .evaluation_threadgroup_width = evaluation_threadgroup_width,
    };
    try execution.validate();
    return execution;
}

fn sampledBasisMultiplications(
    log_size: u32,
    threadgroup_width: u32,
) work_profile.Error!u64 {
    return work_profile.logicalSampledCoefficientBasisMultiplications(
        log_size,
        threadgroup_width,
    );
}

fn addSampledCount(lhs: u64, rhs: u64) work_profile.Error!u64 {
    return std.math.add(u64, lhs, rhs) catch error.CounterOverflow;
}

fn multiplySampledCount(lhs: anytype, rhs: anytype) work_profile.Error!u64 {
    const encoded_lhs = std.math.cast(u64, lhs) orelse return error.CounterOverflow;
    const encoded_rhs = std.math.cast(u64, rhs) orelse return error.CounterOverflow;
    return std.math.mul(u64, encoded_lhs, encoded_rhs) catch error.CounterOverflow;
}

test "Metal sampled basis receipt follows both shader schedules" {
    // The 256-lane kernel executes the low-bit products for every physical
    // lane, even when a small basis stores only its first few results.
    try std.testing.expectEqual(
        @as(u64, 384),
        try sampledBasisMultiplications(3, 256),
    );
    try std.testing.expectEqual(
        @as(u64, 1_024),
        try sampledBasisMultiplications(8, 256),
    );
    // Four blocks at log ten: 4*1024 low products, 4 high products, and
    // 3*256 low/high combines.
    try std.testing.expectEqual(
        @as(u64, 4_868),
        try sampledBasisMultiplications(10, 256),
    );
    // A narrower future pipeline takes the generic popcount schedule.
    try std.testing.expectEqual(
        @as(u64, 5_120),
        try sampledBasisMultiplications(10, 128),
    );
    try std.testing.expectError(
        error.InvalidCounterGroup,
        sampledBasisMultiplications(3, 0),
    );
}

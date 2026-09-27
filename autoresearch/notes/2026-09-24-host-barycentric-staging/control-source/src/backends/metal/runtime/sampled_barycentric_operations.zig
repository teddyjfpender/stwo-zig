//! One proof-owned Metal epoch for evaluation-form sampled values.
//!
//! Plans are collision-safe and deduplicated across all commitment trees by
//! exact `(domain log, normalized point)` equality.  Host column pointers are
//! used only as lookup keys into the concrete borrowed tree's resident map;
//! the Objective-C boundary rejects uploads, cross-tree matches, and partial
//! output rosters.

const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");
const circle = @import("stwo_core").circle;
const constraints = @import("stwo_core").constraints;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const work_profile = @import("stwo_prover_api").work_profile;
const sampled_plan_types = @import("stwo_prover_engine").pcs.sampled_coefficient_plans;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointM31 = circle.CirclePointM31;
const CirclePointQM31 = circle.CirclePointQM31;
const MetalError = runtime.MetalError;
const Runtime = runtime.Runtime;

pub const SampledBarycentricEvaluationResult = struct {
    gpu_ms: f64,
    execution: work_profile.SampledBarycentricExecution,
};

const PointUseV1 = struct {
    tree_index: usize,
    column_indices: []const usize,
    local_point_index: usize,
};

const PointOwnerV1 = struct {
    log_size: u32,
    point: CirclePointQM31,
    uses: std.ArrayList(PointUseV1) = .empty,

    fn deinit(self: *PointOwnerV1, allocator: std.mem.Allocator) void {
        self.uses.deinit(allocator);
        self.* = undefined;
    }
};

const DomainConstantsV1 = struct {
    si0: [4]u32,
    vanishing_rotation: [2]u32,
    additions: u64,
    multiplications: u64,
    inversions: u64,
};

const PreparedEpochV1 = struct {
    allocator: std.mem.Allocator,
    resident_trees: []*anyopaque,
    columns: [][*]const u32,
    column_lengths: []usize,
    output_indices: []u32,
    point_plans: []ffi.SampledBarycentricPointPlanV1,
    groups: []ffi.SampledBarycentricColumnGroupV1,
    output_count: u32,
    execution: work_profile.SampledBarycentricExecution,

    fn deinit(self: *PreparedEpochV1) void {
        self.allocator.free(self.resident_trees);
        self.allocator.free(self.columns);
        self.allocator.free(self.column_lengths);
        self.allocator.free(self.output_indices);
        self.allocator.free(self.point_plans);
        self.allocator.free(self.groups);
        self.* = undefined;
    }
};

pub fn evaluateBarycentricTreePlans(
    self: *Runtime,
    allocator: std.mem.Allocator,
    tree_plans: anytype,
) (MetalError || std.mem.Allocator.Error)!SampledBarycentricEvaluationResult {
    var prepared = prepareEpoch(allocator, tree_plans) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return MetalError.PolynomialEvaluationFailed,
    };
    defer prepared.deinit();

    const output_word_count = std.math.mul(
        usize,
        prepared.output_count,
        4,
    ) catch return MetalError.PolynomialEvaluationFailed;
    const output_words = try allocator.alloc(u32, output_word_count);
    defer allocator.free(output_words);

    var ffi_receipt: ffi.SampledBarycentricReceiptV1 = undefined;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_eval_barycentric_resident_v1(
        self.handle,
        prepared.resident_trees.ptr,
        @intCast(prepared.resident_trees.len),
        prepared.columns.ptr,
        prepared.column_lengths.ptr,
        prepared.output_indices.ptr,
        @intCast(prepared.columns.len),
        prepared.point_plans.ptr,
        @intCast(prepared.point_plans.len),
        prepared.groups.ptr,
        @intCast(prepared.groups.len),
        prepared.output_count,
        output_words.ptr,
        &ffi_receipt,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err(
            "Metal resident barycentric evaluation failed: {s}",
            .{std.mem.sliceTo(&message, 0)},
        );
        return MetalError.PolynomialEvaluationFailed;
    }
    validateFfiReceipt(prepared.execution, ffi_receipt) catch
        return MetalError.PolynomialEvaluationFailed;

    var output_cursor: usize = 0;
    for (tree_plans) |tree_plan| {
        for (tree_plan.tree_values) |values| {
            for (values) |*value| {
                var coordinates: [4]M31 = undefined;
                inline for (0..4) |coordinate| {
                    const word = output_words[output_cursor * 4 + coordinate];
                    if (word >= m31.Modulus)
                        return MetalError.PolynomialEvaluationFailed;
                    coordinates[coordinate] = M31.fromCanonical(word);
                }
                value.* = QM31.fromM31Array(coordinates);
                output_cursor += 1;
            }
        }
    }
    if (output_cursor != @as(usize, prepared.output_count))
        return MetalError.PolynomialEvaluationFailed;

    return .{ .gpu_ms = gpu_ms, .execution = prepared.execution };
}

fn prepareEpoch(
    allocator: std.mem.Allocator,
    tree_plans: anytype,
) !PreparedEpochV1 {
    if (tree_plans.len == 0 or tree_plans.len > std.math.maxInt(u32))
        return error.InvalidSampledBarycentricPlan;

    var points = std.ArrayList(PointOwnerV1).empty;
    defer {
        for (points.items) |*point| point.deinit(allocator);
        points.deinit(allocator);
    }

    const tree_output_bases = try allocator.alloc(u32, tree_plans.len);
    defer allocator.free(tree_output_bases);
    const column_output_bases = try allocator.alloc([]u32, tree_plans.len);
    defer allocator.free(column_output_bases);
    var initialized_bases: usize = 0;
    defer for (column_output_bases[0..initialized_bases]) |bases|
        allocator.free(bases);

    var output_count: usize = 0;
    var total_group_count: usize = 0;
    var total_column_count: usize = 0;
    for (tree_plans, 0..) |tree_plan, tree_index| {
        if (tree_plan.columns.len != tree_plan.tree_values.len) {
            return error.InvalidSampledBarycentricPlan;
        }
        tree_output_bases[tree_index] = std.math.cast(u32, output_count) orelse
            return error.InvalidSampledBarycentricPlan;
        const bases = try allocator.alloc(u32, tree_plan.columns.len);
        column_output_bases[tree_index] = bases;
        initialized_bases += 1;
        const seen_columns = try allocator.alloc(bool, tree_plan.columns.len);
        defer allocator.free(seen_columns);
        @memset(seen_columns, false);
        for (tree_plan.columns, tree_plan.tree_values, 0..) |
            column,
            values,
            column_index,
        | {
            try column.validate();
            bases[column_index] = std.math.cast(u32, output_count -
                @as(usize, tree_output_bases[tree_index])) orelse
                return error.InvalidSampledBarycentricPlan;
            output_count = std.math.add(usize, output_count, values.len) catch
                return error.InvalidSampledBarycentricPlan;
            if (output_count > std.math.maxInt(u32))
                return error.InvalidSampledBarycentricPlan;
        }

        for (tree_plan.plans) |plan| {
            if (plan.log_size == 0 or plan.log_size >= 31 or
                plan.raw_points.len == 0 or
                plan.raw_points.len != plan.normalized_points.len or
                plan.column_indices.items.len == 0)
            {
                return error.InvalidSampledBarycentricPlan;
            }
            if (!plan.hasCanonicalNormalization())
                return error.InvalidSampledBarycentricPlan;
            total_group_count = std.math.add(
                usize,
                total_group_count,
                plan.normalized_points.len,
            ) catch
                return error.InvalidSampledBarycentricPlan;
            total_column_count = std.math.add(
                usize,
                total_column_count,
                std.math.mul(
                    usize,
                    plan.column_indices.items.len,
                    plan.normalized_points.len,
                ) catch return error.InvalidSampledBarycentricPlan,
            ) catch return error.InvalidSampledBarycentricPlan;
            for (plan.column_indices.items) |column_index| {
                if (column_index >= tree_plan.columns.len or
                    seen_columns[column_index] or
                    tree_plan.columns[column_index].log_size != plan.log_size or
                    tree_plan.tree_values[column_index].len !=
                        plan.normalized_points.len)
                {
                    return error.InvalidSampledBarycentricPlan;
                }
                seen_columns[column_index] = true;
            }
            for (plan.normalized_points, 0..) |point, local_point_index| {
                const point_index = findPoint(points.items, plan.log_size, point) orelse blk: {
                    if (!point.isOnCircle())
                        return error.InvalidSampledBarycentricPlan;
                    if (constraints.cosetVanishing(
                        QM31,
                        canonic.CanonicCoset.new(plan.log_size).coset(),
                        point,
                    ).isZero()) return error.SampledBarycentricPointOnDomain;
                    try points.append(allocator, .{
                        .log_size = plan.log_size,
                        .point = point,
                    });
                    break :blk points.items.len - 1;
                };
                try points.items[point_index].uses.append(allocator, .{
                    .tree_index = tree_index,
                    .column_indices = plan.column_indices.items,
                    .local_point_index = local_point_index,
                });
            }
        }
        for (tree_plan.tree_values, seen_columns) |values, seen| {
            if ((values.len != 0) != seen)
                return error.InvalidSampledBarycentricPlan;
        }
    }
    if (points.items.len == 0 or output_count == 0 or
        total_group_count == 0 or total_column_count == 0 or
        points.items.len > std.math.maxInt(u32) or
        total_group_count > std.math.maxInt(u32) or
        total_column_count > std.math.maxInt(u32))
    {
        return error.InvalidSampledBarycentricPlan;
    }

    // Stable insertion sort makes equal-log domain runs contiguous while the
    // output-index scatter preserves the transcript's original tree/column
    // order. Exact point equality, never a digest alone, owns deduplication.
    var sorted_at: usize = 1;
    while (sorted_at < points.items.len) : (sorted_at += 1) {
        var cursor = sorted_at;
        while (cursor != 0 and pointLess(points.items[cursor], points.items[cursor - 1])) {
            std.mem.swap(PointOwnerV1, &points.items[cursor], &points.items[cursor - 1]);
            cursor -= 1;
        }
    }

    const resident_trees = try allocator.alloc(*anyopaque, tree_plans.len);
    errdefer allocator.free(resident_trees);
    for (tree_plans, resident_trees) |tree_plan, *resident|
        resident.* = tree_plan.resident_tree;
    const columns = try allocator.alloc([*]const u32, total_column_count);
    errdefer allocator.free(columns);
    const column_lengths = try allocator.alloc(usize, total_column_count);
    errdefer allocator.free(column_lengths);
    const output_indices = try allocator.alloc(u32, total_column_count);
    errdefer allocator.free(output_indices);
    const point_plans = try allocator.alloc(
        ffi.SampledBarycentricPointPlanV1,
        points.items.len,
    );
    errdefer allocator.free(point_plans);
    const groups = try allocator.alloc(
        ffi.SampledBarycentricColumnGroupV1,
        total_group_count,
    );
    errdefer allocator.free(groups);

    var group_cursor: usize = 0;
    var column_cursor: usize = 0;
    var unique_domain_count: u64 = 0;
    var weight_value_count: u64 = 0;
    var dot_product_terms: u64 = 0;
    var domain_circle_multiplications: u64 = 0;
    var scale_double_count: u64 = 0;
    var inverse_tree_block_count: u64 = 0;
    var direct_inversion_count: u64 = 0;
    var reduction_addition_count: u64 = 0;
    var constant_addition_count: u64 = 0;
    var constant_multiplication_count: u64 = 0;
    var constant_inversion_count: u64 = 0;
    var prior_log: ?u32 = null;
    var constants: DomainConstantsV1 = undefined;
    for (points.items, 0..) |point, point_index| {
        if (prior_log == null or prior_log.? != point.log_size) {
            constants = domainConstants(point.log_size);
            unique_domain_count = try checkedAdd(unique_domain_count, 1);
            domain_circle_multiplications = try checkedAdd(
                domain_circle_multiplications,
                domainCircleMultiplications(point.log_size),
            );
            constant_addition_count = try checkedAdd(
                constant_addition_count,
                constants.additions,
            );
            constant_multiplication_count = try checkedAdd(
                constant_multiplication_count,
                constants.multiplications,
            );
            constant_inversion_count = try checkedAdd(
                constant_inversion_count,
                constants.inversions,
            );
            prior_log = point.log_size;
        }
        const point_words = packPoint(point.point);
        point_plans[point_index] = .{
            .log_size = point.log_size,
            .first_group = @intCast(group_cursor),
            .group_count = @intCast(point.uses.items.len),
            .point = point_words,
            .si0 = constants.si0,
            .vanishing_rotation = constants.vanishing_rotation,
        };

        const domain_size = @as(u64, 1) << @intCast(point.log_size);
        // Exact process-local validation before dispatch: `isOnCircle`
        // executes two squares and one addition; `cosetVanishing` executes
        // two circle additions and `log_size - 1` double-X steps.
        constant_addition_count = try checkedAdd(
            constant_addition_count,
            5 + 2 * (point.log_size - 1),
        );
        constant_multiplication_count = try checkedAdd(
            constant_multiplication_count,
            10 + (point.log_size - 1),
        );
        weight_value_count = try checkedAdd(weight_value_count, domain_size);
        scale_double_count = try checkedAdd(
            scale_double_count,
            point.log_size - 1,
        );
        if (domain_size < 1_024) {
            direct_inversion_count = try checkedAdd(
                direct_inversion_count,
                domain_size,
            );
        } else {
            inverse_tree_block_count = try checkedAdd(
                inverse_tree_block_count,
                domain_size / 1_024,
            );
        }

        for (point.uses.items) |use| {
            groups[group_cursor] = .{
                .tree_index = @intCast(use.tree_index),
                .first_column = @intCast(column_cursor),
                .column_count = @intCast(use.column_indices.len),
            };
            const tree_plan = tree_plans[use.tree_index];
            for (use.column_indices) |column_index| {
                const column = tree_plan.columns[column_index];
                columns[column_cursor] = @ptrCast(column.values.ptr);
                column_lengths[column_cursor] = column.values.len;
                output_indices[column_cursor] = try outputIndex(
                    tree_output_bases[use.tree_index],
                    column_output_bases[use.tree_index][column_index],
                    use.local_point_index,
                );
                column_cursor += 1;
            }
            const evaluation_count: u64 = @intCast(use.column_indices.len);
            dot_product_terms = try checkedAdd(
                dot_product_terms,
                try checkedMul(evaluation_count, domain_size),
            );
            const reduction_blocks = @min(
                @as(u64, 256),
                (domain_size + 255) / 256,
            );
            reduction_addition_count = try checkedAdd(
                reduction_addition_count,
                try checkedMul(
                    evaluation_count,
                    try checkedMul(reduction_blocks + 1, 255),
                ),
            );
            group_cursor += 1;
        }
    }
    std.debug.assert(group_cursor == groups.len);
    std.debug.assert(column_cursor == columns.len);

    const execution = work_profile.SampledBarycentricExecution{
        .point_plan_count = @intCast(points.items.len),
        .domain_plan_count = unique_domain_count,
        .evaluation_task_count = @intCast(total_column_count),
        .weight_value_count = weight_value_count,
        .dot_product_terms = dot_product_terms,
        .domain_circle_multiplications = domain_circle_multiplications,
        .scale_double_count = scale_double_count,
        .inverse_tree_block_count = inverse_tree_block_count,
        .direct_inversion_count = direct_inversion_count,
        .reduction_addition_count = reduction_addition_count,
        .constant_addition_count = constant_addition_count,
        .constant_multiplication_count = constant_multiplication_count,
        .constant_inversion_count = constant_inversion_count,
    };
    try execution.validate();

    return .{
        .allocator = allocator,
        .resident_trees = resident_trees,
        .columns = columns,
        .column_lengths = column_lengths,
        .output_indices = output_indices,
        .point_plans = point_plans,
        .groups = groups,
        .output_count = @intCast(output_count),
        .execution = execution,
    };
}

fn findPoint(
    points: []const PointOwnerV1,
    log_size: u32,
    point: CirclePointQM31,
) ?usize {
    for (points, 0..) |candidate, index| {
        if (candidate.log_size == log_size and candidate.point.eql(point))
            return index;
    }
    return null;
}

fn pointLess(lhs: PointOwnerV1, rhs: PointOwnerV1) bool {
    if (lhs.log_size != rhs.log_size) return lhs.log_size < rhs.log_size;
    const lhs_words = packPoint(lhs.point);
    const rhs_words = packPoint(rhs.point);
    for (lhs_words, rhs_words) |lhs_word, rhs_word| {
        if (lhs_word != rhs_word) return lhs_word < rhs_word;
    }
    return false;
}

fn packPoint(point: CirclePointQM31) [8]u32 {
    var result: [8]u32 = undefined;
    const x = point.x.toM31Array();
    const y = point.y.toM31Array();
    inline for (0..4) |coordinate| {
        result[coordinate] = x[coordinate].v;
        result[4 + coordinate] = y[coordinate].v;
    }
    return result;
}

fn domainConstants(log_size: u32) DomainConstantsV1 {
    std.debug.assert(log_size != 0 and log_size < 31);
    const canonical = canonic.CanonicCoset.new(log_size);
    const domain = canonical.circleDomain();
    const generated = circle.Coset.new(circle.CirclePointIndex.generator(), log_size);
    const domain_point = pointM31IntoQM31(domain.at(0));
    const si0 = QM31.fromBase(M31.fromCanonical(2)).neg()
        .mul(domain_point.y)
        .mul(constraints.cosetVanishingDerivative(QM31, generated, domain_point))
        .inv() catch unreachable;
    const rotation = canonical.coset().initial.neg().add(
        canonical.coset().half_step,
    );
    const si0_words = si0.toM31Array();

    var additions: u64 = 0;
    var multiplications: u64 = 0;
    // Exact CirclePointM31 additions executed by the three Coset constructors,
    // domain.at(0), and the final vanishing-shift construction.
    const canonical_initial = circle.CirclePointIndex.subgroupGen(log_size + 1);
    const circle_additions = cosetConstructorAdds(canonical_initial, log_size) +
        cosetConstructorAdds(canonical_initial, log_size - 1) +
        cosetConstructorAdds(circle.CirclePointIndex.generator(), log_size) +
        @popCount(domain.indexAt(0).v & ((@as(usize, 1) << 31) - 1)) + 1;
    additions += @as(u64, @intCast(circle_additions)) * 2;
    multiplications += @as(u64, @intCast(circle_additions)) * 4;

    // This is the literal `cosetVanishingDerivative` schedule for one point,
    // followed by the two products that form si0.
    multiplications += log_size - 1;
    var inner_log: u32 = 1;
    while (inner_log < log_size) : (inner_log += 1) {
        additions += 4 + 2 * (inner_log - 1);
        multiplications += 9 + (inner_log - 1);
    }
    multiplications += 3;

    return .{
        .si0 = .{
            si0_words[0].v,
            si0_words[1].v,
            si0_words[2].v,
            si0_words[3].v,
        },
        .vanishing_rotation = .{ rotation.x.v, rotation.y.v },
        .additions = additions,
        .multiplications = multiplications,
        .inversions = 1,
    };
}

fn cosetConstructorAdds(initial: circle.CirclePointIndex, log_size: u32) usize {
    const mask = (@as(usize, 1) << 31) - 1;
    const step = circle.CirclePointIndex.subgroupGen(log_size);
    return @popCount(initial.v & mask) + @popCount(step.v & mask) +
        @popCount(step.half().v & mask);
}

fn pointM31IntoQM31(point: CirclePointM31) CirclePointQM31 {
    return .{ .x = QM31.fromBase(point.x), .y = QM31.fromBase(point.y) };
}

fn domainCircleMultiplications(log_size: u32) u64 {
    const size = @as(u32, 1) << @intCast(log_size);
    const half_size = size >> 1;
    const initial = @as(u64, 1) << @intCast(30 - log_size);
    const step = @as(u64, 1) << @intCast(32 - log_size);
    const circle_order = @as(u64, 1) << 31;
    var result: u64 = 0;
    for (0..half_size) |index| {
        const positive = initial + step * index;
        result += powCircleMultiplications(positive);
        result += powCircleMultiplications(circle_order - positive);
    }
    return result;
}

fn powCircleMultiplications(exponent: u64) u64 {
    std.debug.assert(exponent != 0);
    return @as(u64, 64 - @clz(exponent)) + @popCount(exponent);
}

fn outputIndex(tree_base: u32, column_base: u32, point_index: usize) !u32 {
    const base = std.math.add(u32, tree_base, column_base) catch
        return error.InvalidSampledBarycentricPlan;
    return std.math.add(
        u32,
        base,
        std.math.cast(u32, point_index) orelse
            return error.InvalidSampledBarycentricPlan,
    ) catch return error.InvalidSampledBarycentricPlan;
}

fn validateFfiReceipt(
    execution: work_profile.SampledBarycentricExecution,
    receipt: ffi.SampledBarycentricReceiptV1,
) !void {
    if (receipt.schema_version != 1 or receipt.command_buffers != 1 or
        receipt.wait_count != 1 or receipt.reserved != 0 or
        receipt.unique_point_count != execution.point_plan_count or
        receipt.unique_domain_count != execution.domain_plan_count or
        receipt.resident_column_evaluations != execution.evaluation_task_count or
        receipt.weight_values != execution.weight_value_count or
        receipt.dot_product_terms != execution.dot_product_terms or
        receipt.inverse_tree_blocks != execution.inverse_tree_block_count or
        receipt.direct_inversions != execution.direct_inversion_count or
        receipt.reduction_additions != execution.reduction_addition_count or
        receipt.evaluation_threadgroup_width != 256 or
        receipt.inverse_threadgroup_width != 512)
    {
        return error.InvalidSampledBarycentricReceipt;
    }
}

fn checkedAdd(lhs: u64, rhs: anytype) !u64 {
    const encoded = std.math.cast(u64, rhs) orelse
        return error.InvalidSampledBarycentricPlan;
    return std.math.add(u64, lhs, encoded) catch
        return error.InvalidSampledBarycentricPlan;
}

fn checkedMul(lhs: anytype, rhs: anytype) !u64 {
    const encoded_lhs = std.math.cast(u64, lhs) orelse
        return error.InvalidSampledBarycentricPlan;
    const encoded_rhs = std.math.cast(u64, rhs) orelse
        return error.InvalidSampledBarycentricPlan;
    return std.math.mul(u64, encoded_lhs, encoded_rhs) catch
        return error.InvalidSampledBarycentricPlan;
}

test "Metal sampled barycentric domain operation count follows exact pow schedule" {
    try std.testing.expectEqual(@as(u64, 64), domainCircleMultiplications(1));
    try std.testing.expectEqual(@as(u64, 129), domainCircleMultiplications(2));
    try std.testing.expectEqual(@as(u64, 261), domainCircleMultiplications(3));
}

test "Metal sampled barycentric execution rejects inverse coverage mutation" {
    var execution = work_profile.SampledBarycentricExecution{
        .point_plan_count = 1,
        .domain_plan_count = 1,
        .evaluation_task_count = 1,
        .weight_value_count = 1_024,
        .dot_product_terms = 1_024,
        .domain_circle_multiplications = domainCircleMultiplications(10),
        .scale_double_count = 9,
        .inverse_tree_block_count = 1,
        .direct_inversion_count = 0,
        .reduction_addition_count = 5 * 255,
        .constant_addition_count = 1,
        .constant_multiplication_count = 1,
        .constant_inversion_count = 1,
    };
    try execution.validate();
    execution.inverse_tree_block_count = 0;
    try std.testing.expectError(error.InvalidCounterGroup, execution.validate());
}

fn exercisePreparedEpoch(allocator: std.mem.Allocator) !void {
    var first_values = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
    };
    var second_values = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(6),
        M31.fromCanonical(7),
        M31.fromCanonical(8),
    };
    var third_values = [_]M31{
        M31.fromCanonical(9),
        M31.fromCanonical(10),
        M31.fromCanonical(11),
        M31.fromCanonical(12),
    };
    const first_columns = [_]@import("stwo_prover_api").ColumnEvaluation{
        .{ .log_size = 2, .values = &first_values },
        .{ .log_size = 2, .values = &second_values },
    };
    const second_columns = [_]@import("stwo_prover_api").ColumnEvaluation{
        .{ .log_size = 2, .values = &third_values },
    };
    var points = [_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(17),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(29),
    };

    var first_indices = std.ArrayList(usize).empty;
    defer first_indices.deinit(allocator);
    try first_indices.appendSlice(allocator, &.{ 0, 1 });
    var second_indices = std.ArrayList(usize).empty;
    defer second_indices.deinit(allocator);
    try second_indices.append(allocator, 0);
    const first_plan = [_]sampled_plan_types.BarycentricEvalPlan{.{
        .log_size = 2,
        .fold_count = 0,
        .raw_points = &points,
        .normalized_points = &points,
        .column_indices = first_indices,
        .next_same_hash = null,
    }};
    const second_plan = [_]sampled_plan_types.BarycentricEvalPlan{.{
        .log_size = 2,
        .fold_count = 0,
        .raw_points = &points,
        .normalized_points = &points,
        .column_indices = second_indices,
        .next_same_hash = null,
    }};
    var first_output_a: [2]QM31 = undefined;
    var first_output_b: [2]QM31 = undefined;
    var second_output: [2]QM31 = undefined;
    var first_outputs = [_][]QM31{ &first_output_a, &first_output_b };
    var second_outputs = [_][]QM31{&second_output};
    const tree_plans = [_]sampled_plan_types.BarycentricEvalTreePlan{
        .{
            .columns = &first_columns,
            .tree_values = &first_outputs,
            .plans = &first_plan,
            .resident_tree = @ptrFromInt(0x1000),
        },
        .{
            .columns = &second_columns,
            .tree_values = &second_outputs,
            .plans = &second_plan,
            .resident_tree = @ptrFromInt(0x2000),
        },
    };

    var prepared = try prepareEpoch(allocator, &tree_plans);
    defer prepared.deinit();
    try std.testing.expectEqual(@as(usize, 2), prepared.point_plans.len);
    try std.testing.expectEqual(@as(usize, 4), prepared.groups.len);
    try std.testing.expectEqual(@as(usize, 6), prepared.columns.len);
    try std.testing.expectEqual(@as(u32, 6), prepared.output_count);
    try std.testing.expectEqual(@as(u64, 2), prepared.execution.point_plan_count);
    try std.testing.expectEqual(@as(u64, 1), prepared.execution.domain_plan_count);
    try std.testing.expectEqual(@as(u64, 6), prepared.execution.evaluation_task_count);
    try std.testing.expectEqual(@as(u64, 8), prepared.execution.weight_value_count);
    try std.testing.expectEqual(@as(u64, 24), prepared.execution.dot_product_terms);
    var output_seen = [_]bool{false} ** 6;
    for (prepared.output_indices) |output_index| {
        try std.testing.expect(output_index < output_seen.len);
        try std.testing.expect(!output_seen[output_index]);
        output_seen[output_index] = true;
    }
    for (output_seen) |seen| try std.testing.expect(seen);
}

test "Metal sampled barycentric planner deduplicates exact cross-tree points" {
    try exercisePreparedEpoch(std.testing.allocator);
}

test "Metal sampled barycentric planner releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exercisePreparedEpoch,
        .{},
    );
}

test "Metal sampled barycentric planner rejects normalized-point mutation" {
    const allocator = std.testing.allocator;
    var values = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
    };
    const columns = [_]@import("stwo_prover_api").ColumnEvaluation{
        .{ .log_size = 2, .values = &values },
    };
    var raw_points = [_]CirclePointQM31{circle.SECURE_FIELD_CIRCLE_GEN.mul(17)};
    var normalized_points = raw_points;
    normalized_points[0] = circle.SECURE_FIELD_CIRCLE_GEN.mul(19);
    var indices = std.ArrayList(usize).empty;
    defer indices.deinit(allocator);
    try indices.append(allocator, 0);
    const plans = [_]sampled_plan_types.BarycentricEvalPlan{.{
        .log_size = 2,
        .fold_count = 0,
        .raw_points = &raw_points,
        .normalized_points = &normalized_points,
        .column_indices = indices,
        .next_same_hash = null,
    }};
    var output: [1]QM31 = undefined;
    var outputs = [_][]QM31{&output};
    const tree_plans = [_]sampled_plan_types.BarycentricEvalTreePlan{.{
        .columns = &columns,
        .tree_values = &outputs,
        .plans = &plans,
        .resident_tree = @ptrFromInt(0x1000),
    }};
    try std.testing.expectError(
        error.InvalidSampledBarycentricPlan,
        prepareEpoch(allocator, &tree_plans),
    );
}

test "Metal sampled barycentric planner rejects a sampled domain point" {
    const allocator = std.testing.allocator;
    var values = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
    };
    const columns = [_]@import("stwo_prover_api").ColumnEvaluation{
        .{ .log_size = 2, .values = &values },
    };
    const domain_point = canonic.CanonicCoset.new(2).circleDomain().at(0);
    var points = [_]CirclePointQM31{.{
        .x = QM31.fromBase(domain_point.x),
        .y = QM31.fromBase(domain_point.y),
    }};
    var indices = std.ArrayList(usize).empty;
    defer indices.deinit(allocator);
    try indices.append(allocator, 0);
    const plans = [_]sampled_plan_types.BarycentricEvalPlan{.{
        .log_size = 2,
        .fold_count = 0,
        .raw_points = &points,
        .normalized_points = &points,
        .column_indices = indices,
        .next_same_hash = null,
    }};
    var output: [1]QM31 = undefined;
    var outputs = [_][]QM31{&output};
    const tree_plans = [_]sampled_plan_types.BarycentricEvalTreePlan{.{
        .columns = &columns,
        .tree_values = &outputs,
        .plans = &plans,
        .resident_tree = @ptrFromInt(0x1000),
    }};
    try std.testing.expectError(
        error.SampledBarycentricPointOnDomain,
        prepareEpoch(allocator, &tree_plans),
    );
}

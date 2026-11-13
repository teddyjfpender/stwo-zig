//! Backend sampled-evaluation dispatch, exact work receipts and per-tree plan ownership.
//! Sampled-value planning and evaluation for committed PCS trees.
//!
//! This module owns coefficient-plan caching, backend batch dispatch,
//! barycentric fallback, parallel scheduling, and coefficient lifetime release.

const std = @import("std");
const work_profile = @import("stwo_prover_api").work_profile;
const circle = @import("stwo_core").circle;
const qm31 = @import("stwo_core").fields.qm31;
const prover_circle = @import("../poly/circle/mod.zig");
const commitment_tree = @import("commitment_tree.zig");
const sampled_work = @import("sampled_value_work.zig");
const coefficient_plan_ops = @import("sampled_coefficient_plans.zig");
const CoefficientEvalPlan = coefficient_plan_ops.CoefficientEvalPlan;
const CoefficientEvalTreePlan = coefficient_plan_ops.CoefficientEvalTreePlan;
const BarycentricEvalPlan = coefficient_plan_ops.BarycentricEvalPlan;
const BarycentricEvalTreePlan = coefficient_plan_ops.BarycentricEvalTreePlan;
const deinitCoefficientEvalPlans = coefficient_plan_ops.deinitCoefficientEvalPlans;
const deinitBarycentricEvalPlans = coefficient_plan_ops.deinitBarycentricEvalPlans;
const getOrCreateCoefficientEvalPlan = coefficient_plan_ops.getOrCreateCoefficientEvalPlan;
const getOrCreateBarycentricEvalPlan = coefficient_plan_ops.getOrCreateBarycentricEvalPlan;
const evaluateCoefficientPlans = coefficient_plan_ops.evaluateCoefficientPlans;

const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;

pub fn evaluateCoefficientTreesWithBackend(
    comptime B: type,
    comptime H: type,
    trees: anytype,
    tree_points_list: [][][]CirclePointQM31,
    out: [][][]QM31,
    allocator: std.mem.Allocator,
    lifting_log_size: u32,
    work_audit: ?*sampled_work.Audit,
) !bool {
    _ = H;
    for (trees, 0..) |tree, tree_index| if (tree.coefficients == null) {
        std.log.debug(
            "backend sampled evaluation unavailable: tree {d} has no coefficients",
            .{tree_index},
        );
        return false;
    };

    if (comptime @hasDecl(B, "evaluateCoefficientTreePlans")) {
        const plan_lists = try allocator.alloc(std.ArrayList(CoefficientEvalPlan), trees.len);
        defer allocator.free(plan_lists);
        var initialized: usize = 0;
        defer for (plan_lists[0..initialized]) |*plans| {
            deinitCoefficientEvalPlans(allocator, plans);
        };

        const tree_plans = try allocator.alloc(CoefficientEvalTreePlan, trees.len);
        defer allocator.free(tree_plans);
        for (trees, tree_points_list, out, 0..) |tree, tree_points, tree_values, tree_index| {
            plan_lists[tree_index] = try buildCoefficientPlansForTree(
                allocator,
                tree.columns,
                tree_points,
                tree.coefficients.?,
                lifting_log_size,
                work_audit,
            );
            initialized += 1;
            tree_plans[tree_index] = .{
                .coefficients = tree.coefficients.?,
                .tree_values = tree_values,
                .plans = plan_lists[tree_index].items,
            };
        }
        if (comptime @hasDecl(B, "evaluateCoefficientTreePlansWithReceipt")) {
            if (work_audit) |audit| {
                const execution = try B.evaluateCoefficientTreePlansWithReceipt(
                    allocator,
                    tree_plans,
                );
                mergeBackendCoefficientExecution(audit, execution, tree_plans);
            } else {
                try B.evaluateCoefficientTreePlans(allocator, tree_plans);
            }
        } else {
            try B.evaluateCoefficientTreePlans(allocator, tree_plans);
            if (work_audit) |audit| audit.complete = false;
        }
        return true;
    }

    for (trees, tree_points_list, out) |tree, tree_points, tree_values| {
        const coefficients = tree.coefficients.?;
        var plans = try buildCoefficientPlansForTree(
            allocator,
            tree.columns,
            tree_points,
            coefficients,
            lifting_log_size,
            work_audit,
        );
        defer deinitCoefficientEvalPlans(allocator, &plans);
        if (comptime @hasDecl(B, "evaluateCoefficientPlansWithReceipt")) {
            if (work_audit) |audit| {
                const execution = try B.evaluateCoefficientPlansWithReceipt(
                    allocator,
                    coefficients,
                    tree_values,
                    plans.items,
                );
                const SingleTreePlan = struct {
                    coefficients: @TypeOf(coefficients),
                    tree_values: @TypeOf(tree_values),
                    plans: @TypeOf(plans.items),
                };
                const tree_plan = [_]SingleTreePlan{.{
                    .coefficients = coefficients,
                    .tree_values = tree_values,
                    .plans = plans.items,
                }};
                mergeBackendCoefficientExecution(audit, execution, &tree_plan);
            } else {
                try B.evaluateCoefficientPlans(
                    allocator,
                    coefficients,
                    tree_values,
                    plans.items,
                );
            }
        } else {
            try B.evaluateCoefficientPlans(
                allocator,
                coefficients,
                tree_values,
                plans.items,
            );
            if (work_audit) |audit| audit.complete = false;
        }
    }
    return true;
}

pub fn evaluateBarycentricTreesWithBackend(
    comptime B: type,
    comptime H: type,
    trees: anytype,
    tree_points_list: [][][]CirclePointQM31,
    out: [][][]QM31,
    allocator: std.mem.Allocator,
    lifting_log_size: u32,
    work_audit: ?*sampled_work.Audit,
) !bool {
    for (trees) |tree| if (tree.coefficients != null) return false;
    // Keep a large resident tree on its device when another tree (commonly a
    // cached preprocessed root) requires host staging. Without separate epochs,
    // the staging slab limit would unnecessarily apply to every resident tree.
    const residency_epochs = comptime @hasDecl(B, "supportsBarycentricResidencyEpochs") and B.supportsBarycentricResidencyEpochs;
    var host_columns = false;
    var resident_count: usize = 0;
    for (trees) |tree| {
        if (B.quotientResidencyHandle(H, tree.commitment) == null) host_columns = true else resident_count += 1;
    }
    if (host_columns) {
        if (comptime @hasDecl(B, "supportsHostBarycentricColumns")) {
            for (trees) |tree| {
                if (residency_epochs and B.quotientResidencyHandle(H, tree.commitment) != null) continue;
                if (!B.supportsHostBarycentricColumns(tree.columns)) return false;
            }
        } else return false;
    }

    const plan_lists = try allocator.alloc(std.ArrayList(BarycentricEvalPlan), trees.len);
    defer allocator.free(plan_lists);
    var initialized: usize = 0;
    defer for (plan_lists[0..initialized]) |*plans| {
        deinitBarycentricEvalPlans(allocator, plans);
    };

    const tree_plans = try allocator.alloc(BarycentricEvalTreePlan, trees.len);
    defer allocator.free(tree_plans);
    for (trees, tree_points_list, out, 0..) |
        tree,
        tree_points,
        tree_values,
        tree_index,
    | {
        const resident_tree = B.quotientResidencyHandle(
            H,
            tree.commitment,
        );
        var plans = std.ArrayList(BarycentricEvalPlan).empty;
        errdefer deinitBarycentricEvalPlans(allocator, &plans);
        var plan_index = std.AutoHashMap(u64, usize).init(allocator);
        defer plan_index.deinit();
        for (tree.columns, tree_points, 0..) |column, points, column_index| {
            if (points.len == 0) continue;
            const plan = try getOrCreateBarycentricEvalPlan(
                allocator,
                &plan_index,
                &plans,
                column.log_size,
                lifting_log_size - column.log_size,
                points,
                work_audit,
            );
            try plan.column_indices.append(allocator, column_index);
        }
        plan_lists[tree_index] = plans;
        initialized += 1;
        tree_plans[tree_index] = .{
            .columns = tree.columns,
            .tree_values = tree_values,
            .plans = plan_lists[tree_index].items,
            .resident_tree = resident_tree,
        };
    }

    if (residency_epochs and host_columns and resident_count != 0) {
        const ordered = try allocator.alloc(BarycentricEvalTreePlan, tree_plans.len);
        defer allocator.free(ordered);
        var device_index: usize = 0;
        var host_index = resident_count;
        for (tree_plans) |tree_plan| {
            if (tree_plan.resident_tree != null) {
                ordered[device_index] = tree_plan;
                device_index += 1;
            } else {
                ordered[host_index] = tree_plan;
                host_index += 1;
            }
        }
        std.debug.assert(device_index == resident_count and host_index == ordered.len);
        try dispatchBarycentricBackend(B, allocator, ordered[0..resident_count], work_audit);
        try dispatchBarycentricBackend(B, allocator, ordered[resident_count..], work_audit);
    } else {
        try dispatchBarycentricBackend(B, allocator, tree_plans, work_audit);
    }
    return true;
}

fn dispatchBarycentricBackend(
    comptime B: type,
    allocator: std.mem.Allocator,
    tree_plans: []const BarycentricEvalTreePlan,
    work_audit: ?*sampled_work.Audit,
) !void {
    if (comptime @hasDecl(B, "evaluateBarycentricTreePlansWithReceipt")) {
        if (work_audit) |audit| {
            const execution = try B.evaluateBarycentricTreePlansWithReceipt(allocator, tree_plans);
            audit.observeBarycentricBackendExecution(execution);
        } else {
            try B.evaluateBarycentricTreePlans(allocator, tree_plans);
        }
    } else {
        try B.evaluateBarycentricTreePlans(allocator, tree_plans);
        if (work_audit) |audit| audit.complete = false;
    }
}

pub fn mergeBackendCoefficientExecution(
    audit: *sampled_work.Audit,
    execution: work_profile.SampledCoefficientExecution,
    tree_plans: anytype,
) void {
    if (!audit.complete) return;
    execution.validate() catch return invalidateSampledAudit(audit);

    var plan_count: u64 = 0;
    var basis_task_count: u64 = 0;
    var evaluation_task_count: u64 = 0;
    var evaluation_coefficient_terms: u64 = 0;
    var basis_multiplications: u64 = 0;
    for (tree_plans) |tree_plan| {
        for (tree_plan.plans) |plan| {
            plan_count = checkedSampledAdd(plan_count, 1) orelse
                return invalidateSampledAudit(audit);
            const point_count = std.math.cast(u64, plan.normalized_points.len) orelse
                return invalidateSampledAudit(audit);
            basis_task_count = checkedSampledAdd(
                basis_task_count,
                point_count,
            ) orelse return invalidateSampledAudit(audit);
            const column_count = std.math.cast(u64, plan.column_indices.items.len) orelse
                return invalidateSampledAudit(audit);
            const plan_evaluations = checkedSampledMul(
                point_count,
                column_count,
            ) orelse return invalidateSampledAudit(audit);
            evaluation_task_count = checkedSampledAdd(
                evaluation_task_count,
                plan_evaluations,
            ) orelse return invalidateSampledAudit(audit);
            const basis_per_point = work_profile.logicalSampledCoefficientBasisMultiplications(
                plan.coeff_log_size,
                execution.basis_threadgroup_width,
            ) catch return invalidateSampledAudit(audit);
            basis_multiplications = checkedSampledAdd(
                basis_multiplications,
                checkedSampledMul(point_count, basis_per_point) orelse
                    return invalidateSampledAudit(audit),
            ) orelse return invalidateSampledAudit(audit);
            for (plan.column_indices.items) |column_index| {
                if (column_index >= tree_plan.coefficients.len)
                    return invalidateSampledAudit(audit);
                const coefficient_count = std.math.cast(
                    u64,
                    tree_plan.coefficients[column_index].coefficients().len,
                ) orelse return invalidateSampledAudit(audit);
                evaluation_coefficient_terms = checkedSampledAdd(
                    evaluation_coefficient_terms,
                    checkedSampledMul(point_count, coefficient_count) orelse
                        return invalidateSampledAudit(audit),
                ) orelse return invalidateSampledAudit(audit);
            }
        }
    }

    if (execution.plan_count != plan_count or
        execution.basis_task_count != basis_task_count or
        execution.evaluation_task_count != evaluation_task_count or
        execution.evaluation_coefficient_terms != evaluation_coefficient_terms or
        execution.basis_multiplications != basis_multiplications)
    {
        return invalidateSampledAudit(audit);
    }
    const device_work = execution.exactWork() catch
        return invalidateSampledAudit(audit);
    audit.merge(.{ .counters = device_work });
}

fn checkedSampledAdd(lhs: u64, rhs: u64) ?u64 {
    return std.math.add(u64, lhs, rhs) catch null;
}

fn checkedSampledMul(lhs: u64, rhs: u64) ?u64 {
    return std.math.mul(u64, lhs, rhs) catch null;
}

fn invalidateSampledAudit(audit: *sampled_work.Audit) void {
    audit.complete = false;
}

fn buildCoefficientPlansForTree(
    allocator: std.mem.Allocator,
    columns: []const commitment_tree.ColumnEvaluation,
    tree_points: [][]CirclePointQM31,
    coefficients: []const prover_circle.CircleCoefficients,
    lifting_log_size: u32,
    work_audit: ?*sampled_work.Audit,
) !std.ArrayList(CoefficientEvalPlan) {
    var plans = std.ArrayList(CoefficientEvalPlan).empty;
    errdefer deinitCoefficientEvalPlans(allocator, &plans);
    var plan_index = std.AutoHashMap(u64, usize).init(allocator);
    defer plan_index.deinit();
    for (columns, tree_points, 0..) |column, points, column_idx| {
        if (points.len == 0) continue;
        const plan = try getOrCreateCoefficientEvalPlan(
            allocator,
            &plan_index,
            &plans,
            coefficients[column_idx].logSize(),
            lifting_log_size - column.log_size,
            points,
            work_audit,
        );
        try plan.column_indices.append(allocator, column_idx);
    }
    return plans;
}

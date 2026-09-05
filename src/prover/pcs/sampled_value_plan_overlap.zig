//! Exact process-local audit of barycentric weight reuse across PCS trees.
//!
//! The current fallback builds weight vectors independently per committed
//! tree. This audit derives both that exact execution count and the smaller
//! collision-safe key set `(domain log size, normalized OODS point)` that a
//! proof-local shared owner could construct once. It is telemetry only: no
//! digest or receipt produced here participates in proof admission.

const std = @import("std");
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const point_evaluation = @import("../poly/circle/point_evaluation.zig");
const plan_ops = @import("sampled_coefficient_plans.zig");

const M31 = m31.M31;
const CirclePointQM31 = circle.CirclePointQM31;

pub const MAX_TREE_COUNT: usize = 64;

pub const Receipt = struct {
    tree_count: u32,
    barycentric_tree_count: u32,
    current_plan_count: u64,
    current_weight_vector_count: u64,
    per_tree_unique_weight_vector_count: u64,
    global_unique_weight_vector_count: u64,
    within_tree_duplicate_weight_vector_count: u64,
    cross_tree_reusable_weight_vector_count: u64,
    total_reusable_weight_vector_count: u64,
    per_tree_current_weight_vector_count: []u64,
    per_tree_unique_weight_vector_count_values: []u64,
    pairwise_unique_key_overlap: []u64,

    pub fn validate(self: Receipt) !void {
        const tree_count: usize = @intCast(self.tree_count);
        if (tree_count > MAX_TREE_COUNT or
            self.barycentric_tree_count > self.tree_count or
            self.per_tree_current_weight_vector_count.len != tree_count or
            self.per_tree_unique_weight_vector_count_values.len != tree_count or
            self.pairwise_unique_key_overlap.len !=
                std.math.mul(usize, tree_count, tree_count) catch
                    return error.InvalidSampledValuePlanOverlapReceipt)
        {
            return error.InvalidSampledValuePlanOverlapReceipt;
        }

        var current_sum: u64 = 0;
        var unique_sum: u64 = 0;
        var active_trees: u32 = 0;
        for (
            self.per_tree_current_weight_vector_count,
            self.per_tree_unique_weight_vector_count_values,
            0..,
        ) |current, unique, tree_index| {
            if (unique > current) return error.InvalidSampledValuePlanOverlapReceipt;
            current_sum = std.math.add(u64, current_sum, current) catch
                return error.InvalidSampledValuePlanOverlapReceipt;
            unique_sum = std.math.add(u64, unique_sum, unique) catch
                return error.InvalidSampledValuePlanOverlapReceipt;
            if (current != 0) active_trees += 1;
            if (self.pairwise_unique_key_overlap[
                tree_index * tree_count + tree_index
            ] != unique) return error.InvalidSampledValuePlanOverlapReceipt;
            for (0..tree_count) |other| {
                if (self.pairwise_unique_key_overlap[
                    tree_index * tree_count + other
                ] != self.pairwise_unique_key_overlap[
                    other * tree_count + tree_index
                ]) return error.InvalidSampledValuePlanOverlapReceipt;
            }
        }
        if (active_trees != self.barycentric_tree_count or
            current_sum != self.current_weight_vector_count or
            unique_sum != self.per_tree_unique_weight_vector_count or
            self.global_unique_weight_vector_count > unique_sum or
            self.within_tree_duplicate_weight_vector_count !=
                current_sum - unique_sum or
            self.cross_tree_reusable_weight_vector_count !=
                unique_sum - self.global_unique_weight_vector_count or
            self.total_reusable_weight_vector_count !=
                current_sum - self.global_unique_weight_vector_count)
        {
            return error.InvalidSampledValuePlanOverlapReceipt;
        }
    }

    pub fn pairOverlap(
        self: Receipt,
        left_tree: usize,
        right_tree: usize,
    ) !u64 {
        const tree_count: usize = @intCast(self.tree_count);
        if (left_tree >= tree_count or right_tree >= tree_count)
            return error.InvalidSampledValuePlanOverlapReceipt;
        return self.pairwise_unique_key_overlap[
            left_tree * tree_count + right_tree
        ];
    }
};

pub const OwnedReceipt = struct {
    allocator: std.mem.Allocator,
    value: Receipt,

    pub fn deinit(self: *OwnedReceipt) void {
        self.allocator.free(self.value.pairwise_unique_key_overlap);
        self.allocator.free(
            self.value.per_tree_unique_weight_vector_count_values,
        );
        self.allocator.free(self.value.per_tree_current_weight_vector_count);
        self.* = undefined;
    }
};

const WeightKey = struct {
    log_size: u32,
    point: CirclePointQM31,
    tree_mask: u64,
    next_same_hash: ?usize,
};

/// Derives an exact receipt from the same tree/column/point inputs consumed by
/// `sampled_values.evaluateAndRelease`. Coefficient-retained trees are not part
/// of the barycentric weight cache and are deliberately excluded.
pub fn derive(
    allocator: std.mem.Allocator,
    trees: anytype,
    sampled_points: [][][]CirclePointQM31,
    lifting_log_size: u32,
) !OwnedReceipt {
    if (trees.len != sampled_points.len or trees.len > MAX_TREE_COUNT)
        return error.InvalidSampledValuePlanOverlapInput;
    const tree_count = trees.len;
    const pair_count = std.math.mul(usize, tree_count, tree_count) catch
        return error.InvalidSampledValuePlanOverlapInput;
    const current_by_tree = try allocator.alloc(u64, tree_count);
    errdefer allocator.free(current_by_tree);
    @memset(current_by_tree, 0);
    const unique_by_tree = try allocator.alloc(u64, tree_count);
    errdefer allocator.free(unique_by_tree);
    @memset(unique_by_tree, 0);
    const pairwise = try allocator.alloc(u64, pair_count);
    errdefer allocator.free(pairwise);
    @memset(pairwise, 0);

    var key_index = std.AutoHashMap(u64, usize).init(allocator);
    defer key_index.deinit();
    var keys = std.ArrayList(WeightKey).empty;
    defer keys.deinit(allocator);

    var current_plan_count: u64 = 0;
    var barycentric_tree_count: u32 = 0;
    for (trees, sampled_points, 0..) |tree, tree_points, tree_index| {
        if (tree.columns.len != tree_points.len)
            return error.InvalidSampledValuePlanOverlapInput;
        if (tree.coefficients != null) continue;

        var plan_index = std.AutoHashMap(u64, usize).init(allocator);
        defer plan_index.deinit();
        var plans = std.ArrayList(plan_ops.BarycentricEvalPlan).empty;
        defer plan_ops.deinitBarycentricEvalPlans(allocator, &plans);
        for (tree.columns, tree_points) |column, points| {
            if (points.len == 0) continue;
            if (column.log_size > lifting_log_size)
                return error.InvalidSampledValuePlanOverlapInput;
            _ = try plan_ops.getOrCreateBarycentricEvalPlan(
                allocator,
                &plan_index,
                &plans,
                column.log_size,
                lifting_log_size - column.log_size,
                points,
                null,
            );
        }
        if (plans.items.len == 0) continue;
        barycentric_tree_count += 1;
        current_plan_count = try checkedAdd(
            current_plan_count,
            plans.items.len,
        );
        for (plans.items) |plan| {
            current_by_tree[tree_index] = try checkedAdd(
                current_by_tree[tree_index],
                plan.normalized_points.len,
            );
            for (plan.normalized_points) |point| {
                const key_hash = hashWeightKey(plan.log_size, point);
                var key_at = key_index.get(key_hash);
                var found: ?usize = null;
                while (key_at) |index| {
                    const key = keys.items[index];
                    if (key.log_size == plan.log_size and
                        key.point.eql(point))
                    {
                        found = index;
                        break;
                    }
                    key_at = key.next_same_hash;
                }

                const index = found orelse blk: {
                    try keys.append(allocator, .{
                        .log_size = plan.log_size,
                        .point = point,
                        .tree_mask = 0,
                        .next_same_hash = key_index.get(key_hash),
                    });
                    const new_index = keys.items.len - 1;
                    try key_index.put(key_hash, new_index);
                    break :blk new_index;
                };
                const tree_bit = @as(u64, 1) << @intCast(tree_index);
                if ((keys.items[index].tree_mask & tree_bit) != 0) continue;

                unique_by_tree[tree_index] = try checkedAdd(
                    unique_by_tree[tree_index],
                    1,
                );
                pairwise[tree_index * tree_count + tree_index] =
                    unique_by_tree[tree_index];
                var prior_mask = keys.items[index].tree_mask;
                while (prior_mask != 0) {
                    const prior_tree: usize = @intCast(@ctz(prior_mask));
                    pairwise[tree_index * tree_count + prior_tree] =
                        try checkedAdd(
                            pairwise[tree_index * tree_count + prior_tree],
                            1,
                        );
                    pairwise[prior_tree * tree_count + tree_index] =
                        pairwise[tree_index * tree_count + prior_tree];
                    prior_mask &= prior_mask - 1;
                }
                keys.items[index].tree_mask |= tree_bit;
            }
        }
    }

    var current_total: u64 = 0;
    var per_tree_unique_total: u64 = 0;
    for (current_by_tree, unique_by_tree) |current, unique| {
        current_total = try checkedAdd(current_total, current);
        per_tree_unique_total = try checkedAdd(per_tree_unique_total, unique);
    }
    const global_unique = std.math.cast(u64, keys.items.len) orelse
        return error.InvalidSampledValuePlanOverlapInput;
    var result = OwnedReceipt{
        .allocator = allocator,
        .value = .{
            .tree_count = std.math.cast(u32, tree_count) orelse
                return error.InvalidSampledValuePlanOverlapInput,
            .barycentric_tree_count = barycentric_tree_count,
            .current_plan_count = current_plan_count,
            .current_weight_vector_count = current_total,
            .per_tree_unique_weight_vector_count = per_tree_unique_total,
            .global_unique_weight_vector_count = global_unique,
            .within_tree_duplicate_weight_vector_count = current_total - per_tree_unique_total,
            .cross_tree_reusable_weight_vector_count = per_tree_unique_total - global_unique,
            .total_reusable_weight_vector_count = current_total - global_unique,
            .per_tree_current_weight_vector_count = current_by_tree,
            .per_tree_unique_weight_vector_count_values = unique_by_tree,
            .pairwise_unique_key_overlap = pairwise,
        },
    };
    errdefer result.deinit();
    try result.value.validate();
    return result;
}

pub fn print(receipt: Receipt, derivation_ns: u64) void {
    std.debug.print(
        "SAMPLED_VALUE_PLAN_OVERLAP tree_count={} barycentric_trees={} " ++
            "current_plans={} current_weights={} per_tree_unique={} " ++
            "global_unique={} within_tree_reuse={} cross_tree_reuse={} " ++
            "total_reuse={} derivation_ns={}\n",
        .{
            receipt.tree_count,
            receipt.barycentric_tree_count,
            receipt.current_plan_count,
            receipt.current_weight_vector_count,
            receipt.per_tree_unique_weight_vector_count,
            receipt.global_unique_weight_vector_count,
            receipt.within_tree_duplicate_weight_vector_count,
            receipt.cross_tree_reusable_weight_vector_count,
            receipt.total_reusable_weight_vector_count,
            derivation_ns,
        },
    );
    const tree_count: usize = @intCast(receipt.tree_count);
    for (0..tree_count) |tree| std.debug.print(
        "SAMPLED_VALUE_PLAN_TREE tree={} current_weights={} unique_weights={}\n",
        .{
            tree,
            receipt.per_tree_current_weight_vector_count[tree],
            receipt.per_tree_unique_weight_vector_count_values[tree],
        },
    );
    for (0..tree_count) |left| for (left + 1..tree_count) |right| {
        std.debug.print(
            "SAMPLED_VALUE_PLAN_PAIR left={} right={} shared_keys={}\n",
            .{
                left,
                right,
                receipt.pairwise_unique_key_overlap[left * tree_count + right],
            },
        );
    };
}

fn hashWeightKey(log_size: u32, point: CirclePointQM31) u64 {
    var hasher = std.hash.Wyhash.init(0);
    var log_bytes: [@sizeOf(u32)]u8 = undefined;
    std.mem.writeInt(u32, &log_bytes, log_size, .little);
    hasher.update(&log_bytes);
    inline for (.{ point.x, point.y }) |coordinate| {
        inline for (coordinate.toM31Array()) |limb| {
            const bytes = limb.toBytesLe();
            hasher.update(&bytes);
        }
    }
    return hasher.final();
}

fn checkedAdd(value: u64, increment: anytype) !u64 {
    const encoded = std.math.cast(u64, increment) orelse
        return error.InvalidSampledValuePlanOverlapInput;
    return std.math.add(u64, value, encoded) catch
        error.InvalidSampledValuePlanOverlapInput;
}

test "sampled-value overlap: exact normalized keys expose within and cross-tree reuse" {
    const allocator = std.testing.allocator;
    const MockColumn = struct { log_size: u32 };
    const MockTree = struct {
        columns: []const MockColumn,
        coefficients: ?[]const u8 = null,
    };
    const p1 = circle.SECURE_FIELD_CIRCLE_GEN.mul(17);
    const p2 = circle.SECURE_FIELD_CIRCLE_GEN.mul(23);
    const p3 = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    const points_12 = [_]CirclePointQM31{ p1, p2 };
    const points_13 = [_]CirclePointQM31{ p1, p3 };
    const points_1 = [_]CirclePointQM31{p1};
    const columns_0 = [_]MockColumn{ .{ .log_size = 6 }, .{ .log_size = 6 } };
    const columns_1 = [_]MockColumn{.{ .log_size = 6 }};
    const columns_2 = [_]MockColumn{ .{ .log_size = 6 }, .{ .log_size = 6 } };
    const trees = [_]MockTree{
        .{ .columns = &columns_0 },
        .{ .columns = &columns_1 },
        .{ .columns = &columns_2 },
    };
    var tree_0_points = [_][]CirclePointQM31{
        @constCast(&points_12),
        @constCast(&points_12),
    };
    var tree_1_points = [_][]CirclePointQM31{@constCast(&points_13)};
    var tree_2_points = [_][]CirclePointQM31{
        @constCast(&points_12),
        @constCast(&points_1),
    };
    var all_points = [_][][]CirclePointQM31{
        &tree_0_points,
        &tree_1_points,
        &tree_2_points,
    };

    var receipt = try derive(allocator, &trees, &all_points, 6);
    defer receipt.deinit();
    try std.testing.expectEqual(@as(u64, 3), receipt.value.current_plan_count);
    try std.testing.expectEqual(@as(u64, 7), receipt.value.current_weight_vector_count);
    try std.testing.expectEqual(@as(u64, 6), receipt.value.per_tree_unique_weight_vector_count);
    try std.testing.expectEqual(@as(u64, 3), receipt.value.global_unique_weight_vector_count);
    try std.testing.expectEqual(@as(u64, 1), receipt.value.within_tree_duplicate_weight_vector_count);
    try std.testing.expectEqual(@as(u64, 3), receipt.value.cross_tree_reusable_weight_vector_count);
    try std.testing.expectEqual(@as(u64, 4), receipt.value.total_reusable_weight_vector_count);
    try std.testing.expectEqual(@as(u64, 1), try receipt.value.pairOverlap(0, 1));
    try std.testing.expectEqual(@as(u64, 2), try receipt.value.pairOverlap(0, 2));
    try std.testing.expectEqual(@as(u64, 1), try receipt.value.pairOverlap(1, 2));
}

fn deriveUnderAllocationFailure(allocator: std.mem.Allocator) !void {
    const MockColumn = struct { log_size: u32 };
    const MockTree = struct {
        columns: []const MockColumn,
        coefficients: ?[]const u8 = null,
    };
    const columns = [_]MockColumn{.{ .log_size = 4 }};
    const trees = [_]MockTree{.{ .columns = &columns }};
    var points = [_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(11),
    };
    var tree_points = [_][]CirclePointQM31{&points};
    var all_points = [_][][]CirclePointQM31{&tree_points};
    var receipt = try derive(allocator, &trees, &all_points, 4);
    defer receipt.deinit();
}

test "sampled-value overlap: allocation failures retain one owner" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        deriveUnderAllocationFailure,
        .{},
    );
}

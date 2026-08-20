const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const quotients = @import("stwo_core").pcs.quotients;
const pcs_utils = @import("stwo_core").pcs.utils;
const column_geometry = @import("quotient_column_geometry.zig");
const execution = @import("quotients/execution.zig");
const lazy_provider = @import("quotients/lazy_provider.zig");
const planning = @import("quotients/planning.zig");
const secure_column = @import("../secure_column.zig");
const work_profile = @import("stwo_prover_api").work_profile;

pub const work_profile_geometry = @import("quotient_work_profile.zig");

const circle_mod = @import("stwo_core").circle;
const CirclePointQM31 = circle_mod.CirclePointQM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;
const TreeVec = pcs_utils.TreeVec;
const PointSample = quotients.PointSample;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;
/// Number of rows processed per chunk in lazy quotient evaluation.
/// Chosen to amortize function-call overhead while keeping chunk memory bounded.
pub const LAZY_QUOTIENT_CHUNK_SIZE = lazy_provider.LAZY_QUOTIENT_CHUNK_SIZE;

pub const QuotientOpsError = column_geometry.QuotientOpsError;

/// One committed trace/evaluation column.
///
/// Invariants:
/// - `values.len == 2^log_size`.
/// - `values` are in bit-reversed order, matching Stwo prover conventions.
pub const ColumnEvaluation = column_geometry.ColumnEvaluation;

pub const InputMode = lazy_provider.InputMode;

/// Lazy quotient provider for fused quotient computation and Merkle commitment.
pub const LazyQuotientProvider = lazy_provider.LazyQuotientProvider;

/// Computes FRI quotient evaluations for all points in the lifted domain.
///
/// Inputs:
/// - `columns`: per-tree, per-column evaluations and original log sizes.
/// - `sampled_points`: per-tree, per-column OODS sample points; shape must match `columns`.
/// - `sampled_values`: per-tree, per-column OODS sample values; shape must match `columns`.
/// - `random_coeff`: random challenge used for linear combination.
/// - `lifting_log_size`: maximal lifted domain size.
/// - `log_blowup_factor`: included for API parity (not used directly here).
///
/// Output:
/// - secure-field quotient evaluation values over all lifted-domain positions.
pub fn computeFriQuotients(
    allocator: std.mem.Allocator,
    columns: TreeVec([]const ColumnEvaluation),
    sampled_points: TreeVec([][]CirclePointQM31),
    sampled_values: TreeVec([][]QM31),
    random_coeff: QM31,
    lifting_log_size: u32,
    log_blowup_factor: u32,
) !SecureColumnByCoords {
    _ = log_blowup_factor;
    return computeFriQuotientsWithStrategy(
        allocator,
        columns,
        sampled_points,
        sampled_values,
        random_coeff,
        lifting_log_size,
        null,
    );
}

fn computeFriQuotientsWithStrategy(
    allocator: std.mem.Allocator,
    columns: TreeVec([]const ColumnEvaluation),
    sampled_points: TreeVec([][]CirclePointQM31),
    sampled_values: TreeVec([][]QM31),
    random_coeff: QM31,
    lifting_log_size: u32,
    forced_strategy: ?planning.ConstructionStrategy,
) !SecureColumnByCoords {
    return execution.compute(
        allocator,
        columns,
        sampled_points,
        sampled_values,
        random_coeff,
        lifting_log_size,
        forced_strategy,
    );
}

const SplitPointSamples = struct {
    points: TreeVec([][]CirclePointQM31),
    values: TreeVec([][]QM31),

    fn deinit(self: *SplitPointSamples, allocator: std.mem.Allocator) void {
        self.points.deinitDeep(allocator);
        self.values.deinitDeep(allocator);
        self.* = undefined;
    }
};

fn splitPointSamplesForTest(
    allocator: std.mem.Allocator,
    samples: TreeVec([][]PointSample),
) !SplitPointSamples {
    const point_trees = try allocator.alloc([][]CirclePointQM31, samples.items.len);
    errdefer allocator.free(point_trees);
    const value_trees = try allocator.alloc([][]QM31, samples.items.len);
    errdefer allocator.free(value_trees);

    var initialized_trees: usize = 0;
    errdefer {
        for (point_trees[0..initialized_trees]) |tree| {
            for (tree) |column| allocator.free(column);
            allocator.free(tree);
        }
        for (value_trees[0..initialized_trees]) |tree| {
            for (tree) |column| allocator.free(column);
            allocator.free(tree);
        }
    }

    for (samples.items, 0..) |tree, tree_idx| {
        point_trees[tree_idx] = try allocator.alloc([]CirclePointQM31, tree.len);
        value_trees[tree_idx] = try allocator.alloc([]QM31, tree.len);
        initialized_trees += 1;

        var initialized_cols: usize = 0;
        errdefer {
            for (point_trees[tree_idx][0..initialized_cols]) |column| allocator.free(column);
            allocator.free(point_trees[tree_idx]);
            for (value_trees[tree_idx][0..initialized_cols]) |column| allocator.free(column);
            allocator.free(value_trees[tree_idx]);
        }

        for (tree, 0..) |column, col_idx| {
            const points = try allocator.alloc(CirclePointQM31, column.len);
            const values = try allocator.alloc(QM31, column.len);
            point_trees[tree_idx][col_idx] = points;
            value_trees[tree_idx][col_idx] = values;
            initialized_cols += 1;

            for (column, 0..) |sample, sample_idx| {
                points[sample_idx] = sample.point;
                values[sample_idx] = sample.value;
            }
        }
    }

    return .{
        .points = TreeVec([][]CirclePointQM31).initOwned(point_trees),
        .values = TreeVec([][]QM31).initOwned(value_trees),
    };
}

fn borrowColumnsForTest(
    allocator: std.mem.Allocator,
    columns: TreeVec([]ColumnEvaluation),
) !TreeVec([]const ColumnEvaluation) {
    const out = try allocator.alloc([]const ColumnEvaluation, columns.items.len);
    errdefer allocator.free(out);
    for (columns.items, 0..) |tree_columns, i| out[i] = tree_columns;
    return TreeVec([]const ColumnEvaluation).initOwned(out);
}

fn checkLazyProviderAllocationFailureCleanup(
    allocator: std.mem.Allocator,
    columns: TreeVec([]const ColumnEvaluation),
    sampled_points: TreeVec([][]CirclePointQM31),
    sampled_values: TreeVec([][]QM31),
) !void {
    var provider = try LazyQuotientProvider.initWithMode(
        allocator,
        columns,
        sampled_points,
        sampled_values,
        QM31.fromU32Unchecked(3, 0, 1, 0),
        13,
        .bounded_cpu,
    );
    defer provider.deinit(allocator);
}

test "prover pcs bounded quotient provider releases partial state on allocation failure" {
    const column_values = [_]M31{M31.one()} ** (1 << 13);
    var tree_columns = [_]ColumnEvaluation{.{
        .log_size = 13,
        .values = column_values[0..],
    }};
    var column_trees = [_][]const ColumnEvaluation{tree_columns[0..]};
    const columns = TreeVec([]const ColumnEvaluation).initOwned(column_trees[0..]);

    var column_points = [_]CirclePointQM31{circle_mod.SECURE_FIELD_CIRCLE_GEN.mul(7)};
    var tree_points = [_][]CirclePointQM31{column_points[0..]};
    var point_trees = [_][][]CirclePointQM31{tree_points[0..]};
    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(point_trees[0..]);

    var column_samples = [_]QM31{QM31.fromU32Unchecked(9, 10, 11, 12)};
    var tree_samples = [_][]QM31{column_samples[0..]};
    var sample_trees = [_][][]QM31{tree_samples[0..]};
    const sampled_values = TreeVec([][]QM31).initOwned(sample_trees[0..]);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkLazyProviderAllocationFailureCleanup,
        .{ columns, sampled_points, sampled_values },
    );
}

test "prover pcs quotient ops: compute fri quotients matches direct fri answers for legacy point-sample fixtures" {
    const alloc = std.testing.allocator;
    const lifting_log_size: u32 = 5;
    const domain_size = @as(usize, 1) << @intCast(lifting_log_size);

    const col0 = try alloc.alloc(M31, domain_size);
    defer alloc.free(col0);
    for (col0, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(i + 1));

    const col1_log_size: u32 = 3;
    const col1 = try alloc.alloc(M31, @as(usize, 1) << @intCast(col1_log_size));
    defer alloc.free(col1);
    for (col1, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(101 + i));

    const tree_columns = try alloc.dupe(ColumnEvaluation, &[_]ColumnEvaluation{
        .{ .log_size = lifting_log_size, .values = col0 },
        .{ .log_size = col1_log_size, .values = col1 },
    });
    var columns = TreeVec([]ColumnEvaluation).initOwned(
        try alloc.dupe([]ColumnEvaluation, &[_][]ColumnEvaluation{tree_columns}),
    );
    defer columns.deinitDeep(alloc);

    const point0 = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(7);
    const point1 = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(19);

    const col0_samples = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point0, .value = QM31.fromU32Unchecked(1, 2, 3, 4) },
    });
    const col1_samples = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point0, .value = QM31.fromU32Unchecked(5, 6, 7, 8) },
        .{ .point = point1, .value = QM31.fromU32Unchecked(9, 10, 11, 12) },
    });
    const tree_samples = try alloc.dupe([]PointSample, &[_][]PointSample{ col0_samples, col1_samples });
    var samples = TreeVec([][]PointSample).initOwned(
        try alloc.dupe([][]PointSample, &[_][][]PointSample{tree_samples}),
    );
    defer samples.deinitDeep(alloc);
    var split_samples = try splitPointSamplesForTest(alloc, samples);
    defer split_samples.deinit(alloc);
    var columns_borrowed = try borrowColumnsForTest(alloc, columns);
    defer columns_borrowed.deinit(alloc);

    const alpha = QM31.fromU32Unchecked(3, 0, 1, 0);
    var quot_col = try computeFriQuotients(
        alloc,
        columns_borrowed,
        split_samples.points,
        split_samples.values,
        alpha,
        lifting_log_size,
        1,
    );
    defer quot_col.deinit(alloc);

    var col_sizes = TreeVec([]u32).initOwned(
        try alloc.dupe([]u32, &[_][]u32{try alloc.dupe(u32, &[_]u32{ lifting_log_size, col1_log_size })}),
    );
    defer col_sizes.deinitDeep(alloc);

    const q0 = try alloc.dupe(M31, col0);

    const q1 = try alloc.alloc(M31, domain_size);
    const shift: u32 = lifting_log_size - col1_log_size;
    const shift_amt: std.math.Log2Int(usize) = @intCast(shift + 1);
    for (0..domain_size) |position| {
        const idx = ((position >> shift_amt) << 1) + (position & 1);
        q1[position] = col1[idx];
    }

    var queried_values = TreeVec([][]M31).initOwned(
        try alloc.dupe([][]M31, &[_][][]M31{try alloc.dupe([]M31, &[_][]M31{ q0, q1 })}),
    );
    defer queried_values.deinitDeep(alloc);

    const query_positions = try alloc.alloc(usize, domain_size);
    defer alloc.free(query_positions);
    for (query_positions, 0..) |*position, i| position.* = i;

    const expected = try quotients.friAnswers(
        alloc,
        col_sizes,
        split_samples.points,
        split_samples.values,
        alpha,
        query_positions,
        queried_values,
        lifting_log_size,
    );
    defer alloc.free(expected);

    const got = try quot_col.toVec(alloc);
    defer alloc.free(got);

    try std.testing.expectEqual(expected.len, got.len);
    for (expected, got) |lhs, rhs| {
        try std.testing.expect(lhs.eql(rhs));
    }
}

test "prover pcs quotient ops: strategy switches to streaming for medium-wide lifted workloads" {
    try std.testing.expectEqual(
        planning.ConstructionStrategy.materialized,
        planning.chooseConstructionStrategy(256, 2048),
    );
    try std.testing.expectEqual(
        planning.ConstructionStrategy.streaming,
        planning.chooseConstructionStrategy(1500, 4096),
    );
    try std.testing.expectEqual(
        planning.ConstructionStrategy.streaming,
        planning.chooseConstructionStrategy(1400, 8192),
    );
}

test "prover pcs quotient ops: forced materialized and streaming strategies match with sparse active columns" {
    const alloc = std.testing.allocator;
    const lifting_log_size: u32 = 6;
    const domain_size = @as(usize, 1) << @intCast(lifting_log_size);

    const col0 = try alloc.alloc(M31, domain_size);
    defer alloc.free(col0);
    for (col0, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(i + 3));

    const col1_log_size: u32 = 4;
    const col1 = try alloc.alloc(M31, @as(usize, 1) << @intCast(col1_log_size));
    defer alloc.free(col1);
    for (col1, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(101 + i));

    const col2 = try alloc.alloc(M31, domain_size);
    defer alloc.free(col2);
    for (col2, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(205 + i));

    const tree_columns = try alloc.dupe(ColumnEvaluation, &[_]ColumnEvaluation{
        .{ .log_size = lifting_log_size, .values = col0 },
        .{ .log_size = col1_log_size, .values = col1 },
        .{ .log_size = lifting_log_size, .values = col2 },
    });
    var columns = TreeVec([]ColumnEvaluation).initOwned(
        try alloc.dupe([]ColumnEvaluation, &[_][]ColumnEvaluation{tree_columns}),
    );
    defer columns.deinitDeep(alloc);
    var columns_borrowed = try borrowColumnsForTest(alloc, columns);
    defer columns_borrowed.deinit(alloc);

    const point0 = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(7);
    const point1 = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(13);

    const col0_samples = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point0, .value = QM31.fromU32Unchecked(1, 2, 3, 4) },
    });
    const col1_samples = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point0, .value = QM31.fromU32Unchecked(5, 6, 7, 8) },
        .{ .point = point1, .value = QM31.fromU32Unchecked(9, 10, 11, 12) },
    });
    const col2_samples = try alloc.alloc(PointSample, 0);
    const tree_samples = try alloc.dupe([]PointSample, &[_][]PointSample{
        col0_samples,
        col1_samples,
        col2_samples,
    });
    var samples = TreeVec([][]PointSample).initOwned(
        try alloc.dupe([][]PointSample, &[_][][]PointSample{tree_samples}),
    );
    defer samples.deinitDeep(alloc);
    var split_samples = try splitPointSamplesForTest(alloc, samples);
    defer split_samples.deinit(alloc);

    const alpha = QM31.fromU32Unchecked(3, 0, 1, 0);
    var materialized = try computeFriQuotientsWithStrategy(
        alloc,
        columns_borrowed,
        split_samples.points,
        split_samples.values,
        alpha,
        lifting_log_size,
        .materialized,
    );
    defer materialized.deinit(alloc);
    var streaming = try computeFriQuotientsWithStrategy(
        alloc,
        columns_borrowed,
        split_samples.points,
        split_samples.values,
        alpha,
        lifting_log_size,
        .streaming,
    );
    defer streaming.deinit(alloc);

    const materialized_values = try materialized.toVec(alloc);
    defer alloc.free(materialized_values);
    const streaming_values = try streaming.toVec(alloc);
    defer alloc.free(streaming_values);

    try std.testing.expectEqual(materialized_values.len, streaming_values.len);
    for (materialized_values, streaming_values) |lhs, rhs| {
        try std.testing.expect(lhs.eql(rhs));
    }
}

test "prover pcs quotient ops: rejects invalid column length" {
    const alloc = std.testing.allocator;

    const bad_column = [_]M31{ M31.one(), M31.one(), M31.one() };
    const tree_columns = try alloc.dupe(ColumnEvaluation, &[_]ColumnEvaluation{
        .{ .log_size = 2, .values = bad_column[0..] },
    });
    var columns = TreeVec([]ColumnEvaluation).initOwned(
        try alloc.dupe([]ColumnEvaluation, &[_][]ColumnEvaluation{tree_columns}),
    );
    defer columns.deinitDeep(alloc);

    const sample_col = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN, .value = QM31.one() },
    });
    const sample_tree = try alloc.dupe([]PointSample, &[_][]PointSample{sample_col});
    var samples = TreeVec([][]PointSample).initOwned(
        try alloc.dupe([][]PointSample, &[_][][]PointSample{sample_tree}),
    );
    defer samples.deinitDeep(alloc);
    var split_samples = try splitPointSamplesForTest(alloc, samples);
    defer split_samples.deinit(alloc);
    var columns_borrowed = try borrowColumnsForTest(alloc, columns);
    defer columns_borrowed.deinit(alloc);

    try std.testing.expectError(
        QuotientOpsError.InvalidColumnLength,
        computeFriQuotients(
            alloc,
            columns_borrowed,
            split_samples.points,
            split_samples.values,
            QM31.one(),
            2,
            1,
        ),
    );
}

test "prover pcs quotient ops: rejects column log size above lifting" {
    const alloc = std.testing.allocator;

    const column = [_]M31{ M31.one(), M31.one(), M31.one(), M31.one() };
    const tree_columns = try alloc.dupe(ColumnEvaluation, &[_]ColumnEvaluation{
        .{ .log_size = 2, .values = column[0..] },
    });
    var columns = TreeVec([]ColumnEvaluation).initOwned(
        try alloc.dupe([]ColumnEvaluation, &[_][]ColumnEvaluation{tree_columns}),
    );
    defer columns.deinitDeep(alloc);

    const sample_col = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN, .value = QM31.one() },
    });
    const sample_tree = try alloc.dupe([]PointSample, &[_][]PointSample{sample_col});
    var samples = TreeVec([][]PointSample).initOwned(
        try alloc.dupe([][]PointSample, &[_][][]PointSample{sample_tree}),
    );
    defer samples.deinitDeep(alloc);
    var split_samples = try splitPointSamplesForTest(alloc, samples);
    defer split_samples.deinit(alloc);
    var columns_borrowed = try borrowColumnsForTest(alloc, columns);
    defer columns_borrowed.deinit(alloc);

    try std.testing.expectError(
        QuotientOpsError.InvalidColumnLogSize,
        computeFriQuotients(
            alloc,
            columns_borrowed,
            split_samples.points,
            split_samples.values,
            QM31.one(),
            1,
            1,
        ),
    );
}

test "prover pcs quotient ops: rejects shape mismatch" {
    const alloc = std.testing.allocator;

    const column = [_]M31{ M31.one(), M31.one() };
    const tree_columns = try alloc.dupe(ColumnEvaluation, &[_]ColumnEvaluation{
        .{ .log_size = 1, .values = column[0..] },
    });
    var columns = TreeVec([]ColumnEvaluation).initOwned(
        try alloc.dupe([]ColumnEvaluation, &[_][]ColumnEvaluation{tree_columns}),
    );
    defer columns.deinitDeep(alloc);
    var columns_borrowed = try borrowColumnsForTest(alloc, columns);
    defer columns_borrowed.deinit(alloc);

    var sampled_points = TreeVec([][]CirclePointQM31).initOwned(try alloc.alloc([][]CirclePointQM31, 0));
    defer sampled_points.deinitDeep(alloc);
    var sampled_values = TreeVec([][]QM31).initOwned(try alloc.alloc([][]QM31, 0));
    defer sampled_values.deinitDeep(alloc);

    try std.testing.expectError(
        QuotientOpsError.ShapeMismatch,
        computeFriQuotients(
            alloc,
            columns_borrowed,
            sampled_points,
            sampled_values,
            QM31.one(),
            1,
            1,
        ),
    );
}

test "prover pcs quotient ops: lazy provider matches materialized output" {
    const alloc = std.testing.allocator;
    const lifting_log_size: u32 = 6;
    const domain_size = @as(usize, 1) << @intCast(lifting_log_size);

    const col0 = try alloc.alloc(M31, domain_size);
    defer alloc.free(col0);
    for (col0, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(i + 3));

    const col1_log_size: u32 = 4;
    const col1 = try alloc.alloc(M31, @as(usize, 1) << @intCast(col1_log_size));
    defer alloc.free(col1);
    for (col1, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(101 + i));

    const col2 = try alloc.alloc(M31, domain_size);
    defer alloc.free(col2);
    for (col2, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(205 + i));

    const tree_columns = try alloc.dupe(ColumnEvaluation, &[_]ColumnEvaluation{
        .{ .log_size = lifting_log_size, .values = col0 },
        .{ .log_size = col1_log_size, .values = col1 },
        .{ .log_size = lifting_log_size, .values = col2 },
    });
    var columns = TreeVec([]ColumnEvaluation).initOwned(
        try alloc.dupe([]ColumnEvaluation, &[_][]ColumnEvaluation{tree_columns}),
    );
    defer columns.deinitDeep(alloc);
    var columns_borrowed = try borrowColumnsForTest(alloc, columns);
    defer columns_borrowed.deinit(alloc);

    const point0 = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(7);
    const point1 = @import("stwo_core").circle.SECURE_FIELD_CIRCLE_GEN.mul(13);

    const col0_samples = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point0, .value = QM31.fromU32Unchecked(1, 2, 3, 4) },
    });
    const col1_samples = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point0, .value = QM31.fromU32Unchecked(5, 6, 7, 8) },
        .{ .point = point1, .value = QM31.fromU32Unchecked(9, 10, 11, 12) },
    });
    const col2_samples = try alloc.alloc(PointSample, 0);
    const tree_samples = try alloc.dupe([]PointSample, &[_][]PointSample{
        col0_samples,
        col1_samples,
        col2_samples,
    });
    var samples = TreeVec([][]PointSample).initOwned(
        try alloc.dupe([][]PointSample, &[_][][]PointSample{tree_samples}),
    );
    defer samples.deinitDeep(alloc);
    var split_samples = try splitPointSamplesForTest(alloc, samples);
    defer split_samples.deinit(alloc);

    const alpha = QM31.fromU32Unchecked(3, 0, 1, 0);

    // Compute via existing materialized path.
    var materialized = try computeFriQuotientsWithStrategy(
        alloc,
        columns_borrowed,
        split_samples.points,
        split_samples.values,
        alpha,
        lifting_log_size,
        .materialized,
    );
    defer materialized.deinit(alloc);

    // Compute via the profiled lazy provider, chunk by chunk. Preparation is
    // published immediately after successful construction; row work remains
    // absent until the final non-overlapping range completes.
    var work_recorder: work_profile.Recorder(true) = .{};
    try work_recorder.expectProducer(.quotient_sample_preparation);
    try work_recorder.expectProducer(.quotient_row_execution);
    var provider = try LazyQuotientProvider.initForBackendWithWorkRecorder(
        void,
        alloc,
        columns_borrowed,
        split_samples.points,
        split_samples.values,
        alpha,
        lifting_log_size,
        &work_recorder,
    );
    defer provider.deinit(alloc);
    try std.testing.expectEqual(
        @as(u64, 1),
        work_recorder.completed_sites[@intFromEnum(work_profile.Site.quotient_sample_preparation)],
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        work_recorder.completed_sites[@intFromEnum(work_profile.Site.quotient_row_execution)],
    );

    var lazy_column = try SecureColumnByCoords.uninitialized(alloc, domain_size);
    defer lazy_column.deinit(alloc);

    var chunk_start: usize = 0;
    const chunk_size: usize = 16; // use small chunks in test to exercise boundary logic
    while (chunk_start < domain_size) {
        const this_chunk = @min(chunk_size, domain_size - chunk_start);
        var chunk_coords: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
            chunk_coords[coord] = lazy_column.columns[coord][chunk_start..][0..this_chunk];
        }
        try provider.computeChunk(chunk_start, this_chunk, &chunk_coords);
        chunk_start += this_chunk;
    }
    try std.testing.expectEqual(
        @as(u64, 1),
        work_recorder.completed_sites[@intFromEnum(work_profile.Site.quotient_row_execution)],
    );

    // Verify bit-identical output.
    for (0..domain_size) |i| {
        const mat_val = materialized.at(i);
        const lazy_val = lazy_column.at(i);
        try std.testing.expect(mat_val.eql(lazy_val));
    }
}

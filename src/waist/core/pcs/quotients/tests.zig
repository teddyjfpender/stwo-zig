const std = @import("std");
const circle = @import("stwo_core").circle;
const cm31_mod = @import("stwo_core").fields.cm31;
const m31_mod = @import("stwo_core").fields.m31;
const qm31_mod = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const core_utils = @import("stwo_core").utils;
const pcs_utils = @import("stwo_core").pcs.utils;
const quotients = @import("stwo_core").pcs.quotients;

const CirclePointM31 = circle.CirclePointM31;
const CirclePointQM31 = circle.CirclePointQM31;
const CM31 = cm31_mod.CM31;
const M31 = m31_mod.M31;
const QM31 = qm31_mod.QM31;
const TreeVec = quotients.TreeVec;
const PointSample = quotients.PointSample;
const SampleWithRandomness = quotients.SampleWithRandomness;
const NumeratorData = quotients.NumeratorData;
const ColumnSampleBatch = quotients.ColumnSampleBatch;
const RowQuotientWorkspace = quotients.RowQuotientWorkspace;
const accumulateRowQuotientsWithWorkspace = quotients.accumulateRowQuotientsWithWorkspace;
const accumulateRowPartialNumerators = quotients.accumulateRowPartialNumerators;
const accumulateRowQuotients = quotients.accumulateRowQuotients;
const buildSamplesWithRandomnessAndPeriodicity = quotients.buildSamplesWithRandomnessAndPeriodicity;
const buildColumnSampleBatchesFromParallelInputs = quotients.buildColumnSampleBatchesFromParallelInputs;
const denominatorInverses = quotients.denominatorInverses;
const friAnswers = quotients.friAnswers;
const quotientConstants = quotients.quotientConstants;

fn pointM31IntoQM31(point: CirclePointM31) CirclePointQM31 {
    return .{
        .x = QM31.fromBase(point.x),
        .y = QM31.fromBase(point.y),
    };
}

fn nextRandomPow(current: *QM31, random_coeff: QM31) QM31 {
    const out = current.*;
    current.* = current.*.mul(random_coeff);
    return out;
}

fn freeTreeSamplesWithRandomness(
    allocator: std.mem.Allocator,
    tree_samples: [][]SampleWithRandomness,
) void {
    for (tree_samples) |column_samples| allocator.free(column_samples);
    allocator.free(tree_samples);
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

fn buildSamplesWithRandomnessFromPointSamplesForTest(
    allocator: std.mem.Allocator,
    samples: TreeVec([][]PointSample),
    column_log_sizes: TreeVec([]u32),
    lifting_log_size: u32,
    random_coeff: QM31,
) !TreeVec([][]SampleWithRandomness) {
    if (samples.items.len != column_log_sizes.items.len) return error.ShapeMismatch;

    var random_pow = QM31.one();
    const lifting_domain_generator = canonic.CanonicCoset.new(lifting_log_size).step();

    var trees_builder = std.ArrayList([][]SampleWithRandomness).empty;
    defer trees_builder.deinit(allocator);
    errdefer {
        for (trees_builder.items) |tree_samples| {
            freeTreeSamplesWithRandomness(allocator, tree_samples);
        }
    }

    for (samples.items, 0..) |samples_per_tree, tree_idx| {
        const sizes_per_tree = column_log_sizes.items[tree_idx];
        if (samples_per_tree.len != sizes_per_tree.len) return error.ShapeMismatch;

        var cols_builder = std.ArrayList([]SampleWithRandomness).empty;
        defer cols_builder.deinit(allocator);
        errdefer {
            for (cols_builder.items) |column_samples| allocator.free(column_samples);
        }

        for (samples_per_tree, 0..) |samples_per_col, col_idx| {
            const log_size = sizes_per_tree[col_idx];
            if (samples_per_col.len == 0) {
                try cols_builder.append(allocator, try allocator.alloc(SampleWithRandomness, 0));
                continue;
            }

            const has_periodicity = samples_per_col.len == 2;
            const out_samples = try allocator.alloc(
                SampleWithRandomness,
                samples_per_col.len + @intFromBool(has_periodicity),
            );
            errdefer allocator.free(out_samples);

            var out_idx: usize = 0;
            if (has_periodicity) {
                const sample = samples_per_col[1];
                const period_generator = lifting_domain_generator.repeatedDouble(log_size);
                out_samples[out_idx] = .{
                    .point = sample.point.add(pointM31IntoQM31(period_generator)),
                    .value = sample.value,
                    .random_coeff = nextRandomPow(&random_pow, random_coeff),
                };
                out_idx += 1;
            }

            for (samples_per_col) |sample| {
                out_samples[out_idx] = .{
                    .point = sample.point,
                    .value = sample.value,
                    .random_coeff = nextRandomPow(&random_pow, random_coeff),
                };
                out_idx += 1;
            }
            try cols_builder.append(allocator, out_samples);
        }

        try trees_builder.append(allocator, try cols_builder.toOwnedSlice(allocator));
    }

    return TreeVec([][]SampleWithRandomness).initOwned(try trees_builder.toOwnedSlice(allocator));
}

test "pcs quotients: parallel sampled inputs match legacy point-sample batching" {
    const alloc = std.testing.allocator;
    const lifting_log_size: u32 = 7;
    const alpha = QM31.fromU32Unchecked(9, 10, 11, 12);

    const tree_sizes = try alloc.dupe(u32, &[_]u32{ 4, 6 });
    defer alloc.free(tree_sizes);
    const sizes = try alloc.dupe([]u32, &[_][]u32{tree_sizes});
    defer alloc.free(sizes);
    const column_log_sizes = TreeVec([]u32).initOwned(sizes);

    const point0 = circle.SECURE_FIELD_CIRCLE_GEN.mul(17);
    const point1 = circle.SECURE_FIELD_CIRCLE_GEN.mul(21);
    const point2 = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);

    const col0 = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point0, .value = QM31.fromU32Unchecked(1, 2, 3, 4) },
        .{ .point = point1, .value = QM31.fromU32Unchecked(5, 6, 7, 8) },
    });
    const col1 = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point2, .value = QM31.fromU32Unchecked(9, 10, 11, 12) },
    });
    const tree = try alloc.dupe([]PointSample, &[_][]PointSample{ col0, col1 });
    var samples = TreeVec([][]PointSample).initOwned(
        try alloc.dupe([][]PointSample, &[_][][]PointSample{tree}),
    );
    defer samples.deinitDeep(alloc);

    var split = try splitPointSamplesForTest(alloc, samples);
    defer split.deinit(alloc);

    var actual = try buildSamplesWithRandomnessAndPeriodicity(
        alloc,
        split.points,
        split.values,
        column_log_sizes,
        lifting_log_size,
        alpha,
    );
    defer actual.deinitDeep(alloc);

    var expected = try buildSamplesWithRandomnessFromPointSamplesForTest(
        alloc,
        samples,
        column_log_sizes,
        lifting_log_size,
        alpha,
    );
    defer expected.deinitDeep(alloc);

    try std.testing.expectEqual(expected.items.len, actual.items.len);
    for (expected.items, actual.items) |expected_tree, actual_tree| {
        try std.testing.expectEqual(expected_tree.len, actual_tree.len);
        for (expected_tree, actual_tree) |expected_col, actual_col| {
            try std.testing.expectEqual(expected_col.len, actual_col.len);
            for (expected_col, actual_col) |expected_sample, actual_sample| {
                try std.testing.expect(expected_sample.point.eql(actual_sample.point));
                try std.testing.expect(expected_sample.value.eql(actual_sample.value));
                try std.testing.expect(expected_sample.random_coeff.eql(actual_sample.random_coeff));
            }
        }
    }
}

test "pcs quotients: direct parallel batch builder matches legacy grouping" {
    const alloc = std.testing.allocator;
    const lifting_log_size: u32 = 7;
    const alpha = QM31.fromU32Unchecked(9, 10, 11, 12);

    const tree_sizes0 = try alloc.dupe(u32, &[_]u32{ 4, 6 });
    defer alloc.free(tree_sizes0);
    const tree_sizes1 = try alloc.dupe(u32, &[_]u32{5});
    defer alloc.free(tree_sizes1);
    const sizes = try alloc.dupe([]u32, &[_][]u32{ tree_sizes0, tree_sizes1 });
    defer alloc.free(sizes);
    const column_log_sizes = TreeVec([]u32).initOwned(sizes);

    const point0 = circle.SECURE_FIELD_CIRCLE_GEN.mul(17);
    const point1 = circle.SECURE_FIELD_CIRCLE_GEN.mul(21);
    const point2 = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);

    const tree0_col0_points = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{ point0, point1 });
    defer alloc.free(tree0_col0_points);
    const tree0_col0_values = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
    });
    defer alloc.free(tree0_col0_values);
    const tree0_col1_points = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{point2});
    defer alloc.free(tree0_col1_points);
    const tree0_col1_values = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(9, 10, 11, 12),
    });
    defer alloc.free(tree0_col1_values);

    const tree1_col0_points = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{point0});
    defer alloc.free(tree1_col0_points);
    const tree1_col0_values = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(13, 14, 15, 16),
    });
    defer alloc.free(tree1_col0_values);

    const tree0_points = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        tree0_col0_points,
        tree0_col1_points,
    });
    defer alloc.free(tree0_points);
    const tree0_values = try alloc.dupe([]QM31, &[_][]QM31{
        tree0_col0_values,
        tree0_col1_values,
    });
    defer alloc.free(tree0_values);
    const tree1_points = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        tree1_col0_points,
    });
    defer alloc.free(tree1_points);
    const tree1_values = try alloc.dupe([]QM31, &[_][]QM31{
        tree1_col0_values,
    });
    defer alloc.free(tree1_values);

    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{ tree0_points, tree1_points }),
    );
    defer alloc.free(sampled_points.items);
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{ tree0_values, tree1_values }),
    );
    defer alloc.free(sampled_values.items);

    var samples_with_randomness = try buildSamplesWithRandomnessAndPeriodicity(
        alloc,
        sampled_points,
        sampled_values,
        column_log_sizes,
        lifting_log_size,
        alpha,
    );
    defer samples_with_randomness.deinitDeep(alloc);

    var flat_samples = std.ArrayList([]const SampleWithRandomness).empty;
    defer flat_samples.deinit(alloc);
    for (samples_with_randomness.items) |tree_samples| {
        for (tree_samples) |column_samples| {
            try flat_samples.append(alloc, column_samples);
        }
    }

    const legacy = try ColumnSampleBatch.newVec(alloc, flat_samples.items);
    defer ColumnSampleBatch.deinitSlice(alloc, legacy);
    const direct = try buildColumnSampleBatchesFromParallelInputs(
        alloc,
        sampled_points,
        sampled_values,
        column_log_sizes,
        lifting_log_size,
        alpha,
    );
    defer ColumnSampleBatch.deinitSlice(alloc, direct);

    try std.testing.expectEqual(legacy.len, direct.len);
    for (legacy, direct) |legacy_batch, direct_batch| {
        try std.testing.expect(legacy_batch.point.eql(direct_batch.point));
        try std.testing.expectEqual(legacy_batch.cols_vals_randpows.len, direct_batch.cols_vals_randpows.len);
        for (legacy_batch.cols_vals_randpows, direct_batch.cols_vals_randpows) |legacy_entry, direct_entry| {
            try std.testing.expectEqual(legacy_entry.column_index, direct_entry.column_index);
            try std.testing.expect(legacy_entry.sample_value.eql(direct_entry.sample_value));
            try std.testing.expect(legacy_entry.random_coeff.eql(direct_entry.random_coeff));
        }
    }
}

test "pcs quotients: build samples randomness and periodicity" {
    const alloc = std.testing.allocator;
    const lifting_log_size: u32 = 7;
    const col_log_size: u32 = 4;

    const p0 = circle.SECURE_FIELD_CIRCLE_GEN.mul(17);
    const p1 = circle.SECURE_FIELD_CIRCLE_GEN.mul(21);
    const v0 = QM31.fromU32Unchecked(1, 2, 3, 4);
    const v1 = QM31.fromU32Unchecked(5, 6, 7, 8);

    const col0_points = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{ p0, p1 });
    defer alloc.free(col0_points);
    const col0_values = try alloc.dupe(QM31, &[_]QM31{ v0, v1 });
    defer alloc.free(col0_values);
    const tree_points = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{col0_points});
    defer alloc.free(tree_points);
    const tree_values = try alloc.dupe([]QM31, &[_][]QM31{col0_values});
    defer alloc.free(tree_values);
    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{tree_points}),
    );
    defer alloc.free(sampled_points.items);
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{tree_values}),
    );
    defer alloc.free(sampled_values.items);

    const tree_sizes = try alloc.dupe(u32, &[_]u32{col_log_size});
    defer alloc.free(tree_sizes);
    const sizes = try alloc.dupe([]u32, &[_][]u32{tree_sizes});
    defer alloc.free(sizes);
    const column_log_sizes = TreeVec([]u32).initOwned(sizes);

    const alpha = QM31.fromU32Unchecked(9, 10, 11, 12);
    var out = try buildSamplesWithRandomnessAndPeriodicity(
        alloc,
        sampled_points,
        sampled_values,
        column_log_sizes,
        lifting_log_size,
        alpha,
    );
    defer out.deinitDeep(alloc);

    try std.testing.expectEqual(@as(usize, 1), out.items.len);
    try std.testing.expectEqual(@as(usize, 1), out.items[0].len);
    try std.testing.expectEqual(@as(usize, 3), out.items[0][0].len);

    const period_generator = canonic.CanonicCoset.new(lifting_log_size).step().repeatedDouble(col_log_size);
    const expected_periodic_point = p1.add(pointM31IntoQM31(period_generator));
    try std.testing.expect(out.items[0][0][0].point.eql(expected_periodic_point));
    try std.testing.expect(out.items[0][0][0].value.eql(v1));

    try std.testing.expect(out.items[0][0][0].random_coeff.eql(QM31.one()));
    try std.testing.expect(out.items[0][0][1].random_coeff.eql(alpha));
    try std.testing.expect(out.items[0][0][2].random_coeff.eql(alpha.square()));
}

test "pcs quotients: column sample batch grouping preserves order" {
    const alloc = std.testing.allocator;

    const point_a = circle.SECURE_FIELD_CIRCLE_GEN.mul(3);
    const point_b = circle.SECURE_FIELD_CIRCLE_GEN.mul(7);
    const value_a0 = QM31.fromU32Unchecked(1, 0, 0, 0);
    const value_a1 = QM31.fromU32Unchecked(2, 0, 0, 0);
    const value_b = QM31.fromU32Unchecked(3, 0, 0, 0);

    const col0 = [_]SampleWithRandomness{
        .{ .point = point_a, .value = value_a0, .random_coeff = QM31.one() },
        .{ .point = point_b, .value = value_b, .random_coeff = QM31.fromU32Unchecked(5, 0, 0, 0) },
    };
    const col1 = [_]SampleWithRandomness{
        .{ .point = point_a, .value = value_a1, .random_coeff = QM31.fromU32Unchecked(9, 0, 0, 0) },
    };

    const batches = try ColumnSampleBatch.newVec(alloc, &[_][]const SampleWithRandomness{
        col0[0..],
        col1[0..],
    });
    defer ColumnSampleBatch.deinitSlice(alloc, batches);

    try std.testing.expectEqual(@as(usize, 2), batches.len);
    try std.testing.expect(batches[0].point.eql(point_a));
    try std.testing.expect(batches[1].point.eql(point_b));

    try std.testing.expectEqual(@as(usize, 2), batches[0].cols_vals_randpows.len);
    try std.testing.expectEqual(@as(usize, 0), batches[0].cols_vals_randpows[0].column_index);
    try std.testing.expectEqual(@as(usize, 1), batches[0].cols_vals_randpows[1].column_index);
}

test "pcs quotients: denominator inverses multiply back to one" {
    const alloc = std.testing.allocator;
    const sample_points = [_]CirclePointQM31{
        circle.SECURE_FIELD_CIRCLE_GEN.mul(11),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(17),
        circle.SECURE_FIELD_CIRCLE_GEN.mul(23),
    };
    const domain_point = canonic.CanonicCoset.new(8).circleDomain().at(5);

    const inverses = try denominatorInverses(alloc, sample_points[0..], domain_point);
    defer alloc.free(inverses);
    try std.testing.expectEqual(sample_points.len, inverses.len);

    const domain_x = CM31.fromBase(domain_point.x);
    const domain_y = CM31.fromBase(domain_point.y);
    for (sample_points, 0..) |sample_point, i| {
        const prx = sample_point.x.c0;
        const pry = sample_point.y.c0;
        const pix = sample_point.x.c1;
        const piy = sample_point.y.c1;
        const denominator = prx.sub(domain_x).mul(piy).sub(pry.sub(domain_y).mul(pix));
        try std.testing.expect(denominator.mul(inverses[i]).eql(CM31.one()));
    }
}

test "pcs quotients: row accumulators match direct formulas" {
    const alloc = std.testing.allocator;

    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(19);
    const batch_entries = try alloc.dupe(NumeratorData, &[_]NumeratorData{
        .{
            .column_index = 0,
            .sample_value = QM31.fromU32Unchecked(11, 2, 3, 4),
            .random_coeff = QM31.one(),
        },
        .{
            .column_index = 1,
            .sample_value = QM31.fromU32Unchecked(9, 8, 7, 6),
            .random_coeff = QM31.fromU32Unchecked(3, 0, 0, 0),
        },
    });
    defer alloc.free(batch_entries);

    const batch = ColumnSampleBatch{
        .point = point,
        .cols_vals_randpows = batch_entries,
    };
    const batches = [_]ColumnSampleBatch{batch};

    var quotient_constants = try quotientConstants(alloc, batches[0..]);
    defer quotient_constants.deinit(alloc);

    const queried_values_at_row = [_]M31{
        M31.fromCanonical(13),
        M31.fromCanonical(17),
    };
    const partial = try accumulateRowPartialNumerators(
        &batch,
        queried_values_at_row[0..],
        quotient_constants.line_coeffs[0],
    );

    var partial_expected = QM31.zero();
    for (batch_entries, 0..) |sample_data, i| {
        const value = QM31.fromBase(queried_values_at_row[sample_data.column_index]).mul(
            quotient_constants.line_coeffs[0][i].c,
        );
        partial_expected = partial_expected.add(value.sub(quotient_constants.line_coeffs[0][i].b));
    }
    try std.testing.expect(partial.eql(partial_expected));

    const domain_point = canonic.CanonicCoset.new(8).circleDomain().at(7);
    const row = try accumulateRowQuotients(
        alloc,
        batches[0..],
        queried_values_at_row[0..],
        &quotient_constants,
        domain_point,
    );

    const inverses = try denominatorInverses(alloc, &[_]CirclePointQM31{point}, domain_point);
    defer alloc.free(inverses);
    var numerator = QM31.zero();
    for (batch_entries, 0..) |sample_data, i| {
        const value = QM31.fromBase(queried_values_at_row[sample_data.column_index]).mul(
            quotient_constants.line_coeffs[0][i].c,
        );
        const linear_term = quotient_constants.line_coeffs[0][i].a.mulM31(domain_point.y).add(
            quotient_constants.line_coeffs[0][i].b,
        );
        numerator = numerator.add(value.sub(linear_term));
    }
    const expected_row = numerator.mulCM31(inverses[0]);
    try std.testing.expect(row.eql(expected_row));
}

test "pcs quotients: workspace row accumulation matches allocating path" {
    const alloc = std.testing.allocator;
    const lifting_log_size: u32 = 6;
    const query_positions = [_]usize{ 0, 1, 2, 3 };

    const point0 = circle.SECURE_FIELD_CIRCLE_GEN.mul(5);
    const point1 = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    const col0_points = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{point0});
    defer alloc.free(col0_points);
    const col0_values = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(1, 1, 1, 1),
    });
    defer alloc.free(col0_values);
    const col1_points = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{ point0, point1 });
    defer alloc.free(col1_points);
    const col1_values = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(2, 2, 2, 2),
        QM31.fromU32Unchecked(3, 3, 3, 3),
    });
    defer alloc.free(col1_values);

    const tree_points = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        col0_points,
        col1_points,
    });
    defer alloc.free(tree_points);
    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{tree_points}),
    );
    defer alloc.free(sampled_points.items);

    const tree_values = try alloc.dupe([]QM31, &[_][]QM31{
        col0_values,
        col1_values,
    });
    defer alloc.free(tree_values);
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{tree_values}),
    );
    defer alloc.free(sampled_values.items);

    const column_sizes = try alloc.dupe(u32, &[_]u32{ 5, 5 });
    defer alloc.free(column_sizes);
    const size_trees = try alloc.dupe([]u32, &[_][]u32{column_sizes});
    defer alloc.free(size_trees);
    const column_log_sizes = TreeVec([]u32).initOwned(size_trees);

    const q0 = try alloc.dupe(M31, &[_]M31{
        M31.fromCanonical(10),
        M31.fromCanonical(11),
        M31.fromCanonical(12),
        M31.fromCanonical(13),
    });
    defer alloc.free(q0);
    const q1 = try alloc.dupe(M31, &[_]M31{
        M31.fromCanonical(20),
        M31.fromCanonical(21),
        M31.fromCanonical(22),
        M31.fromCanonical(23),
    });
    defer alloc.free(q1);
    const queried_tree = try alloc.dupe([]M31, &[_][]M31{ q0, q1 });
    defer alloc.free(queried_tree);
    const queried_items = try alloc.dupe([][]M31, &[_][][]M31{queried_tree});
    defer alloc.free(queried_items);
    const queried_values = TreeVec([][]M31).initOwned(queried_items);

    const alpha = QM31.fromU32Unchecked(7, 0, 5, 0);
    var samples_with_randomness = try buildSamplesWithRandomnessAndPeriodicity(
        alloc,
        sampled_points,
        sampled_values,
        column_log_sizes,
        lifting_log_size,
        alpha,
    );
    defer samples_with_randomness.deinitDeep(alloc);

    var flat_samples = std.ArrayList([]const SampleWithRandomness).empty;
    defer flat_samples.deinit(alloc);
    for (samples_with_randomness.items) |tree_samples| {
        for (tree_samples) |column_samples| {
            try flat_samples.append(alloc, column_samples);
        }
    }

    const sample_batches = try ColumnSampleBatch.newVec(alloc, flat_samples.items);
    defer ColumnSampleBatch.deinitSlice(alloc, sample_batches);

    var quotient_constants = try quotientConstants(alloc, sample_batches);
    defer quotient_constants.deinit(alloc);

    const queried_values_flat = try pcs_utils.flatten([]M31, alloc, queried_values);
    defer alloc.free(queried_values_flat);

    var workspace = try RowQuotientWorkspace.init(alloc, sample_batches);
    defer workspace.deinit(alloc);

    const row_buffer = try alloc.alloc(M31, queried_values_flat.len);
    defer alloc.free(row_buffer);

    const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();
    for (query_positions, 0..) |position, row_idx| {
        for (queried_values_flat, 0..) |column_queries, col_idx| {
            row_buffer[col_idx] = column_queries[row_idx];
        }
        const domain_point = domain.at(core_utils.bitReverseIndex(position, lifting_log_size));
        const allocating = try accumulateRowQuotients(
            alloc,
            sample_batches,
            row_buffer,
            &quotient_constants,
            domain_point,
        );
        const with_workspace = try accumulateRowQuotientsWithWorkspace(
            sample_batches,
            row_buffer,
            &quotient_constants,
            domain_point,
            &workspace,
        );
        try std.testing.expect(allocating.eql(with_workspace));
    }
}

test "pcs quotients: fri answers smoke test" {
    const alloc = std.testing.allocator;
    const lifting_log_size: u32 = 6;
    const query_positions = [_]usize{ 0, 1, 2, 3 };

    const point0 = circle.SECURE_FIELD_CIRCLE_GEN.mul(5);
    const point1 = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    const col0_points = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{point0});
    defer alloc.free(col0_points);
    const col0_values = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(1, 1, 1, 1),
    });
    defer alloc.free(col0_values);
    const col1_points = try alloc.dupe(CirclePointQM31, &[_]CirclePointQM31{ point0, point1 });
    defer alloc.free(col1_points);
    const col1_values = try alloc.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(2, 2, 2, 2),
        QM31.fromU32Unchecked(3, 3, 3, 3),
    });
    defer alloc.free(col1_values);

    const tree_points = try alloc.dupe([]CirclePointQM31, &[_][]CirclePointQM31{
        col0_points,
        col1_points,
    });
    defer alloc.free(tree_points);
    const sampled_points = TreeVec([][]CirclePointQM31).initOwned(
        try alloc.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{tree_points}),
    );
    defer alloc.free(sampled_points.items);

    const tree_values = try alloc.dupe([]QM31, &[_][]QM31{
        col0_values,
        col1_values,
    });
    defer alloc.free(tree_values);
    const sampled_values = TreeVec([][]QM31).initOwned(
        try alloc.dupe([][]QM31, &[_][][]QM31{tree_values}),
    );
    defer alloc.free(sampled_values.items);

    const column_sizes = try alloc.dupe(u32, &[_]u32{ 5, 5 });
    defer alloc.free(column_sizes);
    const size_trees = try alloc.dupe([]u32, &[_][]u32{column_sizes});
    defer alloc.free(size_trees);
    const column_log_sizes = TreeVec([]u32).initOwned(size_trees);

    const q0 = try alloc.dupe(M31, &[_]M31{
        M31.fromCanonical(10),
        M31.fromCanonical(11),
        M31.fromCanonical(12),
        M31.fromCanonical(13),
    });
    defer alloc.free(q0);
    const q1 = try alloc.dupe(M31, &[_]M31{
        M31.fromCanonical(20),
        M31.fromCanonical(21),
        M31.fromCanonical(22),
        M31.fromCanonical(23),
    });
    defer alloc.free(q1);
    const queried_tree = try alloc.dupe([]M31, &[_][]M31{ q0, q1 });
    defer alloc.free(queried_tree);
    const queried_items = try alloc.dupe([][]M31, &[_][][]M31{queried_tree});
    defer alloc.free(queried_items);
    const queried_values = TreeVec([][]M31).initOwned(queried_items);

    const alpha = QM31.fromU32Unchecked(7, 0, 5, 0);
    const answers = try friAnswers(
        alloc,
        column_log_sizes,
        sampled_points,
        sampled_values,
        alpha,
        query_positions[0..],
        queried_values,
        lifting_log_size,
    );
    defer alloc.free(answers);

    try std.testing.expectEqual(query_positions.len, answers.len);
}

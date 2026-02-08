const std = @import("std");
const circle = @import("../circle.zig");
const constraints = @import("../constraints.zig");
const cm31_mod = @import("../fields/cm31.zig");
const m31_mod = @import("../fields/m31.zig");
const qm31_mod = @import("../fields/qm31.zig");
const pcs_utils = @import("utils.zig");
const canonic = @import("../poly/circle/canonic.zig");
const core_utils = @import("../utils.zig");

const CirclePointM31 = circle.CirclePointM31;
const CirclePointQM31 = circle.CirclePointQM31;
const CM31 = cm31_mod.CM31;
const M31 = m31_mod.M31;
const QM31 = qm31_mod.QM31;

pub const TreeVec = pcs_utils.TreeVec;

/// A sample of one column at one secure-field circle point.
pub const PointSample = struct {
    point: CirclePointQM31,
    value: QM31,
};

/// Helper container for attaching the random coefficient power to each sample.
pub const SampleWithRandomness = struct {
    sample: PointSample,
    random_coeff: QM31,
};

/// Helper struct used in `ColumnSampleBatch`.
pub const NumeratorData = struct {
    column_index: usize,
    sample_value: QM31,
    random_coeff: QM31,
};

/// A batch of column samplings at a sampled point.
pub const ColumnSampleBatch = struct {
    point: CirclePointQM31,
    cols_vals_randpows: []NumeratorData,

    pub fn deinit(self: *ColumnSampleBatch, allocator: std.mem.Allocator) void {
        allocator.free(self.cols_vals_randpows);
        self.* = undefined;
    }

    pub fn deinitSlice(allocator: std.mem.Allocator, batches: []ColumnSampleBatch) void {
        for (batches) |*batch| batch.deinit(allocator);
        allocator.free(batches);
    }

    /// Groups samples by point while preserving first-occurrence order.
    pub fn newVec(
        allocator: std.mem.Allocator,
        samples_with_rand: []const []const SampleWithRandomness,
    ) ![]ColumnSampleBatch {
        const MutableBatch = struct {
            point: CirclePointQM31,
            vals: std.ArrayList(NumeratorData),
        };

        var grouped = std.ArrayList(MutableBatch).empty;
        defer {
            for (grouped.items) |*batch| {
                batch.vals.deinit(allocator);
            }
            grouped.deinit(allocator);
        }

        for (samples_with_rand, 0..) |column_samples, column_index| {
            for (column_samples) |sample_with_rand| {
                var batch_idx: ?usize = null;
                for (grouped.items, 0..) |existing, i| {
                    if (existing.point.eql(sample_with_rand.sample.point)) {
                        batch_idx = i;
                        break;
                    }
                }
                if (batch_idx == null) {
                    try grouped.append(allocator, .{
                        .point = sample_with_rand.sample.point,
                        .vals = std.ArrayList(NumeratorData).empty,
                    });
                    batch_idx = grouped.items.len - 1;
                }
                try grouped.items[batch_idx.?].vals.append(allocator, .{
                    .column_index = column_index,
                    .sample_value = sample_with_rand.sample.value,
                    .random_coeff = sample_with_rand.random_coeff,
                });
            }
        }

        const out = try allocator.alloc(ColumnSampleBatch, grouped.items.len);
        errdefer allocator.free(out);

        var initialized: usize = 0;
        errdefer {
            for (out[0..initialized]) |batch| allocator.free(batch.cols_vals_randpows);
        }

        for (grouped.items, 0..) |*batch, i| {
            out[i] = .{
                .point = batch.point,
                .cols_vals_randpows = try batch.vals.toOwnedSlice(allocator),
            };
            initialized += 1;
        }
        return out;
    }
};

/// Holds the precomputed constants used in each quotient evaluation.
pub const QuotientConstants = struct {
    line_coeffs: [][]constraints.LineCoeffs,

    pub fn deinit(self: *QuotientConstants, allocator: std.mem.Allocator) void {
        for (self.line_coeffs) |batch_coeffs| allocator.free(batch_coeffs);
        allocator.free(self.line_coeffs);
        self.* = undefined;
    }
};

/// Precomputes line coefficients for each sampled column in each sample batch.
pub fn columnLineCoeffs(
    allocator: std.mem.Allocator,
    sample_batches: []const ColumnSampleBatch,
) ![][]constraints.LineCoeffs {
    var outer = std.ArrayList([]constraints.LineCoeffs).empty;
    defer outer.deinit(allocator);
    errdefer {
        for (outer.items) |batch_coeffs| allocator.free(batch_coeffs);
    }

    for (sample_batches) |batch| {
        const batch_coeffs = try allocator.alloc(constraints.LineCoeffs, batch.cols_vals_randpows.len);
        errdefer allocator.free(batch_coeffs);

        for (batch.cols_vals_randpows, 0..) |sample_data, i| {
            batch_coeffs[i] = constraints.complexConjugateLineCoeffs(
                batch.point,
                sample_data.sample_value,
                sample_data.random_coeff,
            ) catch return error.DegenerateLine;
        }
        try outer.append(allocator, batch_coeffs);
    }

    return outer.toOwnedSlice(allocator);
}

pub fn quotientConstants(
    allocator: std.mem.Allocator,
    sample_batches: []const ColumnSampleBatch,
) !QuotientConstants {
    return .{
        .line_coeffs = try columnLineCoeffs(allocator, sample_batches),
    };
}

/// Computes the denominator inverses for one domain point and all sample points.
pub fn denominatorInverses(
    allocator: std.mem.Allocator,
    sample_points: []const CirclePointQM31,
    domain_point: CirclePointM31,
) ![]CM31 {
    const denominators = try allocator.alloc(CM31, sample_points.len);
    defer allocator.free(denominators);
    const inverses = try allocator.alloc(CM31, sample_points.len);
    errdefer allocator.free(inverses);

    try denominatorInversesInto(sample_points, domain_point, denominators, inverses);
    return inverses;
}

fn denominatorInversesInto(
    sample_points: []const CirclePointQM31,
    domain_point: CirclePointM31,
    denominators: []CM31,
    denominator_inverses: []CM31,
) !void {
    if (denominators.len != sample_points.len) return error.ShapeMismatch;
    if (denominator_inverses.len != sample_points.len) return error.ShapeMismatch;

    const domain_x = CM31.fromBase(domain_point.x);
    const domain_y = CM31.fromBase(domain_point.y);

    for (sample_points, 0..) |sample_point, i| {
        const prx = sample_point.x.c0;
        const pry = sample_point.y.c0;
        const pix = sample_point.x.c1;
        const piy = sample_point.y.c1;
        denominators[i] = prx.sub(domain_x).mul(piy).sub(pry.sub(domain_y).mul(pix));
    }

    try batchInverseIntoCM31(denominators, denominator_inverses);
}

fn batchInverseIntoCM31(values: []const CM31, out: []CM31) !void {
    if (values.len != out.len) return error.ShapeMismatch;
    if (values.len == 0) return;

    out[0] = CM31.one();
    var i: usize = 1;
    while (i < values.len) : (i += 1) {
        out[i] = out[i - 1].mul(values[i - 1]);
    }

    var inv_total = out[values.len - 1].mul(values[values.len - 1]).inv() catch {
        return error.DivisionByZero;
    };

    var j: usize = values.len;
    while (j > 0) {
        j -= 1;
        const prefix = if (j == 0) CM31.one() else out[j];
        out[j] = inv_total.mul(prefix);
        inv_total = inv_total.mul(values[j]);
    }
}

/// Computes the partial numerator sum for one row:
/// `∑ alpha^k * (c * value - b)`.
pub fn accumulateRowPartialNumerators(
    batch: *const ColumnSampleBatch,
    queried_values_at_row: []const M31,
    coeffs: []const constraints.LineCoeffs,
) !QM31 {
    if (batch.cols_vals_randpows.len != coeffs.len) return error.ShapeMismatch;

    var numerator = QM31.zero();
    for (batch.cols_vals_randpows, 0..) |sample_data, i| {
        if (sample_data.column_index >= queried_values_at_row.len) {
            return error.ColumnIndexOutOfBounds;
        }
        const value = QM31.fromBase(queried_values_at_row[sample_data.column_index]).mul(coeffs[i].c);
        numerator = numerator.add(value.sub(coeffs[i].b));
    }
    return numerator;
}

/// Computes the full row quotient accumulation for one queried domain row.
pub fn accumulateRowQuotients(
    allocator: std.mem.Allocator,
    sample_batches: []const ColumnSampleBatch,
    queried_values_at_row: []const M31,
    quotient_constants: *const QuotientConstants,
    domain_point: CirclePointM31,
) !QM31 {
    if (sample_batches.len != quotient_constants.line_coeffs.len) return error.ShapeMismatch;

    const sample_points = try allocator.alloc(CirclePointQM31, sample_batches.len);
    defer allocator.free(sample_points);
    for (sample_batches, 0..) |batch, i| sample_points[i] = batch.point;

    const denominator_scratch = try allocator.alloc(CM31, sample_batches.len);
    defer allocator.free(denominator_scratch);
    const denominator_inverses = try allocator.alloc(CM31, sample_batches.len);
    defer allocator.free(denominator_inverses);
    try denominatorInversesInto(
        sample_points,
        domain_point,
        denominator_scratch,
        denominator_inverses,
    );

    var row_accumulator = QM31.zero();
    for (sample_batches, 0..) |batch, batch_idx| {
        const line_coeffs = quotient_constants.line_coeffs[batch_idx];
        if (batch.cols_vals_randpows.len != line_coeffs.len) return error.ShapeMismatch;

        var numerator = QM31.zero();
        for (batch.cols_vals_randpows, 0..) |sample_data, i| {
            if (sample_data.column_index >= queried_values_at_row.len) {
                return error.ColumnIndexOutOfBounds;
            }
            const value = QM31.fromBase(queried_values_at_row[sample_data.column_index]).mul(line_coeffs[i].c);
            const linear_term = line_coeffs[i].a.mulM31(domain_point.y).add(line_coeffs[i].b);
            numerator = numerator.add(value.sub(linear_term));
        }
        row_accumulator = row_accumulator.add(numerator.mulCM31(denominator_inverses[batch_idx]));
    }
    return row_accumulator;
}

fn accumulateRowQuotientsFromColumns(
    sample_batches: []const ColumnSampleBatch,
    queried_values_flat: []const []const M31,
    row_idx: usize,
    quotient_constants: *const QuotientConstants,
    domain_point: CirclePointM31,
    sample_points: []const CirclePointQM31,
    denominator_scratch: []CM31,
    denominator_inverses: []CM31,
) !QM31 {
    if (sample_batches.len != quotient_constants.line_coeffs.len) return error.ShapeMismatch;
    if (sample_points.len != sample_batches.len) return error.ShapeMismatch;
    if (denominator_scratch.len != sample_batches.len) return error.ShapeMismatch;
    if (denominator_inverses.len != sample_batches.len) return error.ShapeMismatch;

    try denominatorInversesInto(
        sample_points,
        domain_point,
        denominator_scratch,
        denominator_inverses,
    );

    var row_accumulator = QM31.zero();
    for (sample_batches, 0..) |batch, batch_idx| {
        const line_coeffs = quotient_constants.line_coeffs[batch_idx];
        if (batch.cols_vals_randpows.len != line_coeffs.len) return error.ShapeMismatch;

        var numerator = QM31.zero();
        for (batch.cols_vals_randpows, 0..) |sample_data, i| {
            if (sample_data.column_index >= queried_values_flat.len) return error.ColumnIndexOutOfBounds;
            const column_queries = queried_values_flat[sample_data.column_index];
            if (row_idx >= column_queries.len) return error.ShapeMismatch;

            const value = QM31.fromBase(column_queries[row_idx]).mul(line_coeffs[i].c);
            const linear_term = line_coeffs[i].a.mulM31(domain_point.y).add(line_coeffs[i].b);
            numerator = numerator.add(value.sub(linear_term));
        }
        row_accumulator = row_accumulator.add(numerator.mulCM31(denominator_inverses[batch_idx]));
    }
    return row_accumulator;
}

/// Attaches random coefficient powers and periodicity checks to all column samples.
///
/// Inputs:
/// - `samples`: per tree -> per column -> point samples.
/// - `column_log_sizes`: per tree -> per column log size.
/// - `lifting_log_size`: maximal lifted log size.
/// - `random_coeff`: random coefficient `alpha`.
///
/// Output:
/// - per tree -> per column -> `(sample, alpha^k)` in upstream order.
pub fn buildSamplesWithRandomnessAndPeriodicity(
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
            for (cols_builder.items) |col_samples| allocator.free(col_samples);
        }

        for (samples_per_tree, 0..) |samples_per_col, col_idx| {
            const log_size = sizes_per_tree[col_idx];
            if (samples_per_col.len == 0) {
                try cols_builder.append(
                    allocator,
                    try allocator.alloc(SampleWithRandomness, 0),
                );
                continue;
            }

            const has_periodicity = samples_per_col.len == 2;
            const n_new_samples = samples_per_col.len + @intFromBool(has_periodicity);
            const out_samples = try allocator.alloc(SampleWithRandomness, n_new_samples);
            errdefer allocator.free(out_samples);

            var out_i: usize = 0;
            if (has_periodicity) {
                const point_sample = samples_per_col[1];
                const period_generator = lifting_domain_generator.repeatedDouble(log_size);
                out_samples[out_i] = .{
                    .sample = .{
                        .point = point_sample.point.add(pointM31IntoQM31(period_generator)),
                        .value = point_sample.value,
                    },
                    .random_coeff = nextRandomPow(&random_pow, random_coeff),
                };
                out_i += 1;
            }

            for (samples_per_col) |sample| {
                out_samples[out_i] = .{
                    .sample = sample,
                    .random_coeff = nextRandomPow(&random_pow, random_coeff),
                };
                out_i += 1;
            }
            try cols_builder.append(allocator, out_samples);
        }

        try trees_builder.append(allocator, try cols_builder.toOwnedSlice(allocator));
    }

    return TreeVec([][]SampleWithRandomness).initOwned(try trees_builder.toOwnedSlice(allocator));
}

/// Computes FRI answers for queried rows.
///
/// Preconditions:
/// - every queried-value column has `query_positions.len` rows.
/// - `samples` and `column_log_sizes` have matching tree/column shapes.
pub fn friAnswers(
    allocator: std.mem.Allocator,
    column_log_sizes: TreeVec([]u32),
    samples: TreeVec([][]PointSample),
    random_coeff: QM31,
    query_positions: []const usize,
    queried_values: TreeVec([][]M31),
    lifting_log_size: u32,
) ![]QM31 {
    const queried_values_flat = try pcs_utils.flatten([]M31, allocator, queried_values);
    defer allocator.free(queried_values_flat);

    for (queried_values_flat) |queries_per_col| {
        if (queries_per_col.len != query_positions.len) return error.ShapeMismatch;
    }

    var samples_with_randomness = try buildSamplesWithRandomnessAndPeriodicity(
        allocator,
        samples,
        column_log_sizes,
        lifting_log_size,
        random_coeff,
    );
    defer samples_with_randomness.deinitDeep(allocator);

    var flat_samples = std.ArrayList([]const SampleWithRandomness).empty;
    defer flat_samples.deinit(allocator);
    for (samples_with_randomness.items) |tree_samples| {
        for (tree_samples) |col_samples| {
            try flat_samples.append(allocator, col_samples);
        }
    }

    const sample_batches = try ColumnSampleBatch.newVec(allocator, flat_samples.items);
    defer ColumnSampleBatch.deinitSlice(allocator, sample_batches);

    var q_consts = try quotientConstants(allocator, sample_batches);
    defer q_consts.deinit(allocator);

    const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();
    const domain_size = domain.size();

    const sample_points = try allocator.alloc(CirclePointQM31, sample_batches.len);
    defer allocator.free(sample_points);
    for (sample_batches, 0..) |batch, i| sample_points[i] = batch.point;

    const denominator_scratch = try allocator.alloc(CM31, sample_batches.len);
    defer allocator.free(denominator_scratch);
    const denominator_inverses = try allocator.alloc(CM31, sample_batches.len);
    defer allocator.free(denominator_inverses);

    const out = try allocator.alloc(QM31, query_positions.len);
    for (query_positions, 0..) |position, row_idx| {
        if (position >= domain_size) return error.QueryPositionOutOfRange;
        const domain_point = domain.at(core_utils.bitReverseIndex(position, lifting_log_size));
        out[row_idx] = try accumulateRowQuotientsFromColumns(
            sample_batches,
            queried_values_flat,
            row_idx,
            &q_consts,
            domain_point,
            sample_points,
            denominator_scratch,
            denominator_inverses,
        );
    }
    return out;
}

fn pointM31IntoQM31(p: CirclePointM31) CirclePointQM31 {
    return .{
        .x = QM31.fromBase(p.x),
        .y = QM31.fromBase(p.y),
    };
}

fn nextRandomPow(curr: *QM31, random_coeff: QM31) QM31 {
    const out = curr.*;
    curr.* = curr.*.mul(random_coeff);
    return out;
}

fn freeTreeSamplesWithRandomness(
    allocator: std.mem.Allocator,
    tree_samples: [][]SampleWithRandomness,
) void {
    for (tree_samples) |col_samples| allocator.free(col_samples);
    allocator.free(tree_samples);
}

test "pcs quotients: build samples randomness and periodicity" {
    const alloc = std.testing.allocator;
    const lifting_log_size: u32 = 7;
    const col_log_size: u32 = 4;

    const p0 = circle.SECURE_FIELD_CIRCLE_GEN.mul(17);
    const p1 = circle.SECURE_FIELD_CIRCLE_GEN.mul(21);
    const v0 = QM31.fromU32Unchecked(1, 2, 3, 4);
    const v1 = QM31.fromU32Unchecked(5, 6, 7, 8);

    const col0 = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = p0, .value = v0 },
        .{ .point = p1, .value = v1 },
    });
    defer alloc.free(col0);
    const tree0 = try alloc.dupe([]PointSample, &[_][]PointSample{col0});
    defer alloc.free(tree0);
    const trees = try alloc.dupe([][]PointSample, &[_][][]PointSample{tree0});
    defer alloc.free(trees);
    const samples = TreeVec([][]PointSample).initOwned(trees);

    const tree_sizes = try alloc.dupe(u32, &[_]u32{col_log_size});
    defer alloc.free(tree_sizes);
    const sizes = try alloc.dupe([]u32, &[_][]u32{tree_sizes});
    defer alloc.free(sizes);
    const column_log_sizes = TreeVec([]u32).initOwned(sizes);

    const alpha = QM31.fromU32Unchecked(9, 10, 11, 12);
    var out = try buildSamplesWithRandomnessAndPeriodicity(
        alloc,
        samples,
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
    try std.testing.expect(out.items[0][0][0].sample.point.eql(expected_periodic_point));
    try std.testing.expect(out.items[0][0][0].sample.value.eql(v1));

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
        .{ .sample = .{ .point = point_a, .value = value_a0 }, .random_coeff = QM31.one() },
        .{ .sample = .{ .point = point_b, .value = value_b }, .random_coeff = QM31.fromU32Unchecked(5, 0, 0, 0) },
    };
    const col1 = [_]SampleWithRandomness{
        .{ .sample = .{ .point = point_a, .value = value_a1 }, .random_coeff = QM31.fromU32Unchecked(9, 0, 0, 0) },
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
        const denom = prx.sub(domain_x).mul(piy).sub(pry.sub(domain_y).mul(pix));
        try std.testing.expect(denom.mul(inverses[i]).eql(CM31.one()));
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

    const coeffs_nested = try columnLineCoeffs(alloc, batches[0..]);
    defer {
        for (coeffs_nested) |coeffs| alloc.free(coeffs);
        alloc.free(coeffs_nested);
    }

    const queried_values_at_row = [_]M31{
        M31.fromCanonical(13),
        M31.fromCanonical(17),
    };
    const partial = try accumulateRowPartialNumerators(&batch, queried_values_at_row[0..], coeffs_nested[0]);

    var partial_expected = QM31.zero();
    for (batch_entries, 0..) |sample_data, i| {
        const value = QM31.fromBase(queried_values_at_row[sample_data.column_index]).mul(coeffs_nested[0][i].c);
        partial_expected = partial_expected.add(value.sub(coeffs_nested[0][i].b));
    }
    try std.testing.expect(partial.eql(partial_expected));

    var q_consts = QuotientConstants{ .line_coeffs = coeffs_nested };
    const domain_point = canonic.CanonicCoset.new(8).circleDomain().at(7);
    const row = try accumulateRowQuotients(
        alloc,
        batches[0..],
        queried_values_at_row[0..],
        &q_consts,
        domain_point,
    );

    const inverses = try denominatorInverses(alloc, &[_]CirclePointQM31{point}, domain_point);
    defer alloc.free(inverses);
    var numerator = QM31.zero();
    for (batch_entries, 0..) |sample_data, i| {
        const value = QM31.fromBase(queried_values_at_row[sample_data.column_index]).mul(coeffs_nested[0][i].c);
        const linear_term = coeffs_nested[0][i].a.mulM31(domain_point.y).add(coeffs_nested[0][i].b);
        numerator = numerator.add(value.sub(linear_term));
    }
    const expected_row = numerator.mulCM31(inverses[0]);
    try std.testing.expect(row.eql(expected_row));
}

test "pcs quotients: zero-copy row accumulation matches row-copy path" {
    const alloc = std.testing.allocator;
    const lifting_log_size: u32 = 6;
    const query_positions = [_]usize{ 0, 1, 2, 3 };

    const point0 = circle.SECURE_FIELD_CIRCLE_GEN.mul(5);
    const point1 = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    const col0_samples = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point0, .value = QM31.fromU32Unchecked(1, 1, 1, 1) },
    });
    defer alloc.free(col0_samples);
    const col1_samples = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point0, .value = QM31.fromU32Unchecked(2, 2, 2, 2) },
        .{ .point = point1, .value = QM31.fromU32Unchecked(3, 3, 3, 3) },
    });
    defer alloc.free(col1_samples);

    const tree_samples = try alloc.dupe([]PointSample, &[_][]PointSample{
        col0_samples,
        col1_samples,
    });
    defer alloc.free(tree_samples);
    const samples_items = try alloc.dupe([][]PointSample, &[_][][]PointSample{tree_samples});
    defer alloc.free(samples_items);
    const samples = TreeVec([][]PointSample).initOwned(samples_items);

    const col_sizes_tree = try alloc.dupe(u32, &[_]u32{ 5, 5 });
    defer alloc.free(col_sizes_tree);
    const col_sizes = try alloc.dupe([]u32, &[_][]u32{col_sizes_tree});
    defer alloc.free(col_sizes);
    const column_log_sizes = TreeVec([]u32).initOwned(col_sizes);

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
        samples,
        column_log_sizes,
        lifting_log_size,
        alpha,
    );
    defer samples_with_randomness.deinitDeep(alloc);

    var flat_samples = std.ArrayList([]const SampleWithRandomness).empty;
    defer flat_samples.deinit(alloc);
    for (samples_with_randomness.items) |tree_samples_slice| {
        for (tree_samples_slice) |col_samples| {
            try flat_samples.append(alloc, col_samples);
        }
    }

    const sample_batches = try ColumnSampleBatch.newVec(alloc, flat_samples.items);
    defer ColumnSampleBatch.deinitSlice(alloc, sample_batches);

    var q_consts = try quotientConstants(alloc, sample_batches);
    defer q_consts.deinit(alloc);

    const queried_values_flat = try pcs_utils.flatten([]M31, alloc, queried_values);
    defer alloc.free(queried_values_flat);

    const sample_points = try alloc.alloc(CirclePointQM31, sample_batches.len);
    defer alloc.free(sample_points);
    for (sample_batches, 0..) |batch, i| sample_points[i] = batch.point;

    const denominator_scratch = try alloc.alloc(CM31, sample_batches.len);
    defer alloc.free(denominator_scratch);
    const denominator_inverses = try alloc.alloc(CM31, sample_batches.len);
    defer alloc.free(denominator_inverses);

    const row_buffer = try alloc.alloc(M31, queried_values_flat.len);
    defer alloc.free(row_buffer);

    const domain = canonic.CanonicCoset.new(lifting_log_size).circleDomain();
    for (query_positions, 0..) |position, row_idx| {
        for (queried_values_flat, 0..) |column_queries, col_idx| {
            row_buffer[col_idx] = column_queries[row_idx];
        }
        const domain_point = domain.at(core_utils.bitReverseIndex(position, lifting_log_size));
        const row_copy = try accumulateRowQuotients(
            alloc,
            sample_batches,
            row_buffer,
            &q_consts,
            domain_point,
        );
        const zero_copy = try accumulateRowQuotientsFromColumns(
            sample_batches,
            queried_values_flat,
            row_idx,
            &q_consts,
            domain_point,
            sample_points,
            denominator_scratch,
            denominator_inverses,
        );
        try std.testing.expect(row_copy.eql(zero_copy));
    }
}

test "pcs quotients: fri answers smoke test" {
    const alloc = std.testing.allocator;
    const lifting_log_size: u32 = 6;
    const query_positions = [_]usize{ 0, 1, 2, 3 };

    const point0 = circle.SECURE_FIELD_CIRCLE_GEN.mul(5);
    const point1 = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    const col0_samples = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point0, .value = QM31.fromU32Unchecked(1, 1, 1, 1) },
    });
    defer alloc.free(col0_samples);
    const col1_samples = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point0, .value = QM31.fromU32Unchecked(2, 2, 2, 2) },
        .{ .point = point1, .value = QM31.fromU32Unchecked(3, 3, 3, 3) },
    });
    defer alloc.free(col1_samples);

    const tree_samples = try alloc.dupe([]PointSample, &[_][]PointSample{
        col0_samples,
        col1_samples,
    });
    defer alloc.free(tree_samples);
    const samples_items = try alloc.dupe([][]PointSample, &[_][][]PointSample{tree_samples});
    defer alloc.free(samples_items);
    const samples = TreeVec([][]PointSample).initOwned(samples_items);

    const col_sizes_tree = try alloc.dupe(u32, &[_]u32{ 5, 5 });
    defer alloc.free(col_sizes_tree);
    const col_sizes = try alloc.dupe([]u32, &[_][]u32{col_sizes_tree});
    defer alloc.free(col_sizes);
    const column_log_sizes = TreeVec([]u32).initOwned(col_sizes);

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
        samples,
        alpha,
        query_positions[0..],
        queried_values,
        lifting_log_size,
    );
    defer alloc.free(answers);

    try std.testing.expectEqual(query_positions.len, answers.len);
}

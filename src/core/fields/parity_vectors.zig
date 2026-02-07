const std = @import("std");
const circle_mod = @import("../circle.zig");
const constraints_mod = @import("../constraints.zig");
const fft_mod = @import("../fft.zig");
const fri_mod = @import("../fri.zig");
const pcs_mod = @import("../pcs/mod.zig");
const proof_mod = @import("../proof.zig");
const quotients_mod = @import("../pcs/quotients.zig");
const canonic_mod = @import("../poly/circle/canonic.zig");
const line_mod = @import("../poly/line.zig");
const utils_mod = @import("../utils.zig");
const vcs_verifier_mod = @import("../vcs/verifier.zig");
const vcs_blake3 = @import("../vcs/blake3_hash.zig");
const vcs_prover_mod = @import("../../prover/vcs/prover.zig");
const vcs_lifted_prover_mod = @import("../../prover/vcs_lifted/prover.zig");
const prover_line_mod = @import("../../prover/line.zig");
const cm31_mod = @import("cm31.zig");
const m31_mod = @import("m31.zig");
const qm31_mod = @import("qm31.zig");

const CirclePointM31 = circle_mod.CirclePointM31;
const CirclePointQM31 = circle_mod.CirclePointQM31;
const M31_CIRCLE_GEN = circle_mod.M31_CIRCLE_GEN;
const M31 = m31_mod.M31;
const CM31 = cm31_mod.CM31;
const QM31 = qm31_mod.QM31;
const PointSample = quotients_mod.PointSample;
const SampleWithRandomness = quotients_mod.SampleWithRandomness;
const NumeratorData = quotients_mod.NumeratorData;
const ColumnSampleBatch = quotients_mod.ColumnSampleBatch;
const LineCoeffs = constraints_mod.LineCoeffs;

const M31Vector = struct {
    a: u32,
    b: u32,
    add: u32,
    sub: u32,
    mul: u32,
    inv_a: u32,
    div_ab: u32,
};

const CM31Vector = struct {
    a: [2]u32,
    b: [2]u32,
    add: [2]u32,
    sub: [2]u32,
    mul: [2]u32,
    inv_a: [2]u32,
    div_ab: [2]u32,
};

const QM31Vector = struct {
    a: [4]u32,
    b: [4]u32,
    add: [4]u32,
    sub: [4]u32,
    mul: [4]u32,
    inv_a: [4]u32,
    div_ab: [4]u32,
};

const CircleM31Vector = struct {
    a_scalar: u64,
    b_scalar: u64,
    log_order_a: u32,
    a: [2]u32,
    b: [2]u32,
    add: [2]u32,
    sub: [2]u32,
    double_a: [2]u32,
    conjugate_a: [2]u32,
};

const FftM31Vector = struct {
    a: u32,
    b: u32,
    twid: u32,
    butterfly: [2]u32,
    ibutterfly: [2]u32,
};

const Blake3Vector = struct {
    data: []u8,
    hash: [32]u8,
    left: [32]u8,
    right: [32]u8,
    concat_hash: [32]u8,
};

const PointSampleVector = struct {
    point: [2][4]u32,
    value: [4]u32,
};

const SampleWithRandomnessVector = struct {
    sample: PointSampleVector,
    random_coeff: [4]u32,
};

const NumeratorDataVector = struct {
    column_index: usize,
    sample_value: [4]u32,
    random_coeff: [4]u32,
};

const ColumnSampleBatchVector = struct {
    point: [2][4]u32,
    cols_vals_randpows: []NumeratorDataVector,
};

const LineCoeffVector = struct {
    a: [4]u32,
    b: [4]u32,
    c: [4]u32,
};

const PcsQuotientsVector = struct {
    lifting_log_size: u32,
    column_log_sizes: [][]u32,
    samples: [][][]PointSampleVector,
    random_coeff: [4]u32,
    query_positions: []usize,
    queried_values: [][][]u32,
    samples_with_randomness: [][][]SampleWithRandomnessVector,
    sample_batches: []ColumnSampleBatchVector,
    line_coeffs: [][]LineCoeffVector,
    denominator_inverses: [][][2]u32,
    partial_numerators: [][][4]u32,
    row_quotients: [][4]u32,
    fri_answers: [][4]u32,
};

const FriFoldVector = struct {
    line_log_size: u32,
    line_eval: [][4]u32,
    alpha: [4]u32,
    fold_line_values: [][4]u32,
    circle_log_size: u32,
    circle_eval: [][4]u32,
    fold_circle_values: [][4]u32,
};

const ProofExtractOodsVector = struct {
    composition_log_size: u32,
    oods_point: [2][4]u32,
    composition_values: [][4]u32,
    expected: [4]u32,
};

const ProofSizeBreakdownVector = struct {
    oods_samples: usize,
    queries_values: usize,
    fri_samples: usize,
    fri_decommitments: usize,
    trace_decommitments: usize,
};

const ProofSizeInnerLayerVector = struct {
    fri_witness: [][4]u32,
    decommitment: [][32]u8,
    commitment: [32]u8,
};

const ProofSizeVector = struct {
    commitments: [][32]u8,
    sampled_values: [][][][4]u32,
    decommitments: [][][32]u8,
    queried_values: [][][]u32,
    proof_of_work: u64,
    first_layer_witness: [][4]u32,
    first_layer_decommitment: [][32]u8,
    first_layer_commitment: [32]u8,
    inner_layers: []ProofSizeInnerLayerVector,
    last_layer_poly: [][4]u32,
    expected_breakdown: ProofSizeBreakdownVector,
};

const ProverLineVector = struct {
    line_log_size: u32,
    values: [][4]u32,
    coeffs_bit_reversed: [][4]u32,
    coeffs_ordered: [][4]u32,
};

const VcsLogSizeQueriesVector = struct {
    log_size: u32,
    queries: []usize,
};

const VcsVerifierVector = struct {
    case: []const u8,
    root: [32]u8,
    column_log_sizes: []u32,
    queries_per_log_size: []VcsLogSizeQueriesVector,
    queried_values: []u32,
    hash_witness: [][32]u8,
    column_witness: []u32,
    expected: []const u8,
};

const VcsProverVector = struct {
    root: [32]u8,
    column_log_sizes: []u32,
    columns: [][]u32,
    queries_per_log_size: []VcsLogSizeQueriesVector,
    queried_values: []u32,
    hash_witness: [][32]u8,
    column_witness: []u32,
};

const VcsLiftedProverVector = struct {
    root: [32]u8,
    column_log_sizes: []u32,
    columns: [][]u32,
    query_positions: []usize,
    queried_values: [][]u32,
    hash_witness: [][32]u8,
};

const VcsLiftedVerifierVector = struct {
    case: []const u8,
    root: [32]u8,
    column_log_sizes: []u32,
    query_positions: []usize,
    queried_values: [][]u32,
    hash_witness: [][32]u8,
    expected: []const u8,
};

const VectorFile = struct {
    meta: struct {
        upstream_commit: []const u8,
        sample_count: usize,
        schema_version: u32,
        seed: u64,
        seed_strategy: []const u8,
    },
    m31: []M31Vector,
    cm31: []CM31Vector,
    qm31: []QM31Vector,
    circle_m31: []CircleM31Vector,
    fft_m31: []FftM31Vector,
    blake3: []Blake3Vector,
    pcs_quotients: []PcsQuotientsVector,
    fri_folds: []FriFoldVector,
    proof_extract_oods: []ProofExtractOodsVector,
    proof_sizes: []ProofSizeVector,
    prover_line: []ProverLineVector,
    vcs_verifier: []VcsVerifierVector,
    vcs_prover: []VcsProverVector,
    vcs_lifted_verifier: []VcsLiftedVerifierVector,
    vcs_lifted_prover: []VcsLiftedProverVector,
};

fn parseVectors(allocator: std.mem.Allocator) !std.json.Parsed(VectorFile) {
    const raw = @embedFile("../../../vectors/fields.json");
    return std.json.parseFromSlice(VectorFile, allocator, raw, .{
        .ignore_unknown_fields = false,
    });
}

fn m31From(x: u32) M31 {
    return M31.fromCanonical(x);
}

fn cm31From(v: [2]u32) CM31 {
    return CM31.fromU32Unchecked(v[0], v[1]);
}

fn qm31From(v: [4]u32) QM31 {
    return QM31.fromU32Unchecked(v[0], v[1], v[2], v[3]);
}

fn encodeCM31(v: CM31) [2]u32 {
    return .{ v.a.toU32(), v.b.toU32() };
}

fn encodeQM31(v: QM31) [4]u32 {
    return .{
        v.c0.a.toU32(),
        v.c0.b.toU32(),
        v.c1.a.toU32(),
        v.c1.b.toU32(),
    };
}

fn circleM31From(v: [2]u32) CirclePointM31 {
    return .{
        .x = m31From(v[0]),
        .y = m31From(v[1]),
    };
}

fn circleQM31From(v: [2][4]u32) CirclePointQM31 {
    return .{
        .x = qm31From(v[0]),
        .y = qm31From(v[1]),
    };
}

fn pointSampleFrom(v: PointSampleVector) PointSample {
    return .{
        .point = circleQM31From(v.point),
        .value = qm31From(v.value),
    };
}

fn sampleWithRandomnessFrom(v: SampleWithRandomnessVector) SampleWithRandomness {
    return .{
        .sample = pointSampleFrom(v.sample),
        .random_coeff = qm31From(v.random_coeff),
    };
}

fn decodeColumnLogSizes(
    allocator: std.mem.Allocator,
    encoded: [][]u32,
) !quotients_mod.TreeVec([]u32) {
    const trees = try allocator.alloc([]u32, encoded.len);
    errdefer allocator.free(trees);

    var initialized: usize = 0;
    errdefer {
        for (trees[0..initialized]) |tree| allocator.free(tree);
    }

    for (encoded, 0..) |tree, i| {
        trees[i] = try allocator.dupe(u32, tree);
        initialized += 1;
    }
    return quotients_mod.TreeVec([]u32).initOwned(trees);
}

fn decodeSamplesTree(
    allocator: std.mem.Allocator,
    encoded: [][][]PointSampleVector,
) !quotients_mod.TreeVec([][]PointSample) {
    var trees_builder = std.ArrayList([][]PointSample).init(allocator);
    defer trees_builder.deinit();
    errdefer {
        for (trees_builder.items) |tree| {
            for (tree) |col| allocator.free(col);
            allocator.free(tree);
        }
    }

    for (encoded) |tree| {
        var cols_builder = std.ArrayList([]PointSample).init(allocator);
        defer cols_builder.deinit();
        errdefer {
            for (cols_builder.items) |col| allocator.free(col);
        }

        for (tree) |col| {
            const decoded_col = try allocator.alloc(PointSample, col.len);
            errdefer allocator.free(decoded_col);
            for (col, 0..) |sample, i| decoded_col[i] = pointSampleFrom(sample);
            try cols_builder.append(decoded_col);
        }
        try trees_builder.append(try cols_builder.toOwnedSlice());
    }

    return quotients_mod.TreeVec([][]PointSample).initOwned(try trees_builder.toOwnedSlice());
}

fn decodeQueriedValuesTree(
    allocator: std.mem.Allocator,
    encoded: [][][]u32,
) !quotients_mod.TreeVec([][]M31) {
    var trees_builder = std.ArrayList([][]M31).init(allocator);
    defer trees_builder.deinit();
    errdefer {
        for (trees_builder.items) |tree| {
            for (tree) |col| allocator.free(col);
            allocator.free(tree);
        }
    }

    for (encoded) |tree| {
        var cols_builder = std.ArrayList([]M31).init(allocator);
        defer cols_builder.deinit();
        errdefer {
            for (cols_builder.items) |col| allocator.free(col);
        }

        for (tree) |col| {
            const decoded_col = try allocator.alloc(M31, col.len);
            errdefer allocator.free(decoded_col);
            for (col, 0..) |value, i| decoded_col[i] = m31From(value);
            try cols_builder.append(decoded_col);
        }
        try trees_builder.append(try cols_builder.toOwnedSlice());
    }

    return quotients_mod.TreeVec([][]M31).initOwned(try trees_builder.toOwnedSlice());
}

fn decodeQm31Tree(
    allocator: std.mem.Allocator,
    encoded: [][][][4]u32,
) !quotients_mod.TreeVec([][]QM31) {
    var trees_builder = std.ArrayList([][]QM31).init(allocator);
    defer trees_builder.deinit();
    errdefer {
        for (trees_builder.items) |tree| {
            for (tree) |col| allocator.free(col);
            allocator.free(tree);
        }
    }

    for (encoded) |tree| {
        var cols_builder = std.ArrayList([]QM31).init(allocator);
        defer cols_builder.deinit();
        errdefer {
            for (cols_builder.items) |col| allocator.free(col);
        }

        for (tree) |col| {
            const decoded_col = try allocator.alloc(QM31, col.len);
            errdefer allocator.free(decoded_col);
            for (col, 0..) |value, i| decoded_col[i] = qm31From(value);
            try cols_builder.append(decoded_col);
        }
        try trees_builder.append(try cols_builder.toOwnedSlice());
    }

    return quotients_mod.TreeVec([][]QM31).initOwned(try trees_builder.toOwnedSlice());
}

fn decodeQm31Slice(allocator: std.mem.Allocator, encoded: [][4]u32) ![]QM31 {
    const out = try allocator.alloc(QM31, encoded.len);
    for (encoded, 0..) |value, i| out[i] = qm31From(value);
    return out;
}

test "field vectors: m31 parity" {
    var parsed = try parseVectors(std.testing.allocator);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.m31.len == parsed.value.meta.sample_count);
    for (parsed.value.m31) |v| {
        const a = m31From(v.a);
        const b = m31From(v.b);
        try std.testing.expect(a.add(b).eql(m31From(v.add)));
        try std.testing.expect(a.sub(b).eql(m31From(v.sub)));
        try std.testing.expect(a.mul(b).eql(m31From(v.mul)));
        try std.testing.expect((try a.inv()).eql(m31From(v.inv_a)));
        try std.testing.expect((try a.div(b)).eql(m31From(v.div_ab)));
    }
}

test "field vectors: cm31 parity" {
    var parsed = try parseVectors(std.testing.allocator);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.cm31.len == parsed.value.meta.sample_count);
    for (parsed.value.cm31) |v| {
        const a = cm31From(v.a);
        const b = cm31From(v.b);
        try std.testing.expect(a.add(b).eql(cm31From(v.add)));
        try std.testing.expect(a.sub(b).eql(cm31From(v.sub)));
        try std.testing.expect(a.mul(b).eql(cm31From(v.mul)));
        try std.testing.expect((try a.inv()).eql(cm31From(v.inv_a)));
        try std.testing.expect((try a.div(b)).eql(cm31From(v.div_ab)));
    }
}

test "field vectors: qm31 parity" {
    var parsed = try parseVectors(std.testing.allocator);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.qm31.len == parsed.value.meta.sample_count);
    for (parsed.value.qm31) |v| {
        const a = qm31From(v.a);
        const b = qm31From(v.b);
        try std.testing.expect(a.add(b).eql(qm31From(v.add)));
        try std.testing.expect(a.sub(b).eql(qm31From(v.sub)));
        try std.testing.expect(a.mul(b).eql(qm31From(v.mul)));
        try std.testing.expect((try a.inv()).eql(qm31From(v.inv_a)));
        try std.testing.expect((try a.div(b)).eql(qm31From(v.div_ab)));
    }
}

test "field vectors: circle m31 parity" {
    var parsed = try parseVectors(std.testing.allocator);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.circle_m31.len == parsed.value.meta.sample_count);
    for (parsed.value.circle_m31) |v| {
        const a = M31_CIRCLE_GEN.mul(@as(u128, v.a_scalar));
        const b = M31_CIRCLE_GEN.mul(@as(u128, v.b_scalar));
        try std.testing.expect(a.eql(circleM31From(v.a)));
        try std.testing.expect(b.eql(circleM31From(v.b)));
        try std.testing.expectEqual(v.log_order_a, a.logOrder());
        try std.testing.expect(a.add(b).eql(circleM31From(v.add)));
        try std.testing.expect(a.sub(b).eql(circleM31From(v.sub)));
        try std.testing.expect(a.double().eql(circleM31From(v.double_a)));
        try std.testing.expect(a.conjugate().eql(circleM31From(v.conjugate_a)));
    }
}

test "field vectors: fft m31 parity" {
    var parsed = try parseVectors(std.testing.allocator);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.fft_m31.len == parsed.value.meta.sample_count);
    for (parsed.value.fft_m31) |v| {
        var a = m31From(v.a);
        var b = m31From(v.b);
        const twid = m31From(v.twid);

        fft_mod.butterfly(M31, &a, &b, twid);
        try std.testing.expect(a.eql(m31From(v.butterfly[0])));
        try std.testing.expect(b.eql(m31From(v.butterfly[1])));

        const itwid = try twid.inv();
        fft_mod.ibutterfly(M31, &a, &b, itwid);
        try std.testing.expect(a.eql(m31From(v.ibutterfly[0])));
        try std.testing.expect(b.eql(m31From(v.ibutterfly[1])));
    }
}

test "field vectors: blake3 parity" {
    var parsed = try parseVectors(std.testing.allocator);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.blake3.len > 0);
    for (parsed.value.blake3) |v| {
        const hash = vcs_blake3.Blake3Hasher.hash(v.data);
        try std.testing.expectEqualSlices(u8, v.hash[0..], hash[0..]);

        const concat = vcs_blake3.Blake3Hasher.concatAndHash(v.left, v.right);
        try std.testing.expectEqualSlices(u8, v.concat_hash[0..], concat[0..]);
    }
}

test "field vectors: pcs quotients parity" {
    const alloc = std.testing.allocator;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.pcs_quotients.len > 0);
    for (parsed.value.pcs_quotients) |v| {
        var column_log_sizes = try decodeColumnLogSizes(alloc, v.column_log_sizes);
        defer column_log_sizes.deinitDeep(alloc);
        var samples = try decodeSamplesTree(alloc, v.samples);
        defer samples.deinitDeep(alloc);
        var queried_values = try decodeQueriedValuesTree(alloc, v.queried_values);
        defer queried_values.deinitDeep(alloc);
        const random_coeff = qm31From(v.random_coeff);

        var samples_with_randomness = try quotients_mod.buildSamplesWithRandomnessAndPeriodicity(
            alloc,
            samples,
            column_log_sizes,
            v.lifting_log_size,
            random_coeff,
        );
        defer samples_with_randomness.deinitDeep(alloc);

        try std.testing.expectEqual(v.samples_with_randomness.len, samples_with_randomness.items.len);
        for (v.samples_with_randomness, 0..) |expected_tree, tree_idx| {
            try std.testing.expectEqual(expected_tree.len, samples_with_randomness.items[tree_idx].len);
            for (expected_tree, 0..) |expected_col, col_idx| {
                try std.testing.expectEqual(expected_col.len, samples_with_randomness.items[tree_idx][col_idx].len);
                for (expected_col, 0..) |expected_sample, sample_idx| {
                    const actual = samples_with_randomness.items[tree_idx][col_idx][sample_idx];
                    const decoded_expected = sampleWithRandomnessFrom(expected_sample);
                    try std.testing.expect(actual.sample.point.eql(decoded_expected.sample.point));
                    try std.testing.expect(actual.sample.value.eql(decoded_expected.sample.value));
                    try std.testing.expect(actual.random_coeff.eql(decoded_expected.random_coeff));
                }
            }
        }

        var flat_samples = std.ArrayList([]const SampleWithRandomness).init(alloc);
        defer flat_samples.deinit();
        for (samples_with_randomness.items) |tree| {
            for (tree) |col| try flat_samples.append(col);
        }

        const sample_batches = try ColumnSampleBatch.newVec(alloc, flat_samples.items);
        defer ColumnSampleBatch.deinitSlice(alloc, sample_batches);

        try std.testing.expectEqual(v.sample_batches.len, sample_batches.len);
        for (v.sample_batches, 0..) |expected_batch, batch_idx| {
            const actual_batch = sample_batches[batch_idx];
            try std.testing.expect(actual_batch.point.eql(circleQM31From(expected_batch.point)));
            try std.testing.expectEqual(expected_batch.cols_vals_randpows.len, actual_batch.cols_vals_randpows.len);
            for (expected_batch.cols_vals_randpows, 0..) |expected_num, num_idx| {
                const actual_num: NumeratorData = actual_batch.cols_vals_randpows[num_idx];
                try std.testing.expectEqual(expected_num.column_index, actual_num.column_index);
                try std.testing.expect(actual_num.sample_value.eql(qm31From(expected_num.sample_value)));
                try std.testing.expect(actual_num.random_coeff.eql(qm31From(expected_num.random_coeff)));
            }
        }

        var q_consts = try quotients_mod.quotientConstants(alloc, sample_batches);
        defer q_consts.deinit(alloc);

        try std.testing.expectEqual(v.line_coeffs.len, q_consts.line_coeffs.len);
        for (v.line_coeffs, 0..) |expected_batch_coeffs, batch_idx| {
            try std.testing.expectEqual(expected_batch_coeffs.len, q_consts.line_coeffs[batch_idx].len);
            for (expected_batch_coeffs, 0..) |expected_coeff, coeff_idx| {
                const actual: LineCoeffs = q_consts.line_coeffs[batch_idx][coeff_idx];
                try std.testing.expect(actual.a.eql(qm31From(expected_coeff.a)));
                try std.testing.expect(actual.b.eql(qm31From(expected_coeff.b)));
                try std.testing.expect(actual.c.eql(qm31From(expected_coeff.c)));
            }
        }

        var queried_values_flat = std.ArrayList([]const M31).init(alloc);
        defer queried_values_flat.deinit();
        for (queried_values.items) |tree| {
            for (tree) |col| try queried_values_flat.append(col);
        }

        const row_values = try alloc.alloc(M31, queried_values_flat.items.len);
        defer alloc.free(row_values);
        const sample_points = try alloc.alloc(CirclePointQM31, sample_batches.len);
        defer alloc.free(sample_points);
        for (sample_batches, 0..) |batch, i| sample_points[i] = batch.point;

        const domain = canonic_mod.CanonicCoset.new(v.lifting_log_size).circleDomain();
        try std.testing.expectEqual(v.query_positions.len, v.denominator_inverses.len);
        try std.testing.expectEqual(v.query_positions.len, v.partial_numerators.len);
        try std.testing.expectEqual(v.query_positions.len, v.row_quotients.len);
        try std.testing.expectEqual(v.query_positions.len, v.fri_answers.len);

        for (v.query_positions, 0..) |position, row_idx| {
            for (queried_values_flat.items, 0..) |column, col_idx| {
                row_values[col_idx] = column[row_idx];
            }
            const domain_point = domain.at(utils_mod.bitReverseIndex(position, v.lifting_log_size));

            const den_inv = try quotients_mod.denominatorInverses(alloc, sample_points, domain_point);
            defer alloc.free(den_inv);
            try std.testing.expectEqual(v.denominator_inverses[row_idx].len, den_inv.len);
            for (v.denominator_inverses[row_idx], 0..) |expected_inv, i| {
                const encoded_inv = encodeCM31(den_inv[i]);
                try std.testing.expectEqualSlices(u32, expected_inv[0..], encoded_inv[0..]);
            }

            try std.testing.expectEqual(v.partial_numerators[row_idx].len, sample_batches.len);
            for (sample_batches, 0..) |batch, batch_idx| {
                const partial = try quotients_mod.accumulateRowPartialNumerators(
                    &batch,
                    row_values,
                    q_consts.line_coeffs[batch_idx],
                );
                try std.testing.expectEqualSlices(
                    u32,
                    v.partial_numerators[row_idx][batch_idx][0..],
                    encodeQM31(partial)[0..],
                );
            }

            const row_quot = try quotients_mod.accumulateRowQuotients(
                alloc,
                sample_batches,
                row_values,
                &q_consts,
                domain_point,
            );
            try std.testing.expectEqualSlices(u32, v.row_quotients[row_idx][0..], encodeQM31(row_quot)[0..]);
        }

        const fri_answers = try quotients_mod.friAnswers(
            alloc,
            column_log_sizes,
            samples,
            random_coeff,
            v.query_positions,
            queried_values,
            v.lifting_log_size,
        );
        defer alloc.free(fri_answers);
        for (v.fri_answers, 0..) |expected, i| {
            try std.testing.expectEqualSlices(u32, expected[0..], encodeQM31(fri_answers[i])[0..]);
        }
    }
}

test "field vectors: fri fold parity" {
    const alloc = std.testing.allocator;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.fri_folds.len > 0);
    for (parsed.value.fri_folds) |v| {
        const line_domain = try line_mod.LineDomain.init(circle_mod.Coset.halfOdds(v.line_log_size));
        const line_eval = try alloc.alloc(QM31, v.line_eval.len);
        defer alloc.free(line_eval);
        for (v.line_eval, 0..) |value, i| line_eval[i] = qm31From(value);

        const folded_line = try fri_mod.foldLine(alloc, line_eval, line_domain, qm31From(v.alpha));
        defer alloc.free(folded_line.values);
        try std.testing.expectEqual(v.fold_line_values.len, folded_line.values.len);
        for (v.fold_line_values, 0..) |expected, i| {
            try std.testing.expectEqualSlices(u32, expected[0..], encodeQM31(folded_line.values[i])[0..]);
        }

        const circle_domain = canonic_mod.CanonicCoset.new(v.circle_log_size).circleDomain();
        const circle_eval = try alloc.alloc(QM31, v.circle_eval.len);
        defer alloc.free(circle_eval);
        for (v.circle_eval, 0..) |value, i| circle_eval[i] = qm31From(value);

        const folded_circle = try alloc.alloc(QM31, v.fold_circle_values.len);
        defer alloc.free(folded_circle);
        @memset(folded_circle, QM31.zero());
        try fri_mod.foldCircleIntoLine(folded_circle, circle_eval, circle_domain, qm31From(v.alpha));
        try std.testing.expectEqual(v.fold_circle_values.len, folded_circle.len);
        for (v.fold_circle_values, 0..) |expected, i| {
            try std.testing.expectEqualSlices(u32, expected[0..], encodeQM31(folded_circle[i])[0..]);
        }
    }
}

test "field vectors: proof extract oods parity" {
    const alloc = std.testing.allocator;
    const Hasher = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const vcs_verifier = @import("../vcs_lifted/verifier.zig");
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.proof_extract_oods.len > 0);
    for (parsed.value.proof_extract_oods) |v| {
        const composition_tree = try alloc.alloc([]QM31, v.composition_values.len);
        var initialized: usize = 0;
        errdefer {
            for (composition_tree[0..initialized]) |col| alloc.free(col);
            alloc.free(composition_tree);
        }
        for (v.composition_values, 0..) |value, i| {
            composition_tree[i] = try alloc.alloc(QM31, 1);
            composition_tree[i][0] = qm31From(value);
            initialized += 1;
        }

        const sampled_values = quotients_mod.TreeVec([][]QM31).initOwned(
            try alloc.dupe([][]QM31, &[_][][]QM31{composition_tree}),
        );
        var proof = proof_mod.StarkProof(Hasher){
            .commitment_scheme_proof = .{
                .config = pcs_mod.PcsConfig.default(),
                .commitments = quotients_mod.TreeVec(Hasher.Hash).initOwned(
                    try alloc.alloc(Hasher.Hash, 0),
                ),
                .sampled_values = sampled_values,
                .decommitments = quotients_mod.TreeVec(vcs_verifier.MerkleDecommitmentLifted(Hasher)).initOwned(
                    try alloc.alloc(vcs_verifier.MerkleDecommitmentLifted(Hasher), 0),
                ),
                .queried_values = quotients_mod.TreeVec([][]M31).initOwned(
                    try alloc.alloc([][]M31, 0),
                ),
                .proof_of_work = 0,
                .fri_proof = .{
                    .first_layer = .{
                        .fri_witness = try alloc.alloc(QM31, 0),
                        .decommitment = .{ .hash_witness = try alloc.alloc(Hasher.Hash, 0) },
                        .commitment = [_]u8{0} ** 32,
                    },
                    .inner_layers = try alloc.alloc(fri_mod.FriLayerProof(Hasher), 0),
                    .last_layer_poly = line_mod.LinePoly.initOwned(
                        try alloc.dupe(QM31, &[_]QM31{QM31.one()}),
                    ),
                },
            },
        };
        defer proof.deinit(alloc);

        const extracted = proof.extractCompositionOodsEval(
            circleQM31From(v.oods_point),
            v.composition_log_size,
        ) orelse unreachable;
        try std.testing.expectEqualSlices(u32, v.expected[0..], encodeQM31(extracted)[0..]);
    }
}

test "field vectors: proof size breakdown parity" {
    const alloc = std.testing.allocator;
    const Hasher = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const vcs_verifier = @import("../vcs_lifted/verifier.zig");
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.proof_sizes.len > 0);
    for (parsed.value.proof_sizes) |v| {
        var sampled_values = try decodeQm31Tree(alloc, v.sampled_values);
        var queried_values = try decodeQueriedValuesTree(alloc, v.queried_values);
        var sampled_values_moved = false;
        var queried_values_moved = false;
        defer if (!sampled_values_moved) sampled_values.deinitDeep(alloc);
        defer if (!queried_values_moved) queried_values.deinitDeep(alloc);

        var commitments = pcs_mod.TreeVec(Hasher.Hash).initOwned(
            try alloc.dupe(Hasher.Hash, v.commitments),
        );
        var commitments_moved = false;
        defer if (!commitments_moved) commitments.deinit(alloc);

        const decommitments_vec = try alloc.alloc(vcs_verifier.MerkleDecommitmentLifted(Hasher), v.decommitments.len);
        errdefer alloc.free(decommitments_vec);
        var decommitments_initialized: usize = 0;
        errdefer {
            for (decommitments_vec[0..decommitments_initialized]) |*decommitment| decommitment.deinit(alloc);
        }
        for (v.decommitments, 0..) |witness, i| {
            decommitments_vec[i] = .{ .hash_witness = try alloc.dupe(Hasher.Hash, witness) };
            decommitments_initialized += 1;
        }
        var decommitments = pcs_mod.TreeVec(vcs_verifier.MerkleDecommitmentLifted(Hasher)).initOwned(decommitments_vec);
        var decommitments_moved = false;
        defer if (!decommitments_moved) {
            for (decommitments.items) |*decommitment| decommitment.deinit(alloc);
            decommitments.deinit(alloc);
        };

        const first_layer_witness = try decodeQm31Slice(alloc, v.first_layer_witness);
        errdefer alloc.free(first_layer_witness);
        const first_layer_decommitment = vcs_verifier.MerkleDecommitmentLifted(Hasher){
            .hash_witness = try alloc.dupe(Hasher.Hash, v.first_layer_decommitment),
        };
        errdefer {
            var tmp = first_layer_decommitment;
            tmp.deinit(alloc);
        }

        const inner_layers = try alloc.alloc(fri_mod.FriLayerProof(Hasher), v.inner_layers.len);
        errdefer alloc.free(inner_layers);
        var inner_layers_initialized: usize = 0;
        errdefer {
            for (inner_layers[0..inner_layers_initialized]) |*layer| layer.deinit(alloc);
        }
        for (v.inner_layers, 0..) |inner, i| {
            inner_layers[i] = .{
                .fri_witness = try decodeQm31Slice(alloc, inner.fri_witness),
                .decommitment = .{ .hash_witness = try alloc.dupe(Hasher.Hash, inner.decommitment) },
                .commitment = inner.commitment,
            };
            inner_layers_initialized += 1;
        }

        const last_layer_poly_coeffs = try decodeQm31Slice(alloc, v.last_layer_poly);
        errdefer alloc.free(last_layer_poly_coeffs);

        sampled_values_moved = true;
        queried_values_moved = true;
        commitments_moved = true;
        decommitments_moved = true;
        var proof = proof_mod.StarkProof(Hasher){
            .commitment_scheme_proof = .{
                .config = pcs_mod.PcsConfig.default(),
                .commitments = commitments,
                .sampled_values = sampled_values,
                .decommitments = decommitments,
                .queried_values = queried_values,
                .proof_of_work = v.proof_of_work,
                .fri_proof = .{
                    .first_layer = .{
                        .fri_witness = first_layer_witness,
                        .decommitment = first_layer_decommitment,
                        .commitment = v.first_layer_commitment,
                    },
                    .inner_layers = inner_layers,
                    .last_layer_poly = line_mod.LinePoly.initOwned(last_layer_poly_coeffs),
                },
            },
        };
        defer proof.deinit(alloc);

        const actual = proof.sizeBreakdownEstimate();
        try std.testing.expectEqual(v.expected_breakdown.oods_samples, actual.oods_samples);
        try std.testing.expectEqual(v.expected_breakdown.queries_values, actual.queries_values);
        try std.testing.expectEqual(v.expected_breakdown.fri_samples, actual.fri_samples);
        try std.testing.expectEqual(v.expected_breakdown.fri_decommitments, actual.fri_decommitments);
        try std.testing.expectEqual(v.expected_breakdown.trace_decommitments, actual.trace_decommitments);
    }
}

test "field vectors: prover line interpolation parity" {
    const alloc = std.testing.allocator;
    const LineEvaluation = prover_line_mod.LineEvaluation;

    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.meta.schema_version >= 1);
    try std.testing.expect(parsed.value.prover_line.len > 0);
    for (parsed.value.prover_line) |v| {
        const domain = try line_mod.LineDomain.init(circle_mod.Coset.halfOdds(v.line_log_size));

        const values = try alloc.alloc(QM31, v.values.len);
        for (v.values, 0..) |value, i| values[i] = qm31From(value);

        var eval = try LineEvaluation.initOwned(domain, values);
        var poly = try eval.interpolate(alloc);
        defer poly.deinit(alloc);

        const coeffs_bit_reversed = poly.coefficients();
        try std.testing.expectEqual(v.coeffs_bit_reversed.len, coeffs_bit_reversed.len);
        for (v.coeffs_bit_reversed, 0..) |expected, i| {
            try std.testing.expect(coeffs_bit_reversed[i].eql(qm31From(expected)));
        }

        const coeffs_ordered = poly.intoOrderedCoefficients();
        try std.testing.expectEqual(v.coeffs_ordered.len, coeffs_ordered.len);
        for (v.coeffs_ordered, 0..) |expected, i| {
            try std.testing.expect(coeffs_ordered[i].eql(qm31From(expected)));
        }

        if (v.values.len > 0) {
            const mutated_values = try alloc.alloc(QM31, v.values.len);
            for (v.values, 0..) |value, i| mutated_values[i] = qm31From(value);
            mutated_values[0] = mutated_values[0].add(QM31.one());

            var mutated_eval = try LineEvaluation.initOwned(domain, mutated_values);
            var mutated_poly = try mutated_eval.interpolate(alloc);
            defer mutated_poly.deinit(alloc);

            var differs = false;
            for (mutated_poly.coefficients(), 0..) |actual, i| {
                if (!actual.eql(qm31From(v.coeffs_bit_reversed[i]))) {
                    differs = true;
                    break;
                }
            }
            try std.testing.expect(differs);
        }
    }
}

test "field vectors: vcs verifier parity" {
    const alloc = std.testing.allocator;
    const Hasher = @import("../vcs/blake2_merkle.zig").Blake2sMerkleHasher;
    const Verifier = vcs_verifier_mod.MerkleVerifier(Hasher);
    const Decommitment = vcs_verifier_mod.MerkleDecommitment(Hasher);

    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.vcs_verifier.len > 0);
    for (parsed.value.vcs_verifier) |v| {
        var verifier = try Verifier.init(alloc, v.root, v.column_log_sizes);
        defer verifier.deinit(alloc);

        const queries = try alloc.alloc(vcs_verifier_mod.LogSizeQueries, v.queries_per_log_size.len);
        defer alloc.free(queries);
        for (v.queries_per_log_size, 0..) |entry, i| {
            queries[i] = .{
                .log_size = entry.log_size,
                .queries = entry.queries,
            };
        }

        const queried_values = try alloc.alloc(M31, v.queried_values.len);
        defer alloc.free(queried_values);
        for (v.queried_values, 0..) |value, i| queried_values[i] = m31From(value);

        var decommitment = Decommitment{
            .hash_witness = try alloc.dupe(Hasher.Hash, v.hash_witness),
            .column_witness = try alloc.alloc(M31, v.column_witness.len),
        };
        for (v.column_witness, 0..) |value, i| decommitment.column_witness[i] = m31From(value);
        defer decommitment.deinit(alloc);

        if (std.mem.eql(u8, v.expected, "ok")) {
            try verifier.verify(alloc, queries, queried_values, decommitment);
        } else {
            try std.testing.expectError(
                expectedVcsError(v.expected),
                verifier.verify(alloc, queries, queried_values, decommitment),
            );
        }
    }
}

test "field vectors: vcs prover parity" {
    const alloc = std.testing.allocator;
    const Hasher = @import("../vcs/blake2_merkle.zig").Blake2sMerkleHasher;
    const Prover = vcs_prover_mod.MerkleProver(Hasher);
    const Verifier = vcs_verifier_mod.MerkleVerifier(Hasher);
    const LogSizeQueries = vcs_verifier_mod.LogSizeQueries;

    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.vcs_prover.len > 0);
    for (parsed.value.vcs_prover) |v| {
        const columns = try alloc.alloc([]const M31, v.columns.len);
        defer alloc.free(columns);

        const owned_columns = try alloc.alloc([]M31, v.columns.len);
        defer {
            for (owned_columns) |col| alloc.free(col);
            alloc.free(owned_columns);
        }

        for (v.columns, 0..) |column, i| {
            owned_columns[i] = try alloc.alloc(M31, column.len);
            for (column, 0..) |value, j| owned_columns[i][j] = m31From(value);
            columns[i] = owned_columns[i];
        }

        var prover = try Prover.commit(alloc, columns);
        defer prover.deinit(alloc);

        try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&prover.root()), std.mem.asBytes(&v.root)));

        const queries = try alloc.alloc(LogSizeQueries, v.queries_per_log_size.len);
        defer alloc.free(queries);
        for (v.queries_per_log_size, 0..) |entry, i| {
            queries[i] = .{
                .log_size = entry.log_size,
                .queries = entry.queries,
            };
        }

        var decommitment = try prover.decommit(alloc, queries, columns);
        defer decommitment.deinit(alloc);

        try std.testing.expectEqual(v.queried_values.len, decommitment.queried_values.len);
        for (v.queried_values, 0..) |value, i| {
            try std.testing.expect(m31From(value).eql(decommitment.queried_values[i]));
        }

        try std.testing.expectEqual(
            v.hash_witness.len,
            decommitment.decommitment.decommitment.hash_witness.len,
        );
        for (v.hash_witness, 0..) |hash, i| {
            try std.testing.expect(std.mem.eql(
                u8,
                std.mem.asBytes(&hash),
                std.mem.asBytes(&decommitment.decommitment.decommitment.hash_witness[i]),
            ));
        }

        try std.testing.expectEqual(
            v.column_witness.len,
            decommitment.decommitment.decommitment.column_witness.len,
        );
        for (v.column_witness, 0..) |value, i| {
            try std.testing.expect(m31From(value).eql(
                decommitment.decommitment.decommitment.column_witness[i],
            ));
        }

        var verifier = try Verifier.init(alloc, prover.root(), v.column_log_sizes);
        defer verifier.deinit(alloc);
        try verifier.verify(
            alloc,
            queries,
            decommitment.queried_values,
            decommitment.decommitment.decommitment,
        );
    }
}

test "field vectors: vcs lifted verifier parity" {
    const alloc = std.testing.allocator;
    const Hasher = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const Verifier = @import("../vcs_lifted/verifier.zig").MerkleVerifierLifted(Hasher);
    const Decommitment = @import("../vcs_lifted/verifier.zig").MerkleDecommitmentLifted(Hasher);

    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.vcs_lifted_verifier.len > 0);
    for (parsed.value.vcs_lifted_verifier) |v| {
        var verifier = try Verifier.init(alloc, v.root, v.column_log_sizes);
        defer verifier.deinit(alloc);

        const queried_values = try alloc.alloc([]const M31, v.queried_values.len);
        defer alloc.free(queried_values);

        const queried_values_owned = try alloc.alloc([]M31, v.queried_values.len);
        defer {
            for (queried_values_owned) |col| alloc.free(col);
            alloc.free(queried_values_owned);
        }

        for (v.queried_values, 0..) |column, i| {
            queried_values_owned[i] = try alloc.alloc(M31, column.len);
            for (column, 0..) |value, j| queried_values_owned[i][j] = m31From(value);
            queried_values[i] = queried_values_owned[i];
        }

        var decommitment = Decommitment{
            .hash_witness = try alloc.dupe(Hasher.Hash, v.hash_witness),
        };
        defer decommitment.deinit(alloc);

        if (std.mem.eql(u8, v.expected, "ok")) {
            try verifier.verify(
                alloc,
                v.query_positions,
                queried_values,
                decommitment,
            );
        } else {
            try std.testing.expectError(
                expectedVcsLiftedError(v.expected),
                verifier.verify(
                    alloc,
                    v.query_positions,
                    queried_values,
                    decommitment,
                ),
            );
        }
    }
}

test "field vectors: vcs lifted prover parity" {
    const alloc = std.testing.allocator;
    const Hasher = @import("../vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const Prover = vcs_lifted_prover_mod.MerkleProverLifted(Hasher);
    const Verifier = @import("../vcs_lifted/verifier.zig").MerkleVerifierLifted(Hasher);

    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.vcs_lifted_prover.len > 0);
    for (parsed.value.vcs_lifted_prover) |v| {
        const columns = try alloc.alloc([]const M31, v.columns.len);
        defer alloc.free(columns);

        const owned_columns = try alloc.alloc([]M31, v.columns.len);
        defer {
            for (owned_columns) |col| alloc.free(col);
            alloc.free(owned_columns);
        }

        for (v.columns, 0..) |column, i| {
            owned_columns[i] = try alloc.alloc(M31, column.len);
            for (column, 0..) |value, j| owned_columns[i][j] = m31From(value);
            columns[i] = owned_columns[i];
        }

        var prover = try Prover.commit(alloc, columns);
        defer prover.deinit(alloc);

        try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&prover.root()), std.mem.asBytes(&v.root)));

        var decommitment = try prover.decommit(alloc, v.query_positions, columns);
        defer decommitment.deinit(alloc);

        try std.testing.expectEqual(v.queried_values.len, decommitment.queried_values.len);
        for (v.queried_values, 0..) |column, i| {
            try std.testing.expectEqual(column.len, decommitment.queried_values[i].len);
            for (column, 0..) |value, j| {
                try std.testing.expect(m31From(value).eql(decommitment.queried_values[i][j]));
            }
        }

        try std.testing.expectEqual(
            v.hash_witness.len,
            decommitment.decommitment.decommitment.hash_witness.len,
        );
        for (v.hash_witness, 0..) |hash, i| {
            try std.testing.expect(std.mem.eql(
                u8,
                std.mem.asBytes(&hash),
                std.mem.asBytes(&decommitment.decommitment.decommitment.hash_witness[i]),
            ));
        }

        const queried_values = try alloc.alloc([]const M31, decommitment.queried_values.len);
        defer alloc.free(queried_values);
        for (decommitment.queried_values, 0..) |column, i| queried_values[i] = column;

        var verifier = try Verifier.init(alloc, prover.root(), v.column_log_sizes);
        defer verifier.deinit(alloc);
        try verifier.verify(
            alloc,
            v.query_positions,
            queried_values,
            decommitment.decommitment.decommitment,
        );
    }
}

fn expectedVcsError(name: []const u8) vcs_verifier_mod.MerkleVerificationError {
    if (std.mem.eql(u8, name, "WitnessTooShort")) return vcs_verifier_mod.MerkleVerificationError.WitnessTooShort;
    if (std.mem.eql(u8, name, "WitnessTooLong")) return vcs_verifier_mod.MerkleVerificationError.WitnessTooLong;
    if (std.mem.eql(u8, name, "TooManyQueriedValues")) return vcs_verifier_mod.MerkleVerificationError.TooManyQueriedValues;
    if (std.mem.eql(u8, name, "TooFewQueriedValues")) return vcs_verifier_mod.MerkleVerificationError.TooFewQueriedValues;
    if (std.mem.eql(u8, name, "RootMismatch")) return vcs_verifier_mod.MerkleVerificationError.RootMismatch;
    unreachable;
}

fn expectedVcsLiftedError(name: []const u8) @import("../vcs_lifted/verifier.zig").MerkleVerificationError {
    const lifted_verifier = @import("../vcs_lifted/verifier.zig");
    if (std.mem.eql(u8, name, "WitnessTooShort")) return lifted_verifier.MerkleVerificationError.WitnessTooShort;
    if (std.mem.eql(u8, name, "WitnessTooLong")) return lifted_verifier.MerkleVerificationError.WitnessTooLong;
    if (std.mem.eql(u8, name, "RootMismatch")) return lifted_verifier.MerkleVerificationError.RootMismatch;
    unreachable;
}

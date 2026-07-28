//! Rust-oracle vector schemas and decoding helpers.

const std = @import("std");
const circle_mod = @import("stwo_core").circle;
const constraints_mod = @import("stwo_core").constraints;
const fft_mod = @import("stwo_core").fft;
const fri_mod = @import("stwo_core").fri;
const pcs_mod = @import("stwo_core").pcs;
const pcs_utils_mod = @import("stwo_core").pcs.utils;
const proof_mod = @import("stwo_core").proof;
const quotients_mod = @import("stwo_core").pcs.quotients;
const canonic_mod = @import("stwo_core").poly.circle.canonic;
const line_mod = @import("stwo_core").poly.line;
const utils_mod = @import("stwo_core").utils;
const vcs_verifier_mod = @import("stwo_core").vcs.verifier;
const vcs_blake3 = @import("stwo_core").vcs.blake3_hash;
const prover_fri_mod = @import("stwo_prover_engine").fri;
const prover_secure_column_mod = @import("stwo_prover_engine").secure_column;
const vcs_prover_mod = @import("stwo_prover_engine").vcs.prover;
const vcs_lifted_prover_mod = @import("stwo_prover_engine").vcs_lifted.prover;
const prover_line_mod = @import("stwo_prover_engine").line;
const example_plonk_mod = @import("stwo_native_examples").plonk;
const example_state_machine_mod = @import("stwo_native_examples").state_machine;
const example_wide_fibonacci_mod = @import("stwo_native_examples").wide_fibonacci;
const example_xor_mod = @import("stwo_native_examples").xor;
const cm31_mod = @import("stwo_core").fields.cm31;
const m31_mod = @import("stwo_core").fields.m31;
const qm31_mod = @import("stwo_core").fields.qm31;

pub const CirclePointM31 = circle_mod.CirclePointM31;
pub const CirclePointQM31 = circle_mod.CirclePointQM31;
pub const M31_CIRCLE_GEN = circle_mod.M31_CIRCLE_GEN;
pub const M31 = m31_mod.M31;
pub const CM31 = cm31_mod.CM31;
pub const QM31 = qm31_mod.QM31;
pub const PointSample = quotients_mod.PointSample;
pub const SampleWithRandomness = quotients_mod.SampleWithRandomness;
pub const NumeratorData = quotients_mod.NumeratorData;
pub const ColumnSampleBatch = quotients_mod.ColumnSampleBatch;
pub const LineCoeffs = constraints_mod.LineCoeffs;

pub const M31Vector = struct {
    a: u32,
    b: u32,
    add: u32,
    sub: u32,
    mul: u32,
    inv_a: u32,
    div_ab: u32,
};

pub const CM31Vector = struct {
    a: [2]u32,
    b: [2]u32,
    add: [2]u32,
    sub: [2]u32,
    mul: [2]u32,
    inv_a: [2]u32,
    div_ab: [2]u32,
};

pub const QM31Vector = struct {
    a: [4]u32,
    b: [4]u32,
    add: [4]u32,
    sub: [4]u32,
    mul: [4]u32,
    inv_a: [4]u32,
    div_ab: [4]u32,
};

pub const CircleM31Vector = struct {
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

pub const FftM31Vector = struct {
    a: u32,
    b: u32,
    twid: u32,
    butterfly: [2]u32,
    ibutterfly: [2]u32,
};

pub const Blake3Vector = struct {
    data: []u8,
    hash: [32]u8,
    left: [32]u8,
    right: [32]u8,
    concat_hash: [32]u8,
};

pub const PointSampleVector = struct {
    point: [2][4]u32,
    value: [4]u32,
};

pub const SampleWithRandomnessVector = struct {
    sample: PointSampleVector,
    random_coeff: [4]u32,
};

pub const NumeratorDataVector = struct {
    column_index: usize,
    sample_value: [4]u32,
    random_coeff: [4]u32,
};

pub const ColumnSampleBatchVector = struct {
    point: [2][4]u32,
    cols_vals_randpows: []NumeratorDataVector,
};

pub const LineCoeffVector = struct {
    a: [4]u32,
    b: [4]u32,
    c: [4]u32,
};

pub const PcsQuotientsVector = struct {
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

pub const PcsPreprocessedQueryVector = struct {
    query_positions: []usize,
    max_log_size: u32,
    pp_max_log_size: u32,
    expected: []usize,
};

pub const FriFoldVector = struct {
    line_log_size: u32,
    line_eval: [][4]u32,
    alpha: [4]u32,
    fold_line_values: [][4]u32,
    circle_log_size: u32,
    circle_eval: [][4]u32,
    fold_circle_values: [][4]u32,
};

pub const FriDecommitVector = struct {
    case: []const u8,
    fold_step: u32,
    column: [][4]u32,
    query_positions: []usize,
    decommitment_positions: []usize,
    witness_evals: [][4]u32,
    value_map_positions: []usize,
    value_map_values: [][4]u32,
    expected: []const u8,
};

pub const FriLayerDecommitVector = struct {
    case: []const u8,
    fold_step: u32,
    column: [][4]u32,
    query_positions: []usize,
    commitment: [32]u8,
    decommitment_positions: []usize,
    fri_witness: [][4]u32,
    hash_witness: [][32]u8,
    value_map_positions: []usize,
    value_map_values: [][4]u32,
    expected: []const u8,
};

pub const ProofExtractOodsVector = struct {
    composition_log_size: u32,
    oods_point: [2][4]u32,
    composition_values: [][4]u32,
    expected: [4]u32,
};

pub const ProofSizeBreakdownVector = struct {
    oods_samples: usize,
    queries_values: usize,
    fri_samples: usize,
    fri_decommitments: usize,
    trace_decommitments: usize,
};

pub const ProofSizeInnerLayerVector = struct {
    fri_witness: [][4]u32,
    decommitment: [][32]u8,
    commitment: [32]u8,
};

pub const ProofSizeVector = struct {
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

pub const ProverLineVector = struct {
    line_log_size: u32,
    values: [][4]u32,
    coeffs_bit_reversed: [][4]u32,
    coeffs_ordered: [][4]u32,
};

pub const VcsLogSizeQueriesVector = struct {
    log_size: u32,
    queries: []usize,
};

pub const VcsVerifierVector = struct {
    case: []const u8,
    root: [32]u8,
    column_log_sizes: []u32,
    queries_per_log_size: []VcsLogSizeQueriesVector,
    queried_values: []u32,
    hash_witness: [][32]u8,
    column_witness: []u32,
    expected: []const u8,
};

pub const VcsProverVector = struct {
    root: [32]u8,
    column_log_sizes: []u32,
    columns: [][]u32,
    queries_per_log_size: []VcsLogSizeQueriesVector,
    queried_values: []u32,
    hash_witness: [][32]u8,
    column_witness: []u32,
};

pub const VcsLiftedProverVector = struct {
    root: [32]u8,
    column_log_sizes: []u32,
    columns: [][]u32,
    query_positions: []usize,
    queried_values: [][]u32,
    hash_witness: [][32]u8,
};

pub const VcsLiftedVerifierVector = struct {
    case: []const u8,
    root: [32]u8,
    column_log_sizes: []u32,
    query_positions: []usize,
    queried_values: [][]u32,
    hash_witness: [][32]u8,
    expected: []const u8,
};

pub const ExampleStateMachineTraceVector = struct {
    log_size: u32,
    initial_state: [2]u32,
    inc_index: usize,
    columns: [][]u32,
};

pub const ExampleStateMachineTransitionVector = struct {
    log_n_rows: u32,
    initial_state: [2]u32,
    intermediate_state: [2]u32,
    final_state: [2]u32,
};

pub const ExampleStateMachineClaimedSumVector = struct {
    log_size: u32,
    initial_state: [2]u32,
    inc_index: usize,
    z: [4]u32,
    alpha: [4]u32,
    claimed_sum: [4]u32,
    telescoping_claim: [4]u32,
};

pub const ExampleStateMachineLookupDrawVector = struct {
    mix_u64: u64,
    mix_u32s: []u32,
    z: [4]u32,
    alpha: [4]u32,
};

pub const ExampleStateMachineStatementVector = struct {
    log_n_rows: u32,
    initial_state: [2]u32,
    z: [4]u32,
    alpha: [4]u32,
    intermediate_state: [2]u32,
    final_state: [2]u32,
    x_axis_claimed_sum: [4]u32,
    y_axis_claimed_sum: [4]u32,
};

pub const ExampleXorIsFirstVector = struct {
    log_size: u32,
    values: []u32,
};

pub const ExampleXorIsStepWithOffsetVector = struct {
    log_size: u32,
    log_step: u32,
    offset: usize,
    values: []u32,
};

pub const ExampleWideFibonacciTraceVector = struct {
    log_n_rows: u32,
    sequence_len: u32,
    columns: [][]u32,
};

pub const ExamplePlonkTraceVector = struct {
    log_n_rows: u32,
    preprocessed: [][]u32,
    main: [][]u32,
};

pub const VectorFile = struct {
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
    pcs_preprocessed_queries: []PcsPreprocessedQueryVector,
    fri_folds: []FriFoldVector,
    fri_decommit: []FriDecommitVector,
    fri_layer_decommit: []FriLayerDecommitVector,
    proof_extract_oods: []ProofExtractOodsVector,
    proof_sizes: []ProofSizeVector,
    prover_line: []ProverLineVector,
    vcs_verifier: []VcsVerifierVector,
    vcs_prover: []VcsProverVector,
    vcs_lifted_verifier: []VcsLiftedVerifierVector,
    vcs_lifted_prover: []VcsLiftedProverVector,
    example_state_machine_trace: []ExampleStateMachineTraceVector,
    example_state_machine_transitions: []ExampleStateMachineTransitionVector,
    example_state_machine_claimed_sum: []ExampleStateMachineClaimedSumVector,
    example_state_machine_lookup_draw: []ExampleStateMachineLookupDrawVector,
    example_state_machine_statement: []ExampleStateMachineStatementVector,
    example_xor_is_first: []ExampleXorIsFirstVector,
    example_xor_is_step_with_offset: []ExampleXorIsStepWithOffsetVector,
    example_wide_fibonacci_trace: []ExampleWideFibonacciTraceVector,
    example_plonk_trace: []ExamplePlonkTraceVector,
};

pub fn parseVectors(allocator: std.mem.Allocator) !std.json.Parsed(VectorFile) {
    const raw = try std.fs.cwd().readFileAlloc(
        allocator,
        "vectors/fields.json",
        16 * 1024 * 1024,
    );
    defer allocator.free(raw);
    return std.json.parseFromSlice(VectorFile, allocator, raw, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    });
}

pub fn m31From(x: u32) M31 {
    return M31.fromCanonical(x);
}

pub fn cm31From(v: [2]u32) CM31 {
    return CM31.fromU32Unchecked(v[0], v[1]);
}

pub fn qm31From(v: [4]u32) QM31 {
    return QM31.fromU32Unchecked(v[0], v[1], v[2], v[3]);
}

pub fn encodeCM31(v: CM31) [2]u32 {
    return .{ v.a.toU32(), v.b.toU32() };
}

pub fn encodeQM31(v: QM31) [4]u32 {
    return .{
        v.c0.a.toU32(),
        v.c0.b.toU32(),
        v.c1.a.toU32(),
        v.c1.b.toU32(),
    };
}

pub fn circleM31From(v: [2]u32) CirclePointM31 {
    return .{
        .x = m31From(v[0]),
        .y = m31From(v[1]),
    };
}

pub fn circleQM31From(v: [2][4]u32) CirclePointQM31 {
    return .{
        .x = qm31From(v[0]),
        .y = qm31From(v[1]),
    };
}

pub fn pointSampleFrom(v: PointSampleVector) PointSample {
    return .{
        .point = circleQM31From(v.point),
        .value = qm31From(v.value),
    };
}

pub fn sampleWithRandomnessFrom(v: SampleWithRandomnessVector) SampleWithRandomness {
    return .{
        .point = circleQM31From(v.sample.point),
        .value = qm31From(v.sample.value),
        .random_coeff = qm31From(v.random_coeff),
    };
}

pub fn decodeColumnLogSizes(
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

pub fn decodeSamplesTree(
    allocator: std.mem.Allocator,
    encoded: [][][]PointSampleVector,
) !quotients_mod.TreeVec([][]PointSample) {
    var trees_builder = std.ArrayList([][]PointSample).empty;
    defer trees_builder.deinit(allocator);
    errdefer {
        for (trees_builder.items) |tree| {
            for (tree) |col| allocator.free(col);
            allocator.free(tree);
        }
    }

    for (encoded) |tree| {
        var cols_builder = std.ArrayList([]PointSample).empty;
        defer cols_builder.deinit(allocator);
        errdefer {
            for (cols_builder.items) |col| allocator.free(col);
        }

        for (tree) |col| {
            const decoded_col = try allocator.alloc(PointSample, col.len);
            errdefer allocator.free(decoded_col);
            for (col, 0..) |sample, i| decoded_col[i] = pointSampleFrom(sample);
            try cols_builder.append(allocator, decoded_col);
        }
        try trees_builder.append(allocator, try cols_builder.toOwnedSlice(allocator));
    }

    return quotients_mod.TreeVec([][]PointSample).initOwned(try trees_builder.toOwnedSlice(allocator));
}

pub const SplitPointSamples = struct {
    points: quotients_mod.TreeVec([][]CirclePointQM31),
    values: quotients_mod.TreeVec([][]QM31),

    pub fn deinit(self: *SplitPointSamples, allocator: std.mem.Allocator) void {
        self.points.deinitDeep(allocator);
        self.values.deinitDeep(allocator);
        self.* = undefined;
    }
};

pub fn splitPointSamplesTree(
    allocator: std.mem.Allocator,
    samples: quotients_mod.TreeVec([][]PointSample),
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
        .points = quotients_mod.TreeVec([][]CirclePointQM31).initOwned(point_trees),
        .values = quotients_mod.TreeVec([][]QM31).initOwned(value_trees),
    };
}

pub fn decodeQueriedValuesTree(
    allocator: std.mem.Allocator,
    encoded: [][][]u32,
) !quotients_mod.TreeVec([][]M31) {
    var trees_builder = std.ArrayList([][]M31).empty;
    defer trees_builder.deinit(allocator);
    errdefer {
        for (trees_builder.items) |tree| {
            for (tree) |col| allocator.free(col);
            allocator.free(tree);
        }
    }

    for (encoded) |tree| {
        var cols_builder = std.ArrayList([]M31).empty;
        defer cols_builder.deinit(allocator);
        errdefer {
            for (cols_builder.items) |col| allocator.free(col);
        }

        for (tree) |col| {
            const decoded_col = try allocator.alloc(M31, col.len);
            errdefer allocator.free(decoded_col);
            for (col, 0..) |value, i| decoded_col[i] = m31From(value);
            try cols_builder.append(allocator, decoded_col);
        }
        try trees_builder.append(allocator, try cols_builder.toOwnedSlice(allocator));
    }

    return quotients_mod.TreeVec([][]M31).initOwned(try trees_builder.toOwnedSlice(allocator));
}

pub fn decodeQm31Tree(
    allocator: std.mem.Allocator,
    encoded: [][][][4]u32,
) !quotients_mod.TreeVec([][]QM31) {
    var trees_builder = std.ArrayList([][]QM31).empty;
    defer trees_builder.deinit(allocator);
    errdefer {
        for (trees_builder.items) |tree| {
            for (tree) |col| allocator.free(col);
            allocator.free(tree);
        }
    }

    for (encoded) |tree| {
        var cols_builder = std.ArrayList([]QM31).empty;
        defer cols_builder.deinit(allocator);
        errdefer {
            for (cols_builder.items) |col| allocator.free(col);
        }

        for (tree) |col| {
            const decoded_col = try allocator.alloc(QM31, col.len);
            errdefer allocator.free(decoded_col);
            for (col, 0..) |value, i| decoded_col[i] = qm31From(value);
            try cols_builder.append(allocator, decoded_col);
        }
        try trees_builder.append(allocator, try cols_builder.toOwnedSlice(allocator));
    }

    return quotients_mod.TreeVec([][]QM31).initOwned(try trees_builder.toOwnedSlice(allocator));
}

pub fn decodeQm31Slice(allocator: std.mem.Allocator, encoded: [][4]u32) ![]QM31 {
    const out = try allocator.alloc(QM31, encoded.len);
    for (encoded, 0..) |value, i| out[i] = qm31From(value);
    return out;
}

pub fn expectedVcsError(name: []const u8) vcs_verifier_mod.MerkleVerificationError {
    if (std.mem.eql(u8, name, "WitnessTooShort")) return vcs_verifier_mod.MerkleVerificationError.WitnessTooShort;
    if (std.mem.eql(u8, name, "WitnessTooLong")) return vcs_verifier_mod.MerkleVerificationError.WitnessTooLong;
    if (std.mem.eql(u8, name, "TooManyQueriedValues")) return vcs_verifier_mod.MerkleVerificationError.TooManyQueriedValues;
    if (std.mem.eql(u8, name, "TooFewQueriedValues")) return vcs_verifier_mod.MerkleVerificationError.TooFewQueriedValues;
    if (std.mem.eql(u8, name, "RootMismatch")) return vcs_verifier_mod.MerkleVerificationError.RootMismatch;
    unreachable;
}

pub fn expectedFriDecommitError(name: []const u8) prover_fri_mod.FriDecommitError {
    if (std.mem.eql(u8, name, "QueryOutOfRange")) return prover_fri_mod.FriDecommitError.QueryOutOfRange;
    if (std.mem.eql(u8, name, "FoldStepTooLarge")) return prover_fri_mod.FriDecommitError.FoldStepTooLarge;
    unreachable;
}

pub fn expectedVcsLiftedError(name: []const u8) @import("stwo_core").vcs_lifted.verifier.MerkleVerificationError {
    const lifted_verifier = @import("stwo_core").vcs_lifted.verifier;
    if (std.mem.eql(u8, name, "WitnessTooShort")) return lifted_verifier.MerkleVerificationError.WitnessTooShort;
    if (std.mem.eql(u8, name, "WitnessTooLong")) return lifted_verifier.MerkleVerificationError.WitnessTooLong;
    if (std.mem.eql(u8, name, "RootMismatch")) return lifted_verifier.MerkleVerificationError.RootMismatch;
    unreachable;
}

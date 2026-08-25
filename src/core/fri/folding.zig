//! Sparse decommitment reconstruction and FRI folding mechanics.

const std = @import("std");
const circle = @import("../circle.zig");
const fft = @import("../fft.zig");
const fields = @import("../fields/mod.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const line = @import("../poly/line.zig");
const circle_domain = @import("../poly/circle/domain.zig");
const queries_mod = @import("../queries.zig");
const core_utils = @import("../utils.zig");
const config = @import("config.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const FOLD_STEP = config.FOLD_STEP;
const CIRCLE_TO_LINE_FOLD_STEP = config.CIRCLE_TO_LINE_FOLD_STEP;

pub const SparseEvaluation = struct {
    subset_evals: [][]QM31,
    subset_domain_initial_indexes: []usize,

    pub const Error = error{
        InvalidSubsetSize,
        ShapeMismatch,
    };

    pub fn initOwned(
        subset_evals: [][]QM31,
        subset_domain_initial_indexes: []usize,
    ) Error!SparseEvaluation {
        // Validate that all subsets have the same (power-of-two) length.
        // The actual fold step varies: CIRCLE_TO_LINE_FOLD_STEP for the first
        // layer, FOLD_STEP for inner layers.  We just check consistency.
        if (subset_evals.len > 0) {
            const expected_len = subset_evals[0].len;
            for (subset_evals[1..]) |subset| {
                if (subset.len != expected_len) return Error.InvalidSubsetSize;
            }
        }
        if (subset_evals.len != subset_domain_initial_indexes.len) return Error.ShapeMismatch;
        return .{
            .subset_evals = subset_evals,
            .subset_domain_initial_indexes = subset_domain_initial_indexes,
        };
    }

    pub fn deinit(self: *SparseEvaluation, allocator: std.mem.Allocator) void {
        for (self.subset_evals) |subset| allocator.free(subset);
        allocator.free(self.subset_evals);
        allocator.free(self.subset_domain_initial_indexes);
        self.* = undefined;
    }

    /// Folds each subset using the default FOLD_STEP.
    pub fn foldLineSubsets(
        self: SparseEvaluation,
        allocator: std.mem.Allocator,
        fold_alpha: QM31,
        source_domain: line.LineDomain,
    ) ![]QM31 {
        return self.foldLineSubsetsN(allocator, fold_alpha, source_domain, FOLD_STEP);
    }

    /// Folds each subset using a caller-specified number of folds.
    pub fn foldLineSubsetsN(
        self: SparseEvaluation,
        allocator: std.mem.Allocator,
        fold_alpha: QM31,
        source_domain: line.LineDomain,
        n_folds: u32,
    ) ![]QM31 {
        const out = try allocator.alloc(QM31, self.subset_evals.len);
        if (self.subset_evals.len == 0) return out;
        var workspace = try FoldLineWorkspace.init(allocator, self.subset_evals[0].len / 2);
        defer workspace.deinit(allocator);
        var i: usize = 0;
        while (i < self.subset_evals.len) : (i += 1) {
            const domain_initial_index = self.subset_domain_initial_indexes[i];
            const fold_domain_initial = source_domain.coset().indexAt(domain_initial_index);
            const fold_domain = try line.LineDomain.init(circle.Coset.new(fold_domain_initial, n_folds));
            const folded = try foldLineNWithWorkspace(
                allocator,
                self.subset_evals[i],
                fold_domain,
                fold_alpha,
                &workspace,
                n_folds,
            );
            defer allocator.free(folded.values);
            out[i] = folded.values[0];
        }
        return out;
    }

    pub fn foldCircleSubsets(
        self: SparseEvaluation,
        allocator: std.mem.Allocator,
        fold_alpha: QM31,
        source_domain: circle_domain.CircleDomain,
        fold_step: u32,
    ) ![]QM31 {
        const out = try allocator.alloc(QM31, self.subset_evals.len);
        if (self.subset_evals.len == 0) return out;
        if (fold_step == 0 or self.subset_evals[0].len != (@as(usize, 1) << @intCast(fold_step)))
            return error.ShapeMismatch;
        const circle_fold_len = self.subset_evals[0].len / 2;
        const circle_buffer = try allocator.alloc(QM31, circle_fold_len);
        defer allocator.free(circle_buffer);
        var circle_workspace = try FoldCircleWorkspace.init(allocator, circle_fold_len);
        defer circle_workspace.deinit(allocator);
        var line_workspace = try FoldLineWorkspace.init(allocator, @max(1, circle_fold_len / 2));
        defer line_workspace.deinit(allocator);
        var i: usize = 0;
        while (i < self.subset_evals.len) : (i += 1) {
            const domain_initial_index = self.subset_domain_initial_indexes[i];
            const fold_domain_initial = source_domain.indexAt(domain_initial_index);
            const fold_domain = circle_domain.CircleDomain.new(
                circle.Coset.new(fold_domain_initial, fold_step - 1),
            );
            if (fold_domain.half_coset.size() != circle_buffer.len) return error.ShapeMismatch;
            @memset(circle_buffer, QM31.zero());
            try foldCircleIntoLineWithWorkspace(
                allocator,
                circle_buffer,
                self.subset_evals[i],
                fold_domain,
                fold_alpha,
                &circle_workspace,
            );
            if (fold_step == 1) {
                out[i] = circle_buffer[0];
            } else {
                const folded = try foldLineNWithWorkspace(
                    allocator,
                    circle_buffer,
                    line.LineDomain.fromCircleDomain(fold_domain),
                    fold_alpha.square(),
                    &line_workspace,
                    fold_step - 1,
                );
                defer allocator.free(folded.values);
                out[i] = folded.values[0];
            }
        }
        return out;
    }
};

pub const ComputeDecommitmentResult = struct {
    decommitment_positions: []usize,
    sparse_evaluation: SparseEvaluation,
    consumed_witness: usize,

    pub fn deinit(self: *ComputeDecommitmentResult, allocator: std.mem.Allocator) void {
        allocator.free(self.decommitment_positions);
        self.sparse_evaluation.deinit(allocator);
        self.* = undefined;
    }
};

pub fn computeDecommitmentPositionsAndRebuildEvals(
    allocator: std.mem.Allocator,
    queries: queries_mod.Queries,
    query_evals: []const QM31,
    witness_evals: []const QM31,
    fold_step: u32,
) !ComputeDecommitmentResult {
    if (query_evals.len != queries.positions.len) return error.ShapeMismatch;

    var decommitment_positions = std.ArrayList(usize).empty;
    defer decommitment_positions.deinit(allocator);
    var subset_evals = std.ArrayList([]QM31).empty;
    defer subset_evals.deinit(allocator);
    errdefer {
        for (subset_evals.items) |subset| allocator.free(subset);
    }
    var subset_domain_initial_indexes = std.ArrayList(usize).empty;
    defer subset_domain_initial_indexes.deinit(allocator);

    const subset_size: usize = @as(usize, 1) << @intCast(fold_step);

    var query_idx: usize = 0;
    var witness_idx: usize = 0;
    while (query_idx < queries.positions.len) {
        const subset_group = queries.positions[query_idx] >> @intCast(fold_step);
        const subset_start = subset_group << @intCast(fold_step);

        var subset_end_idx = query_idx;
        while (subset_end_idx < queries.positions.len and
            (queries.positions[subset_end_idx] >> @intCast(fold_step)) == subset_group)
        {
            subset_end_idx += 1;
        }

        var pos: usize = subset_start;
        while (pos < subset_start + subset_size) : (pos += 1) {
            try decommitment_positions.append(allocator, pos);
        }

        const subset = try allocator.alloc(QM31, subset_size);
        errdefer allocator.free(subset);

        var subset_query_idx = query_idx;
        var subset_pos: usize = 0;
        while (subset_pos < subset_size) : (subset_pos += 1) {
            const absolute_pos = subset_start + subset_pos;
            if (subset_query_idx < subset_end_idx and queries.positions[subset_query_idx] == absolute_pos) {
                subset[subset_pos] = query_evals[subset_query_idx];
                subset_query_idx += 1;
            } else {
                if (witness_idx >= witness_evals.len) return error.InsufficientWitness;
                subset[subset_pos] = witness_evals[witness_idx];
                witness_idx += 1;
            }
        }

        try subset_evals.append(allocator, subset);
        try subset_domain_initial_indexes.append(
            allocator,
            core_utils.bitReverseIndex(subset_start, queries.log_domain_size),
        );
        query_idx = subset_end_idx;
    }

    return .{
        .decommitment_positions = try decommitment_positions.toOwnedSlice(allocator),
        .sparse_evaluation = try SparseEvaluation.initOwned(
            try subset_evals.toOwnedSlice(allocator),
            try subset_domain_initial_indexes.toOwnedSlice(allocator),
        ),
        .consumed_witness = witness_idx,
    };
}

pub const FoldLineResult = struct {
    domain: line.LineDomain,
    values: []QM31,
};

pub const FoldLineWorkspace = struct {
    x_values: []M31,
    inv_x_values: []M31,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !FoldLineWorkspace {
        return .{
            .x_values = try allocator.alloc(M31, capacity),
            .inv_x_values = try allocator.alloc(M31, capacity),
        };
    }

    pub fn deinit(self: *FoldLineWorkspace, allocator: std.mem.Allocator) void {
        allocator.free(self.x_values);
        allocator.free(self.inv_x_values);
        self.* = undefined;
    }

    pub fn ensureCapacity(
        self: *FoldLineWorkspace,
        allocator: std.mem.Allocator,
        capacity: usize,
    ) !void {
        if (self.x_values.len >= capacity and self.inv_x_values.len >= capacity) return;

        self.x_values = try allocator.realloc(self.x_values, capacity);
        self.inv_x_values = try allocator.realloc(self.inv_x_values, capacity);
    }
};

/// Scratch workspace for circle-to-line folding.
///
/// Invariants:
/// - `py_values.len == inv_py_values.len`.
/// - both buffers are resized to at least the destination line length.
pub const FoldCircleWorkspace = struct {
    py_values: []M31,
    inv_py_values: []M31,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !FoldCircleWorkspace {
        return .{
            .py_values = try allocator.alloc(M31, capacity),
            .inv_py_values = try allocator.alloc(M31, capacity),
        };
    }

    pub fn deinit(self: *FoldCircleWorkspace, allocator: std.mem.Allocator) void {
        allocator.free(self.py_values);
        allocator.free(self.inv_py_values);
        self.* = undefined;
    }

    pub fn ensureCapacity(
        self: *FoldCircleWorkspace,
        allocator: std.mem.Allocator,
        capacity: usize,
    ) !void {
        if (self.py_values.len >= capacity and self.inv_py_values.len >= capacity) return;

        self.py_values = try allocator.realloc(self.py_values, capacity);
        self.inv_py_values = try allocator.realloc(self.inv_py_values, capacity);
    }
};

const CosetCoordinate = enum { x, y };

/// Fills one coordinate of the first `out.len` coset points in bit-reversed
/// order. FRI consumes even natural-domain indices in bit-reversed order, and
/// for a `log_size`-bit index `bitReverse(i << 1)` is exactly the
/// `(log_size - 1)`-bit reversal of `i`.
///
/// Walking the arithmetic-progression coset once avoids reconstructing every
/// point independently from the set bits of its index. Bit reversal is an
/// involution, so scattering natural point `j` to `bitReverse(j)` produces the
/// same output order as gathering point `bitReverse(i)` for each output `i`.
fn fillBitReversedCosetCoordinate(
    out: []M31,
    coset: circle.Coset,
    comptime coordinate: CosetCoordinate,
) void {
    std.debug.assert(out.len != 0 and std.math.isPowerOfTwo(out.len));
    std.debug.assert(out.len <= coset.size());

    const log_len: u32 = @intCast(std.math.log2_int(usize, out.len));
    var points = coset.iter();
    var natural_index: usize = 0;
    while (natural_index < out.len) : (natural_index += 1) {
        const point = points.next() orelse unreachable;
        const output_index = core_utils.bitReverseIndex(natural_index, log_len);
        out[output_index] = switch (coordinate) {
            .x => point.x,
            .y => point.y,
        };
    }
}

pub fn foldLine(
    allocator: std.mem.Allocator,
    eval: []const QM31,
    domain: line.LineDomain,
    alpha: QM31,
) !FoldLineResult {
    if (eval.len < 2 or (eval.len & 1) != 0) return error.InvalidEvaluationLength;

    var workspace = try FoldLineWorkspace.init(allocator, eval.len / 2);
    defer workspace.deinit(allocator);
    return foldLineWithWorkspace(allocator, eval, domain, alpha, &workspace);
}

/// Performs a single butterfly fold (halving), independent of FOLD_STEP.
/// This is the building block used by the multi-step fold functions.
pub fn foldLineSingleStep(
    allocator: std.mem.Allocator,
    eval: []const QM31,
    domain: line.LineDomain,
    alpha: QM31,
    workspace: *FoldLineWorkspace,
) !FoldLineResult {
    if (eval.len < 2 or (eval.len & 1) != 0) return error.InvalidEvaluationLength;

    const folded_values = try allocator.alloc(QM31, eval.len / 2);
    try workspace.ensureCapacity(allocator, folded_values.len);
    const x_values = workspace.x_values[0..folded_values.len];
    const inv_x_values = workspace.inv_x_values[0..folded_values.len];

    fillBitReversedCosetCoordinate(x_values, domain.coset(), .x);
    try fields.batchInverseInPlace(M31, x_values, inv_x_values);

    var i: usize = 0;
    while (i < folded_values.len) : (i += 1) {
        const inv_x = inv_x_values[i];
        var f0 = eval[i * 2];
        var f1 = eval[i * 2 + 1];
        fft.ibutterfly(QM31, &f0, &f1, inv_x);
        folded_values[i] = f0.add(alpha.mul(f1));
    }

    return .{
        .domain = domain.double(),
        .values = folded_values,
    };
}

/// Performs `n_folds` sequential single folds, reducing evaluation size by
/// 2^n_folds.  Allocates and returns the final folded buffer.
pub fn foldLineNWithWorkspace(
    allocator: std.mem.Allocator,
    eval: []const QM31,
    domain: line.LineDomain,
    alpha: QM31,
    workspace: *FoldLineWorkspace,
    n_folds: u32,
) !FoldLineResult {
    if (eval.len < 2 or (eval.len & 1) != 0) return error.InvalidEvaluationLength;

    // First fold: allocate from the source (which is const).
    var current_alpha = alpha;
    var result = try foldLineSingleStep(allocator, eval, domain, current_alpha, workspace);

    // Subsequent folds: fold from the previous result, freeing intermediates.
    var step: u32 = 1;
    while (step < n_folds) : (step += 1) {
        const prev_values = result.values;
        const prev_domain = result.domain;
        current_alpha = current_alpha.square();
        result = try foldLineSingleStep(allocator, prev_values, prev_domain, current_alpha, workspace);
        allocator.free(prev_values);
    }

    return result;
}

/// Convenience wrapper that folds FOLD_STEP times (the default for inner layers).
pub fn foldLineWithWorkspace(
    allocator: std.mem.Allocator,
    eval: []const QM31,
    domain: line.LineDomain,
    alpha: QM31,
    workspace: *FoldLineWorkspace,
) !FoldLineResult {
    return foldLineNWithWorkspace(allocator, eval, domain, alpha, workspace, FOLD_STEP);
}

/// Performs a single in-place fold (halving) on a mutable evaluation buffer.
/// The buffer is compacted to its first half and then reallocated to the
/// smaller size.
fn foldLineInPlaceSingleStep(
    allocator: std.mem.Allocator,
    eval: []QM31,
    domain: line.LineDomain,
    alpha: QM31,
    workspace: *FoldLineWorkspace,
) !FoldLineResult {
    if (eval.len < 2 or (eval.len & 1) != 0) return error.InvalidEvaluationLength;

    const folded_len = eval.len / 2;
    try workspace.ensureCapacity(allocator, folded_len);
    const x_values = workspace.x_values[0..folded_len];
    const inv_x_values = workspace.inv_x_values[0..folded_len];

    fillBitReversedCosetCoordinate(x_values, domain.coset(), .x);
    try fields.batchInverseInPlace(M31, x_values, inv_x_values);

    var i: usize = 0;
    while (i < folded_len) : (i += 1) {
        const inv_x = inv_x_values[i];
        var f0 = eval[i * 2];
        var f1 = eval[i * 2 + 1];
        fft.ibutterfly(QM31, &f0, &f1, inv_x);
        eval[i] = f0.add(alpha.mul(f1));
    }

    const resized = try allocator.realloc(eval, folded_len);
    return .{
        .domain = domain.double(),
        .values = resized,
    };
}

/// Folds a line evaluation in place by `n_folds` sequential halvings,
/// shrinking the backing slice by a factor of 2^n_folds.
///
/// Preconditions:
/// - `eval` is allocator-owned and mutable.
/// - `eval.len >= 2^n_folds` and is a power of two.
pub fn foldLineInPlaceNWithWorkspace(
    allocator: std.mem.Allocator,
    eval: []QM31,
    domain: line.LineDomain,
    alpha: QM31,
    workspace: *FoldLineWorkspace,
    n_folds: u32,
) !FoldLineResult {
    var current_eval = eval;
    var current_domain = domain;
    var current_alpha = alpha;

    var step: u32 = 0;
    while (step < n_folds) : (step += 1) {
        const result = try foldLineInPlaceSingleStep(
            allocator,
            current_eval,
            current_domain,
            current_alpha,
            workspace,
        );
        current_eval = result.values;
        current_domain = result.domain;
        current_alpha = current_alpha.square();
    }

    return .{
        .domain = current_domain,
        .values = current_eval,
    };
}

/// Convenience wrapper that folds FOLD_STEP times in place.
pub fn foldLineInPlaceWithWorkspace(
    allocator: std.mem.Allocator,
    eval: []QM31,
    domain: line.LineDomain,
    alpha: QM31,
    workspace: *FoldLineWorkspace,
) !FoldLineResult {
    return foldLineInPlaceNWithWorkspace(allocator, eval, domain, alpha, workspace, FOLD_STEP);
}

pub fn foldCircleIntoLine(
    dst: []QM31,
    src: []const QM31,
    src_domain: circle_domain.CircleDomain,
    alpha: QM31,
) !void {
    var workspace = try FoldCircleWorkspace.init(std.heap.page_allocator, dst.len);
    defer workspace.deinit(std.heap.page_allocator);
    return foldCircleIntoLineWithWorkspace(
        std.heap.page_allocator,
        dst,
        src,
        src_domain,
        alpha,
        &workspace,
    );
}

pub fn foldCircleIntoLineWithWorkspace(
    allocator: std.mem.Allocator,
    dst: []QM31,
    src: []const QM31,
    src_domain: circle_domain.CircleDomain,
    alpha: QM31,
    workspace: *FoldCircleWorkspace,
) !void {
    if ((src.len >> @intCast(CIRCLE_TO_LINE_FOLD_STEP)) != dst.len) {
        return error.ShapeMismatch;
    }

    const alpha_sq = alpha.square();
    try workspace.ensureCapacity(allocator, dst.len);
    const py_values = workspace.py_values[0..dst.len];
    const inv_py_values = workspace.inv_py_values[0..dst.len];

    fillBitReversedCosetCoordinate(py_values, src_domain.half_coset, .y);
    try fields.batchInverseInPlace(M31, py_values, inv_py_values);

    var i: usize = 0;
    while (i < dst.len) : (i += 1) {
        const inv_py = inv_py_values[i];
        var f0_px = src[i * 2];
        var f1_px = src[i * 2 + 1];
        fft.ibutterfly(QM31, &f0_px, &f1_px, inv_py);
        const f_prime = alpha.mul(f1_px).add(f0_px);
        dst[i] = dst[i].mul(alpha_sq).add(f_prime);
    }
}

pub fn foldCircleColumnsIntoLineWithWorkspace(
    allocator: std.mem.Allocator,
    dst: []QM31,
    src_columns: [qm31.SECURE_EXTENSION_DEGREE][]const M31,
    src_domain: circle_domain.CircleDomain,
    alpha: QM31,
    workspace: *FoldCircleWorkspace,
) !void {
    if ((src_columns[0].len >> @intCast(CIRCLE_TO_LINE_FOLD_STEP)) != dst.len) {
        return error.ShapeMismatch;
    }
    inline for (src_columns[1..]) |column| {
        if (column.len != src_columns[0].len) return error.ShapeMismatch;
    }

    const alpha_sq = alpha.square();
    try workspace.ensureCapacity(allocator, dst.len);
    const py_values = workspace.py_values[0..dst.len];
    const inv_py_values = workspace.inv_py_values[0..dst.len];

    fillBitReversedCosetCoordinate(py_values, src_domain.half_coset, .y);
    try fields.batchInverseInPlace(M31, py_values, inv_py_values);

    var i: usize = 0;
    while (i < dst.len) : (i += 1) {
        const inv_py = inv_py_values[i];
        const left_idx = i * 2;
        const right_idx = left_idx + 1;
        var f0_px = QM31.fromM31Array(.{
            src_columns[0][left_idx],
            src_columns[1][left_idx],
            src_columns[2][left_idx],
            src_columns[3][left_idx],
        });
        var f1_px = QM31.fromM31Array(.{
            src_columns[0][right_idx],
            src_columns[1][right_idx],
            src_columns[2][right_idx],
            src_columns[3][right_idx],
        });
        fft.ibutterfly(QM31, &f0_px, &f1_px, inv_py);
        const f_prime = alpha.mul(f1_px).add(f0_px);
        dst[i] = dst[i].mul(alpha_sq).add(f_prime);
    }
}

pub fn accumulateLine(layer_query_evals: []QM31, column_query_evals: []const QM31, folding_alpha: QM31) void {
    std.debug.assert(layer_query_evals.len == column_query_evals.len);
    const alpha_sq = folding_alpha.square();
    for (layer_query_evals, 0..) |*curr, i| {
        curr.* = curr.*.mul(alpha_sq).add(column_query_evals[i]);
    }
}

test "fri folding: coset walk matches indexed bit-reversed coordinates" {
    const allocator = std.testing.allocator;

    var line_log_size: u32 = 1;
    while (line_log_size <= 15) : (line_log_size += 1) {
        const base_coset = circle.Coset.halfOdds(line_log_size);
        const shifted_coset = base_coset.shift(base_coset.step_size.mul(3));
        const domain = try line.LineDomain.init(shifted_coset);
        const output_len = domain.size() / 2;
        const actual = try allocator.alloc(M31, output_len);
        defer allocator.free(actual);

        fillBitReversedCosetCoordinate(actual, domain.coset(), .x);
        for (actual, 0..) |coordinate, i| {
            const expected = domain.at(core_utils.bitReverseIndex(i << 1, line_log_size));
            try std.testing.expect(coordinate.eql(expected));
        }
    }

    var circle_log_size: u32 = 2;
    while (circle_log_size <= 15) : (circle_log_size += 1) {
        const base_half_coset = circle.Coset.halfOdds(circle_log_size - 1);
        const shifted_half_coset = base_half_coset.shift(base_half_coset.step_size.mul(5));
        const domain = circle_domain.CircleDomain.new(shifted_half_coset);
        const actual = try allocator.alloc(M31, domain.size() / 2);
        defer allocator.free(actual);

        fillBitReversedCosetCoordinate(actual, domain.half_coset, .y);
        for (actual, 0..) |coordinate, i| {
            const expected = domain.at(core_utils.bitReverseIndex(i << 1, circle_log_size)).y;
            try std.testing.expect(coordinate.eql(expected));
        }
    }
}

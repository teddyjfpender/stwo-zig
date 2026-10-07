//! The shape and `CircuitSerialize` size of a circuit STARK proof.
//!
//! One model for the in-circuit verifier's `ProofConfig`
//! (`crates/stark_verifier/src/proof.rs`) and the `CircuitSerialize` wire
//! format (`crates/circuit_serialize`) of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230: the per-tree column counts, the
//! FRI layer schedule (`compute_all_fold_steps`, `fri.allFoldSteps`) and
//! `ProofInfo::total_bytes`. Both the circuit frontend and the wire package
//! read proofs through it, so a proof's length cannot differ between them.

const std = @import("std");
const fri = @import("fri.zig");
const FriConfigV2 = @import("pcs/config_v2.zig").FriConfigV2;

/// Committed trees: preprocessed, trace, interaction, composition.
pub const n_traces: usize = 4;
/// Legacy split-one composition width. A proof shape may request a larger
/// split through `composition_log_split`.
pub const n_composition_columns: usize = 8;
/// The trailing interaction columns of every component that hold its
/// cumulative sum, also sampled at the previous point.
pub const n_cumulative_sum_columns_per_component: usize = 4;
/// Upper bound on FRI layers (`log_trace_size <= 31`).
pub const max_fri_layers: usize = 32;

pub const hash_bytes: usize = 32;
pub const m31_bytes: usize = 4;
pub const qm31_bytes: usize = 4 * m31_bytes;
const current_offsets = [_]i8{0};
const cumulative_offsets = [_]i8{ -1, 0 };

/// Trace and interaction column counts of one AIR component.
pub const ComponentShape = struct {
    trace_columns: usize,
    interaction_columns: usize,
};

pub const Error = error{
    /// The shape cannot describe a circuit proof (see `ProofShape.validate`).
    InvalidProofShape,
};

/// The structure of a circuit proof, as far as its bytes depend on it.
///
/// `component_shapes` is in the order the statement iterates its components
/// (for the circuit AIR, `all_circuit_components`). It is borrowed.
pub const ProofShape = struct {
    n_preprocessed_columns: usize,
    component_shapes: []const ComponentShape,
    log_trace_size: u32,
    fri: FriConfigV2,
    composition_log_split: u32 = 1,
    /// Native PCS mask-point offsets for each main-trace column, in sampled
    /// value order. Null is the original singleton mask at the OODS point.
    /// This layout is verifier-owned; proof bytes never select openings.
    trace_mask_offsets: ?[]const []const i8 = null,
    /// Ordered interaction masks. Null retains the legacy last-four
    /// previous/current cumulative-sum columns of each component.
    interaction_mask_offsets: ?[]const []const i8 = null,
    /// Number of transcript claims contributed by each AIR component.
    /// Null means one claim for an interaction component, none for a
    /// trace-only component. The caller word bus contributes two claims.
    claim_arities: ?[]const u8 = null,

    /// Rejects a shape upstream would assert on or that has no proof: a
    /// component with fewer interaction columns than its cumulative sum, a
    /// zero FRI fold step, a last layer larger than the trace, or an
    /// evaluation domain past 2^31.
    pub fn validate(self: ProofShape) Error!void {
        for (self.component_shapes) |shape| if (shape.interaction_columns != 0 and
            shape.interaction_columns < n_cumulative_sum_columns_per_component) return error.InvalidProofShape;
        if (@import("verifier_types.zig").compositionColumnCount(self.composition_log_split, 4) == null)
            return error.InvalidProofShape;
        if (self.fri.fold_step == 0) return error.InvalidProofShape;
        if (self.fri.log_last_layer_degree_bound > self.log_trace_size) return error.InvalidProofShape;
        if (self.logEvaluationDomainSize() > 31) return error.InvalidProofShape;
        if (self.trace_mask_offsets) |masks| {
            if (masks.len != self.nTraceColumns()) return error.InvalidProofShape;
            for (masks) |offsets| {
                if (offsets.len == 0) return error.InvalidProofShape;
                var has_current = false;
                for (offsets, 0..) |offset, i| {
                    if (offset == 0) has_current = true;
                    for (offsets[0..i]) |prior| if (prior == offset) return error.InvalidProofShape;
                }
                if (!has_current) return error.InvalidProofShape;
            }
        }
        if (self.interaction_mask_offsets) |masks| {
            if (masks.len != self.nInteractionColumns()) return error.InvalidProofShape;
            for (masks) |offsets| {
                if (!std.mem.eql(i8, offsets, &current_offsets) and
                    !std.mem.eql(i8, offsets, &cumulative_offsets)) return error.InvalidProofShape;
            }
        }
        if (self.claim_arities) |arities| {
            if (arities.len != self.nComponents()) return error.InvalidProofShape;
        }
        var interaction_start: usize = 0;
        for (self.component_shapes, 0..) |component, index| {
            const claims = self.claimArity(index);
            if ((component.interaction_columns == 0) != (claims == 0)) return error.InvalidProofShape;
            var cumulative: usize = 0;
            for (interaction_start..interaction_start + component.interaction_columns) |column|
                cumulative += @intFromBool(self.isCumulativeSumColumn(column));
            if (cumulative != @as(usize, claims) * n_cumulative_sum_columns_per_component)
                return error.InvalidProofShape;
            interaction_start += component.interaction_columns;
        }
    }

    pub fn nComponents(self: ProofShape) usize {
        return self.component_shapes.len;
    }

    pub fn claimArity(self: ProofShape, component: usize) u8 {
        std.debug.assert(component < self.nComponents());
        return if (self.claim_arities) |arities| arities[component] else @intFromBool(self.component_shapes[component].interaction_columns != 0);
    }

    pub fn nClaimedSums(self: ProofShape) usize {
        var total: usize = 0;
        for (self.component_shapes, 0..) |_, index| total += self.claimArity(index);
        return total;
    }

    pub fn claimRange(self: ProofShape, component: usize) struct { start: usize, end: usize } {
        std.debug.assert(component < self.nComponents());
        var start: usize = 0;
        for (0..component) |index| start += self.claimArity(index);
        return .{ .start = start, .end = start + self.claimArity(component) };
    }

    pub fn nTraceColumns(self: ProofShape) usize {
        var total: usize = 0;
        for (self.component_shapes) |shape| total += shape.trace_columns;
        return total;
    }

    pub fn nInteractionColumns(self: ProofShape) usize {
        var total: usize = 0;
        for (self.component_shapes) |shape| total += shape.interaction_columns;
        return total;
    }

    pub fn nCumulativeSumColumns(self: ProofShape) usize {
        if (self.interaction_mask_offsets) |masks| {
            var total: usize = 0;
            for (masks) |offsets| total += @intFromBool(offsets.len == 2);
            return total;
        }
        var total: usize = 0;
        for (self.component_shapes) |component| {
            if (component.interaction_columns != 0) total += n_cumulative_sum_columns_per_component;
        }
        return total;
    }

    pub fn nCompositionColumns(self: ProofShape) usize {
        return @import("verifier_types.zig").compositionColumnCount(self.composition_log_split, 4).?;
    }

    /// Native mask order for any committed column. The cumulative-sum
    /// interaction columns have the existing previous/current pair.
    pub fn columnMaskOffsets(self: ProofShape, tree: usize, column: usize) []const i8 {
        const columns = self.nColumnsPerTrace();
        std.debug.assert(tree < n_traces and column < columns[tree]);
        if (tree == 1) return if (self.trace_mask_offsets) |masks| masks[column] else &current_offsets;
        if (tree == 2) return if (self.interaction_mask_offsets) |masks|
            masks[column]
        else if (self.isCumulativeSumColumn(column))
            &cumulative_offsets
        else
            &current_offsets;
        return &current_offsets;
    }

    /// Sum of the main-tree mask lengths, not the number of committed columns.
    pub fn nTraceOodsValues(self: ProofShape) usize {
        if (self.trace_mask_offsets) |masks| {
            var total: usize = 0;
            for (masks) |offsets| total += offsets.len;
            return total;
        }
        return self.nTraceColumns();
    }

    pub fn traceMaskRange(self: ProofShape, column: usize) struct { start: usize, end: usize } {
        std.debug.assert(column < self.nTraceColumns());
        if (self.trace_mask_offsets) |masks| {
            var start: usize = 0;
            for (masks[0..column]) |offsets| start += offsets.len;
            return .{ .start = start, .end = start + masks[column].len };
        }
        return .{ .start = column, .end = column + 1 };
    }

    /// `[preprocessed, trace, interaction, composition]` column counts.
    pub fn nColumnsPerTrace(self: ProofShape) [n_traces]usize {
        return .{ self.n_preprocessed_columns, self.nTraceColumns(), self.nInteractionColumns(), self.nCompositionColumns() };
    }

    pub fn nQueries(self: ProofShape) usize {
        return self.fri.n_queries;
    }

    pub fn logEvaluationDomainSize(self: ProofShape) usize {
        return @as(usize, self.log_trace_size) + self.fri.log_blowup_factor;
    }

    /// Number of FRI layers: `compute_all_fold_steps(..).len()`.
    pub fn nFriLayers(self: ProofShape) usize {
        return fri.nFoldSteps(self.degreeLogRatio(), self.fri.fold_step);
    }

    /// `compute_all_fold_steps(log_trace_size - log_last_layer, fold_step)`,
    /// written into `buffer`.
    pub fn friFoldSteps(self: ProofShape, buffer: *[max_fri_layers]u32) []const u32 {
        return fri.allFoldSteps(self.degreeLogRatio(), self.fri.fold_step, buffer);
    }

    /// Whether interaction column `column` also carries its value at the
    /// previous point: the last four interaction columns of each component.
    pub fn isCumulativeSumColumn(self: ProofShape, column: usize) bool {
        if (self.interaction_mask_offsets) |masks| {
            std.debug.assert(column < masks.len);
            return masks[column].len == 2;
        }
        var start: usize = 0;
        for (self.component_shapes) |shape| {
            const end = start + shape.interaction_columns;
            if (column < end) return column >= end - n_cumulative_sum_columns_per_component;
            start = end;
        }
        unreachable;
    }

    /// `ProofInfo::from_config(config).total_bytes()`: the exact
    /// `CircuitSerialize` length of a proof of this shape.
    pub fn serializedLen(self: ProofShape) usize {
        const columns = self.nColumnsPerTrace();
        const total_columns = columns[0] + columns[1] + columns[2] + columns[3];
        // channel_salt, three roots (two QM31 words each), pow_nonce and
        // interaction_pow_nonce.
        const fixed = (1 + 3 * 2 + 1 + 1) * qm31_bytes;
        const claim = self.nClaimedSums() * qm31_bytes;
        const oods = (total_columns + self.nCumulativeSumColumns() + self.nTraceOodsValues() - columns[1]) * qm31_bytes;
        const fri_last_layer = (@as(usize, 1) << @intCast(self.fri.log_last_layer_degree_bound)) * qm31_bytes;

        var steps_buffer: [max_fri_layers]u32 = undefined;
        const steps = self.friFoldSteps(&steps_buffer);
        var fri_auth_per_query: usize = 0;
        var fri_witness_per_query: usize = 0;
        var log_layer_size = self.logEvaluationDomainSize();
        for (steps) |step| {
            log_layer_size -= step;
            fri_auth_per_query += log_layer_size * hash_bytes;
            fri_witness_per_query += (@as(usize, 1) << @intCast(step)) * qm31_bytes;
        }
        const eval_samples_per_query = total_columns * m31_bytes;
        const eval_auth_per_query = n_traces * self.logEvaluationDomainSize() * hash_bytes;
        const per_query = eval_samples_per_query + eval_auth_per_query + fri_auth_per_query + fri_witness_per_query;
        return fixed + claim + oods + steps.len * hash_bytes + fri_last_layer + per_query * self.nQueries();
    }

    fn degreeLogRatio(self: ProofShape) u32 {
        return self.log_trace_size - self.fri.log_last_layer_degree_bound;
    }
};

// Two components, a short trace, a blowup and a partial last fold, so every
// section is non-empty and shaped differently.
const test_shapes = [_]ComponentShape{
    .{ .trace_columns = 2, .interaction_columns = 4 },
    .{ .trace_columns = 1, .interaction_columns = 8 },
};
const test_shape: ProofShape = .{
    .n_preprocessed_columns = 3,
    .component_shapes = &test_shapes,
    .log_trace_size = 5,
    .fri = .{ .pow_bits = 10, .log_blowup_factor = 1, .log_last_layer_degree_bound = 1, .n_queries = 2, .fold_step = 3 },
};

test "circuit proof shape: FRI schedule, cumulative-sum columns and size" {
    // log_trace 5, last layer 1: ratio 4 folds as [3, 1]; eval domain 6.
    var buffer: [max_fri_layers]u32 = undefined;
    try std.testing.expectEqualSlices(u32, &.{ 3, 1 }, test_shape.friFoldSteps(&buffer));
    try std.testing.expectEqual(@as(usize, 2), test_shape.nFriLayers());
    // Component 0's four interaction columns are all cumulative sum;
    // component 1 has four plain columns (4..7) before its sum (8..11).
    try std.testing.expect(test_shape.isCumulativeSumColumn(0));
    try std.testing.expect(test_shape.isCumulativeSumColumn(3));
    try std.testing.expect(!test_shape.isCumulativeSumColumn(4));
    try std.testing.expect(!test_shape.isCumulativeSumColumn(7));
    try std.testing.expect(test_shape.isCumulativeSumColumn(8));
    try std.testing.expect(test_shape.isCumulativeSumColumn(11));
    // fixed 144 + claim 32 + oods (26 columns + 8 cumsum) * 16 + fri
    // commitments 64 + last layer 32 + per query (104 + 768 + 160 + 160) * 2.
    try std.testing.expectEqual(@as(usize, 144 + 32 + 544 + 64 + 32 + 1192 * 2), test_shape.serializedLen());
}

test "circuit proof shape: validation" {
    try test_shape.validate();
    var bad = test_shape;
    bad.fri.fold_step = 0;
    try std.testing.expectError(error.InvalidProofShape, bad.validate());
    bad = test_shape;
    bad.fri.log_last_layer_degree_bound = 6;
    try std.testing.expectError(error.InvalidProofShape, bad.validate());
    const thin = [_]ComponentShape{.{ .trace_columns = 1, .interaction_columns = 3 }};
    bad = test_shape;
    bad.component_shapes = &thin;
    try std.testing.expectError(error.InvalidProofShape, bad.validate());
}

test "circuit proof shape: split-two composition and trace-only components" {
    const shapes = [_]ComponentShape{
        .{ .trace_columns = 3, .interaction_columns = 0 },
        .{ .trace_columns = 0, .interaction_columns = 8 },
    };
    var shape = test_shape;
    shape.component_shapes = &shapes;
    shape.composition_log_split = 2;
    try shape.validate();
    try std.testing.expectEqual(@as(usize, 16), shape.nCompositionColumns());
    try std.testing.expectEqual(@as(usize, 4), shape.nCumulativeSumColumns());
    const columns = shape.nColumnsPerTrace();
    try std.testing.expectEqualSlices(usize, &.{ 3, 3, 8, 16 }, &columns);
    try std.testing.expect(!shape.isCumulativeSumColumn(3));
    try std.testing.expect(shape.isCumulativeSumColumn(4));
    // Four wider composition columns, four fewer cumulative openings, and
    // one fewer claim because the first component is trace-only.
    const expected_delta = 4 * (qm31_bytes + shape.nQueries() * m31_bytes) - 5 * qm31_bytes;
    try std.testing.expectEqual(test_shape.serializedLen() + expected_delta, shape.serializedLen());
}

test "circuit proof shape: ordered shifted masks increase OODS length and reject malformed masks" {
    const masks = [_][]const i8{ &.{0}, &.{ -3, -2, -1, 0, 1 }, &.{ -16, -15, -7, -2, 0 } };
    var shape = test_shape;
    shape.trace_mask_offsets = &masks;
    try shape.validate();
    try std.testing.expectEqual(@as(usize, 11), shape.nTraceOodsValues());
    try std.testing.expectEqual(@as(usize, 1), shape.traceMaskRange(1).start);
    try std.testing.expectEqual(@as(usize, 6), shape.traceMaskRange(1).end);
    try std.testing.expectEqual(@as(usize, 6), shape.traceMaskRange(2).start);
    try std.testing.expectEqualSlices(i8, &.{ -16, -15, -7, -2, 0 }, shape.columnMaskOffsets(1, 2));
    try std.testing.expectEqual(test_shape.serializedLen() + 8 * qm31_bytes, shape.serializedLen());

    const wrong_count = [_][]const i8{&.{0}};
    shape.trace_mask_offsets = &wrong_count;
    try std.testing.expectError(error.InvalidProofShape, shape.validate());
    const duplicate = [_][]const i8{ &.{0}, &.{ -1, 0, -1 }, &.{0} };
    shape.trace_mask_offsets = &duplicate;
    try std.testing.expectError(error.InvalidProofShape, shape.validate());
    const missing_current = [_][]const i8{ &.{0}, &.{ -1, 1 }, &.{0} };
    shape.trace_mask_offsets = &missing_current;
    try std.testing.expectError(error.InvalidProofShape, shape.validate());
}

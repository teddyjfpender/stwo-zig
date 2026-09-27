//! Verified dynamic-proof to fixed recursive-wire adapter.
//!
//! The ordinary STWO proof is consumed by native verification.  Only the
//! transactional `VerifiedProofCapture` produced by that successful verifier
//! may cross this boundary.  All proof-selected lengths have already been
//! eliminated; this module checks them against an authenticated profile and
//! then performs one infallible publication into caller-owned fixed storage.

const std = @import("std");
const stwo_core = @import("stwo_core");
const statement_mod = @import("../air/statement.zig");
const engine = @import("engine.zig");
const fixed_profile = @import("fixed_profile.zig");
const fixed_wire = @import("fixed_wire.zig");
const protocol = @import("protocol.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const ProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(engine.Hasher);
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");

pub const Error = fixed_wire.Error || error{
    CaptureShapeMismatch,
    InvalidInteractionClaim,
    InvalidQuerySchedule,
    NonCanonicalCapture,
};

/// Populates one exact fixed wire from material authenticated by the native
/// verifier. The destination remains byte-for-byte untouched on every error.
pub fn populate(
    comptime dimensions: fixed_wire.Dimensions,
    destination: *fixed_wire.FixedStarkProofWire(dimensions),
    shape: fixed_profile.ProofShapeV1,
    statement: *const statement_mod.RiscVStatement,
    claim: *const statement_mod.RiscVInteractionClaim,
    capture: *const ProofCapture,
) Error!void {
    try validateCapture(dimensions, shape, statement, claim, capture);

    // Everything below is infallible. A single publication phase preserves
    // failure atomicity without allocating a multi-megabyte temporary wire.
    @memset(std.mem.asBytes(destination), 0);
    for (capture.commitments, 0..) |commitment, index| {
        destination.commitments[index] = commitment;
    }

    const canonical_claim = claim.canonical(statement) catch unreachable;
    for (canonical_claim.claimed_sums, 0..) |value, index| {
        destination.claimed_sums[index] = qm31Wire(value);
    }
    for (capture.sampled_values, 0..) |value, index| {
        destination.sampled_values[index] = qm31Wire(value);
    }
    for (capture.queried_values, 0..) |value, index| {
        destination.queried_values[index] = value.toU32();
    }

    for (capture.trace_paths, 0..) |tree_capture, tree| {
        const tree_start = tree * dimensions.query_count;
        for (0..dimensions.query_count) |query| {
            const target = &destination.trace_paths[tree_start + query];
            target.active_depth = tree_capture.path_depth;
            for (tree_capture.path(query), 0..) |sibling, depth| {
                target.siblings[depth] = sibling;
            }
        }
    }

    for (capture.fri.layers, 0..) |source_layer, layer_index| {
        const target_layer = &destination.fri_layers[layer_index];
        target_layer.active_width = source_layer.fold_width;
        target_layer.commitment = source_layer.commitment;
        for (0..dimensions.query_count) |query| {
            const target_query = &target_layer.queries[query];
            for (source_layer.queryValues(query), 0..) |value, value_index| {
                target_query.values[value_index] = qm31Wire(value);
            }
            target_query.path.active_depth = source_layer.path_depth;
            for (source_layer.queryPath(query), 0..) |sibling, depth| {
                target_query.path.siblings[depth] = sibling;
            }
        }
    }

    for (capture.last_layer_coefficients, 0..) |value, index| {
        destination.last_layer_coefficients[index] = qm31Wire(value);
    }
    destination.interaction_pow = claim.interaction_pow;
    destination.pcs_pow = capture.proof_of_work;

    destination.validateAgainstShape(shape) catch unreachable;
}

fn validateCapture(
    comptime dimensions: fixed_wire.Dimensions,
    shape: fixed_profile.ProofShapeV1,
    statement: *const statement_mod.RiscVStatement,
    claim: *const statement_mod.RiscVInteractionClaim,
    capture: *const ProofCapture,
) Error!void {
    try shape.validate();
    try fixed_wire.validateDimensionsAgainstShape(dimensions, shape);
    if (shape.proof_wire_bytes != fixed_wire.serializedByteCount(dimensions))
        return error.WireByteCountMismatch;

    const canonical_claim = claim.canonical(statement) catch
        return error.InvalidInteractionClaim;
    if (canonical_claim.claimed_sums.len != dimensions.claimed_sum_count)
        return error.CaptureShapeMismatch;

    const composition_columns = stwo_core.verifier_types.compositionColumnCount(
        stwo_core.verifier_types.COMPOSITION_LOG_SPLIT,
        stwo_core.fields.qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.CaptureShapeMismatch;
    const expected_tree_columns = [fixed_profile.TREE_COUNT]usize{
        statement.nPreprocessedColumns(),
        statement.nMainColumns(),
        statement.nInteractionColumns(),
        composition_columns,
    };
    for (expected_tree_columns, shape.tree_column_counts) |expected, actual| {
        if (expected != actual) return error.CaptureShapeMismatch;
    }
    try validateColumnLogSizes(statement, shape, capture.column_log_sizes);
    try validateSampledPoints(shape, capture);

    if (capture.commitments.len != dimensions.commitment_count or
        capture.column_log_sizes.len != fixed_profile.TREE_COUNT or
        capture.sampled_values.len != dimensions.sampled_value_count or
        capture.queried_values.len != dimensions.queried_value_count or
        capture.deep_answers.len != dimensions.query_count or
        capture.trace_paths.len != fixed_profile.TREE_COUNT or
        capture.fri.layers.len != dimensions.fri_layer_count or
        capture.last_layer_coefficients.len !=
            dimensions.last_layer_coefficient_count or
        capture.queries.raw.len != dimensions.query_count or
        capture.queries.unique.len == 0 or
        capture.queries.unique.len > capture.queries.raw.len)
    {
        return error.CaptureShapeMismatch;
    }

    try validateQuerySet(
        capture.queries.raw,
        capture.queries.unique,
        shape.column_log_degree + protocol.PCS_CONFIG.fri_config.log_blowup_factor,
    );
    for (
        capture.trace_paths,
        capture.column_log_sizes,
        shape.tree_heights,
        expected_tree_columns,
    ) |path_capture, column_logs, tree_height, expected_column_count| {
        if (path_capture.path_depth != tree_height or
            column_logs.len != expected_column_count or
            path_capture.positions.len != dimensions.query_count or
            path_capture.siblings.len != dimensions.query_count * tree_height)
        {
            return error.CaptureShapeMismatch;
        }
        var maximum_column_log: u32 = 0;
        for (column_logs) |log_size| {
            if (log_size == 0 or log_size > tree_height)
                return error.CaptureShapeMismatch;
            maximum_column_log = @max(maximum_column_log, log_size);
        }
        if (maximum_column_log != tree_height)
            return error.CaptureShapeMismatch;
        for (capture.queries.raw, path_capture.positions) |raw, actual| {
            if (actual != mapTreeQueryPosition(
                raw,
                shape.column_log_degree +
                    protocol.PCS_CONFIG.fri_config.log_blowup_factor,
                tree_height,
            )) return error.InvalidQuerySchedule;
        }
    }

    const folded_positions = capture.queries.raw;
    var consumed_folds: u32 = 0;
    for (capture.fri.layers, shape.fri.active()) |layer, round| {
        if (layer.fold_step != round.fold_step or
            layer.fold_width != round.fold_width or
            layer.path_depth != round.authentication_path_depth or
            layer.query_count != dimensions.query_count or
            layer.positions.len != dimensions.query_count or
            layer.values.len != dimensions.query_count * round.fold_width or
            layer.siblings.len !=
                dimensions.query_count * round.authentication_path_depth)
        {
            return error.CaptureShapeMismatch;
        }
        for (folded_positions, layer.positions) |raw, actual| {
            if ((raw >> @intCast(consumed_folds)) != actual)
                return error.InvalidQuerySchedule;
        }
        consumed_folds += round.fold_step;
    }

    for (capture.commitments) |digest| try validateDigest(digest);
    for (capture.sampled_values) |value| try validateQm31(value);
    for (capture.queried_values) |value| try validateM31(value);
    for (capture.deep_answers) |value| try validateQm31(value);
    for (capture.trace_paths) |paths| {
        for (paths.siblings) |digest| try validateDigest(digest);
    }
    for (capture.fri.layers) |layer| {
        try validateDigest(layer.commitment);
        for (layer.values) |value| try validateQm31(value);
        for (layer.siblings) |digest| try validateDigest(digest);
    }
    for (capture.last_layer_coefficients) |value| try validateQm31(value);
    try validateQm31(capture.composition_randomness);
    try validateQm31(capture.oods_seed);
    try validateQm31(capture.deep_randomness);
}

fn validateColumnLogSizes(
    statement: *const statement_mod.RiscVStatement,
    shape: fixed_profile.ProofShapeV1,
    captured: []const []u32,
) Error!void {
    if (captured.len != fixed_profile.TREE_COUNT)
        return error.CaptureShapeMismatch;
    const blowup = protocol.PCS_CONFIG.fri_config.log_blowup_factor;

    var cursor: usize = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        try expectRepeatedLog(captured[0], &cursor, 2, descriptor.log_size, blowup);
    }
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        try expectRepeatedLog(
            captured[0],
            &cursor,
            statement_mod.nPreprocessedColumnsForInfra(descriptor.kind),
            descriptor.log_size,
            blowup,
        );
    }
    if (cursor != captured[0].len) return error.CaptureShapeMismatch;

    cursor = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        try expectRepeatedLog(
            captured[1],
            &cursor,
            @intCast(descriptor.n_columns),
            descriptor.log_size,
            blowup,
        );
    }
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        try expectRepeatedLog(
            captured[1],
            &cursor,
            @intCast(descriptor.n_columns),
            descriptor.log_size,
            blowup,
        );
    }
    if (cursor != captured[1].len) return error.CaptureShapeMismatch;

    cursor = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor| {
        try expectRepeatedLog(
            captured[2],
            &cursor,
            opcode_interaction.nColumns(descriptor.family),
            descriptor.log_size,
            blowup,
        );
    }
    for (statement.infra_descs[0..statement.n_infra]) |descriptor| {
        try expectRepeatedLog(
            captured[2],
            &cursor,
            statement_mod.nInteractionColsForInfra(descriptor.kind),
            descriptor.log_size,
            blowup,
        );
    }
    if (cursor != captured[2].len) return error.CaptureShapeMismatch;

    cursor = 0;
    try expectRepeatedLog(
        captured[3],
        &cursor,
        captured[3].len,
        shape.column_log_degree,
        blowup,
    );
    if (cursor != captured[3].len) return error.CaptureShapeMismatch;
}

fn validateSampledPoints(
    shape: fixed_profile.ProofShapeV1,
    capture: anytype,
) Error!void {
    if (capture.sampled_points.len != capture.column_log_sizes.len or
        shape.column_log_degree == 0)
    {
        return error.CaptureShapeMismatch;
    }
    try validateQm31(capture.oods_seed);
    const current = stwo_core.circle.secureFieldPointFromRandomSeedChecked(
        capture.oods_seed,
    ) catch return error.CaptureShapeMismatch;
    const step = stwo_core.poly.circle.canonic.CanonicCoset.new(
        shape.column_log_degree,
    ).step();
    const previous = current.sub(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });
    var sample_count: usize = 0;
    for (capture.sampled_points, capture.column_log_sizes) |columns, logs| {
        if (columns.len != logs.len) return error.CaptureShapeMismatch;
        for (columns) |points| {
            if (points.len > 2 or
                (points.len >= 1 and !points[0].eql(current)) or
                (points.len == 2 and !points[1].eql(previous)))
            {
                return error.CaptureShapeMismatch;
            }
            for (points) |point| {
                try validateQm31(point.x);
                try validateQm31(point.y);
            }
            sample_count = std.math.add(usize, sample_count, points.len) catch
                return error.CaptureShapeMismatch;
        }
    }
    if (sample_count != capture.sampled_values.len)
        return error.CaptureShapeMismatch;
}

fn expectRepeatedLog(
    captured: []const u32,
    cursor: *usize,
    count: usize,
    base_log: u32,
    blowup: u32,
) Error!void {
    if (cursor.* > captured.len or count > captured.len - cursor.*)
        return error.CaptureShapeMismatch;
    const expected = std.math.add(u32, base_log, blowup) catch
        return error.CaptureShapeMismatch;
    for (captured[cursor.*..][0..count]) |actual| {
        if (actual != expected) return error.CaptureShapeMismatch;
    }
    cursor.* += count;
}

fn validateQuerySet(raw: []const usize, unique: []const usize, log_size: u32) Error!void {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidQuerySchedule;
    const domain_size = @as(usize, 1) << @intCast(log_size);
    for (unique, 0..) |position, index| {
        if (position >= domain_size or
            (index != 0 and unique[index - 1] >= position))
        {
            return error.InvalidQuerySchedule;
        }
        var seen = false;
        for (raw) |candidate| {
            if (candidate == position) {
                seen = true;
                break;
            }
        }
        if (!seen) return error.InvalidQuerySchedule;
    }
    for (raw) |position| {
        if (position >= domain_size or findSortedPosition(unique, position) == null)
            return error.InvalidQuerySchedule;
    }
}

fn findSortedPosition(positions: []const usize, target: usize) ?usize {
    var left: usize = 0;
    var right: usize = positions.len;
    while (left < right) {
        const middle = left + (right - left) / 2;
        if (positions[middle] < target) left = middle + 1 else right = middle;
    }
    if (left < positions.len and positions[left] == target) return left;
    return null;
}

fn mapTreeQueryPosition(position: usize, max_log_size: u32, tree_log_size: u32) usize {
    if (tree_log_size == 0) return 0;
    if (max_log_size < tree_log_size) {
        return (position >> 1 << @intCast(tree_log_size - max_log_size + 1)) +
            (position & 1);
    }
    return (position >> @intCast(max_log_size - tree_log_size + 1) << 1) +
        (position & 1);
}

fn qm31Wire(value: QM31) fixed_wire.Qm31Wire {
    const coordinates = value.toM31Array();
    return .{
        coordinates[0].toU32(),
        coordinates[1].toU32(),
        coordinates[2].toU32(),
        coordinates[3].toU32(),
    };
}

fn validateM31(value: M31) Error!void {
    if (value.toU32() >= stwo_core.fields.m31.Modulus)
        return error.NonCanonicalCapture;
}

fn validateQm31(value: QM31) Error!void {
    for (value.toM31Array()) |coordinate| try validateM31(coordinate);
}

fn validateDigest(digest: engine.Hasher.Hash) Error!void {
    for (digest) |word| {
        if (word >= stwo_core.fields.m31.Modulus)
            return error.NonCanonicalCapture;
    }
}

comptime {
    if (engine.Hasher.Hash != @import("poseidon2_channel.zig").Digest)
        @compileError("fixed-wire adapter requires canonical Poseidon M31 digests");
}

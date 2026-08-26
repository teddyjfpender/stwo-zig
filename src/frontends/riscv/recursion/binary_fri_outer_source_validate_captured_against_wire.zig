//! Internal shard of binary_fri_outer_source.zig; use the public facade.

const dependency_0 = @import("binary_fri_outer_source_claims.zig");

const std = dependency_0.std;
const stwo_core = dependency_0.stwo_core;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const air_digest = dependency_0.air_digest;
const captured_fri = dependency_0.captured_fri;
const fixed_profile = dependency_0.fixed_profile;
const fixed_wire = dependency_0.fixed_wire;
const protocol = dependency_0.protocol;
const transcript_program = dependency_0.transcript_program;
const composition = dependency_0.composition;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const SOURCE_AUTHORITY_DOMAIN = dependency_0.SOURCE_AUTHORITY_DOMAIN;
const PREPARED_AUTHORITY_FORMAT_VERSION = dependency_0.PREPARED_AUTHORITY_FORMAT_VERSION;
const PREPARED_AUTHORITY_DOMAIN = dependency_0.PREPARED_AUTHORITY_DOMAIN;
const Error = dependency_0.Error;

pub fn validateCapturedAgainstWire(
    comptime dimensions: fixed_wire.Dimensions,
    capture: *const captured_fri.Owned,
    shape: fixed_profile.ProofShapeV1,
    wire: *const fixed_wire.FixedStarkProofWire(dimensions),
) !void {
    try shape.validate();
    try wire.validateAgainstShape(shape);
    try capture.circuit.validate();
    try capture.evaluation.validateAgainst(&capture.circuit);
    try capture.pcs_circuit.validate();
    try capture.pcs_evaluation.validateAgainst(&capture.pcs_circuit);

    const fri_profile = capture.circuit.profile();
    const expected_lifting = std.math.add(
        u32,
        shape.column_log_degree,
        fri_profile.log_blowup_factor,
    ) catch return error.ArithmeticOverflow;
    if (fri_profile.lifting_log_size != expected_lifting or
        fri_profile.query_count != dimensions.query_count or
        fri_profile.fold_widths.len != dimensions.fri_layer_count or
        capture.fold_widths.len != dimensions.fri_layer_count or
        capture.trace_tree_heights.len != dimensions.commitment_count or
        capture.column_log_sizes.len != dimensions.commitment_count or
        capture.trace_roots.len != dimensions.commitment_count or
        capture.trace_siblings.len != dimensions.commitment_count or
        capture.sampled_values.len != dimensions.sampled_value_count or
        capture.queried_values.len != dimensions.queried_value_count or
        capture.raw_queries.len != dimensions.query_count or
        capture.deep_answers.len != dimensions.query_count or
        capture.fri_roots.len != dimensions.fri_layer_count or
        capture.authenticated_values.len != dimensions.fri_layer_count or
        capture.fri_positions.len != dimensions.fri_layer_count or
        capture.fri_offsets.len != dimensions.fri_layer_count or
        capture.fri_layer_profiles.len != dimensions.fri_layer_count or
        capture.fri_layer_openings.len != dimensions.fri_layer_count or
        capture.fri_siblings.len != dimensions.fri_layer_count or
        capture.fri_alphas.len != dimensions.fri_layer_count or
        capture.last_layer_positions.len != dimensions.query_count or
        capture.last_layer_coefficients.len != dimensions.last_layer_coefficient_count or
        capture.sampled_value_count != dimensions.sampled_value_count or
        @as(usize, capture.queried_values_per_query) * dimensions.query_count !=
            dimensions.queried_value_count)
    {
        return error.CaptureWireMismatch;
    }

    for (capture.trace_roots, wire.commitments) |actual, expected|
        if (!std.meta.eql(actual, expected)) return error.CaptureWireMismatch;
    for (capture.sampled_values, wire.sampled_values) |actual, expected|
        if (!qm31WireEql(actual, expected)) return error.CaptureWireMismatch;
    for (capture.queried_values, wire.queried_values) |actual, expected|
        if (actual.toU32() != expected) return error.CaptureWireMismatch;
    for (capture.last_layer_coefficients, wire.last_layer_coefficients) |
        actual,
        expected,
    | if (!qm31WireEql(actual, expected)) return error.CaptureWireMismatch;

    for (
        capture.trace_tree_heights,
        capture.column_log_sizes,
        capture.trace_siblings,
        shape.tree_heights,
        shape.tree_column_counts,
        0..,
    ) |height, logs, siblings, expected_height, expected_columns, tree| {
        if (height != expected_height or
            logs.len != expected_columns or
            siblings.len != dimensions.query_count * height)
        {
            return error.CaptureWireMismatch;
        }
        var maximum_log: u32 = 0;
        for (logs) |log_size| {
            if (log_size == 0 or log_size > height)
                return error.CaptureWireMismatch;
            maximum_log = @max(maximum_log, log_size);
        }
        if (maximum_log != height) return error.CaptureWireMismatch;
        for (0..dimensions.query_count) |query| {
            const path = wire.trace_paths[tree * dimensions.query_count + query];
            if (path.active_depth != height) return error.CaptureWireMismatch;
            for (0..height) |depth| if (!std.meta.eql(
                siblings[query * height + depth],
                path.siblings[depth],
            )) return error.CaptureWireMismatch;
        }
    }

    var consumed_folds: u32 = 0;
    for (shape.fri.active(), 0..) |round, layer_index| {
        const wire_layer = wire.fri_layers[layer_index];
        const width: usize = @intCast(round.fold_width);
        const captured_profile = capture.fri_layer_profiles[layer_index];
        const captured_opening = capture.fri_layer_openings[layer_index];
        if (capture.fold_widths[layer_index] != round.fold_width or
            fri_profile.fold_widths[layer_index] != round.fold_width or
            wire_layer.active_width != round.fold_width or
            captured_profile.width != round.fold_width or
            captured_opening.width != round.fold_width or
            captured_opening.values.len !=
                dimensions.query_count * width * 4 or
            !std.meta.eql(capture.fri_roots[layer_index], wire_layer.commitment) or
            capture.authenticated_values[layer_index].len !=
                dimensions.query_count * width or
            capture.fri_positions[layer_index].len != dimensions.query_count or
            capture.fri_offsets[layer_index].len != dimensions.query_count or
            capture.fri_siblings[layer_index].len !=
                dimensions.query_count * round.authentication_path_depth)
        {
            return error.CaptureWireMismatch;
        }
        for (0..dimensions.query_count) |query| {
            const raw = capture.raw_queries[query].toU32();
            const expected_position = raw >> @intCast(consumed_folds);
            if (capture.fri_positions[layer_index][query].toU32() != expected_position or
                capture.fri_offsets[layer_index][query].toU32() !=
                    (expected_position & (round.fold_width - 1)))
            {
                return error.InvalidQuerySchedule;
            }
            const wire_query = wire_layer.queries[query];
            if (wire_query.path.active_depth != round.authentication_path_depth)
                return error.CaptureWireMismatch;
            for (0..width) |offset| if (!qm31WireEql(
                capture.authenticated_values[layer_index][query * width + offset],
                wire_query.values[offset],
            )) return error.CaptureWireMismatch;
            for (0..width) |offset| {
                const secure_value = capture.authenticated_values[layer_index][
                    query * width + offset
                ].toM31Array();
                const first_word = (query * width + offset) * 4;
                for (secure_value, captured_opening.values[first_word..][0..4]) |
                    actual,
                    projected,
                | if (!actual.eql(projected)) return error.CaptureWireMismatch;
            }
            for (0..round.authentication_path_depth) |depth| if (!std.meta.eql(
                capture.fri_siblings[layer_index][
                    query *
                        round.authentication_path_depth + depth
                ],
                wire_query.path.siblings[depth],
            )) return error.CaptureWireMismatch;
        }
        consumed_folds = std.math.add(u32, consumed_folds, round.fold_step) catch
            return error.ArithmeticOverflow;
    }
    for (capture.raw_queries, capture.last_layer_positions) |raw, terminal| {
        if (terminal.toU32() != raw.toU32() >> @intCast(consumed_folds))
            return error.InvalidQuerySchedule;
    }

    const pcs_profile = capture.pcs_circuit.profile();
    if (pcs_profile.lifting_log_size != fri_profile.lifting_log_size or
        pcs_profile.log_blowup_factor != fri_profile.log_blowup_factor or
        pcs_profile.query_count != fri_profile.query_count or
        pcs_profile.trees.len != capture.column_log_sizes.len or
        pcs_profile.sample_layouts.len != capture.sample_layouts.len)
    {
        return error.ProfileMismatch;
    }
    for (pcs_profile.trees, capture.column_log_sizes) |tree, logs|
        if (!std.mem.eql(u32, tree.column_log_sizes, logs))
            return error.ProfileMismatch;
    if (!std.mem.eql(
        @TypeOf(capture.sample_layouts[0]),
        pcs_profile.sample_layouts,
        capture.sample_layouts,
    )) return error.ProfileMismatch;
}

pub fn validateExecutionAgainstCapture(
    execution: *const transcript_program.Execution,
    capture: *const captured_fri.Owned,
    query_words: []M31,
) !void {
    if (query_words.len != capture.raw_queries.len or
        capture.circuit.lifting_log_size == 0 or
        capture.circuit.lifting_log_size >= 31)
    {
        return error.InvalidQuerySchedule;
    }
    var saw_composition = false;
    var saw_oods = false;
    var saw_deep = false;
    var alpha_count: usize = 0;
    var query_count: usize = 0;
    var saw_interaction_pow = false;
    var saw_pcs_pow = false;
    for (execution.operations) |operation| switch (operation.step) {
        .draw_composition_randomness => {
            if (saw_composition or
                !(try drawSecure(operation)).eql(capture.composition_randomness))
                return error.CaptureTranscriptMismatch;
            saw_composition = true;
        },
        .draw_oods_point => {
            if (saw_oods or !(try drawSecure(operation)).eql(capture.oods_seed))
                return error.CaptureTranscriptMismatch;
            saw_oods = true;
        },
        .draw_deep_randomness => {
            if (saw_deep or !(try drawSecure(operation)).eql(capture.deep_randomness))
                return error.CaptureTranscriptMismatch;
            saw_deep = true;
        },
        .draw_fri_alpha => |step| {
            if (@as(usize, step.layer) != alpha_count or alpha_count >= capture.fri_alphas.len or
                !(try drawSecure(operation)).eql(capture.fri_alphas[alpha_count]))
            {
                return error.CaptureTranscriptMismatch;
            }
            alpha_count += 1;
        },
        .draw_query_block => |step| {
            const draw = operation.draw orelse return error.CaptureTranscriptMismatch;
            const first: usize = @intCast(step.first_query);
            const count: usize = @intCast(step.query_count);
            if (@as(usize, step.block) != query_count / transcript_program.RATE or
                first != query_count or count == 0 or count > transcript_program.RATE or
                first > query_words.len or count > query_words.len - first)
            {
                return error.InvalidQuerySchedule;
            }
            @memcpy(query_words[first..][0..count], draw[0..count]);
            query_count += count;
        },
        .verify_and_absorb_interaction_pow => |step| {
            if (saw_interaction_pow or step.bits != capture.interaction_pow_bits)
                return error.CaptureTranscriptMismatch;
            saw_interaction_pow = true;
        },
        .verify_and_absorb_pcs_pow => |step| {
            if (saw_pcs_pow or step.bits != capture.pcs_pow_bits)
                return error.CaptureTranscriptMismatch;
            saw_pcs_pow = true;
        },
        else => {},
    };
    if (!saw_composition or !saw_oods or !saw_deep or
        alpha_count != capture.fri_alphas.len or
        query_count != query_words.len or !saw_interaction_pow or !saw_pcs_pow)
    {
        return error.CaptureTranscriptMismatch;
    }
    const mask = (@as(u32, 1) << @intCast(capture.circuit.lifting_log_size)) - 1;
    for (query_words, capture.raw_queries) |full, projected| {
        if ((full.toU32() & mask) != projected.toU32())
            return error.InvalidQuerySchedule;
    }
}

pub fn drawSecure(operation: transcript_program.Operation) Error!QM31 {
    const draw = operation.draw orelse return error.CaptureTranscriptMismatch;
    return QM31.fromM31Array(draw[0..4].*);
}

pub fn qm31WireEql(value: QM31, wire: fixed_wire.Qm31Wire) bool {
    const coordinates = value.toM31Array();
    for (coordinates, wire) |coordinate, word|
        if (coordinate.toU32() != word) return false;
    return true;
}

pub fn m31SliceEql(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!lhs.eql(rhs)) return false;
    return true;
}

pub fn traceLogSize(row_count: usize) !u32 {
    const result: u32 = @max(
        @as(u32, 4),
        @as(u32, @intCast(std.math.log2_int_ceil(usize, @max(row_count, 1)))),
    );
    if (result > 30) return error.LogSizeOutOfRange;
    return result;
}

pub fn validateProtocolDigest(value: protocol.Digest) Error!void {
    for (value) |word| if (word >= stwo_core.fields.m31.Modulus)
        return error.InvalidCompositionProfile;
}

pub fn hashRecursionInputSource(hash: anytype, source: composition.RecursionSource) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source)));
    switch (source) {
        .parent_binary_selector => {},
        .child_kind_selector => |kind| hashInt(hash, u8, @intFromEnum(kind)),
        .statement_word => |word| hashInt(hash, u32, word),
        .sampled_value, .claimed_sum, .public_wire_boundary => |coordinate| {
            hashInt(hash, u32, coordinate.item_index);
            hashInt(hash, u32, coordinate.word_index);
        },
        .relation_challenge => |coordinate| {
            hashInt(hash, u32, coordinate.challenge);
            hashInt(hash, u32, coordinate.word_index);
        },
        .composition_randomness, .oods_point => |word| hashInt(hash, u32, word),
    }
}

pub fn preparedAuthorityDigest(authority: anytype) air_digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PREPARED_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, PREPARED_AUTHORITY_FORMAT_VERSION);
    hashInt(&hash, u16, FORMAT_VERSION);
    hash.update(&authority.source_authority_digest);
    hash.update(&authority.composition_authority_digest);
    hash.update(&authority.fri_authority_digest);
    hash.update(&authority.arithmetic_authority_digest);
    hash.update(&authority.merkle_authority_digest);
    for (authority.bundle_log_sizes) |log_size|
        hashInt(&hash, u32, log_size);
    return hash.finalResult();
}

pub fn sourceAuthorityDigest(source: anytype) air_digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SOURCE_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    for (source.vm_plan.authority_digest) |word| hashInt(&hash, u32, word);
    for (source.recursion_plans) |plan| for (plan.authority_digest) |word|
        hashInt(&hash, u32, word);
    for (source.pair.authenticated_root.pair.node_id) |word| hashInt(&hash, u32, word);
    for (source.children, &source.pair.authority.children) |child, *verified| {
        for (verified.proof_id) |word| hashInt(&hash, u32, word);
        const shape_id = child.shape.id() catch unreachable;
        for (shape_id) |word| hashInt(&hash, u32, word);
        hash.update(&child.capture.circuit.identity_digest);
        hash.update(&child.capture.pcs_circuit.identity_digest);
        hashQm31Slice(&hash, child.capture.evaluation.values);
        hashQm31Slice(&hash, child.capture.pcs_evaluation.values);
        if (child.composition) |composition_authority|
            hash.update(&composition_authority.authority_digest)
        else
            hash.update(&[_]u8{0} ** @sizeOf(air_digest.Digest));
    }
    for (source.query_word_storage) |word| hashInt(&hash, u32, word.toU32());
    if (source.shared_arithmetic) |input| {
        hashInt(&hash, u8, 1);
        hash.update(&input.identity_digest);
    } else {
        hashInt(&hash, u8, 0);
    }
    if (source.composition_rows) |*rows| {
        hashInt(&hash, u8, 1);
        hash.update(&rows.authority_digest);
    } else {
        hashInt(&hash, u8, 0);
    }
    hash.update(&source.fri_rows.authority_digest);
    if (source.arithmetic_rows) |*rows| {
        hashInt(&hash, u8, 1);
        hash.update(&rows.authority_digest);
    } else {
        hashInt(&hash, u8, 0);
    }
    hash.update(&source.merkle_rows.authority_digest);
    return hash.finalResult();
}

pub fn hashQm31Slice(hash: anytype, values: []const QM31) void {
    hashInt(hash, u64, values.len);
    for (values) |value| for (value.toM31Array()) |word|
        hashInt(hash, u32, word.toU32());
}

pub fn qm31FromCanonicalWords(words: [4]u32) Error!QM31 {
    for (words) |word| if (word >= stwo_core.fields.m31.Modulus)
        return error.CompositionAuthorityMismatch;
    return QM31.fromM31Array(.{
        M31.fromCanonical(words[0]),
        M31.fromCanonical(words[1]),
        M31.fromCanonical(words[2]),
        M31.fromCanonical(words[3]),
    });
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

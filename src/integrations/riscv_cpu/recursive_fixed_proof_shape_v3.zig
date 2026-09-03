//! Pointer-free authority for one exact recursive STARK proof wire.
//!
//! A common wrapper cannot be selected from component padding alone.  Its
//! verifier wire also depends on every ordered commitment-tree column, OODS
//! sample count, query/path counts, and the FRI schedule.  This value is minted
//! only from a successful kind-specific cold verifier and is compared exactly
//! across all wrapper roles by the recursive circuit registry.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 2;
pub const TREE_COUNT: usize = 4;
pub const MAX_TREE_COLUMN_COUNT: usize = 2048;
pub const MAX_FRI_LAYER_COUNT: usize = 32;
pub const MAX_DOMAIN_LOG: u8 = 30;

const IDENTITY_DOMAIN =
    "stwo-zig/recursive-fixed-proof-shape/v3\x00";

pub const Error = error{
    InvalidFixedProofShape,
    FixedProofShapePcsMismatch,
};

/// The exact runtime facts which select `fixed_wire.Dimensions`.  Ordered
/// `tree_column_log_sizes` are the four verifier-capture log vectors in
/// commitment order: preprocessed, main, interaction, composition.
pub const AuthorityV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    tree_count: u8 = TREE_COUNT,
    maximum_merkle_depth: u8,
    claimed_sum_count: u16,
    fri_layer_count: u16,
    query_count: u16,
    maximum_fold_width: u8,
    column_log_degree: u8,
    reserved: [2]u8 = .{ 0, 0 },
    sampled_value_count: u32,
    queried_value_count: u32,
    trace_path_count: u32,
    trace_sibling_count: u32,
    fri_value_count: u32,
    fri_sibling_count: u32,
    last_layer_coefficient_count: u32,
    tree_column_counts: [TREE_COUNT]u16,
    tree_column_log_sizes: [TREE_COUNT][MAX_TREE_COLUMN_COUNT]u8,
    /// OODS mask cardinality for every ordered commitment-tree column.
    tree_column_sample_counts: [TREE_COUNT][MAX_TREE_COLUMN_COUNT]u8,
    /// Exact FRI layer wire, including a possibly narrower final fold.
    fri_layer_fold_widths: [MAX_FRI_LAYER_COUNT]u8,
    fri_layer_path_depths: [MAX_FRI_LAYER_COUNT]u8,
    table_layout_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn seal(value: AuthorityV3) Error!AuthorityV3 {
        var result = value;
        result.identity_sha256 = identity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const AuthorityV3) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.tree_count != TREE_COUNT or
            self.claimed_sum_count == 0 or self.fri_layer_count == 0 or
            self.fri_layer_count > MAX_FRI_LAYER_COUNT or
            self.query_count == 0 or self.maximum_fold_width == 0 or
            !std.math.isPowerOfTwo(self.maximum_fold_width) or
            self.maximum_fold_width > 16 or
            self.column_log_degree == 0 or
            self.column_log_degree > MAX_DOMAIN_LOG or
            self.maximum_merkle_depth == 0 or
            self.maximum_merkle_depth > MAX_DOMAIN_LOG or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.sampled_value_count == 0 or
            self.queried_value_count == 0 or self.trace_path_count == 0 or
            self.trace_sibling_count == 0 or self.fri_value_count == 0 or
            self.fri_sibling_count == 0 or
            self.last_layer_coefficient_count == 0 or
            !std.math.isPowerOfTwo(self.last_layer_coefficient_count) or
            std.mem.allEqual(u8, &self.table_layout_identity_sha256, 0))
        {
            return error.InvalidFixedProofShape;
        }

        var total_columns: u32 = 0;
        var total_samples: u32 = 0;
        var maximum_log: u8 = 0;
        var total_trace_siblings: u32 = 0;
        for (
            self.tree_column_counts,
            &self.tree_column_log_sizes,
            &self.tree_column_sample_counts,
        ) |
            column_count,
            *logs,
            *sample_counts,
        | {
            if (column_count == 0 or column_count > MAX_TREE_COLUMN_COUNT)
                return error.InvalidFixedProofShape;
            total_columns = std.math.add(
                u32,
                total_columns,
                column_count,
            ) catch return error.InvalidFixedProofShape;
            for (logs[0..column_count], sample_counts[0..column_count]) |
                log_size,
                sample_count,
            | {
                if (log_size == 0 or log_size > MAX_DOMAIN_LOG)
                    return error.InvalidFixedProofShape;
                maximum_log = @max(maximum_log, log_size);
                total_samples = std.math.add(
                    u32,
                    total_samples,
                    sample_count,
                ) catch return error.InvalidFixedProofShape;
            }
            if (!std.mem.allEqual(u8, logs[column_count..], 0) or
                !std.mem.allEqual(u8, sample_counts[column_count..], 0))
            {
                return error.InvalidFixedProofShape;
            }
            const tree_depth = maxLog(logs[0..column_count]);
            total_trace_siblings = std.math.add(
                u32,
                total_trace_siblings,
                std.math.mul(
                    u32,
                    tree_depth,
                    self.query_count,
                ) catch return error.InvalidFixedProofShape,
            ) catch return error.InvalidFixedProofShape;
        }
        var observed_maximum_fold_width: u8 = 0;
        var total_fri_values: u32 = 0;
        var total_fri_siblings: u32 = 0;
        for (
            self.fri_layer_fold_widths[0..self.fri_layer_count],
            self.fri_layer_path_depths[0..self.fri_layer_count],
        ) |fold_width, path_depth| {
            if (fold_width == 0 or !std.math.isPowerOfTwo(fold_width) or
                fold_width > 16 or path_depth == 0 or
                path_depth > MAX_DOMAIN_LOG)
            {
                return error.InvalidFixedProofShape;
            }
            observed_maximum_fold_width = @max(
                observed_maximum_fold_width,
                fold_width,
            );
            maximum_log = @max(maximum_log, path_depth);
            total_fri_values = std.math.add(
                u32,
                total_fri_values,
                std.math.mul(
                    u32,
                    fold_width,
                    self.query_count,
                ) catch return error.InvalidFixedProofShape,
            ) catch return error.InvalidFixedProofShape;
            total_fri_siblings = std.math.add(
                u32,
                total_fri_siblings,
                std.math.mul(
                    u32,
                    path_depth,
                    self.query_count,
                ) catch return error.InvalidFixedProofShape,
            ) catch return error.InvalidFixedProofShape;
        }
        if (!std.mem.allEqual(
            u8,
            self.fri_layer_fold_widths[self.fri_layer_count..],
            0,
        ) or !std.mem.allEqual(
            u8,
            self.fri_layer_path_depths[self.fri_layer_count..],
            0,
        )) return error.InvalidFixedProofShape;
        const expected_queried = std.math.mul(
            u32,
            total_columns,
            self.query_count,
        ) catch return error.InvalidFixedProofShape;
        const expected_paths = std.math.mul(
            u32,
            TREE_COUNT,
            self.query_count,
        ) catch return error.InvalidFixedProofShape;
        if (self.sampled_value_count != total_samples or
            self.queried_value_count != expected_queried or
            self.trace_path_count != expected_paths or
            self.trace_sibling_count != total_trace_siblings or
            self.fri_value_count != total_fri_values or
            self.fri_sibling_count != total_fri_siblings or
            self.maximum_merkle_depth != maximum_log or
            self.maximum_fold_width != observed_maximum_fold_width or
            !std.mem.eql(u8, &self.identity_sha256, &identity(self)))
        {
            return error.InvalidFixedProofShape;
        }
    }

    pub fn validateAgainstPcs(
        self: *const AuthorityV3,
        fri_log_blowup_factor: u32,
        fri_query_count: u32,
        fri_fold_step: u32,
        fri_log_last_layer_degree_bound: u32,
    ) Error!void {
        try self.validate();
        if (fri_log_blowup_factor == 0 or fri_fold_step == 0 or
            fri_fold_step > 4 or
            fri_query_count != self.query_count or
            fri_log_last_layer_degree_bound >= self.column_log_degree)
        {
            return error.FixedProofShapePcsMismatch;
        }
        const difference = self.column_log_degree -
            @as(u8, @intCast(fri_log_last_layer_degree_bound));
        const expected_layers = std.math.divCeil(
            u16,
            difference,
            @as(u16, @intCast(fri_fold_step)),
        ) catch return error.FixedProofShapePcsMismatch;
        const expected_last_coefficients = @as(u32, 1) <<
            @intCast(fri_log_last_layer_degree_bound);
        var remaining = difference;
        for (self.fri_layer_fold_widths[0..self.fri_layer_count]) |width| {
            const fold_log = @min(
                @as(u8, @intCast(fri_fold_step)),
                remaining,
            );
            const expected_width = @as(u8, 1) << @intCast(fold_log);
            if (width != expected_width)
                return error.FixedProofShapePcsMismatch;
            remaining -= fold_log;
        }
        var composition_max_log: u8 = 0;
        const composition_count = self.tree_column_counts[TREE_COUNT - 1];
        for (self.tree_column_log_sizes[TREE_COUNT - 1][0..composition_count]) |
            log_size,
        | composition_max_log = @max(composition_max_log, log_size);
        const expected_composition_log = std.math.add(
            u32,
            self.column_log_degree,
            fri_log_blowup_factor,
        ) catch return error.FixedProofShapePcsMismatch;
        if (self.fri_layer_count != expected_layers or remaining != 0 or
            self.last_layer_coefficient_count != expected_last_coefficients or
            composition_max_log != expected_composition_log)
        {
            return error.FixedProofShapePcsMismatch;
        }
    }
};

/// Mints the complete fixed-wire authority only from verifier-owned expanded
/// capture material. No producer geometry, proof header, or host estimate is
/// accepted as a substitute for these lengths.
pub fn sealFromCapture(
    capture: anytype,
    claimed_sum_count: u16,
    column_log_degree: u8,
    table_layout_identity_sha256: [32]u8,
) Error!AuthorityV3 {
    if (capture.commitments.len != TREE_COUNT or
        capture.column_log_sizes.len != TREE_COUNT or
        capture.sampled_points.len != TREE_COUNT or
        capture.trace_paths.len != TREE_COUNT or
        capture.queries.raw.len == 0 or
        capture.deep_answers.len != capture.queries.raw.len)
    {
        return error.InvalidFixedProofShape;
    }
    const query_count = std.math.cast(
        u16,
        capture.queries.raw.len,
    ) orelse return error.InvalidFixedProofShape;
    var column_counts = [_]u16{0} ** TREE_COUNT;
    var column_logs = [_][MAX_TREE_COLUMN_COUNT]u8{
        [_]u8{0} ** MAX_TREE_COLUMN_COUNT,
    } ** TREE_COUNT;
    var sample_counts = [_][MAX_TREE_COLUMN_COUNT]u8{
        [_]u8{0} ** MAX_TREE_COLUMN_COUNT,
    } ** TREE_COUNT;
    var maximum_merkle_depth: u8 = 0;
    var trace_sibling_count: u32 = 0;
    for (
        capture.column_log_sizes,
        capture.sampled_points,
        capture.trace_paths,
        0..,
    ) |logs, samples, path, tree_index| {
        if (logs.len == 0 or logs.len > MAX_TREE_COLUMN_COUNT or
            samples.len != logs.len or path.positions.len != query_count)
        {
            return error.InvalidFixedProofShape;
        }
        column_counts[tree_index] = std.math.cast(u16, logs.len) orelse
            return error.InvalidFixedProofShape;
        var tree_max_log: u8 = 0;
        for (logs, samples, 0..) |log_size, points, column_index| {
            const log_u8 = std.math.cast(u8, log_size) orelse
                return error.InvalidFixedProofShape;
            const sample_count = std.math.cast(u8, points.len) orelse
                return error.InvalidFixedProofShape;
            if (log_u8 == 0) return error.InvalidFixedProofShape;
            column_logs[tree_index][column_index] = log_u8;
            sample_counts[tree_index][column_index] = sample_count;
            tree_max_log = @max(tree_max_log, log_u8);
        }
        if (path.path_depth != tree_max_log or
            path.siblings.len != capture.queries.raw.len * tree_max_log)
        {
            return error.InvalidFixedProofShape;
        }
        maximum_merkle_depth = @max(maximum_merkle_depth, tree_max_log);
        trace_sibling_count = std.math.add(
            u32,
            trace_sibling_count,
            std.math.cast(u32, path.siblings.len) orelse
                return error.InvalidFixedProofShape,
        ) catch return error.InvalidFixedProofShape;
    }

    if (capture.fri.layers.len == 0 or
        capture.fri.layers.len > MAX_FRI_LAYER_COUNT)
    {
        return error.InvalidFixedProofShape;
    }
    var fri_fold_widths = [_]u8{0} ** MAX_FRI_LAYER_COUNT;
    var fri_path_depths = [_]u8{0} ** MAX_FRI_LAYER_COUNT;
    var maximum_fold_width: u8 = 0;
    var fri_value_count: u32 = 0;
    var fri_sibling_count: u32 = 0;
    for (capture.fri.layers, 0..) |layer, layer_index| {
        const fold_width = std.math.cast(u8, layer.fold_width) orelse
            return error.InvalidFixedProofShape;
        const path_depth = std.math.cast(u8, layer.path_depth) orelse
            return error.InvalidFixedProofShape;
        if (layer.query_count != capture.queries.raw.len or
            layer.positions.len != capture.queries.raw.len or
            layer.values.len != capture.queries.raw.len * fold_width or
            layer.siblings.len != capture.queries.raw.len * path_depth)
        {
            return error.InvalidFixedProofShape;
        }
        fri_fold_widths[layer_index] = fold_width;
        fri_path_depths[layer_index] = path_depth;
        maximum_fold_width = @max(maximum_fold_width, fold_width);
        maximum_merkle_depth = @max(maximum_merkle_depth, path_depth);
        fri_value_count = std.math.add(
            u32,
            fri_value_count,
            std.math.cast(u32, layer.values.len) orelse
                return error.InvalidFixedProofShape,
        ) catch return error.InvalidFixedProofShape;
        fri_sibling_count = std.math.add(
            u32,
            fri_sibling_count,
            std.math.cast(u32, layer.siblings.len) orelse
                return error.InvalidFixedProofShape,
        ) catch return error.InvalidFixedProofShape;
    }

    return AuthorityV3.seal(.{
        .maximum_merkle_depth = maximum_merkle_depth,
        .claimed_sum_count = claimed_sum_count,
        .fri_layer_count = std.math.cast(u16, capture.fri.layers.len) orelse
            return error.InvalidFixedProofShape,
        .query_count = query_count,
        .maximum_fold_width = maximum_fold_width,
        .column_log_degree = column_log_degree,
        .sampled_value_count = std.math.cast(
            u32,
            capture.sampled_values.len,
        ) orelse return error.InvalidFixedProofShape,
        .queried_value_count = std.math.cast(
            u32,
            capture.queried_values.len,
        ) orelse return error.InvalidFixedProofShape,
        .trace_path_count = std.math.mul(
            u32,
            TREE_COUNT,
            query_count,
        ) catch return error.InvalidFixedProofShape,
        .trace_sibling_count = trace_sibling_count,
        .fri_value_count = fri_value_count,
        .fri_sibling_count = fri_sibling_count,
        .last_layer_coefficient_count = std.math.cast(
            u32,
            capture.last_layer_coefficients.len,
        ) orelse return error.InvalidFixedProofShape,
        .tree_column_counts = column_counts,
        .tree_column_log_sizes = column_logs,
        .tree_column_sample_counts = sample_counts,
        .fri_layer_fold_widths = fri_fold_widths,
        .fri_layer_path_depths = fri_path_depths,
        .table_layout_identity_sha256 = table_layout_identity_sha256,
        .identity_sha256 = undefined,
    });
}

fn identity(value: *const AuthorityV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, value.tree_count);
    hashInt(&hash, u8, value.maximum_merkle_depth);
    hashInt(&hash, u16, value.claimed_sum_count);
    hashInt(&hash, u16, value.fri_layer_count);
    hashInt(&hash, u16, value.query_count);
    hashInt(&hash, u8, value.maximum_fold_width);
    hashInt(&hash, u8, value.column_log_degree);
    hash.update(&value.reserved);
    hashInt(&hash, u32, value.sampled_value_count);
    hashInt(&hash, u32, value.queried_value_count);
    hashInt(&hash, u32, value.trace_path_count);
    hashInt(&hash, u32, value.trace_sibling_count);
    hashInt(&hash, u32, value.fri_value_count);
    hashInt(&hash, u32, value.fri_sibling_count);
    hashInt(&hash, u32, value.last_layer_coefficient_count);
    for (value.tree_column_counts) |count| hashInt(&hash, u16, count);
    for (value.tree_column_log_sizes) |logs| hash.update(&logs);
    for (value.tree_column_sample_counts) |counts| hash.update(&counts);
    hash.update(&value.fri_layer_fold_widths);
    hash.update(&value.fri_layer_path_depths);
    hash.update(&value.table_layout_identity_sha256);
    return hash.finalResult();
}

fn maxLog(logs: []const u8) u8 {
    var result: u8 = 0;
    for (logs) |log_size| result = @max(result, log_size);
    return result;
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (SCHEMA_VERSION != 2 or TREE_COUNT != 4 or
        MAX_TREE_COLUMN_COUNT < 1044 or MAX_FRI_LAYER_COUNT < 8 or
        MAX_DOMAIN_LOG != 30)
    {
        @compileError("recursive fixed proof shape constants drifted");
    }
}

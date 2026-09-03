//! Allocation-free lower bounds for PCS column residency.
//!
//! The estimate covers the extended-domain evaluations retained by a
//! commitment tree and, when required by policy, the coefficient-form copy.
//! It deliberately excludes Merkle nodes, source/witness construction,
//! twiddles, composition, and allocator overhead. Therefore exceeding a host
//! budget is a sound early rejection; fitting the estimate is not an
//! admission guarantee.

const std = @import("std");
const column_storage = @import("columns/storage.zig");

pub const RetentionPolicy = column_storage.CoefficientRetentionPolicy;

pub const Error = error{
    InvalidColumnLogSize,
    ResidencyEstimateOverflow,
    PcsResidentBudgetExceeded,
};

pub const Estimate = struct {
    column_count: u64,
    source_cells: u64,
    extended_cells: u64,
    source_bytes: u64,
    retained_coefficient_bytes: u64,
    extended_evaluation_bytes: u64,
    minimum_resident_bytes: u64,
    max_column_log_size: u32,
    log_blowup_factor: u32,
    retention_policy: RetentionPolicy,

    pub fn requireWithin(self: Estimate, host_byte_budget: u64) Error!void {
        if (self.minimum_resident_bytes > host_byte_budget)
            return error.PcsResidentBudgetExceeded;
    }
};

/// Returns a checked lower bound without allocating or touching column data.
///
/// `.auto` uses zero retained coefficient bytes because its final choice is
/// made per prepared batch. This preserves the lower-bound contract. The
/// source byte count remains available to callers as useful peak telemetry.
pub fn estimate(
    column_log_sizes: []const u32,
    log_blowup_factor: u32,
    retention_policy: RetentionPolicy,
) Error!Estimate {
    var source_cells: u64 = 0;
    var extended_cells: u64 = 0;
    var max_column_log_size: u32 = 0;

    for (column_log_sizes) |log_size| {
        const extended_log = std.math.add(
            u32,
            log_size,
            log_blowup_factor,
        ) catch return error.ResidencyEstimateOverflow;
        if (log_size >= @bitSizeOf(u64) or extended_log >= @bitSizeOf(u64))
            return error.InvalidColumnLogSize;

        source_cells = std.math.add(
            u64,
            source_cells,
            @as(u64, 1) << @intCast(log_size),
        ) catch return error.ResidencyEstimateOverflow;
        extended_cells = std.math.add(
            u64,
            extended_cells,
            @as(u64, 1) << @intCast(extended_log),
        ) catch return error.ResidencyEstimateOverflow;
        max_column_log_size = @max(max_column_log_size, log_size);
    }

    const field_bytes: u64 = @sizeOf(@import("stwo_core").fields.m31.M31);
    const source_bytes = std.math.mul(
        u64,
        source_cells,
        field_bytes,
    ) catch return error.ResidencyEstimateOverflow;
    const extended_evaluation_bytes = std.math.mul(
        u64,
        extended_cells,
        field_bytes,
    ) catch return error.ResidencyEstimateOverflow;
    const retained_coefficient_bytes = switch (retention_policy) {
        .always => source_bytes,
        .auto, .never => 0,
    };
    const minimum_resident_bytes = std.math.add(
        u64,
        retained_coefficient_bytes,
        extended_evaluation_bytes,
    ) catch return error.ResidencyEstimateOverflow;

    return .{
        .column_count = std.math.cast(u64, column_log_sizes.len) orelse
            return error.ResidencyEstimateOverflow,
        .source_cells = source_cells,
        .extended_cells = extended_cells,
        .source_bytes = source_bytes,
        .retained_coefficient_bytes = retained_coefficient_bytes,
        .extended_evaluation_bytes = extended_evaluation_bytes,
        .minimum_resident_bytes = minimum_resident_bytes,
        .max_column_log_size = max_column_log_size,
        .log_blowup_factor = log_blowup_factor,
        .retention_policy = retention_policy,
    };
}

/// Checked lower bound for a tree whose columns all share one log size.
///
/// This avoids manufacturing a temporary log-size array in early admission
/// and shard-planning paths.
pub fn estimateUniform(
    column_count: u64,
    column_log_size: u32,
    log_blowup_factor: u32,
    retention_policy: RetentionPolicy,
) Error!Estimate {
    const extended_log = std.math.add(
        u32,
        column_log_size,
        log_blowup_factor,
    ) catch return error.ResidencyEstimateOverflow;
    if (column_log_size >= @bitSizeOf(u64) or extended_log >= @bitSizeOf(u64))
        return error.InvalidColumnLogSize;

    const source_cells = std.math.mul(
        u64,
        column_count,
        @as(u64, 1) << @intCast(column_log_size),
    ) catch return error.ResidencyEstimateOverflow;
    const extended_cells = std.math.mul(
        u64,
        column_count,
        @as(u64, 1) << @intCast(extended_log),
    ) catch return error.ResidencyEstimateOverflow;
    const field_bytes: u64 = @sizeOf(@import("stwo_core").fields.m31.M31);
    const source_bytes = std.math.mul(
        u64,
        source_cells,
        field_bytes,
    ) catch return error.ResidencyEstimateOverflow;
    const extended_evaluation_bytes = std.math.mul(
        u64,
        extended_cells,
        field_bytes,
    ) catch return error.ResidencyEstimateOverflow;
    const retained_coefficient_bytes = switch (retention_policy) {
        .always => source_bytes,
        .auto, .never => 0,
    };
    const minimum_resident_bytes = std.math.add(
        u64,
        retained_coefficient_bytes,
        extended_evaluation_bytes,
    ) catch return error.ResidencyEstimateOverflow;

    return .{
        .column_count = column_count,
        .source_cells = source_cells,
        .extended_cells = extended_cells,
        .source_bytes = source_bytes,
        .retained_coefficient_bytes = retained_coefficient_bytes,
        .extended_evaluation_bytes = extended_evaluation_bytes,
        .minimum_resident_bytes = minimum_resident_bytes,
        .max_column_log_size = column_log_size,
        .log_blowup_factor = log_blowup_factor,
        .retention_policy = retention_policy,
    };
}

test "residency estimate reproduces real log24 Poseidon provider lower bound" {
    const provider_logs = [_]u32{24} ** 445;
    const result = try estimate(&provider_logs, 1, .always);

    try std.testing.expectEqual(@as(u64, 445), result.column_count);
    try std.testing.expectEqual(@as(u64, 7_465_861_120), result.source_cells);
    try std.testing.expectEqual(@as(u64, 14_931_722_240), result.extended_cells);
    try std.testing.expectEqual(@as(u64, 29_863_444_480), result.source_bytes);
    try std.testing.expectEqual(
        @as(u64, 59_726_888_960),
        result.extended_evaluation_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 89_590_333_440),
        result.minimum_resident_bytes,
    );
    try std.testing.expectError(
        error.PcsResidentBudgetExceeded,
        result.requireWithin(64 * 1024 * 1024 * 1024),
    );
}

test "log20 provider shard has a bounded sequential residency envelope" {
    const shard_logs = [_]u32{20} ** 445;
    const result = try estimate(&shard_logs, 1, .always);

    try std.testing.expectEqual(@as(u64, 466_616_320), result.source_cells);
    try std.testing.expectEqual(
        @as(u64, 5_599_395_840),
        result.minimum_resident_bytes,
    );
    try result.requireWithin(6 * 1024 * 1024 * 1024);
}

test "retention policies and overflow preserve the lower-bound contract" {
    const logs = [_]u32{10};
    const always = try estimate(&logs, 1, .always);
    const automatic = try estimate(&logs, 1, .auto);
    const never = try estimate(&logs, 1, .never);

    try std.testing.expectEqual(@as(u64, 4096), always.source_bytes);
    try std.testing.expectEqual(@as(u64, 8192), always.extended_evaluation_bytes);
    try std.testing.expectEqual(@as(u64, 12_288), always.minimum_resident_bytes);
    try std.testing.expectEqual(@as(u64, 8192), automatic.minimum_resident_bytes);
    try std.testing.expectEqual(
        automatic.minimum_resident_bytes,
        never.minimum_resident_bytes,
    );

    try std.testing.expectError(
        error.InvalidColumnLogSize,
        estimate(&.{63}, 1, .always),
    );
    try std.testing.expectError(
        error.ResidencyEstimateOverflow,
        estimate(&.{std.math.maxInt(u32)}, 1, .always),
    );
}

test "uniform estimate equals the heterogeneous estimator" {
    const logs = [_]u32{17} ** 19;
    const expected = try estimate(&logs, 2, .never);
    const actual = try estimateUniform(logs.len, 17, 2, .never);
    try std.testing.expectEqualDeep(expected, actual);
}

test "degree-bounded Poseidon profiles expose the log24 residency frontier" {
    const degree_five = try estimateUniform(239, 24, 1, .always);
    try std.testing.expectEqual(
        @as(u64, 48_117_055_488),
        degree_five.minimum_resident_bytes,
    );
    const degree_five_bounded = try estimateUniform(239, 24, 1, .never);
    try std.testing.expectEqual(
        @as(u64, 32_078_036_992),
        degree_five_bounded.minimum_resident_bytes,
    );
    const degree_six = try estimateUniform(161, 24, 1, .always);
    try std.testing.expectEqual(
        @as(u64, 32_413_581_312),
        degree_six.minimum_resident_bytes,
    );
    const degree_six_bounded = try estimateUniform(161, 24, 1, .never);
    try std.testing.expectEqual(
        @as(u64, 21_609_054_208),
        degree_six_bounded.minimum_resident_bytes,
    );
    // With the fixed split of one, eight secure composition columns are
    // committed one log below the component's composition-degree bound.
    const degree_five_composition = try estimateUniform(8, 25, 1, .never);
    const degree_six_composition = try estimateUniform(8, 26, 1, .never);
    try std.testing.expectEqual(
        @as(u64, 2_147_483_648),
        degree_five_composition.minimum_resident_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 4_294_967_296),
        degree_six_composition.minimum_resident_bytes,
    );
    try degree_six.requireWithin(48 * 1024 * 1024 * 1024);
}

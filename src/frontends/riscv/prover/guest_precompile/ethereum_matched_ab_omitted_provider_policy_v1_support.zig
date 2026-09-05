//! Arithmetic and hashing support for the matched omitted-provider policy.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const aggregation_hash = @import("../../aggregation/hash.zig");
const residency = @import("stwo_prover_engine").pcs.residency_estimate;

/// Allocation-free PCS lower bound for one commitment stage. It deliberately
/// excludes Merkle nodes, twiddles, witnesses, backend scratch, and allocator
/// overhead; fitting is necessary, never sufficient, for a real run.
pub const StageEstimateV1 = struct {
    column_count: u64,
    source_cells: u64,
    extended_cells: u64,
    source_bytes: u64,
    retained_coefficient_bytes: u64,
    extended_evaluation_bytes: u64,
    minimum_resident_bytes: u64,
    max_column_log_size: u32,
    log_blowup_factor: u32,
    retention_policy: residency.RetentionPolicy,

    pub fn fromResidency(value: residency.Estimate) StageEstimateV1 {
        return .{
            .column_count = value.column_count,
            .source_cells = value.source_cells,
            .extended_cells = value.extended_cells,
            .source_bytes = value.source_bytes,
            .retained_coefficient_bytes = value.retained_coefficient_bytes,
            .extended_evaluation_bytes = value.extended_evaluation_bytes,
            .minimum_resident_bytes = value.minimum_resident_bytes,
            .max_column_log_size = value.max_column_log_size,
            .log_blowup_factor = value.log_blowup_factor,
            .retention_policy = value.retention_policy,
        };
    }

    pub fn validate(self: StageEstimateV1) !void {
        if (self.column_count == 0 or self.log_blowup_factor == 0 or
            self.log_blowup_factor >= @bitSizeOf(u64) or
            self.retention_policy == .auto)
        {
            return error.InvalidMatchedAbStageEstimate;
        }
        const field_bytes: u64 = @sizeOf(M31);
        const source_bytes = try mul(self.source_cells, field_bytes);
        const extended_cells = try mul(
            self.source_cells,
            @as(u64, 1) << @intCast(self.log_blowup_factor),
        );
        const extended_bytes = try mul(self.extended_cells, field_bytes);
        const coefficients = switch (self.retention_policy) {
            .always => source_bytes,
            .never => 0,
            .auto => unreachable,
        };
        if (self.extended_cells != extended_cells or
            self.source_bytes != source_bytes or
            self.retained_coefficient_bytes != coefficients or
            self.extended_evaluation_bytes != extended_bytes or
            self.minimum_resident_bytes != try add(
                coefficients,
                extended_bytes,
            ))
        {
            return error.InvalidMatchedAbStageEstimate;
        }
    }

    pub fn commitTransient(self: StageEstimateV1) !u64 {
        return add(self.source_bytes, self.extended_evaluation_bytes);
    }
};

pub const StagedTotals = struct { retained: u64, transient: u64, peak: u64 };

pub fn stagedTotals(stages: anytype) !StagedTotals {
    var retained: u64 = 0;
    var transient: u64 = 0;
    inline for (stages) |stage| {
        transient = @max(
            transient,
            try add(retained, try stage.commitTransient()),
        );
        retained = try add(retained, stage.minimum_resident_bytes);
    }
    return .{
        .retained = retained,
        .transient = transient,
        .peak = @max(retained, transient),
    };
}

pub fn hashStage(sink: anytype, value: StageEstimateV1) void {
    aggregation_hash.writeU64(sink, value.column_count) catch unreachable;
    aggregation_hash.writeU64(sink, value.source_cells) catch unreachable;
    aggregation_hash.writeU64(sink, value.extended_cells) catch unreachable;
    aggregation_hash.writeU64(sink, value.source_bytes) catch unreachable;
    aggregation_hash.writeU64(
        sink,
        value.retained_coefficient_bytes,
    ) catch unreachable;
    aggregation_hash.writeU64(
        sink,
        value.extended_evaluation_bytes,
    ) catch unreachable;
    aggregation_hash.writeU64(
        sink,
        value.minimum_resident_bytes,
    ) catch unreachable;
    aggregation_hash.writeU32(sink, value.max_column_log_size) catch unreachable;
    aggregation_hash.writeU32(sink, value.log_blowup_factor) catch unreachable;
    sink.writeAll(&.{@intFromEnum(value.retention_policy)}) catch unreachable;
}

pub fn hashLogSizes(sink: anytype, values: []const u32) void {
    aggregation_hash.writeU64(sink, values.len) catch unreachable;
    for (values) |value|
        aggregation_hash.writeU32(sink, value) catch unreachable;
}

pub fn maximumLogSize(values: []const u32) u32 {
    var result: u32 = 0;
    for (values) |value| result = @max(result, value);
    return result;
}

pub fn add(left: u64, right: u64) !u64 {
    return std.math.add(u64, left, right) catch
        error.MatchedAbOmittedProviderEstimateOverflow;
}

fn mul(left: u64, right: u64) !u64 {
    return std.math.mul(u64, left, right) catch
        error.MatchedAbOmittedProviderEstimateOverflow;
}

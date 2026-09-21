//! Allocation-free PCS shard residency planning.
//!
//! The planner selects the largest uniform shard domain that can keep the
//! requested number of shards resident under a caller-owned host reserve.
//! Its memory model is deliberately the same lower bound as
//! `residency_estimate`: fitting is useful planning telemetry, not permission
//! to ignore Merkle, witness, twiddle, allocator, or backend overhead.

const std = @import("std");
const residency = @import("residency_estimate.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const Digest = [32]u8;
pub const Error = residency.Error || error{
    InvalidResidencyShardRequest,
    InvalidResidencyShardPlan,
};

const REQUEST_IDENTITY_DOMAIN =
    "stwo-zig/prover/pcs/residency-shard-request/v1\x00";
const PLAN_IDENTITY_DOMAIN =
    "stwo-zig/prover/pcs/residency-shard-plan/v1\x00";

pub const Request = struct {
    logical_row_count: u64,
    column_count: u64,
    min_shard_log_size: u32,
    max_shard_log_size: u32,
    log_blowup_factor: u32,
    retention_policy: residency.RetentionPolicy,
    host_byte_budget: u64,
    reserved_host_bytes: u64,
    requested_parallel_shards: u32,

    pub fn identity(self: Request) Digest {
        return requestIdentity(self);
    }
};

pub const Plan = struct {
    logical_row_count: u64,
    shard_log_size: u32,
    shard_capacity: u64,
    shard_count: u64,
    final_shard_rows: u64,
    requested_parallel_shards: u32,
    admitted_parallel_shards: u32,
    per_shard_residency: residency.Estimate,
    reserved_host_bytes: u64,
    active_shard_resident_bytes: u64,
    minimum_planned_resident_bytes: u64,
    request_identity: Digest,
    plan_identity: Digest,

    pub fn validateAgainst(self: Plan, request: Request) Error!void {
        const expected = try create(request);
        if (!std.meta.eql(self, expected)) return error.InvalidResidencyShardPlan;
    }
};

/// Selects the largest shard log satisfying the requested parallel lower
/// bound. Every shard except the final one owns exactly `shard_capacity`
/// logical rows; the final shard owns `final_shard_rows`.
pub fn create(request: Request) Error!Plan {
    if (request.logical_row_count == 0 or
        request.column_count == 0 or
        request.min_shard_log_size > request.max_shard_log_size or
        request.requested_parallel_shards == 0 or
        request.reserved_host_bytes >= request.host_byte_budget)
    {
        return error.InvalidResidencyShardRequest;
    }

    const available_bytes = request.host_byte_budget - request.reserved_host_bytes;
    var log_size = request.max_shard_log_size;
    while (true) {
        const estimate = try residency.estimateUniform(
            request.column_count,
            log_size,
            request.log_blowup_factor,
            request.retention_policy,
        );
        if (estimate.minimum_resident_bytes != 0 and
            estimate.minimum_resident_bytes <= available_bytes)
        {
            const shard_capacity = @as(u64, 1) << @intCast(log_size);
            const shard_count = try divCeil(request.logical_row_count, shard_capacity);
            const requested = @min(
                @as(u64, request.requested_parallel_shards),
                shard_count,
            );
            const affordable = available_bytes / estimate.minimum_resident_bytes;
            if (affordable >= requested) {
                const admitted = requested;
                const active_shard_resident_bytes = std.math.mul(
                    u64,
                    estimate.minimum_resident_bytes,
                    admitted,
                ) catch return error.ResidencyEstimateOverflow;
                const minimum_planned_resident_bytes = std.math.add(
                    u64,
                    request.reserved_host_bytes,
                    active_shard_resident_bytes,
                ) catch return error.ResidencyEstimateOverflow;
                const preceding_rows = std.math.mul(
                    u64,
                    shard_count - 1,
                    shard_capacity,
                ) catch return error.ResidencyEstimateOverflow;
                var result = Plan{
                    .logical_row_count = request.logical_row_count,
                    .shard_log_size = log_size,
                    .shard_capacity = shard_capacity,
                    .shard_count = shard_count,
                    .final_shard_rows = request.logical_row_count - preceding_rows,
                    .requested_parallel_shards = request.requested_parallel_shards,
                    .admitted_parallel_shards = std.math.cast(u32, admitted) orelse
                        return error.ResidencyEstimateOverflow,
                    .per_shard_residency = estimate,
                    .reserved_host_bytes = request.reserved_host_bytes,
                    .active_shard_resident_bytes = active_shard_resident_bytes,
                    .minimum_planned_resident_bytes = minimum_planned_resident_bytes,
                    .request_identity = requestIdentity(request),
                    .plan_identity = undefined,
                };
                result.plan_identity = planIdentity(&result);
                return result;
            }
        }

        if (log_size == request.min_shard_log_size) break;
        log_size -= 1;
    }
    return error.PcsResidentBudgetExceeded;
}

pub fn requestIdentity(request: Request) Digest {
    var hash = Sha256.init(.{});
    hash.update(REQUEST_IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u64, request.logical_row_count);
    hashInt(&hash, u64, request.column_count);
    hashInt(&hash, u32, request.min_shard_log_size);
    hashInt(&hash, u32, request.max_shard_log_size);
    hashInt(&hash, u32, request.log_blowup_factor);
    hashInt(&hash, u8, @intFromEnum(request.retention_policy));
    hashInt(&hash, u64, request.host_byte_budget);
    hashInt(&hash, u64, request.reserved_host_bytes);
    hashInt(&hash, u32, request.requested_parallel_shards);
    return hash.finalResult();
}

pub fn planIdentity(plan: *const Plan) Digest {
    var hash = Sha256.init(.{});
    hash.update(PLAN_IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hash.update(&plan.request_identity);
    hashInt(&hash, u64, plan.logical_row_count);
    hashInt(&hash, u32, plan.shard_log_size);
    hashInt(&hash, u64, plan.shard_capacity);
    hashInt(&hash, u64, plan.shard_count);
    hashInt(&hash, u64, plan.final_shard_rows);
    hashInt(&hash, u32, plan.requested_parallel_shards);
    hashInt(&hash, u32, plan.admitted_parallel_shards);
    hashEstimate(&hash, plan.per_shard_residency);
    hashInt(&hash, u64, plan.reserved_host_bytes);
    hashInt(&hash, u64, plan.active_shard_resident_bytes);
    hashInt(&hash, u64, plan.minimum_planned_resident_bytes);
    return hash.finalResult();
}

fn hashEstimate(hash: *Sha256, estimate: residency.Estimate) void {
    hashInt(hash, u64, estimate.column_count);
    hashInt(hash, u64, estimate.source_cells);
    hashInt(hash, u64, estimate.extended_cells);
    hashInt(hash, u64, estimate.source_bytes);
    hashInt(hash, u64, estimate.retained_coefficient_bytes);
    hashInt(hash, u64, estimate.extended_evaluation_bytes);
    hashInt(hash, u64, estimate.minimum_resident_bytes);
    hashInt(hash, u32, estimate.max_column_log_size);
    hashInt(hash, u32, estimate.log_blowup_factor);
    hashInt(hash, u8, @intFromEnum(estimate.retention_policy));
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn divCeil(numerator: u64, denominator: u64) Error!u64 {
    if (denominator == 0) return error.InvalidResidencyShardRequest;
    const adjusted = std.math.add(
        u64,
        numerator,
        denominator - 1,
    ) catch return error.ResidencyEstimateOverflow;
    return adjusted / denominator;
}

test "real narrow-memory workload selects bounded parallel log20 shards" {
    const gib: u64 = 1024 * 1024 * 1024;
    const result = try create(.{
        .logical_row_count = 9_674_526,
        .column_count = 445,
        .min_shard_log_size = 18,
        .max_shard_log_size = 24,
        .log_blowup_factor = 1,
        .retention_policy = .never,
        .host_byte_budget = 64 * gib,
        .reserved_host_bytes = 40 * gib,
        .requested_parallel_shards = 4,
    });

    try std.testing.expectEqual(@as(u32, 20), result.shard_log_size);
    try std.testing.expectEqual(@as(u64, 1_048_576), result.shard_capacity);
    try std.testing.expectEqual(@as(u64, 10), result.shard_count);
    try std.testing.expectEqual(@as(u64, 237_342), result.final_shard_rows);
    try std.testing.expectEqual(@as(u32, 4), result.admitted_parallel_shards);
    try std.testing.expectEqual(
        @as(u64, 3_732_930_560),
        result.per_shard_residency.minimum_resident_bytes,
    );
    try result.validateAgainst(.{
        .logical_row_count = 9_674_526,
        .column_count = 445,
        .min_shard_log_size = 18,
        .max_shard_log_size = 24,
        .log_blowup_factor = 1,
        .retention_policy = .never,
        .host_byte_budget = 64 * gib,
        .reserved_host_bytes = 40 * gib,
        .requested_parallel_shards = 4,
    });

    var mutated = result;
    mutated.final_shard_rows += 1;
    try std.testing.expectError(
        error.InvalidResidencyShardPlan,
        mutated.validateAgainst(.{
            .logical_row_count = 9_674_526,
            .column_count = 445,
            .min_shard_log_size = 18,
            .max_shard_log_size = 24,
            .log_blowup_factor = 1,
            .retention_policy = .never,
            .host_byte_budget = 64 * gib,
            .reserved_host_bytes = 40 * gib,
            .requested_parallel_shards = 4,
        }),
    );
}

test "planner minimizes proof count subject to requested concurrency" {
    const gib: u64 = 1024 * 1024 * 1024;
    const result = try create(.{
        .logical_row_count = 9_674_526,
        .column_count = 445,
        .min_shard_log_size = 18,
        .max_shard_log_size = 24,
        .log_blowup_factor = 1,
        .retention_policy = .never,
        .host_byte_budget = 64 * gib,
        .reserved_host_bytes = 32 * gib,
        .requested_parallel_shards = 4,
    });

    try std.testing.expectEqual(@as(u32, 21), result.shard_log_size);
    try std.testing.expectEqual(@as(u64, 5), result.shard_count);
    try std.testing.expectEqual(@as(u32, 4), result.admitted_parallel_shards);
}

test "planner rejects invalid and impossible requests before allocation" {
    const base = Request{
        .logical_row_count = 1,
        .column_count = 445,
        .min_shard_log_size = 18,
        .max_shard_log_size = 20,
        .log_blowup_factor = 1,
        .retention_policy = .always,
        .host_byte_budget = 1024,
        .reserved_host_bytes = 0,
        .requested_parallel_shards = 1,
    };
    try std.testing.expectError(error.PcsResidentBudgetExceeded, create(base));

    var invalid = base;
    invalid.logical_row_count = 0;
    try std.testing.expectError(error.InvalidResidencyShardRequest, create(invalid));
    invalid = base;
    invalid.requested_parallel_shards = 0;
    try std.testing.expectError(error.InvalidResidencyShardRequest, create(invalid));
    invalid = base;
    invalid.reserved_host_bytes = invalid.host_byte_budget;
    try std.testing.expectError(error.InvalidResidencyShardRequest, create(invalid));
}

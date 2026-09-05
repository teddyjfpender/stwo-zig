const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const shard_planner = @import("stwo_prover_engine").pcs.residency_shard_plan;

const subject =
    @import("ethereum_candidate_degree5_provider_batch_execution_v1.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;

const gib: u64 = 1024 * 1024 * 1024;
const retained_segment1_calls: u64 = 6_671_301;

test "candidate D5 batch accounts retained log18 owners and rejects oversized log16" {
    const allocator = std.testing.allocator;
    const host = try subject.HostCapacityV1.init(18, 64 * gib);

    var log16 = try planFixture(allocator, 16, 18);
    defer log16.deinit(allocator);
    try std.testing.expectError(
        error.Degree5ProviderBatchHostBudgetExceeded,
        subject.AuthorityV1.initAgainstPlan(
            host,
            &log16,
            .{
                .concurrent_owners = 18,
                .engine_workers_per_owner = 1,
                .total_host_byte_budget = 64 * gib,
                .controller_reserve_bytes = 8 * gib,
            },
        ),
    );

    var log18 = try planFixture(allocator, 18, 18);
    defer log18.deinit(allocator);
    const execution18 = try subject.AuthorityV1.initAgainstPlan(
        host,
        &log18,
        .{
            .concurrent_owners = 18,
            .engine_workers_per_owner = 1,
            .total_host_byte_budget = 48 * gib,
            .controller_reserve_bytes = 8 * gib,
        },
    );
    const topology18 = try subject.TopologyReceiptV1.init(
        &log18,
        &execution18,
    );
    try std.testing.expectEqual(@as(u32, 18), topology18.planner_shard_log_size);
    try std.testing.expectEqual(@as(u32, 26), topology18.shard_count);
    try std.testing.expectEqual(@as(u16, 18), topology18.concurrent_owners);
    try std.testing.expectEqual(@as(u32, 2), topology18.wave_count);
    try std.testing.expectEqual(@as(u32, 17), topology18.minimum_descriptor_log_size);
    try std.testing.expectEqual(@as(u32, 18), topology18.maximum_descriptor_log_size);
    try std.testing.expectEqual(@as(u64, 6_684_672), topology18.committed_rows);
    try std.testing.expectEqual(@as(u64, 13_371), topology18.padding_rows);
    try std.testing.expectEqual(@as(u32, 16), topology18.pcs_pow_bits);
    try std.testing.expectEqual(@as(u32, 193), topology18.fri_query_count);
    try std.testing.expectEqual(
        @as(u64, 846_200_832),
        execution18.d5_resource.staged_peak_lower_bound_bytes,
    );
    try std.testing.expect(
        execution18.d5_resource.staged_peak_lower_bound_bytes <
            log18.residency.result.per_shard_residency.minimum_resident_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 19_332_071_424),
        topology18.retained_stage_a_column_reservation_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 13_958_643_712),
        topology18.retained_stage_a_non_column_reservation_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 1_585_446_912),
        topology18.active_post_stage_a_column_reservation_bytes,
    );
    try std.testing.expectEqual(
        @as(u16, 2),
        topology18.composition_domain_scratch_concurrent_owners,
    );
    try std.testing.expectEqual(
        @as(u64, 2_088_763_392),
        topology18.composition_domain_scratch_reservation_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 3_489_660_928),
        topology18.encoded_proof_reservation_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 40_454_586_368),
        topology18.aggregate_owner_reservation_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 49_044_520_960),
        topology18.total_reservation_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 2_495_086_592),
        @as(u64, 48 * gib) - topology18.total_reservation_bytes,
    );
}

test "candidate D5 batch authority rejects CPU RSS and plan mutation" {
    const allocator = std.testing.allocator;
    const host = try subject.HostCapacityV1.init(18, 64 * gib);
    var plan = try planFixture(allocator, 18, 18);
    defer plan.deinit(allocator);
    const valid_request = subject.RequestV1{
        .concurrent_owners = 18,
        .engine_workers_per_owner = 1,
        .total_host_byte_budget = 64 * gib,
        .controller_reserve_bytes = 8 * gib,
    };
    var execution = try subject.AuthorityV1.initAgainstPlan(
        host,
        &plan,
        valid_request,
    );
    try execution.validateAgainstPlan(&plan);

    var scratch_mutation = execution;
    scratch_mutation.composition_domain_scratch_reservation_bytes -= 4;
    try std.testing.expectError(
        error.InvalidDegree5ProviderBatchExecution,
        scratch_mutation.validateAgainstPlan(&plan),
    );
    scratch_mutation = execution;
    scratch_mutation.composition_domain_scratch_concurrent_owners = 3;
    try std.testing.expectError(
        error.InvalidDegree5ProviderBatchExecution,
        scratch_mutation.validateAgainstPlan(&plan),
    );

    try std.testing.expectError(
        error.InvalidDegree5ProviderBatchExecution,
        subject.AuthorityV1.initAgainstPlan(
            host,
            &plan,
            .{
                .concurrent_owners = 18,
                .engine_workers_per_owner = 2,
                .total_host_byte_budget = 64 * gib,
                .controller_reserve_bytes = 8 * gib,
            },
        ),
    );
    try std.testing.expectError(
        error.Degree5ProviderBatchHostBudgetExceeded,
        subject.AuthorityV1.initAgainstPlan(
            host,
            &plan,
            .{
                .concurrent_owners = 18,
                .engine_workers_per_owner = 1,
                .total_host_byte_budget = 32 * gib,
                .controller_reserve_bytes = 8 * gib,
            },
        ),
    );
    execution.plan_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidDegree5ProviderBatchExecution,
        execution.validateAgainstPlan(&plan),
    );

    var wrong_blowup = plan;
    wrong_blowup.residency.request.log_blowup_factor = 2;
    try std.testing.expectError(
        error.InvalidResidencyShardPlan,
        subject.validateQ193Plan(&wrong_blowup),
    );
}

test "candidate D5 batch host admission is machine-generic" {
    const allocator = std.testing.allocator;
    var plan = try planFixture(allocator, 18, 5);
    defer plan.deinit(allocator);
    const synthetic_host = try subject.HostCapacityV1.init(5, 64 * gib);
    const execution = try subject.AuthorityV1.initAgainstPlan(
        synthetic_host,
        &plan,
        .{
            .concurrent_owners = 5,
            .engine_workers_per_owner = 1,
            .total_host_byte_budget = 64 * gib,
            .controller_reserve_bytes = 8 * gib,
        },
    );
    try std.testing.expectEqual(@as(u16, 5), execution.concurrent_owners);
    try std.testing.expectEqual(@as(u16, 5), execution.aggregate_worker_tokens);
}

test "candidate D5 validated call authority is pointer closed and rejects descriptor mutation" {
    const allocator = std.testing.allocator;
    const calls = try allocator.alloc(poseidon2_air.Call, 33);
    defer allocator.free(calls);
    for (calls, 0..) |*call, index| {
        call.* = poseidon2_air.Call.narrowWithOutput(
            @intCast(index + 1),
            @intCast(index + 2),
            @intCast(index + 3),
        );
    }
    var plan = try authority.ProviderShardPlanV1.create(
        allocator,
        [_]u8{0x7d} ** 32,
        calls,
        .{
            .logical_row_count = calls.len,
            .column_count = authority.main_column_count,
            .min_shard_log_size = 4,
            .max_shard_log_size = 4,
            .log_blowup_factor = 1,
            .retention_policy = .always,
            .host_byte_budget = gib,
            .reserved_host_bytes = 0,
            .requested_parallel_shards = 1,
        },
    );
    defer plan.deinit(allocator);
    var validated = try authority.OwnedValidatedPlanCallAuthorityV1.init(
        allocator,
        &plan,
        calls,
    );
    defer validated.deinit();

    var work = validated.workReceipt();
    try work.validate();
    try std.testing.expectEqual(@as(u64, 0), work.fast_pointer_checks);

    try validated.validateBorrowed(&plan, calls);
    const shard = try validated.admittedShard(&plan, calls, 1);
    try std.testing.expectEqual(@as(usize, 16), shard.len);
    try std.testing.expectEqual(calls[16..32].ptr, shard.ptr);

    const copied_calls = try allocator.dupe(poseidon2_air.Call, calls);
    defer allocator.free(copied_calls);
    try std.testing.expectError(
        error.InvalidValidatedProviderPlanCallAuthority,
        validated.validateBorrowed(&plan, copied_calls),
    );

    plan.shards[1].identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidValidatedProviderShardAuthority,
        validated.admittedShard(&plan, calls, 1),
    );
    plan.shards[1].identity[0] ^= 1;

    plan.identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidValidatedProviderPlanCallAuthority,
        validated.validateBorrowed(&plan, calls),
    );
    plan.identity[0] ^= 1;
    try validated.validateBorrowed(&plan, calls);

    work = validated.workReceipt();
    try work.validate();
    try std.testing.expectEqual(@as(u64, 6), work.fast_pointer_checks);
}

fn planFixture(
    allocator: std.mem.Allocator,
    log_size: u32,
    requested_parallel_shards: u32,
) !authority.ProviderShardPlanV1 {
    const request = shard_planner.Request{
        .logical_row_count = retained_segment1_calls,
        .column_count = authority.main_column_count,
        .min_shard_log_size = log_size,
        .max_shard_log_size = log_size,
        .log_blowup_factor = 1,
        .retention_policy = .always,
        .host_byte_budget = 64 * gib,
        .reserved_host_bytes = 8 * gib,
        .requested_parallel_shards = requested_parallel_shards,
    };
    const residency = try authority.ResidencyPlanningAuthorityV1.canonical(
        request,
    );
    const count: usize = @intCast(residency.result.shard_count);
    const shards = try allocator.alloc(authority.ProviderShardDescriptorV1, count);
    errdefer allocator.free(shards);
    for (shards, 0..) |*descriptor, index| {
        const is_last = index + 1 == shards.len;
        const rows = if (is_last)
            residency.result.final_shard_rows
        else
            residency.result.shard_capacity;
        descriptor.* = .{
            .format = authority.format_version,
            .session = [_]u8{0x51} ** 32,
            .shard_index = @intCast(index),
            .shard_count = @intCast(shards.len),
            .first_call = @as(u64, index) * residency.result.shard_capacity,
            .call_count = @intCast(rows),
            .global_call_list_commitment = [_]u8{0xa2} ** 32,
            .shard_call_list_commitment = [_]u8{0xb4} ** 32,
            .mode = .narrow_memory,
            .expected_log_size = @max(
                authority.minimum_shard_log_size,
                std.math.log2_int_ceil(u64, rows),
            ),
            .main_columns = authority.main_column_count,
            .interaction_columns = authority.interaction_column_count,
            .identity = [_]u8{0xd5} ** 32,
        };
    }
    return .{
        .format = authority.format_version,
        .session = [_]u8{0x51} ** 32,
        .total_call_count = retained_segment1_calls,
        .shard_count = @intCast(shards.len),
        .residency = residency,
        .call_list_commitment = [_]u8{0xa2} ** 32,
        .shards = shards,
        .identity = [_]u8{0xc3} ** 32,
    };
}

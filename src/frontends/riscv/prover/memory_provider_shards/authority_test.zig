const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const residency = @import("stwo_prover_engine").pcs.residency_estimate;
const subject = @import("authority.zig");
const shard_planner = @import("stwo_prover_engine").pcs.residency_shard_plan;

fn session(marker: u8) subject.Digest {
    return [_]u8{marker} ** 32;
}

fn callsFixture(allocator: std.mem.Allocator, count: usize) ![]poseidon2_air.Call {
    const calls = try allocator.alloc(poseidon2_air.Call, count);
    for (calls, 0..) |*call, index| {
        call.* = poseidon2_air.Call.narrowWithOutput(
            @intCast(index + 1),
            @intCast(index + 2),
            @intCast(index + 3),
        );
    }
    return calls;
}

fn smallResidencyRequest(count: usize) shard_planner.Request {
    return .{
        .logical_row_count = @intCast(count),
        .column_count = subject.main_column_count,
        .min_shard_log_size = 4,
        .max_shard_log_size = 4,
        .log_blowup_factor = 1,
        .retention_policy = .never,
        .host_byte_budget = 1024 * 1024 * 1024,
        .reserved_host_bytes = 0,
        .requested_parallel_shards = 1,
    };
}

test "narrow-memory Poseidon provider shards seal canonical contiguous coverage" {
    const calls = try callsFixture(std.testing.allocator, 33);
    defer std.testing.allocator.free(calls);
    var plan = try subject.ProviderShardPlanV1.create(
        std.testing.allocator,
        session(0x41),
        calls,
        smallResidencyRequest(calls.len),
    );
    defer plan.deinit(std.testing.allocator);

    try plan.validate(calls);
    try std.testing.expectEqual(@as(u32, 3), plan.shard_count);
    try std.testing.expectEqual(@as(u64, 33), plan.total_call_count);
    try std.testing.expectEqual(@as(u64, 0), plan.shards[0].first_call);
    try std.testing.expectEqual(@as(u32, 16), plan.shards[0].call_count);
    try std.testing.expectEqual(@as(u64, 16), plan.shards[1].first_call);
    try std.testing.expectEqual(@as(u32, 16), plan.shards[1].call_count);
    try std.testing.expectEqual(@as(u64, 32), plan.shards[2].first_call);
    try std.testing.expectEqual(@as(u32, 1), plan.shards[2].call_count);
    for (plan.shards) |shard| {
        try std.testing.expectEqual(subject.Mode.narrow_memory, shard.mode);
        try std.testing.expectEqual(@as(u32, 4), shard.expected_log_size);
        try std.testing.expectEqual(@as(u16, 445), shard.main_columns);
        try std.testing.expectEqual(@as(u16, 8), shard.interaction_columns);
    }
    try std.testing.expect(!subject.ACTIVATES_PRODUCTION_PROOF);
    try std.testing.expect(!subject.ORDERED_CALL_COMMITMENT_IS_AIR_PROVED);
    try std.testing.expect(!subject.CALLER_N_MANIFEST_IMPLEMENTED);
    try std.testing.expect(!subject.JOINT_INTERACTION_POW_IMPLEMENTED);
    try std.testing.expect(!subject.TWO_PASS_BOUNDED_PCS_IMPLEMENTED);
    try std.testing.expect(!subject.RECURSIVE_VERIFICATION_IMPLEMENTED);
}

test "narrow-memory Poseidon provider shards reject source and coverage mutation" {
    const calls = try callsFixture(std.testing.allocator, 33);
    defer std.testing.allocator.free(calls);
    var plan = try subject.ProviderShardPlanV1.create(
        std.testing.allocator,
        session(0x42),
        calls,
        smallResidencyRequest(calls.len),
    );
    defer plan.deinit(std.testing.allocator);

    var mutated = try std.testing.allocator.dupe(poseidon2_air.Call, calls);
    defer std.testing.allocator.free(mutated);
    std.mem.swap(poseidon2_air.Call, &mutated[3], &mutated[4]);
    try std.testing.expectError(
        error.GlobalCallCommitmentMismatch,
        plan.validate(mutated),
    );
    mutated[3] = calls[3];
    mutated[4] = calls[4];
    mutated[17].narrow_output.? +%= 1;
    try std.testing.expectError(
        error.GlobalCallCommitmentMismatch,
        plan.validate(mutated),
    );

    const first_call = plan.shards[1].first_call;
    plan.shards[1].first_call += 1;
    try std.testing.expectError(
        error.NonContiguousShardCoverage,
        plan.validate(calls),
    );
    plan.shards[1].first_call = first_call;

    const call_count = plan.shards[1].call_count;
    plan.shards[1].call_count -= 1;
    try std.testing.expectError(
        error.NonCanonicalShardSize,
        plan.validate(calls),
    );
    plan.shards[1].call_count = call_count;

    const identity = plan.shards[1].identity;
    plan.shards[1].identity[0] ^= 1;
    try std.testing.expectError(
        error.ShardIdentityMismatch,
        plan.validate(calls),
    );
    plan.shards[1].identity = identity;

    const saved = plan.shards[0];
    plan.shards[0] = plan.shards[1];
    try std.testing.expectError(
        error.NonCanonicalShardPosition,
        plan.validate(calls),
    );
    plan.shards[0] = saved;
    try plan.validate(calls);
}

test "narrow-memory Poseidon provider shards bind the generic residency request and result" {
    const calls = try callsFixture(std.testing.allocator, 33);
    defer std.testing.allocator.free(calls);
    var plan = try subject.ProviderShardPlanV1.create(
        std.testing.allocator,
        session(0x4a),
        calls,
        smallResidencyRequest(calls.len),
    );
    defer plan.deinit(std.testing.allocator);

    plan.residency.request.host_byte_budget += 1;
    try std.testing.expectError(
        error.InvalidResidencyShardPlan,
        plan.validate(calls),
    );
    plan.residency.request.host_byte_budget -= 1;

    plan.residency.result.final_shard_rows += 1;
    try std.testing.expectError(
        error.InvalidResidencyShardPlan,
        plan.validate(calls),
    );
    plan.residency.result.final_shard_rows -= 1;

    plan.residency.result.request_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidResidencyShardPlan,
        plan.validate(calls),
    );
    plan.residency.result.request_identity[0] ^= 1;
    try plan.validate(calls);
}

test "narrow-memory Poseidon provider shard authority rejects noncanonical calls" {
    var calls = [_]poseidon2_air.Call{
        poseidon2_air.Call.narrowWithOutput(1, 2, 3),
    };
    var wide = calls;
    wide[0].wide = true;
    try std.testing.expectError(
        error.NonCanonicalNarrowCall,
        subject.ProviderShardPlanV1.create(
            std.testing.allocator,
            session(0x43),
            &wide,
            smallResidencyRequest(wide.len),
        ),
    );
    var missing_output = calls;
    missing_output[0].narrow_output = null;
    try std.testing.expectError(
        error.NonCanonicalNarrowCall,
        subject.orderedCallListCommitment(&missing_output),
    );
    var nonzero_lane = calls;
    nonzero_lane[0].input[2] = 1;
    try std.testing.expectError(
        error.NonCanonicalNarrowCall,
        subject.orderedCallListCommitment(&nonzero_lane),
    );
    var noncanonical = calls;
    noncanonical[0].input[0] = m31.Modulus;
    try std.testing.expectError(
        error.NonCanonicalM31Value,
        subject.orderedCallListCommitment(&noncanonical),
    );
    try std.testing.expectError(
        error.ZeroSession,
        subject.ProviderShardPlanV1.create(
            std.testing.allocator,
            [_]u8{0} ** 32,
            &calls,
            smallResidencyRequest(calls.len),
        ),
    );
}

fn relation(plan: *const subject.ProviderShardPlanV1) !subject.PoseidonRelationContextV1 {
    return subject.PoseidonRelationContextV1.canonical(
        plan.session,
        QM31.fromU32Unchecked(11, 12, 13, 14),
        QM31.fromU32Unchecked(21, 22, 23, 24),
    );
}

fn claimsFixture(
    allocator: std.mem.Allocator,
    plan: *const subject.ProviderShardPlanV1,
    context: subject.PoseidonRelationContextV1,
) ![]subject.ProviderShardClaimV1 {
    const claims = try allocator.alloc(subject.ProviderShardClaimV1, plan.shards.len);
    for (claims, plan.shards, 0..) |*claim, descriptor, index| {
        claim.* = .{
            .plan_identity = plan.identity,
            .descriptor_identity = descriptor.identity,
            .shard_index = @intCast(index),
            .relation_context_identity = context.identity,
            .claims = .{ .sums = .{
                QM31.fromU32Unchecked(@intCast(index + 1), 0, 0, 0),
                QM31.zero(),
            } },
        };
    }
    return claims;
}

test "narrow-memory Poseidon aggregate closes one core against all shard claims" {
    const calls = try callsFixture(std.testing.allocator, 33);
    defer std.testing.allocator.free(calls);
    var plan = try subject.ProviderShardPlanV1.create(
        std.testing.allocator,
        session(0x44),
        calls,
        smallResidencyRequest(calls.len),
    );
    defer plan.deinit(std.testing.allocator);
    const context = try relation(&plan);
    const claims = try claimsFixture(std.testing.allocator, &plan, context);
    defer std.testing.allocator.free(claims);
    var provider_total = QM31.zero();
    for (claims) |claim| provider_total = provider_total.add(claim.claims.total());
    const core = subject.CorePoseidonClaimV1{
        .plan_identity = plan.identity,
        .relation_context_identity = context.identity,
        .claim = provider_total.neg(),
    };
    const aggregate = try subject.verifyAggregateClosure(
        &plan,
        calls,
        context,
        core,
        claims,
    );
    try std.testing.expect(aggregate.closed_sum.isZero());
    try std.testing.expect(aggregate.provider_claim.eql(provider_total));
    try std.testing.expectEqual(@as(u32, 3), aggregate.shard_count);
}

test "narrow-memory Poseidon aggregate rejects omission reorder mutation and context drift" {
    const calls = try callsFixture(std.testing.allocator, 33);
    defer std.testing.allocator.free(calls);
    var plan = try subject.ProviderShardPlanV1.create(
        std.testing.allocator,
        session(0x45),
        calls,
        smallResidencyRequest(calls.len),
    );
    defer plan.deinit(std.testing.allocator);
    const context = try relation(&plan);
    const claims = try claimsFixture(std.testing.allocator, &plan, context);
    defer std.testing.allocator.free(claims);
    var provider_total = QM31.zero();
    for (claims) |claim| provider_total = provider_total.add(claim.claims.total());
    const core = subject.CorePoseidonClaimV1{
        .plan_identity = plan.identity,
        .relation_context_identity = context.identity,
        .claim = provider_total.neg(),
    };

    try std.testing.expectError(
        error.ShardClaimCountMismatch,
        subject.verifyAggregateClosure(
            &plan,
            calls,
            context,
            core,
            claims[0 .. claims.len - 1],
        ),
    );
    std.mem.swap(
        subject.ProviderShardClaimV1,
        &claims[0],
        &claims[1],
    );
    try std.testing.expectError(
        error.NonCanonicalShardClaimOrder,
        subject.verifyAggregateClosure(&plan, calls, context, core, claims),
    );
    std.mem.swap(
        subject.ProviderShardClaimV1,
        &claims[0],
        &claims[1],
    );
    claims[1].claims.sums[0] = claims[1].claims.sums[0].add(QM31.one());
    try std.testing.expectError(
        error.PoseidonRelationNotClosed,
        subject.verifyAggregateClosure(&plan, calls, context, core, claims),
    );
    claims[1].claims.sums[0] = claims[1].claims.sums[0].sub(QM31.one());
    claims[2].relation_context_identity[0] ^= 1;
    try std.testing.expectError(
        error.RelationContextMismatch,
        subject.verifyAggregateClosure(&plan, calls, context, core, claims),
    );
}

test "log20 narrow-memory Poseidon shard pins bounded PCS residency lower bound" {
    const gib: u64 = 1024 * 1024 * 1024;
    const shipping = try shard_planner.create(.{
        .logical_row_count = 9_674_526,
        .column_count = subject.main_column_count,
        .min_shard_log_size = 18,
        .max_shard_log_size = 24,
        .log_blowup_factor = 1,
        .retention_policy = .never,
        .host_byte_budget = 64 * gib,
        .reserved_host_bytes = 40 * gib,
        .requested_parallel_shards = 4,
    });
    try std.testing.expectEqual(@as(u32, 20), shipping.shard_log_size);
    try std.testing.expectEqual(@as(u64, 10), shipping.shard_count);
    try std.testing.expectEqual(@as(u64, 237_342), shipping.final_shard_rows);
    try std.testing.expectEqual(
        @as(u64, 3_732_930_560),
        shipping.per_shard_residency.minimum_resident_bytes,
    );

    const shard_logs = [_]u32{20} ** subject.main_column_count;
    const shard = try residency.estimate(&shard_logs, 1, .always);
    try std.testing.expectEqual(
        @as(u64, 5_599_395_840),
        shard.minimum_resident_bytes,
    );

    const monolithic_logs = [_]u32{24} ** subject.main_column_count;
    const monolithic = try residency.estimate(&monolithic_logs, 1, .always);
    try std.testing.expectEqual(
        @as(u64, 89_590_333_440),
        monolithic.minimum_resident_bytes,
    );
    try std.testing.expect(
        shard.minimum_resident_bytes * 16 == monolithic.minimum_resident_bytes,
    );
}

//! CPU proof-level acceptance for the research base Poseidon provider shard.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const postcard = @import("interop_postcard");
const pcs = @import("stwo_core").pcs;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const shard_planner = @import("stwo_prover_engine").pcs.residency_shard_plan;

const harness = frontend.testing.narrow_memory_provider_proof_harness;
const joint = frontend.testing.narrow_memory_provider_joint_protocol;
const joint_proof = frontend.testing.narrow_memory_provider_joint_proof;
const joint_proof_v2 = frontend.testing.narrow_memory_provider_joint_proof_v2;
const authority = frontend.testing.narrow_memory_provider_shard_authority;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const poseidon2 = frontend.air.memory_commitment.poseidon2;
const Engine = riscv_cpu.CpuProverEngine;
const Hash = Engine.Hasher.Hash;
const full_core_joint = @import("memory_provider_full_core_joint_test.zig");

const CONFIG = pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = pcsConfig(),
};

fn pcsConfig() @import("stwo_core").fri.FriConfig {
    return @import("stwo_core").fri.FriConfig.init(0, 1, 3) catch unreachable;
}

test "base narrow-memory provider log4 proves fresh and retention preserves identity" {
    try runRetentionParity(4, 13);
}

test "base narrow-memory provider log8 proves and fresh verifier binds two QM31 claims" {
    const allocator = std.testing.allocator;
    const calls = try callsFixture(allocator, 193);
    defer allocator.free(calls);
    var plan = try authority.ProviderShardPlanV1.create(
        allocator,
        [_]u8{0x68} ** 32,
        calls,
        residencyRequest(8, calls.len),
    );
    defer plan.deinit(allocator);
    const snapshot = try runArm(allocator, &plan, calls, .never);
    defer snapshot.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 8), snapshot.statement.log_size);
    try std.testing.expectEqual(@as(u32, 193), snapshot.statement.n_rows);
    try std.testing.expectEqual(@as(usize, 2), snapshot.statement.claims.sums.len);
    try std.testing.expect(
        !snapshot.statement.claims.sums[0].isZero() or
            !snapshot.statement.claims.sums[1].isZero(),
    );
    try snapshot.telemetry.validate();
    try std.testing.expectEqual(@as(u32, 0), snapshot.telemetry.retained_coefficient_columns);
    try std.testing.expect(!harness.ACTIVATES_PRODUCTION_PROOF);
    try std.testing.expect(!harness.ORDERED_CALL_COMMITMENT_IS_AIR_PROVED);
    try std.testing.expect(!harness.CALLER_N_MANIFEST_IMPLEMENTED);
    try std.testing.expect(!harness.JOINT_INTERACTION_POW_IMPLEMENTED);
    try std.testing.expect(!harness.RECURSIVE_VERIFICATION_IMPLEMENTED);
}

test "real caller plus three log4 provider shards freshly verify and close" {
    try runFreshJointClosure(4, 33, true);
}

test "real caller plus log8 provider shard freshly verify and close" {
    try runFreshJointClosure(8, 193, false);
}

test "ordered provider V2 log4 proof rejects endpoint range and order mutations" {
    const allocator = std.testing.allocator;
    const calls = try callsFixture(allocator, 13);
    defer allocator.free(calls);
    var plan = try authority.ProviderShardPlanV1.create(
        allocator,
        [_]u8{0x71} ** 32,
        calls,
        residencyRequest(4, calls.len),
    );
    defer plan.deinit(allocator);

    const core_roots = try joint_proof.commitCoreStageA(
        Engine,
        allocator,
        CONFIG,
        &plan,
        calls,
    );
    const provider_roots = [_]harness.StageACommitment(Engine){
        try harness.commitStageA(Engine, allocator, CONFIG, &plan, calls, 0),
    };
    var manifest = try joint.JointManifest(Engine).create(
        allocator,
        &plan,
        calls,
        core_roots,
        &provider_roots,
    );
    defer manifest.deinit(allocator);
    const prepared = try joint.prepareSharedTranscript(
        Engine,
        allocator,
        CONFIG,
        &plan,
        calls,
        &manifest,
    );

    var core_output = try joint_proof.proveCore(
        Engine,
        allocator,
        CONFIG,
        &plan,
        calls,
        &manifest,
        prepared.authority_value,
    );
    defer core_output.proof.deinit(allocator);
    var core_bytes: std.ArrayList(u8) = .{};
    defer core_bytes.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        core_bytes.writer(allocator),
        core_output.proof,
    );
    var core_stream = std.io.fixedBufferStream(core_bytes.items);
    const core_claim = try joint_proof.verifyCoreFresh(
        Engine,
        allocator,
        CONFIG,
        &plan,
        calls,
        &manifest,
        prepared.authority_value,
        core_output.statement,
        try postcard.deserializeProof(Engine.Hasher, allocator, core_stream.reader()),
    );

    var output = try joint_proof_v2.proveProviderV2(
        Engine,
        allocator,
        CONFIG,
        &plan,
        calls,
        &manifest,
        prepared.authority_value,
        0,
    );
    defer output.proof.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 12), output.statement.tree2_geometry.total_columns);
    try std.testing.expectEqual(@as(u16, 4), output.statement.tree2_geometry.ordered_call_columns);

    var provider_bytes: std.ArrayList(u8) = .{};
    defer provider_bytes.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        provider_bytes.writer(allocator),
        output.proof,
    );
    var wrong_statement = output.statement;
    wrong_statement.ordered_call_claim.terminal =
        wrong_statement.ordered_call_claim.terminal.add(QM31.one());
    wrong_statement.identity = joint_proof_v2.providerStatementIdentity(wrong_statement);
    var wrong_stream = std.io.fixedBufferStream(provider_bytes.items);
    try std.testing.expectError(
        error.ProviderOrderClaimMismatch,
        joint_proof_v2.verifyProviderFreshV2(
            Engine,
            allocator,
            CONFIG,
            &plan,
            calls,
            &manifest,
            prepared.authority_value,
            wrong_statement,
            try postcard.deserializeProof(Engine.Hasher, allocator, wrong_stream.reader()),
        ),
    );

    var wrong_range = output.statement;
    wrong_range.first_call += 1;
    wrong_range.ordered_call_claim.first_call += 1;
    wrong_range.identity = joint_proof_v2.providerStatementIdentity(wrong_range);
    var range_stream = std.io.fixedBufferStream(provider_bytes.items);
    try std.testing.expectError(
        error.InvalidProviderStatement,
        joint_proof_v2.verifyProviderFreshV2(
            Engine,
            allocator,
            CONFIG,
            &plan,
            calls,
            &manifest,
            prepared.authority_value,
            wrong_range,
            try postcard.deserializeProof(Engine.Hasher, allocator, range_stream.reader()),
        ),
    );

    var reordered = try allocator.dupe(poseidon2_air.Call, calls);
    defer allocator.free(reordered);
    std.mem.swap(poseidon2_air.Call, &reordered[0], &reordered[1]);
    const reordered_claim = try joint_proof_v2.expectedOrderedCallClaim(
        0,
        reordered,
        &prepared.relations,
    );
    try std.testing.expect(
        !reordered_claim.terminal.eql(output.statement.ordered_call_claim.terminal),
    );
    const omitted_claim = try joint_proof_v2.expectedOrderedCallClaim(
        0,
        calls[0 .. calls.len - 1],
        &prepared.relations,
    );
    try std.testing.expect(
        !omitted_claim.terminal.eql(output.statement.ordered_call_claim.terminal),
    );

    var valid_stream = std.io.fixedBufferStream(provider_bytes.items);
    const provider_claim = try joint_proof_v2.verifyProviderFreshV2(
        Engine,
        allocator,
        CONFIG,
        &plan,
        calls,
        &manifest,
        prepared.authority_value,
        output.statement,
        try postcard.deserializeProof(Engine.Hasher, allocator, valid_stream.reader()),
    );
    const closure = try joint_proof_v2.closeFreshClaimsV2(
        allocator,
        &plan,
        calls,
        manifest.identity,
        prepared.authority_value.relation_context,
        core_claim,
        &.{provider_claim},
    );
    try closure.validate();
    try std.testing.expect(closure.every_ordered_call_air_verified);
    try std.testing.expect(closure.closed_sum.isZero());
    try std.testing.expect(joint_proof_v2.PROVIDER_ORDERED_CALL_COMMITMENT_IS_AIR_PROVED);
    try std.testing.expect(joint_proof_v2.FRESH_VERIFIER_RECOMPUTES_ORDERED_ENDPOINT);
    try std.testing.expect(!joint_proof_v2.FULL_RISCV_CORE_EXTERNALIZED);
    try std.testing.expect(!joint_proof_v2.ACTIVATES_PRODUCTION_PROOF);
}

test "full RISC-V plus ordered log4 providers freshly verify and close" {
    try full_core_joint.run();
}

fn runFreshJointClosure(
    shard_log_size: u32,
    call_count: usize,
    adversarial: bool,
) !void {
    const allocator = std.testing.allocator;
    const calls = try callsFixture(allocator, call_count);
    defer allocator.free(calls);
    var plan = try authority.ProviderShardPlanV1.create(
        allocator,
        [_]u8{0x6a} ** 32,
        calls,
        residencyRequest(shard_log_size, calls.len),
    );
    defer plan.deinit(allocator);

    const core_roots = try joint_proof.commitCoreStageA(
        Engine,
        allocator,
        CONFIG,
        &plan,
        calls,
    );
    const provider_roots = try allocator.alloc(
        harness.StageACommitment(Engine),
        plan.shards.len,
    );
    defer allocator.free(provider_roots);
    for (provider_roots, 0..) |*slot, index| {
        slot.* = try harness.commitStageA(
            Engine,
            allocator,
            CONFIG,
            &plan,
            calls,
            @intCast(index),
        );
    }
    var manifest = try joint.JointManifest(Engine).create(
        allocator,
        &plan,
        calls,
        core_roots,
        provider_roots,
    );
    defer manifest.deinit(allocator);
    const prepared = try joint.prepareSharedTranscript(
        Engine,
        allocator,
        CONFIG,
        &plan,
        calls,
        &manifest,
    );

    var core_output = try joint_proof.proveCore(
        Engine,
        allocator,
        CONFIG,
        &plan,
        calls,
        &manifest,
        prepared.authority_value,
    );
    defer core_output.proof.deinit(allocator);
    var core_bytes: std.ArrayList(u8) = .{};
    defer core_bytes.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        core_bytes.writer(allocator),
        core_output.proof,
    );
    var core_stream = std.io.fixedBufferStream(core_bytes.items);
    const fresh_core_proof = try postcard.deserializeProof(
        Engine.Hasher,
        allocator,
        core_stream.reader(),
    );
    const core_claim = try joint_proof.verifyCoreFresh(
        Engine,
        allocator,
        CONFIG,
        &plan,
        calls,
        &manifest,
        prepared.authority_value,
        core_output.statement,
        fresh_core_proof,
    );

    const provider_claims = try allocator.alloc(
        joint_proof.FreshProviderClaimV1,
        plan.shards.len,
    );
    defer allocator.free(provider_claims);
    for (provider_claims, 0..) |*claim, index| {
        var output = try joint_proof.proveProvider(
            Engine,
            allocator,
            CONFIG,
            &plan,
            calls,
            &manifest,
            prepared.authority_value,
            @intCast(index),
        );
        defer output.proof.deinit(allocator);
        var bytes: std.ArrayList(u8) = .{};
        defer bytes.deinit(allocator);
        try postcard.serializeProof(Engine.Hasher, bytes.writer(allocator), output.proof);
        var stream = std.io.fixedBufferStream(bytes.items);
        const fresh = try postcard.deserializeProof(
            Engine.Hasher,
            allocator,
            stream.reader(),
        );
        claim.* = try joint_proof.verifyProviderFresh(
            Engine,
            allocator,
            CONFIG,
            &plan,
            calls,
            &manifest,
            prepared.authority_value,
            output.statement,
            fresh,
        );
    }

    const closure = try joint_proof.closeFreshClaims(
        allocator,
        &plan,
        calls,
        manifest.identity,
        prepared.authority_value.relation_context,
        core_claim,
        provider_claims,
    );
    try closure.validate();
    try std.testing.expect(closure.closed_sum.isZero());
    try std.testing.expect(closure.every_proof_freshly_verified);
    try std.testing.expect(closure.complete_ordered_coverage);
    try std.testing.expect(closure.one_shared_relation_context);
    try std.testing.expect(!closure.production_eligible);
    try std.testing.expect(joint_proof.FRESH_CORE_VERIFICATION_MINTS_RESIDUAL);
    try std.testing.expect(joint_proof.ALL_NON_POSEIDON_BUSES_CLOSE);
    try std.testing.expect(!joint_proof.ORDERED_CALL_COMMITMENT_IS_AIR_PROVED);
    try std.testing.expect(!joint_proof.FULL_RISCV_CORE_EXTERNALIZED);
    try std.testing.expect(!joint_proof.ACTIVATES_PRODUCTION_PROOF);

    if (!adversarial) return;
    try std.testing.expectEqual(@as(usize, 3), provider_claims.len);
    try std.testing.expectError(
        error.ShardClaimCountMismatch,
        joint_proof.closeFreshClaims(
            allocator,
            &plan,
            calls,
            manifest.identity,
            prepared.authority_value.relation_context,
            core_claim,
            provider_claims[0 .. provider_claims.len - 1],
        ),
    );

    var reordered = try allocator.dupe(
        joint_proof.FreshProviderClaimV1,
        provider_claims,
    );
    defer allocator.free(reordered);
    std.mem.swap(
        joint_proof.FreshProviderClaimV1,
        &reordered[0],
        &reordered[1],
    );
    try std.testing.expectError(
        error.NonCanonicalFreshProviderOrder,
        joint_proof.closeFreshClaims(
            allocator,
            &plan,
            calls,
            manifest.identity,
            prepared.authority_value.relation_context,
            core_claim,
            reordered,
        ),
    );

    var wrong_context = prepared.authority_value;
    wrong_context.relation_context.identity[0] ^= 1;
    try std.testing.expectError(
        error.RelationContextMismatch,
        joint.replaySharedTranscript(
            Engine,
            allocator,
            CONFIG,
            &plan,
            calls,
            &manifest,
            wrong_context,
        ),
    );

    std.mem.swap(
        joint.ProviderStageARecord(Engine),
        &manifest.providers[0],
        &manifest.providers[1],
    );
    defer std.mem.swap(
        joint.ProviderStageARecord(Engine),
        &manifest.providers[0],
        &manifest.providers[1],
    );
    try std.testing.expectError(
        error.ShardIdentityMismatch,
        manifest.validate(&plan, calls),
    );
}

fn runRetentionParity(log_size: u32, call_count: usize) !void {
    const allocator = std.testing.allocator;
    const calls = try callsFixture(allocator, call_count);
    defer allocator.free(calls);
    var plan = try authority.ProviderShardPlanV1.create(
        allocator,
        [_]u8{0x64} ** 32,
        calls,
        residencyRequest(log_size, calls.len),
    );
    defer plan.deinit(allocator);

    const retained = try runArm(allocator, &plan, calls, .always);
    defer retained.deinit(allocator);
    const bounded = try runArm(allocator, &plan, calls, .never);
    defer bounded.deinit(allocator);

    try std.testing.expectEqualSlices(u8, retained.proof_bytes, bounded.proof_bytes);
    try std.testing.expect(std.meta.eql(retained.roots, bounded.roots));
    try std.testing.expect(std.meta.eql(retained.statement, bounded.statement));
    try retained.telemetry.validate();
    try bounded.telemetry.validate();
    try std.testing.expectEqual(
        @as(u32, 2 + poseidon2_air.N_MAIN_COLUMNS + poseidon2_air.N_INTERACTION_COLUMNS),
        retained.telemetry.retained_coefficient_columns,
    );
    try std.testing.expectEqual(@as(u32, 0), bounded.telemetry.retained_coefficient_columns);
}

const Snapshot = struct {
    statement: harness.StatementV1,
    roots: [harness.tree_count]Hash,
    telemetry: harness.OwnerTeardownTelemetryV1,
    proof_bytes: []u8,

    fn deinit(self: *const Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.proof_bytes);
    }
};

fn runArm(
    allocator: std.mem.Allocator,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    retention: harness.CoefficientRetention,
) !Snapshot {
    var output = try harness.proveShard(
        Engine,
        allocator,
        CONFIG,
        plan,
        calls,
        0,
        retention,
        null,
    );
    defer output.proof.deinit(allocator);

    var encoded: std.ArrayList(u8) = .{};
    defer encoded.deinit(allocator);
    try postcard.serializeProof(Engine.Hasher, encoded.writer(allocator), output.proof);
    var stream = std.io.fixedBufferStream(encoded.items);
    const fresh = try postcard.deserializeProof(Engine.Hasher, allocator, stream.reader());
    try harness.verifyShard(
        Engine,
        allocator,
        CONFIG,
        plan,
        calls,
        output.statement,
        fresh,
    );

    return .{
        .statement = output.statement,
        .roots = output.roots,
        .telemetry = output.owner_telemetry,
        .proof_bytes = try allocator.dupe(u8, encoded.items),
    };
}

fn callsFixture(
    allocator: std.mem.Allocator,
    count: usize,
) ![]poseidon2_air.Call {
    const calls = try allocator.alloc(poseidon2_air.Call, count);
    for (calls, 0..) |*call, index| {
        const left: u32 = @intCast(3 * index + 1);
        const right: u32 = @intCast(3 * index + 2);
        call.* = poseidon2_air.Call.narrowWithOutput(
            left,
            right,
            poseidon2.hashPair(left, right),
        );
    }
    return calls;
}

fn residencyRequest(log_size: u32, call_count: usize) shard_planner.Request {
    return .{
        .logical_row_count = @intCast(call_count),
        .column_count = authority.main_column_count,
        .min_shard_log_size = log_size,
        .max_shard_log_size = log_size,
        .log_blowup_factor = CONFIG.fri_config.log_blowup_factor,
        .retention_policy = .never,
        .host_byte_budget = 1024 * 1024 * 1024,
        .reserved_host_bytes = 0,
        .requested_parallel_shards = 1,
    };
}

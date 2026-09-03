const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const batch =
    @import("recursive_temporal_ethereum_poseidon_h1_batch_v1.zig");
const product =
    @import("recursive_temporal_ethereum_poseidon_h1_product_v1.zig");
const parent_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const verified_publication =
    @import("recursive_binary_verified_publication.zig");
const topology = @import("recursive_temporal_topology_v1.zig");

const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const span = recursion.span_statement;
const Sha256 = std.crypto.hash.sha2.Sha256;

test "H1 batch audits exact 105 real pairs inside 210-to-256 topology" {
    const active_job = try job(210);
    const plan = try topology.TopologyPlanV1.init(active_job);
    const geometry = try batch.auditGeometry(std.testing.allocator, plan);
    try geometry.validate();
    try std.testing.expectEqual(@as(u16, 105), geometry.real_h1_pair_count);
    try std.testing.expectEqual(@as(u16, 23), geometry.empty_h1_pair_count);
    try std.testing.expectEqual(@as(u16, 127), geometry.upper_task_count);
    try std.testing.expectEqual(@as(u8, 7), geometry.mixed_parent_task_count);

    var schedule = try topology.BreadthFirstScheduleV1.create(
        std.testing.allocator,
        plan,
    );
    defer schedule.deinit();
    try std.testing.expectEqual(@as(usize, 255), schedule.tasks.len);
    try std.testing.expectEqual(topology.NodeKindV1.real, schedule.tasks[104].right_kind);
    try std.testing.expectEqual(topology.NodeKindV1.empty, schedule.tasks[105].left_kind);
    try std.testing.expectEqual(@as(u8, 2), schedule.tasks[180].parent_height);
    try std.testing.expectEqual(topology.NodeKindV1.real, schedule.tasks[180].left_kind);
    try std.testing.expectEqual(topology.NodeKindV1.empty, schedule.tasks[180].right_kind);

    var forged = geometry;
    forged.real_h1_pair_count -= 1;
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1BatchGeometry,
        forged.validate(),
    );
}

test "H1 batch pair and ordered admission reject identity and arm mutations" {
    var plan = syntheticBatch();
    try plan.validateCustody();
    var pairs: [batch.REAL_H1_PAIR_COUNT]batch.FreshPairAdmissionV1 = undefined;
    for (&pairs, 0..) |*pair, ordinal|
        pair.* = syntheticPair(&plan, ordinal, .retained_baseline_poseidon_v4);
    const admission = try batch.BatchAdmissionV1.init(&plan, pairs);
    try admission.validateAgainst(&plan);

    var forged_pair = pairs[7];
    forged_pair.left_capture_identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1PairAdmission,
        forged_pair.validateAgainst(&plan),
    );

    var mixed = admission;
    mixed.pairs[31].arm_kind = .projected_candidate_v1;
    batch.testing.resealPair(&mixed.pairs[31]);
    batch.testing.resealAdmission(&mixed);
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1BatchAdmission,
        mixed.validateAgainst(&plan),
    );

    plan.tasks[4].right_leaf_index += 1;
    batch.testing.resealTask(&plan.tasks[4]);
    batch.testing.resealPlan(&plan);
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1BatchTask,
        plan.validateCustody(),
    );
}

test "H1 canonical product remains custody until cold verifier readmission" {
    const allocator = std.testing.allocator;
    const active_job = try job(2);
    var middle_registers = active_job.complete.initial_state.registers;
    middle_registers[1] = 8;
    const middle = try span.MachineState.init(
        0x1800,
        middle_registers,
        digest(81),
        digest(91),
    );
    const left = try span.SpanStatement.segmentLeaf(
        active_job,
        0,
        try span.ExecutedSpan.init(
            0,
            1,
            0,
            1,
            active_job.complete.initial_state,
            middle,
            try span.EdgeClaim.present(active_job.complete.public_input),
            span.EdgeClaim.absent(),
        ),
    );
    const right = try span.SpanStatement.segmentLeaf(
        active_job,
        1,
        try span.ExecutedSpan.init(
            1,
            1,
            1,
            1,
            middle,
            active_job.complete.final_state,
            span.EdgeClaim.absent(),
            try span.EdgeClaim.present(active_job.complete.public_output),
        ),
    );
    const parent = try span.SpanStatement.fold(left, right);
    const parent_words = try parent.canonicalWords();
    const session = try parent_artifact.testing.session(
        parent_words,
        seededSha(91),
        41,
    );
    const proof_bytes = "canonical-h1-product-custody-is-not-proof";
    const proof_identity = try verified_publication.CanonicalProofIdentityV1
        .fromBytes(proof_bytes);
    const secure_statement = try parent_artifact.statementFromVerifier(
        &session,
        .{
            .interaction_pow_nonce = 17,
            .canonical_proof_byte_count = proof_identity.byte_count,
            .canonical_proof_sha256 = proof_identity.canonical_proof_sha_id,
            .proof_id = proof_identity.proof_id,
            .capture_id = digest(51),
            .transcript_id = digest(61),
            .claims_sha256 = seededSha(71),
            .audit_sha256 = seededSha(81),
            .closure_sha256 = seededSha(91),
        },
    );
    var secure = try parent_artifact.OwnedArtifactV1.initCopy(
        allocator,
        secure_statement,
        proof_bytes,
    );
    defer secure.deinit();
    const secure_bytes = try secure.encodeCanonicalAlloc(allocator);
    defer allocator.free(secure_bytes);
    var statement = product.StatementV1{
        .arm_kind = .retained_baseline_poseidon_v4,
        .parent_ordinal = 0,
        .parent_index = 0,
        .canonical_secure_artifact_byte_count = @intCast(secure_bytes.len),
        .batch_identity_sha256 = seededSha(1),
        .statement_plan_identity_sha256 = seededSha(2),
        .breadth_schedule_identity_sha256 = seededSha(3),
        .task_identity_sha256 = seededSha(4),
        .pair_admission_identity_sha256 = seededSha(5),
        .ingress_identity_sha256 = session.ingress_identity_sha256,
        .session_identity_sha256 = session.identity_sha256,
        .parent_statement_sha256 = session.parent_statement_sha256,
        .profile_identity_sha256 = session.profile_identity_sha256,
        .secure_parent_statement_identity_sha256 = secure_statement.identity_sha256,
        .canonical_secure_artifact_sha256 = sha256(secure_bytes),
        .proof_id = secure_statement.proof_id,
        .capture_id = secure_statement.capture_id,
        .transcript_id = secure_statement.transcript_id,
        .identity_sha256 = undefined,
    };
    product.testing.resealStatement(&statement);
    var custody = try product.testing.initCustodyOnly(
        allocator,
        statement,
        &secure,
    );
    defer custody.deinit();
    const encoded = try custody.encodeCanonicalAlloc(allocator);
    defer allocator.free(encoded);
    var decoded = try product.OwnedProductV1.decodeCanonical(
        allocator,
        encoded,
    );
    defer decoded.deinit();
    try std.testing.expectEqualDeep(custody.statement, decoded.statement);
    try std.testing.expectEqualSlices(
        u8,
        custody.secure_artifact_bytes,
        decoded.secure_artifact_bytes,
    );
    try std.testing.checkAllAllocationFailures(
        allocator,
        exerciseProductDecodeAllocationFailure,
        .{encoded},
    );
    var fail_nested_decode = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var oom_custody = custody;
    oom_custody.allocator = fail_nested_decode.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        oom_custody.validateCustody(),
    );
    try std.testing.expectError(
        error.EthereumPoseidonH1ProductPublicationUnavailable,
        decoded.requireProductionPublication(),
    );

    var forged_nested = try allocator.dupe(u8, encoded);
    defer allocator.free(forged_nested);
    forged_nested[forged_nested.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1ProductArtifact,
        product.OwnedProductV1.decodeCanonical(allocator, forged_nested),
    );
    try std.testing.checkAllAllocationFailures(
        allocator,
        exerciseProductNestedMutationAllocationFailure,
        .{forged_nested},
    );

    var forged_statement = try allocator.dupe(u8, encoded);
    defer allocator.free(forged_statement);
    forged_statement[product.PRODUCT_HEADER_BYTE_COUNT + 40] ^= 1;
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1ProductStatement,
        product.OwnedProductV1.decodeCanonical(allocator, forged_statement),
    );
}

fn exerciseProductDecodeAllocationFailure(
    allocator: std.mem.Allocator,
    encoded: []const u8,
) !void {
    var decoded = try product.OwnedProductV1.decodeCanonical(
        allocator,
        encoded,
    );
    defer decoded.deinit();
    try decoded.validateCustody();
}

fn exerciseProductNestedMutationAllocationFailure(
    allocator: std.mem.Allocator,
    encoded: []const u8,
) !void {
    if (product.OwnedProductV1.decodeCanonical(allocator, encoded)) |value| {
        var decoded = value;
        defer decoded.deinit();
        return error.TestExpectedError;
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidEthereumPoseidonH1ProductArtifact => {},
        else => return err,
    }
}

fn syntheticBatch() batch.BatchPlanV1 {
    var result = batch.BatchPlanV1{
        .geometry = .{
            .real_leaf_count = 210,
            .padded_leaf_count = 256,
            .empty_leaf_count = 46,
            .root_height = 8,
            .real_h1_pair_count = 105,
            .empty_h1_pair_count = 23,
            .upper_task_count = 127,
            .mixed_parent_task_count = 7,
        },
        .topology_plan_identity_sha256 = seededSha(201),
        .statement_plan_identity_sha256 = seededSha(202),
        .breadth_schedule_identity_sha256 = seededSha(203),
        .real_h1_profile_identity_sha256 = seededSha(204),
        .tasks = undefined,
        .identity_sha256 = undefined,
    };
    for (&result.tasks, 0..) |*task, ordinal|
        task.* = syntheticTask(ordinal);
    batch.testing.resealPlan(&result);
    return result;
}

fn syntheticTask(ordinal: usize) batch.RealH1TaskV1 {
    const seed: u8 = @intCast(ordinal + 1);
    var result = batch.RealH1TaskV1{
        .ordinal = @intCast(ordinal),
        .parent_index = @intCast(ordinal),
        .left_leaf_index = @intCast(ordinal * 2),
        .right_leaf_index = @intCast(ordinal * 2 + 1),
        .topology_task_identity_sha256 = seededSha(seed),
        .left_leaf_record_identity_sha256 = seededSha(seed + 1),
        .right_leaf_record_identity_sha256 = seededSha(seed + 2),
        .left_source_authority_sha256 = seededSha(seed + 3),
        .right_source_authority_sha256 = seededSha(seed + 4),
        .left_source_public_statement_sha256 = seededSha(seed + 5),
        .right_source_public_statement_sha256 = seededSha(seed + 6),
        .left_statement_sha256 = seededSha(seed + 7),
        .right_statement_sha256 = seededSha(seed + 8),
        .parent_record_identity_sha256 = seededSha(seed + 9),
        .parent_statement_sha256 = seededSha(seed + 10),
        .profile_identity_sha256 = seededSha(seed + 11),
        .verification_key_id = digest(seed + 12),
        .next_parent_vk_id = digest(seed + 13),
        .identity_sha256 = undefined,
    };
    batch.testing.resealTask(&result);
    return result;
}

fn syntheticPair(
    plan: *const batch.BatchPlanV1,
    ordinal: usize,
    arm_kind: batch.ArmKindV1,
) batch.FreshPairAdmissionV1 {
    const seed: u8 = @intCast(ordinal + 111);
    var result = batch.FreshPairAdmissionV1{
        .arm_kind = arm_kind,
        .ordinal = @intCast(ordinal),
        .parent_index = @intCast(ordinal),
        .batch_identity_sha256 = plan.identity_sha256,
        .task_identity_sha256 = plan.tasks[ordinal].identity_sha256,
        .ingress_identity_sha256 = seededSha(seed),
        .h1_profile_identity_sha256 = seededSha(seed +% 1),
        .left_descriptor_sha256 = seededSha(seed +% 2),
        .right_descriptor_sha256 = seededSha(seed +% 3),
        .left_node_public_authority_sha256 = seededSha(seed +% 4),
        .right_node_public_authority_sha256 = seededSha(seed +% 5),
        .left_proof_artifact_sha256 = seededSha(seed +% 6),
        .right_proof_artifact_sha256 = seededSha(seed +% 7),
        .left_capture_identity_sha256 = seededSha(seed +% 8),
        .right_capture_identity_sha256 = seededSha(seed +% 9),
        .identity_sha256 = undefined,
    };
    batch.testing.resealPair(&result);
    return result;
}

fn job(segment_count: u32) !span.JobContext {
    var initial_registers = [_]u32{0} ** 32;
    var final_registers = [_]u32{0} ** 32;
    initial_registers[1] = 7;
    final_registers[1] = 9;
    const initial = try span.MachineState.init(
        0x1000,
        initial_registers,
        digest(11),
        digest(21),
    );
    const final = try span.MachineState.init(
        0x2000,
        final_registers,
        digest(31),
        digest(41),
    );
    return span.JobContext.init(
        try span.CompleteExecution.init(
            recursion.protocol.PROTOCOL_ID_WORDS,
            digest(51),
            initial,
            final,
            digest(61),
            digest(71),
            segment_count,
        ),
        segment_count,
    );
}

fn digest(seed: u8) channel.Digest {
    var result: channel.Digest = undefined;
    for (&result, 0..) |*word, index|
        word.* = @as(u32, seed) + @as(u32, @intCast(index)) + 1;
    return result;
}

fn seededSha(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index + 1));
    return result;
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

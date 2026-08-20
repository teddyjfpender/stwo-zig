const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const publication_mod = @import("recursive_segment_v2_verified_publication.zig");
const child_authority = @import("recursive_segment_v2_temporal_child_authority.zig");
const pair_authority = @import("recursive_temporal_pair_authority_v2.zig");

const recursion = frontend.recursion;
const protocol = recursion.protocol;
const span = recursion.span_statement;
const temporal = recursion.temporal_pair_node;
const Digest = recursion.poseidon2_channel.Digest;
const Publication = publication_mod.VerifiedSegmentV2PublicationV1;

test "SegmentV2 verifier publication admits the first honest temporal pair" {
    const statements = try adjacentStatements();
    const session = digest(101);
    const parent_vk = digest(102);
    const leaf_vk = digest(103);
    const shared_lineage = digest(104);
    const left_publication = try publicationFixture(
        statements[0],
        session,
        parent_vk,
        leaf_vk,
        digest(105),
        shared_lineage,
        1,
    );
    const right_publication = try publicationFixture(
        statements[1],
        session,
        parent_vk,
        leaf_vk,
        shared_lineage,
        digest(106),
        2,
    );
    try left_publication.validate();
    try right_publication.validate();

    var left: child_authority.PreparedTemporalChildV1 = undefined;
    try child_authority.admitInto(&left, &left_publication);
    var right: child_authority.PreparedTemporalChildV1 = undefined;
    try child_authority.admitInto(&right, &right_publication);
    try left.validateAgainst(&left_publication);
    try right.validateAgainst(&right_publication);

    const root_pin = temporal.RootVkPinV2{
        .expected_aggregator_vk_id = parent_vk,
    };
    var pair: pair_authority.PreparedTemporalPairAuthorityV1 = undefined;
    try pair_authority.prepareInto(&pair, &left, &right, &root_pin);
    try pair.validate();
    const authenticated = try pair.authenticatePrepared();
    try std.testing.expectEqual(@as(u8, 1), authenticated.pair.parent_height);
    try std.testing.expectEqual(@as(u64, 0), authenticated.pair.parent_node_index);
    try std.testing.expect(!pair.productionReady());
    try std.testing.expect(!left_publication.completeParentReady());
}

test "SegmentV2 publication and temporal pair reject mutation atomically" {
    const statements = try adjacentStatements();
    const session = digest(201);
    const parent_vk = digest(202);
    const leaf_vk = digest(203);
    const shared_lineage = digest(204);
    const honest_left = try publicationFixture(
        statements[0],
        session,
        parent_vk,
        leaf_vk,
        digest(205),
        shared_lineage,
        11,
    );
    const honest_right = try publicationFixture(
        statements[1],
        session,
        parent_vk,
        leaf_vk,
        shared_lineage,
        digest(206),
        12,
    );

    var mutated = honest_left;
    mutated.canonical_proof_byte_count += 1;
    try std.testing.expectError(error.InvalidProofIdentity, mutated.validate());
    mutated = honest_left;
    mutated.proof_id[0] ^= 1;
    try std.testing.expectError(error.InvalidProofIdentity, mutated.validate());
    mutated = honest_left;
    mutated.closure.domain_totals[7][2] = 1;
    try std.testing.expectError(error.InvalidClosure, mutated.validate());
    mutated = honest_left;
    mutated.complete_parent_capability = true;
    try std.testing.expectError(error.CapabilityEscalation, mutated.validate());

    var destination: child_authority.PreparedTemporalChildV1 = undefined;
    @memset(std.mem.asBytes(&destination), 0xa5);
    const before = std.mem.asBytes(&destination)[0..32].*;
    const invalid_publication = mutatedProofSize(honest_left);
    try std.testing.expectError(
        error.InvalidProofIdentity,
        child_authority.admitInto(&destination, &invalid_publication),
    );
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&destination)[0..32]);

    var left: child_authority.PreparedTemporalChildV1 = undefined;
    var right: child_authority.PreparedTemporalChildV1 = undefined;
    try child_authority.admitInto(&left, &honest_left);
    try child_authority.admitInto(&right, &honest_right);
    const root_pin = temporal.RootVkPinV2{
        .expected_aggregator_vk_id = parent_vk,
    };
    var pair_destination: pair_authority.PreparedTemporalPairAuthorityV1 = undefined;
    @memset(std.mem.asBytes(&pair_destination), 0x5a);
    const pair_before = std.mem.asBytes(&pair_destination)[0..32].*;
    try std.testing.expectError(
        error.AdjacencyMismatch,
        pair_authority.prepareInto(
            &pair_destination,
            &right,
            &left,
            &root_pin,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &pair_before,
        std.mem.asBytes(&pair_destination)[0..32],
    );
    try std.testing.expectError(
        error.DuplicateChild,
        pair_authority.prepareInto(
            &pair_destination,
            &left,
            &left,
            &root_pin,
        ),
    );
}

test "SegmentV2 temporal pair rejects cross-session and broken V2 lineage" {
    const statements = try adjacentStatements();
    const parent_vk = digest(302);
    const leaf_vk = digest(303);
    const shared_lineage = digest(304);
    const left_publication = try publicationFixture(
        statements[0],
        digest(301),
        parent_vk,
        leaf_vk,
        digest(305),
        shared_lineage,
        21,
    );
    const cross_session = try publicationFixture(
        statements[1],
        digest(399),
        parent_vk,
        leaf_vk,
        shared_lineage,
        digest(306),
        22,
    );
    const broken_lineage = try publicationFixture(
        statements[1],
        digest(301),
        parent_vk,
        leaf_vk,
        digest(398),
        digest(306),
        23,
    );
    var left: child_authority.PreparedTemporalChildV1 = undefined;
    var right: child_authority.PreparedTemporalChildV1 = undefined;
    try child_authority.admitInto(&left, &left_publication);
    const root_pin = temporal.RootVkPinV2{
        .expected_aggregator_vk_id = parent_vk,
    };
    var pair: pair_authority.PreparedTemporalPairAuthorityV1 = undefined;

    try child_authority.admitInto(&right, &cross_session);
    try std.testing.expectError(
        error.AdjacencyMismatch,
        pair_authority.prepareInto(&pair, &left, &right, &root_pin),
    );
    try child_authority.admitInto(&right, &broken_lineage);
    try std.testing.expectError(
        error.AdjacencyMismatch,
        pair_authority.prepareInto(&pair, &left, &right, &root_pin),
    );

    const wrong_pin = temporal.RootVkPinV2{
        .expected_aggregator_vk_id = digest(397),
    };
    const honest_right = try publicationFixture(
        statements[1],
        digest(301),
        parent_vk,
        leaf_vk,
        shared_lineage,
        digest(306),
        22,
    );
    try child_authority.admitInto(&right, &honest_right);
    try std.testing.expectError(
        error.RootVkMismatch,
        pair_authority.prepareInto(&pair, &left, &right, &wrong_pin),
    );
}

fn publicationFixture(
    statement: span.SpanStatement,
    session_id: Digest,
    parent_vk: Digest,
    leaf_vk: Digest,
    entry_lineage_id: Digest,
    exit_lineage_id: Digest,
    seed: u32,
) !Publication {
    const words = try statement.canonicalWords();
    const executed = switch (statement.body) {
        .empty => return error.UnexpectedEmptyStatement,
        .executed => |value| value,
    };
    var statement_probe = std.mem.zeroes(temporal.VerifiedChildV2);
    statement_probe.statement_words = words;
    const statement_id = try statement_probe.statementId();
    const proof_bytes = if (statement.slots.first == 0)
        "segment-v2-canonical-proof-left"
    else
        "segment-v2-canonical-proof-right";
    var canonical_proof_sha_id: publication_mod.Sha256Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        proof_bytes,
        &canonical_proof_sha_id,
        .{},
    );
    const manifest_sha_id = sha(seed + 1);
    var result = Publication{
        .proof_size_estimate = proof_bytes.len + 128,
        .canonical_proof_byte_count = @intCast(proof_bytes.len),
        .canonical_proof_sha_id = canonical_proof_sha_id,
        .segment_index = @intCast(statement.slots.first),
        .segment_count = statement.job.segment_count,
        .global_cycle_start = @intCast(executed.first_cycle),
        .global_cycle_end = @intCast(executed.endCycle()),
        .entry_continuation_root = 1_000 + seed,
        .exit_continuation_root = 1_001 + seed,
        .statement_words = words,
        .statement_id = statement_id,
        .session_id = session_id,
        .job_id = try temporal.jobId(&words),
        .position_id = digest(seed + 10),
        .segment_wire_id = digest(seed + 11),
        .entry_lineage_id = entry_lineage_id,
        .exit_lineage_id = exit_lineage_id,
        .lineage_id = digest(seed + 12),
        .source_context_id = digest(seed + 13),
        .recursive_parent_vk_id = parent_vk,
        .verification_key_id = leaf_vk,
        .air_program_id = digest(1),
        .manifest_id = publication_mod.expectedManifestId(manifest_sha_id),
        .profile_id = digest(2),
        .capture_id = digest(seed + 14),
        .recursive_witness_id = digest(seed + 16),
        .transcript_id = protocol.transcriptId(digest(seed + 15), 0),
        .verifier_context_id = digest(3),
        .proof_id = protocol.proofId(proof_bytes),
        .prepared_leaf_sha_id = sha(seed + 2),
        .cohort_authority_sha_id = sha(seed + 3),
        .manifest_sha_id = manifest_sha_id,
        .catalog_sha_id = sha(9_001),
        .relation_registry_sha_id = sha(9_002),
        .plan_sha_id = sha(seed + 4),
        .closure = .{
            .active_domain_mask = 1,
            .logical_rows = 1_000 + seed,
            .event_terms = 2_000 + seed,
            .domain_totals = [_]publication_mod.Qm31Words{.{ 0, 0, 0, 0 }} **
                publication_mod.RELATION_DOMAIN_COUNT,
            .framework_total = .{ 0, 0, 0, 0 },
            .verifier_receipt_id = digest(4),
            .claimed_sums_id = digest(5),
            .relation_replay_id = digest(6),
            .auxiliary_claim_seal_id = digest(7),
            .generated_interactions_sha_id = sha(seed + 5),
            .claim_seal_sha_id = sha(seed + 6),
            .audit_sha_id = sha(seed + 7),
            .closure_receipt_id = digest(8),
        },
        .publication_id = digest(9),
    };
    result.air_program_id = publication_mod.expectedAirProgramId(&result);
    result.profile_id = publication_mod.expectedProfileId(&result);
    result.verifier_context_id =
        publication_mod.expectedVerifierContextId(&result);
    result.closure.claimed_sums_id =
        publication_mod.expectedClaimedSumsId(&result);
    result.closure.relation_replay_id =
        publication_mod.expectedRelationReplayId(&result);
    result.closure.auxiliary_claim_seal_id =
        publication_mod.expectedAuxiliaryClaimSealId(&result);
    result.closure.verifier_receipt_id =
        publication_mod.expectedVerifierReceiptId(&result);
    result.closure.closure_receipt_id =
        try publication_mod.expectedTemporalClosureId(&result.closure);
    result.publication_id = publication_mod.expectedPublicationId(&result);
    try result.validate();
    return result;
}

fn adjacentStatements() ![2]span.SpanStatement {
    const zero_registers = [_]u32{0} ** 32;
    const initial = try span.MachineState.init(
        0x1000,
        zero_registers,
        digest(401),
        digest(402),
    );
    const middle = try span.MachineState.init(
        0x1004,
        zero_registers,
        digest(403),
        digest(404),
    );
    const final = try span.MachineState.init(
        0x1008,
        zero_registers,
        digest(405),
        digest(406),
    );
    const input = digest(407);
    const output = digest(408);
    const complete = try span.CompleteExecution.init(
        protocol.PROTOCOL_ID_WORDS,
        digest(409),
        initial,
        final,
        input,
        output,
        20,
    );
    const job = try span.JobContext.init(complete, 2);
    return .{
        try span.SpanStatement.segmentLeaf(
            job,
            0,
            try span.ExecutedSpan.init(
                0,
                1,
                0,
                10,
                initial,
                middle,
                try span.EdgeClaim.present(input),
                span.EdgeClaim.absent(),
            ),
        ),
        try span.SpanStatement.segmentLeaf(
            job,
            1,
            try span.ExecutedSpan.init(
                1,
                1,
                10,
                10,
                middle,
                final,
                span.EdgeClaim.absent(),
                try span.EdgeClaim.present(output),
            ),
        ),
    };
}

fn mutatedProofSize(source: Publication) Publication {
    var result = source;
    result.canonical_proof_byte_count += 1;
    return result;
}

fn digest(value: u32) Digest {
    var result = [_]u32{0} ** recursion.poseidon2_channel.RATE;
    result[0] = value;
    return result;
}

fn sha(value: u32) publication_mod.Sha256Digest {
    var result = [_]u8{0} ** 32;
    std.mem.writeInt(u32, result[0..4], value, .little);
    return result;
}

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const ingress =
    @import("recursive_temporal_ethereum_poseidon_h1_ingress_v1.zig");
const materializer =
    @import("recursive_temporal_ethereum_poseidon_h1_materializer_v1.zig");
const cohort =
    @import("recursive_temporal_ethereum_poseidon_h1_cohort_v1.zig");
const h1_manifest =
    @import("recursive_temporal_ethereum_poseidon_h1_manifest_v1.zig");
const h1_components =
    @import("recursive_temporal_ethereum_poseidon_h1_components_v1.zig");
const h1_trace =
    @import("recursive_temporal_ethereum_poseidon_h1_trace_v1.zig");
const h1_interactions =
    @import("recursive_temporal_ethereum_poseidon_h1_interactions_v1.zig");
const h1_boundary =
    @import("recursive_temporal_ethereum_poseidon_h1_boundary_v1.zig");
const h1_proof_cohort =
    @import("recursive_temporal_ethereum_poseidon_h1_proof_cohort_v1.zig");
const secure_parent_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");

const recursion = frontend.recursion;
const global_v3 = recursion.segment_leaf_local_authority_v3;
const link_v3 = recursion.segment_leaf_local_verified_link_v3;
const link_program = recursion.ethereum_leaf_link_program_v1;
const span = recursion.span_statement;
const channel = recursion.poseidon2_channel;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

test "Ethereum Poseidon h1 custody round-trips but cannot publish" {
    const authority = try structuralFixture();
    try authority.validate();
    const encoded = try authority.encodeCanonical();
    const decoded = try ingress.CustodyV1.decodeCanonical(&encoded);
    try std.testing.expectEqualDeep(authority, decoded);
    try std.testing.expectEqual(@as(u8, 1), decoded.height);
    try std.testing.expect(!decoded.production_activation);
    try std.testing.expectEqual(
        @as(usize, 3),
        ingress.MISSING_PRODUCTION_PREDICATES.len,
    );
    try std.testing.expectError(
        error.SecureParentProofPolicyUnavailable,
        ingress.requireProductionPredicate(.secure_parent_proof_policy),
    );
    try std.testing.expectError(
        error.VerifierMintedH1ProfileUnavailable,
        ingress.requireProductionPredicate(.verifier_minted_h1_profile),
    );
    try std.testing.expectError(
        error.CanonicalParentProofCodecUnavailable,
        ingress.requireProductionPredicate(.canonical_parent_proof_codec),
    );
}

test "Ethereum Poseidon h1 custody rejects resealed semantic mutations" {
    const original = try structuralFixture();

    var metadata_mutation = original;
    metadata_mutation.children[0].metadata_words[
        link_program.METADATA_SEGMENT_COUNT_START
    ] = M31.fromCanonical(17);
    ingress.testing.resealLeaf(&metadata_mutation.children[0]);
    ingress.testing.resealCustody(&metadata_mutation);
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1Leaf,
        metadata_mutation.validate(),
    );

    var program_mutation = original;
    program_mutation.children[0].public_authority_digests[1][0] +%= 1;
    ingress.testing.resealLeaf(&program_mutation.children[0]);
    ingress.testing.resealCustody(&program_mutation);
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1Leaf,
        program_mutation.validate(),
    );

    var semantic_mutation = original;
    semantic_mutation.air_contract.components[0].semantic_digest[0] ^= 1;
    ingress.testing.resealCustody(&semantic_mutation);
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1AirContract,
        semantic_mutation.validate(),
    );

    var profile_mutation = original;
    profile_mutation.h1_profile.parent_outer_manifest_sha256[0] ^= 1;
    ingress.testing.resealCustody(&profile_mutation);
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1Profile,
        profile_mutation.validate(),
    );

    var reordered = original;
    std.mem.swap(
        ingress.LeafAuthorityV1,
        &reordered.children[0],
        &reordered.children[1],
    );
    ingress.testing.resealCustody(&reordered);
    try std.testing.expectError(error.SlotsNotAdjacent, reordered.validate());
}

test "Ethereum Poseidon h1 canonical decoder rejects byte mutations" {
    const authority = try structuralFixture();
    var encoded = try authority.encodeCanonical();
    encoded[encoded.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1Ingress,
        ingress.CustodyV1.decodeCanonical(&encoded),
    );
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1Ingress,
        ingress.CustodyV1.decodeCanonical(encoded[0 .. encoded.len - 1]),
    );
}

test "Ethereum Poseidon h1 structural cohort binds twelve placements" {
    const custody = try structuralFixture();
    const plan = try materializer.PlanV1.initDefault(&custody);
    try plan.validateAgainst(&custody);
    try std.testing.expectEqualDeep(
        h1_manifest.LogSizes{
            11, 11, 9,
            7,  3,  4,
            4,  7,  3,
            4,  4,  8,
        },
        plan.log_sizes,
    );
    try std.testing.expectEqual(@as(u32, 206), plan.active_rows[11]);

    const assembled = try cohort.CohortV1.init(&plan, &custody);
    try assembled.validateAgainst(&plan, &custody);
    try std.testing.expectEqual(@as(u8, 4), assembled.wrapper_air_kind_count);
    try std.testing.expectEqual(@as(u8, 12), assembled.physical_placement_count);
    try std.testing.expectEqual(@as(u32, 842), assembled.link_source.left_count);
    try std.testing.expectEqual(@as(u32, 842), assembled.link_source.right_start);
    try std.testing.expectEqual(@as(u32, 206), assembled.provider_active_rows);
    try std.testing.expectEqual(@as(u32, 103), assembled.hashes[4].provider_call_start);
    try std.testing.expectError(
        error.EthereumPoseidonH1MaterializationUnavailable,
        plan.requireProduction(),
    );
    try std.testing.expectError(
        error.EthereumPoseidonH1CohortUnavailable,
        assembled.requireProduction(),
    );
}

test "Ethereum Poseidon h1 structural mutations fail after resealing" {
    const custody = try structuralFixture();
    const plan = try materializer.PlanV1.initDefault(&custody);

    var row_mutation = plan;
    row_mutation.active_rows[h1_manifest.keyIndex(.child_field_router)] += 1;
    materializer.testing.resealPlan(&row_mutation);
    try std.testing.expectError(
        error.EthereumPoseidonH1MaterializationPlanMismatch,
        row_mutation.validateAgainst(&custody),
    );

    const assembled = try cohort.CohortV1.init(&plan, &custody);
    var reordered = assembled;
    std.mem.swap(
        cohort.HashInstanceV1,
        &reordered.hashes[0],
        &reordered.hashes[1],
    );
    cohort.testing.reseal(&reordered);
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1Cohort,
        reordered.validateAgainst(&plan, &custody),
    );

    var call_gap = assembled;
    call_gap.hashes[3].provider_call_start += 1;
    cohort.testing.reseal(&call_gap);
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1Cohort,
        call_gap.validateAgainst(&plan, &custody),
    );

    var parameter_mutation = assembled;
    parameter_mutation.hashes[6].parameters[1] += 1;
    cohort.testing.reseal(&parameter_mutation);
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1Cohort,
        parameter_mutation.validateAgainst(&plan, &custody),
    );
}

test "Ethereum Poseidon h1 proof plumbing owns exact twelve-placement trees" {
    const custody = try structuralFixture();
    const plan = try materializer.PlanV1.initDefault(&custody);
    const assembled = try cohort.CohortV1.init(&plan, &custody);
    var owners = try h1_components.OwnersV1.init(std.testing.allocator);
    defer owners.deinit();

    var preprocessed = try h1_trace.TreeV1.init(
        std.testing.allocator,
        &plan.manifest,
        h1_manifest.PREPROCESSED_TREE_INDEX,
    );
    defer preprocessed.deinit();
    var main = try h1_trace.TreeV1.init(
        std.testing.allocator,
        &plan.manifest,
        h1_manifest.MAIN_TREE_INDEX,
    );
    defer main.deinit();
    var interaction = try h1_trace.TreeV1.init(
        std.testing.allocator,
        &plan.manifest,
        h1_manifest.INTERACTION_TREE_INDEX,
    );
    defer interaction.deinit();

    try std.testing.expectEqual(
        @as(usize, plan.manifest.total_preprocessed_columns),
        preprocessed.columns.len,
    );
    try std.testing.expectEqual(
        @as(usize, plan.manifest.total_main_columns),
        main.columns.len,
    );
    try std.testing.expectEqual(
        @as(usize, plan.manifest.total_interaction_columns),
        interaction.columns.len,
    );
    try std.testing.expectEqual(
        @as(u32, assembled.provider_active_rows),
        plan.active_rows[h1_manifest.keyIndex(.poseidon2)],
    );

    preprocessed.manifest_seal[0] ^= 1;
    try std.testing.expectError(
        error.DestinationShapeMismatch,
        preprocessed.validate(
            &plan.manifest,
            h1_manifest.PREPROCESSED_TREE_INDEX,
        ),
    );
    preprocessed.manifest_seal[0] ^= 1;
    try preprocessed.validate(
        &plan.manifest,
        h1_manifest.PREPROCESSED_TREE_INDEX,
    );
    std.testing.refAllDeclsRecursive(h1_interactions.GeneratedInteractionsV1);
}

test "Ethereum Poseidon h1 boundary cannot relabel statement as secure wire" {
    var receipt = h1_boundary.ClosureReceiptV1{
        .provider_closed = true,
        .internal_tuple_frontier_closed = true,
        .custody_identity_sha256 = sha(221),
        .materialized_identity_sha256 = sha(222),
        .generated_interactions_sha256 = sha(223),
        .parent_statement_sha256 = sha(224),
        .statement = .{
            .domain = h1_boundary.STATEMENT_DOMAIN,
            .tuple_count = 1,
            .claimed_sum = QM31.one(),
            .tuple_provenance_sha256 = sha(225),
        },
        .verifier_input = .{
            .domain = h1_boundary.VERIFIER_INPUT_DOMAIN,
            .tuple_count = 1,
            .claimed_sum = QM31.one(),
            .tuple_provenance_sha256 = sha(226),
        },
        .identity_sha256 = undefined,
    };
    h1_boundary.testing.reseal(&receipt);
    try receipt.validate();
    try std.testing.expect(
        h1_boundary.STATEMENT_DOMAIN !=
            h1_boundary.REQUIRED_SECURE_WIRE_DOMAIN,
    );
    try std.testing.expectError(
        error.EthereumPoseidonH1StatementWireJoinUnavailable,
        receipt.requireSecureParentAdmission(),
    );

    receipt.statement.domain = h1_boundary.REQUIRED_SECURE_WIRE_DOMAIN;
    h1_boundary.testing.reseal(&receipt);
    try std.testing.expectError(
        error.InvalidEthereumPoseidonH1BoundaryResidual,
        receipt.validate(),
    );
}

test "Ethereum Poseidon h1 cohort satisfies secure q193 engine contract" {
    std.testing.refAllDeclsRecursive(h1_proof_cohort.DefaultCohortV1);
    const Kernel = secure_parent_engine.EngineKernelForManifest(
        h1_proof_cohort.DefaultCohortV1,
        h1_manifest,
        .ethereum_poseidon_h1_v1,
    );
    std.testing.refAllDeclsRecursive(Kernel);
    try std.testing.expectEqual(
        @as(usize, 12),
        h1_manifest.COMPONENT_COUNT,
    );
    const contract_identity = try h1_manifest.contractIdentity();
    try std.testing.expect(!std.mem.allEqual(u8, &contract_identity, 0));
    try std.testing.expect(!h1_proof_cohort.PRODUCTION_ACTIVATION);
    try std.testing.expect(!secure_parent_engine.PRODUCTION_ACTIVATION);
}

fn structuralFixture() !ingress.CustodyV1 {
    const statements = try adjacentStatements();
    var children: [2]ingress.LeafAuthorityV1 = undefined;
    children[0] = try leafFixture(statements[0], 101);
    children[1] = try leafFixture(statements[1], 151);
    const parent = try span.SpanStatement.fold(statements[0], statements[1]);
    const parent_words = try parent.canonicalWords();
    var profile = ingress.H1ProfileBindingV1{
        .admitted_child_security_kind = .ethereum_segment_v3_poseidon2,
        .parent_proof_security_kind = .recursive_parent_functional,
        .node_profile_sha256 = sha(11),
        .child_composition_manifest_sha256 = sha(12),
        .parent_outer_manifest_sha256 = sha(13),
        .admitted_child_security_sha256 = sha(14),
        .parent_proof_security_sha256 = sha(15),
        .verification_key_id = digest(16),
        .next_parent_vk_id = digest(17),
        .air_program_id = digest(18),
        .profile_id = digest(19),
        .identity_sha256 = undefined,
    };
    ingress.testing.resealProfile(&profile);
    var result = ingress.CustodyV1{
        .air_contract = ingress.testing.fixedContract(),
        .h1_profile = profile,
        .children = children,
        .parent_statement_words = parent_words,
        .parent_statement_sha256 = statement_plan.statementSha256(&parent_words),
        .identity_sha256 = undefined,
    };
    ingress.testing.resealCustody(&result);
    try result.validate();
    return result;
}

fn leafFixture(
    statement: span.SpanStatement,
    seed: u32,
) !ingress.LeafAuthorityV1 {
    const global_words = try statement.canonicalWords();
    var metadata_words = [_]M31{M31.zero()} **
        global_v3.METADATA_IDENTITY_WORDS;
    metadata_words[0] = M31.fromCanonical(global_v3.FORMAT_VERSION);
    metadata_words[1] = M31.fromCanonical(global_v3.SCHEMA_VERSION);
    @memcpy(
        metadata_words[link_program.METADATA_BASE_START..][0..span.SPAN_STATEMENT_CANONICAL_WORDS],
        &global_words,
    );
    const metadata_id = channel.hashCanonicalWords(
        &metadata_words,
        global_v3.METADATA_ID_DOMAIN,
    );
    var link_words = [_]M31{M31.zero()} ** link_v3.IDENTITY_WORDS;
    link_words[0] = M31.fromCanonical(link_v3.FORMAT_VERSION);
    link_words[1] = M31.fromCanonical(link_v3.SCHEMA_VERSION);
    putDigest(link_words[2..10], metadata_id);
    putDigest(link_words[10..18], digest(seed + 1));
    putDigest(link_words[18..26], digest(seed + 2));
    putDigest(link_words[26..34], digest(seed + 3));
    for (link_words[34..], 0..) |*word, index|
        word.* = M31.fromCanonical(seed + @as(u32, @intCast(index)) + 4);
    const link_id = channel.hashCanonicalWords(
        &link_words,
        link_v3.IDENTITY_DOMAIN,
    );
    const program_id = digest(seed + 31);
    const component_count: u32 = 3;
    const infra_count: u32 = 4;
    var result = ingress.LeafAuthorityV1{
        .source_authority_sha256 = sha(seed + 4),
        .source_public_statement_sha256 = sha(seed + 5),
        .journal_record_sha256 = sha(seed + 6),
        .descriptor_sha256 = sha(seed + 7),
        .descriptor_subtree_sha256 = sha(seed + 8),
        .node_public_authority_sha256 = sha(seed + 9),
        .node_public_subtree_sha256 = sha(seed + 10),
        .node_public_subtree_digest = digest(seed + 11),
        .metadata_words = metadata_words,
        .verified_link_words = link_words,
        .global_statement_words = global_words,
        .local_statement_words = global_words,
        .transcript_claimed_sums = [_]QM31{QM31.zero()} **
            link_program.TRANSCRIPT_CLAIM_COUNT,
        .child_component_count = component_count,
        .child_infra_count = infra_count,
        .child_router_row_count = 90 + (component_count + infra_count) * 8,
        .child_authority_word_count = 22 + (component_count + infra_count) * 8,
        .vm_field_authority = .{
            .program_word_count = 100,
            .manifest_word_count = 200,
            .verifier_program_authority = program_id,
            .component_manifest_authority = digest(seed + 32),
        },
        .public_authority_digests = .{
            link_id,
            program_id,
            digest(seed + 33),
            digest(seed + 34),
            digest(seed + 35),
            digest(seed + 36),
            digest(seed + 37),
        },
        .local_wire_word_count = global_words.len,
        .local_wire_sha256 = ingress.testing.localWireIdentity(&global_words),
        .proof_artifact_byte_count = seed + 1,
        .proof_artifact_sha256 = sha(seed + 38),
        .proof_root_sha256 = sha(seed + 39),
        .transcript_state_sha256 = sha(seed + 40),
        .proof_capture_sha256 = sha(seed + 41),
        .capture_identity_sha256 = sha(seed + 42),
        .identity_sha256 = undefined,
    };
    ingress.testing.resealLeaf(&result);
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
        recursion.protocol.PROTOCOL_ID_WORDS,
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

fn putDigest(destination: []M31, value: channel.Digest) void {
    for (destination, value) |*word, limb|
        word.* = M31.fromCanonical(limb);
}

fn digest(value: u32) channel.Digest {
    var result = [_]u32{0} ** channel.RATE;
    result[0] = value;
    return result;
}

fn sha(value: u32) [32]u8 {
    var result = [_]u8{0} ** 32;
    std.mem.writeInt(u32, result[0..4], value, .little);
    return result;
}

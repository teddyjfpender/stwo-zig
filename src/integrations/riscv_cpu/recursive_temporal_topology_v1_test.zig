const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");
const topology = @import("recursive_temporal_topology_v1.zig");
const empty_transcript =
    @import("recursive_temporal_empty_parent_transcript_v1.zig");
const empty_source = @import("recursive_temporal_empty_parent_source_v1.zig");
const node_profile = @import("recursive_temporal_node_profile_v1.zig");
const proof_security = @import("recursive_temporal_proof_security_v1.zig");
const heterogeneous_pair =
    @import("recursive_temporal_heterogeneous_pair_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");
const profile_transport_test =
    @import("recursive_temporal_profile_plan_transport_v1_test.zig");
const verified_reducer_test =
    @import("recursive_temporal_verified_reducer_v1_test.zig");
const ethereum_leaf_bridge =
    @import("recursive_temporal_ethereum_leaf_bridge_v1.zig");
const ethereum_leaf_child_field_test =
    frontend.testing.ethereum_leaf_child_field_test;
const provider_shard_child_field_test =
    frontend.testing.provider_shard_child_field_test;

const recursion = frontend.recursion;
const leaf_link_program = recursion.ethereum_leaf_link_program_v1;
const leaf_link_projection = recursion.air.ethereum_leaf_link_projection_v1;
const leaf_link_source = recursion.air.ethereum_leaf_link_source_v1;
const span = recursion.span_statement;
const temporal = recursion.temporal_pair_node;

test "leaf-or-empty and topology public surfaces remain type-complete" {
    std.testing.refAllDeclsRecursive(leaf_mod);
    std.testing.refAllDeclsRecursive(topology);
    std.testing.refAllDeclsRecursive(empty_transcript);
    std.testing.refAllDeclsRecursive(empty_source);
    std.testing.refAllDeclsRecursive(node_profile);
    std.testing.refAllDeclsRecursive(proof_security);
    std.testing.refAllDeclsRecursive(heterogeneous_pair);
    std.testing.refAllDeclsRecursive(statement_plan);
    std.testing.refAllDeclsRecursive(profile_transport_test);
    std.testing.refAllDeclsRecursive(verified_reducer_test);
    std.testing.refAllDeclsRecursive(ethereum_leaf_bridge);
    std.testing.refAllDeclsRecursive(ethereum_leaf_child_field_test);
    std.testing.refAllDeclsRecursive(provider_shard_child_field_test);
    try ethereum_leaf_child_field_test.run();
    try provider_shard_child_field_test.run();
}

test "Ethereum leaf-link AIR seals exact field-native schedule" {
    const allocator = std.testing.allocator;
    var source_definition = try leaf_link_source.build(allocator);
    defer source_definition.deinit();
    _ = try leaf_link_source.authenticate(&source_definition);
    var projection_definition = try leaf_link_projection.build(allocator);
    defer projection_definition.deinit();
    _ = try leaf_link_projection.authenticate(&projection_definition);
    try std.testing.expectEqual(
        leaf_link_source.SEMANTIC_DIGEST,
        try leaf_link_source.computeSemanticDigest(allocator),
    );
    try std.testing.expectEqual(
        leaf_link_projection.SEMANTIC_DIGEST,
        try leaf_link_projection.computeSemanticDigest(allocator),
    );

    var program = try leaf_link_program.ProgramV1.init(allocator);
    defer program.deinit();
    try program.validate();
    try std.testing.expectEqual(
        @as(usize, 842),
        program.source_rows.len,
    );
    try std.testing.expectEqual(
        @as(usize, 930),
        program.projection_rows.len,
    );
    try std.testing.expectEqual(
        @as(usize, 77),
        program.metadata_hash.rows.len,
    );
    try std.testing.expectEqual(
        @as(usize, 7),
        program.link_hash.rows.len,
    );
    try std.testing.expectEqual(
        @as(u32, 4),
        program.source_rows[
            leaf_link_program.METADATA_LOCAL_COUNT_START
        ].use_count,
    );
    try std.testing.expectEqual(
        @as(u32, 4),
        program.source_rows[
            leaf_link_program.METADATA_LOCAL_COUNT_START + 1
        ].use_count,
    );
    const metadata_digest_start =
        leaf_link_program.SOURCE_ROW_COUNT - 2 *
            leaf_link_program.DIGEST_WORD_COUNT;
    try std.testing.expectEqual(
        @as(u32, 2),
        program.source_rows[metadata_digest_start].use_count,
    );

    var source_mutation = try leaf_link_program.ProgramV1.init(allocator);
    defer source_mutation.deinit();
    source_mutation.source_rows[0].use_count += 1;
    try std.testing.expectError(
        error.InvalidEthereumLeafLinkProgram,
        source_mutation.validate(),
    );
    var projection_mutation = try leaf_link_program.ProgramV1.init(allocator);
    defer projection_mutation.deinit();
    projection_mutation.projection_rows[0].raw_index += 1;
    try std.testing.expectError(
        error.InvalidEthereumLeafLinkProgram,
        projection_mutation.validate(),
    );
    var hash_mutation = try leaf_link_program.ProgramV1.init(allocator);
    defer hash_mutation.deinit();
    hash_mutation.metadata_hash.rows[0].chunks[0].word_index += 1;
    try std.testing.expectError(
        error.InvalidEthereumLeafLinkProgram,
        hash_mutation.validate(),
    );
}

test "empty height-one and recursive profiles keep current and next VK distinct" {
    const empty = try node_profile.NodeProfileV1.init(
        .empty_parent_h1,
        1,
        digest(501),
        digest(601),
        shaIdentity(81),
        digest(701),
        digest(801),
        .prooflessEmpty(),
        .recursiveParentFunctional(),
        .emptyParentV1(),
    );
    try empty.validate();
    try std.testing.expect(!std.meta.eql(
        empty.verification_key_id,
        empty.next_parent_vk_id,
    ));
    var mutation = empty;
    mutation.transcript = .temporalParentV3();
    try std.testing.expectError(error.InvalidNodeProfile, mutation.validate());

    const recursive = try node_profile.NodeProfileV1.init(
        .recursive_parent,
        2,
        digest(601),
        digest(901),
        shaIdentity(91),
        digest(1_001),
        digest(1_101),
        .recursiveParentFunctional(),
        .recursiveParentFunctional(),
        .recursiveNodeV1(),
    );
    try recursive.validate();
}

test "proof security is explicit and functional profiles fail production admission" {
    const secure = proof_security.ProofSecurityV1.ethereumSegmentV3Poseidon2();
    try secure.validate();
    try std.testing.expectEqual(@as(u32, 209), secure.configured_pcs_bits);
    try std.testing.expect(secure.isProductionRecursiveProof());

    const native_blake =
        proof_security.ProofSecurityV1.ethereumSegmentV3Blake2s();
    try native_blake.validate();
    try std.testing.expectEqual(
        proof_security.RecursiveIngressV1.native_only,
        native_blake.recursive_ingress,
    );
    try std.testing.expect(!native_blake.isProductionRecursiveProof());

    var mutation = secure;
    mutation.fri_query_count -= 1;
    try std.testing.expectError(
        error.InvalidProofSecurity,
        mutation.validate(),
    );

    const functional = try campaignProfiles();
    try functional.validate();
    try std.testing.expectError(
        error.ProductionSecurityProfileRequired,
        functional.requireProductionSecurity(),
    );
}

test "empty-parent suffix policy admits only composition arithmetic and transcript rows" {
    const policy = empty_source.SuffixPolicyV1.canonical();
    try policy.validate();
    try std.testing.expectEqual(
        empty_source.RowModeV1.composition,
        try policy.mode(18),
    );
    try std.testing.expectEqual(
        empty_source.RowModeV1.composition,
        try policy.mode(19),
    );
    for (20..30) |row| try std.testing.expectEqual(
        empty_source.RowModeV1.inactive_child_verifier,
        try policy.mode(row),
    );
    for (30..33) |row| try std.testing.expectEqual(
        empty_source.RowModeV1.arithmetic,
        try policy.mode(row),
    );
    try std.testing.expectEqual(
        empty_source.RowModeV1.inactive_merkle_path,
        try policy.mode(33),
    );
    try std.testing.expectEqual(
        empty_source.RowModeV1.transcript_provider,
        try policy.mode(34),
    );
    try std.testing.expectError(error.InvalidEmptyParentPolicy, policy.mode(17));
    try std.testing.expectError(error.InvalidEmptyParentPolicy, policy.mode(35));

    var mutation = policy;
    mutation.modes[2] = .arithmetic;
    try std.testing.expectError(
        error.InvalidEmptyParentPolicy,
        mutation.validate(),
    );
    mutation = policy;
    mutation.child_fri_mask = 1;
    try std.testing.expectError(
        error.InvalidEmptyParentPolicy,
        mutation.validate(),
    );
}

test "proofless empty transcript is statement and pair bound without FRI draws" {
    const allocator = std.testing.allocator;
    const active_job = try job(210);
    const session_id = digest(301);
    const leaf_vk_id = digest(401);
    const parent_vk_id = digest(501);
    var left: leaf_mod.LeafOrEmptyV1 = undefined;
    try leaf_mod.admitEmptyInto(
        &left,
        active_job,
        210,
        session_id,
        leaf_vk_id,
        parent_vk_id,
    );
    var right: leaf_mod.LeafOrEmptyV1 = undefined;
    try leaf_mod.admitEmptyInto(
        &right,
        active_job,
        211,
        session_id,
        leaf_vk_id,
        parent_vk_id,
    );
    const pin = temporal.RootVkPinV2{
        .expected_aggregator_vk_id = parent_vk_id,
    };
    var pair: leaf_mod.PreparedLeafPairV1 = undefined;
    try leaf_mod.preparePairInto(&pair, &left, &right, &pin);
    const children = [2]*const leaf_mod.LeafOrEmptyV1{ &left, &right };
    const programs = [2]empty_transcript.ProgramBindingV1{
        try programBinding(&left, 61),
        try programBinding(&right, 71),
    };
    var prepared = try empty_transcript.PreparedTranscriptV1.init(
        allocator,
        &pair,
        children,
        programs,
    );
    defer prepared.deinit();
    try prepared.validateAgainst(&pair, children, programs);
    try std.testing.expect(prepared.transcript_rows.rows.len > 0);
    try prepared.transcript_rows.validate();
    try std.testing.expectEqual(
        nonzeroSum(prepared.transcript_rows.lane_row_counts),
        prepared.transcript_rows.rows.len,
    );
    try std.testing.expectEqual(
        @as(u32, empty_transcript.PACKED_RELATION_DRAW_COUNT + 2),
        prepared.lanes[0].final_draw_count,
    );
    try std.testing.expectEqual(
        @as(u32, empty_transcript.PACKED_RELATION_DRAW_COUNT + 2),
        prepared.lanes[1].final_draw_count,
    );
    try std.testing.expect(!empty_transcript.PROOF_BYTES_ACCEPTED);
    try std.testing.expect(!empty_transcript.FRI_DRAWS_EMITTED);
    try std.testing.expect(!empty_transcript.QUERY_DRAWS_EMITTED);

    var mutated = prepared;
    mutated.format_version += 1;
    try std.testing.expectError(
        error.InvalidEmptyTranscriptAuthority,
        mutated.validateAgainst(&pair, children, programs),
    );
    mutated = prepared;
    mutated.schema_version += 1;
    try std.testing.expectError(
        error.InvalidEmptyTranscriptAuthority,
        mutated.validateAgainst(&pair, children, programs),
    );
    mutated = prepared;
    mutated.pair_authority_sha_id[0] ^= 1;
    try std.testing.expectError(
        error.InvalidEmptyTranscriptAuthority,
        mutated.validateAgainst(&pair, children, programs),
    );

    var wrong_programs = programs;
    wrong_programs[0].manifest_sha_id[0] ^= 1;
    try std.testing.expectError(
        error.InvalidEmptyTranscriptAuthority,
        prepared.validateAgainst(&pair, children, wrong_programs),
    );
    const swapped = [2]*const leaf_mod.LeafOrEmptyV1{ &right, &left };
    try std.testing.expectError(
        error.ChildAuthorityMismatch,
        prepared.validateAgainst(&pair, swapped, programs),
    );

    var statement_mutation = left;
    statement_mutation.payload.empty.child.statement_words[0] =
        statement_mutation.payload.empty.child.statement_words[0].add(
            @import("stwo_core").fields.m31.M31.one(),
        );
    try expectRejected(statement_mutation.validate());
    var span_mutation: leaf_mod.LeafOrEmptyV1 = undefined;
    try leaf_mod.admitEmptyInto(
        &span_mutation,
        active_job,
        212,
        session_id,
        leaf_vk_id,
        parent_vk_id,
    );
    const wrong_span = [2]*const leaf_mod.LeafOrEmptyV1{
        &left,
        &span_mutation,
    };
    try std.testing.expectError(
        error.ChildAuthorityMismatch,
        prepared.validateAgainst(&pair, wrong_span, programs),
    );
}

test "210 real leaves produce exact fail-closed 256-slot height-8 topology" {
    const plan = try topology.TopologyPlanV1.init(try job(210));
    try std.testing.expectEqual(@as(u32, 210), plan.real_leaf_count);
    try std.testing.expectEqual(@as(u64, 256), plan.padded_leaf_count);
    try std.testing.expectEqual(@as(u64, 46), plan.empty_leaf_count);
    try std.testing.expectEqual(@as(u8, 8), plan.root_height);
    try std.testing.expectEqual(@as(u64, 255), try plan.proofCount());
    try std.testing.expect(!plan.empty_subtree_collapse);
    try std.testing.expectEqual(@as(u8, 0), plan.proofless_empty_height);

    const expected_counts = [_]u64{ 256, 128, 64, 32, 16, 8, 4, 2, 1 };
    for (expected_counts, 0..) |expected, height|
        try std.testing.expectEqual(expected, try plan.nodeCount(@intCast(height)));

    // Because 210 is even, height one has a clean real/empty boundary.
    try std.testing.expectEqual(
        topology.NodeKindV1.real,
        try plan.nodeKind(1, 104),
    );
    try std.testing.expectEqual(
        topology.NodeKindV1.empty,
        try plan.nodeKind(1, 105),
    );
    // The first mixed parent is height two: [208,210) + [210,212).
    const boundary = try plan.pair(2, 52);
    try std.testing.expectEqual(@as(u64, 208), boundary.left_first);
    try std.testing.expectEqual(@as(u64, 210), boundary.right_first);
    try std.testing.expectEqual(topology.NodeKindV1.real, boundary.left_kind);
    try std.testing.expectEqual(topology.NodeKindV1.empty, boundary.right_kind);
    try std.testing.expectEqual(
        topology.NodeKindV1.mixed,
        try plan.nodeKind(2, 52),
    );
    try std.testing.expectEqual(
        topology.NodeKindV1.mixed,
        try plan.nodeKind(8, 0),
    );

    var schedule = try topology.BreadthFirstScheduleV1.create(
        std.testing.allocator,
        plan,
    );
    defer schedule.deinit();
    try std.testing.expectEqual(@as(usize, 255), schedule.tasks.len);
    const mixed_task = schedule.tasks[180];
    try std.testing.expectEqual(@as(u64, 180), mixed_task.ordinal);
    try std.testing.expectEqual(@as(u8, 2), mixed_task.parent_height);
    try std.testing.expectEqual(@as(u64, 52), mixed_task.parent_index);
    try std.testing.expectEqual(topology.NodeKindV1.real, mixed_task.left_kind);
    try std.testing.expectEqual(topology.NodeKindV1.empty, mixed_task.right_kind);
    try std.testing.expectEqual(@as(u8, 8), schedule.tasks[254].parent_height);
    try std.testing.expectEqual(@as(u64, 0), schedule.tasks[254].parent_index);

    const original_task = schedule.tasks[1];
    schedule.tasks[1] = schedule.tasks[0];
    try std.testing.expectError(error.InvalidSchedule, schedule.validate());
    schedule.tasks[1] = original_task;
    try schedule.validate();
    schedule.tasks[1].identity[0] ^= 1;
    try std.testing.expectError(error.InvalidSchedule, schedule.validate());
    schedule.tasks[1] = original_task;
    try schedule.validate();

    var mutation = plan;
    mutation.identity[0] ^= 1;
    try std.testing.expectError(error.InvalidTopology, mutation.validate());
    mutation = plan;
    mutation.empty_leaf_count -= 1;
    try std.testing.expectError(error.InvalidTopology, mutation.validate());
    mutation = plan;
    mutation.empty_subtree_collapse = true;
    try std.testing.expectError(error.InvalidTopology, mutation.validate());
}

test "statement materializer seals all 511 nodes before proof publication" {
    const active_job = try job(statement_plan.REAL_LEAF_COUNT);
    var real: [statement_plan.REAL_LEAF_COUNT]statement_plan.ExpectedRealLeafV1 = undefined;
    for (&real, 0..) |*destination, index| {
        const metadata = try campaignMetadata(active_job, @intCast(index));
        destination.* = .{
            .metadata = metadata,
            .metadata_id = try metadata.identity(),
            .source_sha_id = shaIdentity(@intCast(index + 1)),
        };
    }
    const profiles = try campaignProfiles();
    const empty_authority = try statement_plan.EmptyAuthorityV1.init(
        digest(1_501),
        digest(1_601),
    );
    var plan: statement_plan.MaterializedPlanV1 = undefined;
    try statement_plan.materialize210Into(
        &plan,
        &real,
        empty_authority,
        profiles,
    );
    try plan.validateAgainst(&real);
    try std.testing.expectEqual(@as(u8, 8), plan.parents[254].height);
    try std.testing.expectEqual(topology.NodeKindV1.real, plan.leaves[209].kind);
    try std.testing.expectEqual(topology.NodeKindV1.empty, plan.leaves[210].kind);
    try std.testing.expectEqual(topology.NodeKindV1.mixed, plan.parents[180].kind);
    try std.testing.expectEqualSlices(
        u8,
        &plan.root_statement_sha_id,
        &plan.parents[254].statement_sha_id,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &plan.leaves[0].statement_sha_id,
        &plan.leaves[0].source_public_statement_sha_id,
    ));

    var source_mutation = real;
    source_mutation[17].source_sha_id[0] ^= 1;
    try std.testing.expectError(
        error.SourceAuthorityMismatch,
        plan.validateAgainst(&source_mutation),
    );
    var plan_mutation = plan;
    plan_mutation.parents[254].statement_sha_id[0] ^= 1;
    try std.testing.expectError(
        error.InvalidStatementPlan,
        plan_mutation.validate(),
    );
    var empty_mutation = plan.empty_authority;
    empty_mutation.segment_leaf_vk_id[0] += 1;
    try std.testing.expectError(
        error.InvalidEmptyAuthority,
        empty_mutation.validate(),
    );
}

test "topology rejects holes duplicates overlaps and empty-before-real" {
    const plan = try topology.TopologyPlanV1.init(try job(210));
    var indices: [210]u32 = undefined;
    for (&indices, 0..) |*value, index| value.* = @intCast(index);
    try plan.validateRealLeafOrder(&indices);

    var mutated = indices;
    mutated[19] = 18;
    try std.testing.expectError(
        error.DuplicateLeaf,
        plan.validateRealLeafOrder(&mutated),
    );
    mutated = indices;
    mutated[19] = 20;
    try std.testing.expectError(
        error.LeafHole,
        plan.validateRealLeafOrder(&mutated),
    );
    mutated = indices;
    mutated[19] = 17;
    try std.testing.expectError(
        error.LeafOverlap,
        plan.validateRealLeafOrder(&mutated),
    );

    var kinds = [_]leaf_mod.KindV1{.empty} ** 256;
    @memset(kinds[0..210], .segment);
    try plan.validateLeafKinds(&kinds);
    kinds[12] = .empty;
    try std.testing.expectError(
        error.EmptyBeforeReal,
        plan.validateLeafKinds(&kinds),
    );
    kinds[12] = .segment;
    kinds[220] = .segment;
    try std.testing.expectError(
        error.InvalidTopology,
        plan.validateLeafKinds(&kinds),
    );
}

test "canonical trailing empty leaves authenticate and fold only at height zero" {
    const active_job = try job(210);
    const session_id = digest(301);
    const leaf_vk_id = digest(401);
    const parent_vk_id = digest(501);
    var left: leaf_mod.LeafOrEmptyV1 = undefined;
    try leaf_mod.admitEmptyInto(
        &left,
        active_job,
        210,
        session_id,
        leaf_vk_id,
        parent_vk_id,
    );
    var right: leaf_mod.LeafOrEmptyV1 = undefined;
    try leaf_mod.admitEmptyInto(
        &right,
        active_job,
        211,
        session_id,
        leaf_vk_id,
        parent_vk_id,
    );
    try left.validate();
    try right.validate();
    try std.testing.expectEqual(leaf_mod.KindV1.empty, left.kind());

    const pin = temporal.RootVkPinV2{
        .expected_aggregator_vk_id = parent_vk_id,
    };
    var pair: leaf_mod.PreparedLeafPairV1 = undefined;
    try leaf_mod.preparePairInto(&pair, &left, &right, &pin);
    try pair.validateAgainst(&left, &right);
    const parent = pair.prepared_root.result.pair.parent_statement;
    try std.testing.expectEqual(@as(u8, 1), parent.slots.height);
    try std.testing.expectEqual(@as(u64, 210), parent.slots.first);
    switch (parent.body) {
        .empty => {},
        .executed => return error.TestUnexpectedResult,
    }

    const retained = left;
    try std.testing.expectError(
        error.EmptyIndexNotTrailing,
        leaf_mod.admitEmptyInto(
            &left,
            active_job,
            209,
            session_id,
            leaf_vk_id,
            parent_vk_id,
        ),
    );
    try std.testing.expectEqualDeep(retained, left);
    try std.testing.expectError(
        error.EmptyIndexNotTrailing,
        leaf_mod.admitEmptyInto(
            &left,
            active_job,
            256,
            session_id,
            leaf_vk_id,
            parent_vk_id,
        ),
    );
    try std.testing.expectEqualDeep(retained, left);

    // A proofless empty publication cannot be relabelled as a height-one
    // subtree. The next level must consume the verified parent above.
    var higher = retained;
    higher.payload.empty.child.statement_words = try parent.canonicalWords();
    try std.testing.expectError(error.EmptyIndexNotTrailing, higher.validate());
}

test "empty admission and pair identities reject mutation" {
    const active_job = try job(210);
    var left: leaf_mod.LeafOrEmptyV1 = undefined;
    try leaf_mod.admitEmptyInto(
        &left,
        active_job,
        210,
        digest(301),
        digest(401),
        digest(501),
    );
    var mutation = left;
    mutation.authority_sha_id[0] ^= 1;
    try std.testing.expectError(
        error.AdmissionIdentityMismatch,
        mutation.validate(),
    );
    mutation = left;
    mutation.payload.empty.child.proof_id[0] = 1;
    try std.testing.expectError(
        error.ChildAuthorityMismatch,
        mutation.validate(),
    );

    var right: leaf_mod.LeafOrEmptyV1 = undefined;
    try leaf_mod.admitEmptyInto(
        &right,
        active_job,
        211,
        digest(301),
        digest(401),
        digest(501),
    );
    const pin = temporal.RootVkPinV2{
        .expected_aggregator_vk_id = digest(501),
    };
    var pair: leaf_mod.PreparedLeafPairV1 = undefined;
    try leaf_mod.preparePairInto(&pair, &left, &right, &pin);
    var pair_mutation = pair;
    pair_mutation.authority_sha_id[0] ^= 1;
    try std.testing.expectError(
        error.ChildAuthorityMismatch,
        pair_mutation.validate(),
    );
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

fn campaignProfiles() !statement_plan.ProfilePlanV1 {
    var upper: [statement_plan.UPPER_PROFILE_COUNT]node_profile.NodeProfileV1 =
        undefined;
    for (&upper, 0..) |*profile, index| {
        profile.* = try node_profile.NodeProfileV1.init(
            .recursive_parent,
            @intCast(index + 2),
            digest(@intCast(2_000 + index)),
            digest(@intCast(2_001 + index)),
            shaIdentity(@intCast(120 + index)),
            digest(@intCast(2_100 + index)),
            digest(@intCast(2_200 + index)),
            .recursiveParentFunctional(),
            .recursiveParentFunctional(),
            .recursiveNodeV1(),
        );
    }
    return .{
        .real_h1 = try node_profile.NodeProfileV1.init(
            .real_parent_h1,
            1,
            digest(1_800),
            upper[0].verification_key_id,
            shaIdentity(101),
            digest(1_810),
            digest(1_820),
            .segmentV2Poseidon2(),
            .recursiveParentFunctional(),
            .temporalParentV3(),
        ),
        .empty_h1 = try node_profile.NodeProfileV1.init(
            .empty_parent_h1,
            1,
            digest(1_900),
            upper[0].verification_key_id,
            shaIdentity(111),
            digest(1_910),
            digest(1_920),
            .prooflessEmpty(),
            .recursiveParentFunctional(),
            .emptyParentV1(),
        ),
        .upper = upper,
    };
}

fn campaignMetadata(
    active_job: span.JobContext,
    index: u32,
) !recursion.segment_leaf_local_authority_v3.MetadataV3 {
    const last = index + 1 == active_job.segment_count;
    const entry = if (index == 0)
        active_job.complete.initial_state
    else
        try campaignState(index);
    const exit_state = if (last)
        active_job.complete.final_state
    else
        try campaignState(index + 1);
    const executed = try span.ExecutedSpan.init(
        index,
        1,
        index,
        1,
        entry,
        exit_state,
        if (index == 0)
            try span.EdgeClaim.present(active_job.complete.public_input)
        else
            span.EdgeClaim.absent(),
        if (last)
            try span.EdgeClaim.present(active_job.complete.public_output)
        else
            span.EdgeClaim.absent(),
    );
    const statement = try span.SpanStatement.segmentLeaf(
        active_job,
        index,
        executed,
    );
    const segment_v2 = recursion.segment_statement_v2;
    const empty_clock_id = segment_v2.memoryClockIdentity(&.{});
    const result = recursion.segment_leaf_local_authority_v3.MetadataV3{
        .base_statement_words = try statement.canonicalWords(),
        .segment_index = index,
        .segment_count = active_job.segment_count,
        .global_cycle_start = index,
        .global_cycle_end = index + 1,
        .local_cycle_count = 1,
        .entry = campaignBoundary(index, empty_clock_id),
        .exit = campaignBoundary(index + 1, empty_clock_id),
        .completion = if (last) .{
            .kind = .unretired_self_loop,
            .address = exit_state.pc,
            .value = 0x0000_006f,
            .clock = 0,
        } else null,
    };
    try result.validate();
    return result;
}

fn campaignState(index: u32) !span.MachineState {
    var registers = [_]u32{0} ** 32;
    registers[1] = 100 + index;
    return span.MachineState.init(
        0x3000 + 4 * index,
        registers,
        digest(3_000 + index),
        digest(4_000 + index),
    );
}

fn campaignBoundary(
    index: u32,
    empty_clock_id: [8]u32,
) recursion.segment_leaf_local_authority_v3.BoundaryV3 {
    return .{
        .snapshot_id = digest(5_000 + index),
        .snapshot_count = 0,
        .continuation_root = 0,
        .register_clocks = .{0} ** 32,
        .memory_clock_id = empty_clock_id,
        .memory_clock_count = 0,
    };
}

fn digest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn programBinding(
    leaf: *const leaf_mod.LeafOrEmptyV1,
    seed: u8,
) !empty_transcript.ProgramBindingV1 {
    const child = leaf.child();
    const result = empty_transcript.ProgramBindingV1{
        .program_identity = shaIdentity(seed),
        .air_program_id = digest(seed + 1),
        .manifest_sha_id = shaIdentity(seed + 2),
        .binary_layout_sha_id = shaIdentity(seed + 3),
        .empty_layout_sha_id = shaIdentity(seed + 4),
        .parameter_authority_sha_id = shaIdentity(seed + 5),
        .statement_id = try child.statementId(),
        .publication_id = try child.id(),
    };
    try result.validate();
    return result;
}

fn shaIdentity(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

fn expectRejected(result: anyerror!void) !void {
    if (result) |_| return error.TestExpectedError else |_| {}
}

fn nonzeroSum(values: [2]usize) usize {
    return values[0] + values[1];
}

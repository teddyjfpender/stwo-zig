const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const prover_engine = @import("stwo_prover_engine");

const ethereum_leaf =
    @import("recursive_temporal_ethereum_leaf_descriptor_v1.zig");
const incremental_provider =
    @import("recursive_temporal_incremental_provider_authority_v1.zig");
const native_provider = frontend.prover_mod.memory_provider_shard_authority;
const poseidon_air = frontend.air.memory_commitment.poseidon2_air;
const node_public =
    @import("recursive_temporal_node_public_authority_v2.zig");
const reducer_mod = @import("recursive_temporal_verified_reducer_v1.zig");
const statement_plan = @import("recursive_temporal_statement_plan_v1.zig");
const topology = @import("recursive_temporal_topology_v1.zig");

const recursion = frontend.recursion;
const source_wire = frontend.prover_mod.guest_precompile
    .ethereum_segment_source_wire;
const span = recursion.span_statement;
const program_descriptor =
    recursion.ethereum_vm_verified_program_descriptor_v1;
const QM31 = core.fields.qm31.QM31;

test "fresh Ethereum leaf descriptor round-trips source and program custody" {
    const active_job = try testJob(210);
    const metadata = try metadataFor(active_job, 0);
    var source = source_wire.Source{
        .journal_record_sha256 = shaIdentity(211),
        .metadata = metadata,
    };
    const link = try verifiedLinkForMetadata(&metadata);
    const program = try testProgramDescriptor(31);
    const descriptor = try ethereum_leaf.initFromFreshVerifier(.{
        .program = program,
        .source = &source,
        .verified_link = link,
        .proof_artifact_byte_count = 9_141_337,
        .proof_artifact_sha256 = shaIdentity(41),
        .proof_root_sha256 = shaIdentity(51),
        .transcript_state_sha256 = shaIdentity(61),
    });
    try descriptor.validateAgainstSource(&source);
    const encoded = try descriptor.encodeCanonical();
    const decoded = try ethereum_leaf.DescriptorV1.decodeCanonical(&encoded);
    try std.testing.expectEqualDeep(descriptor, decoded);

    source.journal_record_sha256[0] ^= 1;
    try std.testing.expectError(
        error.EthereumLeafDescriptorMismatch,
        descriptor.validateAgainstSource(&source),
    );
    var corrupted = encoded;
    corrupted[corrupted.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidEthereumLeafDescriptor,
        ethereum_leaf.DescriptorV1.decodeCanonical(&corrupted),
    );
    var link_mutation = descriptor;
    link_mutation.verified_link.global_cycle_end += 1;
    try std.testing.expectError(
        error.InvalidVerifiedLink,
        link_mutation.validate(),
    );
}

test "node public V2 retains full leaf metadata and ordered parent custody" {
    const active_job = try testJob(210);
    const left_metadata = try metadataFor(active_job, 0);
    const right_metadata = try metadataFor(active_job, 1);
    const left_descriptor = try freshLeafDescriptor(left_metadata, 31);
    const right_descriptor = try freshLeafDescriptor(right_metadata, 71);
    var left_provider = try ProviderFixture.init(
        left_metadata,
        left_descriptor,
        91,
    );
    defer left_provider.deinit();
    var right_provider = try ProviderFixture.init(
        right_metadata,
        right_descriptor,
        131,
    );
    defer right_provider.deinit();
    const left = try node_public.EthereumLeafAuthorityV2
        .initFromFreshVerifier(
        left_descriptor,
        left_metadata,
        left_provider.input(),
    );
    const right = try node_public.EthereumLeafAuthorityV2
        .initFromFreshVerifier(
        right_descriptor,
        right_metadata,
        right_provider.input(),
    );

    const leaf_bytes = try left.encodeCanonical();
    const decoded_leaf = try node_public.EthereumLeafAuthorityV2
        .decodeCanonical(&leaf_bytes);
    try std.testing.expectEqualDeep(left, decoded_leaf);
    try left.validateAgainstProvider(left_provider.input());
    try std.testing.expectEqual(@as(u32, 3), left.provider.shard_count);
    try std.testing.expectEqual(
        left_provider.residency_plan.shard_count,
        @as(u64, left.provider.shard_count),
    );
    const provider_bytes = try left.provider.encodeCanonical();
    const decoded_provider = try incremental_provider.ProviderCompilerAuthorityV1
        .decodeCanonical(&provider_bytes);
    try std.testing.expectEqualDeep(left.provider, decoded_provider);
    try std.testing.expectError(
        error.IncrementalProviderProofUnavailable,
        left.provider.requireProduction(left_provider.input()),
    );
    var metadata_mutation = left;
    metadata_mutation.metadata.entry.snapshot_count += 1;
    try std.testing.expectError(
        error.InvalidNodePublicLeaf,
        metadata_mutation.validate(),
    );
    var corrupted_leaf = leaf_bytes;
    corrupted_leaf[ethereum_leaf.ENCODED_BYTE_COUNT + 64] ^= 1;
    try std.testing.expectError(
        error.InvalidNodePublicLeaf,
        node_public.EthereumLeafAuthorityV2.decodeCanonical(&corrupted_leaf),
    );
    var provider_manifest_mutation = left;
    provider_manifest_mutation.provider.shard_manifest_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalProviderAuthority,
        provider_manifest_mutation.validate(),
    );
    var provider_aggregate_mutation = left;
    provider_aggregate_mutation.provider
        .aggregate_cancellation_digest[0] += 1;
    try std.testing.expectError(
        error.InvalidIncrementalProviderAuthority,
        provider_aggregate_mutation.validate(),
    );
    var provider_root_input = left_provider.input();
    provider_root_input.exit_continuation_root += 1;
    const provider_root_mutation = try incremental_provider
        .ProviderCompilerAuthorityV1.compile(provider_root_input);
    var provider_root_leaf = left;
    provider_root_leaf.provider = provider_root_mutation;
    try std.testing.expectError(
        error.InvalidNodePublicLeaf,
        provider_root_leaf.validate(),
    );
    var planner_mutation = left_provider.input();
    planner_mutation.residency_plan.plan_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidResidencyShardPlan,
        left.provider.validateAgainst(planner_mutation),
    );
    var reordered_artifacts = left_provider.artifacts;
    std.mem.swap(
        incremental_provider.ShardArtifactV1,
        &reordered_artifacts[0],
        &reordered_artifacts[1],
    );
    var reordered_input = left_provider.input();
    reordered_input.shard_artifacts = &reordered_artifacts;
    try std.testing.expectError(
        error.IncrementalProviderShardMismatch,
        left.provider.validateAgainst(reordered_input),
    );

    const left_reference = try left.reference();
    const right_reference = try right.reference();
    const compiler_input = node_public.ParentCompilerInputV2{
        .left = left_reference,
        .right = right_reference,
        .air_program_identity = shaIdentity(101),
        .verifier_program_authority = shaIdentity(111),
        .protocol_profile_sha256 = shaIdentity(121),
        .preprocessed_commitment_root = digest(13_001),
    };
    const parent = try node_public.ParentCompilerAuthorityV2.compile(
        compiler_input,
    );
    try parent.validateAgainst(compiler_input);
    try std.testing.expectError(
        error.VerifiedParentPublicationUnavailable,
        parent.requireProductionPublication(),
    );
    const parent_bytes = try parent.encodeCanonical();
    const decoded_parent = try node_public.ParentCompilerAuthorityV2
        .decodeCanonical(&parent_bytes);
    try std.testing.expectEqualDeep(parent, decoded_parent);

    var reordered = compiler_input;
    reordered.left = right_reference;
    reordered.right = left_reference;
    try std.testing.expectError(
        error.SlotsNotAdjacent,
        node_public.ParentCompilerAuthorityV2.compile(reordered),
    );
    var parent_mutation = parent;
    parent_mutation.child_subtree_sha256[0][0] ^= 1;
    try std.testing.expectError(
        error.InvalidNodePublicParent,
        parent_mutation.validate(),
    );
    var compiler_mutation = compiler_input;
    compiler_mutation.verifier_program_authority[0] ^= 1;
    try std.testing.expectError(
        error.NodePublicParentMismatch,
        parent.validateAgainst(compiler_mutation),
    );
}

test "dynamic reducer seals 210-to-256 edges and refuses root promotion" {
    const plan = try topology.TopologyPlanV1.init(try testJob(210));
    var reducer = try reducer_mod.ReducerV1.create(
        std.testing.allocator,
        plan,
    );
    defer reducer.deinit();
    try std.testing.expectError(
        error.InvalidReducerOrder,
        reducer.admitTrailingEmpty(),
    );
    for (0..@as(usize, plan.real_leaf_count)) |index|
        try reducer_mod.testing.admitLeafRecord(
            &reducer,
            try realRecord(&plan, @intCast(index)),
        );
    for (
        @as(usize, plan.real_leaf_count)..@as(usize, @intCast(plan.padded_leaf_count)),
    ) |_|
        try reducer.admitTrailingEmpty();

    var first = try reducer_mod.testing.mintNextParentEnvelope(&reducer, 1);
    try std.testing.expectError(
        error.VerifiedParentEnvelopeUnavailable,
        reducer.admitVerifiedParent(&first),
    );
    first.left_subtree_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidVerifiedParentEnvelope,
        reducer_mod.testing.admitParent(&reducer, &first),
    );
    first = try reducer_mod.testing.mintNextParentEnvelope(&reducer, 1);
    try reducer_mod.testing.admitParent(&reducer, &first);
    while (reducer.next_parent_ordinal < reducer.schedule.tasks.len) {
        const envelope = try reducer_mod.testing.mintNextParentEnvelope(
            &reducer,
            @truncate(reducer.next_parent_ordinal + 1),
        );
        try reducer_mod.testing.admitParent(&reducer, &envelope);
    }
    const root = try reducer.rootCandidate();
    try std.testing.expectEqual(@as(u8, 8), root.height);
    try std.testing.expectEqual(@as(u64, 0), root.index);
    try std.testing.expectEqual(topology.NodeKindV1.mixed, root.kind);
    const statement = try span.SpanStatement.fromCanonicalWords(
        &root.statement_words,
    );
    try std.testing.expectEqualDeep(plan.job, statement.job);
    try std.testing.expectError(
        error.FinalRootPromotionUnavailable,
        reducer.promoteFinalRoot(),
    );
}

fn testProgramDescriptor(seed: u8) !program_descriptor.DescriptorV1 {
    var result = program_descriptor.DescriptorV1{
        .sampled_value_count = 100,
        .claimed_sum_count = 42,
        .relation_challenge_count = 25,
        .transcript_claimed_sum_count = 42,
        .public_wire_boundary_count = 0,
        .base_profile_sha256 = shaIdentity(seed),
        .base_geometry_sha256 = shaIdentity(seed +% 1),
        .extension_geometry_sha256 = shaIdentity(seed +% 2),
        .selected_lookup_compiler_sha256 = shaIdentity(seed +% 3),
        .protocol_profile_sha256 = shaIdentity(seed +% 4),
        .graph_sha256 = shaIdentity(seed +% 5),
        .reference_sha256 = shaIdentity(seed +% 6),
        .schedule_sha256 = shaIdentity(seed +% 7),
        .air_program_identity = shaIdentity(seed +% 8),
        .verifier_program_authority = shaIdentity(seed +% 9),
        .preprocessed_commitment_root = digest(seed +% 10),
        .proof_capture_sha256 = shaIdentity(seed +% 11),
        .capture_identity = shaIdentity(seed +% 12),
        .instance_sha256 = undefined,
        .descriptor_sha256 = undefined,
    };
    program_descriptor.testing.reseal(&result);
    try result.validate();
    return result;
}

fn freshLeafDescriptor(
    metadata: recursion.segment_leaf_local_authority_v3.MetadataV3,
    seed: u8,
) !ethereum_leaf.DescriptorV1 {
    var source = source_wire.Source{
        .journal_record_sha256 = shaIdentity(seed +% 1),
        .metadata = metadata,
    };
    return ethereum_leaf.initFromFreshVerifier(.{
        .program = try testProgramDescriptor(seed +% 2),
        .source = &source,
        .verified_link = try verifiedLinkForMetadata(&metadata),
        .proof_artifact_byte_count = 9_141_337,
        .proof_artifact_sha256 = shaIdentity(seed +% 3),
        .proof_root_sha256 = shaIdentity(seed +% 4),
        .transcript_state_sha256 = shaIdentity(seed +% 5),
    });
}

const ProviderFixture = struct {
    calls: [33]poseidon_air.Call,
    provider_plan: native_provider.ProviderShardPlanV1,
    residency_request: prover_engine.pcs.residency_shard_plan.Request,
    residency_plan: prover_engine.pcs.residency_shard_plan.Plan,
    relation: native_provider.PoseidonRelationContextV1,
    core_claim: native_provider.CorePoseidonClaimV1,
    claims: [3]native_provider.ProviderShardClaimV1,
    artifacts: [3]incremental_provider.ShardArtifactV1,
    entry_continuation_root: u32,
    exit_continuation_root: u32,
    core_proof_artifact_sha256: [32]u8,
    core_proof_capture_sha256: [32]u8,
    core_capture_identity: [32]u8,

    fn init(
        metadata: recursion.segment_leaf_local_authority_v3.MetadataV3,
        descriptor: ethereum_leaf.DescriptorV1,
        seed: u32,
    ) !ProviderFixture {
        var calls: [33]poseidon_air.Call = undefined;
        for (&calls, 0..) |*call, index| {
            call.* = poseidon_air.Call.narrowWithOutput(
                @intCast(index + 1),
                @intCast(index + 2),
                @intCast(index + 3),
            );
        }
        const residency_request =
            prover_engine.pcs.residency_shard_plan.Request{
                .logical_row_count = calls.len,
                .column_count = native_provider.main_column_count,
                .min_shard_log_size = 4,
                .max_shard_log_size = 4,
                .log_blowup_factor = 1,
                .retention_policy = .never,
                .host_byte_budget = 1 << 30,
                .reserved_host_bytes = 0,
                .requested_parallel_shards = 2,
            };
        var provider_plan = try native_provider.ProviderShardPlanV1.create(
            std.testing.allocator,
            shaIdentity(@truncate(seed)),
            &calls,
            residency_request,
        );
        errdefer provider_plan.deinit(std.testing.allocator);
        if (provider_plan.shard_count != 3 or
            provider_plan.residency.result.shard_log_size != 4)
        {
            return error.InvalidTestProviderPlan;
        }
        const residency_plan = try prover_engine.pcs.residency_shard_plan
            .create(residency_request);
        const relation = try native_provider.PoseidonRelationContextV1
            .canonical(
            provider_plan.session,
            QM31.fromU32Unchecked(11, 12, 13, 14),
            QM31.fromU32Unchecked(21, 22, 23, 24),
        );
        var claims: [3]native_provider.ProviderShardClaimV1 = undefined;
        var provider_total = QM31.zero();
        for (&claims, provider_plan.shards, 0..) |*claim, shard, index| {
            claim.* = .{
                .plan_identity = provider_plan.identity,
                .descriptor_identity = shard.identity,
                .shard_index = @intCast(index),
                .relation_context_identity = relation.identity,
                .claims = .{ .sums = .{
                    QM31.fromU32Unchecked(@intCast(index + 1), 0, 0, 0),
                    QM31.zero(),
                } },
            };
            provider_total = provider_total.add(claim.claims.total());
        }
        const core_claim = native_provider.CorePoseidonClaimV1{
            .plan_identity = provider_plan.identity,
            .relation_context_identity = relation.identity,
            .claim = provider_total.neg(),
        };
        var artifacts: [3]incremental_provider.ShardArtifactV1 = undefined;
        for (&artifacts, claims, 0..) |*artifact, claim, index| {
            artifact.* = try incremental_provider.ShardArtifactV1
                .initFromFreshVerifier(.{
                .ordinal = @intCast(index),
                .proof_artifact_sha256 = shaIdentity(@truncate(seed + 10 + index)),
                .proof_root_sha256 = shaIdentity(@truncate(seed + 20 + index)),
                .proof_capture_sha256 = shaIdentity(@truncate(seed + 30 + index)),
                .capture_identity = shaIdentity(@truncate(seed + 40 + index)),
                .air_program_identity = shaIdentity(@truncate(seed + 50 + index)),
                .verifier_program_authority = shaIdentity(@truncate(seed + 60 + index)),
                .protocol_profile_sha256 = shaIdentity(@truncate(seed + 70 + index)),
                .preprocessed_commitment_root = digest(seed + 80 + @as(u32, @intCast(index))),
            }, claim);
        }
        return .{
            .calls = calls,
            .provider_plan = provider_plan,
            .residency_request = residency_request,
            .residency_plan = residency_plan,
            .relation = relation,
            .core_claim = core_claim,
            .claims = claims,
            .artifacts = artifacts,
            .entry_continuation_root = metadata.entry.continuation_root,
            .exit_continuation_root = metadata.exit.continuation_root,
            .core_proof_artifact_sha256 = descriptor.proof_artifact_sha256,
            .core_proof_capture_sha256 = descriptor.program.proof_capture_sha256,
            .core_capture_identity = descriptor.program.capture_identity,
        };
    }

    fn deinit(self: *ProviderFixture) void {
        self.provider_plan.deinit(std.testing.allocator);
    }

    fn input(self: *const ProviderFixture) incremental_provider.CompilerInputV1 {
        return .{
            .entry_continuation_root = self.entry_continuation_root,
            .exit_continuation_root = self.exit_continuation_root,
            .core_proof_artifact_sha256 = self.core_proof_artifact_sha256,
            .core_proof_capture_sha256 = self.core_proof_capture_sha256,
            .core_capture_identity = self.core_capture_identity,
            .residency_request = self.residency_request,
            .residency_plan = self.residency_plan,
            .provider_plan = &self.provider_plan,
            .calls = &self.calls,
            .relation = self.relation,
            .core_claim = self.core_claim,
            .shard_claims = &self.claims,
            .shard_artifacts = &self.artifacts,
        };
    }
};

fn verifiedLinkForMetadata(
    metadata: *const recursion.segment_leaf_local_authority_v3.MetadataV3,
) !recursion.segment_leaf_local_verified_link_v3.VerifiedLinkV3 {
    const link_mod = recursion.segment_leaf_local_verified_link_v3;
    var result = link_mod.VerifiedLinkV3{
        .global_metadata_id = try metadata.identity(),
        .local_authority_id = digest(12_001),
        .local_wire_id = digest(12_011),
        .local_receipt_id = digest(12_021),
        .segment_index = metadata.segment_index,
        .segment_count = metadata.segment_count,
        .global_cycle_start = metadata.global_cycle_start,
        .global_cycle_end = metadata.global_cycle_end,
        .local_cycle_count = metadata.local_cycle_count,
        .entry_continuation_root = metadata.entry.continuation_root,
        .exit_continuation_root = metadata.exit.continuation_root,
        .identity = undefined,
    };
    var words: [link_mod.IDENTITY_WORDS]u32 = undefined;
    var at: usize = 0;
    putScalar(&words, &at, result.format_version);
    putScalar(&words, &at, result.schema_version);
    inline for (.{
        result.global_metadata_id,
        result.local_authority_id,
        result.local_wire_id,
        result.local_receipt_id,
    }) |value| for (value) |word| putScalar(&words, &at, word);
    putU32(&words, &at, result.segment_index);
    putU32(&words, &at, result.segment_count);
    putU64(&words, &at, result.global_cycle_start);
    putU64(&words, &at, result.global_cycle_end);
    putU32(&words, &at, result.local_cycle_count);
    putScalar(&words, &at, result.entry_continuation_root);
    putScalar(&words, &at, result.exit_continuation_root);
    std.debug.assert(at == words.len);
    result.identity = recursion.poseidon2_channel.hashCanonicalU32s(
        &words,
        link_mod.IDENTITY_DOMAIN,
    );
    try result.validateHeader();
    return result;
}

fn realRecord(
    plan: *const topology.TopologyPlanV1,
    index: u32,
) !reducer_mod.NodeRecordV1 {
    const metadata = try metadataFor(plan.job, index);
    const result = reducer_mod.NodeRecordV1{
        .height = 0,
        .kind = .real,
        .index = index,
        .statement_words = metadata.base_statement_words,
        .statement_sha256 = statement_plan.statementSha256(
            &metadata.base_statement_words,
        ),
        .descriptor_sha256 = shaIdentity(@truncate(index + 1)),
        .subtree_sha256 = shaIdentity(@truncate(index + 2)),
        .air_program_identity = shaIdentity(@truncate(index + 3)),
        .verifier_program_authority = shaIdentity(@truncate(index + 4)),
        .preprocessed_commitment_root = digest(index + 100),
        .proof_capture_sha256 = shaIdentity(@truncate(index + 5)),
        .capture_identity = shaIdentity(@truncate(index + 6)),
    };
    try result.validateAgainstPlan(plan);
    return result;
}

fn testJob(segment_count: u32) !span.JobContext {
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

fn metadataFor(
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

fn putScalar(words: []u32, at: *usize, value: u32) void {
    words[at.*] = value;
    at.* += 1;
}

fn putU32(words: []u32, at: *usize, value: u32) void {
    putScalar(words, at, value & 0xffff);
    putScalar(words, at, value >> 16);
}

fn putU64(words: []u32, at: *usize, value: u64) void {
    inline for (0..4) |limb|
        putScalar(words, at, @intCast((value >> (16 * limb)) & 0xffff));
}

fn digest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn shaIdentity(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

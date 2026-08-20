//! Non-proof custody and layout gate for the binary V3 composition lane.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod = @import("recursive_binary_v3_verified_artifact.zig");
const bridge_mod = @import("recursive_binary_v3_composition_bridge.zig");
const cohort_mod = @import("recursive_binary_outer_cohort.zig");
const driver = @import("recursive_binary_outer.zig");
const publication_mod = @import("recursive_binary_verified_publication.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const CirclePointQM31 = stwo_core.circle.CirclePointQM31;
const recursion = frontend.recursion;
const fixed_wire = recursion.fixed_wire;
const protocol = recursion.protocol;
const fixture_mod = frontend.testing.binary_pair_outer_fixture;
const air = recursion.air;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const capture_layout = composition_v3.capture_layout_v3;
const graph_recorder = composition_v3.segment_recorder_v3.graph_recorder;
const universal = air.universal_challenges;
const shared_provider = air.universal_shared_provider;
const segment_manifest_mod = air.segment_outer_adapter_manifest_v2;
const segment_catalog = air.segment_outer_typed_catalog_v2;
const segment_boundary_air = recursion.segment_leaf_outer_air_v2;
const segment_boundary = recursion.segment_leaf_outer_authority_v2;
const segment_provider =
    recursion.segment_publication_input_provider_authority_v2;
const range_bridge = air.range_check_8_8_bridge;
const roster = air.universal_roster;

const FRI_LOG_BLOWUP: u32 = 1;
const COMPOSITION_COLUMN_COUNT: usize = 8;
const COMPOSITION_LOG_SPLIT: u32 = stwo_core.verifier_types.COMPOSITION_LOG_SPLIT;

const CHILD_DIMENSIONS = fixed_wire.Dimensions{
    .commitment_count = 4,
    .claimed_sum_count = 36,
    .sampled_value_count = 19,
    .queried_value_count = 11 * protocol.FRI_QUERY_COUNT,
    .trace_path_count = 4 * protocol.FRI_QUERY_COUNT,
    .fri_layer_count = 1,
    .query_count = protocol.FRI_QUERY_COUNT,
    .maximum_fold_width = 16,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 5,
};

const STATEMENT_DIMENSIONS = fixed_wire.Dimensions{
    .commitment_count = 4,
    .claimed_sum_count = 36,
    .sampled_value_count = 4,
    .queried_value_count = 4 * 3,
    .trace_path_count = 4 * 3,
    .fri_layer_count = 5,
    .query_count = 3,
    .maximum_fold_width = 2,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 6,
};

const Cohort = cohort_mod.Cohort(CHILD_DIMENSIONS, STATEMENT_DIMENSIONS);
const Bridge = bridge_mod.Bridge(Cohort);
const Kernel = driver.EngineKernel(Cohort);

comptime {
    if (!std.meta.eql(CHILD_DIMENSIONS, fixture_mod.CHILD_DIMENSIONS) or
        !std.meta.eql(STATEMENT_DIMENSIONS, fixture_mod.STATEMENT_DIMENSIONS))
    {
        @compileError("binary V3 bridge fixture dimensions drifted");
    }
}

test "binary V3 bridge admits one verifier cohort into exact 36 plus zero-tail ABI" {
    const allocator = std.testing.allocator;
    var fixture = try fixture_mod.Fixture.init(allocator);
    defer fixture.deinit();
    const inputs = Cohort.AuthorityInputs{
        .non_fri = try fixture.nonFriInputs(),
        .fri_source = fixture.friSource(),
    };
    var cohort = try Cohort.init(allocator, inputs);
    defer cohort.deinit();

    var channel = driver.Engine.Channel{};
    const relations = try universal.UniversalRelations.draw(allocator, &channel);
    const provider_relations =
        try shared_provider.SharedProviderRelations.init(&relations);
    const generated = try cohort.rebuildGeneratedInteractions(
        &relations,
        &provider_relations,
    );
    var claims = try cohort.claimVector(&generated);
    try claims.validate(cohort.manifest());
    const audited = try cohort.auditGlobalClosureV2(
        &generated,
        &claims,
        &relations,
        &provider_relations,
    );

    const authority = try cohort.publicationAuthority();
    const prepared_pair = try publication_mod.preparePairAuthority(
        authority.authority,
        authority.root_pin,
    );
    const proof_identity = try publication_mod.CanonicalProofIdentityV1.fromBytes(
        "binary-v3-non-proof-verifier-transaction-fixture",
    );
    const evidence = try publication_mod.SuccessfulVerifierEvidenceV1
        .initFromSuccessfulVerifierIdentity(
        proof_identity,
        authority.authority.context.execution_statement_id,
        authority.authority.context.aggregator_vk_id,
        authority.cohort_authority_sha_id,
    );
    var publication: publication_mod.VerifiedBinaryClosurePublicationV2 =
        undefined;
    try publication_mod.publishInto(
        &publication,
        &evidence,
        &prepared_pair,
        authority.authority,
        authority.record,
        authority.root_pin,
        &authority.cohort_authority_sha_id,
        &audited.closure,
    );

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var capture = try syntheticCapture(arena.allocator(), cohort.manifest(), 101);
    const segment_manifest = try fixtureSegmentManifest();
    var segment_capture = try syntheticCapture(
        arena.allocator(),
        &segment_manifest,
        701,
    );
    const program_roster = try composition_v3.ProgramRosterV3.seal(.{
        .universal = cohort.manifest(),
        .segment = &segment_manifest,
    }, .{
        .segment_leaf = nativeDigest(1_001),
        .binary_node = nativeDigest(1_101),
        .empty_leaf = nativeDigest(1_201),
    });
    const descriptor = program_roster.forKind(.binary_node).*;
    var artifact = try stageArtifact(
        &cohort,
        &capture,
        &publication,
        descriptor,
        &claims.values,
        &relations,
        &generated.fri.claims.poseidon2_partials,
    );

    var bridge = try Bridge.init(
        allocator,
        &cohort,
        &capture,
        &publication,
        &artifact,
        descriptor,
    );
    defer bridge.deinit();
    try bridge.validateAgainst(&cohort, &capture, &publication, &artifact);
    try std.testing.expectEqual(@as(u8, 36), bridge.layout.component_count);
    try std.testing.expectEqualSlices(
        QM31,
        &claims.values,
        bridge.claim_inputs[0..artifact_mod.CLAIM_COUNT],
    );
    for (bridge.claim_inputs[36..39]) |value|
        try std.testing.expect(value.eql(QM31.zero()));
    try std.testing.expectEqualSlices(
        QM31,
        &artifact.poseidon2_partials,
        bridge.claim_inputs[39..41],
    );
    try std.testing.expectEqualDeep(relations, bridge.relations);
    try std.testing.expectEqual(
        @as(usize, 0),
        bridge_mod.HEAP_ALLOCATIONS_PER_BEGIN_RECORDER,
    );

    var builder = graph_recorder.Builder.init(allocator);
    defer builder.deinit();
    const graph_input_count = bridge.layout.sampled_value_count +
        composition_v3.COMPOSITION_CLAIM_INPUT_COUNT +
        composition_v3.RELATION_CHALLENGE_COUNT * 2 + 2;
    try builder.reserve(graph_input_count, cohort.manifest().total_constraints);
    const symbolic_samples = try arena.allocator().alloc(
        graph_recorder.Scalar,
        bridge.layout.sampled_value_count,
    );
    var symbolic_claims: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]graph_recorder.Scalar =
        undefined;
    var challenge_draws: [composition_v3.RELATION_CHALLENGE_COUNT][2]graph_recorder.Scalar =
        undefined;
    const concrete_inputs = try arena.allocator().alloc(QM31, graph_input_count);
    var graph_cursor: usize = 0;
    for (symbolic_samples, capture.sampled_values) |*symbolic, concrete| {
        const input = try builder.input();
        symbolic.* = input.value;
        concrete_inputs[graph_cursor] = concrete;
        graph_cursor += 1;
    }
    for (&symbolic_claims, bridge.claim_inputs) |*symbolic, concrete| {
        const input = try builder.input();
        symbolic.* = input.value;
        concrete_inputs[graph_cursor] = concrete;
        graph_cursor += 1;
    }
    for (&challenge_draws, bridge.relations.elements) |*draw, relation| {
        const z = try builder.input();
        const alpha = try builder.input();
        draw.* = .{ z.value, alpha.value };
        concrete_inputs[graph_cursor] = relation.z;
        concrete_inputs[graph_cursor + 1] = relation.alpha;
        graph_cursor += 2;
    }
    const symbolic_composition_randomness = try builder.input();
    concrete_inputs[graph_cursor] = bridge.composition_randomness;
    graph_cursor += 1;
    const symbolic_oods_seed = try builder.input();
    concrete_inputs[graph_cursor] = bridge.oods_seed;
    graph_cursor += 1;
    try std.testing.expectEqual(graph_input_count, graph_cursor);

    try builder.activate();
    const symbolic_challenges = try graph_recorder.ChallengeSet.init(
        challenge_draws,
    );
    const symbolic_oods_point = graph_recorder.pointFromSeed(
        symbolic_oods_seed.value,
    );
    var denominator_cache: graph_recorder.DenominatorCache =
        .{null} ** stwo_core.circle.M31_CIRCLE_LOG_ORDER;
    var program = try bridge.beginRecorder(
        cohort.manifest(),
        &builder,
        symbolic_samples,
        &symbolic_claims,
        &symbolic_challenges,
        symbolic_composition_randomness.value,
        symbolic_oods_point,
        &denominator_cache,
    );
    try std.testing.expectEqual(@as(u8, 0), program.next_row);
    try std.testing.expectEqual(@as(usize, 0), program.constraint_count);
    var components = try cohort.initComponents(
        &generated,
        &relations,
        &provider_relations,
    );
    defer components.deinit();
    const recorded = try program.recordCompleteUniversalCohort(&components);
    try std.testing.expectEqual(@as(u8, 36), recorded.row_count);
    try std.testing.expectEqual(
        cohort.manifest().total_constraints,
        recorded.constraint_count,
    );
    try builder.constrainZero(
        recorded.accumulation.sub(recorded.accumulation),
    );
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    try circuit.validate();
    try std.testing.expectEqual(graph_input_count, circuit.input_count);
    try std.testing.expectEqual(@as(usize, 1), circuit.outputs.len);
    const graph_values = try arena.allocator().alloc(QM31, circuit.nodes.len);
    try circuit.evaluateInto(concrete_inputs, graph_values);

    var segment_layout = try capture_layout.CaptureLayoutV3.initSegment(
        allocator,
        &segment_manifest,
        &segment_capture,
    );
    defer segment_layout.deinit();
    const sample_authority = try capture_layout.SampleInputAuthorityV3.seal(
        &segment_layout,
        &bridge.layout,
    );
    const padded = try allocator.alloc(QM31, sample_authority.max_sample_count);
    defer allocator.free(padded);
    @memset(padded, felt(2_001));
    try bridge.writeSharedSamples(
        &cohort,
        &capture,
        &publication,
        &artifact,
        &segment_layout,
        sample_authority,
        padded,
    );
    try std.testing.expectEqualSlices(
        QM31,
        capture.sampled_values,
        padded[0..capture.sampled_values.len],
    );
    for (padded[capture.sampled_values.len..]) |value|
        try std.testing.expect(value.eql(QM31.zero()));

    var empty_claims = [_]QM31{felt(2_101)} **
        composition_v3.COMPOSITION_CLAIM_INPUT_COUNT;
    try bridge_mod.writeCanonicalEmptyClaimInputs(&empty_claims);
    for (empty_claims) |value|
        try std.testing.expect(value.eql(QM31.zero()));

    // Every rejected mutation precedes the shared destination write.
    @memset(padded, felt(2_201));
    const original_sample = capture.sampled_values[0];
    capture.sampled_values[0] = original_sample.add(QM31.one());
    try std.testing.expectError(
        error.CaptureIdentityMismatch,
        bridge.writeSharedSamples(
            &cohort,
            &capture,
            &publication,
            &artifact,
            &segment_layout,
            sample_authority,
            padded,
        ),
    );
    for (padded) |value| try std.testing.expect(value.eql(felt(2_201)));
    capture.sampled_values[0] = original_sample;

    var descriptor_mutation = descriptor;
    descriptor_mutation.identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidProgramRoster,
        Bridge.init(
            allocator,
            &cohort,
            &capture,
            &publication,
            &artifact,
            descriptor_mutation,
        ),
    );

    bridge.layout.identity[0] ^= 1;
    try std.testing.expectError(
        error.CaptureLayoutIdentityMismatch,
        bridge.beginRecorder(
            cohort.manifest(),
            &builder,
            symbolic_samples,
            &symbolic_claims,
            &symbolic_challenges,
            symbolic_composition_randomness.value,
            symbolic_oods_point,
            &denominator_cache,
        ),
    );
    bridge.layout.identity[0] ^= 1;

    const alias_size = @max(
        @sizeOf(driver.OuterProofCapture),
        @sizeOf(driver.VerifiedBinaryArtifactV3),
    );
    const alias_alignment = @max(
        @alignOf(driver.OuterProofCapture),
        @alignOf(driver.VerifiedBinaryArtifactV3),
    );
    var alias_storage: [alias_size]u8 align(alias_alignment) =
        [_]u8{0x6d} ** alias_size;
    const alias_before = alias_storage;
    const aliased_capture: *driver.OuterProofCapture = @ptrCast(
        @alignCast(&alias_storage),
    );
    const aliased_artifact: *driver.VerifiedBinaryArtifactV3 = @ptrCast(
        @alignCast(&alias_storage),
    );
    var untouched_publication: driver.VerifiedBinaryClosurePublicationV2 =
        undefined;
    @memset(std.mem.asBytes(&untouched_publication), 0x5a);
    const untouched_before = std.mem.asBytes(&untouched_publication)[0..@sizeOf(driver.VerifiedBinaryClosurePublicationV2)].*;
    try std.testing.expectError(
        error.TransactionOutputAlias,
        Kernel.proveAndVerifyV3(
            allocator,
            inputs,
            descriptor,
            aliased_capture,
            &untouched_publication,
            aliased_artifact,
        ),
    );
    try std.testing.expectEqualDeep(alias_before, alias_storage);
    try std.testing.expectEqualSlices(
        u8,
        &untouched_before,
        std.mem.asBytes(&untouched_publication),
    );

    artifact.claimed_sums[0] = artifact.claimed_sums[0].add(QM31.one());
    try std.testing.expectError(
        error.ClaimIdentityMismatch,
        Bridge.init(
            allocator,
            &cohort,
            &capture,
            &publication,
            &artifact,
            descriptor,
        ),
    );
}

fn stageArtifact(
    cohort: *const Cohort,
    capture: *const artifact_mod.OuterProofCapture,
    publication: *const artifact_mod.Publication,
    descriptor: composition_v3.ProgramDescriptorV3,
    claimed_sums: *const [artifact_mod.CLAIM_COUNT]QM31,
    relations: *const universal.UniversalRelations,
    partials: *const [artifact_mod.POSEIDON2_PARTIAL_COUNT]QM31,
) !artifact_mod.VerifiedBinaryArtifactV3 {
    const statement_words = try cohort.recursiveStatementWords();
    var result = artifact_mod.VerifiedBinaryArtifactV3{
        .proof_id = publication.proof_id,
        .publication_id = publication.publication_id,
        .capture_id = artifact_mod.captureIdentity(capture),
        .statement_id = publication.statement_id,
        .verification_key_id = publication.recursive_parent_vk_id,
        .cohort_id = publication.cohort_id,
        .air_program_id = descriptor.air_program_id,
        .cohort_authority_sha_id = publication.cohort_authority_sha_id,
        .manifest_seal = cohort.manifest().seal,
        .program_descriptor_identity = descriptor.identity,
        .statement_words = statement_words.*,
        .claimed_sums = claimed_sums.*,
        .relation_draws = artifact_mod.relationDraws(relations),
        .poseidon2_partials = partials.*,
        .claimed_sums_id = undefined,
        .relation_draws_id = undefined,
        .poseidon2_partials_id = undefined,
        .artifact_id = undefined,
    };
    result.claimed_sums_id = artifact_mod.claimedSumsId(&result);
    result.relation_draws_id = artifact_mod.relationDrawsId(&result);
    result.poseidon2_partials_id = artifact_mod.poseidon2PartialsId(&result);
    result.artifact_id = artifact_mod.artifactId(&result);
    try result.validateAgainst(
        capture,
        publication,
        cohort.manifest(),
        descriptor,
    );
    return result;
}

fn syntheticCapture(
    allocator: std.mem.Allocator,
    manifest: anytype,
    seed: u32,
) !artifact_mod.OuterProofCapture {
    const column_counts = [capture_layout.TREE_COUNT]usize{
        manifest.total_preprocessed_columns,
        manifest.total_main_columns,
        manifest.total_interaction_columns,
        COMPOSITION_COLUMN_COUNT,
    };
    const commitments = try allocator.alloc(
        recursion.engine.Hasher.Hash,
        capture_layout.TREE_COUNT,
    );
    for (commitments, 0..) |*commitment, index|
        commitment.* = nativeDigest(seed + @as(u32, @intCast(10 * index)));

    const points = try allocator.alloc(
        [][]CirclePointQM31,
        capture_layout.TREE_COUNT,
    );
    const logs = try allocator.alloc([]u32, capture_layout.TREE_COUNT);
    var sampled_value_count: usize = 0;
    const composition_log_size = deriveCompositionLogSize(manifest);
    for (column_counts, 0..) |column_count, tree| {
        points[tree] = try allocator.alloc([]CirclePointQM31, column_count);
        logs[tree] = try allocator.alloc(u32, column_count);
        for (points[tree], 0..) |*column_points, column_index| {
            const count = if (tree == capture_layout.INTERACTION_TREE_INDEX)
                interactionSamples(manifest, column_index)
            else
                1;
            column_points.* = try allocator.alloc(CirclePointQM31, count);
            @memset(column_points.*, CirclePointQM31.zero());
            sampled_value_count += count;
            logs[tree][column_index] = if (tree == capture_layout.COMPOSITION_TREE_INDEX)
                composition_log_size - COMPOSITION_LOG_SPLIT +
                    FRI_LOG_BLOWUP
            else
                traceColumnLog(manifest, tree, column_index) + FRI_LOG_BLOWUP;
        }
    }
    const sampled_values = try allocator.alloc(QM31, sampled_value_count);
    for (sampled_values, 0..) |*value, index|
        value.* = felt(seed + 100 + @as(u32, @intCast(index % 10_000)));

    return .{
        .queries = .{
            .raw = try allocator.alloc(usize, 0),
            .unique = try allocator.alloc(usize, 0),
        },
        .commitments = commitments,
        .column_log_sizes = logs,
        .sampled_points = points,
        .sampled_values = sampled_values,
        .queried_values = try allocator.alloc(M31, 0),
        .deep_answers = try allocator.alloc(QM31, 0),
        .trace_paths = try allocator.alloc(
            stwo_core.vcs_lifted.verifier.MerklePathCapture(
                recursion.engine.Hasher,
            ),
            0,
        ),
        .fri = .{ .layers = try allocator.alloc(
            stwo_core.fri.FriLayerQueryCapture(recursion.engine.Hasher),
            0,
        ) },
        .last_layer_coefficients = try allocator.alloc(QM31, 0),
        .proof_of_work = seed,
        .composition_randomness = felt(seed + 17),
        .oods_seed = felt(seed + 19),
        .deep_randomness = felt(seed + 23),
    };
}

fn interactionSamples(manifest: anytype, column: usize) usize {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const start: usize = placement.interaction_offset;
        const end = start + placement.geometry.interaction_columns;
        if (column >= start and column < end) {
            if (row == artifact_mod.POSEIDON2_ROSTER_ROW) return 2;
            return if (column >= end - 4) 2 else 1;
        }
    }
    unreachable;
}

fn traceColumnLog(manifest: anytype, tree: usize, column: usize) u32 {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const range = switch (tree) {
            capture_layout.PREPROCESSED_TREE_INDEX => .{
                placement.preprocessed_offset,
                placement.geometry.preprocessed_columns,
            },
            capture_layout.MAIN_TREE_INDEX => .{
                placement.main_offset,
                placement.geometry.main_columns,
            },
            capture_layout.INTERACTION_TREE_INDEX => .{
                placement.interaction_offset,
                placement.geometry.interaction_columns,
            },
            else => unreachable,
        };
        const start: usize = range[0];
        const end = start + range[1];
        if (column >= start and column < end)
            return placement.geometry.log_size;
    }
    unreachable;
}

fn deriveCompositionLogSize(manifest: anytype) u32 {
    var result: u32 = 0;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const geometry = manifest.placements[row].?.geometry;
        const quotient_blowup = @max(
            @as(u32, 1),
            std.math.log2_int_ceil(u32, geometry.protocol_constraint_degree - 1),
        );
        result = @max(result, geometry.log_size + quotient_blowup);
    }
    return result;
}

fn fixtureSegmentManifest() !segment_manifest_mod.Manifest {
    const logs = fixtureLogSizes();
    const catalog = try segment_catalog.build(logs, boundaryComponents(8));
    return segment_manifest_mod.assemble(&catalog, .{
        .transcript_manifest_id = nativeDigest(11),
        .statement_manifest_id = nativeDigest(29),
        .public_manifest_id = nativeDigest(47),
        .boundary_manifest_id = nativeDigest(71),
        .boundary_authority_sha_id = shaDigest(89),
        .provider_authority_sha_id = segment_provider.sourceAuthorityShaId(),
    });
}

fn fixtureLogSizes() [roster.COMPONENT_COUNT]u32 {
    var result = [_]u32{4} ** roster.COMPONENT_COUNT;
    result[0] = 5;
    result[1] = 6;
    result[5] = 7;
    result[11] = 8;
    result[12] = 5;
    result[13] = 4;
    result[14] = 4;
    result[15] = 6;
    result[16] = 5;
    result[17] = air.vm_public_logup_control_witness_v2.TRACE_LOG_SIZE;
    result[@intFromEnum(roster.Component.poseidon2)] = 11;
    result[@intFromEnum(roster.Component.range_check_8_8)] =
        range_bridge.LOG_SIZE;
    return result;
}

fn boundaryComponents(
    statement_log_size: u8,
) [segment_boundary.COMPONENT_COUNT]segment_boundary.ComponentGeometryV2 {
    return .{
        .{
            .kind = .statement_source,
            .component_tag = segment_boundary.STATEMENT_COMPONENT_TAG,
            .logical_rows = (@as(u32, 1) <<
                @intCast(statement_log_size - 1)) + 1,
            .trace_log_size = statement_log_size,
            .trace_rows = @as(u32, 1) << @intCast(statement_log_size),
            .preprocessed_columns = segment_boundary_air.Statement.PREPROCESSED_COLUMN_COUNT,
            .main_columns = segment_boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = segment_boundary_air.Statement.INTERACTION_COLUMN_COUNT,
            .direct_constraints = segment_boundary_air.Statement.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = segment_boundary_air.Statement.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = segment_boundary_air.Statement
                .REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = segment_boundary_air.Statement.SEMANTIC_DIGEST,
        },
        .{
            .kind = .public_logup_source,
            .component_tag = segment_boundary.PUBLIC_LOGUP_COMPONENT_TAG,
            .logical_rows = segment_boundary.PUBLIC_LOGUP_LOGICAL_ROWS,
            .trace_log_size = segment_boundary.PUBLIC_LOGUP_TRACE_LOG_SIZE,
            .trace_rows = segment_boundary.PUBLIC_LOGUP_TRACE_ROWS,
            .preprocessed_columns = segment_boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT,
            .main_columns = segment_boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = segment_boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT,
            .direct_constraints = segment_boundary_air.PublicLogUp.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = segment_boundary_air.PublicLogUp.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = segment_boundary_air.PublicLogUp
                .REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = segment_boundary_air.PublicLogUp.SEMANTIC_DIGEST,
        },
    };
}

fn felt(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

fn nativeDigest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn shaDigest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

const std = @import("std");
const stwo_core = @import("stwo_core");

const circle = stwo_core.circle;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const subject = @import("canonical_empty_cohort_v3.zig");
const circuit_v3 = @import("recursion_air_composition_circuit_v3.zig");
const recorder = @import("air/composition_graph_recorder.zig");
const universal = @import("air/universal_challenges.zig");
const universal_manifest = @import("air/universal_manifest.zig");
const segment_manifest = @import("air/segment_outer_adapter_manifest_v2.zig");
const span = @import("span_statement.zig");
const temporal = @import("temporal_pair_node.zig");
const protocol = @import("protocol.zig");
const focused = @import("recursion_air_composition_circuit_v3_test.zig");

test "V3.1 active canonical empty records and evaluates all 36 rows" {
    const allocator = std.testing.allocator;
    const log_sizes = focused.fixtureLogSizes();
    const universal_authority = try universal_manifest.build(log_sizes);
    const catalog = try focused.fixtureCatalog(log_sizes);
    const segment_authority = try segment_manifest.assemble(
        &catalog,
        focused.authorityIds(),
    );
    const manifests = circuit_v3.TrustedManifestsV3{
        .universal = &universal_authority,
        .segment = &segment_authority,
    };

    var binary_capture = try focused.CaptureFixture.init(
        allocator,
        &universal_authority,
    );
    defer binary_capture.deinit();
    var binary_layout = try circuit_v3.capture_layout_v3.CaptureLayoutV3.initBinary(
        allocator,
        &universal_authority,
        binary_capture.view(),
    );
    defer binary_layout.deinit();
    var empty_layout =
        try circuit_v3.capture_layout_v3.CanonicalEmptyCaptureLayoutV3.init(
            allocator,
            &universal_authority,
            &binary_layout,
        );
    defer empty_layout.deinit();

    const publication = try canonicalEmptyPublication();
    const program = try subject.sealProgram(
        &universal_authority,
        &binary_layout,
        &empty_layout,
        &publication,
    );
    const relations = universal.UniversalRelations.dummy();
    const claims = try subject.CanonicalEmptyClaimAuthorityV3.seal(
        program,
        &relations,
    );
    const samples = try subject.CanonicalEmptySampleAuthorityV3.seal(
        &empty_layout,
        binary_layout.sampled_value_count,
    );
    var cohort = try subject.CohortV3.create(
        allocator,
        &universal_authority,
        &binary_layout,
        &empty_layout,
        program,
        &relations,
    );
    defer cohort.deinit();

    const air_ids = circuit_v3.AirProgramIdsV3{
        .segment_leaf = digest(101),
        .binary_node = digest(201),
        .empty_leaf = program.air_program_id,
    };
    var segment_capture = try focused.CaptureFixture.init(
        allocator,
        &segment_authority,
    );
    defer segment_capture.deinit();
    const session = try circuit_v3.HeterogeneousSessionV3.createWithCanonicalEmpty(
        allocator,
        manifests,
        air_ids,
        segment_capture.view(),
        binary_capture.view(),
        program,
    );
    errdefer session.deinit();
    try std.testing.expect(session.canonical_empty_layout != null);
    try std.testing.expectEqual(
        circuit_v3.ClaimPolicyV3.canonical_empty_provider,
        session.configuration.program_roster.forKind(.empty_leaf).claim_policy,
    );
    session.deinit();
    const configuration = try circuit_v3.ConfigurationV3.sealWithCanonicalEmpty(
        manifests,
        air_ids,
        binary_layout.sampled_value_count,
        program,
    );

    var graph = try recordGate(
        allocator,
        &empty_layout,
        program,
        cohort,
        configuration,
    );
    defer graph.deinit();
    try std.testing.expectEqual(
        @as(usize, 36),
        graph.result.row_count,
    );
    try std.testing.expectEqual(
        universal_authority.total_constraints,
        graph.result.constraint_count,
    );

    const shared_samples = try allocator.alloc(
        QM31,
        configuration.sampled_value_count,
    );
    defer allocator.free(shared_samples);
    try samples.writeSharedSamples(shared_samples);
    var claim_inputs: [circuit_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31 = undefined;
    try claims.writeClaimInputs(&claim_inputs);
    const statement_words = program.statement_words;
    const witness = circuit_v3.WitnessV3{
        .parent_binary_selector = true,
        .proof_kind = .empty_leaf,
        .statement_words = &statement_words,
        .sampled_values = shared_samples,
        .claim_inputs = &claim_inputs,
        .public_wire_boundary = QM31.zero(),
        .relations = &relations,
        .composition_randomness = secure(701),
        .oods_seed = secure(709),
    };
    const inputs = try allocator.alloc(QM31, graph.circuit.input_count);
    defer allocator.free(inputs);
    const values = try allocator.alloc(QM31, graph.circuit.nodes.len);
    defer allocator.free(values);
    try circuit_v3.writeInputs(
        configuration,
        manifests,
        air_ids,
        witness,
        inputs,
    );
    try graph.circuit.evaluateInto(inputs, values);

    // An all-zero legacy empty claim vector no longer balances the public
    // statement relation when the V3.1 provider descriptor is selected.
    var mutated_claims = claim_inputs;
    mutated_claims[circuit_v3.CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX] = QM31.zero();
    try expectRejectedMutation(
        &graph.circuit,
        configuration,
        manifests,
        air_ids,
        witnessWithClaims(witness, &mutated_claims),
        inputs,
        values,
    );

    mutated_claims = claim_inputs;
    mutated_claims[circuit_v3.CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX] =
        mutated_claims[circuit_v3.CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX].add(secure(1));
    try expectRejectedMutation(
        &graph.circuit,
        configuration,
        manifests,
        air_ids,
        witnessWithClaims(witness, &mutated_claims),
        inputs,
        values,
    );

    var mutated_statement = statement_words;
    mutated_statement[37] = mutated_statement[37].add(M31.one());
    var statement_witness = witness;
    statement_witness.statement_words = &mutated_statement;
    try expectRejectedMutation(
        &graph.circuit,
        configuration,
        manifests,
        air_ids,
        statement_witness,
        inputs,
        values,
    );

    shared_samples[0] = secure(1);
    try expectRejectedMutation(
        &graph.circuit,
        configuration,
        manifests,
        air_ids,
        witness,
        inputs,
        values,
    );
    shared_samples[0] = QM31.zero();

    var mutated_relations = relations;
    const statement_relation = mutated_relations.get(.recursion_statement_word);
    mutated_relations.elements[
        @intFromEnum(
            @import("../air/lang/relation.zig").Domain.recursion_statement_word,
        )
    ].z = statement_relation.z.add(secure(1));
    var relation_witness = witness;
    relation_witness.relations = &mutated_relations;
    try expectRejectedMutation(
        &graph.circuit,
        configuration,
        manifests,
        air_ids,
        relation_witness,
        inputs,
        values,
    );

    var layout_mutation = empty_layout;
    layout_mutation.identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidCanonicalEmptyLayout,
        program.validateAgainst(
            &universal_authority,
            &binary_layout,
            &layout_mutation,
        ),
    );

    var roster_mutation = configuration;
    roster_mutation.program_roster.programs[
        circuit_v3.proofKindIndex(.empty_leaf)
    ].catalog_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidProgramRoster,
        roster_mutation.validateAgainst(manifests, air_ids),
    );
}

const RecordedGate = struct {
    circuit: recorder.Circuit,
    result: circuit_v3.segment_recorder_v3.ProgramResultV3,

    fn deinit(self: *RecordedGate) void {
        self.circuit.deinit();
        self.* = undefined;
    }
};

fn recordGate(
    allocator: std.mem.Allocator,
    empty_layout: *const circuit_v3.capture_layout_v3.CanonicalEmptyCaptureLayoutV3,
    program: circuit_v3.CanonicalEmptyProgramV3,
    cohort: *const subject.CohortV3,
    configuration: circuit_v3.ConfigurationV3,
) !RecordedGate {
    var builder = recorder.Builder.init(allocator);
    errdefer builder.deinit();
    const input_count = try @import("air/composition_circuit.zig").recursionInputCount(
        configuration.graphInputProfile(),
    );
    try builder.reserve(
        input_count,
        cohort.manifest.total_constraints +
            circuit_v3.CANONICAL_EMPTY_CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT +
            circuit_v3.STATEMENT_WORD_COUNT + configuration.sampled_value_count + 9,
    );
    const base_inputs = try allocator.alloc(recorder.Scalar, input_count);
    defer allocator.free(base_inputs);
    for (base_inputs) |*value| value.* = (try builder.input()).value;
    try builder.activate();

    var cursor: usize = 0;
    const parent_selector = base_inputs[cursor];
    cursor += 1;
    var selectors: [circuit_v3.PROGRAM_KIND_COUNT]recorder.Scalar = undefined;
    @memcpy(&selectors, base_inputs[cursor..][0..selectors.len]);
    cursor += selectors.len;
    var statement_words: [circuit_v3.STATEMENT_WORD_COUNT]recorder.Scalar = undefined;
    @memcpy(&statement_words, base_inputs[cursor..][0..statement_words.len]);
    cursor += statement_words.len;
    const sampled = try allocator.alloc(
        recorder.Scalar,
        configuration.sampled_value_count,
    );
    defer allocator.free(sampled);
    for (sampled) |*value| value.* = takeSecureInput(base_inputs, &cursor);
    var claim_inputs: [circuit_v3.COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar =
        undefined;
    for (&claim_inputs) |*value| value.* = takeSecureInput(base_inputs, &cursor);
    const public_wire_boundary = takeSecureInput(base_inputs, &cursor);
    var challenge_draws: [circuit_v3.RELATION_CHALLENGE_COUNT][2]recorder.Scalar =
        undefined;
    for (&challenge_draws) |*draw| {
        draw[0] = takeSecureInput(base_inputs, &cursor);
        draw[1] = takeSecureInput(base_inputs, &cursor);
    }
    const challenges = try recorder.ChallengeSet.init(challenge_draws);
    const composition_randomness = takeSecureInput(base_inputs, &cursor);
    const oods_seed = takeSecureInput(base_inputs, &cursor);
    if (cursor != input_count) return error.InvalidWitnessShape;

    try builder.constrainZero(parent_selector.sub(recorder.Scalar.one()));
    try builder.constrainZero(
        selectors[circuit_v3.proofKindIndex(.segment_leaf)],
    );
    try builder.constrainZero(
        selectors[circuit_v3.proofKindIndex(.binary_node)],
    );
    try builder.constrainZero(
        selectors[circuit_v3.proofKindIndex(.empty_leaf)].sub(
            recorder.Scalar.one(),
        ),
    );
    try builder.constrainZero(public_wire_boundary);
    _ = try circuit_v3.recordClaimPolicyConstraintsForPolicy(
        &builder,
        &selectors,
        &claim_inputs,
        .canonical_empty_provider,
    );
    _ = try circuit_v3.recordCanonicalEmptyProviderConstraints(
        &builder,
        selectors[circuit_v3.proofKindIndex(.empty_leaf)],
        &statement_words,
        sampled,
        &claim_inputs,
        &challenges,
        program,
    );

    var denominator_cache: recorder.DenominatorCache =
        .{null} ** circle.M31_CIRCLE_LOG_ORDER;
    const oods_point = recorder.pointFromSeed(oods_seed);
    var program_recorder =
        try circuit_v3.segment_recorder_v3.EmptyProgramRecorderV3.initCanonicalEmpty(
            &builder,
            &cohort.manifest,
            empty_layout,
            sampled[0..empty_layout.internal_sample_count],
            &claim_inputs,
            &challenges,
            composition_randomness,
            oods_point,
            &denominator_cache,
        );
    const result = try cohort.record(&program_recorder);
    const sampled_composition = try circuit_v3.reconstructSplitCompositionForLayout(
        &empty_layout.geometry,
        sampled[0..empty_layout.internal_sample_count],
        oods_point,
    );
    try builder.constrainZero(sampled_composition.sub(result.accumulation));
    try builder.check();
    builder.deactivate();
    const recorded = try builder.finish();
    builder.deinit();
    return .{ .circuit = recorded, .result = result };
}

fn expectRejectedMutation(
    graph: *const recorder.Circuit,
    configuration: circuit_v3.ConfigurationV3,
    manifests: circuit_v3.TrustedManifestsV3,
    air_ids: circuit_v3.AirProgramIdsV3,
    witness: circuit_v3.WitnessV3,
    inputs: []QM31,
    values: []QM31,
) !void {
    try circuit_v3.writeInputs(
        configuration,
        manifests,
        air_ids,
        witness,
        inputs,
    );
    try std.testing.expectError(
        error.UnsatisfiedCircuit,
        graph.evaluateInto(inputs, values),
    );
}

fn witnessWithClaims(
    witness: circuit_v3.WitnessV3,
    claims: *const [circuit_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31,
) circuit_v3.WitnessV3 {
    var result = witness;
    result.claim_inputs = claims;
    return result;
}

fn takeSecureInput(
    inputs: []const recorder.Scalar,
    cursor: *usize,
) recorder.Scalar {
    var words: [4]recorder.Scalar = undefined;
    @memcpy(&words, inputs[cursor.*..][0..4]);
    cursor.* += 4;
    return recorder.fromPartialEvals(words);
}

fn canonicalEmptyPublication() !temporal.VerifiedChildV2 {
    const initial = try span.MachineState.init(
        0,
        [_]u32{0} ** 32,
        digest(11),
        digest(21),
    );
    const final = try span.MachineState.init(
        16,
        [_]u32{0} ** 32,
        digest(31),
        digest(41),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            digest(51),
            initial,
            final,
            digest(61),
            digest(71),
            32,
        ),
        3,
    );
    const statement = try span.SpanStatement.emptyLeaf(job, 3);
    const words = try statement.canonicalWords();
    const zero = [_]u32{0} ** 8;
    return .{
        .position = try temporal.positionForNextParent(statement),
        .kind = .empty_leaf,
        .scope = .protocol_padding,
        .proof_present = false,
        .roster_count = 0,
        .session_id = digest(81),
        .job_id = try temporal.jobId(&words),
        .recursive_parent_vk_id = digest(91),
        .verification_key_id = zero,
        .air_program_id = zero,
        .manifest_id = zero,
        .profile_id = zero,
        .statement_words = words,
        .proof_id = zero,
        .transcript_id = zero,
        .capture_id = zero,
        .verifier_receipt_id = zero,
        .claimed_sums_id = zero,
        .relation_replay_id = zero,
        .auxiliary_claim_seal_id = zero,
        .closure_receipt_id = zero,
        .lineage_id = zero,
        .closure_value = .{ 0, 0, 0, 0 },
    };
}

fn digest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn secure(seed: u32) QM31 {
    return QM31.fromU32Unchecked(seed, seed + 1, seed + 2, seed + 3);
}

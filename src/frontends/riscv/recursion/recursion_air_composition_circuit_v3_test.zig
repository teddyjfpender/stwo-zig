const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const subject = @import("recursion_air_composition_circuit_v3.zig");
const graph_mod = @import("air/composition_circuit.zig");
const recorder = @import("air/composition_graph_recorder.zig");
const control = @import("air/control.zig");
const control_relation = @import("air/control_relation.zig");
const direct = @import("air/direct_constraint_program.zig");
const universal = @import("air/universal_challenges.zig");
const universal_adapter_manifest = @import("air/universal_adapter_manifest.zig");
const segment_manifest = @import("air/segment_outer_adapter_manifest_v2.zig");
const catalog_mod = @import("air/segment_outer_typed_catalog_v2.zig");
const universal_manifest = @import("air/universal_manifest.zig");
const universal_roster = @import("air/universal_roster.zig");
const row17_witness_v2 = @import("air/vm_public_logup_control_witness_v2.zig");
const boundary_air = @import("segment_leaf_outer_air_v2.zig");
const boundary_manifest = @import("segment_leaf_outer_authority_v2.zig");
const provider_authority = @import("segment_publication_input_provider_authority_v2.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const segment_boundary_components =
    @import("air/segment_boundary_components_v2.zig");
const segment_provider_component =
    @import("air/segment_publication_input_provider_component_v2.zig");
const segment_core_components = @import("segment_core_outer_components_v2.zig");
const segment_public_components =
    @import("segment_public_outer_components_v2.zig");
const segment_range_authority = @import("segment_range_authority_v2.zig");
const segment_statement_components =
    @import("segment_statement_outer_components_v2.zig");
const segment_transcript_components =
    @import("segment_transcript_outer_components_v2.zig");
const binary_transcript_components =
    @import("binary_transcript_outer_source.zig");
const binary_statement_components =
    @import("outer_parent_statement_air_source.zig");
const binary_inactive_components =
    @import("binary_inactive_outer_source.zig");
const binary_fri_components = @import("binary_fri_outer_bundle.zig");
const capture_layout = subject.capture_layout_v3;
const segment_recorder = subject.segment_recorder_v3;

const FRI_LOG_BLOWUP: u32 = 1;
const COMPOSITION_COLUMN_COUNT: usize = 8;

const test_support = @import("recursion_air_composition_circuit_v3_test_support.zig");
const claimsOfLength = test_support.claimsOfLength;
const felt = test_support.felt;
const airProgramId = test_support.airProgramId;
pub const fixtureLogSizes = test_support.fixtureLogSizes;
pub const fixtureCatalog = test_support.fixtureCatalog;
const boundaryComponents = test_support.boundaryComponents;
pub const authorityIds = test_support.authorityIds;
const nativeDigest = test_support.nativeDigest;
const shaDigest = test_support.shaDigest;
const UniversalCohortComponents = test_support.UniversalCohortComponents;
const SegmentCohortComponents = test_support.SegmentCohortComponents;
const expectUniversalOrchestrationCompiles = test_support.expectUniversalOrchestrationCompiles;
pub const CaptureFixture = test_support.CaptureFixture;
const interactionSamples = test_support.interactionSamples;
const traceColumnLog = test_support.traceColumnLog;

test "V3 claim ABI is fixed at 39 physical plus two ordered partials" {
    try std.testing.expectEqual(@as(usize, 36), subject.UNIVERSAL_PHYSICAL_CLAIM_COUNT);
    try std.testing.expectEqual(@as(usize, 39), subject.SEGMENT_PHYSICAL_CLAIM_COUNT);
    try std.testing.expectEqual(@as(usize, 39), subject.POSEIDON_AUX_START);
    try std.testing.expectEqual(@as(usize, 41), subject.COMPOSITION_CLAIM_INPUT_COUNT);
    try std.testing.expect(!subject.LEGACY_V2_PROFILE_ACCEPTED);
    try std.testing.expect(!subject.LOSSY_SEGMENT_PROJECTION_AVAILABLE);
    try std.testing.expect(subject.PROOF_KIND_AWARE_INPUT_AUTHORITY_AVAILABLE);
    try std.testing.expect(subject.HETEROGENEOUS_PROGRAM_ROSTER_AVAILABLE);
    try std.testing.expect(subject.CLAIM_POLICY_GRAPH_CONSTRAINTS_AVAILABLE);
    try std.testing.expectEqual(
        @as(usize, 45),
        subject.CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT,
    );
    try std.testing.expect(!subject.HETEROGENEOUS_GRAPH_RECORDER_AVAILABLE);
}

test "child proof-kind selector truth table is explicit and parent-gated" {
    inline for (std.meta.fields(subject.ProofKind)) |field| {
        const kind: subject.ProofKind = @enumFromInt(field.value);
        const inactive = subject.activeProofKindSelectors(false, kind);
        for (inactive) |selector| try std.testing.expectEqual(M31.zero(), selector);

        const active = subject.activeProofKindSelectors(true, kind);
        for (active, 0..) |selector, index| try std.testing.expectEqual(
            M31.fromCanonical(@intFromBool(index == subject.proofKindIndex(kind))),
            selector,
        );
    }
}

test "V3 profile geometry and native AIR program IDs fail closed" {
    var profile = subject.InputProfileV3{ .sampled_value_count = 1_071 };
    try profile.validate();
    profile.claimed_sum_count -= 1;
    try std.testing.expectError(error.InvalidClaimInputProfile, profile.validate());
    profile = .{ .sampled_value_count = 1_071 };
    profile.relation_challenge_count -= 1;
    try std.testing.expectError(error.InvalidClaimInputProfile, profile.validate());

    const valid = subject.AirProgramIdsV3{
        .segment_leaf = airProgramId(1),
        .binary_node = airProgramId(11),
        .empty_leaf = airProgramId(21),
    };
    try valid.validate();
    var mutation = valid;
    mutation.segment_leaf = [_]u32{0} ** mutation.segment_leaf.len;
    try std.testing.expectError(
        error.AirProgramIdentityMismatch,
        mutation.validate(),
    );
    mutation = valid;
    mutation.binary_node[3] = m31.Modulus;
    try std.testing.expectError(
        error.AirProgramIdentityMismatch,
        mutation.validate(),
    );
}

test "V3 program roster and configuration bind both trusted manifests" {
    const log_sizes = fixtureLogSizes();
    const universal_authority = try universal_manifest.build(log_sizes);
    const catalog = try fixtureCatalog(log_sizes);
    const segment_authority = try segment_manifest.assemble(
        &catalog,
        authorityIds(),
    );
    const manifests = subject.TrustedManifestsV3{
        .universal = &universal_authority,
        .segment = &segment_authority,
    };
    const air_ids = subject.AirProgramIdsV3{
        .segment_leaf = airProgramId(101),
        .binary_node = airProgramId(201),
        .empty_leaf = airProgramId(301),
    };
    const leaf_descriptor = try subject.ProgramDescriptorV3.sealSegment(
        &segment_authority,
        air_ids.segment_leaf,
    );
    const configuration = try subject.ConfigurationV3.seal(
        manifests,
        air_ids,
        1_071,
    );
    try configuration.validateAgainst(manifests, air_ids);
    try configuration.validateSelfConsistency();
    try std.testing.expectEqual(
        @as(u32, 41),
        configuration.graphInputProfile().claimed_sum_count,
    );
    try std.testing.expectEqual(
        @as(u8, 39),
        configuration.program_roster.forKind(.segment_leaf).source_claim_count,
    );
    try std.testing.expectEqualDeep(
        leaf_descriptor,
        configuration.program_roster.forKind(.segment_leaf).*,
    );
    try std.testing.expectEqual(
        @as(u8, 36),
        configuration.program_roster.forKind(.binary_node).source_claim_count,
    );
    try std.testing.expectEqual(
        @as(u8, 0),
        configuration.program_roster.forKind(.empty_leaf).source_claim_count,
    );
    try std.testing.expectError(
        error.LegacyV2ProjectionForbidden,
        configuration.requireLegacyV2Projection(),
    );

    var mutation = configuration;
    mutation.identity[0] ^= 1;
    try std.testing.expectError(
        error.ConfigurationIdentityMismatch,
        mutation.validateAgainst(manifests, air_ids),
    );
    mutation = configuration;
    mutation.program_roster.programs[0].source_claim_count -= 1;
    try std.testing.expectError(
        error.InvalidProgramRoster,
        mutation.validateAgainst(manifests, air_ids),
    );
    var wrong_air_ids = air_ids;
    wrong_air_ids.segment_leaf[0] += 1;
    try std.testing.expectError(
        error.ManifestAuthorityMismatch,
        configuration.validateAgainst(manifests, wrong_air_ids),
    );

    var changed_log_sizes = log_sizes;
    changed_log_sizes[0] += 1;
    const changed_universal = try universal_manifest.build(changed_log_sizes);
    const changed_catalog = try fixtureCatalog(changed_log_sizes);
    const changed_segment = try segment_manifest.assemble(
        &changed_catalog,
        authorityIds(),
    );
    try std.testing.expectError(
        error.ManifestAuthorityMismatch,
        configuration.validateAgainst(.{
            .universal = &changed_universal,
            .segment = &segment_authority,
        }, air_ids),
    );
    try std.testing.expectError(
        error.ManifestAuthorityMismatch,
        configuration.validateAgainst(.{
            .universal = &universal_authority,
            .segment = &changed_segment,
        }, air_ids),
    );
}

test "V3 capture layouts retain distinct 39 and 36 row sample authorities" {
    const allocator = std.testing.allocator;
    const log_sizes = fixtureLogSizes();
    const universal_authority = try universal_manifest.build(log_sizes);
    const catalog = try fixtureCatalog(log_sizes);
    const segment_authority = try segment_manifest.assemble(
        &catalog,
        authorityIds(),
    );
    var segment_capture = try CaptureFixture.init(allocator, &segment_authority);
    defer segment_capture.deinit();
    var binary_capture = try CaptureFixture.init(allocator, &universal_authority);
    defer binary_capture.deinit();
    var segment_layout = try capture_layout.CaptureLayoutV3.initSegment(
        allocator,
        &segment_authority,
        segment_capture.view(),
    );
    defer segment_layout.deinit();
    var binary_layout = try capture_layout.CaptureLayoutV3.initBinary(
        allocator,
        &universal_authority,
        binary_capture.view(),
    );
    defer binary_layout.deinit();
    try segment_layout.validateAgainstSegment(&segment_authority);
    try binary_layout.validateAgainstBinary(&universal_authority);
    try std.testing.expectEqual(
        @as(u8, 39),
        segment_layout.component_count,
    );
    try std.testing.expectEqual(
        @as(u8, 36),
        binary_layout.component_count,
    );
    try std.testing.expectEqual(
        segment_capture.sampled_values.len,
        segment_layout.sampled_value_count,
    );
    try std.testing.expectEqual(
        binary_capture.sampled_values.len,
        binary_layout.sampled_value_count,
    );

    const sample_authority = try capture_layout.SampleInputAuthorityV3.seal(
        &segment_layout,
        &binary_layout,
    );
    try sample_authority.validateAgainstLayouts(&segment_layout, &binary_layout);
    const padded = try allocator.alloc(QM31, sample_authority.max_sample_count);
    defer allocator.free(padded);
    segment_capture.sampled_values[0] = felt(701);
    try sample_authority.writePaddedSamples(
        .segment_leaf,
        segment_capture.sampled_values,
        padded,
    );
    try std.testing.expect(padded[0].eql(felt(701)));
    for (padded[segment_capture.sampled_values.len..]) |value|
        try std.testing.expect(value.eql(QM31.zero()));

    binary_capture.sampled_values[0] = felt(709);
    try sample_authority.writePaddedSamples(
        .binary_node,
        binary_capture.sampled_values,
        padded,
    );
    try std.testing.expect(padded[0].eql(felt(709)));
    for (padded[binary_capture.sampled_values.len..]) |value|
        try std.testing.expect(value.eql(QM31.zero()));

    const no_samples = [_]QM31{};
    try sample_authority.writePaddedSamples(.empty_leaf, &no_samples, padded);
    for (padded) |value| try std.testing.expect(value.eql(QM31.zero()));

    @memset(padded, felt(733));
    try std.testing.expectError(
        error.InvalidSampleInputCount,
        sample_authority.writePaddedSamples(
            .segment_leaf,
            segment_capture.sampled_values[0 .. segment_capture.sampled_values.len - 1],
            padded,
        ),
    );
    for (padded) |value| try std.testing.expect(value.eql(felt(733)));

    var layout_mutation = segment_layout;
    layout_mutation.identity[0] ^= 1;
    try std.testing.expectError(
        error.CaptureLayoutIdentityMismatch,
        layout_mutation.validateAgainstSegment(&segment_authority),
    );
}

test "Segment recorder admits only the capture-bound 39-row ordered program" {
    const allocator = std.testing.allocator;
    const log_sizes = fixtureLogSizes();
    const catalog = try fixtureCatalog(log_sizes);
    const manifest = try segment_manifest.assemble(&catalog, authorityIds());
    var capture = try CaptureFixture.init(allocator, &manifest);
    defer capture.deinit();
    var layout = try capture_layout.CaptureLayoutV3.initSegment(
        allocator,
        &manifest,
        capture.view(),
    );
    defer layout.deinit();

    var builder = recorder.Builder.init(allocator);
    defer builder.deinit();
    try builder.reserve(0, 128);
    try builder.activate();

    const samples = try allocator.alloc(
        recorder.Scalar,
        layout.sampled_value_count,
    );
    defer allocator.free(samples);
    @memset(samples, recorder.Scalar.zero());
    const claims = [_]recorder.Scalar{recorder.Scalar.zero()} **
        subject.COMPOSITION_CLAIM_INPUT_COUNT;
    var challenge_draws: [subject.RELATION_CHALLENGE_COUNT][2]recorder.Scalar =
        undefined;
    for (&challenge_draws) |*draw| draw.* = .{
        recorder.Scalar.zero(),
        recorder.Scalar.one(),
    };
    const challenges = try recorder.ChallengeSet.init(challenge_draws);
    var denominator_cache: recorder.DenominatorCache =
        .{null} ** stwo_core.circle.M31_CIRCLE_LOG_ORDER;
    var program = try segment_recorder.SegmentProgramRecorderV3.init(
        &builder,
        &manifest,
        &layout,
        samples,
        &claims,
        &challenges,
        recorder.Scalar.one(),
        recorder.pointFromSeed(recorder.Scalar.zero()),
        &denominator_cache,
    );
    try std.testing.expectEqual(@as(u8, 0), program.next_row);
    try std.testing.expectError(
        error.IncompleteSegmentProgram,
        program.finishProgram(),
    );

    // These calls fail before dereferencing the deliberately absent adapter,
    // while still compiling each exact manifest-parametric recorder body.
    var poseidon: segment_recorder.PoseidonAdapterV2 = undefined;
    try std.testing.expectError(
        error.ComponentOrderMismatch,
        program.recordPoseidonProvider(&poseidon),
    );
    var range: segment_recorder.RangeCheck8x8AdapterV2 = undefined;
    try std.testing.expectError(
        error.ComponentOrderMismatch,
        program.recordRangeCheck8x8Provider(&range),
    );

    const FakeComponent = struct {
        pub const RelationRuntime = control_relation.Runtime;

        log_size: u32,
        placement: segment_manifest.Placement,
        parameters: [control.PROOF_KIND_PARAMETER_COUNT]M31,
        direct: direct.Program,
        relation_plan: control_relation.Plan,
    };
    var wrong_row: FakeComponent = undefined;
    try std.testing.expectError(
        error.ComponentOrderMismatch,
        program.recordTypedComponent(
            .transcript_air,
            &wrong_row,
        ),
    );
    try std.testing.expectEqual(@as(u8, 0), program.next_row);
    try std.testing.expectEqual(@as(usize, 0), program.constraint_count);
    try std.testing.expect(segment_recorder.SEGMENT_39_ROW_ORDER_AUTHORITY_AVAILABLE);
    try std.testing.expect(segment_recorder.GENERIC_TYPED_ROW_RECORDER_AVAILABLE);
    try std.testing.expect(segment_recorder.EXACT_SHARED_PROVIDER_RECORDERS_AVAILABLE);
    try std.testing.expect(!segment_recorder.SHARED_HETEROGENEOUS_SESSION_AVAILABLE);

    // Instantiate the one-call orchestration against the real frontend
    // component types.  An inactive private builder makes the runtime call
    // fail before touching the deliberately absent values; compile-time still
    // checks all 39 field/runtime/provider pairings.
    const CohortComponents = struct {
        noncore: struct {
            transcript: segment_transcript_components.Components,
            statement: segment_statement_components.ComponentsV2,
            public: segment_public_components.Components,
            range: segment_range_authority.AdapterV2,
            boundary: segment_boundary_components.Components,
            verifier_input_provider: segment_provider_component.AdapterForManifest(
                segment_manifest,
            ),
        },
        core: segment_core_components.ComponentsV2,
    };
    var cohort: CohortComponents = undefined;
    builder.deactivate();
    try std.testing.expectError(
        error.CircuitAlreadyFinished,
        program.recordCompleteCohort(&cohort),
    );
}

test "V3 universal orchestration compiles the exact binary and empty 36-row lanes" {
    const allocator = std.testing.allocator;
    const log_sizes = fixtureLogSizes();
    const manifest = try universal_manifest.build(log_sizes);
    var capture = try CaptureFixture.init(allocator, &manifest);
    defer capture.deinit();
    var layout = try capture_layout.CaptureLayoutV3.initBinary(
        allocator,
        &manifest,
        capture.view(),
    );
    defer layout.deinit();

    try expectUniversalOrchestrationCompiles(
        segment_recorder.UniversalProgramRecorderV3,
        allocator,
        &manifest,
        &layout,
    );
    try expectUniversalOrchestrationCompiles(
        segment_recorder.EmptyProgramRecorderV3,
        allocator,
        &manifest,
        &layout,
    );
    try std.testing.expect(
        segment_recorder.UNIVERSAL_36_ROW_ORDER_AUTHORITY_AVAILABLE,
    );
}

test "V3 heterogeneous session derives one max-sized ABI and withholds incomplete graphs" {
    const allocator = std.testing.allocator;
    const log_sizes = fixtureLogSizes();
    const universal_authority = try universal_manifest.build(log_sizes);
    const catalog = try fixtureCatalog(log_sizes);
    const segment_authority = try segment_manifest.assemble(
        &catalog,
        authorityIds(),
    );
    var segment_capture = try CaptureFixture.init(allocator, &segment_authority);
    defer segment_capture.deinit();
    var binary_capture = try CaptureFixture.init(allocator, &universal_authority);
    defer binary_capture.deinit();
    const manifests = subject.TrustedManifestsV3{
        .universal = &universal_authority,
        .segment = &segment_authority,
    };
    const air_ids = subject.AirProgramIdsV3{
        .segment_leaf = airProgramId(401),
        .binary_node = airProgramId(501),
        .empty_leaf = airProgramId(601),
    };

    const session = try subject.HeterogeneousSessionV3.create(
        allocator,
        manifests,
        air_ids,
        segment_capture.view(),
        binary_capture.view(),
    );
    defer session.deinit();
    try std.testing.expectEqual(
        @max(
            segment_capture.sampled_values.len,
            binary_capture.sampled_values.len,
        ),
        session.sampled_values.len,
    );
    try std.testing.expectEqual(
        session.sample_input_authority.max_sample_count,
        session.configuration.sampled_value_count,
    );
    try std.testing.expectError(
        error.IncompleteHeterogeneousProgram,
        session.finish(),
    );
    try std.testing.expect(subject.HETEROGENEOUS_GRAPH_SESSION_SUBSTRATE_AVAILABLE);
    try std.testing.expect(!subject.HETEROGENEOUS_GRAPH_RECORDER_AVAILABLE);
    try std.testing.expect(!subject.CIRCUIT_AUTHORITY_MINT_AVAILABLE);

    // Instantiate the single three-lane orchestration against exact frontend
    // aggregate types. An inactive private builder rejects before any
    // deliberately absent adapter is dereferenced.
    var segment_components: SegmentCohortComponents = undefined;
    var binary_components: UniversalCohortComponents = undefined;
    var empty_components: UniversalCohortComponents = undefined;
    session.builder.deactivate();
    try std.testing.expectError(
        error.InvalidHeterogeneousProgram,
        session.recordPrograms(
            &segment_components,
            &binary_components,
            &empty_components,
        ),
    );
}

test "segment claim writer retains all 39 claims and appends partials" {
    var claims = claimsOfLength(subject.SEGMENT_PHYSICAL_CLAIM_COUNT, 100);
    const partials = [_]QM31{ felt(17), felt(23) };
    claims[subject.POSEIDON_ROSTER_ROW] = partials[0].add(partials[1]);
    var destination = [_]QM31{felt(777)} ** subject.COMPOSITION_CLAIM_INPUT_COUNT;

    try subject.writeClaimInputs(.segment_leaf, &claims, &partials, &destination);
    try subject.validateClaimInputs(.segment_leaf, &destination);
    try std.testing.expectEqualSlices(
        QM31,
        &claims,
        destination[0..subject.SEGMENT_PHYSICAL_CLAIM_COUNT],
    );
    try std.testing.expectEqualSlices(
        QM31,
        &partials,
        destination[subject.POSEIDON_AUX_START..],
    );
}

test "binary claim writer zeroes the three inactive SegmentV2 tail slots" {
    var claims = claimsOfLength(subject.UNIVERSAL_PHYSICAL_CLAIM_COUNT, 200);
    const partials = [_]QM31{ felt(29), felt(31) };
    claims[subject.POSEIDON_ROSTER_ROW] = partials[0].add(partials[1]);
    var destination = [_]QM31{felt(999)} ** subject.COMPOSITION_CLAIM_INPUT_COUNT;

    try subject.writeClaimInputs(.binary_node, &claims, &partials, &destination);
    try subject.validateClaimInputs(.binary_node, &destination);
    try std.testing.expectEqualSlices(
        QM31,
        &claims,
        destination[0..subject.UNIVERSAL_PHYSICAL_CLAIM_COUNT],
    );
    for (destination[subject.UNIVERSAL_PHYSICAL_CLAIM_COUNT..subject.POSEIDON_AUX_START]) |
        value,
    | try std.testing.expect(value.eql(QM31.zero()));
    try std.testing.expectEqualSlices(
        QM31,
        &partials,
        destination[subject.POSEIDON_AUX_START..],
    );

    for (subject.UNIVERSAL_PHYSICAL_CLAIM_COUNT..subject.POSEIDON_AUX_START) |index| {
        var mutation = destination;
        mutation[index] = felt(@intCast(1 + index));
        try std.testing.expectError(
            error.InactiveClaimInputMustBeZero,
            subject.validateClaimInputs(.binary_node, &mutation),
        );
    }
}

test "empty claim writer canonicalizes the complete fixed ABI to zero" {
    const no_claims = [_]QM31{};
    const no_partials = [_]QM31{};
    var destination = [_]QM31{felt(555)} ** subject.COMPOSITION_CLAIM_INPUT_COUNT;

    try subject.writeClaimInputs(
        .empty_leaf,
        &no_claims,
        &no_partials,
        &destination,
    );
    try subject.validateClaimInputs(.empty_leaf, &destination);
    for (destination) |value| try std.testing.expect(value.eql(QM31.zero()));

    for (0..subject.COMPOSITION_CLAIM_INPUT_COUNT) |index| {
        var mutation = destination;
        mutation[index] = felt(@intCast(index + 1));
        try std.testing.expectError(
            error.EmptyClaimInputMustBeZero,
            subject.validateClaimInputs(.empty_leaf, &mutation),
        );
    }
}

test "claim writer rejects malformed inputs before its first destination write" {
    var claims = claimsOfLength(subject.SEGMENT_PHYSICAL_CLAIM_COUNT, 300);
    const good_partials = [_]QM31{ felt(37), felt(41) };
    claims[subject.POSEIDON_ROSTER_ROW] = good_partials[0].add(good_partials[1]);
    const sentinel = [_]QM31{felt(1_337)} ** subject.COMPOSITION_CLAIM_INPUT_COUNT;

    var destination = sentinel;
    const bad_partials = [_]QM31{ good_partials[0], felt(42) };
    try std.testing.expectError(
        error.PoseidonPartialMismatch,
        subject.writeClaimInputs(
            .segment_leaf,
            &claims,
            &bad_partials,
            &destination,
        ),
    );
    try std.testing.expectEqualDeep(sentinel, destination);

    destination = sentinel;
    try std.testing.expectError(
        error.InvalidClaimInputCount,
        subject.writeClaimInputs(
            .segment_leaf,
            claims[0 .. claims.len - 1],
            &good_partials,
            &destination,
        ),
    );
    try std.testing.expectEqualDeep(sentinel, destination);

    destination = sentinel;
    var noncanonical = claims;
    noncanonical[7].c0.a.v = m31.Modulus;
    try std.testing.expectError(
        error.NonCanonicalField,
        subject.writeClaimInputs(
            .segment_leaf,
            &noncanonical,
            &good_partials,
            &destination,
        ),
    );
    try std.testing.expectEqualDeep(sentinel, destination);
}

test "claim writer rejects destination aliasing without mutation" {
    var storage = claimsOfLength(subject.COMPOSITION_CLAIM_INPUT_COUNT, 400);
    const partials = [_]QM31{ felt(43), felt(47) };
    storage[subject.POSEIDON_ROSTER_ROW] = partials[0].add(partials[1]);
    const before = storage;

    try std.testing.expectError(
        error.AliasedInput,
        subject.writeClaimInputs(
            .segment_leaf,
            storage[0..subject.SEGMENT_PHYSICAL_CLAIM_COUNT],
            &partials,
            &storage,
        ),
    );
    try std.testing.expectEqualDeep(before, storage);
}

test "claim content digest binds proof kind and every active or padded slot" {
    var binary_claims = claimsOfLength(subject.UNIVERSAL_PHYSICAL_CLAIM_COUNT, 500);
    const partials = [_]QM31{ felt(53), felt(59) };
    binary_claims[subject.POSEIDON_ROSTER_ROW] = partials[0].add(partials[1]);
    var binary_inputs: [subject.COMPOSITION_CLAIM_INPUT_COUNT]QM31 = undefined;
    try subject.writeClaimInputs(
        .binary_node,
        &binary_claims,
        &partials,
        &binary_inputs,
    );
    const binary_id = try subject.claimInputContentDigest(.binary_node, &binary_inputs);

    var segment_claims = claimsOfLength(subject.SEGMENT_PHYSICAL_CLAIM_COUNT, 500);
    segment_claims[subject.POSEIDON_ROSTER_ROW] = partials[0].add(partials[1]);
    // Match binary in all shared slots; only the three SegmentV2 slots differ.
    @memcpy(
        segment_claims[0..subject.UNIVERSAL_PHYSICAL_CLAIM_COUNT],
        &binary_claims,
    );
    var segment_inputs: [subject.COMPOSITION_CLAIM_INPUT_COUNT]QM31 = undefined;
    try subject.writeClaimInputs(
        .segment_leaf,
        &segment_claims,
        &partials,
        &segment_inputs,
    );
    const segment_id = try subject.claimInputContentDigest(.segment_leaf, &segment_inputs);
    try std.testing.expect(!std.mem.eql(u8, &binary_id, &segment_id));

    var mutation = segment_inputs;
    mutation[38] = mutation[38].add(felt(1));
    const mutation_id = try subject.claimInputContentDigest(.segment_leaf, &mutation);
    try std.testing.expect(!std.mem.eql(u8, &segment_id, &mutation_id));
}

test "validated-profile hot path writes the exact canonical graph input order" {
    const allocator = std.testing.allocator;
    const input_profile = subject.InputProfileV3{ .sampled_value_count = 2 };
    var statement = [_]M31{M31.zero()} ** subject.STATEMENT_WORD_COUNT;
    statement[0] = M31.fromCanonical(71);
    statement[subject.STATEMENT_WORD_COUNT - 1] = M31.fromCanonical(73);
    const sampled = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
    };
    var physical = claimsOfLength(subject.UNIVERSAL_PHYSICAL_CLAIM_COUNT, 600);
    const partials = [_]QM31{ felt(61), felt(67) };
    physical[subject.POSEIDON_ROSTER_ROW] = partials[0].add(partials[1]);
    var claims: [subject.COMPOSITION_CLAIM_INPUT_COUNT]QM31 = undefined;
    try subject.writeClaimInputs(.binary_node, &physical, &partials, &claims);
    const relations = universal.UniversalRelations.dummy();
    const randomness = QM31.fromU32Unchecked(11, 12, 13, 14);
    const oods_seed = QM31.fromU32Unchecked(15, 16, 17, 18);
    const witness = subject.WitnessV3{
        .parent_binary_selector = true,
        .proof_kind = .binary_node,
        .statement_words = &statement,
        .sampled_values = &sampled,
        .claim_inputs = &claims,
        .public_wire_boundary = QM31.zero(),
        .relations = &relations,
        .composition_randomness = randomness,
        .oods_seed = oods_seed,
    };
    const input_count = try graph_mod.recursionInputCount(
        input_profile.graphProfile(),
    );
    const destination = try allocator.alloc(QM31, input_count);
    defer allocator.free(destination);
    try subject.writeInputsFromValidatedProfile(
        input_profile,
        witness,
        destination,
    );

    try std.testing.expect(destination[0].eql(felt(1)));
    try std.testing.expect(destination[1].eql(QM31.zero()));
    try std.testing.expect(destination[2].eql(felt(1)));
    try std.testing.expect(destination[3].eql(QM31.zero()));
    try std.testing.expect(destination[4].eql(QM31.fromBase(statement[0])));
    try std.testing.expect(destination[3 + subject.STATEMENT_WORD_COUNT].eql(
        QM31.fromBase(statement[subject.STATEMENT_WORD_COUNT - 1]),
    ));

    const sample_start = 4 + subject.STATEMENT_WORD_COUNT;
    for (sampled, 0..) |value, item| for (value.toM31Array(), 0..) |word, limb|
        try std.testing.expect(destination[sample_start + 4 * item + limb].eql(
            QM31.fromBase(word),
        ));
    const claim_start = sample_start + 4 * sampled.len;
    for (claims, 0..) |value, item| for (value.toM31Array(), 0..) |word, limb|
        try std.testing.expect(destination[claim_start + 4 * item + limb].eql(
            QM31.fromBase(word),
        ));

    const alias_storage = try allocator.alloc(QM31, input_count);
    defer allocator.free(alias_storage);
    @memset(alias_storage, felt(1_919));
    var aliased_witness = witness;
    aliased_witness.sampled_values = alias_storage[0..2];
    try std.testing.expectError(
        error.AliasedInput,
        subject.writeInputsFromValidatedProfile(
            input_profile,
            aliased_witness,
            alias_storage,
        ),
    );
    for (alias_storage) |value| try std.testing.expect(value.eql(felt(1_919)));
}

test {
    _ = @import("recursion_air_composition_circuit_v3_test_continuation_1.zig");
}

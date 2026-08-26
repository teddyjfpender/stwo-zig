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
const fixtureLogSizes = test_support.fixtureLogSizes;
const fixtureCatalog = test_support.fixtureCatalog;
const boundaryComponents = test_support.boundaryComponents;
const authorityIds = test_support.authorityIds;
const nativeDigest = test_support.nativeDigest;
const shaDigest = test_support.shaDigest;
const UniversalCohortComponents = test_support.UniversalCohortComponents;
const SegmentCohortComponents = test_support.SegmentCohortComponents;
const expectUniversalOrchestrationCompiles = test_support.expectUniversalOrchestrationCompiles;
const CaptureFixture = test_support.CaptureFixture;
const interactionSamples = test_support.interactionSamples;
const traceColumnLog = test_support.traceColumnLog;

test "full input preflight is fail-atomic on noncanonical sampled values" {
    const allocator = std.testing.allocator;
    const input_profile = subject.InputProfileV3{ .sampled_value_count = 1 };
    const statement = [_]M31{M31.zero()} ** subject.STATEMENT_WORD_COUNT;
    var sampled = [_]QM31{QM31.zero()};
    sampled[0].c1.b.v = m31.Modulus;
    const claims = [_]QM31{QM31.zero()} ** subject.COMPOSITION_CLAIM_INPUT_COUNT;
    const relations = universal.UniversalRelations.dummy();
    const witness = subject.WitnessV3{
        .parent_binary_selector = false,
        .proof_kind = .empty_leaf,
        .statement_words = &statement,
        .sampled_values = &sampled,
        .claim_inputs = &claims,
        .public_wire_boundary = QM31.zero(),
        .relations = &relations,
        .composition_randomness = QM31.zero(),
        .oods_seed = QM31.zero(),
    };
    const input_count = try graph_mod.recursionInputCount(
        input_profile.graphProfile(),
    );
    const destination = try allocator.alloc(QM31, input_count);
    defer allocator.free(destination);
    @memset(destination, felt(1_717));
    try std.testing.expectError(
        error.NonCanonicalField,
        subject.writeInputsFromValidatedProfile(
            input_profile,
            witness,
            destination,
        ),
    );
    for (destination) |value| try std.testing.expect(value.eql(felt(1_717)));
}

test "graph enforces binary tail empty vector and Poseidon partial closure" {
    const allocator = std.testing.allocator;
    var builder = recorder.Builder.init(allocator);
    defer builder.deinit();
    try builder.reserve(
        subject.PROGRAM_KIND_COUNT + subject.COMPOSITION_CLAIM_INPUT_COUNT,
        2 * subject.CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT,
    );
    var selectors: [subject.PROGRAM_KIND_COUNT]recorder.Scalar = undefined;
    var claims: [subject.COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar = undefined;
    for (&selectors) |*value| value.* = (try builder.input()).value;
    for (&claims) |*value| value.* = (try builder.input()).value;
    try builder.activate();
    const recorded = try subject.recordClaimPolicyConstraints(
        &builder,
        &selectors,
        &claims,
    );
    try std.testing.expectEqual(
        subject.CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT,
        recorded,
    );
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();

    var concrete = [_]QM31{QM31.zero()} **
        (subject.PROGRAM_KIND_COUNT + subject.COMPOSITION_CLAIM_INPUT_COUNT);
    const claim_start = subject.PROGRAM_KIND_COUNT;
    concrete[claim_start + subject.POSEIDON_AUX_START] = felt(79);
    concrete[claim_start + subject.POSEIDON_AUX_START + 1] = felt(83);
    concrete[claim_start + subject.POSEIDON_ROSTER_ROW] = felt(162);
    const values = try allocator.alloc(QM31, circuit.nodes.len);
    defer allocator.free(values);

    concrete[subject.proofKindIndex(.segment_leaf)] = felt(1);
    try circuit.evaluateInto(&concrete, values);
    concrete[subject.proofKindIndex(.segment_leaf)] = QM31.zero();
    concrete[subject.proofKindIndex(.binary_node)] = felt(1);
    try circuit.evaluateInto(&concrete, values);

    var mutation = concrete;
    mutation[claim_start + 36] = felt(1);
    try std.testing.expectError(
        error.UnsatisfiedCircuit,
        circuit.evaluateInto(&mutation, values),
    );
    mutation = concrete;
    mutation[claim_start + subject.POSEIDON_AUX_START] = felt(80);
    try std.testing.expectError(
        error.UnsatisfiedCircuit,
        circuit.evaluateInto(&mutation, values),
    );

    concrete[subject.proofKindIndex(.binary_node)] = QM31.zero();
    concrete[subject.proofKindIndex(.empty_leaf)] = felt(1);
    @memset(
        concrete[claim_start..][0..subject.COMPOSITION_CLAIM_INPUT_COUNT],
        QM31.zero(),
    );
    try circuit.evaluateInto(&concrete, values);
    mutation = concrete;
    mutation[claim_start + 0] = felt(1);
    try std.testing.expectError(
        error.UnsatisfiedCircuit,
        circuit.evaluateInto(&mutation, values),
    );
    mutation = concrete;
    mutation[claim_start + subject.POSEIDON_AUX_START + 1] = felt(1);
    try std.testing.expectError(
        error.UnsatisfiedCircuit,
        circuit.evaluateInto(&mutation, values),
    );
}

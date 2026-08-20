//! Real 39-row SegmentV2 outer-proof continuation.
//!
//! Native proving, external-ingress verification, prepared-leaf custody, and
//! both 17-row core/non-core behavioral gates remain single-source in
//! `recursive_segment_v2_leaf_outer_proof_test.zig`. This file contributes
//! only the final proof hook, and receives no authority other than that same
//! successfully verified `PreparedNativeV2LeafOuter` pointer.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const integration = @import("stwo_riscv_cpu_integration");

const ingress = @import("recursive_segment_v2_leaf_outer_proof_test.zig");
const outer_proof = @import("recursive_segment_v2_outer_proof_test.zig");
const recording_support = @import("recursive_v3_recording_test_support.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const leaf_outer = integration.recursive_segment_v2_leaf_outer;
const composition_authority =
    integration.recursive_binary_composition_authority;
const binary_cohort_mod = integration.recursive_binary_outer_cohort;
const binary_driver = integration.recursive_binary_outer;
const outer_cohort = integration.recursive_segment_v2_outer_cohort;
const outer_admission_v2 =
    integration.recursive_segment_v2_outer_admission_v2;
const outer_engine = integration.recursive_segment_v2_outer_engine;
const temporal_nonfri = integration.recursive_temporal_nonfri_source_v2;
const cohort_protocol = frontend.recursion.segment_outer_cohort_v2;
const binary_rows = frontend.recursion.binary_fri_outer_source;
const composition_graph = frontend.recursion.air.composition_circuit;
const lowering = frontend.recursion.air.verifier_arithmetic_lowering;
const verifier_schedule = frontend.recursion.air.verifier_schedule;
const shared_provider = frontend.recursion.air.universal_shared_provider;
const universal = frontend.recursion.air.universal_challenges;
const composition_v3 =
    frontend.recursion.recursion_air_composition_circuit_v3;
const binary_fixture = frontend.testing.binary_pair_outer_fixture;

const BinaryCohort = binary_cohort_mod.Cohort(
    binary_fixture.CHILD_DIMENSIONS,
    binary_fixture.STATEMENT_DIMENSIONS,
);

pub fn runGate(allocator: std.mem.Allocator) !void {
    try ingress.runGateWithHook(allocator, ConcreteOuterProofHook);
}

/// Narrow edit loop for V3 recorder/row-18 work. It preserves the real native
/// ingress and independently verified 39-row SegmentV2 proof, but omits the
/// broader replay/mutation assertions in `ConcreteOuterProofHook.run` before
/// finalizing and evaluating the heterogeneous recording.
pub fn runFocusedRecorderGate(allocator: std.mem.Allocator) !void {
    try ingress.runGateWithHook(allocator, FocusedRecorderHook);
}

const FocusedRecorderHook = struct {
    pub fn run(
        allocator: std.mem.Allocator,
        prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    ) !void {
        var verified = try outer_proof.provePreparedNativeLeaf(
            outer_cohort.Cohort,
            allocator,
            prepared,
            prepared,
            outer_engine.ExecutionOptions{ .worker_count = 1 },
        );
        defer verified.capture.deinit(allocator);
        try exerciseFinalizedRecorderRow18(allocator, prepared, &verified);
    }
};

const ConcreteOuterProofHook = struct {
    /// Fast, challenge-independent development loop. Cohort construction
    /// still consumes the successful native verifier capture; the classifier
    /// receives no detached rows or balancing tuples. A red report remains a
    /// hard failure so this runner cannot be mistaken for a proof gate.
    pub fn runTupleClosureDiagnostic(
        allocator: std.mem.Allocator,
        prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    ) !void {
        var cohort = try outer_cohort.Cohort.init(allocator, prepared);
        defer cohort.deinit();
        var report = try cohort.prepareAndDiagnoseRedTupleClosure(allocator);
        defer report.deinit();
        report.print();
        if (report.closure.redDomainCount() != 0 or
            report.closure.unmatched_tuple_count != 0)
        {
            return error.RelationNotClosed;
        }
    }

    pub fn run(
        allocator: std.mem.Allocator,
        prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    ) !void {
        // `Cohort.AuthorityInputs` is this exact pointer type. The proof helper
        // constructs independent prover and verifier cohorts from it; no
        // detached row, claim, audit, provider schedule, or prover receipt is
        // accepted at this boundary.
        var verified = try outer_proof.provePreparedNativeLeaf(
            outer_cohort.Cohort,
            allocator,
            prepared,
            prepared,
            outer_engine.ExecutionOptions{ .worker_count = 1 },
        );
        defer verified.capture.deinit(allocator);

        try verified.receipt.validate();
        try verified.publication.validate();
        try std.testing.expectEqual(
            @as(u8, outer_cohort.COMPONENT_COUNT),
            verified.receipt.roster_count,
        );
        try std.testing.expectEqual(
            @as(usize, 39),
            outer_cohort.COMPONENT_COUNT,
        );
        try std.testing.expectEqual(
            @as(usize, 47),
            cohort_protocol.DOMAIN_COUNT,
        );
        try std.testing.expectEqual(
            @as(usize, 1),
            verified.receipt.worker_count,
        );
        try std.testing.expect(verified.receipt.proof_size_estimate > 0);
        try std.testing.expect(verified.receipt.canonical_proof_bytes > 0);
        try std.testing.expectEqual(
            @as(usize, verified.publication.canonical_proof_byte_count),
            verified.receipt.canonical_proof_bytes,
        );
        try std.testing.expectEqualDeep(
            verified.receipt.canonical_proof_id,
            verified.publication.proof_id,
        );
        try std.testing.expectEqualSlices(
            u8,
            &verified.receipt.canonical_proof_sha256,
            &verified.publication.canonical_proof_sha_id,
        );
        try std.testing.expect(verified.receipt.transcript_draws > 0);
        try std.testing.expect(verified.receipt.preprocessed_columns > 0);
        try std.testing.expect(verified.receipt.main_columns > 0);
        try std.testing.expect(verified.receipt.interaction_columns > 0);
        try std.testing.expect(verified.capture.commitments.len > 0);
        try std.testing.expect(verified.capture.queries.raw.len > 0);
        try std.testing.expect(verified.publication.temporalChildReady());
        try std.testing.expect(!verified.publication.completeParentReady());
        try std.testing.expectEqual(
            @as(u8, 39),
            verified.publication.closure.proved_component_count,
        );
        try std.testing.expectEqual(
            @as(u8, 36),
            verified.publication.closure.universal_roster_count,
        );
        try std.testing.expectEqual(
            @as(u8, 47),
            verified.publication.closure.relation_domain_count,
        );

        // Reconstruct both downstream consumers from this exact successful
        // verifier transaction. A fresh cohort supplies only the trusted
        // manifest address; no prover claim or transcript checkpoint crosses
        // either boundary.
        var replay_cohort = try outer_cohort.Cohort.init(allocator, prepared);
        defer replay_cohort.deinit();
        const manifest = replay_cohort.manifest();

        const replay = try temporal_nonfri.TemporalChildTranscriptReplayV2
            .deriveFromArtifact(
            manifest,
            &verified.publication,
            &verified.recursive_witness,
            &verified.capture,
        );
        try replay.validateAgainstArtifact(
            manifest,
            &verified.publication,
            &verified.recursive_witness,
            &verified.capture,
        );
        try std.testing.expectEqual(@as(u32, 0), replay.pre_core_draw_count);
        try std.testing.expectEqual(@as(u32, 1), replay.final_draw_count);
        try std.testing.expectEqual(
            verified.capture.fri.layers.len,
            replay.fri_round_count,
        );
        try std.testing.expectEqualDeep(
            verified.publication.publication_id,
            replay.publication_id,
        );
        try std.testing.expectEqualDeep(
            verified.recursive_witness.witness_id,
            replay.witness_id,
        );
        try std.testing.expectEqualDeep(
            verified.recursive_witness.transcript_prefix.transcript_prefix_id,
            replay.transcript_prefix_id,
        );
        for (replay.raw_queries, verified.capture.queries.raw) |actual, expected|
            try std.testing.expectEqual(expected, actual);

        var mutated_witness = verified.recursive_witness;
        mutated_witness.transcript_prefix.noncore_authority_sha_id[0] ^= 1;
        try std.testing.expectError(
            error.TranscriptPrefixIdentityMismatch,
            temporal_nonfri.TemporalChildTranscriptReplayV2.deriveFromArtifact(
                manifest,
                &verified.publication,
                &mutated_witness,
                &verified.capture,
            ),
        );
        var mutated_replay = replay;
        mutated_replay.final_draw_count +%= 1;
        try std.testing.expectError(
            error.ChildTranscriptMismatch,
            mutated_replay.validateAgainstArtifact(
                manifest,
                &verified.publication,
                &verified.recursive_witness,
                &verified.capture,
            ),
        );

        const composition_profile =
            try composition_authority.SegmentV2CompositionProfileV1.seal(
                manifest,
                verified.publication.air_program_id,
            );
        const descriptor = try composition_v3.ProgramDescriptorV3.sealSegment(
            manifest,
            verified.publication.air_program_id,
        );
        var recorder_bridge =
            try composition_authority.SegmentV2RecorderBridgeV3.init(
                allocator,
                composition_profile,
                descriptor,
                manifest,
                &verified.capture,
                &verified.publication,
                &verified.recursive_witness,
            );
        defer recorder_bridge.deinit();
        try recorder_bridge.validateAgainst(
            allocator,
            manifest,
            &verified.capture,
            &verified.publication,
            &verified.recursive_witness,
        );
        const recorder_witness = try recorder_bridge.concreteWitness(
            allocator,
            manifest,
            &verified.capture,
            &verified.publication,
            &verified.recursive_witness,
        );
        try std.testing.expectEqual(
            composition_v3.ProofKind.segment_leaf,
            recorder_witness.proof_kind,
        );
        try std.testing.expectEqual(
            verified.capture.sampled_values.len,
            recorder_witness.sampled_values.len,
        );
        try std.testing.expectEqual(
            @intFromPtr(verified.capture.sampled_values.ptr),
            @intFromPtr(recorder_witness.sampled_values.ptr),
        );

        try exerciseFinalizedRecorderRow18(
            allocator,
            prepared,
            &verified,
        );
    }
};

/// Finalizes the exact heterogeneous graph with real SegmentV2 and universal
/// component cohorts, then evaluates the successful SegmentV2 verifier
/// witness through the opaque recording and the reused rows-18/19 authority.
/// The universal cohort is deliberately reused for the inactive empty lane in
/// this substrate-only test; canonical-empty components remain mandatory
/// before any parent production capability can become true.
fn exerciseFinalizedRecorderRow18(
    allocator: std.mem.Allocator,
    prepared: *const leaf_outer.PreparedNativeV2LeafOuter,
    verified: *const outer_proof.VerifiedOuterProof,
) !void {
    var segment_cohort = try outer_cohort.Cohort.init(allocator, prepared);
    defer segment_cohort.deinit();
    const admitted_child = try outer_admission_v2.admitVerifiedSegmentV2ChildV2(
        allocator,
        &verified.publication,
        &verified.capture,
        &verified.recursive_witness,
        segment_cohort.manifest(),
    );
    defer admitted_child.deinit();
    try admitted_child.validate();
    const admitted_dimensions = admitted_child.dimensions();
    std.debug.print(
        "\nSEGMENT_V2_OUTER_DIMENSIONS commitments={d} claims={d} " ++
            "samples={d} queried_values={d} trace_paths={d} " ++
            "fri_layers={d} queries={d} max_fold={d} " ++
            "last_layer_coefficients={d} max_merkle_depth={d}\n",
        .{
            admitted_dimensions.commitment_count,
            admitted_dimensions.claimed_sum_count,
            admitted_dimensions.sampled_value_count,
            admitted_dimensions.queried_value_count,
            admitted_dimensions.trace_path_count,
            admitted_dimensions.fri_layer_count,
            admitted_dimensions.query_count,
            admitted_dimensions.maximum_fold_width,
            admitted_dimensions.last_layer_coefficient_count,
            admitted_dimensions.maximum_merkle_depth,
        },
    );
    try std.testing.expectEqualDeep(
        outer_admission_v2.SEGMENT_V2_OUTER_DIMENSIONS,
        admitted_dimensions,
    );
    var captured_child = try admitted_child.initCapturedFriOwned(allocator);
    defer captured_child.deinit();
    try std.testing.expectEqual(
        @as(u32, outer_admission_v2.CLAIM_COUNT),
        captured_child.claimed_sum_count,
    );
    // Component claims and Tree-2 samples belong to the outer verifier's
    // actual transcript challenges, not the native-leaf preparation's dummy
    // relation bundle. Reconstruct once from the verifier-minted fixed sidecar
    // so graph recording and concrete evaluation share the same authority.
    const segment_relations = universal.UniversalRelations.fromDraws(
        &verified.recursive_witness.relation_draws,
    );
    try segment_relations.validate();
    const segment_provider_relations =
        try shared_provider.SharedProviderRelations.init(&segment_relations);
    const segment_generated = try segment_cohort.rebuildGeneratedInteractions(
        &segment_relations,
        &segment_provider_relations,
    );
    var segment_components = try segment_cohort.initComponents(
        &segment_generated,
        &segment_relations,
        &segment_provider_relations,
    );
    defer segment_components.deinit();

    var fixture = try binary_fixture.Fixture.init(allocator);
    defer fixture.deinit();
    const binary_inputs = BinaryCohort.AuthorityInputs{
        .non_fri = try fixture.nonFriInputs(),
        .fri_source = fixture.friSource(),
    };
    var universal_cohort = try BinaryCohort.init(allocator, binary_inputs);
    defer universal_cohort.deinit();
    var binary_channel = binary_driver.Engine.Channel{};
    const binary_relations = try universal.UniversalRelations.draw(
        allocator,
        &binary_channel,
    );
    const binary_provider_relations =
        try shared_provider.SharedProviderRelations.init(&binary_relations);
    const binary_generated = try universal_cohort.rebuildGeneratedInteractions(
        &binary_relations,
        &binary_provider_relations,
    );
    var binary_components = try universal_cohort.initComponents(
        &binary_generated,
        &binary_relations,
        &binary_provider_relations,
    );
    defer binary_components.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const binary_capture = try recording_support.syntheticCapture(
        arena.allocator(),
        universal_cohort.manifest(),
        7_301,
    );
    const manifests = composition_v3.TrustedManifestsV3{
        .universal = universal_cohort.manifest(),
        .segment = segment_cohort.manifest(),
    };
    const air_program_ids = composition_v3.AirProgramIdsV3{
        .segment_leaf = verified.publication.air_program_id,
        .binary_node = recording_support.nativeDigest(7_401),
        .empty_leaf = recording_support.nativeDigest(7_501),
    };
    const session = try composition_v3.HeterogeneousSessionV3.create(
        allocator,
        manifests,
        air_program_ids,
        &verified.capture,
        &binary_capture,
    );
    var session_live = true;
    defer if (session_live) session.deinit();
    try session.recordPrograms(
        &segment_components,
        &binary_components,
        &binary_components,
    );
    const recording = try session.finish();
    session_live = false;
    defer recording.deinit();
    try recording.validate(manifests, air_program_ids);

    const configuration = try recording.configurationSnapshot(
        manifests,
        air_program_ids,
    );
    const descriptor = configuration.program_roster.forKind(.segment_leaf).*;
    var bridge = try composition_authority.SegmentV2RecorderBridgeV3.init(
        allocator,
        try composition_authority.SegmentV2CompositionProfileV1.seal(
            segment_cohort.manifest(),
            verified.publication.air_program_id,
        ),
        descriptor,
        segment_cohort.manifest(),
        &verified.capture,
        &verified.publication,
        &verified.recursive_witness,
    );
    defer bridge.deinit();
    const retained_boundary = bridge.public_wire_boundary;
    bridge.public_wire_boundary = retained_boundary.add(QM31.one());
    try std.testing.expectError(
        error.SegmentV2RecorderIdentityMismatch,
        bridge.validateSelfConsistency(segment_cohort.manifest()),
    );
    bridge.public_wire_boundary = retained_boundary;
    try bridge.validateSelfConsistency(segment_cohort.manifest());
    const witness = try bridge.concreteWitness(
        allocator,
        segment_cohort.manifest(),
        &verified.capture,
        &verified.publication,
        &verified.recursive_witness,
    );
    const claimed_total = sumPhysicalClaims(witness.claim_inputs);
    const statement_public = try parentPublicSum(
        witness.statement_words,
        witness.relations,
    );
    const legacy_residual = claimed_total.add(statement_public);
    const segment_residual = claimed_total.add(witness.public_wire_boundary);
    std.debug.print(
        "\nV3_ROW18_DIFFERENTIAL sum39={any} statement_public={any} " ++
            "wire_boundary={any} legacy_residual={any} segment_residual={any}\n",
        .{
            claimed_total.toM31Array(),
            statement_public.toM31Array(),
            witness.public_wire_boundary.toM31Array(),
            legacy_residual.toM31Array(),
            segment_residual.toM31Array(),
        },
    );
    try std.testing.expect(!legacy_residual.isZero());
    try std.testing.expect(segment_residual.isZero());
    const graph = recording.graph();
    const graph_input_count = try composition_graph.recursionInputCount(
        configuration.graphInputProfile(),
    );
    const padded_samples = try allocator.alloc(
        QM31,
        configuration.sampled_value_count,
    );
    defer allocator.free(padded_samples);
    const input_scratch = try allocator.alloc(QM31, graph_input_count);
    defer allocator.free(input_scratch);
    const node_values = try allocator.alloc(QM31, graph.nodes.len);
    defer allocator.free(node_values);
    recording.evaluateSegmentInto(
        manifests,
        air_program_ids,
        &bridge.layout,
        witness,
        padded_samples,
        input_scratch,
        node_values,
    ) catch |err| {
        if (err == error.UnsatisfiedCircuit) try diagnoseRecorderFailure(
            configuration,
            witness,
            padded_samples,
            input_scratch,
            node_values,
            graph,
        );
        return err;
    };

    const view = try recording.validatedView(manifests, air_program_ids);
    const lanes = [2]composition_graph.RecursionLane{
        try view.validatedLane(
            manifests,
            air_program_ids,
            binary_rows.LEFT_RECURSION_VERIFIER_ID,
            531,
            binary_rows.LEFT_COMPOSITION_STATEMENT_SCOPE,
        ),
        try view.validatedLane(
            manifests,
            air_program_ids,
            binary_rows.RIGHT_RECURSION_VERIFIER_ID,
            532,
            binary_rows.RIGHT_COMPOSITION_STATEMENT_SCOPE,
        ),
    };
    const evaluations = [2]lowering.Evaluation{
        .{ .circuit_identity = graph.identity_digest, .values = node_values },
        .{ .circuit_identity = graph.identity_digest, .values = node_values },
    };
    var outer_tree_heights: [frontend.recursion.fixed_profile.TREE_COUNT]u32 =
        undefined;
    if (captured_child.trace_tree_heights.len != outer_tree_heights.len)
        return error.InvalidProofShape;
    @memcpy(&outer_tree_heights, captured_child.trace_tree_heights);
    const outer_schedule_shape = try frontend.recursion.transcript_shape.derive(
        captured_child.circuit.profile(),
        outer_tree_heights,
        .{
            .sampled_value_count = captured_child.sampled_value_count,
            .queried_values_per_query = captured_child.queried_values_per_query,
            .claimed_sum_count = captured_child.claimed_sum_count,
            .interaction_pow_bits = captured_child.interaction_pow_bits,
            .pcs_pow_bits = captured_child.pcs_pow_bits,
        },
    );
    var outer_vm_plan = try verifier_schedule.Plan.initShape(
        allocator,
        prepared.vm_plan.spec,
        outer_schedule_shape,
    );
    defer outer_vm_plan.deinit();
    var outer_recursion_plan = try verifier_schedule.Plan.initShape(
        allocator,
        prepared.recursion_plan.spec,
        outer_schedule_shape,
    );
    defer outer_recursion_plan.deinit();
    var rows = try binary_rows.CompositionRowsAuthority
        .initFromAuthenticatedRecorderLanes(
        allocator,
        &outer_vm_plan,
        &outer_recursion_plan,
        captured_child.sampled_value_count,
        lanes,
        evaluations,
    );
    defer rows.deinit();
    try rows.validateAuthenticatedRecorderLanes(evaluations);

    const original_value = node_values[0];
    node_values[0] = original_value.add(QM31.one());
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        rows.validateAuthenticatedRecorderLanes(evaluations),
    );
    node_values[0] = original_value;
    try rows.validateAuthenticatedRecorderLanes(evaluations);
}

/// Test-only semantic locator for the opaque finalized graph. This deliberately
/// does not participate in proof authority: it replays the public graph ABI
/// only after the production evaluator reports `UnsatisfiedCircuit`, then
/// reports the first non-zero constrained output and the three final
/// split-composition equalities.
fn diagnoseRecorderFailure(
    configuration: composition_v3.ConfigurationV3,
    witness: composition_v3.WitnessV3,
    padded_samples: []const QM31,
    input_scratch: []QM31,
    node_values: []QM31,
    graph: composition_graph.CircuitGraph,
) !void {
    var padded_witness = witness;
    padded_witness.sampled_values = padded_samples;
    try composition_v3.writeInputsFromValidatedProfile(
        configuration.inputProfile(),
        padded_witness,
        input_scratch,
    );
    var input_cursor: usize = 0;
    for (graph.nodes, 0..) |node, node_id| {
        node_values[node_id] = switch (node.op) {
            .input => blk: {
                const value = input_scratch[input_cursor];
                input_cursor += 1;
                break :blk value;
            },
            .constant => |words| QM31.fromU32Unchecked(
                words[0],
                words[1],
                words[2],
                words[3],
            ),
            .add => |operands| node_values[operands.lhs].add(
                node_values[operands.rhs],
            ),
            .sub => |operands| node_values[operands.lhs].sub(
                node_values[operands.rhs],
            ),
            .mul => |operands| node_values[operands.lhs].mul(
                node_values[operands.rhs],
            ),
            .neg => |operand| node_values[operand].neg(),
            .inverse => |operand| try node_values[operand].inv(),
        };
    }
    var first: ?usize = null;
    var first_node: ?u32 = null;
    var first_value = QM31.zero();
    var nonzero: usize = 0;
    for (graph.outputs, 0..) |node_id, output_index| {
        if (node_values[node_id].isZero()) continue;
        if (first == null) {
            first = output_index;
            first_node = node_id;
            first_value = node_values[node_id];
        }
        nonzero += 1;
    }
    std.debug.print(
        "\nV3_RECORDER_UNSAT outputs={d} nonzero={d} first={?d} " ++
            "first_node={?d} first_value={any}",
        .{
            graph.outputs.len,
            nonzero,
            first,
            first_node,
            first_value.toM31Array(),
        },
    );
    const final_start = graph.outputs.len -| composition_v3.PROGRAM_KIND_COUNT;
    for (graph.outputs[final_start..], final_start..) |node_id, output_index| {
        std.debug.print(
            " final[{d}]={any}",
            .{ output_index, node_values[node_id].toM31Array() },
        );
    }
    std.debug.print("\n", .{});
}

fn sumPhysicalClaims(
    claims: *const [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31,
) QM31 {
    var result = QM31.zero();
    for (claims[0..composition_v3.SEGMENT_PHYSICAL_CLAIM_COUNT]) |claim|
        result = result.add(claim);
    return result;
}

fn parentPublicSum(
    words: *const [composition_v3.STATEMENT_WORD_COUNT]M31,
    relations: *const frontend.recursion.air.universal_challenges.UniversalRelations,
) !QM31 {
    const challenge = relations.get(.recursion_statement_word);
    var result = QM31.zero();
    for (words, 0..) |word, word_index| {
        const tuple = [_]M31{
            M31.fromU64(frontend.recursion.air.statement_input.PARENT_STATEMENT_SCOPE),
            M31.fromU64(word_index),
            word,
        };
        result = result.add(try (try challenge.combineBase(&tuple)).inv());
    }
    return result;
}

test "SegmentV2 concrete 39-row outer proof independently verifies all 47 domains" {
    try runGate(std.testing.allocator);
}

test "SegmentV2 finalized heterogeneous recorder evaluates real row18 witness" {
    try runFocusedRecorderGate(std.testing.allocator);
}

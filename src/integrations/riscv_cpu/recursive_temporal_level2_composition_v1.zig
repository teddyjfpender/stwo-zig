//! Authenticated composition capture for a verified temporal-parent child.
//!
//! The existing V3 binary recorder is intentionally frozen to the universal
//! V1 manifest. A temporal parent has the same 36-row roster but a distinct
//! row-8 program and therefore cannot be relabeled as that legacy program.
//! This owner records the actual initialized temporal cohort once, evaluates
//! the resulting graph with verifier-minted inputs, and retains the graph,
//! bindings, and evaluation for the next recursion layer's rows 18 and 19.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const cohort_mod = @import("recursive_temporal_parent_cohort_v3.zig");
const manifest_mod = @import("recursive_temporal_parent_manifest_v3.zig");
const artifact_mod = @import("recursive_temporal_parent_verified_artifact_v1.zig");
const publication_mod = @import("recursive_temporal_parent_publication_v3.zig");
const binary_driver = @import("recursive_binary_outer.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const composition = recursion.air.composition_circuit;
const lowering = recursion.air.verifier_arithmetic_lowering;
const universal = recursion.air.universal_challenges;
const shared_provider = recursion.air.universal_shared_provider;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const recorder = composition_v3.segment_recorder_v3.graph_recorder;
const capture_layout = composition_v3.capture_layout_v3;

const ProgramRecorder = composition_v3.segment_recorder_v3
    .ProgramRecorderForManifest(
    manifest_mod,
    .binary_node,
    manifest_mod.COMPONENT_COUNT,
);

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const CIRCUIT_ID: u32 = 621;
pub const LEFT_CIRCUIT_ID: u32 = CIRCUIT_ID;
pub const RIGHT_CIRCUIT_ID: u32 = CIRCUIT_ID + 1;
pub const MANIFEST_FAMILY = capture_layout.ManifestFamily.temporal_parent_v3;
pub const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-level2-composition/v1\x00";

pub const CaptureV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    publication_id: artifact_mod.Digest,
    artifact_id: artifact_mod.Digest,
    capture_id: artifact_mod.Digest,
    manifest_seal: [32]u8,
    layout: capture_layout.CaptureLayoutV3,
    profile: composition_v3.InputProfileV3,
    claim_inputs: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31,
    wire_boundary: QM31,
    verifier_input_boundary: QM31,
    relations: universal.UniversalRelations,
    circuit: recorder.Circuit,
    bindings: []composition.RecursionInputBinding,
    input_values: []QM31,
    node_values: []QM31,
    validation_values: []QM31,
    identity: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        cohort: *cohort_mod.Cohort,
        capture: *const binary_driver.OuterProofCapture,
        publication: *const publication_mod.VerifiedPublicationV1,
        artifact: *const artifact_mod.VerifiedTemporalParentArtifactV1,
    ) !CaptureV1 {
        try cohort.validate();
        try artifact.validateAgainst(publication);
        try artifact.recursive_admission.validateAgainst(capture);
        const manifest = cohort.manifest();
        if (!std.mem.eql(
            u8,
            &manifest.seal,
            &artifact.transcript_prefix.manifest_sha_id,
        )) return error.ManifestAuthorityMismatch;

        var layout = try capture_layout.CaptureLayoutV3
            .initAuthenticatedBinary(
            allocator,
            MANIFEST_FAMILY,
            manifest,
            capture,
        );
        errdefer layout.deinit();
        const profile = composition_v3.InputProfileV3{
            .sampled_value_count = layout.sampled_value_count,
        };
        try profile.validate();
        const relations = universal.UniversalRelations.fromDraws(
            &artifact.transcript_prefix.relation_draws,
        );
        try relations.validate();
        const provider_relations = try shared_provider.SharedProviderRelations
            .init(&relations);
        const generated = try cohort.rebuildGeneratedInteractions(
            &relations,
            &provider_relations,
        );
        var components = try cohort.initComponents(
            &generated,
            &relations,
            &provider_relations,
        );
        defer components.deinit();

        var physical_claims: [manifest_mod.COMPONENT_COUNT]QM31 = undefined;
        for (
            &physical_claims,
            artifact.recursive_admission.receipt.claimed_sums,
        ) |*destination, source| destination.* = try qm31FromWire(source);
        var claim_inputs: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31 =
            undefined;
        try composition_v3.writeClaimInputs(
            .binary_node,
            &physical_claims,
            &artifact.transcript_prefix.poseidon2_partials,
            &claim_inputs,
        );

        var program = try recordProgram(
            allocator,
            manifest,
            &layout,
            profile,
            &components,
            artifact.transcript_prefix.wire_boundary.claimed_sum,
            artifact.transcript_prefix.verifier_input_boundary.claimed_sum,
        );
        errdefer program.deinit();
        const input_count = try composition.recursionInputCount(
            profile.graphProfile(),
        );
        const input_values = try allocator.alloc(QM31, input_count);
        errdefer allocator.free(input_values);
        const node_values = try allocator.alloc(QM31, program.circuit.nodes.len);
        errdefer allocator.free(node_values);
        const validation_values = try allocator.alloc(
            QM31,
            program.circuit.nodes.len,
        );
        errdefer allocator.free(validation_values);
        const witness = composition_v3.WitnessV3{
            .parent_binary_selector = true,
            .proof_kind = .binary_node,
            .statement_words = &publication.statement_words,
            .sampled_values = capture.sampled_values,
            .claim_inputs = &claim_inputs,
            .public_wire_boundary = artifact.transcript_prefix.wire_boundary.claimed_sum,
            .relations = &relations,
            .composition_randomness = capture.composition_randomness,
            .oods_seed = capture.oods_seed,
        };
        try composition_v3.writeInputsFromValidatedProfile(
            profile,
            witness,
            input_values,
        );
        program.circuit.evaluateInto(input_values, node_values) catch |err| {
            if (err == error.UnsatisfiedCircuit)
                diagnoseUnsatisfiedCircuit(&program.circuit, node_values);
            return err;
        };

        var result = CaptureV1{
            .allocator = allocator,
            .publication_id = artifact.publication_id,
            .artifact_id = artifact.artifact_id,
            .capture_id = publication.capture_id,
            .manifest_seal = manifest.seal,
            .layout = layout,
            .profile = profile,
            .claim_inputs = claim_inputs,
            .wire_boundary = artifact.transcript_prefix.wire_boundary.claimed_sum,
            .verifier_input_boundary = artifact.transcript_prefix
                .verifier_input_boundary.claimed_sum,
            .relations = relations,
            .circuit = program.circuit,
            .bindings = program.bindings,
            .input_values = input_values,
            .node_values = node_values,
            .validation_values = validation_values,
            .identity = undefined,
        };
        result.identity = captureIdentity(&result);
        try result.validateAgainst(manifest, capture, publication, artifact);
        program.moved = true;
        layout = undefined;
        return result;
    }

    pub fn deinit(self: *CaptureV1) void {
        self.allocator.free(self.validation_values);
        self.allocator.free(self.node_values);
        self.allocator.free(self.input_values);
        self.allocator.free(self.bindings);
        self.circuit.deinit();
        self.layout.deinit();
        self.* = undefined;
    }

    pub fn lane(
        self: *const CaptureV1,
        verifier_id: u32,
        circuit_id: u32,
        statement_scope: u32,
    ) composition.RecursionLane {
        return .{
            .verifier_id = verifier_id,
            .circuit_id = circuit_id,
            .statement_scope = statement_scope,
            .graph = self.circuit.graph(),
            .profile = self.profile.graphProfile(),
            .bindings = self.bindings,
        };
    }

    pub fn evaluation(self: *const CaptureV1) lowering.Evaluation {
        return .{
            .circuit_identity = self.circuit.identity_digest,
            .values = self.node_values,
        };
    }

    pub fn validateAgainst(
        self: *CaptureV1,
        manifest: *const manifest_mod.Manifest,
        capture: *const binary_driver.OuterProofCapture,
        publication: *const publication_mod.VerifiedPublicationV1,
        artifact: *const artifact_mod.VerifiedTemporalParentArtifactV1,
    ) !void {
        try artifact.validateAgainst(publication);
        try artifact.recursive_admission.validateAgainst(capture);
        try manifest.validate();
        try self.layout.validateAgainstAuthenticatedBinary(
            MANIFEST_FAMILY,
            manifest,
        );
        if (!std.meta.eql(self.publication_id, artifact.publication_id) or
            !std.meta.eql(self.artifact_id, artifact.artifact_id) or
            !std.meta.eql(self.capture_id, publication.capture_id) or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal))
        {
            return error.CompositionAuthorityMismatch;
        }
        var expected_claims: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31 =
            undefined;
        var physical: [manifest_mod.COMPONENT_COUNT]QM31 = undefined;
        for (&physical, artifact.recursive_admission.receipt.claimed_sums) |
            *destination,
            source,
        | destination.* = try qm31FromWire(source);
        try composition_v3.writeClaimInputs(
            .binary_node,
            &physical,
            &artifact.transcript_prefix.poseidon2_partials,
            &expected_claims,
        );
        const expected_relations = universal.UniversalRelations.fromDraws(
            &artifact.transcript_prefix.relation_draws,
        );
        if (!std.meta.eql(expected_claims, self.claim_inputs) or
            !self.wire_boundary.eql(
                artifact.transcript_prefix.wire_boundary.claimed_sum,
            ) or
            !self.verifier_input_boundary.eql(
                artifact.transcript_prefix.verifier_input_boundary.claimed_sum,
            ) or
            !std.meta.eql(expected_relations, self.relations))
        {
            return error.CompositionAuthorityMismatch;
        }
        const witness = composition_v3.WitnessV3{
            .parent_binary_selector = true,
            .proof_kind = .binary_node,
            .statement_words = &publication.statement_words,
            .sampled_values = capture.sampled_values,
            .claim_inputs = &self.claim_inputs,
            .public_wire_boundary = artifact.transcript_prefix.wire_boundary.claimed_sum,
            .relations = &self.relations,
            .composition_randomness = capture.composition_randomness,
            .oods_seed = capture.oods_seed,
        };
        try composition_v3.writeInputsFromValidatedProfile(
            self.profile,
            witness,
            self.input_values,
        );
        try self.validateRetained();
    }

    /// Replays all retained graph inputs and bindings after ownership crosses
    /// the parent-proof boundary. Manifest-specific placement was checked
    /// while the live cohort existed and remains bound by `manifest_seal`.
    pub fn validateRetained(self: *CaptureV1) !void {
        try self.layout.validateSelfConsistency();
        try self.profile.validate();
        try self.circuit.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0) or
            self.profile.sampled_value_count != self.layout.sampled_value_count or
            self.input_values.len != try composition.recursionInputCount(
                self.profile.graphProfile(),
            ) or
            self.node_values.len != self.circuit.nodes.len or
            self.validation_values.len != self.circuit.nodes.len or
            !std.mem.eql(u8, &self.identity, &captureIdentity(self)))
        {
            return error.CompositionAuthorityMismatch;
        }
        const lane_value = self.lane(
            recursion.binary_fri_outer_source.LEFT_RECURSION_VERIFIER_ID,
            LEFT_CIRCUIT_ID,
            recursion.binary_fri_outer_source.LEFT_COMPOSITION_STATEMENT_SCOPE,
        );
        try composition.validateRecursionBindings(lane_value);
        try self.circuit.evaluateInto(
            self.input_values,
            self.validation_values,
        );
        if (!qm31SliceEql(self.node_values, self.validation_values))
            return error.CompositionAuthorityMismatch;
    }
};

const OwnedProgram = struct {
    circuit: recorder.Circuit,
    bindings: []composition.RecursionInputBinding,
    moved: bool = false,

    fn deinit(self: *OwnedProgram) void {
        if (!self.moved) {
            const allocator = self.circuit.allocator;
            allocator.free(self.bindings);
            self.circuit.deinit();
        }
        self.* = undefined;
    }
};

fn recordProgram(
    allocator: std.mem.Allocator,
    manifest: *const manifest_mod.Manifest,
    layout: *const capture_layout.CaptureLayoutV3,
    profile: composition_v3.InputProfileV3,
    components: *const cohort_mod.Cohort.Components,
    wire_boundary: QM31,
    verifier_input_boundary: QM31,
) !OwnedProgram {
    const graph_profile = profile.graphProfile();
    const input_count = try composition.recursionInputCount(graph_profile);
    const bindings = try allocator.alloc(
        composition.RecursionInputBinding,
        input_count,
    );
    errdefer allocator.free(bindings);
    const base_inputs = try allocator.alloc(recorder.Scalar, input_count);
    defer allocator.free(base_inputs);
    const sampled_values = try allocator.alloc(
        recorder.Scalar,
        layout.sampled_value_count,
    );
    defer allocator.free(sampled_values);
    var builder = recorder.Builder.init(allocator);
    defer builder.deinit();
    try builder.reserve(input_count, manifest.total_constraints + 512);
    for (base_inputs, bindings, 0..) |*value, *binding, index| {
        const input = try builder.input();
        value.* = input.value;
        binding.* = .{
            .node_id = input.node_id,
            .source = composition.expectedRecursionSource(
                graph_profile,
                index,
            ) orelse return error.InvalidWitnessShape,
        };
    }
    try builder.activate();
    errdefer if (builder.active) builder.deactivate();

    var cursor: usize = 0;
    const parent_binary_selector = base_inputs[cursor];
    cursor += 1;
    var child_kind_selectors: [composition_v3.PROGRAM_KIND_COUNT]recorder.Scalar =
        undefined;
    @memcpy(
        &child_kind_selectors,
        base_inputs[cursor..][0..composition_v3.PROGRAM_KIND_COUNT],
    );
    cursor += composition_v3.PROGRAM_KIND_COUNT;
    var statement_words: [composition_v3.STATEMENT_WORD_COUNT]recorder.Scalar =
        undefined;
    @memcpy(
        &statement_words,
        base_inputs[cursor..][0..composition_v3.STATEMENT_WORD_COUNT],
    );
    cursor += composition_v3.STATEMENT_WORD_COUNT;
    for (sampled_values) |*value|
        value.* = composition_v3.takeSecureRecorderInput(base_inputs, &cursor);
    var claim_inputs: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]recorder.Scalar =
        undefined;
    for (&claim_inputs) |*value|
        value.* = composition_v3.takeSecureRecorderInput(base_inputs, &cursor);
    const public_wire_boundary = composition_v3.takeSecureRecorderInput(
        base_inputs,
        &cursor,
    );
    var challenge_draws: [composition_v3.RELATION_CHALLENGE_COUNT][2]recorder.Scalar =
        undefined;
    for (&challenge_draws) |*draw| {
        draw[0] = composition_v3.takeSecureRecorderInput(base_inputs, &cursor);
        draw[1] = composition_v3.takeSecureRecorderInput(base_inputs, &cursor);
    }
    const composition_randomness = composition_v3.takeSecureRecorderInput(
        base_inputs,
        &cursor,
    );
    const oods_seed = composition_v3.takeSecureRecorderInput(
        base_inputs,
        &cursor,
    );
    if (cursor != input_count) return error.InvalidWitnessShape;
    const challenges = try recorder.ChallengeSet.init(challenge_draws);
    const oods_point = recorder.pointFromSeed(oods_seed);
    const split_composition = try composition_v3
        .reconstructSplitCompositionForLayout(
        layout,
        sampled_values,
        oods_point,
    );

    const one = recorder.Scalar.one();
    try builder.constrainZero(parent_binary_selector.sub(one));
    for (child_kind_selectors, 0..) |selector, index| try builder.constrainZero(
        selector.sub(if (index == composition_v3.proofKindIndex(.binary_node))
            one
        else
            recorder.Scalar.zero()),
    );
    const height = statement_words[
        recursion.span_statement.canonical_layout.slot_height
    ];
    try builder.constrainZero(height.mul(height.inverse()).sub(one));
    _ = try composition_v3.recordClaimPolicyConstraints(
        &builder,
        &child_kind_selectors,
        &claim_inputs,
    );
    var claimed_total = recorder.Scalar.zero();
    for (claim_inputs[0..composition_v3.SEGMENT_PHYSICAL_CLAIM_COUNT]) |claim|
        claimed_total = claimed_total.add(claim);
    // The transcript payload internally provides this exact public-wire tuple.
    // The verifier-input boundary is independent external authority and stays
    // a circuit constant rather than being relabeled as a wire tuple.
    try builder.constrainZero(
        public_wire_boundary.sub(recorder.Scalar.fromSecure(wire_boundary)),
    );
    try builder.constrainZero(
        claimed_total
            .add(public_wire_boundary)
            .add(recorder.Scalar.fromSecure(verifier_input_boundary)),
    );

    var denominators: recorder.DenominatorCache =
        .{null} ** stwo_core.circle.M31_CIRCLE_LOG_ORDER;
    var program = try ProgramRecorder.initAuthenticatedBinary(
        &builder,
        manifest,
        MANIFEST_FAMILY,
        layout,
        sampled_values,
        &claim_inputs,
        &challenges,
        composition_randomness,
        oods_point,
        &denominators,
    );
    const recorded = try recordCohort(&program, components);
    try builder.constrainZero(split_composition.sub(recorded.accumulation));
    try builder.check();
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const lane = composition.RecursionLane{
        .verifier_id = recursion.binary_fri_outer_source.LEFT_RECURSION_VERIFIER_ID,
        .circuit_id = CIRCUIT_ID,
        .statement_scope = recursion.binary_fri_outer_source
            .LEFT_COMPOSITION_STATEMENT_SCOPE,
        .graph = circuit.graph(),
        .profile = graph_profile,
        .bindings = bindings,
    };
    try composition.validateRecursionBindings(lane);
    return .{ .circuit = circuit, .bindings = bindings };
}

fn recordCohort(
    program: *ProgramRecorder,
    components: *const cohort_mod.Cohort.Components,
) !composition_v3.segment_recorder_v3.ProgramResultV3 {
    _ = try program.recordTypedComponent(.control, &components.prefix.control);
    _ = try program.recordTypedComponent(.transcript_air, &components.prefix.transcript_air);
    _ = try program.recordTypedComponent(.transcript_binding, &components.prefix.transcript_binding);
    _ = try program.recordTypedComponent(.transcript_state, &components.prefix.transcript_state);
    _ = try program.recordTypedComponent(.transcript_word, &components.prefix.transcript_word);
    _ = try program.recordTypedComponent(.transcript_payload, &components.prefix.transcript_payload);
    _ = try program.recordTypedComponent(.pow_check, &components.prefix.pow_check);
    _ = try program.recordTypedComponent(.pow_frame, &components.prefix.pow_frame);
    _ = try program.recordTypedComponent(.relation_challenge, &components.prefix.packed_relation_challenge);
    _ = try program.recordTypedComponent(.verifier_randomness, &components.prefix.verifier_randomness);
    _ = try program.recordTypedComponent(.statement_input, &components.prefix.statement_input);
    _ = try program.recordTypedComponent(.statement_semantics_input, &components.prefix.statement_semantics);
    _ = try program.recordTypedComponent(.vm_public_claim_input, &components.prefix.vm_claim_input);
    _ = try program.recordTypedComponent(.vm_public_claim_hash, &components.prefix.vm_claim_hash);
    _ = try program.recordTypedComponent(.vm_public_io_hash, &components.prefix.vm_io_hash);
    _ = try program.recordTypedComponent(.vm_public_claim_semantics_input, &components.prefix.vm_claim_semantics);
    _ = try program.recordTypedComponent(.vm_public_logup_input, &components.prefix.vm_public_logup);
    _ = try program.recordTypedComponent(.vm_public_logup_control, &components.prefix.vm_public_logup_control);
    _ = try program.recordTypedComponent(.vm_air_composition_input, &components.suffix.composition_input);
    _ = try program.recordTypedComponent(.vm_air_composition_control, &components.suffix.composition_control);
    _ = try program.recordTypedComponent(.query_bits, &components.suffix.query_bits);
    _ = try program.recordTypedComponent(.query_mapping, &components.suffix.query_mapping);
    _ = try program.recordTypedComponent(.merkle_root, &components.suffix.merkle_root);
    _ = try program.recordTypedComponent(.trace_merkle, &components.suffix.trace_merkle);
    _ = try program.recordTypedComponent(.pcs_deep_input, &components.suffix.pcs_deep);
    _ = try program.recordTypedComponent(.fri_merkle_leaf, &components.suffix.fri_leaf);
    _ = try program.recordTypedComponent(.fri_merkle_node, &components.suffix.fri_node);
    _ = try program.recordTypedComponent(.fri_merkle_anchor, &components.suffix.fri_anchor);
    _ = try program.recordTypedComponent(.fri_verifier_control, &components.suffix.fri_control);
    _ = try program.recordTypedComponent(.fri_verifier_input, &components.suffix.fri_input);
    _ = try program.recordTypedComponent(.qm31_mul, &components.suffix.multiply);
    _ = try program.recordTypedComponent(.qm31_inv, &components.suffix.inverse);
    _ = try program.recordTypedComponent(.linear_ops, &components.suffix.linear);
    _ = try program.recordTypedComponent(.merkle_path, &components.suffix.merkle_path);
    _ = try program.recordPoseidonProvider(&components.suffix.poseidon2);
    _ = try program.recordRangeCheck8x8Provider(&components.row35);
    return program.finishProgram();
}

fn qm31FromWire(value: recursion.fixed_wire.Qm31Wire) !QM31 {
    var words: [4]M31 = undefined;
    for (&words, value) |*destination, source|
        destination.* = M31.fromCanonical(source);
    return QM31.fromM31Array(words);
}

fn captureIdentity(value: *const CaptureV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.padding);
    hashDigest(&hash, value.publication_id);
    hashDigest(&hash, value.artifact_id);
    hashDigest(&hash, value.capture_id);
    hash.update(&value.manifest_seal);
    hash.update(&value.layout.identity);
    hash.update(&value.circuit.identity_digest);
    hashInt(&hash, u32, value.profile.sampled_value_count);
    hashInt(&hash, u32, @as(u32, @intCast(value.bindings.len)));
    for (value.bindings) |binding| {
        hashInt(&hash, u32, binding.node_id);
    }
    for (value.claim_inputs) |claim| hashQm31(&hash, claim);
    hashQm31(&hash, value.wire_boundary);
    hashQm31(&hash, value.verifier_input_boundary);
    for (value.node_values) |node| hashQm31(&hash, node);
    return hash.finalResult();
}

fn qm31SliceEql(left: []const QM31, right: []const QM31) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!lhs.eql(rhs)) return false;
    return true;
}

fn diagnoseUnsatisfiedCircuit(
    circuit: *const recorder.Circuit,
    values: []const QM31,
) void {
    for (circuit.outputs, 0..) |node, output_index| {
        if (values[node].isZero()) continue;
        std.debug.print(
            "TEMPORAL_LEVEL2_COMPOSITION_UNSAT output={d}/{d} node={d} " ++
                "value={any}\n",
            .{ output_index, circuit.outputs.len, node, values[node] },
        );
        return;
    }
}

fn hashDigest(hash: anytype, value: artifact_mod.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

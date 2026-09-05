//! Live q193 composition capture for one cold-verified temporal parent.
//!
//! This is not the functional q=3 level-2 bridge.  It is minted inside the
//! secure verifier transaction from the q193 PCS capture, verifier-rebuilt
//! relations/claims, and the exact temporal-parent cohort.  The retained graph
//! can therefore be re-recorded against the same cold authority before a later
//! parent admits it.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const program_mod =
    @import("recursive_temporal_secure_child_parent_program_v1.zig");
const manifest_mod = @import("recursive_temporal_parent_manifest_v3.zig");

const recursion = frontend.recursion;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const capture_layout = composition_v3.capture_layout_v3;
const composition = recursion.air.composition_circuit;
const lowering = recursion.air.verifier_arithmetic_lowering;
const recorder = composition_v3.segment_recorder_v3.graph_recorder;
const universal = recursion.air.universal_challenges;
const shared_provider = recursion.air.universal_shared_provider;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;
const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);

const ProgramRecorder = composition_v3.segment_recorder_v3
    .ProgramRecorderForManifest(
    manifest_mod,
    .binary_node,
    manifest_mod.COMPONENT_COUNT,
);

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const CIRCUIT_ID: u32 = 741;
pub const PRODUCTION_ACTIVATION = false;
pub const SECURE_QUERY_COUNT: usize = 193;
pub const MAX_SECURE_FOLD_WIDTH: usize = 16;

const RECONSTRUCTION_DOMAIN =
    "stwo-zig/typed-air/secure-child-temporal-reconstruction/v1\x00";
const CAPTURE_DOMAIN =
    "stwo-zig/typed-air/secure-child-temporal-capture/v1\x00";

/// Non-serializable values retained only after successful q193 verification.
pub const VerifiedReconstructionV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    session: artifact_mod.SessionV1,
    statement: artifact_mod.StatementV1,
    manifest: manifest_mod.Manifest,
    program: program_mod.AuthorityV1,
    relations: universal.UniversalRelations,
    provider_relations: shared_provider.SharedProviderRelations,
    claims: manifest_mod.ClaimVector,
    provider_partial_claims: [2]QM31,
    audited_identity_sha256: [32]u8,
    closure_identity_sha256: [32]u8,
    wire_boundary: QM31,
    verifier_input_boundary: QM31,
    identity_sha256: [32]u8,

    pub fn validateRetained(self: *const VerifiedReconstructionV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.session.source_kind != .fresh_temporal_parent_v3)
        {
            return error.InvalidSecureTemporalParentReconstruction;
        }
        try self.session.validate();
        try self.statement.validateAgainstSession(&self.session);
        try self.manifest.validate();
        try self.program.validateAgainst(
            &self.manifest,
            self.session.air_program_id,
        );
        try self.relations.validate();
        try self.provider_relations.validateAgainst(&self.relations);
        try self.claims.validate(&self.manifest);
        if (!self.provider_partial_claims[0].add(
            self.provider_partial_claims[1],
        ).eql(self.claims.values[manifest_mod.keyIndex(.poseidon2)]) or
            std.mem.allEqual(u8, &self.audited_identity_sha256, 0) or
            std.mem.allEqual(u8, &self.closure_identity_sha256, 0) or
            !std.mem.eql(
                u8,
                &self.statement.claims_sha256,
                &self.claims.seal,
            ) or !std.mem.eql(
            u8,
            &self.statement.closure_sha256,
            &self.closure_identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &reconstructionIdentity(self),
        )) {
            return error.InvalidSecureTemporalParentReconstruction;
        }
    }

    pub fn validateAgainstCapture(
        self: *const VerifiedReconstructionV1,
        capture: *const OuterProofCapture,
    ) !void {
        try self.validateRetained();
        try validateSecureCapture(capture);
        if (!std.meta.eql(
            self.statement.capture_id,
            @import("recursive_segment_v2_verified_publication.zig")
                .captureIdentity(capture),
        )) return error.SecureTemporalParentPcsCaptureMismatch;
    }
};

/// Must be called inside the cold verifier while every algebraic value remains
/// live.  A retained digest cannot invoke this constructor on its own.
pub fn fromVerifiedTemporalParentTransaction(
    comptime Cohort: type,
    cohort: *Cohort,
    session: *const artifact_mod.SessionV1,
    statement: *const artifact_mod.StatementV1,
    capture: *const OuterProofCapture,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
    generated: *const Cohort.GeneratedInteractionsV1,
    claims: *const manifest_mod.ClaimVector,
    audited: *const Cohort.AuditedInteractionsV2,
) !VerifiedReconstructionV1 {
    try session.validate();
    if (session.source_kind != .fresh_temporal_parent_v3)
        return error.InvalidSecureTemporalParentReconstruction;
    try statement.validateAgainstSession(session);
    try validateSecureCapture(capture);
    try cohort.validate();
    const manifest = cohort.manifest();
    try manifest.validate();
    try cohort.validateGenerated(generated, relations, provider_relations);
    const expected_claims = try cohort.claimVector(generated);
    if (!std.meta.eql(claims.*, expected_claims))
        return error.SecureTemporalParentClaimVectorMismatch;
    try cohort.validateAuditedInteractions(
        audited,
        claims,
        relations,
        provider_relations,
    );
    const partials = generated.suffix.claims.poseidon2_partials;
    var result = VerifiedReconstructionV1{
        .session = session.*,
        .statement = statement.*,
        .manifest = manifest.*,
        .program = try program_mod.AuthorityV1.init(
            manifest,
            session.air_program_id,
        ),
        .relations = relations.*,
        .provider_relations = provider_relations.*,
        .claims = claims.*,
        .provider_partial_claims = partials,
        .audited_identity_sha256 = audited.identity,
        .closure_identity_sha256 = audited.closure.closure_id,
        .wire_boundary = audited.wire_boundary.claimed_sum,
        .verifier_input_boundary = audited.verifier_input_boundary.claimed_sum,
        .identity_sha256 = undefined,
    };
    result.identity_sha256 = reconstructionIdentity(&result);
    try result.validateAgainstCapture(capture);
    return result;
}

pub const CaptureV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    reconstruction_identity_sha256: [32]u8,
    program_identity_sha256: [32]u8,
    manifest_seal: [32]u8,
    layout: capture_layout.CaptureLayoutV3,
    profile: composition_v3.InputProfileV3,
    claim_inputs: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31,
    circuit: recorder.Circuit,
    bindings: []composition.RecursionInputBinding,
    input_values: []QM31,
    node_values: []QM31,
    validation_values: []QM31,
    identity_sha256: [32]u8,

    pub fn initForCohort(
        comptime Cohort: type,
        allocator: std.mem.Allocator,
        cohort: *Cohort,
        reconstruction: *const VerifiedReconstructionV1,
        capture: *const OuterProofCapture,
    ) !CaptureV1 {
        try reconstruction.validateAgainstCapture(capture);
        try cohort.validate();
        const manifest = cohort.manifest();
        if (!std.meta.eql(manifest.*, reconstruction.manifest))
            return error.SecureTemporalParentManifestMismatch;
        var layout = try capture_layout.CaptureLayoutV3
            .initAuthenticatedBinary(
            allocator,
            .temporal_parent_v3,
            manifest,
            capture,
        );
        errdefer layout.deinit();
        const profile = composition_v3.InputProfileV3{
            .sampled_value_count = layout.sampled_value_count,
        };
        try profile.validate();
        var claim_inputs: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31 =
            undefined;
        try composition_v3.writeClaimInputsForManifest(
            .binary_node,
            .temporal_parent_v3,
            &reconstruction.claims.values,
            &reconstruction.provider_partial_claims,
            &claim_inputs,
        );
        const generated = try cohort.rebuildGeneratedInteractions(
            &reconstruction.relations,
            &reconstruction.provider_relations,
        );
        var components = try cohort.initComponents(
            &generated,
            &reconstruction.relations,
            &reconstruction.provider_relations,
        );
        defer components.deinit();
        var program = try recordProgram(
            allocator,
            manifest,
            &layout,
            profile,
            &components,
            reconstruction,
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
        try writeInputs(
            profile,
            &claim_inputs,
            reconstruction,
            capture,
            input_values,
        );
        try program.circuit.evaluateInto(input_values, node_values);

        var result = CaptureV1{
            .allocator = allocator,
            .reconstruction_identity_sha256 = reconstruction.identity_sha256,
            .program_identity_sha256 = reconstruction.program.identity_sha256,
            .manifest_seal = manifest.seal,
            .layout = layout,
            .profile = profile,
            .claim_inputs = claim_inputs,
            .circuit = program.circuit,
            .bindings = program.bindings,
            .input_values = input_values,
            .node_values = node_values,
            .validation_values = validation_values,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = captureIdentity(&result);
        try result.validateAgainst(
            Cohort,
            cohort,
            reconstruction,
            capture,
            false,
        );
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

    pub fn validateAgainst(
        self: *CaptureV1,
        comptime Cohort: type,
        cohort: *Cohort,
        reconstruction: *const VerifiedReconstructionV1,
        capture: *const OuterProofCapture,
        rerecord_program: bool,
    ) !void {
        try reconstruction.validateAgainstCapture(capture);
        try cohort.validate();
        const manifest = cohort.manifest();
        try self.layout.validateAgainstAuthenticatedBinary(
            .temporal_parent_v3,
            manifest,
        );
        if (!std.meta.eql(manifest.*, reconstruction.manifest) or
            !std.mem.eql(
                u8,
                &self.reconstruction_identity_sha256,
                &reconstruction.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.program_identity_sha256,
            &reconstruction.program.identity_sha256,
        ) or !std.mem.eql(u8, &self.manifest_seal, &manifest.seal)) {
            return error.InvalidSecureTemporalParentCapture;
        }
        var expected_claims: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31 =
            undefined;
        try composition_v3.writeClaimInputsForManifest(
            .binary_node,
            .temporal_parent_v3,
            &reconstruction.claims.values,
            &reconstruction.provider_partial_claims,
            &expected_claims,
        );
        if (!std.meta.eql(expected_claims, self.claim_inputs))
            return error.InvalidSecureTemporalParentCapture;
        try writeInputs(
            self.profile,
            &self.claim_inputs,
            reconstruction,
            capture,
            self.input_values,
        );
        try self.validateRetained();
        if (!rerecord_program) return;
        const generated = try cohort.rebuildGeneratedInteractions(
            &reconstruction.relations,
            &reconstruction.provider_relations,
        );
        var components = try cohort.initComponents(
            &generated,
            &reconstruction.relations,
            &reconstruction.provider_relations,
        );
        defer components.deinit();
        var expected = try recordProgram(
            self.allocator,
            manifest,
            &self.layout,
            self.profile,
            &components,
            reconstruction,
        );
        defer expected.deinit();
        if (!std.mem.eql(
            u8,
            &self.circuit.identity_digest,
            &expected.circuit.identity_digest,
        ) or !bindingsEql(self.bindings, expected.bindings))
            return error.InvalidSecureTemporalParentCapture;
    }

    pub fn validateRetained(self: *CaptureV1) !void {
        try self.layout.validateSelfConsistency();
        try self.profile.validate();
        try self.circuit.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            self.layout.manifest_family != .temporal_parent_v3 or
            self.input_values.len != try composition.recursionInputCount(
                self.profile.graphProfile(),
            ) or self.node_values.len != self.circuit.nodes.len or
            self.validation_values.len != self.circuit.nodes.len or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &captureIdentity(self),
            )) return error.InvalidSecureTemporalParentCapture;
        try composition.validateRecursionBindings(self.lane());
        try self.circuit.evaluateInto(
            self.input_values,
            self.validation_values,
        );
        if (!qm31SliceEql(self.node_values, self.validation_values))
            return error.InvalidSecureTemporalParentCapture;
    }

    pub fn lane(self: *const CaptureV1) composition.RecursionLane {
        return .{
            .verifier_id = recursion.binary_fri_outer_source
                .LEFT_RECURSION_VERIFIER_ID,
            .circuit_id = CIRCUIT_ID,
            .statement_scope = recursion.binary_fri_outer_source
                .LEFT_COMPOSITION_STATEMENT_SCOPE,
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
    components: anytype,
    reconstruction: *const VerifiedReconstructionV1,
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
    _ = try composition_v3.recordClaimPolicyConstraintsForManifestPolicy(
        &builder,
        &child_kind_selectors,
        &claim_inputs,
        .temporal_parent_v3,
        .temporal_parent,
    );
    var claimed_total = recorder.Scalar.zero();
    for (claim_inputs[0..composition_v3.SEGMENT_PHYSICAL_CLAIM_COUNT]) |claim|
        claimed_total = claimed_total.add(claim);
    try builder.constrainZero(public_wire_boundary.sub(
        recorder.Scalar.fromSecure(reconstruction.wire_boundary),
    ));
    try builder.constrainZero(
        claimed_total
            .add(public_wire_boundary)
            .add(recorder.Scalar.fromSecure(
            reconstruction.verifier_input_boundary,
        )),
    );

    var denominators: recorder.DenominatorCache =
        .{null} ** stwo_core.circle.M31_CIRCLE_LOG_ORDER;
    var program = try ProgramRecorder.initAuthenticatedBinary(
        &builder,
        manifest,
        .temporal_parent_v3,
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
        .verifier_id = recursion.binary_fri_outer_source
            .LEFT_RECURSION_VERIFIER_ID,
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

fn recordCohort(program: *ProgramRecorder, components: anytype) !composition_v3
    .segment_recorder_v3.ProgramResultV3 {
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

fn writeInputs(
    profile: composition_v3.InputProfileV3,
    claim_inputs: *const [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31,
    reconstruction: *const VerifiedReconstructionV1,
    capture: *const OuterProofCapture,
    destination: []QM31,
) !void {
    const witness = composition_v3.WitnessV3{
        .parent_binary_selector = true,
        .proof_kind = .binary_node,
        .statement_words = &reconstruction.session.parent_statement_words,
        .sampled_values = capture.sampled_values,
        .claim_inputs = claim_inputs,
        .public_wire_boundary = reconstruction.wire_boundary,
        .relations = &reconstruction.relations,
        .composition_randomness = capture.composition_randomness,
        .oods_seed = capture.oods_seed,
    };
    try composition_v3.writeInputsFromValidatedProfileAndManifestPolicy(
        profile,
        .temporal_parent_v3,
        .temporal_parent,
        witness,
        destination,
    );
}

fn validateSecureCapture(capture: *const OuterProofCapture) !void {
    if (capture.queries.raw.len != SECURE_QUERY_COUNT or
        capture.sampled_values.len == 0 or capture.fri.layers.len == 0)
    {
        return error.InvalidSecureTemporalParentFixedWire;
    }
    for (capture.fri.layers) |layer| if (layer.query_count != SECURE_QUERY_COUNT or
        layer.fold_width == 0 or layer.fold_width > MAX_SECURE_FOLD_WIDTH) return error.InvalidSecureTemporalParentFixedWire;
}

fn reconstructionIdentity(value: *const VerifiedReconstructionV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(RECONSTRUCTION_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.session.identity_sha256);
    hash.update(&value.statement.identity_sha256);
    hash.update(&value.manifest.seal);
    hash.update(&value.program.identity_sha256);
    hash.update(&value.claims.seal);
    for (value.provider_partial_claims) |claim| hashQm31(&hash, claim);
    hash.update(&value.audited_identity_sha256);
    hash.update(&value.closure_identity_sha256);
    hashQm31(&hash, value.wire_boundary);
    hashQm31(&hash, value.verifier_input_boundary);
    return hash.finalResult();
}

fn captureIdentity(value: *const CaptureV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CAPTURE_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.reconstruction_identity_sha256);
    hash.update(&value.program_identity_sha256);
    hash.update(&value.manifest_seal);
    hash.update(&value.layout.identity);
    hash.update(&value.circuit.identity_digest);
    hashInt(&hash, u32, value.profile.sampled_value_count);
    hashInt(&hash, u32, @as(u32, @intCast(value.bindings.len)));
    for (value.bindings) |binding| hashInt(&hash, u32, binding.node_id);
    for (value.claim_inputs) |claim| hashQm31(&hash, claim);
    for (value.node_values) |node| hashQm31(&hash, node);
    return hash.finalResult();
}

fn bindingsEql(
    left: []const composition.RecursionInputBinding,
    right: []const composition.RecursionInputBinding,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!std.meta.eql(lhs, rhs)) return false;
    return true;
}

fn qm31SliceEql(left: []const QM31, right: []const QM31) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!lhs.eql(rhs)) return false;
    return true;
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (PRODUCTION_ACTIVATION or SECURE_QUERY_COUNT != 193 or
        MAX_SECURE_FOLD_WIDTH != 16 or manifest_mod.COMPONENT_COUNT != 36)
    {
        @compileError("secure temporal-parent child capture drifted");
    }
}

//! Retained evaluated composition graph for one cold-verified H1 child.
//!
//! The graph is minted only from the typed verifier reconstruction and the
//! actual PCS capture. H1 statement and verifier-input residuals are recorded
//! as circuit constants under the H1 program identity. The legacy
//! `public_wire_boundary` input is constrained to zero; a statement-domain
//! residual is never relabeled as a recursion-wire residual.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const reconstruction_mod =
    @import("recursive_temporal_secure_child_composition_v1.zig");
const graph_mod = @import("recursive_temporal_secure_child_h1_graph_v1.zig");
const manifest_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_manifest_v1.zig");

const recursion = frontend.recursion;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const capture_layout = composition_v3.capture_layout_v3;
const composition = recursion.air.composition_circuit;
const lowering = recursion.air.verifier_arithmetic_lowering;
const recorder = composition_v3.segment_recorder_v3.graph_recorder;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const Sha256 = std.crypto.hash.sha2.Sha256;
const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const CIRCUIT_ID: u32 = 731;
pub const PRODUCTION_ACTIVATION = false;
pub const PARENT_ADMISSION_AVAILABLE = false;

const CAPTURE_DOMAIN =
    "stwo-zig/typed-air/secure-child-h1-composition-capture/v1\x00";

pub const CaptureV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    reconstruction_identity_sha256: [32]u8,
    manifest_seal: [32]u8,
    layout: capture_layout.CaptureLayoutV3,
    profile: composition_v3.InputProfileV3,
    claim_inputs: graph_mod.ClaimInputsV1,
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
        reconstruction: *const reconstruction_mod.VerifiedReconstructionV1,
        capture: *const OuterProofCapture,
    ) !CaptureV1 {
        try reconstruction.validateAgainstCapture(capture);
        try cohort.validate();
        const manifest = cohort.manifest();
        if (!std.meta.eql(manifest.*, reconstruction.manifest))
            return error.SecureChildH1ManifestMismatch;

        var layout = try graph_mod.initCaptureLayout(
            allocator,
            manifest,
            capture,
        );
        errdefer layout.deinit();
        const profile = composition_v3.InputProfileV3{
            .sampled_value_count = layout.sampled_value_count,
        };
        try profile.validate();
        const claim_inputs = try graph_mod.ClaimInputsV1
            .initFromReconstruction(reconstruction);
        const generated = try cohort.rebuildGeneratedInteractions(
            &reconstruction.relations,
            &reconstruction.provider_relations,
        );
        try cohort.validateGenerated(
            &generated,
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
            &components.inner,
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
        reconstruction: *const reconstruction_mod.VerifiedReconstructionV1,
        capture: *const OuterProofCapture,
        rerecord_program: bool,
    ) !void {
        try reconstruction.validateAgainstCapture(capture);
        try cohort.validate();
        const manifest = cohort.manifest();
        try self.layout.validateAgainstAuthenticatedBinary(
            graph_mod.MANIFEST_FAMILY,
            manifest,
        );
        try self.claim_inputs.validateAgainst(reconstruction);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            !std.meta.eql(manifest.*, reconstruction.manifest) or
            !std.mem.eql(
                u8,
                &self.reconstruction_identity_sha256,
                &reconstruction.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.manifest_seal,
            &manifest.seal,
        )) return error.InvalidSecureChildH1CompositionCapture;
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
            &components.inner,
            reconstruction,
        );
        defer expected.deinit();
        if (!std.mem.eql(
            u8,
            &self.circuit.identity_digest,
            &expected.circuit.identity_digest,
        ) or !bindingsEql(self.bindings, expected.bindings))
            return error.InvalidSecureChildH1CompositionCapture;
    }

    pub fn validateRetained(self: *CaptureV1) !void {
        try self.layout.validateSelfConsistency();
        try self.profile.validate();
        try self.claim_inputs.validate();
        try self.circuit.validate();
        if (self.input_values.len != try composition.recursionInputCount(
            self.profile.graphProfile(),
        ) or self.node_values.len != self.circuit.nodes.len or
            self.validation_values.len != self.circuit.nodes.len or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &captureIdentity(self),
            )) return error.InvalidSecureChildH1CompositionCapture;
        try composition.validateRecursionBindings(self.lane());
        try self.circuit.evaluateInto(
            self.input_values,
            self.validation_values,
        );
        if (!qm31SliceEql(self.node_values, self.validation_values))
            return error.InvalidSecureChildH1CompositionCapture;
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

    pub fn requireParentAdmission(self: *CaptureV1) !void {
        try self.validateRetained();
        if (!PARENT_ADMISSION_AVAILABLE)
            return error.SecureChildH1ParentAdmissionUnavailable;
        if (!PRODUCTION_ACTIVATION)
            return error.SecureChildH1ProductionUnavailable;
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
    reconstruction: *const reconstruction_mod.VerifiedReconstructionV1,
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
    try builder.reserve(
        input_count,
        @as(usize, manifest.total_constraints) +
            composition_v3.STATEMENT_WORD_COUNT + 768,
    );
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
    for (statement_words, reconstruction.session.parent_statement_words) |
        actual,
        expected,
    | try builder.constrainZero(actual.sub(recorder.Scalar.fromBase(expected)));
    try builder.constrainZero(public_wire_boundary);
    _ = try composition_v3.recordClaimPolicyConstraintsForManifestPolicy(
        &builder,
        &child_kind_selectors,
        &claim_inputs,
        graph_mod.CLAIM_MANIFEST_FAMILY,
        .canonical_empty,
    );
    var claimed_total = recorder.Scalar.zero();
    for (claim_inputs[0..graph_mod.PHYSICAL_CLAIM_COUNT]) |claim|
        claimed_total = claimed_total.add(claim);
    try builder.constrainZero(claimed_total
        .add(recorder.Scalar.fromSecure(
            reconstruction.audited.wire_boundary.claimed_sum,
        ))
        .add(recorder.Scalar.fromSecure(
        reconstruction.audited.verifier_input_boundary.claimed_sum,
    )));

    var denominators: recorder.DenominatorCache =
        .{null} ** stwo_core.circle.M31_CIRCLE_LOG_ORDER;
    var program = try graph_mod.ProgramRecorder.initAuthenticatedBinary(
        &builder,
        manifest,
        graph_mod.MANIFEST_FAMILY,
        layout,
        sampled_values,
        &claim_inputs,
        &challenges,
        composition_randomness,
        oods_point,
        &denominators,
    );
    const recorded = try graph_mod.recordCohort(&program, components);
    try builder.constrainZero(split_composition.sub(recorded.accumulation));
    try builder.check();
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    try composition.validateRecursionBindings(.{
        .verifier_id = recursion.binary_fri_outer_source
            .LEFT_RECURSION_VERIFIER_ID,
        .circuit_id = CIRCUIT_ID,
        .statement_scope = recursion.binary_fri_outer_source
            .LEFT_COMPOSITION_STATEMENT_SCOPE,
        .graph = circuit.graph(),
        .profile = graph_profile,
        .bindings = bindings,
    });
    return .{ .circuit = circuit, .bindings = bindings };
}

fn writeInputs(
    profile: composition_v3.InputProfileV3,
    claim_inputs: *const graph_mod.ClaimInputsV1,
    reconstruction: *const reconstruction_mod.VerifiedReconstructionV1,
    capture: *const OuterProofCapture,
    destination: []QM31,
) !void {
    try composition_v3.writeInputsFromValidatedProfileAndManifestPolicy(
        profile,
        graph_mod.CLAIM_MANIFEST_FAMILY,
        .ethereum_poseidon_h1,
        .{
            .parent_binary_selector = true,
            .proof_kind = .binary_node,
            .statement_words = &reconstruction.session.parent_statement_words,
            .sampled_values = capture.sampled_values,
            .claim_inputs = &claim_inputs.values,
            .public_wire_boundary = QM31.zero(),
            .relations = &reconstruction.relations,
            .composition_randomness = capture.composition_randomness,
            .oods_seed = capture.oods_seed,
        },
        destination,
    );
}

fn captureIdentity(value: *const CaptureV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CAPTURE_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hash.update(&value.reserved);
    hash.update(&value.reconstruction_identity_sha256);
    hash.update(&value.manifest_seal);
    hash.update(&value.layout.identity);
    hash.update(&value.claim_inputs.identity_sha256);
    hash.update(&value.circuit.identity_digest);
    hashInt(&hash, u32, @as(u32, @intCast(value.bindings.len)));
    hashInt(&hash, u32, @as(u32, @intCast(value.input_values.len)));
    hashInt(&hash, u32, @as(u32, @intCast(value.node_values.len)));
    for (value.input_values) |item| hashQm31(&hash, item);
    for (value.node_values) |item| hashQm31(&hash, item);
    return hash.finalResult();
}

fn bindingsEql(
    left: []const composition.RecursionInputBinding,
    right: []const composition.RecursionInputBinding,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}

fn qm31SliceEql(left: []const QM31, right: []const QM31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!a.eql(b)) return false;
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
    if (PRODUCTION_ACTIVATION or PARENT_ADMISSION_AVAILABLE)
        @compileError("secure child H1 capture activated before parent admission");
}

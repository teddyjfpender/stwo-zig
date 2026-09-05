//! Verifier-rerecorded composition capture for a canonical-empty wrapper.
//!
//! A retained q193 proof is first cold verified by the native engine.  This
//! owner then rebuilds the exact relations, interactions, claim vector, PCS
//! sample layout, 36 physical components, composition graph, and lowering
//! evaluation.  Its lane/evaluation view has no codec and is exposed only by
//! `revalidateAndView`, or through a verifier-minted process-local token that
//! closes the same exact retained allocations without a second graph replay.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const cohort_mod =
    @import("recursive_common_canonical_empty_universal_cohort_v2.zig");
const graph_mod =
    @import("recursive_common_canonical_empty_composition_graph_v2.zig");
const validation_token =
    @import("recursive_process_local_validation_token_v1.zig");
const manifest_mod =
    @import("recursive_common_canonical_empty_universal_manifest_v2.zig");
const publication =
    @import("recursive_segment_v2_verified_publication.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

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

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const CIRCUIT_ID: u32 = 751;
pub const PRODUCTION_ACTIVATION = false;

const CAPTURE_DOMAIN =
    "stwo-zig/common-canonical-empty-composition-capture/v2\x00";

pub const QUERY_WORD_COUNT: usize = 193;
pub const TranscriptDigestV2 = recursion.poseidon2_channel.Digest;

/// Live verifier replay authority for recursive row 20. The words are the
/// complete field draws, never the masked Merkle positions in `capture`.
/// This value has no codec and is copied into the cold-proof owner only after
/// the engine has replayed and authenticated the terminal transcript frames.
pub const VerifierQueryAuthorityV2 = struct {
    query_words: [QUERY_WORD_COUNT]M31,
    query_log_size: u32,
    final_transcript_digest: TranscriptDigestV2,
    final_transcript_draw_count: u32,
    query_words_identity_sha256: [32]u8,

    pub fn init(replay: *const graph_mod.VerifiedReplay) !VerifierQueryAuthorityV2 {
        const result = VerifierQueryAuthorityV2{
            .query_words = replay.query_words,
            .query_log_size = replay.query_log_size,
            .final_transcript_digest = replay.final_transcript_digest,
            .final_transcript_draw_count = replay.final_transcript_draw_count,
            .query_words_identity_sha256 = replay.query_words_identity_sha256,
        };
        try result.validateAgainstReplay(replay);
        return result;
    }

    pub fn validateAgainst(
        self: *const VerifierQueryAuthorityV2,
        replay: *const graph_mod.VerifiedReplay,
        fresh: *const secure_engine.FreshVerificationV1,
    ) !void {
        try replay.validateQueryWordsAgainst(fresh);
        try self.validateAgainstReplay(replay);
    }

    fn validateAgainstReplay(
        self: *const VerifierQueryAuthorityV2,
        replay: *const graph_mod.VerifiedReplay,
    ) !void {
        if (!m31SliceEql(&self.query_words, &replay.query_words) or
            self.query_log_size != replay.query_log_size or
            !std.meta.eql(
                self.final_transcript_digest,
                replay.final_transcript_digest,
            ) or self.final_transcript_draw_count !=
            replay.final_transcript_draw_count or
            !std.mem.eql(
                u8,
                &self.query_words_identity_sha256,
                &replay.query_words_identity_sha256,
            )) return error.InvalidCanonicalEmptyQueryAuthority;
    }
};

/// Borrowed live capability. Every slice is backed by a `CaptureV2` that was
/// rechecked against the current cold proof transaction immediately before
/// this value was returned.
pub const FreshGraphViewV2 = struct {
    capture_identity_sha256: *const [32]u8,
    layout_identity_sha256: *const [32]u8,
    query_words: *const [QUERY_WORD_COUNT]M31,
    query_log_size: u32,
    final_transcript_digest: *const TranscriptDigestV2,
    final_transcript_draw_count: u32,
    query_words_identity_sha256: *const [32]u8,
    lane: composition.RecursionLane,
    evaluation: lowering.Evaluation,
};

pub const CaptureV2 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    session_identity_sha256: [32]u8,
    statement_identity_sha256: [32]u8,
    claims_sha256: [32]u8,
    transcript_audit_sha256: [32]u8,
    cohort_audit_sha256: [32]u8,
    closure_sha256: [32]u8,
    manifest_seal: [32]u8,
    layout: capture_layout.CaptureLayoutV3,
    profile: composition_v3.InputProfileV3,
    claim_inputs: graph_mod.ClaimInputsV2,
    circuit: recorder.Circuit,
    bindings: []composition.RecursionInputBinding,
    input_values: []QM31,
    node_values: []QM31,
    identity_sha256: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        cohort: *cohort_mod.CohortV2,
        session: *const secure_artifact.SessionV1,
        statement: *const secure_artifact.StatementV1,
        capture: *const OuterProofCapture,
        replay: *const graph_mod.VerifiedReplay,
    ) !CaptureV2 {
        try validateTransaction(
            cohort,
            session,
            statement,
            capture,
            replay,
        );
        const manifest = cohort.manifest();
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
        const claim_inputs = try graph_mod.ClaimInputsV2.init(replay);
        var components = try cohort.initComponents(
            &replay.generated,
            &replay.relations,
            &replay.provider_relations,
        );
        defer components.deinit();
        var program = try recordProgram(
            allocator,
            manifest,
            &layout,
            profile,
            &components,
            session,
            replay,
        );
        errdefer program.deinit();

        const input_count = try composition.recursionInputCount(
            profile.graphProfile(),
        );
        const input_values = try allocator.alloc(QM31, input_count);
        errdefer allocator.free(input_values);
        const node_values = try allocator.alloc(QM31, program.circuit.nodes.len);
        errdefer allocator.free(node_values);
        try writeInputs(
            profile,
            &claim_inputs,
            session,
            replay,
            capture,
            input_values,
        );
        try program.circuit.evaluateInto(input_values, node_values);

        var result = CaptureV2{
            .allocator = allocator,
            .session_identity_sha256 = session.identity_sha256,
            .statement_identity_sha256 = statement.identity_sha256,
            .claims_sha256 = replay.claims.seal,
            .transcript_audit_sha256 = replay.transcript_audit_sha256,
            .cohort_audit_sha256 = replay.audited.identity_sha256,
            .closure_sha256 = replay.audited.closure.closure_id,
            .manifest_seal = manifest.seal,
            .layout = layout,
            .profile = profile,
            .claim_inputs = claim_inputs,
            .circuit = program.circuit,
            .bindings = program.bindings,
            .input_values = input_values,
            .node_values = node_values,
            .identity_sha256 = undefined,
        };
        program.moved = true;
        layout = undefined;
        result.identity_sha256 = captureIdentity(&result);
        errdefer result.deinit();
        try result.validateProcessLocalRetained();
        return result;
    }

    pub fn deinit(self: *CaptureV2) void {
        self.allocator.free(self.node_values);
        self.allocator.free(self.input_values);
        self.allocator.free(self.bindings);
        self.circuit.deinit();
        self.layout.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const CaptureV2,
        cohort: *cohort_mod.CohortV2,
        session: *const secure_artifact.SessionV1,
        statement: *const secure_artifact.StatementV1,
        capture: *const OuterProofCapture,
        replay: *const graph_mod.VerifiedReplay,
        rerecord_program: bool,
    ) !void {
        try validateTransaction(
            cohort,
            session,
            statement,
            capture,
            replay,
        );
        const manifest = cohort.manifest();
        try self.layout.validateAgainstAuthenticatedBinary(
            graph_mod.MANIFEST_FAMILY,
            manifest,
        );
        try self.claim_inputs.validateAgainst(replay);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            !std.mem.eql(
                u8,
                &self.session_identity_sha256,
                &session.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.statement_identity_sha256,
            &statement.identity_sha256,
        ) or !std.mem.eql(u8, &self.claims_sha256, &replay.claims.seal) or
            !std.mem.eql(
                u8,
                &self.transcript_audit_sha256,
                &replay.transcript_audit_sha256,
            ) or !std.mem.eql(
            u8,
            &self.cohort_audit_sha256,
            &replay.audited.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.closure_sha256,
            &replay.audited.closure.closure_id,
        ) or !std.mem.eql(u8, &self.manifest_seal, &manifest.seal)) {
            return error.InvalidCanonicalEmptyCompositionCapture;
        }
        const expected_inputs = try self.allocator.alloc(
            QM31,
            self.input_values.len,
        );
        defer self.allocator.free(expected_inputs);
        try writeInputs(
            self.profile,
            &self.claim_inputs,
            session,
            replay,
            capture,
            expected_inputs,
        );
        if (!qm31SliceEql(self.input_values, expected_inputs))
            return error.InvalidCanonicalEmptyCompositionCapture;
        try self.validateRetained();
        if (!rerecord_program) return;

        var components = try cohort.initComponents(
            &replay.generated,
            &replay.relations,
            &replay.provider_relations,
        );
        defer components.deinit();
        var expected = try recordProgram(
            self.allocator,
            manifest,
            &self.layout,
            self.profile,
            &components,
            session,
            replay,
        );
        defer expected.deinit();
        if (!std.mem.eql(
            u8,
            &self.circuit.identity_digest,
            &expected.circuit.identity_digest,
        ) or !bindingsEql(self.bindings, expected.bindings)) {
            return error.InvalidCanonicalEmptyCompositionCapture;
        }
    }

    pub fn validateRetained(self: *const CaptureV2) !void {
        try self.layout.validateSelfConsistency();
        try self.profile.validate();
        try self.circuit.validate();
        if (self.input_values.len != try composition.recursionInputCount(
            self.profile.graphProfile(),
        ) or self.node_values.len != self.circuit.nodes.len or
            !std.mem.eql(u8, &self.identity_sha256, &captureIdentity(self)))
        {
            return error.InvalidCanonicalEmptyCompositionCapture;
        }
        try composition.validateRecursionBindings(self.lane());
        const values = try self.allocator.alloc(QM31, self.circuit.nodes.len);
        defer self.allocator.free(values);
        try self.circuit.evaluateInto(self.input_values, values);
        if (!qm31SliceEql(self.node_values, values))
            return error.InvalidCanonicalEmptyCompositionCapture;
    }

    /// Cheap view reborrow after the owning cold proof has validated `token`.
    /// The exact graph allocations and identities must still match the token;
    /// no digest is promoted into verifier freshness by this method.
    pub fn borrowProcessLocalView(
        self: *const CaptureV2,
        query_authority: *const VerifierQueryAuthorityV2,
        token: *const validation_token.TokenV1,
    ) !FreshGraphViewV2 {
        try self.validateProcessLocalClosure(token);
        return .{
            .capture_identity_sha256 = &self.identity_sha256,
            .layout_identity_sha256 = &self.layout.identity,
            .query_words = &query_authority.query_words,
            .query_log_size = query_authority.query_log_size,
            .final_transcript_digest = &query_authority.final_transcript_digest,
            .final_transcript_draw_count = query_authority.final_transcript_draw_count,
            .query_words_identity_sha256 = &query_authority.query_words_identity_sha256,
            .lane = self.lane(),
            .evaluation = self.evaluation(),
        };
    }

    /// Constant-time closure check for an immutable, already validated graph.
    /// Hostile content mutation remains covered by `validateRetained`; normal
    /// capability extraction checks only the token-sealed identities and exact
    /// allocations and therefore performs no graph hashing or evaluation.
    pub fn validateProcessLocalClosure(
        self: *const CaptureV2,
        token: *const validation_token.TokenV1,
    ) !void {
        const snapshot = token.snapshot;
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            !std.mem.eql(
                u8,
                &snapshot.graph_capture_identity_sha256,
                &self.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &snapshot.graph_layout_identity_sha256,
            &self.layout.identity,
        ) or !std.mem.eql(
            u8,
            &snapshot.graph_circuit_identity_sha256,
            &self.circuit.identity_digest,
        ) or snapshot.graph_node_ptr != @intFromPtr(self.circuit.nodes.ptr) or
            snapshot.graph_node_len != self.circuit.nodes.len or
            snapshot.graph_binding_ptr != @intFromPtr(self.bindings.ptr) or
            snapshot.graph_binding_len != self.bindings.len or
            snapshot.graph_input_ptr != @intFromPtr(self.input_values.ptr) or
            snapshot.graph_input_len != self.input_values.len or
            snapshot.graph_output_ptr != @intFromPtr(self.node_values.ptr) or
            snapshot.graph_output_len != self.node_values.len)
        {
            return error.InvalidCanonicalEmptyCompositionCapture;
        }
    }

    /// Recomputes all retained graph seals and pointer-independent identities,
    /// but deliberately does not rerun q193, rerecord, or reevaluate nodes.
    pub fn validateProcessLocalRetained(self: *const CaptureV2) !void {
        try self.layout.validateSelfConsistency();
        try self.profile.validate();
        try self.circuit.validate();
        if (self.input_values.len != try composition.recursionInputCount(
            self.profile.graphProfile(),
        ) or self.node_values.len != self.circuit.nodes.len or
            !std.mem.eql(u8, &self.identity_sha256, &captureIdentity(self)))
        {
            return error.InvalidCanonicalEmptyCompositionCapture;
        }
        try composition.validateRecursionBindings(self.lane());
    }

    /// Deep hostile-boundary audit. Normal extraction from an already cold
    /// owner uses `borrowProcessLocalView` after its nonserializable token has
    /// closed these exact allocations.
    pub fn revalidateAndView(
        self: *const CaptureV2,
        cohort: *cohort_mod.CohortV2,
        session: *const secure_artifact.SessionV1,
        fresh: *const secure_engine.FreshVerificationV1,
        replay: *const graph_mod.VerifiedReplay,
        query_authority: *const VerifierQueryAuthorityV2,
    ) !FreshGraphViewV2 {
        try self.validateAgainst(
            cohort,
            session,
            &fresh.statement,
            &fresh.capture,
            replay,
            true,
        );
        try query_authority.validateAgainst(replay, fresh);
        return .{
            .capture_identity_sha256 = &self.identity_sha256,
            .layout_identity_sha256 = &self.layout.identity,
            .query_words = &query_authority.query_words,
            .query_log_size = query_authority.query_log_size,
            .final_transcript_digest = &query_authority.final_transcript_digest,
            .final_transcript_draw_count = query_authority.final_transcript_draw_count,
            .query_words_identity_sha256 = &query_authority.query_words_identity_sha256,
            .lane = self.lane(),
            .evaluation = self.evaluation(),
        };
    }

    fn lane(self: *const CaptureV2) composition.RecursionLane {
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

    fn evaluation(self: *const CaptureV2) lowering.Evaluation {
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
    components: *const cohort_mod.ComponentSetV2,
    session: *const secure_artifact.SessionV1,
    replay: *const graph_mod.VerifiedReplay,
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
    var kind_selectors: [composition_v3.PROGRAM_KIND_COUNT]recorder.Scalar =
        undefined;
    @memcpy(
        &kind_selectors,
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
    for (kind_selectors, 0..) |selector, index| try builder.constrainZero(
        selector.sub(if (index == composition_v3.proofKindIndex(.binary_node))
            one
        else
            recorder.Scalar.zero()),
    );
    for (statement_words, session.parent_statement_words) |actual, expected|
        try builder.constrainZero(actual.sub(recorder.Scalar.fromBase(expected)));
    _ = try composition_v3.recordClaimPolicyConstraintsForManifestPolicy(
        &builder,
        &kind_selectors,
        &claim_inputs,
        graph_mod.CLAIM_MANIFEST_FAMILY,
        graph_mod.CLAIM_POLICY,
    );
    try builder.constrainZero(public_wire_boundary.sub(
        recorder.Scalar.fromSecure(replay.audited.wire_boundary.claimed_sum),
    ));
    var claimed_total = recorder.Scalar.zero();
    for (claim_inputs[0..graph_mod.PHYSICAL_CLAIM_COUNT]) |claim|
        claimed_total = claimed_total.add(claim);
    try builder.constrainZero(claimed_total
        .add(public_wire_boundary)
        .add(recorder.Scalar.fromSecure(
        replay.audited.verifier_input_boundary.claimed_sum,
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
    claim_inputs: *const graph_mod.ClaimInputsV2,
    session: *const secure_artifact.SessionV1,
    replay: *const graph_mod.VerifiedReplay,
    capture: *const OuterProofCapture,
    destination: []QM31,
) !void {
    try composition_v3.writeInputsFromValidatedProfileAndManifestPolicy(
        profile,
        graph_mod.CLAIM_MANIFEST_FAMILY,
        graph_mod.CLAIM_POLICY,
        .{
            .parent_binary_selector = true,
            .proof_kind = .binary_node,
            .statement_words = &session.parent_statement_words,
            .sampled_values = capture.sampled_values,
            .claim_inputs = &claim_inputs.values,
            .public_wire_boundary = replay.audited.wire_boundary.claimed_sum,
            .relations = &replay.relations,
            .composition_randomness = capture.composition_randomness,
            .oods_seed = capture.oods_seed,
        },
        destination,
    );
}

fn validateTransaction(
    cohort: *cohort_mod.CohortV2,
    session: *const secure_artifact.SessionV1,
    statement: *const secure_artifact.StatementV1,
    capture: *const OuterProofCapture,
    replay: *const graph_mod.VerifiedReplay,
) !void {
    try cohort.validate();
    try cohort.validateSession(session);
    try statement.validateAgainstSession(session);
    try replay.validateAgainst(cohort);
    try replay.validateStatementAudit(statement.audit_sha256);
    if (session.source_kind != .canonical_empty_wrapper_v1 or
        !std.meta.eql(statement.capture_id, publication.captureIdentity(capture)) or
        !std.mem.eql(u8, &statement.claims_sha256, &replay.claims.seal) or
        !std.mem.eql(
            u8,
            &statement.closure_sha256,
            &replay.audited.closure.closure_id,
        )) return error.InvalidCanonicalEmptyCompositionCapture;
}

fn captureIdentity(value: *const CaptureV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CAPTURE_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hash.update(&value.reserved);
    hash.update(&value.session_identity_sha256);
    hash.update(&value.statement_identity_sha256);
    hash.update(&value.claims_sha256);
    hash.update(&value.transcript_audit_sha256);
    hash.update(&value.cohort_audit_sha256);
    hash.update(&value.closure_sha256);
    hash.update(&value.manifest_seal);
    hash.update(&value.layout.identity);
    hash.update(&value.circuit.identity_digest);
    hashInt(&hash, u32, @as(u32, @intCast(value.bindings.len)));
    for (value.bindings) |binding| {
        hashInt(&hash, u32, binding.node_id);
        hashRecursionSource(&hash, binding.source);
    }
    for (value.claim_inputs.values) |item| hashQm31(&hash, item);
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

fn m31SliceEql(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!lhs.eql(rhs)) return false;
    return true;
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashRecursionSource(
    hash: *Sha256,
    source: composition.RecursionSource,
) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(source)));
    switch (source) {
        .parent_binary_selector => {},
        .child_kind_selector => |kind| hashInt(
            hash,
            u8,
            @intFromEnum(kind),
        ),
        .statement_word => |word| hashInt(hash, u32, word),
        .sampled_value,
        .claimed_sum,
        .transcript_claimed_sum,
        .public_wire_boundary,
        => |coordinate| {
            hashInt(hash, u32, coordinate.item_index);
            hashInt(hash, u32, coordinate.word_index);
        },
        .relation_challenge => |coordinate| {
            hashInt(hash, u32, coordinate.challenge);
            hashInt(hash, u32, coordinate.word_index);
        },
        .composition_randomness,
        .oods_point,
        => |word| hashInt(hash, u32, word),
    }
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or CIRCUIT_ID != 751 or
        manifest_mod.COMPONENT_COUNT != 36)
    {
        @compileError("canonical-empty composition capture drifted");
    }
}

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact = @import("recursive_segment_v2_verified_artifact.zig");
const publication_mod = @import("recursive_segment_v2_verified_publication.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
const catalog_mod = recursion.air.segment_outer_typed_catalog_v2;
const universal = recursion.air.universal_challenges;
const universal_manifest = recursion.air.universal_manifest;
const universal_roster = recursion.air.universal_roster;
const boundary_air = recursion.segment_leaf_outer_air_v2;
const boundary_manifest = recursion.segment_leaf_outer_authority_v2;
const provider_authority =
    recursion.segment_publication_input_provider_authority_v2;
const row17_witness = recursion.air.vm_public_logup_control_witness_v2;
const range_bridge = recursion.air.range_check_8_8_bridge;

test "SegmentV2 recursive-witness fixed preflight rejects mutation fleet" {
    var fixture = try Fixture.init();
    try fixture.validate();

    var malformed = fixture;
    malformed.witness.schema_version +%= 1;
    try std.testing.expectError(
        error.UnsupportedFormat,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.relation_draw_count -= 1;
    try std.testing.expectError(
        error.UnsupportedFormat,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.padding[2] = 1;
    try std.testing.expectError(
        error.UnsupportedFormat,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );

    malformed = fixture;
    malformed.witness.transcript_prefix.format_version +%= 1;
    try std.testing.expectError(
        error.InvalidTranscriptPrefix,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.transcript_prefix.schema_version +%= 1;
    try std.testing.expectError(
        error.InvalidTranscriptPrefix,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.transcript_prefix.padding[0] = 1;
    try std.testing.expectError(
        error.InvalidTranscriptPrefix,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );

    inline for (.{
        "noncore_authority_sha_id",
        "core_authority_sha_id",
        "core_layout_sha_id",
        "core_call_buffer_sha_id",
        "public_wire_boundary_sha_id",
    }) |field_name| {
        malformed = fixture;
        @memset(&@field(malformed.witness.transcript_prefix, field_name), 0);
        try std.testing.expectError(
            error.InvalidTranscriptPrefix,
            malformed.witness.validateAgainstValidatedPublication(
                &malformed.publication,
                &malformed.manifest,
            ),
        );
    }

    malformed = fixture;
    malformed.witness.transcript_prefix.core_total_call_count = 0;
    try std.testing.expectError(
        error.InvalidTranscriptPrefix,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.transcript_prefix.core_total_call_count = m31.Modulus;
    try std.testing.expectError(
        error.InvalidTranscriptPrefix,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.transcript_prefix.public_wire_boundary_term_count = 0;
    try std.testing.expectError(
        error.InvalidTranscriptPrefix,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.transcript_prefix.public_wire_boundary_term_count =
        m31.Modulus;
    try std.testing.expectError(
        error.InvalidTranscriptPrefix,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.transcript_prefix.public_wire_boundary_claimed_sum.c0.a =
        M31.fromU32Unchecked(m31.Modulus);
    try std.testing.expectError(
        error.NonCanonicalField,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );

    inline for (.{
        "noncore_authority_sha_id",
        "core_layout_sha_id",
        "core_call_buffer_sha_id",
    }) |field_name| {
        malformed = fixture;
        @field(malformed.witness.transcript_prefix, field_name)[0] ^= 1;
        try std.testing.expectError(
            error.TranscriptPrefixIdentityMismatch,
            malformed.witness.validateAgainstValidatedPublication(
                &malformed.publication,
                &malformed.manifest,
            ),
        );
    }
    malformed = fixture;
    malformed.witness.transcript_prefix.core_authority_sha_id[0] ^= 1;
    try std.testing.expectError(
        error.TranscriptPrefixBoundaryMismatch,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.transcript_prefix.core_total_call_count += 1;
    try std.testing.expectError(
        error.TranscriptPrefixIdentityMismatch,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.transcript_prefix.public_wire_boundary_term_count += 1;
    try std.testing.expectError(
        error.TranscriptPrefixBoundaryMismatch,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.transcript_prefix.public_wire_boundary_claimed_sum =
        malformed.witness.transcript_prefix.public_wire_boundary_claimed_sum
            .add(QM31.one());
    try std.testing.expectError(
        error.TranscriptPrefixBoundaryMismatch,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.transcript_prefix.public_wire_boundary_sha_id[0] ^= 1;
    try std.testing.expectError(
        error.TranscriptPrefixBoundaryMismatch,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.transcript_prefix.transcript_prefix_id[0] ^= 1;
    try std.testing.expectError(
        error.TranscriptPrefixIdentityMismatch,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );

    inline for (.{
        "proof_id",
        "capture_id",
        "statement_id",
        "air_program_id",
        "manifest_id",
        "profile_id",
    }) |field_name| {
        malformed = fixture;
        @field(malformed.witness, field_name)[0] ^= 1;
        try std.testing.expectError(
            error.PublicationLinkMismatch,
            malformed.witness.validateAgainstValidatedPublication(
                &malformed.publication,
                &malformed.manifest,
            ),
        );
    }

    for (0..artifact.CLAIM_COUNT) |index| {
        malformed = fixture;
        malformed.witness.claimed_sums[index] =
            malformed.witness.claimed_sums[index].add(QM31.one());
        try std.testing.expectError(
            error.ClaimSealMismatch,
            malformed.witness.validateAgainstValidatedPublication(
                &malformed.publication,
                &malformed.manifest,
            ),
        );
    }

    for (0..artifact.RELATION_DRAW_COUNT) |index| {
        malformed = fixture;
        malformed.witness.relation_draws[index] =
            malformed.witness.relation_draws[index].add(QM31.one());
        try std.testing.expectError(
            error.RelationDrawsIdentityMismatch,
            malformed.witness.validateAgainstValidatedPublication(
                &malformed.publication,
                &malformed.manifest,
            ),
        );
    }

    inline for (0..artifact.POSEIDON2_PARTIAL_COUNT) |index| {
        malformed = fixture;
        malformed.witness.poseidon2_partials[index] =
            malformed.witness.poseidon2_partials[index].add(QM31.one());
        try std.testing.expectError(
            error.Poseidon2PartialMismatch,
            malformed.witness.validateAgainstValidatedPublication(
                &malformed.publication,
                &malformed.manifest,
            ),
        );
    }

    malformed = fixture;
    std.mem.swap(
        QM31,
        &malformed.witness.poseidon2_partials[0],
        &malformed.witness.poseidon2_partials[1],
    );
    try std.testing.expectError(
        error.Poseidon2PartialsIdentityMismatch,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );

    malformed = fixture;
    const delta = QM31.fromU32Unchecked(1, 2, 3, 4);
    malformed.witness.poseidon2_partials[0] =
        malformed.witness.poseidon2_partials[0].add(delta);
    malformed.witness.poseidon2_partials[1] =
        malformed.witness.poseidon2_partials[1].sub(delta);
    try std.testing.expectError(
        error.Poseidon2PartialsIdentityMismatch,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );

    malformed = fixture;
    malformed.witness.relation_draws_id[0] ^= 1;
    try std.testing.expectError(
        error.RelationDrawsIdentityMismatch,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.poseidon2_partials_id[0] ^= 1;
    try std.testing.expectError(
        error.Poseidon2PartialsIdentityMismatch,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.witness.witness_id[0] ^= 1;
    try std.testing.expectError(
        error.PublicationLinkMismatch,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
    malformed = fixture;
    malformed.publication.recursive_witness_id[0] ^= 1;
    try std.testing.expectError(
        error.PublicationLinkMismatch,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );

    malformed = fixture;
    malformed.manifest.seal[0] ^= 1;
    try std.testing.expectError(
        error.ManifestSealMismatch,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );

    malformed = fixture;
    malformed.witness.relation_draws[0].c0.a =
        M31.fromU32Unchecked(m31.Modulus);
    try std.testing.expectError(
        error.NonCanonicalField,
        malformed.witness.validateAgainstValidatedPublication(
            &malformed.publication,
            &malformed.manifest,
        ),
    );
}

test "SegmentV2 recursive-witness capture preflight hashes exact capture once" {
    var fixture = try Fixture.init();
    var capture = emptyCapture();
    const capture_id = publication_mod.captureIdentity(&capture);
    fixture.publication.capture_id = capture_id;
    fixture.witness.capture_id = capture_id;
    fixture.reseal();

    try artifact.preflightAgainstValidatedPublication(
        &capture,
        &fixture.publication,
        &fixture.witness,
        &fixture.manifest,
    );
    capture.proof_of_work = 1;
    try std.testing.expectError(
        error.CaptureIdentityMismatch,
        artifact.preflightAgainstValidatedPublication(
            &capture,
            &fixture.publication,
            &fixture.witness,
            &fixture.manifest,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        artifact.CAPTURE_ID_HASHES_PER_PREFLIGHT,
    );
}

const Fixture = struct {
    manifest: manifest_mod.Manifest,
    publication: publication_mod.VerifiedSegmentV2PublicationV1,
    witness: artifact.RecursiveWitnessV1,

    fn init() !Fixture {
        const manifest = try fixtureManifest();
        var claimed_sums: [artifact.CLAIM_COUNT]QM31 = undefined;
        for (&claimed_sums, 0..) |*claim, index| claim.* =
            QM31.fromU32Unchecked(
                @intCast(11 + index),
                @intCast(101 + index),
                @intCast(211 + index),
                @intCast(307 + index),
            );
        const partials = [artifact.POSEIDON2_PARTIAL_COUNT]QM31{
            QM31.fromU32Unchecked(401, 409, 419, 421),
            QM31.fromU32Unchecked(431, 433, 439, 443),
        };
        claimed_sums[artifact.POSEIDON2_ROSTER_ROW] =
            partials[0].add(partials[1]);

        var claims = try manifest_mod.ClaimVector.init(&manifest);
        for (claimed_sums, 0..) |claim, row|
            try claims.bind(@enumFromInt(row), claim);
        try claims.sealClaims(&manifest);

        const relations = universal.UniversalRelations.dummy();
        var relation_draws: [artifact.RELATION_DRAW_COUNT]QM31 = undefined;
        for (relations.elements, 0..) |element, index| {
            relation_draws[2 * index] = element.z;
            relation_draws[2 * index + 1] = element.alpha;
        }

        var publication: publication_mod.VerifiedSegmentV2PublicationV1 =
            undefined;
        @memset(std.mem.asBytes(&publication), 0);
        publication.proof_id = nativeDigest(11);
        publication.capture_id = nativeDigest(31);
        publication.statement_id = nativeDigest(51);
        publication.air_program_id = nativeDigest(71);
        publication.manifest_id =
            publication_mod.expectedManifestId(manifest.seal);
        publication.profile_id = nativeDigest(91);
        publication.manifest_sha_id = manifest.seal;
        publication.relation_registry_sha_id = shaDigest(111);
        publication.closure.claim_seal_sha_id = claims.seal;
        publication.closure.generated_interactions_sha_id = shaDigest(131);
        publication.closure.audit_sha_id = shaDigest(151);

        const core_authority_sha_id = shaDigest(37);
        const transcript_prefix = try artifact.TranscriptPrefixV1.init(
            shaDigest(17),
            core_authority_sha_id,
            shaDigest(57),
            shaDigest(77),
            1_193,
            try recursion.segment_outer_cohort_v2.PublicWireBoundaryV2.init(
                core_authority_sha_id,
                521,
                QM31.fromU32Unchecked(5, 7, 11, 13),
            ),
        );

        const witness = artifact.RecursiveWitnessV1{
            .proof_id = publication.proof_id,
            .capture_id = publication.capture_id,
            .statement_id = publication.statement_id,
            .air_program_id = publication.air_program_id,
            .manifest_id = publication.manifest_id,
            .profile_id = publication.profile_id,
            .claimed_sums = claimed_sums,
            .relation_draws = relation_draws,
            .poseidon2_partials = partials,
            .transcript_prefix = transcript_prefix,
            .outer_admission = undefined,
            .relation_draws_id = undefined,
            .poseidon2_partials_id = undefined,
            .witness_id = undefined,
        };
        var result = Fixture{
            .manifest = manifest,
            .publication = publication,
            .witness = witness,
        };
        result.reseal();
        return result;
    }

    fn reseal(self: *Fixture) void {
        self.witness.proof_id = self.publication.proof_id;
        self.witness.capture_id = self.publication.capture_id;
        self.witness.statement_id = self.publication.statement_id;
        self.witness.air_program_id = self.publication.air_program_id;
        self.witness.manifest_id = self.publication.manifest_id;
        self.witness.profile_id = self.publication.profile_id;
        var component_log_sizes: [artifact.CLAIM_COUNT]u32 = undefined;
        for (&component_log_sizes, 0..) |*log_size, row|
            log_size.* = self.manifest.placements[row].?.geometry.log_size;
        self.witness.outer_admission = .{
            .proof_id = self.publication.proof_id,
            .capture_id = self.publication.capture_id,
            .component_log_sizes = component_log_sizes,
            .pre_core_channel = .{
                .digest = nativeDigest(401),
                .draw_count = 0,
            },
            .claimed_sums = self.witness.claimed_sums,
            .verifier_input_boundary = QM31.fromU32Unchecked(17, 19, 23, 29),
            .wire_closure = .{
                self.witness.transcript_prefix
                    .public_wire_boundary_claimed_sum.neg(),
                self.witness.transcript_prefix
                    .public_wire_boundary_claimed_sum,
            },
            .receipt_id = undefined,
        };
        self.witness.outer_admission.receipt_id =
            artifact.outerAdmissionReceiptId(
                &self.witness.outer_admission,
                &self.publication,
            );
        self.witness.relation_draws_id = artifact.relationDrawsId(
            &self.witness,
            &self.publication,
        );
        self.witness.poseidon2_partials_id = artifact.poseidon2PartialsId(
            &self.witness,
            &self.publication,
        );
        self.witness.witness_id = artifact.witnessId(
            &self.witness,
            &self.publication,
        );
        self.publication.recursive_witness_id = self.witness.witness_id;
    }

    fn validate(self: *const Fixture) !void {
        try self.witness.validateAgainstValidatedPublication(
            &self.publication,
            &self.manifest,
        );
    }
};

fn fixtureManifest() !manifest_mod.Manifest {
    const catalog = try catalog_mod.build(
        fixtureLogSizes(),
        boundaryComponents(8),
    );
    return manifest_mod.assemble(&catalog, .{
        .transcript_manifest_id = nativeDigest(171),
        .statement_manifest_id = nativeDigest(191),
        .public_manifest_id = nativeDigest(211),
        .boundary_manifest_id = nativeDigest(231),
        .boundary_authority_sha_id = shaDigest(251),
        .provider_authority_sha_id = provider_authority.sourceAuthorityShaId(),
    });
}

fn fixtureLogSizes() universal_manifest.LogSizes {
    var result = [_]u32{4} ** universal_roster.COMPONENT_COUNT;
    result[0] = 5;
    result[1] = 6;
    result[5] = 7;
    result[11] = 8;
    result[12] = 5;
    result[15] = 6;
    result[16] = 5;
    result[17] = row17_witness.TRACE_LOG_SIZE;
    result[34] = 8;
    result[35] = range_bridge.LOG_SIZE;
    return result;
}

fn boundaryComponents(
    statement_log_size: u8,
) [boundary_manifest.COMPONENT_COUNT]boundary_manifest.ComponentGeometryV2 {
    return .{
        .{
            .kind = .statement_source,
            .component_tag = boundary_manifest.STATEMENT_COMPONENT_TAG,
            .logical_rows = (@as(u32, 1) <<
                @intCast(statement_log_size - 1)) + 1,
            .trace_log_size = statement_log_size,
            .trace_rows = @as(u32, 1) << @intCast(statement_log_size),
            .preprocessed_columns = boundary_air.Statement.PREPROCESSED_COLUMN_COUNT,
            .main_columns = boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = boundary_air.Statement.INTERACTION_COLUMN_COUNT,
            .direct_constraints = boundary_air.Statement.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = boundary_air.Statement.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = boundary_air.Statement.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = boundary_air.Statement.SEMANTIC_DIGEST,
        },
        .{
            .kind = .public_logup_source,
            .component_tag = boundary_manifest.PUBLIC_LOGUP_COMPONENT_TAG,
            .logical_rows = boundary_manifest.PUBLIC_LOGUP_LOGICAL_ROWS,
            .trace_log_size = boundary_manifest.PUBLIC_LOGUP_TRACE_LOG_SIZE,
            .trace_rows = boundary_manifest.PUBLIC_LOGUP_TRACE_ROWS,
            .preprocessed_columns = boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT,
            .main_columns = boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT,
            .direct_constraints = boundary_air.PublicLogUp.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = boundary_air.PublicLogUp.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = boundary_air.PublicLogUp.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = boundary_air.PublicLogUp.SEMANTIC_DIGEST,
        },
    };
}

fn emptyCapture() artifact.OuterProofCapture {
    return .{
        .queries = .{ .raw = &.{}, .unique = &.{} },
        .commitments = &.{},
        .column_log_sizes = &.{},
        .sampled_points = &.{},
        .sampled_values = &.{},
        .queried_values = &.{},
        .deep_answers = &.{},
        .trace_paths = &.{},
        .fri = .{ .layers = &.{} },
        .last_layer_coefficients = &.{},
        .proof_of_work = 0,
        .composition_randomness = QM31.zero(),
        .oods_seed = QM31.zero(),
        .deep_randomness = QM31.zero(),
    };
}

fn nativeDigest(seed: u32) publication_mod.Digest {
    var result: publication_mod.Digest = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn shaDigest(seed: u32) publication_mod.Sha256Digest {
    var result: publication_mod.Sha256Digest = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = @truncate(seed + @as(u32, @intCast(index)));
    return result;
}

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const profile_mod =
    @import("recursive_temporal_child_relation_profile.zig");
const artifact = @import("recursive_segment_v2_verified_artifact.zig");
const publication_mod =
    @import("recursive_segment_v2_verified_publication.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const universal = frontend.recursion.air.universal_challenges;

test "temporal child relation profile reconstructs exact ordered verifier draws" {
    const fixture = try Fixture.init();
    const relations = try fixture.profile.reconstructAgainstValidatedWitness(
        &fixture.publication,
        &fixture.witness,
    );

    try std.testing.expect(std.meta.eql(
        fixture.profile.relation_draws,
        fixture.witness.relation_draws,
    ));
    for (relations.elements, 0..) |element, relation_index| {
        try std.testing.expect(element.z.eql(
            fixture.profile.relation_draws[2 * relation_index],
        ));
        try std.testing.expect(element.alpha.eql(
            fixture.profile.relation_draws[2 * relation_index + 1],
        ));
    }
    try std.testing.expectEqual(
        @as(usize, 0),
        profile_mod.HEAP_ALLOCATIONS_PER_RECONSTRUCT,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        profile_mod.UNIVERSAL_RECONSTRUCTIONS_PER_RECONSTRUCT,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        profile_mod.RAW_DRAW_REHASHES_PER_DERIVE,
    );
}

test "temporal child relation profile rejects exact mutation fleet" {
    const fixture = try Fixture.init();
    try fixture.profile.validateAgainstValidatedWitness(
        &fixture.publication,
        &fixture.witness,
    );

    var malformed = fixture.profile;
    malformed.format_version +%= 1;
    try expectProfileError(error.UnsupportedFormat, &malformed, &fixture);
    malformed = fixture.profile;
    malformed.schema_version +%= 1;
    try expectProfileError(error.UnsupportedFormat, &malformed, &fixture);
    malformed = fixture.profile;
    malformed.relation_draw_count -= 1;
    try expectProfileError(error.UnsupportedFormat, &malformed, &fixture);
    malformed = fixture.profile;
    malformed.padding[2] = 1;
    try expectProfileError(error.UnsupportedFormat, &malformed, &fixture);

    malformed = fixture.profile;
    malformed.publication_id[0] ^= 1;
    try expectProfileError(error.PublicationLinkMismatch, &malformed, &fixture);
    malformed = fixture.profile;
    malformed.witness_id[0] ^= 1;
    try expectProfileError(error.PublicationLinkMismatch, &malformed, &fixture);
    malformed = fixture.profile;
    malformed.relation_draws_id[0] ^= 1;
    try expectProfileError(
        error.RelationDrawsIdentityMismatch,
        &malformed,
        &fixture,
    );
    malformed = fixture.profile;
    malformed.profile_id[0] ^= 1;
    try expectProfileError(
        error.RelationProfileIdentityMismatch,
        &malformed,
        &fixture,
    );

    for (0..profile_mod.RELATION_DRAW_COUNT) |draw_index| {
        malformed = fixture.profile;
        malformed.relation_draws[draw_index] =
            malformed.relation_draws[draw_index].add(QM31.one());
        try expectProfileError(
            error.RelationDrawsMismatch,
            &malformed,
            &fixture,
        );
    }

    malformed = fixture.profile;
    std.mem.swap(
        QM31,
        &malformed.relation_draws[0],
        &malformed.relation_draws[1],
    );
    try expectProfileError(error.RelationDrawsMismatch, &malformed, &fixture);

    malformed = fixture.profile;
    malformed.relation_draws[47].c0.a =
        M31.fromU32Unchecked(m31.Modulus);
    try expectProfileError(error.NonCanonicalField, &malformed, &fixture);
    malformed = fixture.profile;
    malformed.profile_id[0] = m31.Modulus;
    try expectProfileError(error.NonCanonicalField, &malformed, &fixture);
}

test "temporal child relation profile rejects publication and witness splice" {
    const fixture = try Fixture.init();

    var publication = fixture.publication;
    publication.publication_id[0] ^= 1;
    try std.testing.expectError(
        error.PublicationLinkMismatch,
        fixture.profile.validateAgainstValidatedWitness(
            &publication,
            &fixture.witness,
        ),
    );

    publication = fixture.publication;
    publication.recursive_witness_id[0] ^= 1;
    try std.testing.expectError(
        error.PublicationLinkMismatch,
        fixture.profile.validateAgainstValidatedWitness(
            &publication,
            &fixture.witness,
        ),
    );

    var witness = fixture.witness;
    witness.witness_id[0] ^= 1;
    try std.testing.expectError(
        error.PublicationLinkMismatch,
        fixture.profile.validateAgainstValidatedWitness(
            &fixture.publication,
            &witness,
        ),
    );
    witness = fixture.witness;
    witness.relation_draws_id[0] ^= 1;
    try std.testing.expectError(
        error.RelationDrawsIdentityMismatch,
        fixture.profile.validateAgainstValidatedWitness(
            &fixture.publication,
            &witness,
        ),
    );
}

fn expectProfileError(
    expected: anyerror,
    candidate: *const profile_mod.TemporalChildRelationProfileV1,
    fixture: *const Fixture,
) !void {
    try std.testing.expectError(
        expected,
        candidate.validateAgainstValidatedWitness(
            &fixture.publication,
            &fixture.witness,
        ),
    );
}

const Fixture = struct {
    publication: publication_mod.VerifiedSegmentV2PublicationV1,
    witness: artifact.RecursiveWitnessV1,
    profile: profile_mod.TemporalChildRelationProfileV1,

    fn init() !Fixture {
        var publication: publication_mod.VerifiedSegmentV2PublicationV1 =
            undefined;
        @memset(std.mem.asBytes(&publication), 0);
        publication.proof_id = nativeDigest(11);
        publication.capture_id = nativeDigest(31);
        publication.manifest_id = nativeDigest(51);
        publication.profile_id = nativeDigest(71);
        publication.publication_id = nativeDigest(91);
        publication.relation_registry_sha_id = shaDigest(111);

        const relations = universal.UniversalRelations.dummy();
        var relation_draws: [artifact.RELATION_DRAW_COUNT]QM31 = undefined;
        for (relations.elements, 0..) |element, relation_index| {
            relation_draws[2 * relation_index] = element.z;
            relation_draws[2 * relation_index + 1] = element.alpha;
        }

        const core_authority_sha_id = shaDigest(17);
        const transcript_prefix = try artifact.TranscriptPrefixV1.init(
            shaDigest(7),
            core_authority_sha_id,
            shaDigest(27),
            shaDigest(37),
            1_193,
            try frontend.recursion.segment_outer_cohort_v2
                .PublicWireBoundaryV2.init(
                core_authority_sha_id,
                521,
                QM31.fromU32Unchecked(5, 7, 11, 13),
            ),
        );

        var witness = artifact.RecursiveWitnessV1{
            .proof_id = publication.proof_id,
            .capture_id = publication.capture_id,
            .statement_id = nativeDigest(131),
            .air_program_id = nativeDigest(151),
            .manifest_id = publication.manifest_id,
            .profile_id = publication.profile_id,
            .claimed_sums = [_]QM31{QM31.zero()} ** artifact.CLAIM_COUNT,
            .relation_draws = relation_draws,
            .poseidon2_partials = [_]QM31{QM31.zero()} **
                artifact.POSEIDON2_PARTIAL_COUNT,
            .transcript_prefix = transcript_prefix,
            .outer_admission = .{
                .proof_id = publication.proof_id,
                .capture_id = publication.capture_id,
                .component_log_sizes = [_]u32{4} ** artifact.CLAIM_COUNT,
                .pre_core_channel = .{
                    .digest = nativeDigest(171),
                    .draw_count = 73,
                },
                .claimed_sums = [_]QM31{QM31.zero()} ** artifact.CLAIM_COUNT,
                .verifier_input_boundary = QM31.zero(),
                .wire_closure = .{
                    transcript_prefix.public_wire_boundary_claimed_sum.neg(),
                    transcript_prefix.public_wire_boundary_claimed_sum,
                },
                .receipt_id = undefined,
            },
            .relation_draws_id = undefined,
            .poseidon2_partials_id = undefined,
            .witness_id = undefined,
        };
        witness.relation_draws_id = artifact.relationDrawsId(
            &witness,
            &publication,
        );
        witness.poseidon2_partials_id = artifact.poseidon2PartialsId(
            &witness,
            &publication,
        );
        witness.outer_admission.receipt_id = artifact.outerAdmissionReceiptId(
            &witness.outer_admission,
            &publication,
        );
        witness.witness_id = artifact.witnessId(&witness, &publication);
        publication.recursive_witness_id = witness.witness_id;

        return .{
            .publication = publication,
            .witness = witness,
            .profile = try profile_mod.TemporalChildRelationProfileV1
                .deriveFromValidatedWitness(&publication, &witness),
        };
    }
};

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

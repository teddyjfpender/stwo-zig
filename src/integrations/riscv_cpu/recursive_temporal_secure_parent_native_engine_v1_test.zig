const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const engine_mod =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");
const cohort_mod = @import("recursive_binary_outer_cohort.zig");
const verified_publication =
    @import("recursive_binary_verified_publication.zig");

const recursion = frontend.recursion;
const manifest_mod = recursion.air.universal_adapter_manifest;
const fixture_mod = frontend.testing.binary_pair_outer_fixture;
const ManifestContract = struct {
    pub const Manifest = manifest_mod.Manifest;
    pub const Placement = manifest_mod.Placement;
    pub const Geometry = manifest_mod.Geometry;
    pub const ProofGate = manifest_mod.ProofGate;
    pub const TREE_COUNT = manifest_mod.TREE_COUNT;
    pub const PREPROCESSED_TREE_INDEX =
        manifest_mod.PREPROCESSED_TREE_INDEX;
    pub const MAIN_TREE_INDEX = manifest_mod.MAIN_TREE_INDEX;
    pub const INTERACTION_TREE_INDEX = manifest_mod.INTERACTION_TREE_INDEX;
    pub const COMPONENT_COUNT = cohort_mod.COMPLETE_ROW_COUNT;
};
const Cohort = cohort_mod.Cohort(
    fixture_mod.CHILD_DIMENSIONS,
    fixture_mod.STATEMENT_DIMENSIONS,
);
const Kernel = engine_mod.EngineKernelForManifest(
    Cohort,
    ManifestContract,
    .legacy_binary_test,
);

test "secure parent artifact round-trips as custody only" {
    var fixture = try fixture_mod.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const inputs = Cohort.AuthorityInputs{
        .non_fri = try fixture.nonFriInputs(),
        .fri_source = fixture.friSource(),
    };
    const session = try sessionForInputs(inputs, 41);
    const proof_bytes = "custody-is-not-proof";
    const proof_identity = try verified_publication
        .CanonicalProofIdentityV1.fromBytes(proof_bytes);
    const statement = try artifact_mod.statementFromVerifier(
        &session,
        .{
            .interaction_pow_nonce = 17,
            .canonical_proof_byte_count = proof_identity.byte_count,
            .canonical_proof_sha256 = proof_identity.canonical_proof_sha_id,
            .proof_id = proof_identity.proof_id,
            .capture_id = seededDigest(51),
            .transcript_id = seededDigest(61),
            .claims_sha256 = [_]u8{71} ** 32,
            .audit_sha256 = [_]u8{81} ** 32,
            .closure_sha256 = [_]u8{91} ** 32,
        },
    );
    var artifact = try artifact_mod.OwnedArtifactV1.initCopy(
        std.testing.allocator,
        statement,
        proof_bytes,
    );
    defer artifact.deinit();
    const encoded = try artifact.encodeCanonicalAlloc(std.testing.allocator);
    defer std.testing.allocator.free(encoded);
    var decoded = try artifact_mod.OwnedArtifactV1.decodeCanonical(
        std.testing.allocator,
        encoded,
    );
    defer decoded.deinit();
    try std.testing.expectEqualDeep(artifact.statement, decoded.statement);
    try std.testing.expectEqualSlices(
        u8,
        artifact.proof_bytes,
        decoded.proof_bytes,
    );

    var corrupted = try std.testing.allocator.dupe(u8, encoded);
    defer std.testing.allocator.free(corrupted);
    corrupted[corrupted.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidSecureTemporalParentArtifact,
        artifact_mod.OwnedArtifactV1.decodeCanonical(
            std.testing.allocator,
            corrupted,
        ),
    );
}

test "secure parent q193 proof bytes cold fresh-verify" {
    const allocator = std.testing.allocator;
    var fixture = try fixture_mod.Fixture.init(allocator);
    defer fixture.deinit();
    const inputs = Cohort.AuthorityInputs{
        .non_fri = try fixture.nonFriInputs(),
        .fri_source = fixture.friSource(),
    };
    const session = try sessionForInputs(inputs, 101);
    var result = try Kernel.proveAndColdVerify(
        allocator,
        inputs,
        session,
        .{ .worker_count = 1 },
    );
    defer result.deinit();
    try result.receipt.validate();
    try std.testing.expectEqual(@as(u32, 10), result.receipt.interaction_pow_bits);
    try std.testing.expectEqual(@as(u32, 16), result.receipt.pcs_pow_bits);
    try std.testing.expectEqual(@as(u32, 193), result.receipt.fri_query_count);
    try std.testing.expectEqual(@as(u32, 4), result.receipt.fri_fold_step);
    try std.testing.expectEqual(
        @as(usize, 193),
        result.fresh.capture.queries.raw.len,
    );
    for (result.fresh.capture.fri.layers) |layer| {
        try std.testing.expectEqual(@as(usize, 193), layer.query_count);
        try std.testing.expect(layer.fold_width <= 16);
    }

    const encoded = try result.artifact.encodeCanonicalAlloc(allocator);
    defer allocator.free(encoded);
    var reopened = try artifact_mod.OwnedArtifactV1.decodeCanonical(
        allocator,
        encoded,
    );
    defer reopened.deinit();
    var second_fresh = try Kernel.verifyCold(
        allocator,
        inputs,
        &session,
        &reopened,
    );
    defer second_fresh.deinit();
    try std.testing.expectEqualDeep(
        result.fresh.statement,
        second_fresh.statement,
    );
    try std.testing.expectEqualDeep(
        result.fresh.statement.capture_id,
        second_fresh.statement.capture_id,
    );
}

test "secure parent cold verifier rejects context and proof mutations" {
    const allocator = std.testing.allocator;
    var fixture = try fixture_mod.Fixture.init(allocator);
    defer fixture.deinit();
    const inputs = Cohort.AuthorityInputs{
        .non_fri = try fixture.nonFriInputs(),
        .fri_source = fixture.friSource(),
    };
    const session = try sessionForInputs(inputs, 131);
    var result = try Kernel.proveAndColdVerify(
        allocator,
        inputs,
        session,
        .{ .worker_count = 1 },
    );
    defer result.deinit();

    var wrong_session = session;
    wrong_session.profile_identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidSecureTemporalParentSession,
        Kernel.verifyCold(
            allocator,
            inputs,
            &wrong_session,
            &result.artifact,
        ),
    );

    var mutated = try artifact_mod.OwnedArtifactV1.initCopy(
        allocator,
        result.artifact.statement,
        result.artifact.proof_bytes,
    );
    defer mutated.deinit();
    mutated.proof_bytes[mutated.proof_bytes.len / 2] ^= 1;
    try std.testing.expectError(
        error.InvalidSecureTemporalParentArtifact,
        Kernel.verifyCold(allocator, inputs, &session, &mutated),
    );

    var wrong_profile = try artifact_mod.OwnedArtifactV1.initCopy(
        allocator,
        result.artifact.statement,
        result.artifact.proof_bytes,
    );
    defer wrong_profile.deinit();
    wrong_profile.statement.profile_identity_sha256[0] ^= 1;
    artifact_mod.testing.resealStatement(&wrong_profile.statement);
    try wrong_profile.validateCustody();
    try std.testing.expectError(
        error.SecureTemporalParentSessionMismatch,
        Kernel.verifyCold(allocator, inputs, &session, &wrong_profile),
    );
}

fn sessionForInputs(
    inputs: Cohort.AuthorityInputs,
    seed: u8,
) !artifact_mod.SessionV1 {
    var cohort = try Cohort.init(std.testing.allocator, inputs);
    defer cohort.deinit();
    try cohort.validate();
    const statement_words = try cohort.recursiveStatementWords();
    return artifact_mod.testing.session(
        statement_words.*,
        cohort.manifest().seal,
        seed,
    );
}

fn seededDigest(seed: u8) recursion.poseidon2_channel.Digest {
    var result: recursion.poseidon2_channel.Digest = undefined;
    for (&result, 0..) |*word, index|
        word.* = @as(u32, seed) + @as(u32, @intCast(index)) + 1;
    return result;
}

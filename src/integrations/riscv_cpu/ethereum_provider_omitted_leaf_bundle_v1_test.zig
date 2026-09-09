const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const leaf_support = @import("ethereum_block_leaf_support.zig");
const artifact = @import("ethereum_degree5_provider_proof_artifact_v1.zig");
const bundle = @import("ethereum_provider_omitted_leaf_bundle_v1.zig");
const bundle_support =
    @import("ethereum_provider_omitted_leaf_bundle_v1_support.zig");

const Engine = leaf_support.RecursiveEngine;
const guest = frontend.prover_mod.guest_precompile;
const d5 = frontend.testing
    .narrow_memory_provider_degree5_ethereum_omit_proof_v1;

test "ordinary omitted-provider bundle frozen APIs type instantiate" {
    _ = &instantiateFrozenApi;
}

fn instantiateFrozenApi(
    allocator: std.mem.Allocator,
    core_output: *guest.ethereum_types.SegmentProveOutputForEngine(Engine),
    provider_source: d5.Source(Engine),
    authority: bundle.Authority(Engine),
    limits: bundle.Limits,
    artifact_bytes: []const u8,
    existing: *const bundle.FreshVerifiedOmittedLeafV1(Engine),
) !void {
    var built = try bundle.createDestroyAndColdVerify(
        Engine,
        allocator,
        core_output,
        provider_source,
        authority,
        limits,
    );
    defer built.deinit();
    var reopened = try bundle.coldVerify(
        Engine,
        allocator,
        artifact_bytes,
        authority,
        limits,
    );
    defer reopened.deinit();
    try existing.validate(authority);
    const view: bundle.OrdinaryH1ViewV1(Engine) = existing.ordinaryH1View();
    try view.validateCaptureCustody(authority);
    _ = try view.descriptorMintInputColdDerived(authority.source);
    _ = try view.providerCompilerInput(authority);
}

test "ordinary omitted-provider framing rejects canonical order and identity mutations" {
    const allocator = std.testing.allocator;
    const limits = artifact.BundleLimits{
        .max_bundle_bytes = 4096,
        .max_section_bytes = 1024,
        .max_provider_count = 8,
    };
    const identity = filledDigest(0x31);
    const sections = [artifact.bundle_section_count][]const u8{
        "canonical-full-statement",
        "canonical-projected-core",
        "canonical-provider-artifacts",
    };
    const encoded = try artifact.testing.encodeRawBundleAlloc(
        allocator,
        identity,
        sections,
        2,
        limits,
    );
    defer allocator.free(encoded);
    try artifact.testing.validateRawBundle(encoded, identity, 2, limits);
    try artifact.testing.validateProviderOrder(&.{ 0, 1, 2 });

    var wrong_identity = identity;
    wrong_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidOmittedLeafBundleHeader,
        artifact.testing.validateRawBundle(
            encoded,
            wrong_identity,
            2,
            limits,
        ),
    );
    try std.testing.expectError(
        error.OmittedLeafProviderArtifactOrderMismatch,
        artifact.testing.validateProviderOrder(&.{ 0, 2, 1 }),
    );

    encoded[artifact.testing.canonical_reserved_offset] = 1;
    try std.testing.expectError(
        error.InvalidOmittedLeafBundleHeader,
        artifact.testing.validateRawBundle(encoded, identity, 2, limits),
    );
    encoded[artifact.testing.canonical_reserved_offset] = 0;
    encoded[encoded.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidOmittedLeafBundleHeader,
        artifact.testing.validateRawBundle(encoded, identity, 2, limits),
    );
}

test "ordinary omitted-provider capture custody rejects identity and ordinal mutations" {
    const capture_identity = filledDigest(0x41);
    const proof_capture = filledDigest(0x42);
    const proof_root = filledDigest(0x43);
    try (bundle.CoreCaptureLinkV1{
        .capture_identity = capture_identity,
        .descriptor_capture_identity = capture_identity,
        .proof_capture_sha256 = proof_capture,
        .descriptor_proof_capture_sha256 = proof_capture,
    }).validate();
    var wrong_core = capture_identity;
    wrong_core[0] ^= 1;
    try std.testing.expectError(
        error.OmittedLeafCoreCaptureLinkMismatch,
        (bundle.CoreCaptureLinkV1{
            .capture_identity = capture_identity,
            .descriptor_capture_identity = wrong_core,
            .proof_capture_sha256 = proof_capture,
            .descriptor_proof_capture_sha256 = proof_capture,
        }).validate(),
    );

    const canonical = bundle.ProviderCaptureLinkV1{
        .ordinal = 3,
        .artifact_ordinal = 3,
        .capture_identity = capture_identity,
        .artifact_capture_identity = capture_identity,
        .proof_root_sha256 = proof_root,
        .artifact_proof_root_sha256 = proof_root,
        .proof_capture_sha256 = proof_capture,
        .artifact_proof_capture_sha256 = proof_capture,
    };
    try canonical.validate();
    var wrong_order = canonical;
    wrong_order.artifact_ordinal = 4;
    try std.testing.expectError(
        error.OmittedLeafProviderCaptureLinkMismatch,
        wrong_order.validate(),
    );
    var wrong_capture = canonical;
    wrong_capture.artifact_capture_identity[0] ^= 1;
    try std.testing.expectError(
        error.OmittedLeafProviderCaptureLinkMismatch,
        wrong_capture.validate(),
    );
    var wrong_proof_root = canonical;
    wrong_proof_root.artifact_proof_root_sha256[0] ^= 1;
    try std.testing.expectError(
        error.OmittedLeafProviderCaptureLinkMismatch,
        wrong_proof_root.validate(),
    );

    const QM31 = core.fields.qm31.QM31;
    const expected_draws = [_]QM31{QM31.zero()} **
        frontend.air.relation_challenges.DRAW_COUNT;
    var actual_draws = expected_draws;
    try d5.validateFreshProviderRelationDraws(
        &actual_draws,
        &expected_draws,
    );
    actual_draws[0] = QM31.one();
    try std.testing.expectError(
        error.InvalidFreshDegree5ProviderRelationDraws,
        d5.validateFreshProviderRelationDraws(
            &actual_draws,
            &expected_draws,
        ),
    );

    const DigestOwner = struct { identity: [32]u8 };
    const LinkIdentityOwner = struct { identity: [8]u32 };
    const FreshIdentityFixture = struct {
        authority_identity: [32]u8,
        proof_artifact_sha256: [32]u8,
        proof_root_sha256: [32]u8,
        transcript_state_sha256: [32]u8,
        tree0: DigestOwner,
        verified_link: LinkIdentityOwner,
        closure: DigestOwner,
    };
    var fresh_identity_fixture: FreshIdentityFixture = .{
        .authority_identity = filledDigest(0x51),
        .proof_artifact_sha256 = filledDigest(0x52),
        .proof_root_sha256 = filledDigest(0x53),
        .transcript_state_sha256 = filledDigest(0x54),
        .tree0 = .{ .identity = filledDigest(0x55) },
        .verified_link = .{
            .identity = [_]u32{
                0x0102_0304,
                0x1112_1314,
                0x2122_2324,
                0x3132_3334,
                0x4142_4344,
                0x5152_5354,
                0x6162_6364,
                0x7172_7374,
            },
        },
        .closure = .{ .identity = filledDigest(0x56) },
    };
    const canonical_fresh_identity = bundle_support.freshCaptureIdentity(
        void,
        &fresh_identity_fixture,
    );
    var expected_fresh_identity: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_fresh_identity,
        "a090fe632d4a6d40aeea8240852ea8bd50344d4ad73dff1413d50368316d85dc",
    );
    try std.testing.expectEqual(expected_fresh_identity, canonical_fresh_identity);
    fresh_identity_fixture.verified_link.identity[7] ^= 1;
    try std.testing.expect(!std.mem.eql(
        u8,
        &canonical_fresh_identity,
        &bundle_support.freshCaptureIdentity(void, &fresh_identity_fixture),
    ));
}

fn filledDigest(value: u8) [32]u8 {
    return @splat(value);
}

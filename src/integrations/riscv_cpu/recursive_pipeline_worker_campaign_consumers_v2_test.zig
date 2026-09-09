const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const subject =
    @import("recursive_pipeline_worker_campaign_consumers_v2.zig");
const common_backend =
    @import("recursive_pipeline_worker_campaign_common_fold_v2.zig");
const canonical_backend =
    @import("recursive_pipeline_worker_campaign_canonical_empty_v2.zig");
const fold_lease =
    @import("recursive_pipeline_campaign_fold_lease_v2.zig");
const validation =
    @import("recursive_process_local_validation_token_v1.zig");
const preprocessed =
    @import("recursive_process_local_preprocessed_authority_v1.zig");
const throughput =
    @import("recursive_recursion_verifier_throughput_v1.zig");

test "campaign Stage103 and Stage104 siblings are typed and unrouteable" {
    const Stage103 = subject.Stage103For(
        UnavailableAuthority,
        canonical_backend.Backend,
    );
    const Stage104 = subject.Stage104For(
        UnavailableAuthority,
        CampaignCommonBackend,
    );
    try std.testing.expect(!Stage103.available);
    try std.testing.expect(!Stage104.available);
    try std.testing.expect(!Stage103.production);
    try std.testing.expect(!Stage104.production);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.ROUTER_ACTIVATION);
    try std.testing.expect(!subject.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(!canonical_backend.PRODUCTION_ACTIVATION);
    try std.testing.expect(!canonical_backend.ROUTER_ACTIVATION);
    try std.testing.expect(!canonical_backend.Q193_GENUINE_GATE_GREEN);
    try std.testing.expect(@hasDecl(
        canonical_backend.Backend.LeasePayload,
        "campaignFoldProjection",
    ));
    try std.testing.expect(!common_backend.PRODUCTION_ACTIVATION);
    try std.testing.expect(!common_backend.ROUTER_ACTIVATION);
    try std.testing.expect(!common_backend.Q193_GENUINE_GATE_GREEN);
    try std.testing.expect(
        !common_backend.ALL_NOMINAL_CHILD_PAIRS_AVAILABLE,
    );
    try std.testing.expect(common_backend.BUILD_BORROWS_CHILD_LEASES);
    try std.testing.expect(common_backend.COLD_OPEN_REMINTS_FRESH_LEASE);
    try std.testing.expect(!fold_lease.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(subject.EVERY_COLD_OPEN_REQUIRES_INDEPENDENT_Q193);
    try std.testing.expect(subject.CHILD_LEASES_BORROWED_DURING_BUILD);
    try std.testing.expect(subject.BUILD_FAILURE_RETAINS_CHILD_LEASES);
    try std.testing.expectEqualDeep(
        subject.stage103Contract(),
        subject.StageContractV2{
            .stage_kind = artifact_store.StageKindV1.prove,
            .stage_schema_version = 103,
            .output_kind = artifact_store.ArtifactKindV1.recursion_node,
            .output_schema_version = 2,
            .dependency_count = 0,
            .root_cold_open_transitive = true,
            .production = false,
        },
    );
    try std.testing.expectEqualDeep(
        subject.stage104Contract(),
        subject.StageContractV2{
            .stage_kind = artifact_store.StageKindV1.fold,
            .stage_schema_version = 104,
            .output_kind = artifact_store.ArtifactKindV1.recursion_node,
            .output_schema_version = 2,
            .dependency_count = 2,
            .root_cold_open_transitive = true,
            .production = false,
        },
    );
    const stage103 = try Stage103.describe(.prove, 103);
    const stage104 = try Stage104.describe(.fold, 104);
    try std.testing.expect(stage103.root_cold_open_transitive);
    try std.testing.expect(stage104.root_cold_open_transitive);
    try std.testing.expectError(
        error.CampaignWorkerInputMismatch,
        Stage103.describe(.fold, 103),
    );
    try std.testing.expectError(
        error.CampaignWorkerInputMismatch,
        Stage104.describe(.fold, 103),
    );
    try std.testing.expect(@hasDecl(TypedDependencyLease, "fromReal"));
    try std.testing.expect(@hasDecl(TypedDependencyLease, "fromEmpty"));
    try std.testing.expect(@hasDecl(TypedDependencyLease, "fromCommon"));
    try std.testing.expect(@hasDecl(TypedDependencyLease, "foldProjection"));
    try std.testing.expect(!@hasDecl(TypedDependencyLease, "encode"));
    try std.testing.expect(!@hasDecl(TypedDependencyLease, "decode"));
    try std.testing.expect(!@hasDecl(TypedDependencyLease, "deinit"));
    try std.testing.expect(
        @typeInfo(TypedDependencyLease.PayloadV2).@"union".tag_type.? ==
            subject.Role,
    );

    const source_ref = try blobRef(
        .source,
        subject.STAGE103_SOURCE_SCHEMA_VERSION,
        subject.STAGE103_SOURCE_BYTE_COUNT,
        31,
    );
    const proof_ref = try blobRef(.proof_artifact, 1, 4096, 32);
    const node_ref = try blobRef(
        .recursion_node,
        subject.OUTPUT_SCHEMA_VERSION,
        subject.OUTPUT_BYTE_COUNT,
        33,
    );
    const manifest_ref = try blobRef(.stage_manifest, 1, 512, 34);
    try subject.validateCasRef(source_ref, .stage103_source);
    try subject.validateCasRef(proof_ref, .proof);
    try subject.validateCasRef(node_ref, .recursion_node);
    try subject.validateCasRef(manifest_ref, .stage_manifest);

    var wrong_source = source_ref;
    wrong_source.schema_version += 1;
    try std.testing.expectError(
        error.CampaignWorkerInputMismatch,
        subject.validateCasRef(wrong_source, .stage103_source),
    );
    var empty_proof = proof_ref;
    empty_proof.byte_count = 0;
    try std.testing.expectError(
        error.CampaignWorkerProofReferenceMismatch,
        subject.validateCasRef(empty_proof, .proof),
    );
    var wrong_node = node_ref;
    wrong_node.kind = .proof_artifact;
    try std.testing.expectError(
        error.CampaignWorkerDependencyMismatch,
        subject.validateCasRef(wrong_node, .recursion_node),
    );
    var wrong_manifest = manifest_ref;
    wrong_manifest.schema_version += 1;
    try std.testing.expectError(
        error.CampaignWorkerOutputMismatch,
        subject.validateCasRef(wrong_manifest, .stage_manifest),
    );

    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(allocator, root, false);
    defer store.deinit();
    const source_bytes = try allocator.alloc(
        u8,
        @intCast(subject.STAGE103_SOURCE_BYTE_COUNT),
    );
    defer allocator.free(source_bytes);
    @memset(source_bytes, 0xA3);
    const stored_source = try store.putBytes(
        .source,
        subject.STAGE103_SOURCE_SCHEMA_VERSION,
        source_bytes,
    );
    try subject.validateCasRef(stored_source, .stage103_source);
    var reopened = try store.openBlob(
        stored_source,
        .source,
        subject.STAGE103_SOURCE_SCHEMA_VERSION,
        subject.STAGE103_SOURCE_BYTE_COUNT,
    );
    defer reopened.deinit(allocator);
    try std.testing.expectEqualSlices(u8, source_bytes, reopened.bytes);

    const stored_empty_proof = try store.putBytes(
        .proof_artifact,
        subject.PROOF_SCHEMA_VERSION,
        &.{},
    );
    try std.testing.expectError(
        error.CampaignWorkerProofReferenceMismatch,
        subject.validateCasRef(stored_empty_proof, .proof),
    );
}

test "process-local throughput receipts reject capability and counter drift" {
    var owner = try validation.ValidatedOwnerV1.init(fixtureTokenSnapshot(7));
    const validation_before = zeroValidationSnapshot();
    var validation_after = validation_before;
    validation_after.q193_cold_verifications = 1;
    validation_after.transcript_replays = 1;
    validation_after.graph_records = 1;
    validation_after.q193_cold_verification_ns = 9_000;
    validation_after.transcript_replay_ns = 700;
    validation_after.graph_record_ns = 300;
    const cache_before = zeroCacheSnapshot();
    var cache_after = cache_before;
    cache_after.lookups = 1;
    cache_after.misses = 1;
    cache_after.full_rebuilds = 1;
    cache_after.lookup_ns = 200;
    cache_after.rebuild_ns = 180;
    const cold = try throughput.ColdBoundaryReceiptV1.init(
        &owner,
        validation_before,
        validation_after,
        cache_before,
        cache_after,
        12_000,
        10_000,
    );
    try cold.validateAgainst(&owner);
    var hostile = cold;
    hostile.token_seal_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidVerifierThroughputReceipt,
        hostile.validateAgainst(&owner),
    );

    var reuse_after = validation_after;
    reuse_after.token_checks = 64;
    reuse_after.graph_view_borrows = 32;
    reuse_after.token_check_ns = 2_000;
    reuse_after.graph_view_borrow_ns = 800;
    const reuse = try throughput.ReuseReceiptV1.init(
        &owner,
        validation_after,
        reuse_after,
        32,
        10_000_000,
        5_000,
    );
    try reuse.validateAgainst(&owner);
    try std.testing.expect(reuse.meetsStretchTarget());
    var q193_drift = reuse_after;
    q193_drift.q193_cold_verifications += 1;
    try std.testing.expectError(
        error.InvalidVerifierThroughputReceipt,
        throughput.ReuseReceiptV1.init(
            &owner,
            validation_after,
            q193_drift,
            32,
            10_000_000,
            5_000,
        ),
    );
}

const UnavailableAuthority = struct {
    pub const available = false;

    pub fn finalRemintForCampaign(
        _: [32]u8,
    ) error{Unavailable}!*const subject.CampaignFinalRemintAuthorityV2 {
        return error.Unavailable;
    }
};

const MockProjection = struct {
    role: subject.Role,
    geometry: *const subject.Geometry,

    pub fn validateAgainst(
        _: MockProjection,
        _: *const subject.Registry,
    ) !void {}
};

fn MockRoleLease(comptime role: subject.Role) type {
    return struct {
        pub const ROLE = role;

        pub fn validateForCampaign(
            _: *const @This(),
            _: *const subject.CampaignFinalRemintAuthorityV2,
        ) !void {}

        pub fn foldProjection(
            _: *const @This(),
            _: *const subject.Registry,
        ) error{Unavailable}!MockProjection {
            return error.Unavailable;
        }

        pub fn campaignFoldProjection(
            _: *const @This(),
            _: *const subject.CampaignFinalRemintAuthorityV2,
        ) error{Unavailable}!fold_lease.CampaignFoldProjectionV2 {
            return error.Unavailable;
        }
    };
}

const TypedDependencyLease = fold_lease.TypedCampaignUnifiedFoldLeaseV2(
    MockRoleLease(.ethereum_incremental_leaf_wrapper_v4),
    MockRoleLease(.canonical_empty_field_v2),
    MockRoleLease(.common_fold_field_v2),
);

const MockCommonOutputLease = struct {
    pub const ROLE = subject.Role.common_fold_field_v2;

    pub fn validateForCampaign(
        _: *const @This(),
        _: *const subject.CampaignFinalRemintAuthorityV2,
    ) !void {}

    pub fn foldProjection(
        _: *const @This(),
        _: *const subject.Registry,
    ) error{Unavailable}!MockProjection {
        return error.Unavailable;
    }

    pub fn deinit(_: *@This()) void {}
};

const UnavailableCampaignCommonProof = struct {
    pub const available = false;
    pub const q193_genuine_gate_green = false;
    pub const LeasePayload = MockCommonOutputLease;
    pub const ProvedV2 = struct {
        pub fn deinit(_: *@This()) void {}
        pub fn validate() void {}
        pub fn proofBytes() void {}
        pub fn nodeArtifact() void {}
    };

    pub fn validateBorrowedChildren() void {}
    pub fn proveAndColdVerify() void {}
    pub fn coldOpenOwned() void {}
    pub fn validateLease() void {}
    pub fn deinitLeasePayload(_: *LeasePayload) void {}
};

const UnavailableExecutionPolicy = struct {
    pub const available = false;
    pub fn policyForExecution() void {}
};

const CampaignCommonBackend = common_backend.BackendForProofFamily(
    UnavailableCampaignCommonProof,
    TypedDependencyLease,
    UnavailableExecutionPolicy,
);

fn fixtureTokenSnapshot(seed: u8) validation.SnapshotV1 {
    var result: validation.SnapshotV1 = undefined;
    inline for (std.meta.fields(validation.SnapshotV1), 0..) |field, index| {
        if (comptime field.type == [32]u8) {
            @field(result, field.name) = [_]u8{
                seed + @as(u8, @intCast(index)),
            } ** 32;
        } else {
            @field(result, field.name) = index + 1;
        }
    }
    return result;
}

fn zeroValidationSnapshot() validation.CounterSnapshotV1 {
    return std.mem.zeroes(validation.CounterSnapshotV1);
}

fn zeroCacheSnapshot() preprocessed.CounterSnapshotV1 {
    return std.mem.zeroes(preprocessed.CounterSnapshotV1);
}

fn blobRef(
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    byte_count: u64,
    seed: u8,
) !artifact_store.BlobRefV1 {
    var digest: [32]u8 = undefined;
    for (&digest, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return artifact_store.BlobRefV1.create(
        kind,
        schema_version,
        byte_count,
        digest,
    );
}

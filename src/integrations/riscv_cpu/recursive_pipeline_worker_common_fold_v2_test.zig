const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const subject = @import("recursive_pipeline_worker_common_fold_v2.zig");
const campaign_shape = @import("recursive_pipeline_campaign_shape_v2.zig");
const node_artifact = @import("recursive_node_artifact_v2.zig");

test "stage104 topology derives a non-power-of-two campaign shape" {
    const shape = try campaign_shape.CampaignShapeAuthorityV2.init(
        [_]u8{0x31} ** 32,
        [_]u8{0x52} ** 32,
        13,
    );
    try shape.validate();
    try std.testing.expectEqual(@as(u32, 13), shape.real_leaf_count);
    try std.testing.expectEqual(@as(u32, 16), shape.padded_leaf_count);
    try std.testing.expectEqual(@as(u32, 3), shape.empty_leaf_count);
    try std.testing.expectEqual(@as(u32, 15), shape.fold_count);
    try std.testing.expectEqual(@as(u8, 4), shape.root_height);
    try std.testing.expectEqual(@as(u32, 8), try shape.nodeCount(1));

    const mixed = try shape.parentCoordinate(1, 6);
    try std.testing.expectEqual(@as(u32, 22), mixed.global_ordinal);
    try std.testing.expectEqual(node_artifact.NodeKindV1.mixed, mixed.node_kind);
    const empty = try shape.parentCoordinate(1, 7);
    try std.testing.expectEqual(node_artifact.NodeKindV1.empty, empty.node_kind);
    const root = try shape.parentCoordinate(4, 0);
    try std.testing.expectEqual(@as(u32, 30), root.global_ordinal);
    try std.testing.expectEqual(node_artifact.NodeKindV1.mixed, root.node_kind);

    try std.testing.expectError(
        error.InvalidCampaignShapeCoordinateV2,
        shape.parentCoordinate(5, 0),
    );
    try std.testing.expectError(
        error.InvalidCampaignShapeV2,
        shape.validateAgainstCampaign([_]u8{0x99} ** 32),
    );
}

test "stage104 contract is typed and default route is fail closed" {
    const contract = subject.stageContract();
    try std.testing.expectEqual(
        artifact_store.StageKindV1.fold,
        contract.stage_kind,
    );
    try std.testing.expectEqual(@as(u16, 104), contract.stage_schema_version);
    try std.testing.expectEqual(
        artifact_store.ArtifactKindV1.recursion_node,
        contract.output_kind,
    );
    try std.testing.expectEqual(@as(u16, 2), contract.output_schema_version);
    try std.testing.expectEqual(
        @as(u64, node_artifact.ENCODED_BYTE_COUNT),
        contract.output_byte_count,
    );
    try std.testing.expectEqual(
        artifact_store.ArtifactKindV1.proof_artifact,
        contract.proof_kind,
    );
    try std.testing.expectEqual(@as(u16, 1), contract.proof_schema_version);
    try std.testing.expectEqual(@as(u8, 2), contract.dependency_count);
    try std.testing.expect(contract.root_cold_open_transitive);
    _ = try subject.Adapter.describe(.fold, 104);
    try std.testing.expectError(
        error.UnsupportedRecursivePipelineStage,
        subject.Adapter.describe(.prove, 104),
    );
    try std.testing.expectError(
        error.CommonFoldStage104BackendUnavailable,
        subject.Adapter.unavailable(),
    );
    try std.testing.expect(!subject.Adapter.available);
    try std.testing.expect(!subject.Adapter.production);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.ROUTER_ACTIVATION);
}

test "stage104 CAS allocation rejects wrong codec and empty proof" {
    const digest = [_]u8{0x42} ** 32;
    const proof = try artifact_store.BlobRefV1.create(
        .proof_artifact,
        1,
        4096,
        digest,
    );
    const node = try artifact_store.BlobRefV1.create(
        .recursion_node,
        2,
        node_artifact.ENCODED_BYTE_COUNT,
        digest,
    );
    try subject.validateCasRef(proof, .proof);
    try subject.validateCasRef(node, .node);

    var wrong_proof = proof;
    wrong_proof.schema_version = 2;
    try std.testing.expectError(
        error.CommonFoldStage104ArtifactMismatch,
        subject.validateCasRef(wrong_proof, .proof),
    );
    var empty_proof = proof;
    empty_proof.byte_count = 0;
    try std.testing.expectError(
        error.CommonFoldStage104ArtifactMismatch,
        subject.validateCasRef(empty_proof, .proof),
    );
    var wrong_node = node;
    wrong_node.kind = .proof_artifact;
    try std.testing.expectError(
        error.CommonFoldStage104ArtifactMismatch,
        subject.validateCasRef(wrong_node, .node),
    );
    var short_node = node;
    short_node.byte_count -= 1;
    try std.testing.expectError(
        error.CommonFoldStage104ArtifactMismatch,
        subject.validateCasRef(short_node, .node),
    );
}

test "cold child pair guard releases on failure and transfers on success" {
    var releases: usize = 0;
    const Pair = TestChildColdOpener.OwnedPair;
    const Guard = subject.OwnedPairGuard(TestChildColdOpener);

    {
        var guard = Guard{ .pair = Pair{ .releases = &releases } };
        defer guard.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), releases);

    {
        var guard = Guard{ .pair = Pair{ .releases = &releases } };
        defer guard.deinit(std.testing.allocator);
        var moved = guard.transferValue();
        guard.commitTransfer();
        TestChildColdOpener.deinitOwnedPair(&moved, std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 2), releases);
}

test "default live lease has no serialized capability surface" {
    comptime {
        const Lease = subject.Adapter.LeasePayload;
        for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |
            name,
        | {
            if (@hasDecl(Lease, name))
                @compileError("stage104 process-local lease gained a codec");
        }
        _ = subject.AdapterFor(
            subject.UnavailableAuthorityProviderV2,
            subject.UnavailableChildColdOpenerV2,
            subject.UnavailableBackendV2,
        );
    }
    try std.testing.expect(subject.DEPENDENCIES_BORROWED_DURING_BUILD);
    try std.testing.expect(subject.BUILD_FAILURE_RETAINS_DEPENDENCIES);
    try std.testing.expect(subject.COLD_OPEN_OWNS_DEPENDENCY_PAIR);
    try std.testing.expect(!subject.SERIALIZABLE_FRESH_CAPABILITY);
}

const TestChildColdOpener = struct {
    pub const OwnedPair = struct {
        releases: *usize,
    };

    pub fn deinitOwnedPair(
        pair: *OwnedPair,
        _: std.mem.Allocator,
    ) void {
        pair.releases.* += 1;
        pair.* = undefined;
    }
};

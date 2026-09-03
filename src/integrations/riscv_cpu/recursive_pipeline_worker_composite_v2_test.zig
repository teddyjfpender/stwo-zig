const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const subject = @import("recursive_pipeline_worker_composite_v2.zig");
const canonical_empty =
    @import("recursive_pipeline_worker_canonical_empty_v2.zig");
const native_leaf = @import("recursive_pipeline_worker_native_leaf_v4.zig");
const child_capability =
    @import("recursive_common_fold_child_capability_v2.zig");
const common_child = @import("recursive_common_fold_child_v2.zig");
const node_artifact = @import("recursive_node_artifact_v2.zig");

test "composite contract pins stage codes and typed CAS outputs" {
    const expected = [_]struct {
        code: subject.StageCodeV2,
        kind: artifact_store.StageKindV1,
        output: artifact_store.ArtifactKindV1,
        schema: u16,
        dependencies: u8,
    }{
        .{ .code = .native_leaf_v4, .kind = .prove, .output = .proof_artifact, .schema = 1, .dependencies = 0 },
        .{ .code = .real_wrapper_v4, .kind = .prove, .output = .recursion_node, .schema = 2, .dependencies = 1 },
        .{ .code = .canonical_empty_v2, .kind = .prove, .output = .recursion_node, .schema = 2, .dependencies = 0 },
        .{ .code = .common_fold_v2, .kind = .fold, .output = .recursion_node, .schema = 2, .dependencies = 2 },
    };
    for (expected) |item| {
        const contract = subject.stageContract(item.code);
        try std.testing.expectEqual(item.kind, contract.stage_kind);
        try std.testing.expectEqual(item.output, contract.output_kind);
        try std.testing.expectEqual(item.schema, contract.output_schema_version);
        try std.testing.expectEqual(item.dependencies, contract.dependency_lease_count);
        try std.testing.expectEqual(
            subject.CAS_FORMAT_VERSION,
            contract.output_format_version,
        );
        try std.testing.expect(contract.produces_process_local_lease);
        if (item.output == .recursion_node) {
            try std.testing.expectEqual(
                @as(?u64, node_artifact.ENCODED_BYTE_COUNT),
                contract.fixed_output_byte_count,
            );
        }
    }
    try std.testing.expectEqual(@as(u16, 2), subject.stageContract(
        .native_leaf_v4,
    ).embedded_artifact_schema_version);
    try std.testing.expectEqual(@as(u16, 1), subject.PROOF_CAS_SCHEMA_VERSION);
    try std.testing.expectEqual(
        @as(u16, 1),
        subject.STAGE_MANIFEST_CAS_SCHEMA_VERSION,
    );
}

test "stage101 and stage103 route while composite production stays closed" {
    const native = try subject.Adapter.describe(.prove, 101);
    try std.testing.expectEqual(
        artifact_store.ArtifactKindV1.proof_artifact,
        native.output_kind,
    );
    try std.testing.expectEqual(@as(u16, 1), native.output_schema_version);
    const empty = try subject.Adapter.describe(.prove, 103);
    try std.testing.expectEqual(
        artifact_store.ArtifactKindV1.recursion_node,
        empty.output_kind,
    );
    try std.testing.expectEqual(@as(u16, 2), empty.output_schema_version);
    try std.testing.expectError(
        error.CompositeRecursiveStageUnavailable,
        subject.Adapter.describe(.prove, 102),
    );
    try std.testing.expectError(
        error.CompositeRecursiveStageUnavailable,
        subject.Adapter.describe(.fold, 104),
    );
    try std.testing.expect(!subject.Adapter.available);
    try std.testing.expect(!subject.Adapter.production);
    try std.testing.expect(subject.stageContract(.native_leaf_v4).route_available);
    try std.testing.expect(!subject.stageContract(.real_wrapper_v4).route_available);
    try std.testing.expect(!subject.stageContract(.common_fold_v2).route_available);
}

test "lease union owns nominal payloads and has no durable codec" {
    comptime {
        if (@hasDecl(subject.LeasePayloadV2, "encode") or
            @hasDecl(subject.LeasePayloadV2, "decode") or
            @hasDecl(subject.LeasePayloadV2, "encodeAlloc") or
            @hasDecl(subject.LeasePayloadV2, "decodeAlloc"))
        {
            @compileError("process-local recursive lease gained a codec");
        }
        if (@FieldType(subject.LeasePayloadV2, "canonical_empty_v2") !=
            canonical_empty.LeasePayloadV2)
        {
            @compileError("stage103 lease stopped owning its cold admission");
        }
        if (@FieldType(subject.LeasePayloadV2, "native_leaf_v4") !=
            native_leaf.Adapter.LeasePayload)
        {
            @compileError("stage101 lease stopped owning its cold admission");
        }
        _ = subject.LeasePayloadV2.FoldChildCapability;
    }
    try std.testing.expect(!subject.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(!subject.DURABLE_LEASE_CODEC_AVAILABLE);
    try std.testing.expect(subject.DEPENDENCIES_BORROWED_DURING_BUILD);
    try std.testing.expect(subject.BUILD_FAILURE_RETAINS_DEPENDENCY_LEASES);
    try std.testing.expect(subject.SUCCESS_CONSUMES_AFTER_OUTER_PUBLICATION);
}

test "generic lease ownership releases exactly once by active stage" {
    const Native = TestNativeLease;
    const Real = TestRealLease;
    const Common = TestCommonLease;
    const Lease = subject.LeasePayloadFor(Native, Real, Common);

    var native_releases: usize = 0;
    var native = Lease{ .native_leaf_v4 = .{ .releases = &native_releases } };
    try native.validate();
    try std.testing.expectEqual(subject.StageCodeV2.native_leaf_v4, native.stageCode());
    var unused_registry: @import(
        "recursive_circuit_registry_v1.zig",
    ).RecursiveCircuitRegistryV1 = undefined;
    try std.testing.expectError(
        error.InvalidCompositeRecursiveLease,
        native.foldProjection(&unused_registry),
    );
    try subject.validateDependencyLeaseShape(Lease, .real_wrapper_v4, &.{&native});
    try std.testing.expectError(
        error.InvalidCompositeRecursiveLease,
        subject.validateDependencyLeaseShape(Lease, .common_fold_v2, &.{ &native, &native }),
    );
    try std.testing.expectEqual(@as(usize, 0), native_releases);
    native.deinit();
    try std.testing.expectEqual(@as(usize, 1), native_releases);

    var real_releases: usize = 0;
    var real = Lease{ .real_wrapper_v4 = .{ .releases = &real_releases } };
    try real.validate();

    var common_releases: usize = 0;
    var common = Lease{ .common_fold_v2 = .{ .releases = &common_releases } };
    try common.validate();
    try subject.validateDependencyLeaseShape(
        Lease,
        .common_fold_v2,
        &.{ &real, &common },
    );
    try std.testing.expectEqual(@as(usize, 0), real_releases);
    try std.testing.expectEqual(@as(usize, 0), common_releases);
    real.deinit();
    try std.testing.expectEqual(@as(usize, 1), real_releases);
    common.deinit();
    try std.testing.expectEqual(@as(usize, 1), common_releases);
}

const TestNativeLease = struct {
    releases: *usize,

    pub fn validate(_: *const TestNativeLease) !void {}

    pub fn deinit(self: *TestNativeLease) void {
        self.releases.* += 1;
    }
};

const TestRealLease = struct {
    pub const FoldChild = child_capability.UnavailableRealLeafChildV2;
    releases: *usize,

    pub fn validate(_: *const TestRealLease) !void {}

    pub fn requireFoldChild(_: *const TestRealLease) !FoldChild {
        return error.RealWrapperStage102Unavailable;
    }

    pub fn deinit(self: *TestRealLease) void {
        self.releases.* += 1;
    }
};

const TestCommonLease = struct {
    pub const FoldChild = common_child.FreshFoldChildV2;
    releases: *usize,

    pub fn validate(_: *const TestCommonLease) !void {}

    pub fn requireFoldChild(_: *const TestCommonLease) !FoldChild {
        return error.CommonFoldStage104Unavailable;
    }

    pub fn deinit(self: *TestCommonLease) void {
        self.releases.* += 1;
    }
};

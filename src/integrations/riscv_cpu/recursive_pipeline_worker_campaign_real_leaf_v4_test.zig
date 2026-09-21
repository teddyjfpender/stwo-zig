const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("recursive_pipeline_worker_campaign_real_leaf_v4.zig");
const backend_mod =
    @import("recursive_pipeline_worker_campaign_real_leaf_backend_v4.zig");
const fold_child =
    @import("recursive_common_ethereum_incremental_leaf_campaign_fold_child_v4.zig");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const padding_fixture =
    @import("recursive_common_wrapper_padding_remint_v2_test.zig");

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
const ActiveSources = @TypeOf(
    @as(*padding_fixture.Fixture, undefined).activeSources(),
);

test "campaign Stage102 worker fixes one proof dependency and seal-last output" {
    const proof = blob(.proof_artifact, 1, 31, 4096);
    const ordered = [_]artifact_store.InputRefV1{.{
        .role = .proof,
        .ordinal = 0,
        .blob = proof,
    }};
    var dependencies = [_]protocol.Dependency{.{
        .node_id = "native/003",
        .role = @intFromEnum(artifact_store.InputRoleV1.proof),
        .ordinal = 0,
    }};
    const node = stage102Node(&dependencies, &ordered);
    try subject.testing.validateStageNodeV4(node, &ordered);

    var wrong_role = ordered;
    wrong_role[0].role = .direct;
    try std.testing.expectError(
        error.CampaignRealLeafStage102DependencyMismatchV4,
        subject.testing.validateStageNodeV4(node, &wrong_role),
    );
    var wrong_kind = ordered;
    wrong_kind[0].blob.kind = .recursion_node;
    try std.testing.expectError(
        error.CampaignWorkerProofReferenceMismatch,
        subject.testing.validateStageNodeV4(node, &wrong_kind),
    );
    var no_dependencies = node;
    var empty_dependencies: [0]protocol.Dependency = .{};
    no_dependencies.dependencies = &empty_dependencies;
    try std.testing.expectError(
        error.CampaignRealLeafStage102InputMismatchV4,
        subject.testing.validateStageNodeV4(no_dependencies, &ordered),
    );

    try std.testing.expect(subject.WORKER_OWNS_STAGE_MANIFEST_SEAL_LAST);
    try std.testing.expect(subject.BUILD_FAILURE_RETAINS_DEPENDENCY);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.ROUTER_ACTIVATION);
}

test "campaign Stage102 generic adapter stays unavailable without authorities" {
    const Adapter = subject.Stage102For(MockProvider, MockBackend);
    try std.testing.expect(!Adapter.available);
    const description = try Adapter.describe(.prove, 102);
    try std.testing.expectEqual(
        artifact_store.ArtifactKindV1.recursion_node,
        description.output_kind,
    );
    try std.testing.expectEqual(@as(u16, 2), description.output_schema_version);
    try std.testing.expect(description.root_cold_open_transitive);
    try std.testing.expect(!@hasDecl(MockBackend.LeasePayload, "encode"));
    try std.testing.expect(!@hasDecl(MockBackend.LeasePayload, "decode"));
}

test "campaign Stage102 real backend and final fold lease type-check separately" {
    const Backend = blk: {
        @setEvalBranchQuota(500_000);
        break :blk backend_mod.BackendFor(
            Engine,
            ActiveSources,
            backend_mod.UnavailableExecutionPolicyProviderV4,
        );
    };
    const Lease = fold_child.Types(Engine).OwnedLeaseV4;
    std.testing.refAllDecls(Backend);
    std.testing.refAllDecls(Lease);
    try std.testing.expect(!Backend.available);
    try std.testing.expectEqual(
        @import("recursive_circuit_registry_v1.zig").CircuitRoleV4
            .ethereum_incremental_leaf_wrapper_v4,
        Lease.ROLE,
    );
    try std.testing.expect(!@hasDecl(Lease, "encode"));
    try std.testing.expect(!@hasDecl(Lease, "decode"));
}

fn stage102Node(
    dependencies: []protocol.Dependency,
    _: []const artifact_store.InputRefV1,
) protocol.Node {
    return .{
        .node_id = "leaf/003",
        .stage_kind = .prove,
        .stage_schema_version = subject.STAGE_SCHEMA_VERSION,
        .adapter = subject.adapter_name,
        .dependencies = dependencies,
        .external_inputs = &.{},
        .local_task_identity_sha256 = sha(41),
        .semantic_authorities = zeroSemanticAuthorities(),
        .semantic_options = .null,
        .cpu_tokens = 1,
        .rss_tokens = 1,
        .output_kind = .recursion_node,
        .output_schema_version = subject.OUTPUT_SCHEMA_VERSION,
    };
}

fn blob(
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    seed: u8,
    byte_count: u64,
) artifact_store.BlobRefV1 {
    return .{
        .kind = kind,
        .schema_version = schema_version,
        .byte_count = byte_count,
        .sha256 = sha(seed),
    };
}

fn sha(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

fn zeroSemanticAuthorities() protocol.SemanticAuthorities {
    const zero = [_]u8{0} ** 32;
    return .{
        .protocol_identity_sha256 = zero,
        .program_identity_sha256 = zero,
        .profile_identity_sha256 = zero,
        .pcs_identity_sha256 = zero,
        .security_identity_sha256 = zero,
        .statement_identity_sha256 = zero,
        .provider_identity_sha256 = zero,
        .layout_identity_sha256 = zero,
        .registry_identity_sha256 = zero,
    };
}

const MockAuthority = struct {};
const MockLease = struct {
    pub fn campaignFoldProjection(_: *const MockLease, _: anytype) !void {}
};
const MockBackend = struct {
    pub const available = false;
    pub const AuthorityV4 = MockAuthority;
    pub const NativeLeasePayload = struct {};
    pub const LeasePayload = MockLease;
    pub fn validateAuthority() void {}
    pub fn validateBorrowedDependency() void {}
    pub fn executionPolicyForNode() void {}
    pub fn proveAndColdVerify() void {}
    pub fn coldOpenOwned() void {}
    pub fn validateLease() void {}
    pub fn deinitLeasePayload() void {}
};
const MockProvider = struct {
    pub const available = false;
    pub fn authorityForCampaign(_: [32]u8) !*const MockAuthority {
        return error.CampaignRealLeafStage102AuthorityUnavailableV4;
    }
};

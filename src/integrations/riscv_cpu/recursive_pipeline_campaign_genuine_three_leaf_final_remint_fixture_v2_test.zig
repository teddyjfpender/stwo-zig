const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("recursive_pipeline_campaign_genuine_three_leaf_final_remint_fixture_v2.zig");
const canonical_proof =
    @import("recursive_common_canonical_empty_universal_proof_v2.zig");
const registry = @import("recursive_circuit_registry_v1.zig");
const table_mod =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");
const recipe_mod =
    @import("recursive_pipeline_incremental_leaf_recipe_v4.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");
const policy_mod =
    @import("recursive_pipeline_worker_execution_policy_v2.zig");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const backend_mod =
    @import("recursive_pipeline_worker_campaign_real_leaf_backend_v4.zig");
const opener_mod =
    @import("recursive_pipeline_worker_campaign_real_leaf_inventory_opener_v4.zig");
const lifecycle_mod =
    @import("recursive_pipeline_worker_campaign_stage102_final_lifecycle_v4.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);

const FixtureActiveEmpty = ActiveFixtureSource(
    .canonical_empty_field_v2,
);
const FixtureActiveCommon = ActiveFixtureSource(.common_fold_field_v2);
const Fixture = blk: {
    @setEvalBranchQuota(500_000);
    break :blk subject.Types(
        Engine,
        canonical_proof.CAPTURE_DERIVED_FIXED_WIRE_DIMENSIONS_V2,
        FixtureActiveEmpty,
        FixtureActiveCommon,
    );
};

test "genuine three-leaf final-remint fixture rejects non-3-to-4 campaign before q193" {
    std.testing.refAllDecls(Fixture);
    std.testing.refAllDecls(Fixture.OwnedCampaignV2);
    std.testing.refAllDecls(Fixture.OwnedFinalV2);
    try std.testing.expectEqual(@as(u32, 3), subject.REAL_LEAF_COUNT);
    try std.testing.expectEqual(@as(u32, 4), subject.PADDED_LEAF_COUNT);
    try std.testing.expectEqual(@as(u32, 3), subject.EMPTY_LEAF_INDEX);
    try std.testing.expectEqual(@as(u32, 2), subject.ACTIVE_ROLE0_LEAF_INDEX);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.ROUTER_ACTIVATION);
    try std.testing.expect(!subject.GENUINE_Q193_GATE_GREEN);
    try std.testing.expect(!subject.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(!subject.CALLER_AUTHORED_STAGE101_REFS_ADMITTED);
    try std.testing.expect(subject.EXACT_STWCIT04_REQUIRED);

    var table_storage: [2]table_mod.LeafRecordV4 = undefined;
    const table = try fixtureTable(2, &table_storage);
    try std.testing.expectError(
        error.GenuineThreeLeafCampaignFixtureMismatchV2,
        Fixture.OwnedCampaignV2.buildWithExecution(
            std.testing.allocator,
            &table,
            .{},
            .{},
        ),
    );
}

test "genuine three-leaf fixture rejects unauthenticated STWCIT04 refs before q193" {
    var table_storage: [3]table_mod.LeafRecordV4 = undefined;
    const table = try fixtureTable(3, &table_storage);
    table_storage[1].stage_inputs[0].blob.sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalCampaignTableV4,
        Fixture.OwnedCampaignV2.buildWithExecution(
            std.testing.allocator,
            &table,
            .{},
            .{},
        ),
    );
}

test "genuine 3-to-4 three-cold-proof FinalRemint exact body compiles without q193" {
    const shape = try @import("recursive_pipeline_campaign_shape_v2.zig")
        .CampaignShapeAuthorityV2.init(digest(1), digest(2), 3);
    try std.testing.expectEqual(@as(u32, 4), shape.padded_leaf_count);
    try std.testing.expectEqual(@as(u32, 1), shape.empty_leaf_count);
    try std.testing.expectEqual(@as(u32, 3), shape.fold_count);

    const host = try policy_mod.HostExecutionAuthorityV2.init(2, 4096);
    const policy = try policy_mod.PolicyV2.init(host, .{
        .total_cpu_tokens = 2,
        .cpu_tokens_per_node = 2,
        .proof_worker_count = 2,
        .maximum_parallel_nodes = 1,
        .total_rss_bytes = 4096,
        .rss_bytes_per_node = 4096,
    });
    const execution = try artifact_store.ExecutionKeyV1.create(.{
        .semantic_key_identity = digest(3),
        .producer_identity = digest(4),
        .verifier_identity = digest(5),
        .source_identity = digest(6),
        .build_identity = digest(7),
        .executable_identity = digest(8),
        .toolchain_identity = digest(9),
        .backend_identity = digest(10),
        .optimization_identity = digest(11),
        .worker_policy_identity = policy.worker_policy_identity,
        .memory_policy_identity = digest(12),
        .retention_policy_identity = digest(13),
        .timeout_policy_identity = digest(14),
    });
    const campaign: Fixture.OwnedCampaignV2 = undefined;
    try std.testing.expectError(
        error.RecursiveExecutionPolicyMismatch,
        Fixture.OwnedFinalV2.proveAndFinalize(
            std.testing.allocator,
            &campaign,
            undefined,
            undefined,
            execution,
            &policy,
        ),
    );
}

const UnavailablePolicyProvider = struct {
    pub const available = false;

    pub fn policyForExecution(
        _: artifact_store.ExecutionKeyV1,
    ) error{FixtureExecutionPolicyUnavailable}!policy_mod.PolicyV2 {
        return error.FixtureExecutionPolicyUnavailable;
    }
};

const Role0Backend = blk: {
    @setEvalBranchQuota(500_000);
    break :blk backend_mod.BackendFor(
        Engine,
        Fixture.ActiveSourcesV2,
        UnavailablePolicyProvider,
    );
};

const GateProvider = struct {
    pub const available = false;
    pub const AuthorityV4 = Role0Backend.AuthorityV4;

    pub fn authorityForCampaign(
        _: artifact_store.Digest,
    ) error{FixtureGateProviderUnavailable}!*const AuthorityV4 {
        return error.FixtureGateProviderUnavailable;
    }

    pub fn stage102AdmissionForOutput(
        _: artifact_store.Digest,
        _: artifact_store.BlobRefV1,
    ) error{FixtureGateProviderUnavailable}!*const opener_mod.Stage102ColdAdmissionV4 {
        return error.FixtureGateProviderUnavailable;
    }
};

const GateOpener = blk: {
    @setEvalBranchQuota(500_000);
    break :blk opener_mod.OpenerFor(Role0Backend, GateProvider);
};

const GateLifecycle = blk: {
    @setEvalBranchQuota(500_000);
    break :blk lifecycle_mod.CampaignSupervisorFor(
        Engine,
        Fixture.ActiveSourcesV2,
        UnavailablePolicyProvider,
    );
};

test "role0 transitive genuine gate returns exact production lease and bypasses only release flag" {
    try std.testing.expect(!GateOpener.available);
    try std.testing.expect(@hasDecl(
        GateOpener,
        "coldOpenNodeForGenuineGate",
    ));
    try std.testing.expect(GateOpener.LeasePayload ==
        @import("recursive_common_ethereum_incremental_leaf_campaign_fold_child_v4.zig")
            .Types(Engine).OwnedLeaseV4);
    try std.testing.expect(@hasDecl(
        GateOpener.Stage102AdapterV4,
        "validateOutputForGenuineGate",
    ));
    try std.testing.expect(@hasDecl(
        GateOpener.Stage102AdapterV4,
        "buildOutputWithExecutionAndLeasesForGenuineGate",
    ));
    try std.testing.expect(@hasDecl(
        GateOpener.Stage102AdapterV4,
        "coldOpenLeaseForGenuineGate",
    ));

    var no_dependencies: [0]protocol.Dependency = .{};
    var no_external_inputs: [0]artifact_store.InputRefV1 = .{};
    const invalid_node = protocol.Node{
        .node_id = "genuine-gate-invalid",
        .stage_kind = .prove,
        .stage_schema_version = 0,
        .adapter = "zig-worker-v1",
        .dependencies = &no_dependencies,
        .external_inputs = &no_external_inputs,
        .local_task_identity_sha256 = digest(15),
        .semantic_authorities = .{
            .protocol_identity_sha256 = digest(16),
            .program_identity_sha256 = digest(17),
            .profile_identity_sha256 = digest(18),
            .pcs_identity_sha256 = digest(19),
            .security_identity_sha256 = digest(20),
            .statement_identity_sha256 = digest(21),
            .provider_identity_sha256 = digest(22),
            .layout_identity_sha256 = digest(23),
            .registry_identity_sha256 = digest(24),
        },
        .semantic_options = .null,
        .cpu_tokens = 1,
        .rss_tokens = 1,
        .output_kind = .recursion_node,
        .output_schema_version = 2,
    };
    const no_inputs = [_]artifact_store.InputRefV1{};
    const no_leases = [_]*const GateOpener.Stage102AdapterV4.DependencyLease{};
    try std.testing.expectError(
        error.CampaignRealLeafStage102BackendUnavailableV4,
        GateOpener.Stage102AdapterV4.buildOutputWithExecutionAndLeases(
            std.testing.allocator,
            undefined,
            invalid_node,
            undefined,
            undefined,
            &no_inputs,
            0,
            &no_leases,
        ),
    );
    try std.testing.expectError(
        error.CampaignRealLeafStage102InputMismatchV4,
        GateOpener.Stage102AdapterV4
            .buildOutputWithExecutionAndLeasesForGenuineGate(
            std.testing.allocator,
            undefined,
            invalid_node,
            undefined,
            undefined,
            &no_inputs,
            0,
            &no_leases,
        ),
    );
    try std.testing.expectError(
        error.CampaignRealLeafStage102BackendUnavailableV4,
        GateOpener.Stage102AdapterV4.validateOutput(
            std.testing.allocator,
            &.{},
            invalid_node,
            undefined,
            &no_inputs,
        ),
    );
    try std.testing.expectError(
        error.CampaignRealLeafStage102InputMismatchV4,
        GateOpener.Stage102AdapterV4.validateOutputForGenuineGate(
            std.testing.allocator,
            &.{},
            invalid_node,
            undefined,
            &no_inputs,
        ),
    );
    try std.testing.expectError(
        error.CampaignRealLeafStage102BackendUnavailableV4,
        GateOpener.Stage102AdapterV4.coldOpenLease(
            std.testing.allocator,
            undefined,
            &.{},
            invalid_node,
            undefined,
            &no_inputs,
        ),
    );
    try std.testing.expectError(
        error.CampaignRealLeafStage102InputMismatchV4,
        GateOpener.Stage102AdapterV4.coldOpenLeaseForGenuineGate(
            std.testing.allocator,
            undefined,
            &.{},
            invalid_node,
            undefined,
            &no_inputs,
        ),
    );

    const shape = try @import("recursive_pipeline_campaign_shape_v2.zig")
        .CampaignShapeAuthorityV2.init(digest(21), digest(22), 3);
    const final_remint = final_mod.CampaignFinalRemintAuthorityV2{
        .shape = &shape,
        .final_remint = undefined,
        .binding_identity_sha256 = undefined,
    };
    try std.testing.expectError(
        error.CampaignRealLeafInventoryOpenerUnavailableV4,
        GateOpener.coldOpenNode(
            std.testing.allocator,
            undefined,
            &final_remint,
            undefined,
            undefined,
        ),
    );
    try std.testing.expectError(
        error.FixtureGateProviderUnavailable,
        GateOpener.coldOpenNodeForGenuineGate(
            std.testing.allocator,
            undefined,
            &final_remint,
            undefined,
            undefined,
        ),
    );
}

test "immutable Stage102 session exposes only exact-body role0 gate before activation" {
    @setEvalBranchQuota(500_000);
    std.testing.refAllDecls(GateLifecycle.OwnedFinalSessionV4);
    try std.testing.expect(!GateLifecycle.available);
    try std.testing.expect(@hasDecl(
        GateLifecycle.OwnedFinalSessionV4,
        "role0ForOutputForGenuineGate",
    ));
    try std.testing.expect(GateLifecycle.Role0LeaseV4 == GateOpener.LeasePayload);
    try std.testing.expect(!@hasDecl(
        GateLifecycle.OwnedFinalSessionV4,
        "encode",
    ));
    try std.testing.expect(!@hasDecl(
        GateLifecycle.OwnedFinalSessionV4,
        "decode",
    ));
}

fn ActiveFixtureSource(comptime role: registry.CircuitRoleV1) type {
    return struct {
        pub const ROLE = role;
        geometry: registry.AuthenticatedGeometryV1,

        pub fn validateColdGeometry(self: *const @This()) !void {
            try self.geometry.validate();
            if (self.geometry.role != role)
                return error.FixtureActiveGeometryMismatch;
        }

        pub fn geometryForPaddingTarget(
            self: *const @This(),
        ) *const registry.AuthenticatedGeometryV1 {
            return &self.geometry;
        }
    };
}

fn fixtureTable(
    comptime count: usize,
    records: *[count]table_mod.LeafRecordV4,
) !table_mod.CampaignTableV4 {
    const globals = fixtureGlobals();
    for (records, 0..) |*record, index|
        record.* = fixtureRecord(globals, @intCast(index));
    return table_mod.CampaignTableV4.seal(.{
        .segment_count = count,
        .globals = globals,
        .records = records,
        .content_sha256 = undefined,
    });
}

fn fixtureGlobals() table_mod.GlobalRefsV4 {
    return .{
        .capture_manifest = ref(.capture_transport, 4, 13, 1),
        .public_wire_manifest = ref(
            .capture_transport,
            wire_publication.CAS_MANIFEST_SCHEMA_VERSION,
            17,
            2,
        ),
        .compact_manifest = ref(
            .capture_transport,
            table_mod.COMPACT_MANIFEST_CAS_SCHEMA_VERSION,
            19,
            3,
        ),
        .execution_profile_receipt = ref(.profile_receipt, 1, 23, 4),
        .materialization_result = ref(
            .source,
            table_mod.MATERIALIZATION_CAS_SCHEMA_VERSION,
            29,
            5,
        ),
        .source_request = ref(.source, 1, 31, 6),
        .execution_journal = ref(
            .journal,
            table_mod.FULL_JOURNAL_CAS_SCHEMA_VERSION,
            37,
            7,
        ),
        .program = ref(.program, 1, 41, 8),
        .raw_input = ref(.raw, 1, 43, 9),
        .expected_output = ref(.raw, 1, 47, 10),
    };
}

fn fixtureRecord(
    globals: table_mod.GlobalRefsV4,
    index: u32,
) table_mod.LeafRecordV4 {
    const statement = ref(
        .statement,
        1,
        @import("ethereum_block_leaf_support.zig").source_wire.encoded_size,
        @intCast(20 + index),
    );
    const recipe = ref(
        .capture_transport,
        recipe_mod.SCHEMA_VERSION,
        recipe_mod.ENCODED_BYTE_COUNT,
        @intCast(30 + index),
    );
    const compact = ref(
        .capture_transport,
        1,
        53 + index,
        @intCast(40 + index),
    );
    const boundary = ref(
        .capture_transport,
        4,
        59 + index,
        @intCast(50 + index),
    );
    const public_reference = ref(
        .capture_transport,
        wire_publication.CAS_REFERENCE_SCHEMA_VERSION,
        wire_publication.reference_byte_count,
        @intCast(60 + index),
    );
    const journal = ref(
        .journal,
        1,
        61 + index,
        @intCast(70 + index),
    );
    return .{
        .segment_index = index,
        .recipe = recipe,
        .stage_inputs = .{
            input(.statement, 0, statement),
            input(.program, 0, globals.program),
            input(.profile, 0, recipe),
            input(.witness, 0, compact),
            input(.capture, 0, boundary),
            input(.capture, 1, public_reference),
            input(.journal, 0, journal),
        },
    };
}

fn input(
    role: artifact_store.InputRoleV1,
    ordinal: u32,
    blob: artifact_store.BlobRefV1,
) artifact_store.InputRefV1 {
    return .{ .role = role, .ordinal = ordinal, .blob = blob };
}

fn ref(
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    byte_count: u64,
    seed: u8,
) artifact_store.BlobRefV1 {
    var identity = [_]u8{seed} ** 32;
    identity[31] +%= 1;
    return artifact_store.BlobRefV1.create(
        kind,
        schema_version,
        byte_count,
        identity,
    ) catch unreachable;
}

fn digest(seed: u8) [32]u8 {
    var result = [_]u8{seed} ** 32;
    result[31] +%= 1;
    return result;
}

comptime {
    if (opener_mod.TRANSITIVE_Q193_GATE_GREEN or
        opener_mod.PRODUCTION_ACTIVATION or opener_mod.ROUTER_ACTIVATION or
        subject.PRODUCTION_ACTIVATION or subject.ROUTER_ACTIVATION or
        subject.GENUINE_Q193_GATE_GREEN)
    {
        @compileError("three-leaf genuine gate escalated production authority");
    }
}

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const role0_mod =
    @import("recursive_common_ethereum_incremental_leaf_campaign_prefinal_fold_child_v4.zig");
const role0_proof_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4.zig");
const recursive_core = @import("recursive_fri_outer.zig");
const live_mod =
    @import("recursive_common_fold_campaign_prefinal_live_v2.zig");
const proof_mod =
    @import("recursive_common_fold_campaign_prefinal_proof_v2.zig");
const final_proof_mod =
    @import("recursive_common_fold_campaign_final_proof_v2.zig");
const final_backend_mod =
    @import("recursive_pipeline_worker_campaign_common_fold_v2.zig");
const campaign_artifact_mod =
    @import("recursive_campaign_node_artifact_v2.zig");
const child_opener_mod =
    @import("recursive_pipeline_worker_campaign_child_cold_opener_v2.zig");
const real_inventory_opener_mod =
    @import("recursive_pipeline_worker_campaign_real_leaf_inventory_opener_v4.zig");
const real_backend_mod =
    @import("recursive_pipeline_worker_campaign_real_leaf_backend_v4.zig");
const real_leaf_composite_mod =
    @import("recursive_pipeline_worker_campaign_real_leaf_composite_v4.zig");
const final_worker_transaction_mod =
    @import("recursive_pipeline_campaign_final_worker_transaction_v2.zig");
const final_composite_mod =
    @import("recursive_pipeline_worker_campaign_final_composite_v2.zig");
const final_driver_mod =
    @import("recursive_pipeline_campaign_final_driver_v2.zig");
const final_live_runtime_mod =
    @import("recursive_pipeline_campaign_final_live_runtime_v2.zig");
const final_owned_live_runtime_mod =
    @import("recursive_pipeline_campaign_final_owned_live_runtime_v2.zig");
const final_assembly_bound_runtime_mod =
    @import("recursive_pipeline_campaign_final_assembly_bound_runtime_v2.zig");
const stage102_final_lifecycle_mod =
    @import("recursive_pipeline_worker_campaign_stage102_final_lifecycle_v4.zig");
const target_native_q193_mod =
    @import("recursive_pipeline_campaign_target_native_q193_pairs_v2.zig");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const stage102_inventory_mod =
    @import("recursive_pipeline_worker_campaign_stage102_inventory_v4.zig");
const stage102_inventory_builder_mod =
    @import("recursive_pipeline_worker_campaign_stage102_inventory_builder_v4.zig");
const session_provider_mod =
    @import("recursive_pipeline_worker_campaign_session_provider_v4.zig");
const role0_final_mod =
    @import("recursive_common_ethereum_incremental_leaf_campaign_fold_child_v4.zig");
const role1_final_mod =
    @import("recursive_common_canonical_empty_campaign_fold_child_v2.zig");
const canonical_proof =
    @import("recursive_common_canonical_empty_universal_proof_v2.zig");
const campaign_empty_proof =
    @import("recursive_common_canonical_empty_campaign_universal_proof_v2.zig");
const genuine_final =
    @import("recursive_pipeline_campaign_genuine_final_remint_v2.zig");
const genuine_three_leaf_fixture_mod =
    @import("recursive_pipeline_campaign_genuine_three_leaf_final_remint_fixture_v2.zig");
const genuine_three_leaf_tree_gate_mod =
    @import("recursive_pipeline_campaign_genuine_three_leaf_tree_gate_v2.zig");
const authenticated_stage101_mod =
    @import("recursive_pipeline_campaign_genuine_stage101_authenticated_inputs_v4.zig");
const genuine_stage102_tree_lifecycle_mod =
    @import("recursive_pipeline_campaign_genuine_stage102_tree_lifecycle_v4.zig");
const prefinal =
    @import("recursive_pipeline_campaign_prefinal_fold_lease_v2.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const padding_remint_mod =
    @import("recursive_common_wrapper_padding_remint_v2.zig");
const campaign_final_mod =
    @import("recursive_pipeline_campaign_final_remint_v2.zig");
const padding_fixture_mod =
    @import("recursive_common_wrapper_padding_remint_v2_test.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);

fn FixtureLease(comptime role: registry_mod.CircuitRoleV1) type {
    return struct {
        pub const ROLE = role;

        pub fn validateForPaddingTarget(
            _: *const @This(),
            _: *const target_mod.CampaignPaddingTargetV2,
        ) !void {
            return error.FixturePreFinalProjectionUnavailable;
        }

        pub fn preFinalFoldProjection(
            _: *const @This(),
            _: *const target_mod.CampaignPaddingTargetV2,
        ) !prefinal.ProjectionV2 {
            return error.FixturePreFinalProjectionUnavailable;
        }
    };
}

const RealFixtureLease = FixtureLease(.ethereum_incremental_leaf_wrapper_v4);
const EmptyFixtureLease = FixtureLease(.canonical_empty_field_v2);
const LiveTypes = live_mod.Types(RealFixtureLease, EmptyFixtureLease);
const PrefinalProof = proof_mod.Types(
    canonical_proof.CAPTURE_DERIVED_FIXED_WIRE_DIMENSIONS_V2,
    RealFixtureLease,
    EmptyFixtureLease,
);
const Role0Types = role0_mod.Types(Engine);
const Role0Proof = role0_proof_mod.Types(Engine);
const GenuineFinal = blk: {
    // Test-only type analysis spans all three 36-row q193 cohorts.
    @setEvalBranchQuota(500_000);
    break :blk genuine_final.Types(
        Engine,
        canonical_proof.CAPTURE_DERIVED_FIXED_WIRE_DIMENSIONS_V2,
    );
};
const FinalRole2 = blk: {
    // The all-level common arm recursively names this exact output lease.
    @setEvalBranchQuota(500_000);
    break :blk final_proof_mod.AllLevelTypes(
        canonical_proof.CAPTURE_DERIVED_FIXED_WIRE_DIMENSIONS_V2,
        role0_final_mod.Types(Engine).OwnedLeaseV4,
        role1_final_mod.OwnedLeaseV2,
        FinalChildOpenerFactory,
    );
};
const TargetNativeQ193 = blk: {
    // Test-only analysis reaches both target-native 36-row q193 bodies.
    @setEvalBranchQuota(500_000);
    break :blk target_native_q193_mod.Types(FinalRole2);
};
const FinalRole2Backend = final_backend_mod.BackendForProofFamily(
    FinalRole2.ProofFamily,
    FinalRole2.DependencyLease,
    UnavailableFinalExecutionPolicy,
);

const GenuineThreeLeafFixtureV2 = blk: {
    @setEvalBranchQuota(500_000);
    break :blk genuine_three_leaf_fixture_mod.Types(
        Engine,
        canonical_proof.CAPTURE_DERIVED_FIXED_WIRE_DIMENSIONS_V2,
        campaign_empty_proof.OwnedColdProofV2,
        PrefinalProof.OwnedColdProofV2,
    );
};
const FinalActiveSourcesV2 = GenuineThreeLeafFixtureV2.ActiveSourcesV2;
const FinalWorkerRole0Backend = blk: {
    // Test-only analysis instantiates the complete role-0 q193 body.
    @setEvalBranchQuota(500_000);
    break :blk real_backend_mod.BackendFor(
        Engine,
        FinalActiveSourcesV2,
        UnavailableFinalExecutionPolicy,
    );
};
const FinalWorkerSessionV4 = stage102_inventory_mod.SessionFor(
    FinalWorkerRole0Backend.AuthorityV4,
);
const FinalWorkerInventoryBuilderV4 = stage102_inventory_builder_mod.BuilderFor(
    FinalWorkerRole0Backend.AuthorityV4,
);
const FinalWorkerProviderV4 = session_provider_mod.ProviderFor(
    FinalWorkerSessionV4,
);
const FinalWorkerBuilderProviderV4 = session_provider_mod.ProviderFor(
    FinalWorkerInventoryBuilderV4,
);
const FinalWorkerTransaction = blk: {
    @setEvalBranchQuota(500_000);
    break :blk final_worker_transaction_mod.Types(
        Engine,
        canonical_proof.CAPTURE_DERIVED_FIXED_WIRE_DIMENSIONS_V2,
        FinalActiveSourcesV2,
        FinalWorkerProviderV4,
        FinalWorkerProviderV4,
    );
};
const ProductionFinalRole2 = FinalWorkerTransaction.Role2TypesV2;
const ProductionFinalRole2Proof = ProductionFinalRole2.ProofFamily;
const ProductionFinalChildOpener = ProductionFinalRole2.ChildColdOpener;
const ProductionFinalRole0Opener =
    FinalWorkerTransaction.Role0InventoryOpenerV4;
const FinalCompositeV2 = final_composite_mod.AdapterFor(
    FinalWorkerTransaction,
    FinalWorkerProviderV4,
);
const FinalDriverV2 = final_driver_mod.DriverFor(
    FinalWorkerSessionV4,
    FinalCompositeV2,
);
const FinalLiveRuntimeV2 = blk: {
    // Test-only closure reaches the complete campaign Worker/binder/executor
    // type graph without making any route available.
    @setEvalBranchQuota(500_000);
    break :blk final_live_runtime_mod.Types(
        FinalWorkerTransaction,
        FinalWorkerProviderV4,
    );
};
const ExactStage102LifecycleV4 = blk: {
    @setEvalBranchQuota(500_000);
    break :blk stage102_final_lifecycle_mod.CampaignSupervisorFor(
        Engine,
        FinalActiveSourcesV2,
        UnavailableFinalExecutionPolicy,
    );
};
const FinalLiveRuntimeEpochV2 = blk: {
    @setEvalBranchQuota(500_000);
    break :blk FinalLiveRuntimeV2.LifecycleEpochFor(
        ExactStage102LifecycleV4,
    );
};
const FinalOwnedRuntimeV2 = blk: {
    @setEvalBranchQuota(500_000);
    break :blk final_owned_live_runtime_mod.OwnerFor(
        FinalLiveRuntimeEpochV2,
        ExactStage102LifecycleV4,
    );
};
const FinalAssemblyBoundRuntimeV2 = blk: {
    @setEvalBranchQuota(500_000);
    break :blk final_assembly_bound_runtime_mod.OwnerFor(
        FinalOwnedRuntimeV2,
        FinalWorkerTransaction.ValidatedAssemblyV2,
        FinalActiveSourcesV2,
    );
};
const GenuineThreeLeafTreeGateV2 = blk: {
    // Exact-body closure reaches role0 replay plus all three recursive q193
    // parent types. The runtime-false test below performs no proof work.
    @setEvalBranchQuota(500_000);
    break :blk genuine_three_leaf_tree_gate_mod.Types(
        GenuineThreeLeafFixtureV2,
        ExactStage102LifecycleV4,
        FinalWorkerTransaction,
        TargetNativeQ193,
        FinalDriverV2,
    );
};
const AuthenticatedStage101V4 = authenticated_stage101_mod.Types(Engine);
const GenuineStage102LifecycleAssemblyV4 = struct {
    pub const AuthorityV4 = FinalWorkerRole0Backend.AuthorityV4;

    /// The installed mutable/immutable provider is both the exact campaign
    /// authority and the execution-policy authority. This avoids the older
    /// cold-open-only lifecycle specialization's unavailable policy stub.
    pub fn AdapterFor(comptime Provider: type) type {
        return real_leaf_composite_mod.CampaignAdapterFor(
            Engine,
            FinalActiveSourcesV2,
            Provider,
            Provider,
        );
    }

    pub fn Role0OpenerFor(comptime Provider: type) type {
        return real_inventory_opener_mod.OpenerFor(
            real_backend_mod.BackendFor(
                Engine,
                FinalActiveSourcesV2,
                Provider,
            ),
            Provider,
        );
    }
};
const GenuineStage102LifecycleV4 = blk: {
    @setEvalBranchQuota(500_000);
    break :blk stage102_final_lifecycle_mod.SupervisorFor(
        GenuineStage102LifecycleAssemblyV4,
    );
};
const GenuineStage102BoundTreeGateV2 = blk: {
    @setEvalBranchQuota(500_000);
    break :blk genuine_three_leaf_tree_gate_mod.Types(
        GenuineThreeLeafFixtureV2,
        GenuineStage102LifecycleV4,
        FinalWorkerTransaction,
        TargetNativeQ193,
        FinalDriverV2,
    );
};
const GenuineStage102TreeLifecycleV4 = blk: {
    // This exact-body family spans authenticated Stage-101 custody, the
    // mutable Stage-102 worker epoch, immutable install, and the final tree.
    @setEvalBranchQuota(500_000);
    break :blk genuine_stage102_tree_lifecycle_mod.Types(
        Engine,
        AuthenticatedStage101V4,
        GenuineThreeLeafFixtureV2,
        GenuineStage102LifecycleV4,
        GenuineStage102BoundTreeGateV2,
    );
};

const RuntimePlanVisitor = struct {
    shape: *const final_driver_mod.Shape,
    stage103_count: u32 = 0,
    stage104_count: u32 = 0,
    first_empty: ?final_driver_mod.Coordinate = null,
    last_parent: ?final_driver_mod.Coordinate = null,

    pub fn stage103(
        self: *RuntimePlanVisitor,
        coordinate: final_driver_mod.Coordinate,
    ) !void {
        try @import("recursive_campaign_node_public_v2.zig")
            .validateStageCoordinate(self.shape, .leaf_wrapper, coordinate);
        if (coordinate.index < self.shape.real_leaf_count)
            return error.UnexpectedRuntimePlanCoordinate;
        if (self.first_empty == null) self.first_empty = coordinate;
        self.stage103_count += 1;
    }

    pub fn stage104(
        self: *RuntimePlanVisitor,
        parent: final_driver_mod.Coordinate,
        left: final_driver_mod.Coordinate,
        right: final_driver_mod.Coordinate,
    ) !void {
        const expected = try self.shape.parentCoordinate(
            parent.height,
            parent.index,
        );
        if (parent.height == 0 or left.height + 1 != parent.height or
            right.height != left.height or
            left.index != parent.index * 2 or
            right.index != left.index + 1 or
            parent.global_ordinal != expected.global_ordinal)
        {
            return error.UnexpectedRuntimePlanCoordinate;
        }
        self.last_parent = parent;
        self.stage104_count += 1;
    }
};

test "campaign pre-final role0 child is cold-owned and fail-closed on padding" {
    try std.testing.expect(!role0_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!role0_mod.ROUTER_ACTIVATION);
    try std.testing.expect(!role0_mod.HOST_PADDING_ADMITTED);
    try std.testing.expect(!role0_mod.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expectEqual(
        registry_mod.CircuitRoleV1.ethereum_incremental_leaf_wrapper_v4,
        Role0Types.OwnedPreFinalLeaseV4.ROLE,
    );
    inline for (.{
        "initOwned",
        "validateForPaddingTarget",
        "validateColdGeometry",
        "geometryForPaddingTarget",
        "preFinalFoldProjection",
    }) |name| try std.testing.expect(
        @hasDecl(Role0Types.OwnedPreFinalLeaseV4, name),
    );
    try std.testing.expect(!@hasDecl(
        Role0Types.OwnedPreFinalLeaseV4,
        "encode",
    ));
    try std.testing.expect(@hasDecl(
        Role0Proof.CoreV4.KernelV4,
        "proveAndColdVerifyWithCohort",
    ));
    inline for (.{
        "proveAndColdVerifyPreFinal",
        "coldOpenPreFinal",
    }) |name| try std.testing.expect(@hasDecl(Role0Proof, name));

    var active: recursive_core.NativeSegmentCoreLogSizesV2 = @splat(4);
    var requested = active;
    requested[0] = 5;
    try std.testing.expectEqualDeep(
        requested,
        try recursive_core.selectPaddedNativeCoreLogSizesV2(
            active,
            requested,
        ),
    );

    requested = active;
    requested[0] = 3;
    try std.testing.expectError(
        error.AuthorityMismatch,
        recursive_core.selectPaddedNativeCoreLogSizesV2(active, requested),
    );

    active[0] = 0;
    requested = active;
    requested[0] = 4;
    try std.testing.expectError(
        error.AuthorityMismatch,
        recursive_core.selectPaddedNativeCoreLogSizesV2(active, requested),
    );

    active[0] = 4;
    requested = active;
    requested[0] = 31;
    try std.testing.expectError(
        error.AuthorityMismatch,
        recursive_core.selectPaddedNativeCoreLogSizesV2(active, requested),
    );
}

test "campaign pre-final role2 types retain typed children and no durable node" {
    try std.testing.expect(!proof_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!proof_mod.ROUTER_ACTIVATION);
    try std.testing.expect(!proof_mod.DURABLE_PREFINAL_NODE_AVAILABLE);
    try std.testing.expect(!proof_mod.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expectEqual(
        registry_mod.CircuitRoleV1.common_fold_field_v2,
        PrefinalProof.OwnedColdProofV2.ROLE,
    );
    try std.testing.expect(@hasField(
        LiveTypes.FoldChild,
        "ethereum_incremental_leaf_wrapper_v4",
    ));
    try std.testing.expect(@hasField(
        LiveTypes.FoldChild,
        "canonical_empty_field_v2",
    ));
    try std.testing.expect(!@hasField(
        LiveTypes.FoldChild,
        "common_fold_field_v2",
    ));
    inline for (.{
        "proveAndColdVerify",
        "coldOpen",
    }) |name| try std.testing.expect(@hasDecl(PrefinalProof, name));
    inline for (.{
        "validateForPaddingTarget",
        "validateColdGeometry",
        "geometryForPaddingTarget",
        "preFinalFoldProjection",
        "proofBytes",
    }) |name| try std.testing.expect(
        @hasDecl(PrefinalProof.OwnedColdProofV2, name),
    );
    try std.testing.expect(!@hasField(
        PrefinalProof.OwnedColdProofV2,
        "node_artifact",
    ));
    try std.testing.expect(!@hasDecl(
        PrefinalProof.OwnedColdProofV2,
        "encode",
    ));
    _ = PrefinalProof.FixedV2.WireV2;
    _ = PrefinalProof.SecureCohortV2;

    const sources = .{
        Role0Proof.OwnedColdProofV4,
        campaign_empty_proof.OwnedColdProofV2,
        PrefinalProof.OwnedColdProofV2,
    };
    inline for (sources, 0..) |Source, ordinal| {
        try std.testing.expectEqual(
            @as(u8, @intCast(ordinal)),
            @intFromEnum(Source.ROLE),
        );
        inline for (.{
            "validateForPaddingTarget",
            "validateColdGeometry",
            "geometryForPaddingTarget",
        }) |name| try std.testing.expect(@hasDecl(Source, name));
        try std.testing.expect(!@hasDecl(Source, "encode"));
    }

    try std.testing.expect(!genuine_final.PRODUCTION_ACTIVATION);
    try std.testing.expect(!genuine_final.ROUTER_ACTIVATION);
    try std.testing.expect(!genuine_final.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(!genuine_final.BOOTSTRAP_GEOMETRY_ADMITTED);
    try std.testing.expect(
        genuine_final.FINAL_REMINT_AFTER_THREE_COLD_PROOFS,
    );
    try std.testing.expect(@hasDecl(GenuineFinal, "proveAndFinalize"));
    try std.testing.expect(@hasDecl(GenuineFinal.OwnedV2, "validate"));
    try std.testing.expect(@hasDecl(GenuineFinal.OwnedV2, "authority"));
    try std.testing.expect(!@hasDecl(GenuineFinal.OwnedV2, "encode"));
    try std.testing.expect(!@hasDecl(GenuineFinal.OwnedV2, "decode"));

    // The mismatched sealed ExecutionKey returns before touching the
    // deliberately unavailable genuine fixtures, while the call still type-
    // instantiates the complete role0 -> role1 -> role2 -> FinalRemint body.
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
        .semantic_key_identity = digest(1),
        .producer_identity = digest(2),
        .verifier_identity = digest(3),
        .source_identity = digest(4),
        .build_identity = digest(5),
        .executable_identity = digest(6),
        .toolchain_identity = digest(7),
        .backend_identity = digest(8),
        .optimization_identity = digest(9),
        .worker_policy_identity = digest(10),
        .memory_policy_identity = policy.memory_policy_identity,
        .retention_policy_identity = digest(11),
        .timeout_policy_identity = digest(12),
    });
    const active_sources = .{
        @as(*const Role0Proof.OwnedColdProofV4, undefined),
        @as(*const campaign_empty_proof.OwnedColdProofV2, undefined),
        @as(*const PrefinalProof.OwnedColdProofV2, undefined),
    };
    try std.testing.expectError(
        error.RecursiveExecutionPolicyMismatch,
        GenuineFinal.proveAndFinalize(
            std.testing.allocator,
            active_sources,
            undefined,
            undefined,
            undefined,
            undefined,
            execution,
            &policy,
        ),
    );
}

test "campaign final role2 family is self-recursive and owns reopened children" {
    std.testing.refAllDecls(FinalWorkerInventoryBuilderV4);
    std.testing.refAllDecls(
        FinalWorkerInventoryBuilderV4.OwnedSealedSessionV4,
    );
    const Family = FinalRole2.ProofFamily;
    const Dependency = FinalRole2.DependencyLease;
    try std.testing.expect(!Family.available);
    try std.testing.expect(!FinalRole2Backend.available);
    try std.testing.expect(!Family.q193_genuine_gate_green);
    try std.testing.expect(!final_proof_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!final_proof_mod.ROUTER_ACTIVATION);
    try std.testing.expect(!final_proof_mod.Q193_GENUINE_GATE_GREEN);
    try std.testing.expect(
        !final_proof_mod.ALL_NOMINAL_CHILD_PAIRS_AVAILABLE,
    );
    try std.testing.expect(
        final_proof_mod.BUILD_BORROWS_ORIGINAL_CHILDREN,
    );
    try std.testing.expect(
        final_proof_mod.OUTPUT_LEASE_OWNS_COLD_OPENED_CHILDREN,
    );
    try std.testing.expect(!child_opener_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!child_opener_mod.ROUTER_ACTIVATION);
    try std.testing.expect(
        child_opener_mod.COLD_OPEN_OWNS_EVERY_CHILD,
    );
    try std.testing.expect(
        child_opener_mod.PARTIAL_FAILURE_DEINITS_EXACTLY_ONCE,
    );
    try std.testing.expect(!FinalRole2.ChildColdOpener.available);
    try std.testing.expectEqual(
        registry_mod.CircuitRoleV1.common_fold_field_v2,
        Family.LeasePayload.ROLE,
    );
    inline for (.{ "fromReal", "fromEmpty", "fromCommon" }) |name|
        try std.testing.expect(@hasDecl(Dependency, name));
    inline for (.{
        "validateForCampaign",
        "campaignFoldProjection",
        "foldProjection",
        "nodeArtifact",
        "proofBytes",
        "requireFoldChild",
        "deinit",
    }) |name| try std.testing.expect(@hasDecl(Family.LeasePayload, name));
    inline for (.{
        "validateBorrowedChildren",
        "proveAndColdVerify",
        "coldOpenOwned",
        "validateLease",
        "deinitLeasePayload",
    }) |name| try std.testing.expect(@hasDecl(Family, name));
    try std.testing.expect(!@hasDecl(Dependency, "encode"));
    try std.testing.expect(!@hasDecl(Family.LeasePayload, "encode"));

    try std.testing.expect(!FinalWorkerTransaction.available);
    try std.testing.expect(
        !final_worker_transaction_mod.PRODUCTION_ACTIVATION,
    );
    try std.testing.expect(!final_worker_transaction_mod.ROUTER_ACTIVATION);
    try std.testing.expect(
        final_worker_transaction_mod.ALL_ROLES_SHARE_ONE_FINAL_REMINT,
    );
    try std.testing.expect(
        final_worker_transaction_mod.EXTERNAL_INVENTORY_IS_TRANSPORT_ONLY,
    );
    try std.testing.expect(
        !real_inventory_opener_mod.TRANSITIVE_Q193_GATE_GREEN,
    );
    try std.testing.expect(
        !FinalWorkerTransaction.Role0InventoryOpenerV4.available,
    );
    try std.testing.expect(!FinalWorkerProviderV4.isInstalled());
    try std.testing.expect(!FinalWorkerBuilderProviderV4.isInstalled());
    try std.testing.expect(
        stage102_inventory_mod.ORDERED_COMPLETE_REAL_INVENTORY,
    );
    try std.testing.expect(
        stage102_inventory_mod.VALIDATE_ALL_CAS_AT_INSTALL,
    );
    try std.testing.expect(
        stage102_inventory_mod.ADOPTION_IS_EXACT_IDEMPOTENT_CONFIRMATION,
    );
    try std.testing.expect(
        !stage102_inventory_mod.REQUEST_POINTERS_RETAINED,
    );
    try std.testing.expect(
        FinalWorkerRole0Backend.LeasePayload ==
            FinalWorkerTransaction.Role0InventoryOpenerV4.LeasePayload,
    );
    inline for (.{
        "init",
        "validate",
        "finalRemint",
    }) |name| try std.testing.expect(@hasDecl(
        FinalWorkerTransaction.ValidatedAssemblyV2,
        name,
    ));
    try std.testing.expect(!@hasDecl(
        FinalWorkerTransaction.ValidatedAssemblyV2,
        "encode",
    ));
    inline for (.{
        "validate",
        "authorityForCampaign",
        "stage102AdmissionForOutput",
        "finalRemintForCampaign",
        "policyForExecution",
        "adoptStage102ColdPublication",
    }) |name| try std.testing.expect(@hasDecl(FinalWorkerSessionV4, name));
    try std.testing.expect(!@hasDecl(FinalWorkerSessionV4, "encode"));

    try std.testing.expect(
        stage102_inventory_builder_mod.REQUEST_PROJECTIONS_DEEP_OWNED,
    );
    try std.testing.expect(
        stage102_inventory_builder_mod.POINTER_STABLE_COORDINATE_SLOTS,
    );
    try std.testing.expect(
        stage102_inventory_builder_mod.OUT_OF_ORDER_ARRIVAL_CANONICALIZED,
    );
    try std.testing.expect(
        stage102_inventory_builder_mod.SEAL_COMPLETE_IS_ATOMIC,
    );
    inline for (.{
        "init",
        "validate",
        "authorityForCampaign",
        "stage102AdmissionForOutput",
        "finalRemintForCampaign",
        "policyForExecution",
        "adoptStage102ColdPublication",
        "sealComplete",
        "adoptedCount",
        "deinit",
    }) |name| try std.testing.expect(@hasDecl(
        FinalWorkerInventoryBuilderV4,
        name,
    ));
    inline for (.{ "sessionView", "validate", "deinit" }) |name|
        try std.testing.expect(@hasDecl(
            FinalWorkerInventoryBuilderV4.OwnedSealedSessionV4,
            name,
        ));
    try std.testing.expect(!@hasDecl(
        FinalWorkerInventoryBuilderV4,
        "encode",
    ));
    try std.testing.expect(!@hasDecl(
        FinalWorkerInventoryBuilderV4.OwnedSealedSessionV4,
        "encode",
    ));
}

test "campaign final composite owns nominal 102 103 104 leases and stays closed" {
    std.testing.refAllDecls(FinalCompositeV2);
    std.testing.refAllDecls(FinalDriverV2);
    try std.testing.expect(!FinalCompositeV2.available);
    try std.testing.expect(!FinalCompositeV2.production);
    try std.testing.expect(!final_composite_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!final_composite_mod.ROUTER_ACTIVATION);
    try std.testing.expect(!final_composite_mod.GENUINE_Q193_GATE_GREEN);
    try std.testing.expect(final_composite_mod.STAGE102_IS_COLD_OPEN_ONLY);
    try std.testing.expect(
        final_composite_mod.BUILD_BORROWS_TYPED_CHILDREN,
    );
    try std.testing.expect(
        final_composite_mod.BUILD_FAILURE_RETAINS_CHILDREN,
    );
    try std.testing.expect(
        final_composite_mod.SUCCESS_CONSUMES_AFTER_OUTER_PUBLICATION,
    );
    try std.testing.expect(@hasField(
        FinalCompositeV2.LeasePayload,
        "real_wrapper_v4",
    ));
    try std.testing.expect(@hasField(
        FinalCompositeV2.LeasePayload,
        "canonical_empty_v2",
    ));
    try std.testing.expect(@hasField(
        FinalCompositeV2.LeasePayload,
        "common_fold_v2",
    ));
    try std.testing.expect(!@hasDecl(FinalCompositeV2.LeasePayload, "encode"));
    try std.testing.expect(@hasDecl(
        FinalWorkerTransaction.Role2TypesV2.CommonLeaseHandleV2,
        "borrow",
    ));

    const stage102 = try FinalCompositeV2.describe(.prove, 102);
    const stage103 = try FinalCompositeV2.describe(.prove, 103);
    const stage104 = try FinalCompositeV2.describe(.fold, 104);
    try std.testing.expectEqual(@as(u16, 102), stage102.stage_schema_version);
    try std.testing.expectEqual(@as(u16, 103), stage103.stage_schema_version);
    try std.testing.expectEqual(@as(u16, 104), stage104.stage_schema_version);
    try std.testing.expect(stage102.root_cold_open_transitive);
    try std.testing.expect(stage103.root_cold_open_transitive);
    try std.testing.expect(stage104.root_cold_open_transitive);
    try std.testing.expectError(
        error.CampaignFinalCompositeStageMismatch,
        FinalCompositeV2.describe(.fold, 103),
    );
}

test "campaign final driver derives nonlegacy topology and exact execution envelope" {
    const shape3 = try final_driver_mod.Shape.init(digest(21), digest(22), 3);
    const plan3 = try final_driver_mod.TopologyPlanV2.init(&shape3);
    try std.testing.expectEqual(@as(u32, 3), plan3.real_leaf_count);
    try std.testing.expectEqual(@as(u32, 4), plan3.padded_leaf_count);
    try std.testing.expectEqual(@as(u32, 1), plan3.empty_leaf_count);
    try std.testing.expectEqual(@as(u32, 3), plan3.fold_count);
    try std.testing.expectEqual(@as(u16, 3), plan3.level_count);
    var visitor3 = RuntimePlanVisitor{ .shape = &shape3 };
    try final_driver_mod.walkRuntimePlan(&shape3, &visitor3);
    try std.testing.expectEqual(@as(u32, 1), visitor3.stage103_count);
    try std.testing.expectEqual(@as(u32, 3), visitor3.stage104_count);
    try std.testing.expectEqual(@as(u32, 3), visitor3.first_empty.?.index);
    try std.testing.expectEqual(@as(u8, 2), visitor3.last_parent.?.height);
    try std.testing.expectEqual(@as(u32, 0), visitor3.last_parent.?.index);

    const shape13 = try final_driver_mod.Shape.init(
        digest(23),
        digest(24),
        13,
    );
    const plan13 = try final_driver_mod.TopologyPlanV2.init(&shape13);
    try std.testing.expectEqual(@as(u32, 16), plan13.padded_leaf_count);
    try std.testing.expectEqual(@as(u32, 3), plan13.empty_leaf_count);
    try std.testing.expectEqual(@as(u32, 15), plan13.fold_count);
    try std.testing.expectEqual(@as(u16, 5), plan13.level_count);
    try std.testing.expectEqual(
        @as(u32, 2),
        try plan13.nodeCountAt(&shape13, 3),
    );
    var visitor13 = RuntimePlanVisitor{ .shape = &shape13 };
    try final_driver_mod.walkRuntimePlan(&shape13, &visitor13);
    try std.testing.expectEqual(@as(u32, 3), visitor13.stage103_count);
    try std.testing.expectEqual(@as(u32, 15), visitor13.stage104_count);
    try std.testing.expectEqual(@as(u32, 13), visitor13.first_empty.?.index);
    try std.testing.expectEqual(@as(u8, 4), visitor13.last_parent.?.height);
    try std.testing.expectEqual(@as(u32, 0), visitor13.last_parent.?.index);

    const host = try policy_mod.HostExecutionAuthorityV2.init(6, 24_000);
    const policy = try policy_mod.PolicyV2.init(host, .{
        .total_cpu_tokens = 6,
        .cpu_tokens_per_node = 3,
        .proof_worker_count = 3,
        .maximum_parallel_nodes = 2,
        .total_rss_bytes = 24_000,
        .rss_bytes_per_node = 12_000,
    });
    var padding_fixture = try padding_fixture_mod.Fixture.init();
    const padding_target = try target_mod.CampaignPaddingTargetV2.derive(
        &shape13,
        padding_fixture.activeSources(),
    );
    padding_fixture.remintForTarget(&padding_target.target);
    const final_remint = try padding_remint_mod.FinalRemintAuthorityV2.mint(
        &padding_target.target,
        padding_fixture.activeSources(),
        padding_fixture.finalSources(),
    );
    const final_authority = try campaign_final_mod
        .CampaignFinalRemintAuthorityV2.init(&shape13, &final_remint);
    const description = try final_driver_mod.RuntimePlanDescriptionV2.init(
        &final_authority,
        &policy,
    );
    try description.validate(&final_authority, &policy);
    var described_visitor = RuntimePlanVisitor{ .shape = &shape13 };
    try final_driver_mod.walkDescribedRuntimePlan(
        &description,
        &final_authority,
        &policy,
        &described_visitor,
    );
    try std.testing.expectEqual(
        visitor13.stage103_count,
        described_visitor.stage103_count,
    );
    try std.testing.expectEqual(
        visitor13.stage104_count,
        described_visitor.stage104_count,
    );
    try std.testing.expect(
        !@hasField(final_driver_mod.RuntimePlanDescriptionV2, "output_ref"),
    );
    try std.testing.expect(
        !@hasField(
            final_driver_mod.RuntimePlanDescriptionV2,
            "stage_manifest_ref",
        ),
    );
    var hostile_description = description;
    hostile_description.maximum_parallel_nodes += 1;
    try std.testing.expectError(
        error.CampaignFinalDriverTopologyMismatch,
        hostile_description.validate(&final_authority, &policy),
    );
    hostile_description = description;
    hostile_description.registry_identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.CampaignFinalDriverTopologyMismatch,
        hostile_description.validate(&final_authority, &policy),
    );
    const no_inputs = [_]artifact_store.InputRefV1{};
    const semantic = try artifact_store.SemanticKeyV1.create(
        std.testing.allocator,
        .{
            .stage_kind = .prove,
            .stage_schema_version = 103,
            .campaign_namespace = digest(31),
            .local_task_identity = digest(32),
            .protocol_identity = digest(33),
            .program_identity = digest(34),
            .profile_identity = digest(35),
            .pcs_identity = digest(36),
            .security_identity = digest(37),
            .statement_identity = digest(38),
            .layout_identity = digest(39),
            .registry_identity = digest(40),
            .semantic_options_identity = digest(41),
            .ordered_inputs = &no_inputs,
        },
    );
    const execution = try artifact_store.ExecutionKeyV1.create(.{
        .semantic_key_identity = semantic.identity,
        .producer_identity = digest(42),
        .verifier_identity = digest(43),
        .source_identity = digest(44),
        .build_identity = digest(45),
        .executable_identity = digest(46),
        .toolchain_identity = digest(47),
        .backend_identity = digest(48),
        .optimization_identity = digest(49),
        .worker_policy_identity = policy.worker_policy_identity,
        .memory_policy_identity = policy.memory_policy_identity,
        .retention_policy_identity = digest(50),
        .timeout_policy_identity = digest(51),
    });
    const dependencies = [_]@import(
        "recursive_pipeline_worker_protocol_v1.zig",
    ).Dependency{};
    const external_inputs = [_]artifact_store.InputRefV1{};
    var node = @import(
        "recursive_pipeline_worker_protocol_v1.zig",
    ).Node{
        .node_id = "empty/3",
        .stage_kind = .prove,
        .stage_schema_version = 103,
        .adapter = final_composite_mod.adapter_name,
        .dependencies = &dependencies,
        .external_inputs = &external_inputs,
        .local_task_identity_sha256 = digest(32),
        .semantic_authorities = .{
            .protocol_identity_sha256 = digest(33),
            .program_identity_sha256 = digest(34),
            .profile_identity_sha256 = digest(35),
            .pcs_identity_sha256 = digest(36),
            .security_identity_sha256 = digest(37),
            .statement_identity_sha256 = digest(38),
            .provider_identity_sha256 = [_]u8{0} ** 32,
            .layout_identity_sha256 = digest(39),
            .registry_identity_sha256 = digest(40),
        },
        .semantic_options = .null,
        .cpu_tokens = 3,
        .rss_tokens = 12_000,
        .output_kind = .recursion_node,
        .output_schema_version = 2,
    };
    const output_ref = try artifact_store.BlobRefV1.create(
        .recursion_node,
        2,
        2380,
        digest(52),
    );
    const manifest_ref = try artifact_store.BlobRefV1.create(
        .stage_manifest,
        1,
        512,
        digest(53),
    );
    const no_manifests = [_]artifact_store.BlobRefV1{};
    var receipt = final_driver_mod.CommittedStageV2{
        .node = &node,
        .semantic = &semantic,
        .execution = &execution,
        .ordered_inputs = &no_inputs,
        .output_ref = output_ref,
        .stage_manifest_ref = manifest_ref,
        .dependency_stage_manifest_refs = &no_manifests,
        .lease_id = "lease-empty-3",
    };
    try final_driver_mod.validateReceiptEnvelope(&receipt, &policy, 103, 0);

    node.cpu_tokens = 2;
    try std.testing.expectError(
        error.CampaignFinalDriverExecutionMismatch,
        final_driver_mod.validateReceiptEnvelope(&receipt, &policy, 103, 0),
    );
    node.cpu_tokens = 3;
    receipt.lease_id = "";
    try std.testing.expectError(
        error.CampaignFinalDriverExecutionMismatch,
        final_driver_mod.validateReceiptEnvelope(&receipt, &policy, 103, 0),
    );
    receipt.lease_id = "lease-empty-3";
    receipt.stage_manifest_ref.schema_version = 2;
    try std.testing.expectError(
        error.CampaignWorkerOutputMismatch,
        final_driver_mod.validateReceiptEnvelope(&receipt, &policy, 103, 0),
    );
    receipt.stage_manifest_ref.schema_version = 1;
    const wrong_execution = try artifact_store.ExecutionKeyV1.create(.{
        .semantic_key_identity = digest(60),
        .producer_identity = digest(42),
        .verifier_identity = digest(43),
        .source_identity = digest(44),
        .build_identity = digest(45),
        .executable_identity = digest(46),
        .toolchain_identity = digest(47),
        .backend_identity = digest(48),
        .optimization_identity = digest(49),
        .worker_policy_identity = policy.worker_policy_identity,
        .memory_policy_identity = policy.memory_policy_identity,
        .retention_policy_identity = digest(50),
        .timeout_policy_identity = digest(51),
    });
    receipt.execution = &wrong_execution;
    try std.testing.expectError(
        error.CampaignFinalDriverExecutionMismatch,
        final_driver_mod.validateReceiptEnvelope(&receipt, &policy, 103, 0),
    );
    receipt.execution = &execution;
    const aliased = [_]final_driver_mod.CommittedStageV2{ receipt, receipt };
    try std.testing.expectError(
        error.CampaignFinalDriverAlias,
        final_driver_mod.validateReceiptSet(&aliased),
    );
}

test "campaign q193 nominal pair plans derive every role from runtime shape" {
    var padding_fixture = try padding_fixture_mod.Fixture.init();
    const shape13 = try final_driver_mod.Shape.init(
        digest(101),
        digest(102),
        13,
    );
    const padding_target = try target_mod.CampaignPaddingTargetV2.derive(
        &shape13,
        padding_fixture.activeSources(),
    );
    padding_fixture.remintForTarget(&padding_target.target);
    const final_remint = try padding_remint_mod.FinalRemintAuthorityV2.mint(
        &padding_target.target,
        padding_fixture.activeSources(),
        padding_fixture.finalSources(),
    );
    const authority13 = try campaign_final_mod
        .CampaignFinalRemintAuthorityV2.init(&shape13, &final_remint);
    const inventory13 = try target_native_q193_mod.NominalPairInventoryV2
        .init(&authority13);
    try inventory13.validate(&authority13);
    try std.testing.expectEqual(
        @as(u32, 6),
        inventory13.count(.real_real),
    );
    try std.testing.expectEqual(
        @as(u32, 1),
        inventory13.count(.real_empty),
    );
    try std.testing.expectEqual(
        @as(u32, 1),
        inventory13.count(.empty_empty),
    );
    try std.testing.expectEqual(
        @as(u32, 7),
        inventory13.count(.common_common),
    );
    try std.testing.expectEqual(shape13.fold_count, inventory13.total);

    const real_real = try target_native_q193_mod.PairPlanV2.init(
        &authority13,
        try @import("recursive_campaign_node_public_v2.zig").coordinate(
            &shape13,
            1,
            0,
        ),
    );
    const real_empty = try target_native_q193_mod.PairPlanV2.init(
        &authority13,
        try @import("recursive_campaign_node_public_v2.zig").coordinate(
            &shape13,
            1,
            6,
        ),
    );
    const empty_empty = try target_native_q193_mod.PairPlanV2.init(
        &authority13,
        try @import("recursive_campaign_node_public_v2.zig").coordinate(
            &shape13,
            1,
            7,
        ),
    );
    const common_common = try target_native_q193_mod.PairPlanV2.init(
        &authority13,
        try @import("recursive_campaign_node_public_v2.zig").coordinate(
            &shape13,
            2,
            0,
        ),
    );
    try std.testing.expectEqual(
        target_native_q193_mod.NominalPairKindV2.real_real,
        real_real.kind,
    );
    try std.testing.expectEqual(
        target_native_q193_mod.NominalPairKindV2.real_empty,
        real_empty.kind,
    );
    try std.testing.expectEqual(
        target_native_q193_mod.NominalPairKindV2.empty_empty,
        empty_empty.kind,
    );
    try std.testing.expectEqual(
        target_native_q193_mod.NominalPairKindV2.common_common,
        common_common.kind,
    );
    try std.testing.expectEqualDeep(
        [_]registry_mod.CircuitRoleV1{
            .ethereum_incremental_leaf_wrapper_v4,
            .canonical_empty_field_v2,
        },
        real_empty.roles,
    );

    var hostile = real_empty;
    hostile.roles[1] = .ethereum_incremental_leaf_wrapper_v4;
    try std.testing.expectError(
        error.CampaignTargetNativeNominalPairMismatch,
        hostile.validate(&authority13),
    );
    hostile = real_empty;
    hostile.final_remint_binding_identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.CampaignTargetNativeNominalPairMismatch,
        hostile.validate(&authority13),
    );
    var hostile_inventory = inventory13;
    hostile_inventory.counts[
        @intFromEnum(
            target_native_q193_mod.NominalPairKindV2.common_common,
        )
    ] -= 1;
    try std.testing.expectError(
        error.CampaignTargetNativeNominalPairMismatch,
        hostile_inventory.validate(&authority13),
    );

    // A second depth proves that pair counts come from the authenticated
    // shape rather than a legacy campaign or host scheduling constant.
    const shape33 = try final_driver_mod.Shape.init(
        digest(103),
        digest(104),
        33,
    );
    const authority33 = try campaign_final_mod
        .CampaignFinalRemintAuthorityV2.init(&shape33, &final_remint);
    const inventory33 = try target_native_q193_mod.NominalPairInventoryV2
        .init(&authority33);
    try std.testing.expectEqual(@as(u32, 16), inventory33.count(.real_real));
    try std.testing.expectEqual(@as(u32, 1), inventory33.count(.real_empty));
    try std.testing.expectEqual(@as(u32, 15), inventory33.count(.empty_empty));
    try std.testing.expectEqual(
        @as(u32, 31),
        inventory33.count(.common_common),
    );
    try std.testing.expectEqual(shape33.fold_count, inventory33.total);
}

test "campaign q193 lifecycle plan binds final driver topology and execution envelope" {
    var padding_fixture = try padding_fixture_mod.Fixture.init();
    const shape = try final_driver_mod.Shape.init(
        digest(132),
        digest(133),
        13,
    );
    const padding_target = try target_mod.CampaignPaddingTargetV2.derive(
        &shape,
        padding_fixture.activeSources(),
    );
    padding_fixture.remintForTarget(&padding_target.target);
    const final_remint = try padding_remint_mod.FinalRemintAuthorityV2.mint(
        &padding_target.target,
        padding_fixture.activeSources(),
        padding_fixture.finalSources(),
    );
    const authority = try campaign_final_mod.CampaignFinalRemintAuthorityV2
        .init(&shape, &final_remint);
    const host = try policy_mod.HostExecutionAuthorityV2.init(11, 96_000);
    const policy = try policy_mod.PolicyV2.init(host, .{
        .total_cpu_tokens = 8,
        .cpu_tokens_per_node = 4,
        .proof_worker_count = 4,
        .maximum_parallel_nodes = 2,
        .total_rss_bytes = 96_000,
        .rss_bytes_per_node = 48_000,
    });
    const plan = try target_native_q193_mod.GenuineLifecyclePlanV2.init(
        &authority,
        &policy,
    );
    try plan.validate();
    try plan.runtime_plan.validate(&authority, &policy);
    try plan.pair_inventory.validate(&authority);
    try std.testing.expectEqual(shape.empty_leaf_count, plan.role1_proof_count);
    try std.testing.expectEqual(shape.fold_count, plan.role2_proof_count);
    try std.testing.expectEqual(@as(usize, 4), plan.worker_count);
    try std.testing.expectEqual(@as(u64, 4), plan.cpu_tokens_per_node);
    try std.testing.expectEqual(@as(u64, 48_000), plan.rss_bytes_per_node);
    try std.testing.expect(!@hasDecl(
        target_native_q193_mod.GenuineLifecyclePlanV2,
        "encode",
    ));
    try std.testing.expect(!@hasDecl(
        target_native_q193_mod.GenuineLifecyclePlanV2,
        "decode",
    ));

    var hostile = plan;
    hostile.role1_proof_count -= 1;
    try std.testing.expectError(
        error.CampaignTargetNativeLifecycleMismatch,
        hostile.validate(),
    );
    hostile = plan;
    hostile.runtime_plan.fold_count -= 1;
    try std.testing.expectError(
        error.CampaignFinalDriverTopologyMismatch,
        hostile.validate(),
    );
    hostile = plan;
    hostile.rss_bytes_per_node -= 1;
    try std.testing.expectError(
        error.CampaignTargetNativeLifecycleMismatch,
        hostile.validate(),
    );
}

test "campaign final live runtime production types close while unavailable" {
    std.testing.refAllDecls(FinalLiveRuntimeV2);
    std.testing.refAllDecls(FinalLiveRuntimeV2.BorrowedRuntimeV2);
    std.testing.refAllDecls(FinalLiveRuntimeV2.OwnedRuntimeV2);
    std.testing.refAllDecls(FinalLiveRuntimeEpochV2);
    try std.testing.expect(!FinalLiveRuntimeV2.available);
    try std.testing.expect(!FinalLiveRuntimeEpochV2.available);
    try std.testing.expect(!final_live_runtime_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!final_live_runtime_mod.ROUTER_ACTIVATION);
    try std.testing.expect(
        !final_live_runtime_mod.SERIALIZABLE_FRESH_CAPABILITY,
    );
    try std.testing.expect(
        final_live_runtime_mod.ONE_IMMUTABLE_SESSION_PROVIDER_REQUIRED,
    );
    try std.testing.expect(final_live_runtime_mod.ONE_FINAL_REMINT_REQUIRED);
    try std.testing.expect(
        final_live_runtime_mod.EXACT_EXECUTION_KEY_POLICY_REQUIRED,
    );
    try std.testing.expect(
        final_live_runtime_mod.LIVE_CHILD_PAYLOAD_REMAINS_WORKER_PRIVATE,
    );
    try std.testing.expect(
        FinalLiveRuntimeV2.FinalWorkerV2 == FinalWorkerTransaction,
    );
    try std.testing.expect(
        FinalLiveRuntimeV2.SessionProviderV4 == FinalWorkerProviderV4,
    );
    try std.testing.expect(
        FinalLiveRuntimeV2.ImmutableSessionV4 == FinalWorkerSessionV4,
    );
    try std.testing.expect(
        FinalLiveRuntimeV2.CompositeAdapterV2 == FinalCompositeV2,
    );
    try std.testing.expect(
        FinalLiveRuntimeV2.FinalDriverV2 == FinalDriverV2,
    );
    try std.testing.expect(
        FinalLiveRuntimeEpochV2.WorkerV1 == FinalLiveRuntimeV2.WorkerV1,
    );
    try std.testing.expect(
        FinalLiveRuntimeEpochV2.FinalDriverV2 ==
            FinalLiveRuntimeV2.FinalDriverV2,
    );
    try std.testing.expect(
        FinalLiveRuntimeEpochV2.SessionProviderV4 ==
            FinalLiveRuntimeV2.SessionProviderV4,
    );
    try std.testing.expect(!@hasDecl(
        FinalLiveRuntimeV2.BorrowedRuntimeV2,
        "encode",
    ));
    try std.testing.expect(!@hasDecl(
        FinalLiveRuntimeV2.BorrowedRuntimeV2,
        "decode",
    ));
    try std.testing.expect(!@hasDecl(
        FinalLiveRuntimeV2.OwnedRuntimeV2,
        "encode",
    ));
    try std.testing.expect(!@hasDecl(
        FinalLiveRuntimeV2.OwnedRuntimeV2,
        "decode",
    ));
}

test "campaign final assembly bound runtime production types close while unavailable" {
    std.testing.refAllDecls(FinalOwnedRuntimeV2);
    std.testing.refAllDecls(FinalAssemblyBoundRuntimeV2);
    try std.testing.expect(!FinalOwnedRuntimeV2.available);
    try std.testing.expect(!FinalAssemblyBoundRuntimeV2.available);
    try std.testing.expect(
        FinalAssemblyBoundRuntimeV2.OwnedRuntimeV2 ==
            FinalOwnedRuntimeV2,
    );
    try std.testing.expect(
        FinalAssemblyBoundRuntimeV2.ValidatedAssemblyV2 ==
            FinalWorkerTransaction.ValidatedAssemblyV2,
    );
    try std.testing.expect(
        FinalAssemblyBoundRuntimeV2.ActiveSourcesV2 ==
            FinalActiveSourcesV2,
    );
    try std.testing.expect(
        !final_assembly_bound_runtime_mod.PRODUCTION_ACTIVATION,
    );
    try std.testing.expect(!final_assembly_bound_runtime_mod.ROUTER_ACTIVATION);
    try std.testing.expect(
        !final_assembly_bound_runtime_mod.SERIALIZABLE_FRESH_CAPABILITY,
    );
    try std.testing.expect(!@hasDecl(
        FinalAssemblyBoundRuntimeV2,
        "encode",
    ));
    try std.testing.expect(!@hasDecl(
        FinalAssemblyBoundRuntimeV2,
        "decode",
    ));
}

test "campaign role1 and role2 q193 gates bind ExecutionKey workers and RSS" {
    std.testing.refAllDecls(TargetNativeQ193);
    std.testing.refAllDecls(TargetNativeQ193.PreparedRole2PairV2);
    try std.testing.expect(!target_native_q193_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!target_native_q193_mod.ROUTER_ACTIVATION);
    try std.testing.expect(!target_native_q193_mod.ROLE1_Q193_GENUINE_GATE_GREEN);
    try std.testing.expect(
        !target_native_q193_mod.ROLE2_NOMINAL_PAIR_Q193_GATES_GREEN,
    );
    try std.testing.expect(target_native_q193_mod.GENUINE_GATE_ONLY);
    try std.testing.expect(
        target_native_q193_mod.ROLE2_GATE_OUTPUT_IS_NOT_A_DURABLE_NODE,
    );
    try std.testing.expect(
        target_native_q193_mod.GATE_PUBLICATION_IS_CREATE_ONLY,
    );
    try std.testing.expect(target_native_q193_mod.GATE_MANIFEST_IS_SEAL_LAST);
    inline for (.{
        "proveRole1ForGenuineGate",
        "coldOpenRole1ForGenuineGate",
        "role1PublicationForGenuineGate",
    }) |name| try std.testing.expect(@hasDecl(target_native_q193_mod, name));
    inline for (.{
        "proveRole2ForGenuineGate",
        "coldOpenRole2ForGenuineGate",
        "role2PublicationForGenuineGate",
    }) |name| try std.testing.expect(@hasDecl(TargetNativeQ193, name));
    inline for (.{ "init", "validate", "deinit" }) |name|
        try std.testing.expect(@hasDecl(
            TargetNativeQ193.PreparedRole2PairV2,
            name,
        ));
    try std.testing.expect(!@hasDecl(
        TargetNativeQ193.PreparedRole2PairV2,
        "encode",
    ));
    try std.testing.expect(!@hasDecl(
        TargetNativeQ193.PreparedRole2PairV2,
        "decode",
    ));
    try std.testing.expect(!@hasDecl(
        target_native_q193_mod.GatePublicationV2,
        "encode",
    ));
    try std.testing.expect(!@hasDecl(
        target_native_q193_mod.GatePublicationV2,
        "decode",
    ));
    try std.testing.expect(!@hasDecl(
        target_native_q193_mod.SealedGatePublicationV2,
        "encode",
    ));
    try std.testing.expect(!@hasDecl(
        target_native_q193_mod.SealedGatePublicationV2,
        "decode",
    ));

    const host = try policy_mod.HostExecutionAuthorityV2.init(7, 30_000);
    const policy = try policy_mod.PolicyV2.init(host, .{
        .total_cpu_tokens = 6,
        .cpu_tokens_per_node = 3,
        .proof_worker_count = 3,
        .maximum_parallel_nodes = 2,
        .total_rss_bytes = 24_000,
        .rss_bytes_per_node = 12_000,
    });
    const no_inputs = [_]artifact_store.InputRefV1{};
    const semantic = try artifact_store.SemanticKeyV1.create(
        std.testing.allocator,
        .{
            .stage_kind = .fold,
            .stage_schema_version = 104,
            .campaign_namespace = digest(111),
            .local_task_identity = digest(112),
            .protocol_identity = digest(113),
            .program_identity = digest(114),
            .profile_identity = digest(115),
            .pcs_identity = digest(116),
            .security_identity = digest(117),
            .statement_identity = digest(118),
            .layout_identity = digest(119),
            .registry_identity = digest(120),
            .semantic_options_identity = digest(121),
            .ordered_inputs = &no_inputs,
        },
    );
    const execution = try artifact_store.ExecutionKeyV1.create(.{
        .semantic_key_identity = semantic.identity,
        .producer_identity = digest(122),
        .verifier_identity = digest(123),
        .source_identity = digest(124),
        .build_identity = digest(125),
        .executable_identity = digest(126),
        .toolchain_identity = digest(127),
        .backend_identity = digest(128),
        .optimization_identity = digest(129),
        .worker_policy_identity = policy.worker_policy_identity,
        .memory_policy_identity = policy.memory_policy_identity,
        .retention_policy_identity = digest(130),
        .timeout_policy_identity = digest(131),
    });
    const no_dependencies = [_]protocol.Dependency{};
    var node = protocol.Node{
        .node_id = "fold/1/0",
        .stage_kind = .fold,
        .stage_schema_version = 104,
        .adapter = "campaign_common_fold_v2",
        .dependencies = &no_dependencies,
        .external_inputs = &no_inputs,
        .local_task_identity_sha256 = digest(112),
        .semantic_authorities = .{
            .protocol_identity_sha256 = digest(113),
            .program_identity_sha256 = digest(114),
            .profile_identity_sha256 = digest(115),
            .pcs_identity_sha256 = digest(116),
            .security_identity_sha256 = digest(117),
            .statement_identity_sha256 = digest(118),
            .provider_identity_sha256 = [_]u8{0} ** 32,
            .layout_identity_sha256 = digest(119),
            .registry_identity_sha256 = digest(120),
        },
        .semantic_options = .null,
        .cpu_tokens = 3,
        .rss_tokens = 12_000,
        .output_kind = .recursion_node,
        .output_schema_version = 2,
    };
    const binding = try target_native_q193_mod.ExecutionBindingV2.init(
        std.testing.allocator,
        &policy,
        &node,
        &semantic,
        &execution,
        .fold,
        104,
    );
    try binding.validate(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), binding.worker_count);
    try std.testing.expectEqual(@as(u64, 3), binding.cpu_tokens);
    try std.testing.expectEqual(@as(u64, 12_000), binding.rss_bytes);
    try std.testing.expectEqual(
        binding.worker_count,
        binding.proofOptions().worker_count,
    );

    node.rss_tokens -= 1;
    try std.testing.expectError(
        error.CampaignTargetNativeExecutionMismatch,
        target_native_q193_mod.ExecutionBindingV2.init(
            std.testing.allocator,
            &policy,
            &node,
            &semantic,
            &execution,
            .fold,
            104,
        ),
    );
    node.rss_tokens += 1;
    var hostile_execution = execution;
    hostile_execution.fields.worker_policy_identity[0] ^= 1;
    hostile_execution = try artifact_store.ExecutionKeyV1.create(
        hostile_execution.fields,
    );
    try std.testing.expectError(
        error.RecursiveExecutionPolicyMismatch,
        target_native_q193_mod.ExecutionBindingV2.init(
            std.testing.allocator,
            &policy,
            &node,
            &semantic,
            &hostile_execution,
            .fold,
            104,
        ),
    );
}

test "campaign final role2 transitive q193 exact bodies compile while unavailable" {
    std.testing.refAllDecls(ProductionFinalRole2);
    std.testing.refAllDecls(ProductionFinalRole2Proof);
    std.testing.refAllDecls(ProductionFinalChildOpener);
    try std.testing.expect(ProductionFinalRole2 == FinalRole2);
    try std.testing.expect(
        ProductionFinalChildOpener.RealLeaseV4 == Role0FinalLease,
    );
    try std.testing.expect(
        ProductionFinalChildOpener.RealColdOpenerV4 ==
            ProductionFinalRole0Opener,
    );
    try std.testing.expect(
        ProductionFinalRole0Opener.LeasePayload == Role0FinalLease,
    );
    try std.testing.expect(
        ProductionFinalChildOpener.DependencyLease ==
            ProductionFinalRole2.DependencyLease,
    );
    try std.testing.expect(
        ProductionFinalChildOpener.CommonLeaseV2 ==
            ProductionFinalRole2.CommonLeaseHandleV2,
    );
    try std.testing.expect(!ProductionFinalRole0Opener.available);
    try std.testing.expect(!ProductionFinalChildOpener.available);
    try std.testing.expect(!ProductionFinalRole2Proof.available);
    try std.testing.expect(child_opener_mod.GENUINE_GATE_ONLY);
    try std.testing.expect(final_proof_mod.GENUINE_GATE_ONLY);
    try std.testing.expect(
        final_proof_mod.PROVER_OWNER_DESTROYED_BEFORE_COLD_OPEN,
    );
    inline for (.{
        "coldOpenPairForGenuineGate",
        "views",
        "deinitOwnedPair",
    }) |name| try std.testing.expect(@hasDecl(
        ProductionFinalChildOpener,
        name,
    ));
    inline for (.{
        "proveAndColdVerifyForGenuineGate",
        "coldOpenOwnedForGenuineGate",
    }) |name| try std.testing.expect(@hasDecl(
        ProductionFinalRole2Proof,
        name,
    ));
    inline for (.{
        "coldOpenFromNodeRef",
        "coldOpenFromNodeRefForGenuineGate",
        "validateForCampaign",
        "campaignFoldProjection",
        "deinit",
    }) |name| try std.testing.expect(@hasDecl(
        ProductionFinalRole2Proof.LeasePayload,
        name,
    ));
    try std.testing.expect(!@hasDecl(
        ProductionFinalRole2Proof.LeasePayload,
        "encode",
    ));
    try std.testing.expect(!@hasDecl(
        ProductionFinalRole2Proof.LeasePayload,
        "decode",
    ));
    inline for (.{
        "proveRole2TransitiveForGenuineGate",
        "coldOpenRole2TransitiveForGenuineGate",
    }) |name| try std.testing.expect(@hasDecl(TargetNativeQ193, name));
    try std.testing.expect(
        TargetNativeQ193.ProductionLeasePayloadV2 ==
            ProductionFinalRole2Proof.LeasePayload,
    );
    try std.testing.expect(
        TargetNativeQ193.ProductionProvedV2 ==
            ProductionFinalRole2Proof.ProvedV2,
    );

    // Runtime-false so this focused gate spends no q193 work. It forces
    // semantic analysis of the exact production nominal flow: borrow two
    // typed live children, prove, retain canonical bytes, destroy that owner,
    // then recursively cold-open both CAS children into a fresh lease.
    var run_genuine_transitive_q193 = false;
    std.mem.doNotOptimizeAway(&run_genuine_transitive_q193);
    if (!run_genuine_transitive_q193) return;

    const allocator = std.testing.allocator;
    const store: *artifact_store.Store = undefined;
    const left: ProductionFinalRole2.DependencyLease = undefined;
    const right: ProductionFinalRole2.DependencyLease = undefined;
    const prepared = try TargetNativeQ193.PreparedRole2PairV2.init(
        allocator,
        allocator,
        undefined,
        left,
        right,
    );
    defer prepared.deinit();
    var proved = try TargetNativeQ193
        .proveRole2TransitiveForGenuineGate(
        allocator,
        allocator,
        store,
        prepared,
    );
    const retained = blk: {
        defer proved.deinit();
        const proof_bytes = try allocator.dupe(u8, proved.proofBytes());
        errdefer allocator.free(proof_bytes);
        const node_bytes = try campaign_artifact_mod.encodeCanonical(
            prepared.final_remint.shape,
            proved.nodeArtifact(),
        );
        break :blk .{ .proof = proof_bytes, .node = node_bytes };
    };
    defer allocator.free(retained.proof);
    var cold = try TargetNativeQ193
        .coldOpenRole2TransitiveForGenuineGate(
        allocator,
        allocator,
        store,
        prepared,
        retained.proof,
        &retained.node,
    );
    defer cold.deinit();
    try cold.validateForCampaign(prepared.final_remint);
}

test "campaign target-native q193 exact bodies compile without running proof" {
    // This runtime-false branch forces semantic analysis of the exact genuine
    // prove -> retained canonical bytes -> destroy -> fresh-cold-open flow.
    // The focused structural target must never spend q193 work; the same body
    // is invoked with real descriptions and owned children by the later
    // coordinated genuine fixture.
    var run_genuine_q193 = false;
    std.mem.doNotOptimizeAway(&run_genuine_q193);
    if (!run_genuine_q193) return;

    var role1_proved = try target_native_q193_mod.proveRole1ForGenuineGate(
        std.testing.allocator,
        std.testing.allocator,
        undefined,
        undefined,
    );
    const role1_bytes = try role1_proved.proof.encodeArtifactAlloc(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(role1_bytes);
    role1_proved.deinit();
    var role1_lease = try target_native_q193_mod
        .coldOpenRole1ForGenuineGate(
        std.testing.allocator,
        std.testing.allocator,
        undefined,
        undefined,
        role1_bytes,
    );
    defer role1_lease.deinit();
    const role1_publication = try target_native_q193_mod
        .role1PublicationForGenuineGate(
        std.testing.allocator,
        undefined,
        undefined,
        &role1_lease,
        role1_bytes,
    );
    try role1_publication.validate(std.testing.allocator);

    const left: FinalRole2.DependencyLease = undefined;
    const right: FinalRole2.DependencyLease = undefined;
    const prepared = try TargetNativeQ193.PreparedRole2PairV2.init(
        std.testing.allocator,
        std.testing.allocator,
        undefined,
        left,
        right,
    );
    defer prepared.deinit();
    var role2_proved = try TargetNativeQ193.proveRole2ForGenuineGate(
        std.testing.allocator,
        std.testing.allocator,
        prepared,
    );
    const role2_bytes = try std.testing.allocator.dupe(
        u8,
        role2_proved.proof.proofBytes(),
    );
    defer std.testing.allocator.free(role2_bytes);
    role2_proved.deinit();
    var role2_cold = try TargetNativeQ193.coldOpenRole2ForGenuineGate(
        std.testing.allocator,
        std.testing.allocator,
        prepared,
        role2_bytes,
    );
    defer role2_cold.deinit();
    const role2_publication = try TargetNativeQ193
        .role2PublicationForGenuineGate(
        std.testing.allocator,
        prepared,
        &role2_cold,
    );
    try role2_publication.validate(std.testing.allocator);
    const dependency_manifests: [2]artifact_store.BlobRefV1 = undefined;
    const sealed = try target_native_q193_mod.SealedGatePublicationV2
        .publishSealLast(
        std.testing.allocator,
        undefined,
        &role2_publication,
        &dependency_manifests,
    );
    try sealed.validate(std.testing.allocator);
}

test "genuine three-leaf tree gate exact production leases compile while unavailable" {
    std.testing.refAllDecls(GenuineThreeLeafTreeGateV2);
    std.testing.refAllDecls(GenuineThreeLeafTreeGateV2.OwnedTreeV2);
    try std.testing.expect(
        GenuineThreeLeafTreeGateV2.FinalOwnerV2 ==
            GenuineThreeLeafFixtureV2.OwnedFinalV2,
    );
    try std.testing.expect(
        GenuineThreeLeafTreeGateV2.FinalSessionOwnerV4 ==
            ExactStage102LifecycleV4.OwnedFinalSessionV4,
    );
    try std.testing.expect(
        GenuineThreeLeafTreeGateV2.Role0LeaseV4 ==
            ProductionFinalRole0Opener.LeasePayload,
    );
    try std.testing.expect(
        GenuineThreeLeafTreeGateV2.Role1LeaseV2 ==
            role1_final_mod.OwnedLeaseV2,
    );
    try std.testing.expect(
        GenuineThreeLeafTreeGateV2.Role2LeaseV2 ==
            ProductionFinalRole2Proof.LeasePayload,
    );
    try std.testing.expect(
        GenuineThreeLeafTreeGateV2.DependencyLeaseV2 ==
            ProductionFinalRole2.DependencyLease,
    );
    try std.testing.expect(
        GenuineThreeLeafTreeGateV2.FinalDriverV2 == FinalDriverV2,
    );
    try std.testing.expect(genuine_three_leaf_tree_gate_mod.GENUINE_GATE_ONLY);
    try std.testing.expect(
        !genuine_three_leaf_tree_gate_mod.PRODUCTION_ACTIVATION,
    );
    try std.testing.expect(
        !genuine_three_leaf_tree_gate_mod.ROUTER_ACTIVATION,
    );
    try std.testing.expect(
        !genuine_three_leaf_tree_gate_mod.GENUINE_Q193_GATE_GREEN,
    );
    try std.testing.expect(
        !genuine_three_leaf_tree_gate_mod.LIVE_WORKER_LEASE_ADMISSION,
    );
    try std.testing.expect(
        genuine_three_leaf_tree_gate_mod
            .PROOF_AND_NODE_PRECEDE_STAGE_MANIFEST,
    );
    try std.testing.expect(
        genuine_three_leaf_tree_gate_mod
            .EVERY_PROOF_IS_FRESHLY_COLD_OPENED,
    );
    try std.testing.expect(
        genuine_three_leaf_tree_gate_mod
            .EXECUTION_POLICY_HAS_NO_SERIAL_FALLBACK,
    );
    inline for (.{
        "validate",
        "rootOutputRef",
        "rootStageManifestRef",
        "deinit",
    }) |name| try std.testing.expect(@hasDecl(
        GenuineThreeLeafTreeGateV2.OwnedTreeV2,
        name,
    ));
    try std.testing.expect(!@hasDecl(
        GenuineThreeLeafTreeGateV2.OwnedTreeV2,
        "encode",
    ));
    try std.testing.expect(!@hasDecl(
        GenuineThreeLeafTreeGateV2.OwnedTreeV2,
        "decode",
    ));

    // Runtime-false: force semantic analysis of the exact three-leaf owner
    // without spending q193 work in the structural target.
    var run_genuine_tree = false;
    std.mem.doNotOptimizeAway(&run_genuine_tree);
    if (!run_genuine_tree) return;
    const owner = try GenuineThreeLeafTreeGateV2.OwnedTreeV2
        .proveAndSealForGenuineGate(
        std.testing.allocator,
        std.testing.allocator,
        undefined,
        undefined,
        undefined,
    );
    defer owner.deinit();
    try owner.validate(std.testing.allocator);
    _ = owner.rootOutputRef();
    _ = owner.rootStageManifestRef();
}

test "authenticated Stage101 installs genuine Stage102 session and final tree while unavailable" {
    std.testing.refAllDecls(GenuineStage102TreeLifecycleV4);
    std.testing.refAllDecls(
        GenuineStage102TreeLifecycleV4.OwnedStage102PlanV4,
    );
    std.testing.refAllDecls(
        GenuineStage102TreeLifecycleV4.OwnedInstalledStage102V4,
    );
    std.testing.refAllDecls(
        GenuineStage102TreeLifecycleV4.OwnedCompleteTreeV4,
    );
    try std.testing.expect(!GenuineStage102TreeLifecycleV4.available);
    try std.testing.expect(
        GenuineStage102TreeLifecycleV4.EngineV4 == Engine,
    );
    try std.testing.expect(
        GenuineStage102TreeLifecycleV4.AuthenticatedStage101V4 ==
            AuthenticatedStage101V4,
    );
    try std.testing.expect(
        GenuineStage102TreeLifecycleV4.FinalFixtureV2 ==
            GenuineThreeLeafFixtureV2,
    );
    try std.testing.expect(
        GenuineStage102TreeLifecycleV4.LifecycleV4 ==
            GenuineStage102LifecycleV4,
    );
    try std.testing.expect(
        GenuineStage102TreeLifecycleV4.TreeGateV2 ==
            GenuineStage102BoundTreeGateV2,
    );
    try std.testing.expect(
        GenuineStage102TreeLifecycleV4.AuthorityV4 ==
            FinalWorkerRole0Backend.AuthorityV4,
    );
    try std.testing.expect(
        GenuineStage102TreeLifecycleV4.FinalSessionOwnerV4 ==
            GenuineStage102LifecycleV4.OwnedFinalSessionV4,
    );
    try std.testing.expect(
        GenuineStage102TreeLifecycleV4.TreeOwnerV2 ==
            GenuineStage102BoundTreeGateV2.OwnedTreeV2,
    );
    try std.testing.expect(
        genuine_stage102_tree_lifecycle_mod.GENUINE_GATE_ONLY,
    );
    try std.testing.expect(
        !genuine_stage102_tree_lifecycle_mod.PRODUCTION_ACTIVATION,
    );
    try std.testing.expect(
        !genuine_stage102_tree_lifecycle_mod.ROUTER_ACTIVATION,
    );
    try std.testing.expect(
        !genuine_stage102_tree_lifecycle_mod.GENUINE_Q193_GATE_GREEN,
    );
    try std.testing.expect(
        !genuine_stage102_tree_lifecycle_mod
            .SERIALIZABLE_FRESH_CAPABILITY,
    );
    try std.testing.expect(
        !genuine_stage102_tree_lifecycle_mod
            .SERIALIZABLE_LIVE_LEASE_SELECTOR,
    );
    try std.testing.expect(
        genuine_stage102_tree_lifecycle_mod
            .EXECUTION_POLICY_HAS_NO_SERIAL_FALLBACK,
    );
    try std.testing.expect(
        genuine_stage102_tree_lifecycle_mod
            .RUNTIME_CAMPAIGN_CARDINALITY_REQUIRED,
    );

    const paths = [_]genuine_stage102_tree_lifecycle_mod.BuildPathsV4{
        .{
            .output_path = "/tmp/stage102-0.node",
            .profile_receipt_path = "/tmp/stage102-0.profile",
            .candidate_ref_path = "/tmp/stage102-0.ref",
        },
        .{
            .output_path = "/tmp/stage102-1.node",
            .profile_receipt_path = "/tmp/stage102-1.profile",
            .candidate_ref_path = "/tmp/stage102-1.ref",
        },
        .{
            .output_path = "/tmp/stage102-2.node",
            .profile_receipt_path = "/tmp/stage102-2.profile",
            .candidate_ref_path = "/tmp/stage102-2.ref",
        },
    };
    try genuine_stage102_tree_lifecycle_mod.validateBuildPathsV4(&paths);
    var duplicate = paths;
    duplicate[2].candidate_ref_path = paths[0].output_path;
    try std.testing.expectError(
        error.GenuineStage102TreeLifecyclePathMismatchV4,
        genuine_stage102_tree_lifecycle_mod.validateBuildPathsV4(&duplicate),
    );
    var relative = paths;
    relative[1].output_path = "stage102-relative.node";
    try std.testing.expectError(
        error.InvalidWorkerOutputPath,
        genuine_stage102_tree_lifecycle_mod.validateBuildPathsV4(&relative),
    );
    try std.testing.expectError(
        error.GenuineStage102TreeLifecyclePathMismatchV4,
        genuine_stage102_tree_lifecycle_mod.validateBuildPathsV4(&.{}),
    );

    // Runtime-false: analyze the exact authenticated Stage101 -> live
    // Stage102 -> immutable Session -> role1/role2 tree body without q193.
    var run_genuine_lifecycle = false;
    std.mem.doNotOptimizeAway(&run_genuine_lifecycle);
    if (!run_genuine_lifecycle) return;
    const owner = try GenuineStage102TreeLifecycleV4.OwnedCompleteTreeV4
        .proveAndSealForGenuineGate(
        std.testing.allocator,
        std.testing.allocator,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
    );
    defer owner.deinit();
    try owner.validate(std.testing.allocator);
    _ = owner.rootOutputRef();
    _ = owner.rootStageManifestRef();
}

fn digest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

const Role0FinalLease = role0_final_mod.Types(Engine).OwnedLeaseV4;

const FinalChildOpenerFactory = child_opener_mod.Factory(
    Role0FinalLease,
    FinalWorkerTransaction.Role0InventoryOpenerV4,
);

const UnavailableFinalExecutionPolicy = struct {
    pub const available = false;

    pub fn policyForExecution(
        _: artifact_store.ExecutionKeyV1,
    ) error{CampaignFinalCommonFoldUnavailable}!policy_mod.PolicyV2 {
        return error.CampaignFinalCommonFoldUnavailable;
    }
};

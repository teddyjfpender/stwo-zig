const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("recursive_pipeline_worker_campaign_real_leaf_composite_v4.zig");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const native_execution =
    @import("recursive_pipeline_worker_native_leaf_execution_v4.zig");
const real_backend =
    @import("recursive_pipeline_worker_campaign_real_leaf_backend_v4.zig");
const padding_fixture =
    @import("recursive_common_wrapper_padding_remint_v2_test.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const projection_mod =
    @import("recursive_pipeline_campaign_fold_projection_v2.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");
const session_provider =
    @import("recursive_pipeline_worker_campaign_session_provider_v4.zig");

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
const ActiveSources = @TypeOf(
    @as(*padding_fixture.Fixture, undefined).activeSources(),
);

test "campaign two-stage composite keeps the production route unavailable" {
    const Backend = blk: {
        @setEvalBranchQuota(500_000);
        break :blk real_backend.BackendFor(
            Engine,
            ActiveSources,
            real_backend.UnavailableExecutionPolicyProviderV4,
        );
    };
    const Provider = session_provider.ProviderFor(
        RouteSession(Backend.AuthorityV4),
    );
    const Composite = subject.CampaignAdapterFor(
        Engine,
        ActiveSources,
        Provider,
        Provider,
    );
    const Worker = subject.CampaignWorkerFor(
        Engine,
        ActiveSources,
        Provider,
        Provider,
    );
    std.testing.refAllDecls(Composite);
    std.testing.refAllDecls(Worker);
    std.testing.refAllDecls(Provider);
    try std.testing.expect(!Composite.available);
    try std.testing.expect(!Composite.production);
    try std.testing.expect(!Composite.routes_cryptographically_implemented);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.ROUTER_ACTIVATION);
    try std.testing.expect(!subject.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(subject.EXECUTION_KEY_FORWARDED);
    try std.testing.expect(!Provider.isInstalled());
    const session = RouteSession(Backend.AuthorityV4){};
    var installed = try Provider.install(std.testing.allocator, &session);
    defer if (installed.installed) installed.deinit();
    try installed.validate(std.testing.allocator);
    try std.testing.expect(Provider.isInstalled());
    try std.testing.expectError(
        error.CampaignWorkerSessionAlreadyInstalledV4,
        Provider.install(std.testing.allocator, &session),
    );
    installed.deinit();
    try std.testing.expect(!Provider.isInstalled());
    inline for (.{ "init", "deinit", "handle" }) |name|
        try std.testing.expect(@hasDecl(Worker, name));
}

test "native Stage101 execution adapter derives one strict bounded request" {
    const allocator = std.testing.allocator;
    const keys = try keyPair(allocator);
    const host = try policy_mod.HostExecutionAuthorityV2.init(
        8,
        2 * 1024 * 1024 * 1024,
    );
    TestPolicyProvider.policy = try policy_mod.PolicyV2.init(host, .{
        .total_cpu_tokens = 8,
        .cpu_tokens_per_node = 4,
        .proof_worker_count = 4,
        .maximum_parallel_nodes = 2,
        .total_rss_bytes = 2 * 1024 * 1024 * 1024,
        .rss_bytes_per_node = 1024 * 1024 * 1024,
    });
    const execution = try executionForPolicy(
        keys.semantic.identity,
        &TestPolicyProvider.policy,
    );
    var dependencies: [0]protocol.Dependency = .{};
    var external_inputs: [0]artifact_store.InputRefV1 = .{};
    var node = protocol.Node{
        .node_id = "native/004",
        .stage_kind = .prove,
        .stage_schema_version = 101,
        .adapter = "zig-worker-v1",
        .dependencies = &dependencies,
        .external_inputs = &external_inputs,
        .local_task_identity_sha256 = digest(2),
        .semantic_authorities = semanticAuthorities(),
        .semantic_options = .null,
        .cpu_tokens = 4,
        .rss_tokens = 1024 * 1024 * 1024,
        .output_kind = .proof_artifact,
        .output_schema_version = 1,
    };
    const request = try native_execution.testing.executionRequestV4(
        TestPolicyProvider,
        allocator,
        node,
        keys.semantic,
        execution,
    );
    try std.testing.expectEqual(@as(usize, 4), request.worker_count);
    try std.testing.expectEqual(
        @as(usize, 1024 * 1024 * 1024),
        request.host_byte_budget,
    );
    try std.testing.expectEqual(
        @import("stwo_prover_api").CpuCompositionContentionPolicy.strict,
        request.contention_policy,
    );
    const Stage102Backend = blk: {
        @setEvalBranchQuota(500_000);
        break :blk real_backend.BackendFor(
            Engine,
            ActiveSources,
            TestPolicyProvider,
        );
    };
    const selected = try Stage102Backend.executionPolicyForNode(
        allocator,
        node,
        keys.semantic,
        execution,
    );
    try std.testing.expectEqual(
        TestPolicyProvider.policy.cpu_tokens_per_node,
        selected.cpu_tokens_per_node,
    );
    try std.testing.expectEqual(
        TestPolicyProvider.policy.rss_bytes_per_node,
        selected.rss_bytes_per_node,
    );
    node.cpu_tokens = 3;
    try std.testing.expectError(
        error.NativeLeafStage101ExecutionAuthorityMismatchV4,
        native_execution.testing.executionRequestV4(
            TestPolicyProvider,
            allocator,
            node,
            keys.semantic,
            execution,
        ),
    );
    try std.testing.expectError(
        error.CampaignRealLeafExecutionAuthorityMismatchV4,
        Stage102Backend.executionPolicyForNode(
            allocator,
            node,
            keys.semantic,
            execution,
        ),
    );
}

test "campaign two-stage composite forwards execution and exact native lease" {
    const Adapter = subject.AdapterFor(MockNativeAdapter, MockRealAdapter);
    const Lease = Adapter.LeasePayload;
    const allocator = std.testing.allocator;
    const keys = try keyPair(allocator);
    var dependencies = [_]protocol.Dependency{.{
        .node_id = "native/004",
        .role = @intFromEnum(artifact_store.InputRoleV1.proof),
        .ordinal = 0,
    }};
    var external_inputs: [0]artifact_store.InputRefV1 = .{};
    const node = protocol.Node{
        .node_id = "leaf/004",
        .stage_kind = .prove,
        .stage_schema_version = 102,
        .adapter = "zig-worker-v1",
        .dependencies = &dependencies,
        .external_inputs = &external_inputs,
        .local_task_identity_sha256 = digest(2),
        .semantic_authorities = semanticAuthorities(),
        .semantic_options = .null,
        .cpu_tokens = 1,
        .rss_tokens = 1,
        .output_kind = .recursion_node,
        .output_schema_version = 2,
    };
    var native_releases: usize = 0;
    var native = Lease{ .native_leaf_v4 = .{
        .releases = &native_releases,
    } };
    const borrowed = [_]*const Lease{&native};
    MockRealAdapter.reset();
    const output = try Adapter.buildOutputWithExecutionAndLeases(
        allocator,
        undefined,
        node,
        keys.semantic,
        keys.execution,
        &key_inputs,
        17,
        &borrowed,
    );
    defer allocator.free(output);
    try std.testing.expectEqualStrings("stage102", output);
    try std.testing.expect(MockRealAdapter.called);
    try std.testing.expect(
        MockRealAdapter.native_dependency == &native.native_leaf_v4,
    );
    try std.testing.expectEqualDeep(
        keys.execution.identity,
        MockRealAdapter.execution_identity,
    );
    try std.testing.expectEqual(@as(u64, 17), MockRealAdapter.ordinal);
    try std.testing.expectEqual(@as(usize, 0), native_releases);

    var wrong_execution = keys.execution;
    wrong_execution.fields.semantic_key_identity = digest(90);
    wrong_execution = try artifact_store.ExecutionKeyV1.create(
        wrong_execution.fields,
    );
    try std.testing.expectError(
        error.CampaignRealLeafExecutionAuthorityMismatchV4,
        real_backend.testing.validateExecutionBindingV4(
            allocator,
            keys.semantic,
            wrong_execution,
        ),
    );
    MockRealAdapter.reset();
    try std.testing.expectError(
        error.CampaignRealLeafCompositeExecutionMismatchV4,
        Adapter.buildOutputWithExecutionAndLeases(
            allocator,
            undefined,
            node,
            keys.semantic,
            wrong_execution,
            &key_inputs,
            18,
            &borrowed,
        ),
    );
    try std.testing.expect(!MockRealAdapter.called);

    var real_releases: usize = 0;
    var wrong_dependency = Lease{ .real_wrapper_v4 = .{
        .releases = &real_releases,
    } };
    const wrong_borrowed = [_]*const Lease{&wrong_dependency};
    try std.testing.expectError(
        error.CampaignRealLeafCompositeLeaseMismatchV4,
        Adapter.buildOutputWithExecutionAndLeases(
            allocator,
            undefined,
            node,
            keys.semantic,
            keys.execution,
            &key_inputs,
            19,
            &wrong_borrowed,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), real_releases);
    wrong_dependency.deinit();
    try std.testing.expectEqual(@as(usize, 1), real_releases);
    native.deinit();
    try std.testing.expectEqual(@as(usize, 1), native_releases);
}

test "campaign two-stage tagged lease has no durable capability codec" {
    const Lease = subject.LeasePayloadFor(TestNativeLease, TestRealLease);
    comptime {
        for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |
            name,
        | if (@hasDecl(Lease, name))
            @compileError("campaign two-stage lease gained a codec");
    }
    var releases: usize = 0;
    var native = Lease{ .native_leaf_v4 = .{ .releases = &releases } };
    try native.validate();
    try std.testing.expectEqual(
        subject.StageCodeV4.native_leaf_v4,
        native.stageCode(),
    );
    var authority: final_mod.CampaignFinalRemintAuthorityV2 = undefined;
    try std.testing.expectError(
        error.CampaignRealLeafCompositeLeaseMismatchV4,
        native.campaignFoldProjection(&authority),
    );
    native.deinit();
    try std.testing.expectEqual(@as(usize, 1), releases);
}

fn RouteSession(comptime Authority: type) type {
    return struct {
        pub const AuthorityV4 = Authority;

        pub fn validate(
            _: *const @This(),
            _: std.mem.Allocator,
        ) !void {}

        pub fn authorityForCampaign(
            _: *const @This(),
            _: [32]u8,
        ) error{CampaignRealLeafStage102AuthorityUnavailableV4}!*const Authority {
            return error.CampaignRealLeafStage102AuthorityUnavailableV4;
        }

        pub fn stage102AdmissionForOutput(
            _: *const @This(),
            _: [32]u8,
            _: artifact_store.BlobRefV1,
        ) error{CampaignRealLeafStage102AuthorityUnavailableV4}!*const session_provider.Stage102ColdAdmissionV4 {
            return error.CampaignRealLeafStage102AuthorityUnavailableV4;
        }

        pub fn finalRemintForCampaign(
            _: *const @This(),
            _: [32]u8,
        ) error{CampaignRealLeafStage102AuthorityUnavailableV4}!*const session_provider.FinalRemint {
            return error.CampaignRealLeafStage102AuthorityUnavailableV4;
        }

        pub fn policyForExecution(
            _: *const @This(),
            _: artifact_store.ExecutionKeyV1,
        ) error{CampaignRealLeafStage102ExecutionAuthorityUnavailableV4}!session_provider.PolicyV2 {
            return error.CampaignRealLeafStage102ExecutionAuthorityUnavailableV4;
        }

        pub fn adoptStage102ColdPublication(
            _: *const @This(),
            _: std.mem.Allocator,
            _: protocol.Node,
            _: artifact_store.SemanticKeyV1,
            _: artifact_store.ExecutionKeyV1,
            _: []const artifact_store.InputRefV1,
            _: artifact_store.BlobRefV1,
            _: artifact_store.BlobRefV1,
            _: []const artifact_store.BlobRefV1,
        ) !void {}
    };
}

const TestNativeLease = struct {
    releases: *usize,

    pub fn validate(_: *const TestNativeLease) !void {}

    pub fn deinit(self: *TestNativeLease) void {
        self.releases.* += 1;
    }
};

const TestRealLease = struct {
    releases: *usize,

    pub fn validate(_: *const TestRealLease) !void {}

    pub fn campaignFoldProjection(
        _: *const TestRealLease,
        _: *const final_mod.CampaignFinalRemintAuthorityV2,
    ) !projection_mod.ProjectionV2 {
        return error.TestProjectionUnavailable;
    }

    pub fn deinit(self: *TestRealLease) void {
        self.releases.* += 1;
    }
};

const MockNativeAdapter = struct {
    pub const available = true;
    pub const LeasePayload = TestNativeLease;

    pub fn acceptsNodeAdapter(value: []const u8) bool {
        return std.mem.eql(u8, value, "zig-worker-v1");
    }

    pub fn describe(_: artifact_store.StageKindV1, _: u16) !protocol.StageDescription {
        return error.TestAdapterUnavailable;
    }

    pub fn buildOutputWithLeases(
        _: std.mem.Allocator,
        _: *artifact_store.Store,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
        _: u64,
        _: []const *const LeasePayload,
    ) ![]u8 {
        return error.TestAdapterUnavailable;
    }

    pub fn buildOutputWithExecutionAndLeases(
        _: std.mem.Allocator,
        _: *artifact_store.Store,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: artifact_store.ExecutionKeyV1,
        _: []const artifact_store.InputRefV1,
        _: u64,
        _: []const *const LeasePayload,
    ) ![]u8 {
        return error.TestAdapterUnavailable;
    }

    pub fn profileValue(
        _: std.mem.Allocator,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: artifact_store.ExecutionKeyV1,
        _: u64,
    ) !protocol.Json {
        return error.TestAdapterUnavailable;
    }

    pub fn validateOutput(
        _: std.mem.Allocator,
        _: []const u8,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
    ) !void {
        return error.TestAdapterUnavailable;
    }

    pub fn coldOpenLease(
        _: std.mem.Allocator,
        _: *artifact_store.Store,
        _: []const u8,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
    ) !LeasePayload {
        return error.TestAdapterUnavailable;
    }

    pub fn validationValue(
        _: std.mem.Allocator,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: artifact_store.BlobRefV1,
        _: u32,
        _: []const u8,
    ) !protocol.Json {
        return error.TestAdapterUnavailable;
    }

    pub fn deinitLeasePayload(value: *LeasePayload, _: std.mem.Allocator) void {
        value.deinit();
    }
};

const MockRealAdapter = struct {
    pub const available = true;
    pub const DependencyLease = TestNativeLease;
    pub const LeasePayload = TestRealLease;
    var called = false;
    var native_dependency: ?*const TestNativeLease = null;
    var execution_identity: [32]u8 = [_]u8{0} ** 32;
    var ordinal: u64 = 0;

    pub fn reset() void {
        called = false;
        native_dependency = null;
        execution_identity = [_]u8{0} ** 32;
        ordinal = 0;
    }

    pub fn acceptsNodeAdapter(value: []const u8) bool {
        return std.mem.eql(u8, value, "zig-worker-v1");
    }

    pub fn describe(_: artifact_store.StageKindV1, _: u16) !protocol.StageDescription {
        return error.TestAdapterUnavailable;
    }

    pub fn buildOutputWithLeases(
        _: std.mem.Allocator,
        _: *artifact_store.Store,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
        _: u64,
        _: []const *const DependencyLease,
    ) ![]u8 {
        return error.TestAdapterUnavailable;
    }

    pub fn buildOutputWithExecutionAndLeases(
        allocator: std.mem.Allocator,
        _: *artifact_store.Store,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        execution: artifact_store.ExecutionKeyV1,
        _: []const artifact_store.InputRefV1,
        candidate_ordinal: u64,
        dependencies: []const *const DependencyLease,
    ) ![]u8 {
        if (dependencies.len != 1) return error.TestAdapterUnavailable;
        called = true;
        native_dependency = dependencies[0];
        execution_identity = execution.identity;
        ordinal = candidate_ordinal;
        return allocator.dupe(u8, "stage102");
    }

    pub fn buildOutputWithExecutionAndLeasesForGenuineGate(
        allocator: std.mem.Allocator,
        store: *artifact_store.Store,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        execution: artifact_store.ExecutionKeyV1,
        ordered_inputs: []const artifact_store.InputRefV1,
        candidate_ordinal: u64,
        dependencies: []const *const DependencyLease,
    ) ![]u8 {
        return buildOutputWithExecutionAndLeases(
            allocator,
            store,
            node,
            semantic,
            execution,
            ordered_inputs,
            candidate_ordinal,
            dependencies,
        );
    }

    pub fn profileValue(
        _: std.mem.Allocator,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: artifact_store.ExecutionKeyV1,
        _: u64,
    ) !protocol.Json {
        return error.TestAdapterUnavailable;
    }

    pub fn validateOutput(
        _: std.mem.Allocator,
        _: []const u8,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
    ) !void {
        return error.TestAdapterUnavailable;
    }

    pub fn validateOutputForGenuineGate(
        allocator: std.mem.Allocator,
        bytes: []const u8,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        ordered_inputs: []const artifact_store.InputRefV1,
    ) !void {
        return validateOutput(
            allocator,
            bytes,
            node,
            semantic,
            ordered_inputs,
        );
    }

    pub fn coldOpenLease(
        _: std.mem.Allocator,
        _: *artifact_store.Store,
        _: []const u8,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: []const artifact_store.InputRefV1,
    ) !LeasePayload {
        return error.TestAdapterUnavailable;
    }

    pub fn coldOpenLeaseForGenuineGate(
        allocator: std.mem.Allocator,
        store: *artifact_store.Store,
        bytes: []const u8,
        node: protocol.Node,
        semantic: artifact_store.SemanticKeyV1,
        ordered_inputs: []const artifact_store.InputRefV1,
    ) !LeasePayload {
        return coldOpenLease(
            allocator,
            store,
            bytes,
            node,
            semantic,
            ordered_inputs,
        );
    }

    pub fn validationValue(
        _: std.mem.Allocator,
        _: protocol.Node,
        _: artifact_store.SemanticKeyV1,
        _: artifact_store.BlobRefV1,
        _: u32,
        _: []const u8,
    ) !protocol.Json {
        return error.TestAdapterUnavailable;
    }

    pub fn deinitLeasePayload(value: *LeasePayload, _: std.mem.Allocator) void {
        value.deinit();
    }
};

const key_inputs = [1]artifact_store.InputRefV1{.{
    .role = .proof,
    .ordinal = 0,
    .blob = .{
        .kind = .proof_artifact,
        .schema_version = 1,
        .byte_count = 4096,
        .sha256 = digest(21),
    },
}};

const TestPolicyProvider = struct {
    pub const available = true;
    var policy: policy_mod.PolicyV2 = undefined;

    pub fn policyForExecution(
        _: artifact_store.ExecutionKeyV1,
    ) !policy_mod.PolicyV2 {
        return policy;
    }
};

fn keyPair(allocator: std.mem.Allocator) !struct {
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
} {
    const semantic = try artifact_store.SemanticKeyV1.create(allocator, .{
        .stage_kind = .prove,
        .stage_schema_version = 102,
        .campaign_namespace = digest(1),
        .local_task_identity = digest(2),
        .protocol_identity = digest(3),
        .program_identity = digest(4),
        .profile_identity = digest(5),
        .pcs_identity = digest(6),
        .security_identity = digest(7),
        .statement_identity = digest(8),
        .provider_identity = digest(9),
        .layout_identity = digest(10),
        .registry_identity = digest(11),
        .semantic_options_identity = digest(12),
        .ordered_inputs = &key_inputs,
    });
    const execution = try artifact_store.ExecutionKeyV1.create(.{
        .semantic_key_identity = semantic.identity,
        .producer_identity = digest(41),
        .verifier_identity = digest(42),
        .source_identity = digest(43),
        .build_identity = digest(44),
        .executable_identity = digest(45),
        .toolchain_identity = digest(46),
        .backend_identity = digest(47),
        .optimization_identity = digest(48),
        .worker_policy_identity = digest(49),
        .memory_policy_identity = digest(50),
        .retention_policy_identity = digest(51),
        .timeout_policy_identity = digest(52),
    });
    return .{
        .semantic = semantic,
        .execution = execution,
    };
}

fn executionForPolicy(
    semantic_identity: [32]u8,
    policy: *const policy_mod.PolicyV2,
) !artifact_store.ExecutionKeyV1 {
    return artifact_store.ExecutionKeyV1.create(.{
        .semantic_key_identity = semantic_identity,
        .producer_identity = digest(61),
        .verifier_identity = digest(62),
        .source_identity = digest(63),
        .build_identity = digest(64),
        .executable_identity = digest(65),
        .toolchain_identity = digest(66),
        .backend_identity = digest(67),
        .optimization_identity = digest(68),
        .worker_policy_identity = policy.worker_policy_identity,
        .memory_policy_identity = policy.memory_policy_identity,
        .retention_policy_identity = digest(69),
        .timeout_policy_identity = digest(70),
    });
}

fn semanticAuthorities() protocol.SemanticAuthorities {
    return .{
        .protocol_identity_sha256 = digest(3),
        .program_identity_sha256 = digest(4),
        .profile_identity_sha256 = digest(5),
        .pcs_identity_sha256 = digest(6),
        .security_identity_sha256 = digest(7),
        .statement_identity_sha256 = digest(8),
        .provider_identity_sha256 = digest(9),
        .layout_identity_sha256 = digest(10),
        .registry_identity_sha256 = digest(11),
    };
}

fn digest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

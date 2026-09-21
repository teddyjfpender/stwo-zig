const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const description =
    @import("recursive_pipeline_campaign_stage102_inventory_description_v4.zig");
const bridge_mod =
    @import("recursive_pipeline_campaign_stage102_inventory_description_bridge_v4.zig");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");

const Digest = artifact_store.Digest;

const FakeRegistry = struct {
    identity_sha256: Digest,
};

const FakeShape = struct {
    campaign_namespace_sha256: Digest,
    inventory_identity_sha256: Digest,
    identity_sha256: Digest,
    real_leaf_count: u32,
    padded_leaf_count: u32,
    empty_leaf_count: u32,
    fold_count: u32,
    root_height: u8,
};

const FakeFinalRemint = struct {
    shape: *const FakeShape,
    registry: *const FakeRegistry,
    binding_identity_sha256: Digest,

    pub fn registryAuthority(self: *const FakeFinalRemint) !*const FakeRegistry {
        return self.registry;
    }
};

const FakeAuthority = struct {
    final_remint: *const FakeFinalRemint,
};

const FakeHost = struct {
    identity_sha256: Digest,
};

const FakePolicy = struct {
    host: FakeHost,
    total_cpu_tokens: u16,
    cpu_tokens_per_node: u16,
    proof_worker_count: u16,
    maximum_parallel_nodes: u16,
    total_rss_bytes: u64,
    rss_bytes_per_node: u64,
    worker_policy_identity: Digest,
    memory_policy_identity: Digest,
};

const FakeAdmission = struct {
    node: *const protocol.Node,
    semantic: *const artifact_store.SemanticKeyV1,
    execution: *const artifact_store.ExecutionKeyV1,
    ordered_inputs: *const [1]artifact_store.InputRefV1,
    stage_manifest_ref: artifact_store.BlobRefV1,
    dependency_stage_manifest_ref: artifact_store.BlobRefV1,
};

const FakeEntry = struct {
    output_ref: artifact_store.BlobRefV1,
    admission: FakeAdmission,
};

const FakeSession = struct {
    store: *u8,
    authority: *const FakeAuthority,
    entries: []const FakeEntry,
    policy: *const FakePolicy,
    validate_calls: *usize,
    lookup_alias: bool = false,

    pub fn validate(self: *const FakeSession, _: std.mem.Allocator) !void {
        self.validate_calls.* += 1;
        if (self.entries.len != self.authority.final_remint.shape.real_leaf_count)
            return error.FakeStage102SessionInvalid;
    }

    pub fn stage102AdmissionForOutput(
        self: *const FakeSession,
        namespace: Digest,
        output_ref: artifact_store.BlobRefV1,
    ) !*const FakeAdmission {
        if (!std.mem.eql(
            u8,
            &namespace,
            &self.authority.final_remint.shape.campaign_namespace_sha256,
        )) return error.FakeStage102SessionInvalid;
        for (self.entries, 0..) |*entry, index| {
            if (!artifact_store.BlobRefV1.eql(entry.output_ref, output_ref))
                continue;
            if (self.lookup_alias)
                return &self.entries[(index + 1) % self.entries.len].admission;
            return &entry.admission;
        }
        return error.FakeStage102SessionInvalid;
    }
};

const Description = description.DescriptionFor(FakeSession);

const FakeOwner = struct {
    session: *FakeSession,

    pub fn validate(self: *FakeOwner, allocator: std.mem.Allocator) !void {
        try self.session.validate(allocator);
    }

    pub fn immutableSession(self: *const FakeOwner) !*const FakeSession {
        return self.session;
    }
};

const FakeLifecycle = struct {
    pub const ImmutableSessionV4 = FakeSession;
    pub const OwnedFinalSessionV4 = FakeOwner;
};

const Bridge = bridge_mod.BridgeFor(FakeLifecycle);

test "immutable Stage102 inventory description validates and seals exact rows" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temporary = arena.allocator();

    var semantic_options = protocol.jsonObject(temporary);
    try protocol.put(
        &semantic_options,
        "schema",
        protocol.string("stwo.recursive-campaign-real-leaf-wrapper-options.v4"),
    );
    try protocol.putDigest(
        temporary,
        &semantic_options,
        "campaign_semantic_inputs_identity_sha256",
        digest(40),
    );
    const options_identity = try protocol.canonicalDigest(
        temporary,
        semantic_options,
    );

    var inputs = [_][1]artifact_store.InputRefV1{
        .{.{
            .role = .proof,
            .ordinal = 0,
            .blob = blob(.proof_artifact, 1, 4096, 41),
        }},
        .{.{
            .role = .proof,
            .ordinal = 0,
            .blob = blob(.proof_artifact, 1, 4097, 42),
        }},
    };
    var dependencies = [_][1]protocol.Dependency{
        .{.{ .node_id = "native/0", .role = 8, .ordinal = 0 }},
        .{.{ .node_id = "native/1", .role = 8, .ordinal = 0 }},
    };
    var external_inputs: [0]artifact_store.InputRefV1 = .{};
    const semantic_authorities = protocol.SemanticAuthorities{
        .protocol_identity_sha256 = digest(1),
        .program_identity_sha256 = digest(2),
        .profile_identity_sha256 = digest(3),
        .pcs_identity_sha256 = digest(4),
        .security_identity_sha256 = digest(5),
        .statement_identity_sha256 = digest(6),
        .provider_identity_sha256 = digest(7),
        .layout_identity_sha256 = digest(8),
        .registry_identity_sha256 = digest(9),
    };
    var nodes = [_]protocol.Node{
        node(
            "real/0",
            digest(10),
            &dependencies[0],
            &external_inputs,
            semantic_authorities,
            semantic_options,
        ),
        node(
            "real/1",
            digest(11),
            &dependencies[1],
            &external_inputs,
            semantic_authorities,
            semantic_options,
        ),
    };
    var semantics = [_]artifact_store.SemanticKeyV1{
        try semanticKey(
            temporary,
            &nodes[0],
            &inputs[0],
            options_identity,
            digest(10),
        ),
        try semanticKey(
            temporary,
            &nodes[1],
            &inputs[1],
            options_identity,
            digest(11),
        ),
    };
    var executions = [_]artifact_store.ExecutionKeyV1{
        try executionKey(semantics[0].identity, 50),
        try executionKey(semantics[1].identity, 70),
    };
    var entries = [_]FakeEntry{
        .{
            .output_ref = blob(.recursion_node, 2, 2380, 90),
            .admission = .{
                .node = &nodes[0],
                .semantic = &semantics[0],
                .execution = &executions[0],
                .ordered_inputs = &inputs[0],
                .stage_manifest_ref = blob(.stage_manifest, 1, 500, 91),
                .dependency_stage_manifest_ref = blob(
                    .stage_manifest,
                    1,
                    400,
                    92,
                ),
            },
        },
        .{
            .output_ref = blob(.recursion_node, 2, 2380, 93),
            .admission = .{
                .node = &nodes[1],
                .semantic = &semantics[1],
                .execution = &executions[1],
                .ordered_inputs = &inputs[1],
                .stage_manifest_ref = blob(.stage_manifest, 1, 501, 94),
                .dependency_stage_manifest_ref = blob(
                    .stage_manifest,
                    1,
                    401,
                    95,
                ),
            },
        },
    };
    const shape = FakeShape{
        .campaign_namespace_sha256 = digest(20),
        .inventory_identity_sha256 = digest(21),
        .identity_sha256 = digest(22),
        .real_leaf_count = 2,
        .padded_leaf_count = 2,
        .empty_leaf_count = 0,
        .fold_count = 1,
        .root_height = 1,
    };
    const registry = FakeRegistry{ .identity_sha256 = digest(9) };
    const final_remint = FakeFinalRemint{
        .shape = &shape,
        .registry = &registry,
        .binding_identity_sha256 = digest(23),
    };
    const authority = FakeAuthority{ .final_remint = &final_remint };
    const policy = FakePolicy{
        .host = .{ .identity_sha256 = digest(24) },
        .total_cpu_tokens = 8,
        .cpu_tokens_per_node = 4,
        .proof_worker_count = 4,
        .maximum_parallel_nodes = 2,
        .total_rss_bytes = 160_000,
        .rss_bytes_per_node = 40_000,
        .worker_policy_identity = executions[0].fields.worker_policy_identity,
        .memory_policy_identity = executions[0].fields.memory_policy_identity,
    };
    var store_marker: u8 = 0;
    var validate_calls: usize = 0;
    var session = FakeSession{
        .store = &store_marker,
        .authority = &authority,
        .entries = &entries,
        .policy = &policy,
        .validate_calls = &validate_calls,
    };

    const encoded = try Description.encodeCanonicalJsonAlloc(
        allocator,
        &session,
    );
    defer allocator.free(encoded);
    const repeated = try Description.encodeCanonicalJsonAlloc(
        allocator,
        &session,
    );
    defer allocator.free(repeated);
    try std.testing.expectEqualSlices(u8, encoded, repeated);
    try std.testing.expectEqual(@as(usize, 2), validate_calls);
    try std.testing.expect(std.mem.endsWith(u8, encoded, "\n"));
    try std.testing.expect(std.mem.indexOf(
        u8,
        encoded,
        description.FORMAT,
    ) != null);
    inline for (.{
        "lease_id",
        "live_lease_selector",
        "admission",
        "proof_capture",
    }) |forbidden| try std.testing.expect(
        std.mem.indexOf(u8, encoded, forbidden) == null,
    );

    var parsed = try std.json.parseFromSlice(
        protocol.Json,
        allocator,
        encoded,
        .{},
    );
    defer parsed.deinit();
    try protocol.validateSeal(
        allocator,
        try protocol.objectValue(parsed.value),
    );

    session.lookup_alias = true;
    try std.testing.expectError(
        error.CampaignStage102InventoryDescriptionMismatchV4,
        Description.encodeCanonicalJsonAlloc(allocator, &session),
    );
}

test "immutable Stage102 inventory description remains unrouteable" {
    std.testing.refAllDeclsRecursive(Bridge);
    try std.testing.expect(!description.PRODUCTION_ACTIVATION);
    try std.testing.expect(!description.ROUTER_ACTIVATION);
    try std.testing.expect(!description.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(!description.SERIALIZABLE_LIVE_LEASE_SELECTOR);
    try std.testing.expect(description.EXACT_ORDERED_SESSION_PROJECTION);
    try std.testing.expect(!bridge_mod.PRODUCTION_ACTIVATION);
    try std.testing.expect(!bridge_mod.ROUTER_ACTIVATION);
    try std.testing.expect(!bridge_mod.SERIALIZABLE_FINAL_SESSION);
}

fn node(
    node_id: []const u8,
    local_task_identity: Digest,
    dependencies: []protocol.Dependency,
    external_inputs: []artifact_store.InputRefV1,
    semantic_authorities: protocol.SemanticAuthorities,
    semantic_options: protocol.Json,
) protocol.Node {
    return .{
        .node_id = node_id,
        .stage_kind = .prove,
        .stage_schema_version = 102,
        .adapter = "campaign_ethereum_incremental_leaf_wrapper_v4",
        .dependencies = dependencies,
        .external_inputs = external_inputs,
        .local_task_identity_sha256 = local_task_identity,
        .semantic_authorities = semantic_authorities,
        .semantic_options = semantic_options,
        .cpu_tokens = 4,
        .rss_tokens = 40_000,
        .output_kind = .recursion_node,
        .output_schema_version = 2,
    };
}

fn semanticKey(
    allocator: std.mem.Allocator,
    value: *const protocol.Node,
    inputs: *const [1]artifact_store.InputRefV1,
    options_identity: Digest,
    local_task_identity: Digest,
) !artifact_store.SemanticKeyV1 {
    return artifact_store.SemanticKeyV1.create(allocator, .{
        .stage_kind = value.stage_kind,
        .stage_schema_version = value.stage_schema_version,
        .campaign_namespace = digest(20),
        .local_task_identity = local_task_identity,
        .protocol_identity = value.semantic_authorities.protocol_identity_sha256,
        .program_identity = value.semantic_authorities.program_identity_sha256,
        .profile_identity = value.semantic_authorities.profile_identity_sha256,
        .pcs_identity = value.semantic_authorities.pcs_identity_sha256,
        .security_identity = value.semantic_authorities.security_identity_sha256,
        .statement_identity = value.semantic_authorities.statement_identity_sha256,
        .provider_identity = value.semantic_authorities.provider_identity_sha256,
        .layout_identity = value.semantic_authorities.layout_identity_sha256,
        .registry_identity = value.semantic_authorities.registry_identity_sha256,
        .semantic_options_identity = options_identity,
        .ordered_inputs = inputs,
    });
}

fn executionKey(
    semantic_identity: Digest,
    seed: u8,
) !artifact_store.ExecutionKeyV1 {
    return artifact_store.ExecutionKeyV1.create(.{
        .semantic_key_identity = semantic_identity,
        .producer_identity = digest(seed),
        .verifier_identity = digest(seed +% 1),
        .source_identity = digest(seed +% 2),
        .build_identity = digest(seed +% 3),
        .executable_identity = digest(seed +% 4),
        .toolchain_identity = digest(seed +% 5),
        .backend_identity = digest(seed +% 6),
        .optimization_identity = digest(seed +% 7),
        .worker_policy_identity = digest(110),
        .memory_policy_identity = digest(111),
        .retention_policy_identity = digest(seed +% 8),
        .timeout_policy_identity = digest(seed +% 9),
    });
}

fn blob(
    kind: artifact_store.ArtifactKindV1,
    schema: u16,
    byte_count: u64,
    seed: u8,
) artifact_store.BlobRefV1 {
    return .{
        .kind = kind,
        .schema_version = schema,
        .byte_count = byte_count,
        .sha256 = digest(seed),
    };
}

fn digest(seed: u8) Digest {
    var result: Digest = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

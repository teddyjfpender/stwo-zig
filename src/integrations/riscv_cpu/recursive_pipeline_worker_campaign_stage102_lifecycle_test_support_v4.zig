//! Test-only framed-worker adapter for Stage-102 inventory lifecycle tests.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const real_worker = @import("recursive_pipeline_worker_campaign_real_leaf_v4.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_store =
    @import("recursive_campaign_node_artifact_store_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub fn AdapterV4(comptime Provider: type) type {
    return AdapterWithAvailabilityV4(Provider, true);
}

pub fn GateOnlyAdapterV4(comptime Provider: type) type {
    return AdapterWithAvailabilityV4(Provider, false);
}

fn AdapterWithAvailabilityV4(
    comptime Provider: type,
    comptime release_available: bool,
) type {
    return struct {
        const Adapter = @This();

        pub const available = release_available;
        pub const production = false;
        pub const maximum_output_bytes = campaign_artifact.ENCODED_BYTE_COUNT;
        var live_leases: std.atomic.Value(usize) = .init(0);
        pub const LeasePayload = struct {
            coordinate: campaign_artifact.TaskCoordinate,
            valid: bool = true,

            pub fn validate(self: *const @This()) !void {
                if (!self.valid) return error.InvalidFixtureLeaseV4;
            }
        };

        pub fn acceptsNodeAdapter(value: []const u8) bool {
            return std.mem.eql(u8, value, real_worker.adapter_name);
        }

        pub fn describe(
            stage_kind: artifact_store.StageKindV1,
            stage_schema_version: u16,
        ) !protocol.StageDescription {
            if (stage_kind != .prove or
                stage_schema_version != real_worker.STAGE_SCHEMA_VERSION)
            {
                return error.InvalidFixtureStageV4;
            }
            return .{
                .stage_kind = .prove,
                .stage_schema_version = real_worker.STAGE_SCHEMA_VERSION,
                .output_kind = .recursion_node,
                .output_schema_version = campaign_artifact.SCHEMA_VERSION,
                .minimum_cpu_tokens = 1,
                .minimum_rss_tokens = 1,
                .root_cold_open_transitive = true,
            };
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
            return error.InvalidFixtureStageV4;
        }

        pub fn buildOutputWithExecutionAndLeasesForGenuineGate(
            _: std.mem.Allocator,
            _: *artifact_store.Store,
            _: protocol.Node,
            _: artifact_store.SemanticKeyV1,
            _: artifact_store.ExecutionKeyV1,
            _: []const artifact_store.InputRefV1,
            _: u64,
            _: []const *const LeasePayload,
        ) ![]u8 {
            return error.InvalidFixtureStageV4;
        }

        pub fn profileValue(
            _: std.mem.Allocator,
            _: protocol.Node,
            _: artifact_store.SemanticKeyV1,
            _: artifact_store.ExecutionKeyV1,
            _: u64,
        ) !protocol.Json {
            return error.InvalidFixtureStageV4;
        }

        pub fn validateOutput(
            allocator: std.mem.Allocator,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !void {
            var lease = try coldOpenLease(
                allocator,
                undefined,
                bytes,
                node,
                semantic,
                ordered_inputs,
            );
            deinitLeasePayload(&lease, allocator);
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
            allocator: std.mem.Allocator,
            _: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            const authority = try Provider.authorityForCampaign(
                semantic.fields.campaign_namespace,
            );
            const artifact = try campaign_artifact.decodeCanonical(
                authority.final_remint.shape,
                bytes,
            );
            const projected = try campaign_artifact.semanticInputsForStore(
                authority.final_remint.shape,
                &artifact,
            );
            try real_worker.validateSemanticProjectionV4(
                allocator,
                authority.final_remint.shape,
                node,
                &semantic,
                ordered_inputs,
                &projected,
            );
            _ = Adapter.live_leases.fetchAdd(1, .monotonic);
            return .{ .coordinate = artifact.coordinate };
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
            allocator: std.mem.Allocator,
            node: protocol.Node,
            _: artifact_store.SemanticKeyV1,
            _: artifact_store.BlobRefV1,
            _: u32,
            _: []const u8,
        ) !protocol.Json {
            var result = protocol.jsonObject(allocator);
            try protocol.put(&result, "schema", protocol.string("fixture-v4"));
            try protocol.put(&result, "node_id", protocol.string(node.node_id));
            try protocol.sealObject(allocator, &result);
            return result;
        }

        pub fn adoptColdPublication(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            output_ref: artifact_store.BlobRefV1,
            stage_manifest_ref: artifact_store.BlobRefV1,
            dependency_stage_manifest_refs: []const artifact_store.BlobRefV1,
        ) !void {
            try Provider.adoptStage102ColdPublication(
                allocator,
                node,
                semantic,
                execution,
                ordered_inputs,
                output_ref,
                stage_manifest_ref,
                dependency_stage_manifest_refs,
            );
        }

        pub fn adoptColdPublicationForGenuineGate(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            output_ref: artifact_store.BlobRefV1,
            stage_manifest_ref: artifact_store.BlobRefV1,
            dependency_stage_manifest_refs: []const artifact_store.BlobRefV1,
        ) !void {
            return adoptColdPublication(
                allocator,
                node,
                semantic,
                execution,
                ordered_inputs,
                output_ref,
                stage_manifest_ref,
                dependency_stage_manifest_refs,
            );
        }

        pub fn deinitLeasePayload(
            value: *LeasePayload,
            _: std.mem.Allocator,
        ) void {
            const previous = Adapter.live_leases.fetchSub(1, .monotonic);
            std.debug.assert(previous != 0);
            value.* = undefined;
        }

        pub fn liveLeaseCount() usize {
            return live_leases.load(.monotonic);
        }
    };
}

pub fn FinalLifecycleAssemblyV4(comptime Authority: type) type {
    return struct {
        pub const AuthorityV4 = Authority;

        pub fn AdapterFor(comptime Provider: type) type {
            return AdapterV4(Provider);
        }

        pub fn Role0OpenerFor(comptime Provider: type) type {
            return Role0OpenerV4(Provider);
        }
    };
}

pub fn GateOnlyFinalLifecycleAssemblyV4(comptime Authority: type) type {
    return struct {
        pub const AuthorityV4 = Authority;

        pub fn AdapterFor(comptime Provider: type) type {
            return GateOnlyAdapterV4(Provider);
        }

        pub fn Role0OpenerFor(comptime Provider: type) type {
            return GateOnlyRole0OpenerV4(Provider);
        }
    };
}

pub fn Role0OpenerV4(comptime Provider: type) type {
    return Role0OpenerWithAvailabilityV4(Provider, true);
}

pub fn GateOnlyRole0OpenerV4(comptime Provider: type) type {
    return Role0OpenerWithAvailabilityV4(Provider, false);
}

fn Role0OpenerWithAvailabilityV4(
    comptime Provider: type,
    comptime release_available: bool,
) type {
    return struct {
        const Opener = @This();

        pub const available = release_available;
        var live_leases: std.atomic.Value(usize) = .init(0);

        pub const FixtureProjectionV4 = struct {
            authority: *const final_mod.CampaignFinalRemintAuthorityV2,
            geometry: *const registry_mod.AuthenticatedGeometryV1,
            node_artifact: *const campaign_artifact.Artifact,

            pub fn validateAgainstFinal(
                self: FixtureProjectionV4,
                authority: *const final_mod.CampaignFinalRemintAuthorityV2,
            ) !void {
                const expected = try authority.geometryForRole(
                    .ethereum_incremental_leaf_wrapper_v4,
                );
                if (self.authority != authority or self.geometry != expected or
                    self.node_artifact.stage_kind != .leaf_wrapper or
                    self.node_artifact.node_kind != .real)
                {
                    return error.InvalidFixtureFinalRole0V4;
                }
            }
        };

        pub const LeasePayload = struct {
            final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
            artifact: campaign_artifact.Artifact,

            pub fn validateForCampaign(
                self: *const LeasePayload,
                authority: *const final_mod.CampaignFinalRemintAuthorityV2,
            ) !void {
                if (self.final_remint != authority)
                    return error.InvalidFixtureFinalRole0V4;
                try authority.validateAgainstCampaign(
                    self.artifact.campaign_namespace_sha256,
                );
                try campaign_artifact.validate(authority.shape, &self.artifact);
                if (self.artifact.stage_kind != .leaf_wrapper or
                    self.artifact.node_kind != .real)
                {
                    return error.InvalidFixtureFinalRole0V4;
                }
            }

            pub fn geometryForPaddingTarget(
                self: *const LeasePayload,
            ) *const registry_mod.AuthenticatedGeometryV1 {
                return &self.final_remint.final_remint.final_geometries[
                    @intFromEnum(
                        registry_mod.CircuitRoleV4
                            .ethereum_incremental_leaf_wrapper_v4,
                    )
                ];
            }

            pub fn nodeArtifact(
                self: *const LeasePayload,
            ) *const campaign_artifact.Artifact {
                return &self.artifact;
            }

            pub fn campaignFoldProjection(
                self: *const LeasePayload,
                authority: *const final_mod.CampaignFinalRemintAuthorityV2,
            ) !FixtureProjectionV4 {
                try self.validateForCampaign(authority);
                const result = FixtureProjectionV4{
                    .authority = authority,
                    .geometry = self.geometryForPaddingTarget(),
                    .node_artifact = &self.artifact,
                };
                try result.validateAgainstFinal(authority);
                return result;
            }

            pub fn deinit(self: *LeasePayload) void {
                const previous = Opener.live_leases.fetchSub(1, .monotonic);
                std.debug.assert(previous != 0);
                self.* = undefined;
            }
        };

        pub fn coldOpenNode(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
            output_ref: artifact_store.BlobRefV1,
            artifact: *const campaign_artifact.Artifact,
        ) !LeasePayload {
            const namespace = final_remint.shape.campaign_namespace_sha256;
            const authority = try Provider.authorityForCampaign(namespace);
            if (authority.final_remint != final_remint)
                return error.InvalidFixtureFinalRole0V4;
            const admission = try Provider.stage102AdmissionForOutput(
                namespace,
                output_ref,
            );
            try admission.validate(
                allocator,
                store,
                authority,
                final_remint,
                output_ref,
                artifact,
            );
            const expected = try node_store.toSharedRef(
                try campaign_artifact.artifactRef(
                    final_remint.shape,
                    artifact,
                ),
            );
            if (!artifact_store.BlobRefV1.eql(expected, output_ref))
                return error.InvalidFixtureFinalRole0V4;
            var result = LeasePayload{
                .final_remint = final_remint,
                .artifact = artifact.*,
            };
            errdefer result.deinit();
            _ = Opener.live_leases.fetchAdd(1, .monotonic);
            try result.validateForCampaign(final_remint);
            return result;
        }

        pub fn coldOpenNodeForGenuineGate(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
            output_ref: artifact_store.BlobRefV1,
            artifact: *const campaign_artifact.Artifact,
        ) !LeasePayload {
            return coldOpenNode(
                allocator,
                store,
                final_remint,
                output_ref,
                artifact,
            );
        }

        pub fn liveLeaseCount() usize {
            return live_leases.load(.monotonic);
        }
    };
}

pub fn coldOpenAndClose(
    comptime WorkerType: type,
    worker: *WorkerType,
    allocator: std.mem.Allocator,
    row: anytype,
    supplied_manifest: ?artifact_store.BlobRefV1,
) !artifact_store.BlobRefV1 {
    return coldOpenAndCloseImpl(
        WorkerType,
        worker,
        allocator,
        row,
        supplied_manifest,
        false,
    );
}

pub fn coldOpenAndCloseForGenuineGate(
    comptime WorkerType: type,
    worker: *WorkerType,
    allocator: std.mem.Allocator,
    row: anytype,
    supplied_manifest: ?artifact_store.BlobRefV1,
) !artifact_store.BlobRefV1 {
    return coldOpenAndCloseImpl(
        WorkerType,
        worker,
        allocator,
        row,
        supplied_manifest,
        true,
    );
}

fn coldOpenAndCloseImpl(
    comptime WorkerType: type,
    worker: *WorkerType,
    allocator: std.mem.Allocator,
    row: anytype,
    supplied_manifest: ?artifact_store.BlobRefV1,
    comptime genuine_gate: bool,
) !artifact_store.BlobRefV1 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var payload = protocol.jsonObject(arena);
    try protocol.put(&payload, "node", try nodeValue(arena, row.node));
    try protocol.put(
        &payload,
        "ordered_inputs",
        try inputRefsValue(arena, &row.ordered_inputs),
    );
    try protocol.put(
        &payload,
        "semantic_key",
        try protocol.semanticProjection(arena, row.semantic),
    );
    try protocol.put(
        &payload,
        "execution_key",
        try protocol.executionProjection(arena, row.execution),
    );
    try protocol.put(
        &payload,
        "output_ref",
        try protocol.blobRefValue(arena, row.output_ref),
    );
    try protocol.put(&payload, "output_path", protocol.string(row.output_path));
    try protocol.put(
        &payload,
        "dependency_stage_manifest_refs",
        try blobRefsValue(arena, &.{row.dependency_manifest_ref}),
    );
    try protocol.put(
        &payload,
        "stage_manifest_ref",
        if (supplied_manifest) |value|
            try protocol.blobRefValue(arena, value)
        else
            .null,
    );
    try protocol.put(&payload, "validator_version", protocol.integer(1));
    try protocol.put(&payload, "mode", protocol.string("root"));
    const request = protocol.Request{
        .sequence = 0,
        .action = .cold_open,
        .payload = payload,
    };
    const result = if (comptime genuine_gate)
        try worker.handleForGenuineGate(arena, request)
    else
        try worker.handle(arena, request);
    const object = try protocol.objectValue(result);
    const manifest_ref = try protocol.parseBlobRef(
        object.get("stage_manifest_ref") orelse
            return error.InvalidFixtureStageV4,
    );
    const lease_id = try protocol.stringField(object, "lease_id");
    try std.testing.expectEqual(@as(usize, 1), worker.leases.count());
    var close_payload = protocol.jsonObject(arena);
    try protocol.put(&close_payload, "lease_id", protocol.string(lease_id));
    const close_request = protocol.Request{
        .sequence = 1,
        .action = .close_lease,
        .payload = close_payload,
    };
    _ = if (comptime genuine_gate)
        try worker.handleForGenuineGate(arena, close_request)
    else
        try worker.handle(arena, close_request);
    try std.testing.expectEqual(@as(usize, 0), worker.leases.count());
    return manifest_ref;
}

pub const RetainedColdOpenV4 = struct {
    allocator: std.mem.Allocator,
    stage_manifest_ref: artifact_store.BlobRefV1,
    lease_id: []u8,

    pub fn deinit(self: *RetainedColdOpenV4) void {
        self.allocator.free(self.lease_id);
        self.* = undefined;
    }
};

/// Leaves the verifier lease inside `worker`; destroying/quiescing that worker
/// must release it. Only the opaque lease identifier is copied for assertions.
pub fn coldOpenAndRetain(
    comptime WorkerType: type,
    worker: *WorkerType,
    allocator: std.mem.Allocator,
    row: anytype,
    supplied_manifest: ?artifact_store.BlobRefV1,
) !RetainedColdOpenV4 {
    return coldOpenAndRetainAtCount(
        WorkerType,
        worker,
        allocator,
        row,
        supplied_manifest,
        1,
    );
}

/// Multi-lease sibling used by final-frontier tests. The expected count pins
/// that each cold open retained exactly one additional typed worker lease.
pub fn coldOpenAndRetainAtCount(
    comptime WorkerType: type,
    worker: *WorkerType,
    allocator: std.mem.Allocator,
    row: anytype,
    supplied_manifest: ?artifact_store.BlobRefV1,
    expected_live_count: usize,
) !RetainedColdOpenV4 {
    if (expected_live_count == 0) return error.InvalidFixtureStageV4;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var payload = protocol.jsonObject(arena);
    try protocol.put(&payload, "node", try nodeValue(arena, row.node));
    try protocol.put(
        &payload,
        "ordered_inputs",
        try inputRefsValue(arena, &row.ordered_inputs),
    );
    try protocol.put(
        &payload,
        "semantic_key",
        try protocol.semanticProjection(arena, row.semantic),
    );
    try protocol.put(
        &payload,
        "execution_key",
        try protocol.executionProjection(arena, row.execution),
    );
    try protocol.put(
        &payload,
        "output_ref",
        try protocol.blobRefValue(arena, row.output_ref),
    );
    try protocol.put(&payload, "output_path", protocol.string(row.output_path));
    try protocol.put(
        &payload,
        "dependency_stage_manifest_refs",
        try blobRefsValue(arena, &.{row.dependency_manifest_ref}),
    );
    try protocol.put(
        &payload,
        "stage_manifest_ref",
        if (supplied_manifest) |value|
            try protocol.blobRefValue(arena, value)
        else
            .null,
    );
    try protocol.put(&payload, "validator_version", protocol.integer(1));
    try protocol.put(&payload, "mode", protocol.string("root"));
    const response = try worker.handle(arena, .{
        .sequence = 0,
        .action = .cold_open,
        .payload = payload,
    });
    const object = try protocol.objectValue(response);
    const result = RetainedColdOpenV4{
        .allocator = allocator,
        .stage_manifest_ref = try protocol.parseBlobRef(
            object.get("stage_manifest_ref") orelse
                return error.InvalidFixtureStageV4,
        ),
        .lease_id = try allocator.dupe(
            u8,
            try protocol.stringField(object, "lease_id"),
        ),
    };
    errdefer allocator.free(result.lease_id);
    try std.testing.expectEqual(expected_live_count, worker.leases.count());
    return result;
}

fn nodeValue(
    allocator: std.mem.Allocator,
    node: protocol.Node,
) !protocol.Json {
    var result = protocol.jsonObject(allocator);
    try protocol.put(&result, "node_id", protocol.string(node.node_id));
    try protocol.put(&result, "stage_kind", protocol.integer(@intFromEnum(node.stage_kind)));
    try protocol.put(&result, "stage_schema_version", protocol.integer(node.stage_schema_version));
    try protocol.put(&result, "adapter", protocol.string(node.adapter));
    var dependencies = protocol.array(allocator);
    for (node.dependencies) |dependency| {
        var value = protocol.jsonObject(allocator);
        try protocol.put(&value, "node_id", protocol.string(dependency.node_id));
        try protocol.put(&value, "role", protocol.integer(dependency.role));
        try protocol.put(&value, "ordinal", protocol.integer(dependency.ordinal));
        try protocol.append(&dependencies, value);
    }
    try protocol.put(&result, "dependencies", dependencies);
    try protocol.put(&result, "external_inputs", try inputRefsValue(allocator, node.external_inputs));
    try protocol.putDigest(allocator, &result, "local_task_identity_sha256", node.local_task_identity_sha256);
    try protocol.put(&result, "semantic_authorities", try semanticAuthoritiesValue(allocator, node.semantic_authorities));
    try protocol.put(&result, "semantic_options", node.semantic_options);
    try protocol.put(&result, "cpu_tokens", try protocol.integerU64(allocator, node.cpu_tokens));
    try protocol.put(&result, "rss_tokens", try protocol.integerU64(allocator, node.rss_tokens));
    try protocol.put(&result, "output_kind", protocol.integer(@intFromEnum(node.output_kind)));
    try protocol.put(&result, "output_schema_version", protocol.integer(node.output_schema_version));
    return result;
}

fn semanticAuthoritiesValue(
    allocator: std.mem.Allocator,
    value: protocol.SemanticAuthorities,
) !protocol.Json {
    var result = protocol.jsonObject(allocator);
    inline for (.{
        .{ "protocol_identity_sha256", value.protocol_identity_sha256 },
        .{ "program_identity_sha256", value.program_identity_sha256 },
        .{ "profile_identity_sha256", value.profile_identity_sha256 },
        .{ "pcs_identity_sha256", value.pcs_identity_sha256 },
        .{ "security_identity_sha256", value.security_identity_sha256 },
        .{ "statement_identity_sha256", value.statement_identity_sha256 },
        .{ "provider_identity_sha256", value.provider_identity_sha256 },
        .{ "layout_identity_sha256", value.layout_identity_sha256 },
        .{ "registry_identity_sha256", value.registry_identity_sha256 },
    }) |field| try protocol.putDigest(allocator, &result, field[0], field[1]);
    return result;
}

fn inputRefsValue(
    allocator: std.mem.Allocator,
    values: []const artifact_store.InputRefV1,
) !protocol.Json {
    var result = protocol.array(allocator);
    for (values) |input| {
        var value = protocol.jsonObject(allocator);
        try protocol.put(&value, "role", protocol.integer(@intFromEnum(input.role)));
        try protocol.put(&value, "ordinal", protocol.integer(input.ordinal));
        try protocol.put(&value, "blob", try protocol.blobRefValue(allocator, input.blob));
        try protocol.append(&result, value);
    }
    return result;
}

fn blobRefsValue(
    allocator: std.mem.Allocator,
    values: []const artifact_store.BlobRefV1,
) !protocol.Json {
    var result = protocol.array(allocator);
    for (values) |value|
        try protocol.append(&result, try protocol.blobRefValue(allocator, value));
    return result;
}

comptime {
    if (PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("Stage102 lifecycle test adapter activated");
    }
}

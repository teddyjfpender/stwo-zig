//! Post-Stage102 campaign worker composition for recursive stages 102--104.
//!
//! A sealed Stage102 inventory is installed before this worker starts. Real
//! leaves are therefore cold-open-only inputs: this adapter never rebuilds a
//! Stage102 wrapper without its Stage101 worker epoch. Stage103 and Stage104
//! remain buildable through their exact campaign backends. One tagged,
//! process-local payload keeps role nominality while the generic worker owns
//! every lease and consumes children only after durable outer publication.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const real_worker =
    @import("recursive_pipeline_worker_campaign_real_leaf_v4.zig");
const consumers =
    @import("recursive_pipeline_worker_campaign_consumers_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const fold_projection =
    @import("recursive_pipeline_campaign_fold_projection_v2.zig");

pub const adapter_name = "campaign_final_recursive_v2";
pub const profile_schema = "stwo.recursive-campaign-final-profile.v2";
pub const validation_schema =
    "stwo.recursive-campaign-final-validation.v2";

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const STAGE102_SCHEMA_VERSION: u16 = 102;
pub const STAGE103_SCHEMA_VERSION: u16 = 103;
pub const STAGE104_SCHEMA_VERSION: u16 = 104;
pub const OUTPUT_SCHEMA_VERSION: u16 = campaign_artifact.SCHEMA_VERSION;
pub const OUTPUT_BYTE_COUNT: usize = campaign_artifact.ENCODED_BYTE_COUNT;

pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const GENUINE_Q193_GATE_GREEN = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const STAGE102_IS_COLD_OPEN_ONLY = true;
pub const BUILD_BORROWS_TYPED_CHILDREN = true;
pub const BUILD_FAILURE_RETAINS_CHILDREN = true;
pub const SUCCESS_CONSUMES_AFTER_OUTER_PUBLICATION = true;
pub const EXECUTION_KEY_POLICY_REQUIRED = true;

pub const Error = error{
    CampaignFinalCompositeDependencyMismatch,
    CampaignFinalCompositeExecutionMismatch,
    CampaignFinalCompositeStage102BuildForbidden,
    CampaignFinalCompositeStageMismatch,
    CampaignFinalCompositeUnavailable,
};

pub const StageCodeV2 = enum(u16) {
    real_wrapper_v4 = STAGE102_SCHEMA_VERSION,
    canonical_empty_v2 = STAGE103_SCHEMA_VERSION,
    common_fold_v2 = STAGE104_SCHEMA_VERSION,
};

/// `FinalWorker` is one exact specialization returned by
/// `recursive_pipeline_campaign_final_worker_transaction_v2.Types`.
/// `PolicyProvider` must be the same installed immutable session provider
/// used to instantiate it.
pub fn AdapterFor(
    comptime FinalWorker: type,
    comptime PolicyProvider: type,
) type {
    assertFinalWorker(FinalWorker);
    assertPolicyProvider(PolicyProvider);
    const Stage102 = FinalWorker.Stage102AdapterV4;
    const Stage103 = FinalWorker.Stage103AdapterV2;
    const Stage104 = FinalWorker.Stage104AdapterV2;
    const Role2 = FinalWorker.Role2TypesV2;

    if (Stage104.DependencyLease != Role2.DependencyLease or
        Stage104.LeasePayload != Role2.ProofFamily.LeasePayload)
    {
        @compileError("campaign final composite role2 types drifted");
    }

    const Lease = union(StageCodeV2) {
        const Self = @This();

        real_wrapper_v4: Stage102.LeasePayload,
        canonical_empty_v2: Stage103.LeasePayload,
        common_fold_v2: Stage104.LeasePayload,

        pub fn stageCode(self: *const Self) StageCodeV2 {
            return std.meta.activeTag(self.*);
        }

        pub fn validateForCampaign(
            self: *const Self,
            authority: *const consumers.CampaignFinalRemintAuthorityV2,
        ) !void {
            switch (self.*) {
                inline else => |*payload| try payload.validateForCampaign(
                    authority,
                ),
            }
        }

        pub fn campaignFoldProjection(
            self: *const Self,
            authority: *const consumers.CampaignFinalRemintAuthorityV2,
        ) !@import("recursive_pipeline_campaign_fold_projection_v2.zig").ProjectionV2 {
            return switch (self.*) {
                inline else => |*payload| payload.campaignFoldProjection(
                    authority,
                ),
            };
        }

        pub fn deinit(self: *Self) void {
            switch (self.*) {
                inline else => |*value| value.deinit(),
            }
            self.* = undefined;
        }
    };

    return struct {
        const Self = @This();

        pub const available = PRODUCTION_ACTIVATION and ROUTER_ACTIVATION and
            GENUINE_Q193_GATE_GREEN and FinalWorker.available and
            Stage102.available and Stage103.available and Stage104.available and
            PolicyProvider.available;
        pub const production = PRODUCTION_ACTIVATION;
        pub const maximum_output_bytes = OUTPUT_BYTE_COUNT;
        pub const SessionProviderV4 = PolicyProvider;
        pub const LeasePayload = Lease;
        pub const RetainedLeaseProjection = fold_projection.ProjectionV2;

        pub fn acceptsNodeAdapter(value: []const u8) bool {
            return std.mem.eql(u8, value, adapter_name) or
                Stage102.acceptsNodeAdapter(value) or
                std.mem.eql(u8, value, Stage103.adapter_name) or
                std.mem.eql(u8, value, Stage104.adapter_name);
        }

        pub fn unavailable() error{CampaignFinalCompositeUnavailable} {
            return error.CampaignFinalCompositeUnavailable;
        }

        pub fn describe(
            stage_kind: artifact_store.StageKindV1,
            stage_schema_version: u16,
        ) !protocol.StageDescription {
            return switch (try parseStage(
                stage_kind,
                stage_schema_version,
            )) {
                .real_wrapper_v4 => Stage102.describe(
                    stage_kind,
                    stage_schema_version,
                ),
                .canonical_empty_v2 => Stage103.describe(
                    stage_kind,
                    stage_schema_version,
                ),
                .common_fold_v2 => Stage104.describe(
                    stage_kind,
                    stage_schema_version,
                ),
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
            return error.CampaignFinalCompositeExecutionMismatch;
        }

        pub fn buildOutputWithExecutionAndLeases(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const LeasePayload,
        ) ![]u8 {
            const stage = try checkedNode(node);
            _ = try validatedPolicy(node, execution);
            return switch (stage) {
                .real_wrapper_v4 => error.CampaignFinalCompositeStage102BuildForbidden,
                .canonical_empty_v2 => blk: {
                    if (dependency_leases.len != 0)
                        return error.CampaignFinalCompositeDependencyMismatch;
                    break :blk Stage103.buildOutputWithExecutionAndLeases(
                        allocator,
                        store,
                        node,
                        semantic,
                        execution,
                        ordered_inputs,
                        candidate_ordinal,
                        &.{},
                    );
                },
                .common_fold_v2 => blk: {
                    var dependencies = try dependencyViews(
                        dependency_leases,
                    );
                    defer dependencies.deinit();
                    const pointers = [2]*const Stage104.DependencyLease{
                        &dependencies.values[0],
                        &dependencies.values[1],
                    };
                    break :blk Stage104.buildOutputWithExecutionAndLeases(
                        allocator,
                        store,
                        node,
                        semantic,
                        execution,
                        ordered_inputs,
                        candidate_ordinal,
                        &pointers,
                    );
                },
            };
        }

        pub fn profileValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            candidate_ordinal: u64,
        ) !protocol.Json {
            const stage = try checkedNode(node);
            if (stage == .real_wrapper_v4)
                return Stage102.profileValue(
                    allocator,
                    node,
                    semantic,
                    execution,
                    candidate_ordinal,
                );
            const policy = try validatedPolicy(node, execution);
            var value = protocol.jsonObject(allocator);
            try protocol.put(&value, "schema", protocol.string(profile_schema));
            try protocol.put(&value, "node_id", protocol.string(node.node_id));
            try protocol.putDigest(
                allocator,
                &value,
                "semantic_key_sha256",
                semantic.identity,
            );
            try protocol.putDigest(
                allocator,
                &value,
                "execution_key_sha256",
                execution.identity,
            );
            try protocol.putDigest(
                allocator,
                &value,
                "worker_policy_sha256",
                execution.fields.worker_policy_identity,
            );
            try protocol.putDigest(
                allocator,
                &value,
                "memory_policy_sha256",
                execution.fields.memory_policy_identity,
            );
            try protocol.put(
                &value,
                "worker_count",
                try protocol.integerU64(
                    allocator,
                    @as(u64, @intCast(try policy.engineWorkerCount())),
                ),
            );
            try protocol.put(
                &value,
                "host_byte_budget",
                try protocol.integerU64(
                    allocator,
                    policy.rss_bytes_per_node,
                ),
            );
            try protocol.put(
                &value,
                "candidate_ordinal",
                try protocol.integerU64(allocator, candidate_ordinal),
            );
            try protocol.put(&value, "production", .{ .bool = false });
            try protocol.sealObject(allocator, &value);
            return value;
        }

        pub fn validateOutput(
            allocator: std.mem.Allocator,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !void {
            return switch (try checkedNode(node)) {
                .real_wrapper_v4 => Stage102.validateOutput(
                    allocator,
                    bytes,
                    node,
                    semantic,
                    ordered_inputs,
                ),
                .canonical_empty_v2 => Stage103.validateOutput(
                    allocator,
                    bytes,
                    node,
                    semantic,
                    ordered_inputs,
                ),
                .common_fold_v2 => Stage104.validateOutput(
                    allocator,
                    bytes,
                    node,
                    semantic,
                    ordered_inputs,
                ),
            };
        }

        pub fn coldOpenLease(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            return switch (try checkedNode(node)) {
                .real_wrapper_v4 => .{
                    .real_wrapper_v4 = try Stage102.coldOpenLease(
                        allocator,
                        store,
                        bytes,
                        node,
                        semantic,
                        ordered_inputs,
                    ),
                },
                .canonical_empty_v2 => .{
                    .canonical_empty_v2 = try Stage103.coldOpenLease(
                        allocator,
                        store,
                        bytes,
                        node,
                        semantic,
                        ordered_inputs,
                    ),
                },
                .common_fold_v2 => .{
                    .common_fold_v2 = try Stage104.coldOpenLease(
                        allocator,
                        store,
                        bytes,
                        node,
                        semantic,
                        ordered_inputs,
                    ),
                },
            };
        }

        pub fn validationValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            output_ref: artifact_store.BlobRefV1,
            validator_version: u32,
            mode: []const u8,
        ) !protocol.Json {
            const stage = try checkedNode(node);
            if (stage == .real_wrapper_v4)
                return Stage102.validationValue(
                    allocator,
                    node,
                    semantic,
                    output_ref,
                    validator_version,
                    mode,
                );
            var value = protocol.jsonObject(allocator);
            try protocol.put(
                &value,
                "schema",
                protocol.string(validation_schema),
            );
            try protocol.put(&value, "node_id", protocol.string(node.node_id));
            try protocol.putDigest(
                allocator,
                &value,
                "semantic_key_sha256",
                semantic.identity,
            );
            try protocol.putDigest(
                allocator,
                &value,
                "output_sha256",
                output_ref.sha256,
            );
            try protocol.put(
                &value,
                "validator_version",
                protocol.integer(validator_version),
            );
            try protocol.put(&value, "mode", protocol.string(mode));
            try protocol.put(&value, "q193_cold_verified", .{ .bool = true });
            try protocol.put(
                &value,
                "transitive_children_cold_opened",
                .{ .bool = stage == .common_fold_v2 },
            );
            try protocol.put(&value, "production", .{ .bool = false });
            try protocol.sealObject(allocator, &value);
            return value;
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
            if (try checkedNode(node) == .real_wrapper_v4)
                return Stage102.adoptColdPublication(
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
            payload: *LeasePayload,
            _: std.mem.Allocator,
        ) void {
            payload.deinit();
        }

        pub fn projectRetainedLease(
            payload: *const LeasePayload,
            authority: *const consumers.CampaignFinalRemintAuthorityV2,
        ) !RetainedLeaseProjection {
            try payload.validateForCampaign(authority);
            const result = try payload.campaignFoldProjection(authority);
            try result.validateAgainstFinal(authority);
            return result;
        }

        const DependencyViewsV2 = struct {
            values: [2]Stage104.DependencyLease,
            common_handles: [2]Role2.CommonLeaseHandleV2,
            has_common_handle: [2]bool,

            fn deinit(self: *DependencyViewsV2) void {
                var index = self.has_common_handle.len;
                while (index != 0) {
                    index -= 1;
                    if (self.has_common_handle[index])
                        self.common_handles[index].deinit();
                }
                self.* = undefined;
            }
        };

        fn dependencyViews(
            dependencies: []const *const LeasePayload,
        ) !DependencyViewsV2 {
            if (dependencies.len != 2 or dependencies[0] == dependencies[1])
                return error.CampaignFinalCompositeDependencyMismatch;
            var result: DependencyViewsV2 = .{
                .values = undefined,
                .common_handles = undefined,
                .has_common_handle = .{ false, false },
            };
            var complete: usize = 0;
            errdefer {
                var index = complete;
                while (index != 0) {
                    index -= 1;
                    if (result.has_common_handle[index])
                        result.common_handles[index].deinit();
                }
            }
            for (dependencies, 0..) |dependency, index| {
                result.values[index] = switch (dependency.*) {
                    .real_wrapper_v4 => |*value| Stage104.DependencyLease
                        .fromReal(value),
                    .canonical_empty_v2 => |*value| Stage104.DependencyLease
                        .fromEmpty(value),
                    .common_fold_v2 => |*value| blk: {
                        result.common_handles[index] = try Role2
                            .CommonLeaseHandleV2.borrow(value);
                        result.has_common_handle[index] = true;
                        break :blk Stage104.DependencyLease.fromCommon(
                            &result.common_handles[index],
                        );
                    },
                };
                complete += 1;
            }
            return result;
        }

        fn validatedPolicy(
            node: protocol.Node,
            execution: artifact_store.ExecutionKeyV1,
        ) !@import("recursive_pipeline_worker_execution_policy_v2.zig").PolicyV2 {
            const policy = try PolicyProvider.policyForExecution(execution);
            try policy.validateAgainstExecution(execution);
            if (node.cpu_tokens != @as(u64, policy.cpu_tokens_per_node) or
                node.rss_tokens != policy.rss_bytes_per_node)
            {
                return error.CampaignFinalCompositeExecutionMismatch;
            }
            return policy;
        }

        fn checkedNode(node: protocol.Node) !StageCodeV2 {
            const stage = try validateNode(node);
            const matches = std.mem.eql(u8, node.adapter, adapter_name) or
                switch (stage) {
                    .real_wrapper_v4 => Stage102.acceptsNodeAdapter(
                        node.adapter,
                    ),
                    .canonical_empty_v2 => std.mem.eql(
                        u8,
                        node.adapter,
                        Stage103.adapter_name,
                    ),
                    .common_fold_v2 => std.mem.eql(
                        u8,
                        node.adapter,
                        Stage104.adapter_name,
                    ),
                };
            if (!matches)
                return error.CampaignFinalCompositeStageMismatch;
            return stage;
        }

        comptime {
            rejectCodec(LeasePayload);
            if (Self.available or Self.production)
                @compileError("campaign final composite activated before gates");
        }
    };
}

fn parseStage(
    stage_kind: artifact_store.StageKindV1,
    stage_schema_version: u16,
) !StageCodeV2 {
    const result = std.meta.intToEnum(
        StageCodeV2,
        stage_schema_version,
    ) catch return error.CampaignFinalCompositeStageMismatch;
    const expected: artifact_store.StageKindV1 = switch (result) {
        .real_wrapper_v4, .canonical_empty_v2 => .prove,
        .common_fold_v2 => .fold,
    };
    if (stage_kind != expected)
        return error.CampaignFinalCompositeStageMismatch;
    return result;
}

fn validateNode(node: protocol.Node) !StageCodeV2 {
    const stage = try parseStage(node.stage_kind, node.stage_schema_version);
    const dependency_count: usize = switch (stage) {
        .real_wrapper_v4 => 1,
        .canonical_empty_v2 => 0,
        .common_fold_v2 => 2,
    };
    if (node.dependencies.len != dependency_count or
        node.output_kind != .recursion_node or
        node.output_schema_version != OUTPUT_SCHEMA_VERSION)
    {
        return error.CampaignFinalCompositeStageMismatch;
    }
    return stage;
}

fn assertFinalWorker(comptime FinalWorker: type) void {
    inline for (.{
        "available",
        "Stage102AdapterV4",
        "Stage103AdapterV2",
        "Stage104AdapterV2",
        "Role2TypesV2",
    }) |name| if (!@hasDecl(FinalWorker, name))
        @compileError("campaign final composite missing transaction " ++ name);
}

fn assertPolicyProvider(comptime Provider: type) void {
    inline for (.{ "available", "policyForExecution" }) |name|
        if (!@hasDecl(Provider, name))
            @compileError("campaign final composite missing policy " ++ name);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign final composite lease gained a codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        STAGE102_SCHEMA_VERSION != 102 or STAGE103_SCHEMA_VERSION != 103 or
        STAGE104_SCHEMA_VERSION != 104 or OUTPUT_SCHEMA_VERSION != 2 or
        OUTPUT_BYTE_COUNT != 2380 or PRODUCTION_ACTIVATION or
        ROUTER_ACTIVATION or GENUINE_Q193_GATE_GREEN or
        SERIALIZABLE_FRESH_CAPABILITY or !STAGE102_IS_COLD_OPEN_ONLY or
        !BUILD_BORROWS_TYPED_CHILDREN or !BUILD_FAILURE_RETAINS_CHILDREN or
        !SUCCESS_CONSUMES_AFTER_OUTER_PUBLICATION or
        !EXECUTION_KEY_POLICY_REQUIRED)
    {
        @compileError("campaign final composite contract drifted");
    }
}

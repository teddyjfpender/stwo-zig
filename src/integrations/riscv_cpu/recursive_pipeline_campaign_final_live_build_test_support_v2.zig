//! Test-only typed adapter for the Stage-104 live-build executor.
//!
//! Stage-102 children are cold-opened from the real campaign transport used
//! by lifecycle fixtures. Stage-104 creates a deterministic dummy nested
//! proof BlobRef and a fully sealed campaign node envelope so the generic
//! worker's CAS, lease-consumption, StageManifest, and cold-open behavior can
//! be exercised without presenting this fixture as q193 proof evidence.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const real_worker = @import("recursive_pipeline_worker_campaign_real_leaf_v4.zig");
const consumers = @import("recursive_pipeline_worker_campaign_consumers_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const campaign_cas = @import("recursive_pipeline_worker_campaign_cas_v2.zig");
const empty_source = @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const GENUINE_Q193_GATE_GREEN = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const DUMMY_PROOF_IS_TEST_ONLY = true;

pub const Error = error{
    CampaignFinalLiveBuildFixtureFailureV2,
    CampaignFinalLiveBuildFixtureMismatchV2,
};

pub fn AdapterV2(comptime Provider: type) type {
    return struct {
        const Self = @This();

        pub const available = true;
        pub const production = false;
        pub const maximum_output_bytes = campaign_artifact.ENCODED_BYTE_COUNT;
        pub const SessionProviderV4 = Provider;

        var live_leases: std.atomic.Value(usize) = .init(0);
        var fail_next_build: std.atomic.Value(bool) = .init(false);

        pub const LeasePayload = struct {
            final_remint: *const consumers.CampaignFinalRemintAuthorityV2,
            artifact: campaign_artifact.Artifact,

            pub fn validate(self: *const LeasePayload) !void {
                try self.final_remint.validateAgainstCampaign(
                    self.artifact.campaign_namespace_sha256,
                );
                try campaign_artifact.validate(
                    self.final_remint.shape,
                    &self.artifact,
                );
            }
        };

        pub const RetainedLeaseProjection = struct {
            authority: *const consumers.CampaignFinalRemintAuthorityV2,
            node_artifact: *const campaign_artifact.Artifact,

            pub fn validateAgainstFinal(
                self: RetainedLeaseProjection,
                authority: *const consumers.CampaignFinalRemintAuthorityV2,
            ) !void {
                if (self.authority != authority)
                    return error.CampaignFinalLiveBuildFixtureMismatchV2;
                try campaign_artifact.validate(
                    authority.shape,
                    self.node_artifact,
                );
                const role = switch (self.node_artifact.stage_kind) {
                    .leaf_wrapper => switch (self.node_artifact.node_kind) {
                        .real => registry_mod.CircuitRoleV1
                            .ethereum_incremental_leaf_wrapper_v4,
                        .empty => registry_mod.CircuitRoleV1
                            .canonical_empty_field_v2,
                        .mixed => return error.CampaignFinalLiveBuildFixtureMismatchV2,
                    },
                    .fold, .root => registry_mod.CircuitRoleV1
                        .common_fold_field_v2,
                };
                try campaign_artifact.admitRegistry(
                    try authority.registryAuthority(),
                    authority.shape,
                    self.node_artifact,
                    try authority.geometryForRole(role),
                );
            }
        };

        pub fn acceptsNodeAdapter(value: []const u8) bool {
            return std.mem.eql(u8, value, real_worker.adapter_name) or
                std.mem.eql(u8, value, consumers.stage103_adapter_name) or
                std.mem.eql(u8, value, consumers.stage104_adapter_name);
        }

        pub fn describe(
            stage_kind: artifact_store.StageKindV1,
            stage_schema_version: u16,
        ) !protocol.StageDescription {
            if (stage_kind == .prove and
                stage_schema_version == real_worker.STAGE_SCHEMA_VERSION)
            {
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
            if (stage_kind == .fold and
                stage_schema_version == consumers.STAGE104_SCHEMA_VERSION)
            {
                return .{
                    .stage_kind = .fold,
                    .stage_schema_version = consumers.STAGE104_SCHEMA_VERSION,
                    .output_kind = .recursion_node,
                    .output_schema_version = campaign_artifact.SCHEMA_VERSION,
                    .minimum_cpu_tokens = 1,
                    .minimum_rss_tokens = 1,
                    .root_cold_open_transitive = true,
                };
            }
            if (stage_kind == .prove and
                stage_schema_version == consumers.STAGE103_SCHEMA_VERSION)
            {
                return .{
                    .stage_kind = .prove,
                    .stage_schema_version = consumers.STAGE103_SCHEMA_VERSION,
                    .output_kind = .recursion_node,
                    .output_schema_version = campaign_artifact.SCHEMA_VERSION,
                    .minimum_cpu_tokens = 1,
                    .minimum_rss_tokens = 1,
                    .root_cold_open_transitive = true,
                };
            }
            return error.CampaignFinalLiveBuildFixtureMismatchV2;
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
            return error.CampaignFinalLiveBuildFixtureMismatchV2;
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
            if (fail_next_build.swap(false, .acq_rel))
                return error.CampaignFinalLiveBuildFixtureFailureV2;
            if (node.stage_kind == .prove and
                node.stage_schema_version ==
                    consumers.STAGE103_SCHEMA_VERSION and
                std.mem.eql(u8, node.adapter, consumers.stage103_adapter_name))
            {
                return buildStage103(
                    allocator,
                    store,
                    node,
                    semantic,
                    execution,
                    ordered_inputs,
                    candidate_ordinal,
                    dependency_leases,
                );
            }
            if (node.stage_kind != .fold or
                node.stage_schema_version !=
                    consumers.STAGE104_SCHEMA_VERSION or
                !std.mem.eql(u8, node.adapter, consumers.stage104_adapter_name) or
                dependency_leases.len != 2 or ordered_inputs.len != 2)
            {
                return error.CampaignFinalLiveBuildFixtureMismatchV2;
            }
            const final_remint = try Provider.finalRemintForCampaign(
                semantic.fields.campaign_namespace,
            );
            const policy = try Provider.policyForExecution(execution);
            try policy.validateAgainstExecution(execution);
            if (node.cpu_tokens != policy.cpu_tokens_per_node or
                node.rss_tokens != policy.rss_bytes_per_node)
            {
                return error.CampaignFinalLiveBuildFixtureMismatchV2;
            }
            for (dependency_leases) |lease| {
                try lease.validate();
                if (lease.final_remint != final_remint)
                    return error.CampaignFinalLiveBuildFixtureMismatchV2;
            }
            const left = dependency_leases[0];
            const right = dependency_leases[1];
            const expected_left = try node_store.toSharedRef(
                try campaign_artifact.artifactRef(
                    final_remint.shape,
                    &left.artifact,
                ),
            );
            const expected_right = try node_store.toSharedRef(
                try campaign_artifact.artifactRef(
                    final_remint.shape,
                    &right.artifact,
                ),
            );
            if (!artifact_store.BlobRefV1.eql(
                expected_left,
                ordered_inputs[0].blob,
            ) or !artifact_store.BlobRefV1.eql(
                expected_right,
                ordered_inputs[1].blob,
            )) return error.CampaignFinalLiveBuildFixtureMismatchV2;

            const left_coordinate = left.artifact.coordinate;
            const right_coordinate = right.artifact.coordinate;
            const expected_right_index = std.math.add(
                u32,
                left_coordinate.index,
                1,
            ) catch return error.CampaignFinalLiveBuildFixtureMismatchV2;
            const height = std.math.add(
                u8,
                left_coordinate.height,
                1,
            ) catch return error.CampaignFinalLiveBuildFixtureMismatchV2;
            if (left_coordinate.height != right_coordinate.height or
                left_coordinate.index & 1 != 0 or
                right_coordinate.index != expected_right_index)
            {
                return error.CampaignFinalLiveBuildFixtureMismatchV2;
            }
            const coordinate = try campaign_public.coordinate(
                final_remint.shape,
                height,
                left_coordinate.index / 2,
            );
            const node_public = try campaign_public.initParent(
                final_remint.shape,
                &left.artifact.node_public,
                &right.artifact.node_public,
                coordinate,
            );

            var proof_hash = std.crypto.hash.sha2.Sha256.init(.{});
            proof_hash.update(
                "stwo-zig/campaign-final-live-build-fixture-proof/v2\x00",
            );
            proof_hash.update(&semantic.identity);
            proof_hash.update(&execution.identity);
            var ordinal_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &ordinal_bytes, candidate_ordinal, .little);
            proof_hash.update(&ordinal_bytes);
            const proof_bytes = proof_hash.finalResult();
            const proof_ref = try store.putBytes(
                .proof_artifact,
                campaign_cas.PROOF_SCHEMA_VERSION,
                &proof_bytes,
            );
            const registry = try final_remint.registryAuthority();
            const geometry = try final_remint.geometryForRole(
                .common_fold_field_v2,
            );
            const entry = try registry.entry(.common_fold_field_v2);
            const artifact = try campaign_artifact.seal(
                final_remint.shape,
                .{
                    .stage_kind = if (coordinate.height ==
                        final_remint.shape.root_height)
                        .root
                    else
                        .fold,
                    .node_kind = node_public.node_kind,
                    .child_count = 2,
                    .coordinate = coordinate,
                    .node_public = node_public,
                    .campaign_namespace_sha256 = final_remint.shape
                        .campaign_namespace_sha256,
                    .circuit_identity_sha256 = entry.circuit_identity_sha256,
                    .program_identity_sha256 = entry.program_identity_sha256,
                    .profile_identity_sha256 = entry.profile_identity_sha256,
                    .pcs_identity_sha256 = entry.pcs_identity_sha256,
                    .padding_layout_identity_sha256 = entry
                        .padding_layout_identity_sha256,
                    .registry_identity_sha256 = registry.identity_sha256,
                    .node_public_abi_sha256 = geometry.output_abi
                        .node_public_abi_sha256,
                    .proof_shape_identity_sha256 = geometry.proof_shape
                        .identity_sha256,
                    .ordered_children = .{
                        try node_store.fromSharedRef(expected_left),
                        try node_store.fromSharedRef(expected_right),
                    },
                    .proof_ref = try node_store.fromSharedRef(proof_ref),
                    .preprocessed_root = geometry.preprocessed_root,
                    .semantic_inputs_identity_sha256 = undefined,
                    .field_public_transport_sha256 = undefined,
                    .content_identity_sha256 = undefined,
                },
            );
            try campaign_artifact.admitRegistry(
                registry,
                final_remint.shape,
                &artifact,
                geometry,
            );
            const projected = try campaign_artifact.semanticInputsForStore(
                final_remint.shape,
                &artifact,
            );
            try consumers.validateSemanticProjectionV2(
                allocator,
                final_remint.shape,
                node,
                &semantic,
                ordered_inputs,
                &projected,
            );
            const encoded = try campaign_artifact.encodeCanonical(
                final_remint.shape,
                &artifact,
            );
            return allocator.dupe(u8, &encoded);
        }

        fn buildStage103(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const LeasePayload,
        ) ![]u8 {
            if (dependency_leases.len != 0 or ordered_inputs.len != 1 or
                ordered_inputs[0].role != .direct or
                ordered_inputs[0].ordinal != 0)
            {
                return error.CampaignFinalLiveBuildFixtureMismatchV2;
            }
            const final_remint = try Provider.finalRemintForCampaign(
                semantic.fields.campaign_namespace,
            );
            const policy = try Provider.policyForExecution(execution);
            try policy.validateAgainstExecution(execution);
            if (node.cpu_tokens != policy.cpu_tokens_per_node or
                node.rss_tokens != policy.rss_bytes_per_node)
            {
                return error.CampaignFinalLiveBuildFixtureMismatchV2;
            }
            const source_ref = ordered_inputs[0].blob;
            try campaign_cas.validate(source_ref, .stage103_source);
            var source_blob = try store.openBlob(
                source_ref,
                .source,
                empty_source.SCHEMA_VERSION,
                empty_source.SOURCE_ENCODED_BYTE_COUNT,
            );
            defer source_blob.deinit(store.allocator);
            const source = try empty_source.ColdInputV2.open(
                final_remint.shape,
                source_blob.bytes,
            );

            var proof_hash = std.crypto.hash.sha2.Sha256.init(.{});
            proof_hash.update(
                "stwo-zig/campaign-final-live-build-fixture-empty-proof/v2\x00",
            );
            proof_hash.update(&semantic.identity);
            proof_hash.update(&execution.identity);
            var ordinal_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &ordinal_bytes, candidate_ordinal, .little);
            proof_hash.update(&ordinal_bytes);
            const proof_bytes = proof_hash.finalResult();
            const proof_ref = try store.putBytes(
                .proof_artifact,
                campaign_cas.PROOF_SCHEMA_VERSION,
                &proof_bytes,
            );
            const registry = try final_remint.registryAuthority();
            const geometry = try final_remint.geometryForRole(
                .canonical_empty_field_v2,
            );
            const entry = try registry.entry(.canonical_empty_field_v2);
            const source_artifact_ref = try source.source.artifactRef(
                final_remint.shape,
            );
            const artifact = try campaign_artifact.seal(
                final_remint.shape,
                .{
                    .stage_kind = .leaf_wrapper,
                    .node_kind = .empty,
                    .child_count = 1,
                    .coordinate = source.node_public.coordinate,
                    .node_public = source.node_public,
                    .campaign_namespace_sha256 = final_remint.shape
                        .campaign_namespace_sha256,
                    .circuit_identity_sha256 = entry.circuit_identity_sha256,
                    .program_identity_sha256 = entry.program_identity_sha256,
                    .profile_identity_sha256 = entry.profile_identity_sha256,
                    .pcs_identity_sha256 = entry.pcs_identity_sha256,
                    .padding_layout_identity_sha256 = entry
                        .padding_layout_identity_sha256,
                    .registry_identity_sha256 = registry.identity_sha256,
                    .node_public_abi_sha256 = geometry.output_abi
                        .node_public_abi_sha256,
                    .proof_shape_identity_sha256 = geometry.proof_shape
                        .identity_sha256,
                    .ordered_children = .{
                        source_artifact_ref,
                        campaign_artifact.ArtifactRef.zero(),
                    },
                    .proof_ref = try node_store.fromSharedRef(proof_ref),
                    .preprocessed_root = geometry.preprocessed_root,
                    .semantic_inputs_identity_sha256 = undefined,
                    .field_public_transport_sha256 = undefined,
                    .content_identity_sha256 = undefined,
                },
            );
            try campaign_artifact.admitRegistry(
                registry,
                final_remint.shape,
                &artifact,
                geometry,
            );
            const projected = try campaign_artifact.semanticInputsForStore(
                final_remint.shape,
                &artifact,
            );
            try consumers.validateSemanticProjectionV2(
                allocator,
                final_remint.shape,
                node,
                &semantic,
                ordered_inputs,
                &projected,
            );
            const encoded = try campaign_artifact.encodeCanonical(
                final_remint.shape,
                &artifact,
            );
            return allocator.dupe(u8, &encoded);
        }

        pub fn profileValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            candidate_ordinal: u64,
        ) !protocol.Json {
            var result = protocol.jsonObject(allocator);
            try protocol.put(
                &result,
                "schema",
                protocol.string(
                    "stwo.recursive-pipeline-live-build-fixture-profile.v2",
                ),
            );
            try protocol.put(&result, "node_id", protocol.string(node.node_id));
            try protocol.putDigest(
                allocator,
                &result,
                "semantic_key_sha256",
                semantic.identity,
            );
            try protocol.putDigest(
                allocator,
                &result,
                "execution_key_sha256",
                execution.identity,
            );
            try protocol.put(
                &result,
                "candidate_ordinal",
                try protocol.integerU64(allocator, candidate_ordinal),
            );
            try protocol.put(&result, "production", .{ .bool = false });
            try protocol.sealObject(allocator, &result);
            return result;
        }

        pub fn coldOpenLease(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            const final_remint = try Provider.finalRemintForCampaign(
                semantic.fields.campaign_namespace,
            );
            const artifact = try campaign_artifact.decodeCanonical(
                final_remint.shape,
                bytes,
            );
            const projected = try campaign_artifact.semanticInputsForStore(
                final_remint.shape,
                &artifact,
            );
            if (node.stage_schema_version == real_worker.STAGE_SCHEMA_VERSION) {
                try real_worker.validateSemanticProjectionV4(
                    allocator,
                    final_remint.shape,
                    node,
                    &semantic,
                    ordered_inputs,
                    &projected,
                );
                if (artifact.stage_kind != .leaf_wrapper or
                    artifact.node_kind != .real)
                {
                    return error.CampaignFinalLiveBuildFixtureMismatchV2;
                }
            } else if (node.stage_schema_version ==
                consumers.STAGE103_SCHEMA_VERSION)
            {
                try consumers.validateSemanticProjectionV2(
                    allocator,
                    final_remint.shape,
                    node,
                    &semantic,
                    ordered_inputs,
                    &projected,
                );
                if (ordered_inputs.len != 1 or
                    ordered_inputs[0].role != .direct or
                    ordered_inputs[0].ordinal != 0 or
                    artifact.stage_kind != .leaf_wrapper or
                    artifact.node_kind != .empty)
                {
                    return error.CampaignFinalLiveBuildFixtureMismatchV2;
                }
                const source_ref = ordered_inputs[0].blob;
                try campaign_cas.validate(source_ref, .stage103_source);
                var source_blob = try store.openBlob(
                    source_ref,
                    .source,
                    empty_source.SCHEMA_VERSION,
                    empty_source.SOURCE_ENCODED_BYTE_COUNT,
                );
                defer source_blob.deinit(store.allocator);
                const source = try empty_source.ColdInputV2.open(
                    final_remint.shape,
                    source_blob.bytes,
                );
                if (!std.meta.eql(artifact.node_public, source.node_public))
                    return error.CampaignFinalLiveBuildFixtureMismatchV2;
            } else if (node.stage_schema_version ==
                consumers.STAGE104_SCHEMA_VERSION)
            {
                try consumers.validateSemanticProjectionV2(
                    allocator,
                    final_remint.shape,
                    node,
                    &semantic,
                    ordered_inputs,
                    &projected,
                );
                if (artifact.stage_kind != .fold and
                    artifact.stage_kind != .root)
                {
                    return error.CampaignFinalLiveBuildFixtureMismatchV2;
                }
            } else return error.CampaignFinalLiveBuildFixtureMismatchV2;
            const role: registry_mod.CircuitRoleV1 =
                if (artifact.stage_kind == .leaf_wrapper)
                    switch (artifact.node_kind) {
                        .real => .ethereum_incremental_leaf_wrapper_v4,
                        .empty => .canonical_empty_field_v2,
                        .mixed => return error.CampaignFinalLiveBuildFixtureMismatchV2,
                    }
                else
                    .common_fold_field_v2;
            const geometry = try final_remint.geometryForRole(role);
            try campaign_artifact.admitRegistry(
                try final_remint.registryAuthority(),
                final_remint.shape,
                &artifact,
                geometry,
            );
            const proof_ref = try node_store.toSharedRef(artifact.proof_ref);
            var proof = try store.openBlob(
                proof_ref,
                .proof_artifact,
                campaign_cas.PROOF_SCHEMA_VERSION,
                campaign_cas.MAX_PROOF_BYTE_COUNT,
            );
            defer proof.deinit(store.allocator);
            _ = live_leases.fetchAdd(1, .monotonic);
            return .{ .final_remint = final_remint, .artifact = artifact };
        }

        pub fn validationValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            output_ref: artifact_store.BlobRefV1,
            validator_version: u32,
            mode: []const u8,
        ) !protocol.Json {
            var result = protocol.jsonObject(allocator);
            try protocol.put(
                &result,
                "schema",
                protocol.string(
                    "stwo.recursive-pipeline-live-build-fixture-validation.v2",
                ),
            );
            try protocol.put(&result, "node_id", protocol.string(node.node_id));
            try protocol.putDigest(
                allocator,
                &result,
                "semantic_key_sha256",
                semantic.identity,
            );
            try protocol.putDigest(
                allocator,
                &result,
                "output_sha256",
                output_ref.sha256,
            );
            try protocol.put(
                &result,
                "validator_version",
                protocol.integer(validator_version),
            );
            try protocol.put(&result, "mode", protocol.string(mode));
            try protocol.put(&result, "valid", .{ .bool = true });
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
            if (node.stage_schema_version != real_worker.STAGE_SCHEMA_VERSION)
                return;
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

        pub fn deinitLeasePayload(
            value: *LeasePayload,
            _: std.mem.Allocator,
        ) void {
            const previous = live_leases.fetchSub(1, .monotonic);
            std.debug.assert(previous != 0);
            value.* = undefined;
        }

        pub fn projectRetainedLease(
            value: *const LeasePayload,
            authority: *const consumers.CampaignFinalRemintAuthorityV2,
        ) !RetainedLeaseProjection {
            try value.validate();
            if (value.final_remint != authority)
                return error.CampaignFinalLiveBuildFixtureMismatchV2;
            const result = RetainedLeaseProjection{
                .authority = authority,
                .node_artifact = &value.artifact,
            };
            try result.validateAgainstFinal(authority);
            return result;
        }

        pub fn armOneBuildFailure() void {
            fail_next_build.store(true, .release);
        }

        pub fn liveLeaseCount() usize {
            return live_leases.load(.acquire);
        }
    };
}

comptime {
    if (PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        GENUINE_Q193_GATE_GREEN or SERIALIZABLE_FRESH_CAPABILITY or
        !DUMMY_PROOF_IS_TEST_ONLY)
    {
        @compileError("campaign final live build fixture activated");
    }
}

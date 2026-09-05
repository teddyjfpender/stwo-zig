//! Campaign-native persistent-worker adapter for Stage 102 role-0 wrappers.
//!
//! The adapter publishes the nested q193 proof into the shared CAS and returns
//! the canonical campaign NodePublic envelope. The generic worker then writes
//! and ingests that node, cold-opens it through this adapter, publishes its
//! validation/profile receipts, and only then seals StageManifest kind 4.
//! Thus neither a node ref nor a manifest receipt can substitute for the
//! nonserializable cold verifier lease.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_store =
    @import("recursive_campaign_node_artifact_store_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const campaign_cas = @import("recursive_pipeline_worker_campaign_cas_v2.zig");
const backend_mod =
    @import("recursive_pipeline_worker_campaign_real_leaf_backend_v4.zig");

pub const adapter_name = "campaign_ethereum_incremental_leaf_wrapper_v4";
pub const profile_schema =
    "stwo.recursive-campaign-real-leaf-wrapper-profile.v4";
pub const validation_schema =
    "stwo.recursive-campaign-real-leaf-wrapper-validation.v4";
pub const semantic_options_schema =
    "stwo.recursive-campaign-real-leaf-wrapper-options.v4";

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const STAGE_SCHEMA_VERSION: u16 =
    node_store.REAL_WRAPPER_STAGE_SCHEMA_VERSION;
pub const OUTPUT_SCHEMA_VERSION: u16 = campaign_artifact.SCHEMA_VERSION;
pub const OUTPUT_BYTE_COUNT: u64 = campaign_artifact.ENCODED_BYTE_COUNT;
pub const DEPENDENCY_COUNT: usize = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const BUILD_BORROWS_DEPENDENCY = true;
pub const BUILD_FAILURE_RETAINS_DEPENDENCY = true;
pub const EVERY_COLD_OPEN_REPLAYS_STAGE101_AND_Q193 = true;
pub const WORKER_OWNS_STAGE_MANIFEST_SEAL_LAST = true;
pub const COLD_ADMISSION_ADOPTION_REQUIRED = true;
pub const SEMANTIC_OPTIONS_BIND_TYPED_PROJECTION = true;

pub const Error = error{
    CampaignRealLeafStage102AuthorityUnavailableV4,
    CampaignRealLeafStage102BackendUnavailableV4,
    CampaignRealLeafStage102ColdAdmissionUnavailableV4,
    CampaignRealLeafStage102DependencyMismatchV4,
    CampaignRealLeafStage102ExecutionAuthorityUnavailableV4,
    CampaignRealLeafStage102InputMismatchV4,
    CampaignRealLeafStage102OutputMismatchV4,
    CampaignRealLeafStage102ProjectionMismatchV4,
    CampaignRealLeafStage102ProofReferenceMismatchV4,
};

/// Provider contract:
/// - `available: bool`;
/// - `authorityForCampaign([32]u8) !*const Backend.AuthorityV4`.
///
/// The returned process-local authority owns no proof freshness, but retains
/// the validated runtime table, seven-ref rows, target, FinalRemint, and the
/// active cold sources from which the target was derived.
pub fn Stage102For(
    comptime AuthorityProvider: type,
    comptime Backend: type,
) type {
    assertAuthorityProvider(AuthorityProvider, Backend.AuthorityV4);
    assertBackend(Backend);
    return struct {
        pub const available = AuthorityProvider.available and Backend.available;
        pub const production = PRODUCTION_ACTIVATION;
        pub const LeasePayload = Backend.LeasePayload;
        pub const DependencyLease = Backend.NativeLeasePayload;
        pub const maximum_output_bytes: usize = campaign_artifact.ENCODED_BYTE_COUNT;

        pub fn acceptsNodeAdapter(value: []const u8) bool {
            return std.mem.eql(u8, value, adapter_name) or
                std.mem.eql(u8, value, "zig-worker-v1");
        }

        pub fn describe(
            stage_kind: artifact_store.StageKindV1,
            stage_schema_version: u16,
        ) !protocol.StageDescription {
            if (stage_kind != .prove or
                stage_schema_version != STAGE_SCHEMA_VERSION)
            {
                return error.CampaignRealLeafStage102InputMismatchV4;
            }
            return .{
                .stage_kind = .prove,
                .stage_schema_version = STAGE_SCHEMA_VERSION,
                .output_kind = .recursion_node,
                .output_schema_version = OUTPUT_SCHEMA_VERSION,
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
            _: []const *const DependencyLease,
        ) ![]u8 {
            return error.CampaignRealLeafStage102ExecutionAuthorityUnavailableV4;
        }

        pub fn buildOutputWithExecutionAndLeases(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const DependencyLease,
        ) ![]u8 {
            if (comptime !available)
                return error.CampaignRealLeafStage102BackendUnavailableV4;
            return buildOutputWithExecutionAndLeasesValidated(
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

        /// Exact-body proof-production sibling for the genuine q193 gate.
        /// It skips only the compile-time release boolean and otherwise shares
        /// the production execution-policy, dependency, proof publication,
        /// artifact, and semantic-projection path byte for byte.
        pub fn buildOutputWithExecutionAndLeasesForGenuineGate(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const DependencyLease,
        ) ![]u8 {
            return buildOutputWithExecutionAndLeasesValidated(
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

        fn buildOutputWithExecutionAndLeasesValidated(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const DependencyLease,
        ) ![]u8 {
            try validateStageNode(node, ordered_inputs);
            if (dependency_leases.len != DEPENDENCY_COUNT)
                return error.CampaignRealLeafStage102DependencyMismatchV4;
            const authority = try currentAuthorityValidated(
                AuthorityProvider,
                Backend,
                allocator,
                semantic.fields.campaign_namespace,
            );
            _ = try Backend.validateBorrowedDependency(
                allocator,
                authority,
                node.local_task_identity_sha256,
                dependency_leases[0],
            );
            var proved = try Backend.proveAndColdVerify(
                allocator,
                store,
                authority,
                node,
                semantic,
                execution,
                ordered_inputs,
                candidate_ordinal,
                dependency_leases[0],
            );
            defer proved.deinit();
            try proved.validate(
                allocator,
                authority,
                node.local_task_identity_sha256,
                ordered_inputs[0].blob,
            );
            const proof_bytes = proved.proofBytes();
            if (proof_bytes.len == 0)
                return error.CampaignRealLeafStage102ProofReferenceMismatchV4;
            const proof_ref = try store.putBytes(
                .proof_artifact,
                campaign_cas.PROOF_SCHEMA_VERSION,
                proof_bytes,
            );
            try campaign_cas.validate(proof_ref, .proof);
            const artifact = proved.nodeArtifact();
            const expected_proof = try node_store.toSharedRef(
                artifact.proof_ref,
            );
            if (!artifact_store.BlobRefV1.eql(proof_ref, expected_proof))
                return error.CampaignRealLeafStage102ProofReferenceMismatchV4;
            try validateProjection(
                allocator,
                node,
                &semantic,
                ordered_inputs,
                authority,
                artifact,
            );
            const encoded = try campaign_artifact.encodeCanonical(
                authority.final_remint.shape,
                artifact,
            );
            return allocator.dupe(u8, &encoded);
        }

        pub fn validateOutput(
            allocator: std.mem.Allocator,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !void {
            if (comptime !available)
                return error.CampaignRealLeafStage102BackendUnavailableV4;
            return validateOutputValidated(
                allocator,
                bytes,
                node,
                semantic,
                ordered_inputs,
            );
        }

        /// Exact-body sibling for the genuine transitive q193 gate. It skips
        /// only the compile-time release boolean; all authority, node,
        /// artifact, and semantic-projection validation is shared with the
        /// production method above.
        pub fn validateOutputForGenuineGate(
            allocator: std.mem.Allocator,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !void {
            return validateOutputValidated(
                allocator,
                bytes,
                node,
                semantic,
                ordered_inputs,
            );
        }

        fn validateOutputValidated(
            allocator: std.mem.Allocator,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !void {
            try validateStageNode(node, ordered_inputs);
            const authority = try currentAuthorityValidated(
                AuthorityProvider,
                Backend,
                allocator,
                semantic.fields.campaign_namespace,
            );
            const artifact = try campaign_artifact.decodeCanonical(
                authority.final_remint.shape,
                bytes,
            );
            try validateProjection(
                allocator,
                node,
                &semantic,
                ordered_inputs,
                authority,
                &artifact,
            );
        }

        /// Reopens both nested proof layers. No validation/profile receipt or
        /// preexisting StageManifest is promoted into this live payload.
        pub fn coldOpenLease(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            if (comptime !available)
                return error.CampaignRealLeafStage102BackendUnavailableV4;
            return coldOpenLeaseValidated(
                allocator,
                store,
                bytes,
                node,
                semantic,
                ordered_inputs,
            );
        }

        /// Exact-body sibling for the genuine transitive q193 gate. The
        /// returned value is the production `LeasePayload`; the nested
        /// Stage-101 replay, role-0 proof cold verification, campaign fold
        /// projection, and pointer closure are unchanged.
        pub fn coldOpenLeaseForGenuineGate(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            return coldOpenLeaseValidated(
                allocator,
                store,
                bytes,
                node,
                semantic,
                ordered_inputs,
            );
        }

        fn coldOpenLeaseValidated(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            try validateStageNode(node, ordered_inputs);
            const authority = try currentAuthorityValidated(
                AuthorityProvider,
                Backend,
                allocator,
                semantic.fields.campaign_namespace,
            );
            const artifact = try campaign_artifact.decodeCanonical(
                authority.final_remint.shape,
                bytes,
            );
            try validateProjection(
                allocator,
                node,
                &semantic,
                ordered_inputs,
                authority,
                &artifact,
            );
            const proof_ref = try node_store.toSharedRef(artifact.proof_ref);
            try campaign_cas.validate(proof_ref, .proof);
            var proof = try store.openBlob(
                proof_ref,
                .proof_artifact,
                campaign_cas.PROOF_SCHEMA_VERSION,
                campaign_cas.MAX_PROOF_BYTE_COUNT,
            );
            defer proof.deinit(store.allocator);
            var result = try Backend.coldOpenOwned(
                allocator,
                store,
                authority,
                node,
                ordered_inputs,
                proof.bytes,
                bytes,
            );
            errdefer Backend.deinitLeasePayload(&result);
            try Backend.validateLease(
                allocator,
                &result,
                authority,
                node.local_task_identity_sha256,
                ordered_inputs[0].blob,
                &artifact,
            );
            const projection = try result.campaignFoldProjection(
                authority.final_remint,
            );
            try projection.validateAgainstFinal(authority.final_remint);
            if (projection.role !=
                registry_mod.CircuitRoleV4.ethereum_incremental_leaf_wrapper_v4)
            {
                return error.CampaignRealLeafStage102ProjectionMismatchV4;
            }
            return result;
        }

        pub fn deinitLeasePayload(
            value: *LeasePayload,
            _: std.mem.Allocator,
        ) void {
            Backend.deinitLeasePayload(value);
        }

        pub fn profileValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            candidate_ordinal: u64,
        ) !protocol.Json {
            const policy = try Backend.executionPolicyForNode(
                allocator,
                node,
                semantic,
                execution,
            );
            const worker_count = try policy.engineWorkerCount();
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
                    @as(u64, @intCast(worker_count)),
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

        pub fn validationValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            output_ref: artifact_store.BlobRefV1,
            validator_version: u32,
            mode: []const u8,
        ) !protocol.Json {
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
            try protocol.put(&value, "stage101_replayed", .{ .bool = true });
            try protocol.put(&value, "q193_cold_verified", .{ .bool = true });
            try protocol.put(&value, "production", .{ .bool = false });
            try protocol.sealObject(allocator, &value);
            return value;
        }

        /// Called only after the generic worker has independently cold-opened
        /// the q193 output and published/validated its canonical StageManifest.
        /// The provider must deep-own every retained request projection before
        /// this request arena is destroyed.
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
            if (comptime !@hasDecl(
                AuthorityProvider,
                "adoptStage102ColdPublication",
            )) return error.CampaignRealLeafStage102ColdAdmissionUnavailableV4;
            try validateStageNode(node, ordered_inputs);
            _ = try currentAuthority(
                AuthorityProvider,
                Backend,
                allocator,
                semantic.fields.campaign_namespace,
            );
            _ = try Backend.executionPolicyForNode(
                allocator,
                node,
                semantic,
                execution,
            );
            try campaign_cas.validate(output_ref, .recursion_node);
            try campaign_cas.validate(
                stage_manifest_ref,
                .stage_manifest,
            );
            if (dependency_stage_manifest_refs.len != DEPENDENCY_COUNT)
                return error.CampaignRealLeafStage102DependencyMismatchV4;
            try campaign_cas.validate(
                dependency_stage_manifest_refs[0],
                .stage_manifest,
            );
            try AuthorityProvider.adoptStage102ColdPublication(
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
    };
}

pub fn AdapterFor(
    comptime Engine: type,
    comptime ActiveSources: type,
    comptime AuthorityProvider: type,
    comptime PolicyProvider: type,
) type {
    const Backend = backend_mod.BackendFor(
        Engine,
        ActiveSources,
        PolicyProvider,
    );
    return Stage102For(AuthorityProvider, Backend);
}

/// Canonical Stage-102 semantic options. The generic worker hashes these JSON
/// bytes into `SemanticKeyV1`; the carried field separately binds the exact
/// typed campaign projection used by the recursive-node store. The two hash
/// domains are deliberately distinct.
pub fn semanticOptionsValueV4(
    allocator: std.mem.Allocator,
    projected: *const campaign_artifact.CampaignSemanticInputsV2,
) !protocol.Json {
    var result = protocol.jsonObject(allocator);
    try protocol.put(
        &result,
        "schema",
        protocol.string(semantic_options_schema),
    );
    try protocol.putDigest(
        allocator,
        &result,
        "campaign_semantic_inputs_identity_sha256",
        projected.identity_sha256,
    );
    return result;
}

/// Exact bridge between the generic worker key and the typed campaign-store
/// projection. This does not reinterpret the store's semantic key: every
/// projected field is checked directly, while the worker key retains its
/// canonical-JSON semantic-options identity.
pub fn validateSemanticProjectionV4(
    allocator: std.mem.Allocator,
    shape: *const campaign_artifact.CampaignShape,
    node: protocol.Node,
    semantic: *const artifact_store.SemanticKeyV1,
    ordered_inputs: []const artifact_store.InputRefV1,
    projected: *const campaign_artifact.CampaignSemanticInputsV2,
) !void {
    try validateStageNode(node, ordered_inputs);
    try projected.validate(shape);
    try semantic.validate(allocator);

    const options = protocol.objectValue(node.semantic_options) catch
        return error.CampaignRealLeafStage102ProjectionMismatchV4;
    protocol.exactKeys(options, &.{
        "schema",
        "campaign_semantic_inputs_identity_sha256",
    }) catch return error.CampaignRealLeafStage102ProjectionMismatchV4;
    const projected_identity = protocol.digestField(
        options,
        "campaign_semantic_inputs_identity_sha256",
        true,
    ) catch return error.CampaignRealLeafStage102ProjectionMismatchV4;
    const options_schema = protocol.stringField(options, "schema") catch
        return error.CampaignRealLeafStage102ProjectionMismatchV4;
    if (!std.mem.eql(
        u8,
        options_schema,
        semantic_options_schema,
    ) or !std.mem.eql(
        u8,
        &projected_identity,
        &projected.identity_sha256,
    )) return error.CampaignRealLeafStage102ProjectionMismatchV4;

    const options_identity = try protocol.canonicalDigest(
        allocator,
        node.semantic_options,
    );
    const local_task = try campaign_store.localTaskIdentity(shape, projected);
    const statement = try campaign_store.statementCacheIdentity(
        shape,
        projected,
    );
    const security = node_store.security.ProofSecurityV1
        .recursiveParentSecure();
    const fields = semantic.fields;
    if (fields.stage_kind != campaign_store.sharedStageKind(
        projected.stage_kind,
    ) or fields.stage_schema_version != try campaign_store.stageSchemaVersion(
        shape,
        projected,
    ) or !std.mem.eql(
        u8,
        &fields.campaign_namespace,
        &projected.campaign_namespace_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.local_task_identity,
        &local_task,
    ) or !std.mem.eql(
        u8,
        &node.local_task_identity_sha256,
        &local_task,
    ) or !std.mem.eql(
        u8,
        &fields.protocol_identity,
        &projected.circuit_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.program_identity,
        &projected.program_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.profile_identity,
        &projected.profile_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.pcs_identity,
        &projected.pcs_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.security_identity,
        &security.identity,
    ) or !std.mem.eql(
        u8,
        &fields.statement_identity,
        &statement,
    ) or !artifact_store.encoding.isZeroDigest(fields.provider_identity) or
        !std.mem.eql(
            u8,
            &fields.layout_identity,
            &projected.padding_layout_identity_sha256,
        ) or !std.mem.eql(
        u8,
        &fields.registry_identity,
        &projected.registry_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.semantic_options_identity,
        &options_identity,
    ) or !semanticAuthoritiesEqualV4(
        node.semantic_authorities,
        fields,
    ) or fields.ordered_inputs.len != ordered_inputs.len) {
        return error.CampaignRealLeafStage102ProjectionMismatchV4;
    }
    for (fields.ordered_inputs, ordered_inputs) |actual, expected| {
        if (!std.meta.eql(actual, expected))
            return error.CampaignRealLeafStage102ProjectionMismatchV4;
    }
    if (ordered_inputs.len != projected.child_count)
        return error.CampaignRealLeafStage102ProjectionMismatchV4;
    for (ordered_inputs, projected.ordered_children[0..projected.child_count]) |
        actual,
        expected,
    | {
        if (!artifact_store.BlobRefV1.eql(
            actual.blob,
            try node_store.toSharedRef(expected),
        )) return error.CampaignRealLeafStage102ProjectionMismatchV4;
    }
}

fn currentAuthority(
    comptime Provider: type,
    comptime Backend: type,
    allocator: std.mem.Allocator,
    campaign_namespace_sha256: artifact_store.Digest,
) !*const Backend.AuthorityV4 {
    if (comptime !Provider.available)
        return error.CampaignRealLeafStage102AuthorityUnavailableV4;
    return currentAuthorityValidated(
        Provider,
        Backend,
        allocator,
        campaign_namespace_sha256,
    );
}

fn currentAuthorityValidated(
    comptime Provider: type,
    comptime Backend: type,
    allocator: std.mem.Allocator,
    campaign_namespace_sha256: artifact_store.Digest,
) !*const Backend.AuthorityV4 {
    const authority = try Provider.authorityForCampaign(
        campaign_namespace_sha256,
    );
    try Backend.validateAuthority(
        allocator,
        authority,
        campaign_namespace_sha256,
    );
    return authority;
}

fn validateStageNode(
    node: protocol.Node,
    ordered_inputs: []const artifact_store.InputRefV1,
) !void {
    if (node.stage_kind != .prove or
        node.stage_schema_version != STAGE_SCHEMA_VERSION or
        node.dependencies.len != DEPENDENCY_COUNT or
        node.external_inputs.len != 0 or
        ordered_inputs.len != DEPENDENCY_COUNT or
        node.output_kind != .recursion_node or
        node.output_schema_version != OUTPUT_SCHEMA_VERSION or
        !(std.mem.eql(u8, node.adapter, adapter_name) or
            std.mem.eql(u8, node.adapter, "zig-worker-v1")))
    {
        return error.CampaignRealLeafStage102InputMismatchV4;
    }
    const dependency = node.dependencies[0];
    const input = ordered_inputs[0];
    if (dependency.role != @intFromEnum(artifact_store.InputRoleV1.proof) or
        dependency.ordinal != 0 or input.role != .proof or
        input.ordinal != 0)
    {
        return error.CampaignRealLeafStage102DependencyMismatchV4;
    }
    try campaign_cas.validate(input.blob, .proof);
}

fn validateProjection(
    allocator: std.mem.Allocator,
    node: protocol.Node,
    semantic: *const artifact_store.SemanticKeyV1,
    ordered_inputs: []const artifact_store.InputRefV1,
    authority: anytype,
    artifact: *const campaign_artifact.Artifact,
) !void {
    try authority.validate(
        allocator,
        semantic.fields.campaign_namespace,
    );
    const final_remint = authority.final_remint;
    const shape = final_remint.shape;
    const registry = try final_remint.registryAuthority();
    const geometry = try final_remint.geometryForRole(
        .ethereum_incremental_leaf_wrapper_v4,
    );
    try campaign_artifact.validate(shape, artifact);
    try campaign_artifact.admitRegistry(
        registry,
        shape,
        artifact,
        geometry,
    );
    const projected = try campaign_artifact.semanticInputsForStore(
        shape,
        artifact,
    );
    try validateSemanticProjectionV4(
        allocator,
        shape,
        node,
        semantic,
        ordered_inputs,
        &projected,
    );
    const local_task = try campaign_store.localTaskIdentity(shape, &projected);
    const selected = try authority.admissionForWrapperTask(
        allocator,
        semantic.fields.campaign_namespace,
        node.local_task_identity_sha256,
    );
    const child = try node_store.toSharedRef(artifact.ordered_children[0]);
    if (artifact.stage_kind != .leaf_wrapper or
        artifact.node_kind != .real or artifact.child_count != 1 or
        artifact.coordinate.height != 0 or
        artifact.coordinate.index != selected.row.segment_index or
        artifact.coordinate.global_ordinal != selected.row.segment_index or
        !std.mem.eql(
            u8,
            &node.local_task_identity_sha256,
            &local_task,
        ) or !std.mem.eql(
        u8,
        &node.local_task_identity_sha256,
        &selected.admission.wrapper_local_task_identity_sha256,
    ) or !artifact_store.BlobRefV1.eql(child, ordered_inputs[0].blob)) {
        return error.CampaignRealLeafStage102ProjectionMismatchV4;
    }
}

fn semanticAuthoritiesEqualV4(
    node: protocol.SemanticAuthorities,
    fields: artifact_store.SemanticKeyFieldsV1,
) bool {
    return std.mem.eql(
        u8,
        &node.protocol_identity_sha256,
        &fields.protocol_identity,
    ) and std.mem.eql(
        u8,
        &node.program_identity_sha256,
        &fields.program_identity,
    ) and std.mem.eql(
        u8,
        &node.profile_identity_sha256,
        &fields.profile_identity,
    ) and std.mem.eql(
        u8,
        &node.pcs_identity_sha256,
        &fields.pcs_identity,
    ) and std.mem.eql(
        u8,
        &node.security_identity_sha256,
        &fields.security_identity,
    ) and std.mem.eql(
        u8,
        &node.statement_identity_sha256,
        &fields.statement_identity,
    ) and std.mem.eql(
        u8,
        &node.provider_identity_sha256,
        &fields.provider_identity,
    ) and std.mem.eql(
        u8,
        &node.layout_identity_sha256,
        &fields.layout_identity,
    ) and std.mem.eql(
        u8,
        &node.registry_identity_sha256,
        &fields.registry_identity,
    );
}

fn assertAuthorityProvider(comptime Provider: type, comptime Authority: type) void {
    inline for (.{ "available", "authorityForCampaign" }) |name| {
        if (!@hasDecl(Provider, name))
            @compileError("campaign Stage102 authority provider missing " ++ name);
    }
    _ = Authority;
}

fn assertBackend(comptime Backend: type) void {
    inline for (.{
        "available",
        "AuthorityV4",
        "NativeLeasePayload",
        "LeasePayload",
        "validateAuthority",
        "validateBorrowedDependency",
        "executionPolicyForNode",
        "proveAndColdVerify",
        "coldOpenOwned",
        "validateLease",
        "deinitLeasePayload",
    }) |name| if (!@hasDecl(Backend, name))
        @compileError("campaign Stage102 backend missing " ++ name);
    if (!@hasDecl(Backend.LeasePayload, "campaignFoldProjection") or
        @hasDecl(Backend.LeasePayload, "encode") or
        @hasDecl(Backend.LeasePayload, "decode"))
    {
        @compileError("campaign Stage102 lease contract drifted");
    }
}

pub const testing = struct {
    pub const validateStageNodeV4 = validateStageNode;
};

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        STAGE_SCHEMA_VERSION != 102 or OUTPUT_SCHEMA_VERSION != 2 or
        OUTPUT_BYTE_COUNT != 2380 or DEPENDENCY_COUNT != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or !BUILD_BORROWS_DEPENDENCY or
        !BUILD_FAILURE_RETAINS_DEPENDENCY or
        !EVERY_COLD_OPEN_REPLAYS_STAGE101_AND_Q193 or
        !WORKER_OWNS_STAGE_MANIFEST_SEAL_LAST or
        !COLD_ADMISSION_ADOPTION_REQUIRED or
        !SEMANTIC_OPTIONS_BIND_TYPED_PROJECTION)
    {
        @compileError("campaign Stage102 adapter drifted");
    }
}

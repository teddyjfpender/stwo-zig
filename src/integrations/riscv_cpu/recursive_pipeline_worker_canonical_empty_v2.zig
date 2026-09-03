//! Persistent-worker adapter for the field-native canonical-empty wrapper.
//!
//! Stage 103 consumes one canonical source artifact and emits one schema-2
//! recursive-node envelope.  The producer publishes the retained q193 proof
//! but never promotes its in-process verifier state into a lease.  Cold-open
//! reopens both immutable inputs, repeats canonical decoding and q193
//! verification, then owns the resulting `FreshAdmissionV2` until the worker
//! explicitly releases it.
//!
//! A registry alone is insufficient: `RegistryParityAuthorityV2` retains the
//! three independently cold-derived geometries and their checked padding
//! parity.  Until real-leaf and common-fold geometries exist, the default
//! provider fails before proving. Claims/PCS capture pointer identity alone
//! does not authenticate common-fold rows 18--34: `requireFoldChild` therefore
//! consumes the exact verifier-rerecorded graph retained by its cold owner.
//! A nonserializable process-local token prevents repeated q193/transcript
//! replay while closing the same owner allocations and identities.
//!
//! The deterministic replay boundary is exact. Durable inputs are only the
//! canonical source, retained proof, and schema-2 node. Cold verification
//! remints statement/claims/PCS capture and rerecords `UniversalRelations`,
//! `SharedProviderRelations`, CohortV2 generated interactions and audited
//! closure against that same capture. The retained Circuit, bindings, input
//! and node values, RecursionLane, and lowering Evaluation remain live-only;
//! none may be added to the durable node codec.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const node_artifact = @import("recursive_node_artifact_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");
const proof_mod =
    @import("recursive_common_canonical_empty_universal_proof_v2.zig");
const source_mod =
    @import("recursive_common_canonical_empty_wrapper_input_v1.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

pub const adapter_name = "canonical_empty_wrapper_v2";
pub const profile_schema =
    "stwo.recursive-canonical-empty-wrapper-profile.v2";
pub const validation_schema =
    "stwo.recursive-canonical-empty-wrapper-validation.v2";

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 2;
pub const STAGE_SCHEMA_VERSION =
    node_store.EMPTY_WRAPPER_STAGE_SCHEMA_VERSION;
pub const OUTPUT_SCHEMA_VERSION = node_artifact.SCHEMA_VERSION;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const AUTHENTICATED_COMPOSITION_GRAPH_AVAILABLE = true;
pub const MAX_RETAINED_ARTIFACT_BYTES: u64 =
    secure_artifact.MAX_CANONICAL_PROOF_BYTES + 4 * 1024 * 1024;

pub const Error = registry_mod.Error || proof_mod.Error || error{
    CanonicalEmptyStage103ArtifactMismatch,
    CanonicalEmptyStage103InputMismatch,
    CanonicalEmptyStage103OutputMismatch,
    CanonicalEmptyStage103ProjectionMismatch,
    CanonicalEmptyStage103RequiresArtifactStore,
    CommonWrapperRegistryParityUnavailable,
    MissingAuthenticatedCompositionGraph,
};

/// Process-local authority.  Every geometry must have been minted by its
/// role-specific cold verifier; the parity object is replayed rather than
/// trusted by digest.  No encoder exists for this type.
pub const RegistryParityAuthorityV2 = struct {
    registry: registry_mod.RecursiveCircuitRegistryV1,
    geometries: [registry_mod.ROLE_COUNT]registry_mod.AuthenticatedGeometryV1,
    parity: registry_mod.PaddingParityV1,

    pub fn init(
        registry: registry_mod.RecursiveCircuitRegistryV1,
        geometries: [registry_mod.ROLE_COUNT]registry_mod.AuthenticatedGeometryV1,
        parity: registry_mod.PaddingParityV1,
    ) !RegistryParityAuthorityV2 {
        const result = RegistryParityAuthorityV2{
            .registry = registry,
            .geometries = geometries,
            .parity = parity,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: *const RegistryParityAuthorityV2) !void {
        try self.registry.validate();
        try self.parity.validate(&self.registry, &self.geometries);
        inline for (std.meta.tags(registry_mod.CircuitRoleV1)) |role| {
            const index = @intFromEnum(role);
            if (self.geometries[index].role != role)
                return error.CommonWrapperRegistryParityUnavailable;
            const entry = try self.registry.entry(role);
            const expected = try registry_mod.RegistryEntryV1.fromGeometry(
                &self.geometries[index],
            );
            if (!std.meta.eql(entry.*, expected))
                return error.CommonWrapperRegistryParityUnavailable;
        }
    }

    pub fn canonicalEmptyGeometry(
        self: *const RegistryParityAuthorityV2,
    ) *const registry_mod.AuthenticatedGeometryV1 {
        return &self.geometries[
            @intFromEnum(registry_mod.CircuitRoleV1.canonical_empty_field_v2)
        ];
    }
};

pub const FoldChildReadinessV2 = enum(u8) {
    missing_authenticated_composition_graph = 1,
    verifier_rerecorded_composition_graph = 2,
};

pub fn currentFoldChildReadiness() FoldChildReadinessV2 {
    return .verifier_rerecorded_composition_graph;
}

/// Complete process-local child boundary for common-fold rows 18--34. The
/// wrapper/ingress pointers and graph slices borrow one `LeasePayloadV2`.
pub const FreshFoldChildV2 = struct {
    wrapper: @import("recursive_common_wrapper_authority_v2.zig").FreshWrapperViewV2,
    ingress: proof_mod.FreshRecursiveIngressV2,
    graph: proof_mod.FreshCompositionGraphV2,
    query_words: *const [proof_mod.QUERY_WORD_COUNT]proof_mod.QueryWordV2,
    query_log_size: u32,
    final_transcript_digest: *const proof_mod.TranscriptDigestV2,
    final_transcript_draw_count: u32,
    query_words_identity_sha256: *const [32]u8,

    pub fn validateBorrowed(self: FreshFoldChildV2) !void {
        try self.ingress.validate();
        if (self.wrapper.capture != self.ingress.capture or
            &self.wrapper.artifact.node_public != self.ingress.node_public or
            self.wrapper.geometry != self.ingress.geometry or
            self.query_words != self.ingress.query_words or
            self.query_words != self.graph.query_words or
            self.query_log_size != self.ingress.query_log_size or
            self.query_log_size != self.graph.query_log_size or
            self.final_transcript_digest !=
                self.ingress.final_transcript_digest or
            self.final_transcript_digest !=
                self.graph.final_transcript_digest or
            self.final_transcript_draw_count !=
                self.ingress.final_transcript_draw_count or
            self.final_transcript_draw_count !=
                self.graph.final_transcript_draw_count or
            self.query_words_identity_sha256 !=
                self.ingress.query_words_identity_sha256 or
            self.query_words_identity_sha256 !=
                self.graph.query_words_identity_sha256 or
            self.graph.evaluation.values.len != self.graph.lane.graph.nodes.len or
            !std.mem.eql(
                u8,
                &self.graph.evaluation.circuit_identity,
                &self.graph.lane.graph.identity_digest,
            ) or std.mem.allEqual(
            u8,
            self.graph.capture_identity_sha256,
            0,
        ) or std.mem.allEqual(
            u8,
            self.graph.layout_identity_sha256,
            0,
        )) return error.CanonicalEmptyStage103ArtifactMismatch;
        try self.graph.lane.graph.validate();
    }
};

/// Worker-owned verifier lease.  Its views borrow the same exact cold owner;
/// neither the lease nor either view has a durable codec.
pub const LeasePayloadV2 = struct {
    admission: proof_mod.FreshAdmissionV2,
    parity_authority: RegistryParityAuthorityV2,

    pub fn initOwned(
        admission: proof_mod.FreshAdmissionV2,
        parity_authority: RegistryParityAuthorityV2,
    ) !LeasePayloadV2 {
        var owned = admission;
        errdefer owned.deinit();
        const result = LeasePayloadV2{
            .admission = owned,
            .parity_authority = parity_authority,
        };
        try result.validate();
        return result;
    }

    pub fn deinit(self: *LeasePayloadV2) void {
        self.admission.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const LeasePayloadV2) !void {
        try self.parity_authority.validate();
        try self.admission.validate();
        if (!std.meta.eql(
            self.admission.registry,
            self.parity_authority.registry,
        ) or !std.meta.eql(
            self.admission.evidence.geometry().*,
            self.parity_authority.canonicalEmptyGeometry().*,
        )) return error.CommonWrapperRegistryParityUnavailable;
    }

    pub fn wrapperView(
        self: *const LeasePayloadV2,
    ) !@import("recursive_common_wrapper_authority_v2.zig").FreshWrapperViewV2 {
        try self.validate();
        return self.admission.view();
    }

    pub fn recursiveIngress(
        self: *const LeasePayloadV2,
    ) !proof_mod.FreshRecursiveIngressV2 {
        try self.validate();
        const ingress = try self.admission.evidence.ingressView();
        try ingress.validate();
        const wrapper = self.admission.view();
        if (wrapper.geometry != ingress.geometry or
            wrapper.capture != ingress.capture or
            &wrapper.artifact.node_public != ingress.node_public)
        {
            return error.CanonicalEmptyStage103ArtifactMismatch;
        }
        return ingress;
    }

    pub fn foldChildReadiness(
        self: *const LeasePayloadV2,
    ) !FoldChildReadinessV2 {
        _ = try self.wrapperView();
        _ = try self.recursiveIngress();
        return currentFoldChildReadiness();
    }

    /// Exposes the cached graph only after the owned cold proof's process-local
    /// token rechecks its exact allocation and identity closure.
    pub fn requireFoldChild(
        self: *const LeasePayloadV2,
    ) !FreshFoldChildV2 {
        try self.validate();
        const wrapper = try self.wrapperView();
        const ingress = try self.recursiveIngress();
        const graph = try self.admission.evidence.foldGraphView();
        const result = FreshFoldChildV2{
            .wrapper = wrapper,
            .ingress = ingress,
            .graph = graph,
            .query_words = ingress.query_words,
            .query_log_size = ingress.query_log_size,
            .final_transcript_digest = ingress.final_transcript_digest,
            .final_transcript_draw_count = ingress.final_transcript_draw_count,
            .query_words_identity_sha256 = ingress.query_words_identity_sha256,
        };
        try result.validateBorrowed();
        return result;
    }
};

/// Default authority keeps the production worker route unavailable until all
/// three wrapper roles have genuine cold geometry and exact parity.
pub const UnavailableRegistryAuthorityV2 = struct {
    pub const available = false;

    pub fn current() error{CommonWrapperRegistryParityUnavailable}!RegistryParityAuthorityV2 {
        return error.CommonWrapperRegistryParityUnavailable;
    }
};

pub fn AdapterForRegistryAuthority(comptime Authority: type) type {
    assertAuthorityContract(Authority);
    return struct {
        pub const name = adapter_name;
        pub const production = PRODUCTION_ACTIVATION;
        pub const available = Authority.available;
        pub const LeasePayload = LeasePayloadV2;

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
                return error.UnsupportedRecursivePipelineStage;
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

        pub fn unavailable() error{CommonWrapperRegistryParityUnavailable} {
            return error.CommonWrapperRegistryParityUnavailable;
        }

        pub fn buildOutput(
            _: std.mem.Allocator,
            _: protocol.Node,
            _: artifact_store.SemanticKeyV1,
            _: []const artifact_store.InputRefV1,
            _: u64,
        ) ![]u8 {
            return error.CanonicalEmptyStage103RequiresArtifactStore;
        }

        pub fn buildOutputWithLeases(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            _: u64,
            dependency_leases: []const *const LeasePayload,
        ) ![]u8 {
            if (dependency_leases.len != 0)
                return error.CanonicalEmptyStage103InputMismatch;
            const authority = try currentAuthority();
            try validateStageNode(node, ordered_inputs);
            const source_ref = try sourceRef(ordered_inputs);
            var source_blob = try store.openBlob(
                source_ref,
                .source,
                source_mod.SCHEMA_VERSION,
                source_mod.SOURCE_ENCODED_BYTE_COUNT,
            );
            defer source_blob.deinit(store.allocator);

            var proved = try proof_mod.proveAndColdVerify(
                allocator,
                source_blob.bytes,
                .{ .worker_count = 1 },
            );
            var proved_owned = true;
            defer if (proved_owned) proved.deinit();
            try proved.receipt.validate();
            const proof_bytes = try proved.proof.encodeArtifactAlloc(allocator);
            defer allocator.free(proof_bytes);
            const published_proof = try store.putBytes(
                .proof_artifact,
                proof_mod.PROOF_ARTIFACT_SCHEMA_VERSION,
                proof_bytes,
            );
            const expected_proof = try node_store.toSharedRef(
                try proved.proof.proofArtifactRef(),
            );
            if (!artifact_store.BlobRefV1.eql(
                published_proof,
                expected_proof,
            )) return error.CanonicalEmptyStage103ArtifactMismatch;

            var cold = proved.proof;
            proved.proof = undefined;
            proved_owned = false;
            var evidence = try proof_mod.EvidenceV2.initOwned(
                cold,
                &authority.registry,
                semantic.fields.campaign_namespace,
            );
            cold = undefined;
            defer evidence.deinit();
            try validateProjection(
                allocator,
                node,
                semantic,
                ordered_inputs,
                evidence.artifact(),
                &authority,
            );
            const bytes = try evidence.artifact().encodeCanonical();
            return allocator.dupe(u8, &bytes);
        }

        pub fn profileValue(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            _: artifact_store.ExecutionKeyV1,
            candidate_ordinal: u64,
        ) !protocol.Json {
            var value = protocol.jsonObject(allocator);
            try protocol.put(&value, "schema", protocol.string(profile_schema));
            try protocol.put(&value, "node_id", protocol.string(node.node_id));
            try protocol.putDigest(
                allocator,
                &value,
                "semantic_key_sha256",
                semantic.identity,
            );
            try protocol.put(
                &value,
                "candidate_ordinal",
                try protocol.integerU64(allocator, candidate_ordinal),
            );
            try protocol.put(&value, "performance", .{ .bool = false });
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
            const authority = try currentAuthority();
            try validateStageNode(node, ordered_inputs);
            const artifact = try node_artifact.RecursiveNodeArtifactV2
                .decodeCanonical(bytes);
            try validateProjection(
                allocator,
                node,
                semantic,
                ordered_inputs,
                &artifact,
                &authority,
            );
        }

        pub fn coldOpenLease(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            bytes: []const u8,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !LeasePayload {
            const authority = try currentAuthority();
            try validateStageNode(node, ordered_inputs);
            const artifact = try node_artifact.RecursiveNodeArtifactV2
                .decodeCanonical(bytes);
            try validateProjection(
                allocator,
                node,
                semantic,
                ordered_inputs,
                &artifact,
                &authority,
            );
            const source_ref = try sourceRef(ordered_inputs);
            var source_blob = try store.openBlob(
                source_ref,
                .source,
                source_mod.SCHEMA_VERSION,
                source_mod.SOURCE_ENCODED_BYTE_COUNT,
            );
            defer source_blob.deinit(store.allocator);
            const proof_ref = try node_store.toSharedRef(artifact.proof_ref);
            var proof_blob = try store.openBlob(
                proof_ref,
                .proof_artifact,
                proof_mod.PROOF_ARTIFACT_SCHEMA_VERSION,
                MAX_RETAINED_ARTIFACT_BYTES,
            );
            defer proof_blob.deinit(store.allocator);

            var cold = try proof_mod.coldOpen(
                allocator,
                source_blob.bytes,
                proof_blob.bytes,
            );
            var cold_owned = true;
            defer if (cold_owned) cold.deinit();
            const moved_cold = cold;
            cold = undefined;
            cold_owned = false;
            var evidence = try proof_mod.EvidenceV2.initOwned(
                moved_cold,
                &authority.registry,
                semantic.fields.campaign_namespace,
            );
            var evidence_owned = true;
            defer if (evidence_owned) evidence.deinit();
            if (!std.meta.eql(evidence.node_artifact, artifact))
                return error.CanonicalEmptyStage103ArtifactMismatch;
            const moved_evidence = evidence;
            evidence = undefined;
            evidence_owned = false;
            var admission = try proof_mod.FreshAdmissionV2.initOwned(
                moved_evidence,
                authority.registry,
            );
            var admission_owned = true;
            defer if (admission_owned) admission.deinit();
            const moved_admission = admission;
            admission = undefined;
            admission_owned = false;
            const result = try LeasePayload.initOwned(
                moved_admission,
                authority,
            );
            return result;
        }

        pub fn deinitLeasePayload(
            payload: *LeasePayload,
            _: std.mem.Allocator,
        ) void {
            payload.deinit();
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
            try protocol.put(&value, "cold_verified", .{ .bool = true });
            try protocol.put(&value, "production", .{ .bool = false });
            try protocol.sealObject(allocator, &value);
            return value;
        }

        fn currentAuthority() !RegistryParityAuthorityV2 {
            if (comptime !Authority.available)
                return error.CommonWrapperRegistryParityUnavailable;
            const result = try Authority.current();
            try result.validate();
            return result;
        }
    };
}

pub const Adapter = AdapterForRegistryAuthority(
    UnavailableRegistryAuthorityV2,
);

fn validateStageNode(
    node: protocol.Node,
    ordered_inputs: []const artifact_store.InputRefV1,
) !void {
    if (node.stage_kind != .prove or
        node.stage_schema_version != STAGE_SCHEMA_VERSION or
        node.dependencies.len != 0 or node.external_inputs.len != 1 or
        node.output_kind != .recursion_node or
        node.output_schema_version != OUTPUT_SCHEMA_VERSION or
        !Adapter.acceptsNodeAdapter(node.adapter) or ordered_inputs.len != 1 or
        !std.meta.eql(node.external_inputs[0], ordered_inputs[0]))
    {
        return error.CanonicalEmptyStage103InputMismatch;
    }
    const options = try protocol.objectValue(node.semantic_options);
    try protocol.exactKeys(options, &.{});
    _ = try sourceRef(ordered_inputs);
}

fn sourceRef(
    ordered_inputs: []const artifact_store.InputRefV1,
) !artifact_store.BlobRefV1 {
    if (ordered_inputs.len != 1 or ordered_inputs[0].role != .direct or
        ordered_inputs[0].ordinal != 0 or
        ordered_inputs[0].blob.kind != .source or
        ordered_inputs[0].blob.schema_version != source_mod.SCHEMA_VERSION or
        ordered_inputs[0].blob.byte_count != source_mod.SOURCE_ENCODED_BYTE_COUNT)
    {
        return error.CanonicalEmptyStage103InputMismatch;
    }
    try ordered_inputs[0].blob.validate();
    return ordered_inputs[0].blob;
}

fn validateProjection(
    allocator: std.mem.Allocator,
    node: protocol.Node,
    semantic: artifact_store.SemanticKeyV1,
    ordered_inputs: []const artifact_store.InputRefV1,
    artifact: *const node_artifact.RecursiveNodeArtifactV2,
    authority: *const RegistryParityAuthorityV2,
) !void {
    try semantic.validate(allocator);
    try artifact.validate();
    try authority.validate();
    const source_ref = try sourceRef(ordered_inputs);
    const expected_source = try node_store.toSharedRef(
        artifact.ordered_children[0],
    );
    if (artifact.stage_kind != .leaf_wrapper or artifact.node_kind != .empty or
        artifact.child_count != 1 or artifact.coordinate.height != 0 or
        !artifact_store.BlobRefV1.eql(source_ref, expected_source) or
        !std.meta.eql(
            artifact.ordered_children[1],
            node_artifact.ArtifactRefV1.zero(),
        )) return error.CanonicalEmptyStage103ArtifactMismatch;
    try authority.registry.admitV2(
        artifact,
        authority.canonicalEmptyGeometry(),
    );
    const projected = try artifact.semanticInputs();
    const local_task = try node_store.localTaskIdentityV2(&projected);
    const statement = try node_store.statementCacheIdentityV2(&projected);
    const expected_security = node_store.security.ProofSecurityV1
        .recursiveParentSecure();
    const fields = semantic.fields;
    if (fields.stage_kind != .prove or
        fields.stage_schema_version != STAGE_SCHEMA_VERSION or
        !std.mem.eql(
            u8,
            &fields.campaign_namespace,
            &artifact.campaign_namespace_sha256,
        ) or !std.mem.eql(
        u8,
        &fields.local_task_identity,
        &local_task,
    ) or !std.mem.eql(
        u8,
        &fields.protocol_identity,
        &artifact.circuit_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.program_identity,
        &artifact.program_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.profile_identity,
        &artifact.profile_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.pcs_identity,
        &artifact.pcs_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &fields.security_identity,
        &expected_security.identity,
    ) or !std.mem.eql(
        u8,
        &fields.statement_identity,
        &statement,
    ) or !artifact_store.encoding.isZeroDigest(fields.provider_identity) or
        !std.mem.eql(
            u8,
            &fields.layout_identity,
            &artifact.padding_layout_identity_sha256,
        ) or !std.mem.eql(
        u8,
        &fields.registry_identity,
        &authority.registry.identity_sha256,
    ) or fields.ordered_inputs.len != 1 or
        !std.meta.eql(fields.ordered_inputs[0], ordered_inputs[0]) or
        !std.mem.eql(u8, &node.local_task_identity_sha256, &local_task))
    {
        return error.CanonicalEmptyStage103ProjectionMismatch;
    }
}

fn assertAuthorityContract(comptime Authority: type) void {
    inline for (.{ "available", "current" }) |name| {
        if (!@hasDecl(Authority, name))
            @compileError("stage103 registry authority missing: " ++ name);
    }
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 2 or
        STAGE_SCHEMA_VERSION != 103 or OUTPUT_SCHEMA_VERSION != 2 or
        PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        !AUTHENTICATED_COMPOSITION_GRAPH_AVAILABLE or Adapter.available or
        @intFromEnum(artifact_store.ArtifactKindV1.recursion_node) != 10 or
        source_mod.SOURCE_ARTIFACT_KIND !=
            @intFromEnum(artifact_store.ArtifactKindV1.source))
    {
        @compileError("canonical-empty stage103 adapter drifted");
    }
}

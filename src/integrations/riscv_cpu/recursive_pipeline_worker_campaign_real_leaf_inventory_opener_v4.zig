//! Typed external-inventory cold opener for campaign role-0 nodes.
//!
//! A kind-10/schema-2 role-0 node does not contain the Stage-102 Node,
//! SemanticKey, ExecutionKey, or dependency StageManifest needed to replay its
//! nested Stage-101 proof. Those authorities are supplied by one sealed,
//! process-local campaign inventory. This module authenticates that inventory
//! against both manifests and the canonical node before delegating to the
//! frozen Stage-102 adapter. No lease, inventory pointer, or verifier-owned
//! capability has a codec.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const support = @import("recursive_pipeline_worker_support_v1.zig");
const storage = @import("recursive_pipeline_worker_storage_v1.zig");
const real_worker =
    @import("recursive_pipeline_worker_campaign_real_leaf_v4.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_store =
    @import("recursive_campaign_node_artifact_store_v2.zig");
const campaign_cas =
    @import("recursive_pipeline_worker_campaign_cas_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const native_worker = @import("recursive_pipeline_worker_native_leaf_v4.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const STAGE102_DEPENDENCY_COUNT: usize = 1;
pub const MAXIMUM_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
pub const TRANSITIVE_Q193_GATE_GREEN = false;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const MANIFEST_CLOSURE_REQUIRED = true;
pub const ZIG_KEYS_REQUIRED = true;

pub const FinalRemint = final_mod.CampaignFinalRemintAuthorityV2;

pub const Error = error{
    CampaignRealLeafInventoryAdmissionMismatchV4,
    CampaignRealLeafInventoryManifestMismatchV4,
    CampaignRealLeafInventoryOpenerUnavailableV4,
    CampaignRealLeafInventoryProviderMismatchV4,
};

/// Borrowed view into one sealed Stage-102 inventory row. The two key values
/// were decoded/minted by Zig; the manifest refs are durable transport only.
/// `ordered_inputs[0]` is the exact Stage-101 proof ref.
pub const Stage102ColdAdmissionV4 = struct {
    node: *const protocol.Node,
    semantic: *const artifact_store.SemanticKeyV1,
    execution: *const artifact_store.ExecutionKeyV1,
    ordered_inputs: *const [STAGE102_DEPENDENCY_COUNT]artifact_store.InputRefV1,
    stage_manifest_ref: artifact_store.BlobRefV1,
    dependency_stage_manifest_ref: artifact_store.BlobRefV1,

    pub fn validate(
        self: Stage102ColdAdmissionV4,
        allocator: std.mem.Allocator,
        store: *artifact_store.Store,
        authority: anytype,
        final_remint: *const FinalRemint,
        output_ref: artifact_store.BlobRefV1,
        artifact: *const campaign_artifact.Artifact,
    ) !void {
        if (authority.final_remint != final_remint)
            return error.CampaignRealLeafInventoryProviderMismatchV4;
        const namespace = final_remint.shape.campaign_namespace_sha256;
        try authority.validate(allocator, namespace);
        try final_remint.validateAgainstCampaign(namespace);
        try campaign_cas.validate(output_ref, .recursion_node);
        try campaign_cas.validate(self.stage_manifest_ref, .stage_manifest);
        try campaign_cas.validate(
            self.dependency_stage_manifest_ref,
            .stage_manifest,
        );
        try real_worker.testing.validateStageNodeV4(
            self.node.*,
            self.ordered_inputs[0..],
        );
        try support.validateKeys(
            allocator,
            self.node.*,
            self.ordered_inputs[0..],
            self.semantic.*,
            self.execution.*,
        );
        if (!std.mem.eql(
            u8,
            &self.semantic.fields.campaign_namespace,
            &namespace,
        )) return error.CampaignRealLeafInventoryAdmissionMismatchV4;

        const expected_output = try node_store.toSharedRef(
            try campaign_artifact.artifactRef(
                final_remint.shape,
                artifact,
            ),
        );
        const child_ref = try node_store.toSharedRef(
            artifact.ordered_children[0],
        );
        if (!artifact_store.BlobRefV1.eql(expected_output, output_ref) or
            !artifact_store.BlobRefV1.eql(
                child_ref,
                self.ordered_inputs[0].blob,
            )) return error.CampaignRealLeafInventoryAdmissionMismatchV4;

        const semantic_projection = try campaign_artifact
            .semanticInputsForStore(final_remint.shape, artifact);
        try real_worker.validateSemanticProjectionV4(
            allocator,
            final_remint.shape,
            self.node.*,
            self.semantic,
            self.ordered_inputs[0..],
            &semantic_projection,
        );
        const local_task = try campaign_store.localTaskIdentity(
            final_remint.shape,
            &semantic_projection,
        );
        const selected = try authority.admissionForWrapperTask(
            allocator,
            namespace,
            self.node.local_task_identity_sha256,
        );
        if (!std.mem.eql(
            u8,
            &local_task,
            &self.node.local_task_identity_sha256,
        ) or selected.index != @as(
            usize,
            @intCast(artifact.coordinate.index),
        ) or
            selected.row.segment_index != artifact.coordinate.index)
        {
            return error.CampaignRealLeafInventoryAdmissionMismatchV4;
        }

        const dependencies = [_]artifact_store.BlobRefV1{
            self.dependency_stage_manifest_ref,
        };
        try support.validateExistingStageManifest(
            allocator,
            store,
            self.stage_manifest_ref,
            self.node.*,
            self.ordered_inputs[0..],
            self.semantic.*,
            self.execution.*,
            output_ref,
            &dependencies,
            "root",
        );
        try validateDependencyManifest(
            allocator,
            store,
            self.dependency_stage_manifest_ref,
            self.ordered_inputs[0].blob,
        );
    }
};

/// Provider contract:
///
/// - `available: bool`;
/// - `AuthorityV4 == Backend.AuthorityV4`;
/// - `authorityForCampaign(namespace) !*const AuthorityV4`;
/// - `stage102AdmissionForOutput(namespace, output_ref)
///      !*const Stage102ColdAdmissionV4`.
///
/// This deliberately remains external to FinalRemint: the seven Stage-101
/// input refs and Zig key objects are campaign inventory, not registry data.
pub fn OpenerFor(comptime Backend: type, comptime Provider: type) type {
    assertBackend(Backend);
    assertProvider(Provider, Backend.AuthorityV4);
    const Adapter = real_worker.Stage102For(Provider, Backend);

    return struct {
        pub const available = TRANSITIVE_Q193_GATE_GREEN and
            Adapter.available and Provider.available;
        pub const LeasePayload = Backend.LeasePayload;
        pub const AuthorityV4 = Backend.AuthorityV4;
        pub const Stage102AdapterV4 = Adapter;

        pub fn coldOpenNode(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            final_remint: *const FinalRemint,
            output_ref: artifact_store.BlobRefV1,
            artifact: *const campaign_artifact.Artifact,
        ) !LeasePayload {
            if (comptime !available)
                return error.CampaignRealLeafInventoryOpenerUnavailableV4;
            return coldOpenNodeValidated(
                false,
                allocator,
                store,
                final_remint,
                output_ref,
                artifact,
            );
        }

        /// Exact-body entrypoint for the genuine transitive q193 gate. This
        /// returns the production `LeasePayload` and executes every normal
        /// inventory, manifest, artifact, cold-verifier, and fold-projection
        /// check. It bypasses only the release boolean so the gate can produce
        /// the evidence which eventually lifts that boolean.
        pub fn coldOpenNodeForGenuineGate(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            final_remint: *const FinalRemint,
            output_ref: artifact_store.BlobRefV1,
            artifact: *const campaign_artifact.Artifact,
        ) !LeasePayload {
            return coldOpenNodeValidated(
                true,
                allocator,
                store,
                final_remint,
                output_ref,
                artifact,
            );
        }

        fn coldOpenNodeValidated(
            comptime genuine_gate: bool,
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            final_remint: *const FinalRemint,
            output_ref: artifact_store.BlobRefV1,
            artifact: *const campaign_artifact.Artifact,
        ) !LeasePayload {
            const namespace = final_remint.shape.campaign_namespace_sha256;
            const authority = try Provider.authorityForCampaign(namespace);
            if (authority.final_remint != final_remint)
                return error.CampaignRealLeafInventoryProviderMismatchV4;
            try Backend.validateAuthority(allocator, authority, namespace);
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
            const node_bytes = try campaign_artifact.encodeCanonical(
                final_remint.shape,
                artifact,
            );
            if (comptime genuine_gate) {
                try Adapter.validateOutputForGenuineGate(
                    allocator,
                    &node_bytes,
                    admission.node.*,
                    admission.semantic.*,
                    admission.ordered_inputs[0..],
                );
            } else {
                try Adapter.validateOutput(
                    allocator,
                    &node_bytes,
                    admission.node.*,
                    admission.semantic.*,
                    admission.ordered_inputs[0..],
                );
            }
            var result = if (comptime genuine_gate)
                try Adapter.coldOpenLeaseForGenuineGate(
                    allocator,
                    store,
                    &node_bytes,
                    admission.node.*,
                    admission.semantic.*,
                    admission.ordered_inputs[0..],
                )
            else
                try Adapter.coldOpenLease(
                    allocator,
                    store,
                    &node_bytes,
                    admission.node.*,
                    admission.semantic.*,
                    admission.ordered_inputs[0..],
                );
            errdefer Backend.deinitLeasePayload(&result);
            try Backend.validateLease(
                allocator,
                &result,
                authority,
                admission.node.local_task_identity_sha256,
                admission.ordered_inputs[0].blob,
                artifact,
            );
            const projection = try result.campaignFoldProjection(
                final_remint,
            );
            try projection.validateAgainstFinal(final_remint);
            return result;
        }
    };
}

fn validateDependencyManifest(
    allocator: std.mem.Allocator,
    store: *artifact_store.Store,
    manifest_ref: artifact_store.BlobRefV1,
    expected_output: artifact_store.BlobRefV1,
) !void {
    const bytes = try storage.readSmallRefAlloc(
        allocator,
        store,
        manifest_ref,
        MAXIMUM_MANIFEST_BYTES,
    );
    defer store.allocator.free(bytes);
    var owned = try artifact_store.decodeStageManifestAlloc(
        allocator,
        bytes,
    );
    defer owned.deinit(allocator);
    const fields = owned.value.fields;
    if (!std.mem.eql(
        u8,
        &owned.value.identity,
        &manifest_ref.sha256,
    ) or fields.stage_kind != .prove or
        fields.stage_schema_version != native_worker.STAGE_SCHEMA_VERSION or
        fields.phase != .published or fields.status != .complete or
        fields.ordered_outputs.len != 1 or
        !artifact_store.BlobRefV1.eql(
            fields.ordered_outputs[0],
            expected_output,
        )) return error.CampaignRealLeafInventoryManifestMismatchV4;
}

fn assertBackend(comptime Backend: type) void {
    inline for (.{
        "available",
        "AuthorityV4",
        "LeasePayload",
        "validateAuthority",
        "coldOpenOwned",
        "validateLease",
        "deinitLeasePayload",
    }) |name| if (!@hasDecl(Backend, name))
        @compileError("campaign role-0 inventory backend missing " ++ name);
    if (!@hasDecl(Backend.LeasePayload, "campaignFoldProjection"))
        @compileError("campaign role-0 inventory lease is not fold-capable");
    rejectCodec(Backend.LeasePayload);
}

fn assertProvider(comptime Provider: type, comptime Authority: type) void {
    inline for (.{
        "available",
        "AuthorityV4",
        "authorityForCampaign",
        "stage102AdmissionForOutput",
    }) |name| if (!@hasDecl(Provider, name))
        @compileError("campaign role-0 inventory provider missing " ++ name);
    if (Provider.AuthorityV4 != Authority)
        @compileError("campaign role-0 inventory provider authority mismatch");
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign role-0 live inventory gained a codec");
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        STAGE102_DEPENDENCY_COUNT != 1 or
        MAXIMUM_MANIFEST_BYTES != 16 * 1024 * 1024 or
        TRANSITIVE_Q193_GATE_GREEN or PRODUCTION_ACTIVATION or
        ROUTER_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        !MANIFEST_CLOSURE_REQUIRED or !ZIG_KEYS_REQUIRED)
    {
        @compileError("campaign role-0 inventory opener contract drifted");
    }
}

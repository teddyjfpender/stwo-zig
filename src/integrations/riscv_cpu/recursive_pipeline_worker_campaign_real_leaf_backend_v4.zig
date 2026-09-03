//! Genuine Stage-102 backend over the role-0 universal q193 proof.
//!
//! Build borrows the worker's Stage-101 lease only for validation. It then
//! reopens the authenticated campaign row and Stage-101 proof from CAS into a
//! distinct fresh owner, because a failed outer build must consume neither
//! dependency lease. Cold-open repeats that transaction before verifying the
//! nested role-0 proof. ExecutionKey CPU/RSS policy is checked before work;
//! only the validated worker count reaches materialization and proving.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const authority_mod =
    @import("recursive_pipeline_worker_campaign_real_leaf_authority_v4.zig");
const native_worker = @import("recursive_pipeline_worker_native_leaf_v4.zig");
const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const role0_proof =
    @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4.zig");
const fold_child =
    @import("recursive_common_ethereum_incremental_leaf_campaign_fold_child_v4.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const execution_policy =
    @import("recursive_pipeline_worker_execution_policy_v2.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const CRYPTO_IMPLEMENTED = true;
pub const GENUINE_FINAL_PARITY_GATE_GREEN = false;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const BUILD_BORROWS_DEPENDENCY = true;
pub const BUILD_FAILURE_RETAINS_DEPENDENCY = true;
pub const COLD_OPEN_REPLAYS_STAGE101 = true;

pub const Error = error{
    CampaignRealLeafBackendMismatchV4,
    CampaignRealLeafExecutionAuthorityUnavailableV4,
    CampaignRealLeafExecutionAuthorityMismatchV4,
    CampaignRealLeafProofReferenceMismatchV4,
};

pub fn BackendFor(
    comptime Engine: type,
    comptime ActiveSources: type,
    comptime PolicyProvider: type,
) type {
    assertPolicyProvider(PolicyProvider);
    const Authority = authority_mod.CampaignAuthorityV4(ActiveSources);
    const NativeAdapter = native_worker.AdapterForEngine(Engine);
    const NativeLease = NativeAdapter.LeasePayload;
    const Materialized =
        campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine);
    const Proof = role0_proof.Types(Engine);
    const Lease = fold_child.Types(Engine).OwnedLeaseV4;

    return struct {
        pub const available = GENUINE_FINAL_PARITY_GATE_GREEN and
            PolicyProvider.available;
        pub const AuthorityV4 = Authority;
        pub const NativeLeasePayload = NativeLease;
        pub const LeasePayload = Lease;

        pub const ProvedV4 = struct {
            lease: Lease,

            pub fn deinit(self: *ProvedV4) void {
                self.lease.deinit();
                self.* = undefined;
            }

            pub fn validate(
                self: *const ProvedV4,
                allocator: std.mem.Allocator,
                authority: *const Authority,
                wrapper_task_identity: artifact_store.Digest,
                stage101_proof_ref: artifact_store.BlobRefV1,
            ) !void {
                try authority.validate(
                    allocator,
                    authority.final_remint.shape.campaign_namespace_sha256,
                );
                _ = try authority.admissionForWrapperTask(
                    allocator,
                    authority.final_remint.shape.campaign_namespace_sha256,
                    wrapper_task_identity,
                );
                try self.lease.validateForCampaign(authority.final_remint);
                const artifact = self.lease.nodeArtifact();
                const child = try node_store.toSharedRef(
                    artifact.ordered_children[0],
                );
                if (!artifact_store.BlobRefV1.eql(
                    child,
                    stage101_proof_ref,
                ) or self.lease.proofBytes().len == 0) {
                    return error.CampaignRealLeafBackendMismatchV4;
                }
            }

            pub fn proofBytes(self: *const ProvedV4) []const u8 {
                return self.lease.proofBytes();
            }

            pub fn nodeArtifact(self: *const ProvedV4) *const campaign_artifact.Artifact {
                return self.lease.nodeArtifact();
            }
        };

        pub fn validateAuthority(
            allocator: std.mem.Allocator,
            authority: *const Authority,
            campaign_namespace_sha256: artifact_store.Digest,
        ) !void {
            try authority.validate(allocator, campaign_namespace_sha256);
        }

        pub fn validateBorrowedDependency(
            allocator: std.mem.Allocator,
            authority: *const Authority,
            wrapper_task_identity: artifact_store.Digest,
            dependency: *const NativeLease,
        ) !usize {
            const selected = try authority.admissionForWrapperTask(
                allocator,
                authority.final_remint.shape.campaign_namespace_sha256,
                wrapper_task_identity,
            );
            try dependency.validate();
            try authority.campaign_geometry.validateFreshInputAt(
                Engine,
                allocator,
                selected.index,
                &dependency.fresh,
            );
            if (!std.mem.eql(
                u8,
                &dependency.semantic_key_identity,
                &selected.admission.semantic.identity,
            )) return error.CampaignRealLeafBackendMismatchV4;
            return selected.index;
        }

        pub fn executionPolicyForNode(
            allocator: std.mem.Allocator,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
        ) !execution_policy.PolicyV2 {
            try validateExecutionBinding(allocator, semantic, execution);
            const policy = try PolicyProvider.policyForExecution(execution);
            try policy.validateAgainstExecution(execution);
            if (node.cpu_tokens != @as(u64, policy.cpu_tokens_per_node) or
                node.rss_tokens != policy.rss_bytes_per_node)
            {
                return error.CampaignRealLeafExecutionAuthorityMismatchV4;
            }
            return policy;
        }

        pub fn proveAndColdVerify(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            authority: *const Authority,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            _: u64,
            dependency: *const NativeLease,
        ) !ProvedV4 {
            const policy = try executionPolicyForNode(
                allocator,
                node,
                semantic,
                execution,
            );
            const index = try validateBorrowedDependency(
                allocator,
                authority,
                node.local_task_identity_sha256,
                dependency,
            );
            var opened = try independentlyColdOpenStage101(
                allocator,
                store,
                authority,
                index,
                ordered_inputs[0].blob,
            );
            var opened_owned = true;
            defer if (opened_owned) opened.deinit();
            const materialized = try allocator.create(Materialized);
            var materialized_initialized = false;
            errdefer {
                if (materialized_initialized) materialized.deinit();
                allocator.destroy(materialized);
            }
            materialized.* = try Materialized.initOwnedMeasuredWithExecution(
                allocator,
                &opened.fresh,
                authority.campaign_geometry,
                index,
                .{ .worker_count = try policy.engineWorkerCount() },
                null,
            );
            // Materialized moved the sole allocation-owning field.
            opened_owned = false;
            materialized_initialized = true;
            var proved = try Proof.proveAndColdVerifyPreFinal(
                allocator,
                authority.padding_target,
                authority.active_sources.*,
                materialized,
                .{ .worker_count = try policy.engineWorkerCount() },
            );
            var proved_owned = true;
            defer if (proved_owned) proved.deinit();
            var cold = proved.proof;
            proved.proof = undefined;
            proved_owned = false;
            cold_ownedByLease(&materialized_initialized);
            var lease = Lease.initOwned(
                allocator,
                authority.padding_target,
                authority.final_remint,
                materialized,
                cold,
            ) catch |err| return err;
            cold = undefined;
            errdefer lease.deinit();
            const result = ProvedV4{ .lease = lease };
            try result.lease.validateForCampaign(authority.final_remint);
            return result;
        }

        pub fn coldOpenOwned(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            authority: *const Authority,
            node: protocol.Node,
            ordered_inputs: []const artifact_store.InputRefV1,
            proof_bytes: []const u8,
            node_bytes: []const u8,
        ) !Lease {
            const selected = try authority.admissionForWrapperTask(
                allocator,
                authority.final_remint.shape.campaign_namespace_sha256,
                node.local_task_identity_sha256,
            );
            const expected_node = try campaign_artifact.decodeCanonical(
                authority.final_remint.shape,
                node_bytes,
            );
            var opened = try independentlyColdOpenStage101(
                allocator,
                store,
                authority,
                selected.index,
                ordered_inputs[0].blob,
            );
            var opened_owned = true;
            defer if (opened_owned) opened.deinit();
            const materialized = try allocator.create(Materialized);
            var materialized_initialized = false;
            errdefer {
                if (materialized_initialized) materialized.deinit();
                allocator.destroy(materialized);
            }
            materialized.* = try Materialized.initOwned(
                allocator,
                &opened.fresh,
                authority.campaign_geometry,
                selected.index,
            );
            opened_owned = false;
            materialized_initialized = true;
            var cold = try Proof.coldOpenPreFinal(
                allocator,
                authority.padding_target,
                authority.active_sources.*,
                materialized,
                proof_bytes,
            );
            var cold_owned = true;
            defer if (cold_owned) cold.deinit();
            const moved = cold;
            cold = undefined;
            cold_owned = false;
            cold_ownedByLease(&materialized_initialized);
            var result = Lease.initOwned(
                allocator,
                authority.padding_target,
                authority.final_remint,
                materialized,
                moved,
            ) catch |err| return err;
            errdefer result.deinit();
            if (!std.meta.eql(result.node_artifact, expected_node))
                return error.CampaignRealLeafBackendMismatchV4;
            return result;
        }

        pub fn validateLease(
            allocator: std.mem.Allocator,
            value: *const Lease,
            authority: *const Authority,
            wrapper_task_identity: artifact_store.Digest,
            stage101_proof_ref: artifact_store.BlobRefV1,
            artifact: *const campaign_artifact.Artifact,
        ) !void {
            _ = try authority.admissionForWrapperTask(
                allocator,
                authority.final_remint.shape.campaign_namespace_sha256,
                wrapper_task_identity,
            );
            try value.validateForCampaign(authority.final_remint);
            const child = try node_store.toSharedRef(
                artifact.ordered_children[0],
            );
            if (!std.meta.eql(value.node_artifact, artifact.*) or
                !artifact_store.BlobRefV1.eql(child, stage101_proof_ref))
            {
                return error.CampaignRealLeafBackendMismatchV4;
            }
        }

        pub fn deinitLeasePayload(value: *Lease) void {
            value.deinit();
        }

        fn independentlyColdOpenStage101(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            authority: *const Authority,
            index: usize,
            proof_ref: artifact_store.BlobRefV1,
        ) !NativeLease {
            if (index >= authority.table.records.len)
                return error.CampaignRealLeafBackendMismatchV4;
            try validateStage101ProofRef(proof_ref);
            const admission = authority.stage101_admissions[index];
            const row = authority.table.records[index];
            var proof = try store.openBlob(
                proof_ref,
                .proof_artifact,
                native_worker.OUTPUT_SCHEMA_VERSION,
                @intCast(native_worker.MAXIMUM_OUTPUT_BYTES),
            );
            defer proof.deinit(store.allocator);
            return NativeAdapter.coldOpenLease(
                allocator,
                store,
                proof.bytes,
                admission.node,
                admission.semantic.*,
                &row.stage_inputs,
            );
        }
    };
}

fn validateExecutionBinding(
    allocator: std.mem.Allocator,
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
) !void {
    try semantic.validate(allocator);
    try execution.validate();
    if (!std.mem.eql(
        u8,
        &execution.fields.semantic_key_identity,
        &semantic.identity,
    )) return error.CampaignRealLeafExecutionAuthorityMismatchV4;
}

fn validateStage101ProofRef(ref: artifact_store.BlobRefV1) !void {
    try ref.validate();
    if (ref.kind != .proof_artifact or ref.schema_version != 1 or
        ref.byte_count == 0)
    {
        return error.CampaignRealLeafProofReferenceMismatchV4;
    }
}

fn cold_ownedByLease(materialized_initialized: *bool) void {
    // `OwnedLeaseV4.initOwned` assumes cleanup responsibility even when its
    // validation fails. Disable the caller's cleanup before crossing it.
    materialized_initialized.* = false;
}

fn assertPolicyProvider(comptime Provider: type) void {
    inline for (.{ "available", "policyForExecution" }) |name| {
        if (!@hasDecl(Provider, name))
            @compileError("campaign Stage102 execution policy missing " ++ name);
    }
}

pub const UnavailableExecutionPolicyProviderV4 = struct {
    pub const available = false;

    pub fn policyForExecution(
        _: artifact_store.ExecutionKeyV1,
    ) error{CampaignRealLeafExecutionAuthorityUnavailableV4}!execution_policy.PolicyV2 {
        return error.CampaignRealLeafExecutionAuthorityUnavailableV4;
    }
};

pub const testing = struct {
    pub const validateExecutionBindingV4 = validateExecutionBinding;
};

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        !CRYPTO_IMPLEMENTED or GENUINE_FINAL_PARITY_GATE_GREEN or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or !BUILD_BORROWS_DEPENDENCY or
        !BUILD_FAILURE_RETAINS_DEPENDENCY or !COLD_OPEN_REPLAYS_STAGE101)
    {
        @compileError("campaign Stage102 real-leaf backend drifted");
    }
}

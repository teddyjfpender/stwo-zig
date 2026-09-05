//! Concrete campaign-native Stage103 q193 backend.
//!
//! The router remains disabled. When an outer campaign supplies one validated
//! FinalRemint, the backend proves or cold-opens the 1,892-byte source, owns
//! the verifier capture, and returns a nonserializable role-1 fold lease.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const consumers = @import("recursive_pipeline_worker_campaign_consumers_v2.zig");
const source_mod =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const proof_mod =
    @import("recursive_common_canonical_empty_campaign_universal_proof_v2.zig");
const fold_child =
    @import("recursive_common_canonical_empty_campaign_fold_child_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const execution_policy =
    @import("recursive_pipeline_worker_execution_policy_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const CRYPTO_IMPLEMENTED = true;
pub const Q193_GENUINE_GATE_GREEN = false;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Backend = BackendForExecutionPolicy(
    UnavailableExecutionPolicyProvider,
);

pub fn BackendForExecutionPolicy(comptime PolicyProvider: type) type {
    if (!@hasDecl(PolicyProvider, "available") or
        !@hasDecl(PolicyProvider, "policyForExecution"))
    {
        @compileError("campaign Stage103 execution policy provider incomplete");
    }
    return struct {
        pub const available = Q193_GENUINE_GATE_GREEN and PolicyProvider.available;
        pub const LeasePayload = fold_child.OwnedLeaseV2;

        pub const ProvedV2 = struct {
            allocator: std.mem.Allocator,
            lease: LeasePayload,
            proof_bytes: []u8,

            pub fn deinit(self: *ProvedV2) void {
                self.allocator.free(self.proof_bytes);
                self.lease.deinit();
                self.* = undefined;
            }

            pub fn validate(
                self: *const ProvedV2,
                authorities: consumers.AuthoritiesV2,
                source: *const source_mod.ColdInputV2,
            ) !void {
                try authorities.validate(.canonical_empty_field_v2);
                try self.lease.validateForCampaign(authorities.final_remint);
                if (!std.meta.eql(
                    self.lease.evidence.cold.source_input,
                    source.*,
                ) or self.proof_bytes.len == 0) {
                    return error.CampaignWorkerOutputMismatch;
                }
                const encoded = try self.lease.evidence.cold.encodeArtifactAlloc(
                    self.allocator,
                );
                defer self.allocator.free(encoded);
                if (!std.mem.eql(u8, encoded, self.proof_bytes))
                    return error.CampaignWorkerOutputMismatch;
            }

            pub fn proofBytes(self: *const ProvedV2) []const u8 {
                return self.proof_bytes;
            }

            pub fn nodeArtifact(
                self: *const ProvedV2,
            ) *const campaign_artifact.Artifact {
                return self.lease.evidence.artifact();
            }
        };

        pub fn proveAndColdVerify(
            allocator: std.mem.Allocator,
            _: *artifact_store.Store,
            authorities: consumers.AuthoritiesV2,
            source: *const source_mod.ColdInputV2,
            _: protocol.Node,
            _: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            _: []const artifact_store.InputRefV1,
            _: u64,
        ) !ProvedV2 {
            try authorities.validate(.canonical_empty_field_v2);
            const policy = try PolicyProvider.policyForExecution(execution);
            try policy.validateAgainstExecution(execution);
            const source_bytes = try source.source.encodeCanonical(&source.shape);
            var proved = try proof_mod.proveAndColdVerify(
                allocator,
                authorities.final_remint,
                &source_bytes,
                .{ .worker_count = try policy.engineWorkerCount() },
            );
            var proved_owned = true;
            defer if (proved_owned) proved.deinit();
            const proof_bytes = try proved.proof.encodeArtifactAlloc(allocator);
            errdefer allocator.free(proof_bytes);
            var cold = proved.proof;
            proved.proof = undefined;
            proved_owned = false;
            var lease = try fold_child.OwnedLeaseV2.initOwned(
                authorities.final_remint,
                cold,
            );
            cold = undefined;
            errdefer lease.deinit();
            var result = ProvedV2{
                .allocator = allocator,
                .lease = lease,
                .proof_bytes = proof_bytes,
            };
            try result.validate(authorities, source);
            return result;
        }

        pub fn coldOpenOwned(
            allocator: std.mem.Allocator,
            _: *artifact_store.Store,
            authorities: consumers.AuthoritiesV2,
            source: *const source_mod.ColdInputV2,
            proof_bytes: []const u8,
            node_bytes: []const u8,
        ) !LeasePayload {
            try authorities.validate(.canonical_empty_field_v2);
            const source_bytes = try source.source.encodeCanonical(&source.shape);
            const expected_node = try campaign_artifact.decodeCanonical(
                authorities.shape,
                node_bytes,
            );
            var cold = try proof_mod.coldOpen(
                allocator,
                authorities.final_remint,
                &source_bytes,
                proof_bytes,
            );
            var cold_owned = true;
            defer if (cold_owned) cold.deinit();
            const moved = cold;
            cold = undefined;
            cold_owned = false;
            var result = try fold_child.OwnedLeaseV2.initOwned(
                authorities.final_remint,
                moved,
            );
            errdefer result.deinit();
            if (!std.meta.eql(result.evidence.node_artifact, expected_node))
                return error.CampaignWorkerOutputMismatch;
            try validateLease(&result, authorities, source, &expected_node);
            return result;
        }

        pub fn validateLease(
            value: *const LeasePayload,
            authorities: consumers.AuthoritiesV2,
            source: *const source_mod.ColdInputV2,
            artifact: *const campaign_artifact.Artifact,
        ) !void {
            try authorities.validate(.canonical_empty_field_v2);
            try value.validateForCampaign(authorities.final_remint);
            if (!std.meta.eql(value.evidence.cold.source_input, source.*) or
                !std.meta.eql(value.evidence.node_artifact, artifact.*))
            {
                return error.CampaignWorkerOutputMismatch;
            }
        }

        pub fn deinitLeasePayload(value: *LeasePayload) void {
            value.deinit();
        }
    };
}

const UnavailableExecutionPolicyProvider = struct {
    pub const available = false;

    pub fn policyForExecution(
        _: artifact_store.ExecutionKeyV1,
    ) error{CampaignWorkerExecutionAuthorityUnavailable}!execution_policy.PolicyV2 {
        return error.CampaignWorkerExecutionAuthorityUnavailable;
    }
};

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        !CRYPTO_IMPLEMENTED or Q193_GENUINE_GATE_GREEN or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("campaign canonical-empty worker backend drifted");
    }
}

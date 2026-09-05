//! ExecutionKey-aware backend owner for campaign-native Stage104.
//!
//! The generic campaign consumer owns CAS publication and StageManifest
//! sealing. This boundary owns only the cryptographic transaction and its
//! process-local lease: it validates two borrowed typed children, forwards
//! the sealed runtime worker policy to the q193 proof family, and requires an
//! independent cold open for every new-process lease. No proof bytes, graph,
//! query authority, or lease handle are copied into this module's authority.
//!
//! The default production route remains absent. A concrete `ProofFamily`
//! becomes available only after its role-2 proof supports every nominal child
//! pairing under one runtime campaign FinalRemint; the initial real+empty
//! geometry bootstrap is deliberately insufficient.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const consumers = @import("recursive_pipeline_worker_campaign_consumers_v2.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const STAGE_SCHEMA_VERSION: u16 = consumers.STAGE104_SCHEMA_VERSION;
pub const OUTPUT_SCHEMA_VERSION: u16 = consumers.OUTPUT_SCHEMA_VERSION;
pub const Q193_GENUINE_GATE_GREEN = false;
pub const ALL_NOMINAL_CHILD_PAIRS_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const BUILD_BORROWS_CHILD_LEASES = true;
pub const COLD_OPEN_REMINTS_FRESH_LEASE = true;

pub const Error = error{
    CampaignCommonFoldBackendUnavailable,
    CampaignCommonFoldDependencyMismatch,
    CampaignCommonFoldExecutionPolicyMismatch,
};

/// Cryptographic proof-family contract:
///
/// - `available` and `q193_genuine_gate_green` are explicit booleans;
/// - `LeasePayload` is a role-2 cold owner with no codec;
/// - `ProvedV2` owns proof bytes and the live output lease;
/// - build receives two borrowed dependency leases and a validated runtime
///   worker count;
/// - cold open owns only its newly reconstructed output lease and performs a
///   new q193/PCS verification inside the proof family.
///
/// The family, not this adapter, constructs the campaign NodeArtifact and
/// verifies each child artifact ref against the ordered inputs.
pub fn BackendForProofFamily(
    comptime ProofFamily: type,
    comptime DependencyLeaseType: type,
    comptime ExecutionPolicyProvider: type,
) type {
    assertProofFamily(ProofFamily);
    assertDependencyLease(DependencyLeaseType);
    assertExecutionPolicyProvider(ExecutionPolicyProvider);

    return struct {
        pub const available = ProofFamily.available and
            ProofFamily.q193_genuine_gate_green and
            ExecutionPolicyProvider.available and
            Q193_GENUINE_GATE_GREEN and
            ALL_NOMINAL_CHILD_PAIRS_AVAILABLE;
        pub const DependencyLease = DependencyLeaseType;
        pub const LeasePayload = ProofFamily.LeasePayload;
        pub const ProvedV2 = ProofFamily.ProvedV2;

        pub fn validateBorrowedChildren(
            dependency_leases: []const *const DependencyLease,
            authorities: consumers.AuthoritiesV2,
            ordered_inputs: []const artifact_store.InputRefV1,
        ) !void {
            try authorities.validate(.common_fold_field_v2);
            if (dependency_leases.len != consumers.STAGE104_DEPENDENCY_COUNT or
                ordered_inputs.len != consumers.STAGE104_DEPENDENCY_COUNT)
            {
                return error.CampaignCommonFoldDependencyMismatch;
            }
            for (dependency_leases) |lease| {
                try lease.validateAgainst(authorities.final_remint);
                _ = try lease.foldProjection(authorities.final_remint);
            }
            try ProofFamily.validateBorrowedChildren(
                dependency_leases,
                authorities,
                ordered_inputs,
            );
        }

        pub fn proveAndColdVerify(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            authorities: consumers.AuthoritiesV2,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            execution: artifact_store.ExecutionKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            candidate_ordinal: u64,
            dependency_leases: []const *const DependencyLease,
        ) !ProvedV2 {
            if (comptime !available)
                return error.CampaignCommonFoldBackendUnavailable;
            try validateBorrowedChildren(
                dependency_leases,
                authorities,
                ordered_inputs,
            );
            const policy = try ExecutionPolicyProvider.policyForExecution(
                execution,
            );
            try policy.validateAgainstExecution(execution);
            const worker_count = try policy.engineWorkerCount();
            var result = try ProofFamily.proveAndColdVerify(
                allocator,
                store,
                authorities,
                node,
                semantic,
                ordered_inputs,
                candidate_ordinal,
                dependency_leases,
                worker_count,
            );
            errdefer result.deinit();
            try result.validate(authorities, dependency_leases);
            return result;
        }

        /// This method must not consult a durable receipt. `ProofFamily`
        /// canonically decodes the proof/node, independently verifies q193,
        /// rerecords its graph, and returns the sole owner of the new lease.
        pub fn coldOpenOwned(
            allocator: std.mem.Allocator,
            store: *artifact_store.Store,
            authorities: consumers.AuthoritiesV2,
            node: protocol.Node,
            semantic: artifact_store.SemanticKeyV1,
            ordered_inputs: []const artifact_store.InputRefV1,
            proof_bytes: []const u8,
            node_bytes: []const u8,
        ) !LeasePayload {
            if (comptime !available)
                return error.CampaignCommonFoldBackendUnavailable;
            try authorities.validate(.common_fold_field_v2);
            if (proof_bytes.len == 0 or
                node_bytes.len != campaign_artifact.ENCODED_BYTE_COUNT)
            {
                return error.CampaignCommonFoldDependencyMismatch;
            }
            var result = try ProofFamily.coldOpenOwned(
                allocator,
                store,
                authorities,
                node,
                semantic,
                ordered_inputs,
                proof_bytes,
                node_bytes,
            );
            errdefer ProofFamily.deinitLeasePayload(&result);
            const artifact = try campaign_artifact.decodeCanonical(
                authorities.shape,
                node_bytes,
            );
            try ProofFamily.validateLease(
                &result,
                authorities,
                &artifact,
            );
            try result.validateForCampaign(authorities.final_remint);
            return result;
        }

        pub fn validateLease(
            value: *const LeasePayload,
            authorities: consumers.AuthoritiesV2,
            artifact: *const campaign_artifact.Artifact,
        ) !void {
            try authorities.validate(.common_fold_field_v2);
            try value.validateForCampaign(authorities.final_remint);
            try ProofFamily.validateLease(value, authorities, artifact);
        }

        pub fn deinitLeasePayload(value: *LeasePayload) void {
            ProofFamily.deinitLeasePayload(value);
        }
    };
}

fn assertProofFamily(comptime ProofFamily: type) void {
    inline for (.{
        "available",
        "q193_genuine_gate_green",
        "LeasePayload",
        "ProvedV2",
        "validateBorrowedChildren",
        "proveAndColdVerify",
        "coldOpenOwned",
        "validateLease",
        "deinitLeasePayload",
    }) |name| if (!@hasDecl(ProofFamily, name))
        @compileError("campaign common-fold proof family missing " ++ name);
    if (ProofFamily.available and !ProofFamily.q193_genuine_gate_green)
        @compileError("campaign common-fold proof family advertises before q193 gate");
    assertOutputLease(ProofFamily.LeasePayload);
    inline for (.{ "deinit", "validate", "proofBytes", "nodeArtifact" }) |
        name,
    | if (!@hasDecl(ProofFamily.ProvedV2, name))
        @compileError("campaign common-fold prove result missing " ++ name);
}

fn assertDependencyLease(comptime Lease: type) void {
    inline for (.{ "validateAgainst", "foldProjection" }) |name|
        if (!@hasDecl(Lease, name))
            @compileError("campaign common-fold dependency lease missing " ++ name);
    rejectCodec(Lease);
}

fn assertOutputLease(comptime Lease: type) void {
    if (!@hasDecl(Lease, "ROLE") or
        Lease.ROLE != consumers.Role.common_fold_field_v2)
    {
        @compileError("campaign common-fold output lease has wrong role");
    }
    inline for (.{ "validateForCampaign", "foldProjection", "deinit" }) |name|
        if (!@hasDecl(Lease, name))
            @compileError("campaign common-fold output lease missing " ++ name);
    rejectCodec(Lease);
}

fn assertExecutionPolicyProvider(comptime Provider: type) void {
    inline for (.{ "available", "policyForExecution" }) |name|
        if (!@hasDecl(Provider, name))
            @compileError("campaign common-fold execution provider missing " ++ name);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign common-fold live authority gained a codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        STAGE_SCHEMA_VERSION != 104 or OUTPUT_SCHEMA_VERSION != 2 or
        Q193_GENUINE_GATE_GREEN or ALL_NOMINAL_CHILD_PAIRS_AVAILABLE or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or !BUILD_BORROWS_CHILD_LEASES or
        !COLD_OPEN_REMINTS_FRESH_LEASE or
        policy_mod.MAX_PROOF_WORKERS != 32)
    {
        @compileError("campaign common-fold backend owner drifted");
    }
}

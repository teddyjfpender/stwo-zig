//! Genuine non-circular three-role campaign padding transaction.
//!
//! A caller supplies three independently cold-derived active geometry owners,
//! one live role-0 campaign materialization, and its sibling campaign-empty
//! source.  This owner derives the common target, independently proves and
//! cold-opens role 0 and role 1 at that target, proves and cold-opens role 2
//! from those two typed pre-final children, and only then mints FinalRemint.
//! The returned owner is heap-stable because the cold capabilities retain
//! process-local pointers into the target, child leases, and live fold input.
//!
//! This module has no durable codec or worker route.  Its purpose is to make
//! the genuine 3 -> 4 (and any other authenticated runtime shape) gate a
//! single auditable transaction without promoting a bootstrap geometry.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const frontend = @import("stwo_riscv_frontend");

const role0_proof_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4.zig");
const role0_child_mod =
    @import("recursive_common_ethereum_incremental_leaf_campaign_prefinal_fold_child_v4.zig");
const role1_source_mod =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const role1_proof_mod =
    @import("recursive_common_canonical_empty_campaign_universal_proof_v2.zig");
const role1_child_mod =
    @import("recursive_common_canonical_empty_campaign_prefinal_fold_child_v2.zig");
const role2_live_mod =
    @import("recursive_common_fold_campaign_prefinal_live_v2.zig");
const role2_proof_mod =
    @import("recursive_common_fold_campaign_prefinal_proof_v2.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");
const finalized_mod =
    @import("recursive_pipeline_campaign_padding_transaction_v2.zig");
const final_authority_mod =
    @import("recursive_pipeline_campaign_final_remint_v2.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");

const recursion = frontend.recursion;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const BOOTSTRAP_GEOMETRY_ADMITTED = false;
pub const FINAL_REMINT_AFTER_THREE_COLD_PROOFS = true;

pub const Error = error{
    CampaignGenuineFinalRemintMismatch,
};

pub fn Types(
    comptime Engine: type,
    comptime dimensions: recursion.fixed_wire.Dimensions,
) type {
    dimensions.validate();
    const Role0Proof = role0_proof_mod.Types(Engine);
    const Role0Lease = role0_child_mod.Types(Engine).OwnedPreFinalLeaseV4;
    const Role1Lease = role1_child_mod.OwnedPreFinalLeaseV2;
    const Role2Live = role2_live_mod.Types(Role0Lease, Role1Lease);
    const Role2Proof = role2_proof_mod.Types(
        dimensions,
        Role0Lease,
        Role1Lease,
    );

    return struct {
        const SelfTypes = @This();

        pub const Role0ProofV4 = Role0Proof;
        pub const Role0PreFinalLeaseV4 = Role0Lease;
        pub const Role1PreFinalLeaseV2 = Role1Lease;
        pub const Role2LiveV2 = Role2Live;
        pub const Role2ProofV2 = Role2Proof;
        pub const MaterializedV4 = Role0Proof.CoreV4.MaterializedV4;
        pub const EmptySourceV2 = role1_source_mod.ColdInputV2;
        pub const CampaignShapeV2 = shape_mod.CampaignShapeAuthorityV2;

        pub const ReceiptsV2 = struct {
            role0: @import("recursive_temporal_secure_parent_native_engine_v1.zig").ReceiptV1,
            role1: @import("recursive_temporal_secure_parent_native_engine_v1.zig").ReceiptV1,
            role2: @import("recursive_temporal_secure_parent_native_engine_v1.zig").ReceiptV1,

            pub fn validate(self: *const ReceiptsV2, worker_count: usize) !void {
                const expected_worker_count = std.math.cast(
                    u32,
                    worker_count,
                ) orelse return error.CampaignGenuineFinalRemintMismatch;
                inline for (.{ self.role0, self.role1, self.role2 }) |receipt| {
                    try receipt.validate();
                    if (receipt.worker_count != expected_worker_count) {
                        return error.CampaignGenuineFinalRemintMismatch;
                    }
                }
            }
        };

        /// Heap-only owner. Moving its fields would invalidate verifier-owned
        /// child and target pointers, so construction returns `*Self`.
        pub const OwnedV2 = struct {
            allocator: std.mem.Allocator,
            target: target_mod.CampaignPaddingTargetV2,
            role0: Role0Lease,
            role1: Role1Lease,
            fold_input: Role2Live.FoldInputV2,
            fold_live: Role2Live.LiveV2,
            role2: Role2Proof.OwnedColdProofV2,
            finalized: finalized_mod.FinalizedCampaignV2,
            final_authority: final_authority_mod.CampaignFinalRemintAuthorityV2,
            receipts: ReceiptsV2,
            worker_count: usize,

            pub fn deinit(self: *OwnedV2) void {
                const allocator = self.allocator;
                self.role2.deinit();
                self.role1.deinit();
                self.role0.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }

            pub fn validate(self: *const OwnedV2, active_sources: anytype) !void {
                try self.target.validateAgainstActive(active_sources);
                try self.role0.validateForPaddingTarget(&self.target);
                try self.role1.validateForPaddingTarget(&self.target);
                try self.fold_input.validate();
                try self.fold_live.validate();
                try self.role2.validateForPaddingTarget(&self.target);
                const final_sources = self.finalSources();
                try self.finalized.validate(
                    &self.target,
                    active_sources,
                    final_sources,
                );
                const expected_authority = try self.finalized.authority(
                    &self.target,
                );
                if (!std.meta.eql(
                    self.final_authority,
                    expected_authority,
                ) or self.final_authority.shape != &self.target.shape or
                    self.final_authority.final_remint !=
                        &self.finalized.final_remint)
                {
                    return error.CampaignGenuineFinalRemintMismatch;
                }
                try self.receipts.validate(self.worker_count);
            }

            pub fn finalSources(self: *const OwnedV2) struct {
                *const Role0Proof.OwnedColdProofV4,
                *const role1_proof_mod.OwnedColdProofV2,
                *const Role2Proof.OwnedColdProofV2,
            } {
                return .{
                    &self.role0.cold,
                    &self.role1.cold,
                    &self.role2,
                };
            }

            pub fn authority(
                self: *const OwnedV2,
            ) *const final_authority_mod.CampaignFinalRemintAuthorityV2 {
                return &self.final_authority;
            }
        };

        pub fn proveAndFinalize(
            allocator: std.mem.Allocator,
            active_sources: anytype,
            shape: *const CampaignShapeV2,
            materialized: *const MaterializedV4,
            empty_source: *const EmptySourceV2,
            parent_coordinate: @import("recursive_campaign_node_public_v2.zig").TaskCoordinateV1,
            execution: artifact_store.ExecutionKeyV1,
            policy: *const policy_mod.PolicyV2,
        ) !*OwnedV2 {
            try policy.validateAgainstExecution(execution);
            const worker_count = try policy.engineWorkerCount();
            const owner = try allocator.create(OwnedV2);
            var role0_initialized = false;
            var role1_initialized = false;
            var role2_initialized = false;
            errdefer {
                if (role2_initialized) owner.role2.deinit();
                if (role1_initialized) owner.role1.deinit();
                if (role0_initialized) owner.role0.deinit();
                allocator.destroy(owner);
            }
            owner.allocator = allocator;
            try validateCampaignInputs(shape, materialized, empty_source);
            owner.target = try target_mod.CampaignPaddingTargetV2.derive(
                shape,
                active_sources,
            );

            var proved_role0 = try Role0Proof.proveAndColdVerifyPreFinal(
                allocator,
                &owner.target,
                active_sources,
                materialized,
                .{ .worker_count = worker_count },
            );
            var proved_role0_owned = true;
            defer if (proved_role0_owned) proved_role0.deinit();
            owner.receipts.role0 = proved_role0.receipt;
            const cold_role0 = proved_role0.proof;
            proved_role0.proof = undefined;
            proved_role0_owned = false;
            owner.role0 = try Role0Lease.initOwned(
                &owner.target,
                cold_role0,
            );
            role0_initialized = true;

            const empty_source_bytes = try empty_source.source.encodeCanonical(
                &empty_source.shape,
            );
            var proved_role1 = try role1_proof_mod.proveAndColdVerifyPreFinal(
                allocator,
                &owner.target,
                active_sources,
                &empty_source_bytes,
                .{ .worker_count = worker_count },
            );
            var proved_role1_owned = true;
            defer if (proved_role1_owned) proved_role1.deinit();
            owner.receipts.role1 = proved_role1.receipt;
            const cold_role1 = proved_role1.proof;
            proved_role1.proof = undefined;
            proved_role1_owned = false;
            owner.role1 = try Role1Lease.initOwned(
                &owner.target,
                cold_role1,
            );
            role1_initialized = true;

            owner.fold_input = try Role2Live.FoldInputV2.init(
                &owner.target,
                &owner.role0.cold.node_public,
                &owner.role1.cold.node_public,
                parent_coordinate,
            );
            owner.fold_live = try Role2Live.LiveV2.init(
                &owner.fold_input,
                .{
                    try Role2Live.FoldChild.fromReal(
                        &owner.target,
                        &owner.role0,
                    ),
                    try Role2Live.FoldChild.fromEmpty(
                        &owner.target,
                        &owner.role1,
                    ),
                },
            );
            var proved_role2 = try Role2Proof.proveAndColdVerify(
                allocator,
                &owner.target,
                &owner.fold_live,
                .{ .worker_count = worker_count },
            );
            var proved_role2_owned = true;
            defer if (proved_role2_owned) proved_role2.deinit();
            owner.receipts.role2 = proved_role2.receipt;
            owner.role2 = proved_role2.proof;
            proved_role2.proof = undefined;
            proved_role2_owned = false;
            role2_initialized = true;

            owner.worker_count = worker_count;
            const final_sources = owner.finalSources();
            owner.finalized = try finalized_mod.FinalizedCampaignV2.init(
                &owner.target,
                active_sources,
                final_sources,
            );
            owner.final_authority = try owner.finalized.authority(
                &owner.target,
            );
            try owner.validate(active_sources);
            return owner;
        }

        fn validateCampaignInputs(
            shape: *const CampaignShapeV2,
            materialized: *const MaterializedV4,
            empty_source: *const EmptySourceV2,
        ) !void {
            try shape.validate();
            try materialized.validate();
            const empty_source_bytes = try empty_source.source.encodeCanonical(
                &empty_source.shape,
            );
            try empty_source.validate(&empty_source_bytes);
            if (!std.meta.eql(empty_source.shape, shape.*) or
                materialized.campaign_authority.leaf_count !=
                    shape.real_leaf_count or
                !std.mem.eql(
                    u8,
                    &materialized.campaign_authority.campaign_inventory
                        .table_identity_sha256,
                    &shape.inventory_identity_sha256,
                ))
            {
                return error.CampaignGenuineFinalRemintMismatch;
            }
        }
    };
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or BOOTSTRAP_GEOMETRY_ADMITTED or
        !FINAL_REMINT_AFTER_THREE_COLD_PROOFS)
    {
        @compileError("genuine campaign final-remint transaction drifted");
    }
}

//! Final-remint-to-worker assembly for campaign Stages 102/103/104.
//!
//! The genuine pre-final transaction owns three independently cold-verified
//! role geometries and mints the sole FinalRemint. This process-local view
//! binds that owner to the exact external Stage-101/102 inventory authority,
//! then type-instantiates the role-0 inventory opener, campaign-native role-1
//! backend, and self-recursive role-2 backend. All routes remain disabled
//! until their genuine gates are independently frozen.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const genuine_final =
    @import("recursive_pipeline_campaign_genuine_final_remint_v2.zig");
const real_backend_mod =
    @import("recursive_pipeline_worker_campaign_real_leaf_backend_v4.zig");
const real_worker =
    @import("recursive_pipeline_worker_campaign_real_leaf_v4.zig");
const real_inventory_opener =
    @import("recursive_pipeline_worker_campaign_real_leaf_inventory_opener_v4.zig");
const role0_child =
    @import("recursive_common_ethereum_incremental_leaf_campaign_fold_child_v4.zig");
const role1_child =
    @import("recursive_common_canonical_empty_campaign_fold_child_v2.zig");
const role1_backend_mod =
    @import("recursive_pipeline_worker_campaign_canonical_empty_v2.zig");
const role2_proof_mod =
    @import("recursive_common_fold_campaign_final_proof_v2.zig");
const role2_backend_mod =
    @import("recursive_pipeline_worker_campaign_common_fold_v2.zig");
const child_opener_mod =
    @import("recursive_pipeline_worker_campaign_child_cold_opener_v2.zig");
const consumers =
    @import("recursive_pipeline_worker_campaign_consumers_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const registry_mod = @import("recursive_circuit_registry_v1.zig");

const recursion = frontend.recursion;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const GENUINE_FINAL_WORKER_GATE_GREEN = false;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const ALL_ROLES_SHARE_ONE_FINAL_REMINT = true;
pub const EXTERNAL_INVENTORY_IS_TRANSPORT_ONLY = true;

pub const Error = error{
    CampaignFinalWorkerAuthorityMismatch,
    CampaignFinalWorkerProviderUnavailable,
};

/// `Provider` is the process-local sealed inventory provider shared by the
/// role-0 transitive opener and the Stage103/104 consumers. It supplies both
/// `authorityForCampaign` and `finalRemintForCampaign`; this assembly requires
/// them to return the exact pointers owned by one genuine final transaction.
pub fn Types(
    comptime Engine: type,
    comptime dimensions: recursion.fixed_wire.Dimensions,
    comptime ActiveSources: type,
    comptime Provider: type,
    comptime PolicyProvider: type,
) type {
    dimensions.validate();
    assertPolicyProvider(PolicyProvider);

    const GenuineFinal = genuine_final.Types(Engine, dimensions);
    const Role0Backend = real_backend_mod.BackendFor(
        Engine,
        ActiveSources,
        PolicyProvider,
    );
    assertProvider(Provider, Role0Backend.AuthorityV4);
    const Role0Opener = real_inventory_opener.OpenerFor(
        Role0Backend,
        Provider,
    );
    const Role0Lease = role0_child.Types(Engine).OwnedLeaseV4;
    const Role1Lease = role1_child.OwnedLeaseV2;
    const ChildOpenerFactory = child_opener_mod.Factory(
        Role0Lease,
        Role0Opener,
    );
    const Role2 = role2_proof_mod.AllLevelTypes(
        dimensions,
        Role0Lease,
        Role1Lease,
        ChildOpenerFactory,
    );
    const Role1Backend = role1_backend_mod.BackendForExecutionPolicy(
        PolicyProvider,
    );
    const Role2Backend = role2_backend_mod.BackendForProofFamily(
        Role2.ProofFamily,
        Role2.DependencyLease,
        PolicyProvider,
    );
    const Stage102 = real_worker.Stage102For(Provider, Role0Backend);
    const Stage103 = consumers.Stage103For(Provider, Role1Backend);
    const Stage104 = consumers.Stage104For(Provider, Role2Backend);

    return struct {
        pub const available = GENUINE_FINAL_WORKER_GATE_GREEN and
            Stage102.available and Stage103.available and Stage104.available;
        pub const GenuineFinalV2 = GenuineFinal;
        pub const Role0BackendV4 = Role0Backend;
        pub const Role0InventoryOpenerV4 = Role0Opener;
        pub const Role1BackendV2 = Role1Backend;
        pub const Role2TypesV2 = Role2;
        pub const Role2BackendV2 = Role2Backend;
        pub const Stage102AdapterV4 = Stage102;
        pub const Stage103AdapterV2 = Stage103;
        pub const Stage104AdapterV2 = Stage104;

        /// Borrowed, validated assembly. It owns no verifier capability;
        /// `genuine` and `role0_authority` must outlive every worker lease.
        pub const ValidatedAssemblyV2 = struct {
            genuine: *const GenuineFinal.OwnedV2,
            role0_authority: *const Role0Backend.AuthorityV4,
            active_sources: *const ActiveSources,

            pub fn init(
                genuine: *const GenuineFinal.OwnedV2,
                role0_authority: *const Role0Backend.AuthorityV4,
                active_sources: *const ActiveSources,
            ) !ValidatedAssemblyV2 {
                const result = ValidatedAssemblyV2{
                    .genuine = genuine,
                    .role0_authority = role0_authority,
                    .active_sources = active_sources,
                };
                try result.validate();
                return result;
            }

            pub fn validate(self: *const ValidatedAssemblyV2) !void {
                if (comptime !Provider.available)
                    return error.CampaignFinalWorkerProviderUnavailable;
                try self.genuine.validate(self.active_sources.*);
                const authority = self.genuine.authority();
                const namespace = authority.shape.campaign_namespace_sha256;
                try self.role0_authority.validate(
                    self.genuine.allocator,
                    namespace,
                );
                const provided_role0 = try Provider.authorityForCampaign(
                    namespace,
                );
                const provided_final = try Provider.finalRemintForCampaign(
                    namespace,
                );
                if (self.role0_authority != provided_role0 or
                    self.role0_authority.final_remint != authority or
                    self.role0_authority.padding_target !=
                        &self.genuine.target or
                    self.role0_authority.active_sources !=
                        self.active_sources or provided_final != authority)
                {
                    return error.CampaignFinalWorkerAuthorityMismatch;
                }
                try authority.validateAgainstCampaign(namespace);
                for (std.enums.values(registry_mod.CircuitRoleV1)) |
                    role,
                | _ = try authority.geometryForRole(role);
            }

            pub fn finalRemint(
                self: *const ValidatedAssemblyV2,
            ) *const final_mod.CampaignFinalRemintAuthorityV2 {
                return self.genuine.authority();
            }
        };

        comptime {
            rejectCodec(ValidatedAssemblyV2);
            if (Role0Opener.LeasePayload != Role0Lease or
                Role2.ChildColdOpener.CommonLeaseV2 !=
                    Role2.CommonLeaseHandleV2 or
                Stage104.DependencyLease != Role2.DependencyLease or
                Stage104.LeasePayload != Role2.ProofFamily.LeasePayload)
            {
                @compileError("campaign final worker custody types drifted");
            }
        }
    };
}

fn assertProvider(comptime Provider: type, comptime Authority: type) void {
    inline for (.{
        "available",
        "AuthorityV4",
        "authorityForCampaign",
        "stage102AdmissionForOutput",
        "finalRemintForCampaign",
    }) |name| if (!@hasDecl(Provider, name))
        @compileError("campaign final worker provider missing " ++ name);
    if (Provider.AuthorityV4 != Authority)
        @compileError("campaign final worker provider authority mismatch");
}

fn assertPolicyProvider(comptime Provider: type) void {
    inline for (.{ "available", "policyForExecution" }) |name|
        if (!@hasDecl(Provider, name))
            @compileError("campaign final worker policy provider missing " ++ name);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("campaign final worker authority gained a codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        GENUINE_FINAL_WORKER_GATE_GREEN or PRODUCTION_ACTIVATION or
        ROUTER_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        !ALL_ROLES_SHARE_ONE_FINAL_REMINT or
        !EXTERNAL_INVENTORY_IS_TRANSPORT_ONLY or
        @intFromEnum(registry_mod.CircuitRoleV1
            .ethereum_incremental_leaf_wrapper_v4) != 0 or
        @intFromEnum(registry_mod.CircuitRoleV1
            .canonical_empty_field_v2) != 1 or
        @intFromEnum(registry_mod.CircuitRoleV1
            .common_fold_field_v2) != 2)
    {
        @compileError("campaign final worker transaction contract drifted");
    }
}

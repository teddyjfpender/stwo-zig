//! Borrowed bridge from a sealed Stage-102 lifecycle into final workers.
//!
//! This module owns neither side.  It proves that the immutable inventory
//! installed by the Stage-102 lifecycle is the exact provider/authority used
//! by `campaign_final_worker_transaction_v2.ValidatedAssemblyV2`. Only then
//! may a role-0 output be opened through the already-frozen inventory opener.
//! No ref, digest, registry entry, or durable receipt creates a live lease.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const EXACT_PROVIDER_TYPE_REQUIRED = true;
pub const EXACT_AUTHORITY_POINTER_REQUIRED = true;
pub const EXACT_FINAL_REMINT_POINTER_REQUIRED = true;

pub const Error = error{
    CampaignFinalSessionBridgeMismatchV4,
};

/// `Lifecycle` is one specialization returned by
/// `stage102_final_lifecycle_v4.SupervisorFor`. `FinalWorker` is one
/// specialization returned by `campaign_final_worker_transaction_v2.Types`.
/// The generic surface also permits small structural fixtures.
pub fn BridgeFor(
    comptime Lifecycle: type,
    comptime FinalWorker: type,
) type {
    assertLifecycle(Lifecycle);
    assertFinalWorker(FinalWorker);
    if (Lifecycle.AuthorityV4 != FinalWorker.Role0BackendV4.AuthorityV4)
        @compileError("final session bridge role-0 authority type mismatch");
    if (Lifecycle.Role0OpenerV4 != FinalWorker.Role0InventoryOpenerV4)
        @compileError("final session bridge inventory opener/provider mismatch");
    if (Lifecycle.Role0LeaseV4 !=
        FinalWorker.Role0InventoryOpenerV4.LeasePayload)
    {
        @compileError("final session bridge role-0 lease type mismatch");
    }

    return struct {
        pub const LifecycleV4 = Lifecycle;
        pub const FinalWorkerV2 = FinalWorker;
        pub const PolicyV2 = Lifecycle.PolicyV2;
        pub const Role0FinalV4 = Lifecycle.BorrowedRole0FinalV4;

        lifecycle: *Lifecycle.OwnedFinalSessionV4,
        assembly: *const FinalWorker.ValidatedAssemblyV2,

        const Self = @This();

        pub fn init(
            lifecycle: *Lifecycle.OwnedFinalSessionV4,
            assembly: *const FinalWorker.ValidatedAssemblyV2,
            scratch_allocator: std.mem.Allocator,
        ) !Self {
            const result = Self{
                .lifecycle = lifecycle,
                .assembly = assembly,
            };
            try result.validate(scratch_allocator);
            return result;
        }

        pub fn validate(
            self: *const Self,
            scratch_allocator: std.mem.Allocator,
        ) !void {
            try self.lifecycle.validate(scratch_allocator);
            try self.assembly.validate();
            const session = try self.lifecycle.immutableSession();
            const final_remint = self.assembly.finalRemint();
            const namespace = final_remint.shape.campaign_namespace_sha256;
            const provider_authority = try Lifecycle.ReplayProviderV4
                .authorityForCampaign(namespace);
            const provider_final = try Lifecycle.ReplayProviderV4
                .finalRemintForCampaign(namespace);
            if (session.authority != self.assembly.role0_authority or
                session.authority != provider_authority or
                session.authority.final_remint != final_remint or
                provider_final != final_remint or
                session.authority.padding_target !=
                    self.assembly.role0_authority.padding_target or
                session.entries.len !=
                    @as(usize, @intCast(final_remint.shape.real_leaf_count)))
            {
                return error.CampaignFinalSessionBridgeMismatchV4;
            }
            try final_remint.validateAgainstCampaign(namespace);
        }

        /// Returns the lifecycle's exact borrowed role-0 view; the bridge
        /// adds no wrapper or cast. Its lease remains owned by `lifecycle`.
        pub fn role0ForOutput(
            self: *const Self,
            scratch_allocator: std.mem.Allocator,
            output_ref: artifact_store.BlobRefV1,
        ) !Role0FinalV4 {
            try self.validate(scratch_allocator);
            const session = try self.lifecycle.immutableSession();
            const result = try self.lifecycle.role0ForOutput(output_ref);
            try result.validate();
            const final_remint = self.assembly.finalRemint();
            const admission = try Lifecycle.ReplayProviderV4
                .stage102AdmissionForOutput(
                final_remint.shape.campaign_namespace_sha256,
                output_ref,
            );
            if (result.session != session or
                result.final_remint != final_remint or
                result.admission != admission or
                result.geometry != try final_remint.geometryForRole(
                    .ethereum_incremental_leaf_wrapper_v4,
                ))
            {
                return error.CampaignFinalSessionBridgeMismatchV4;
            }
            return result;
        }

        comptime {
            rejectCodec(Self);
        }
    };
}

fn assertLifecycle(comptime Lifecycle: type) void {
    inline for (.{
        "AuthorityV4",
        "ReplayProviderV4",
        "Role0OpenerV4",
        "Role0LeaseV4",
        "OwnedFinalSessionV4",
        "BorrowedRole0FinalV4",
    }) |name| if (!@hasDecl(Lifecycle, name))
        @compileError("final session bridge lifecycle missing " ++ name);
}

fn assertFinalWorker(comptime FinalWorker: type) void {
    inline for (.{
        "Role0BackendV4",
        "Role0InventoryOpenerV4",
        "ValidatedAssemblyV2",
    }) |name| if (!@hasDecl(FinalWorker, name))
        @compileError("final session bridge worker missing " ++ name);
    const Assembly = FinalWorker.ValidatedAssemblyV2;
    inline for (.{ "validate", "finalRemint" }) |name|
        if (!@hasDecl(Assembly, name))
            @compileError("final session bridge assembly missing " ++ name);
    if (!@hasField(Assembly, "role0_authority"))
        @compileError("final session bridge assembly missing role0 authority");
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("final session bridge gained a durable codec");
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        SERIALIZABLE_FRESH_CAPABILITY or !EXACT_PROVIDER_TYPE_REQUIRED or
        !EXACT_AUTHORITY_POINTER_REQUIRED or
        !EXACT_FINAL_REMINT_POINTER_REQUIRED)
    {
        @compileError("campaign final session bridge contract drifted");
    }
}

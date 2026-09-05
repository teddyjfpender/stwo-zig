//! Nonserializable typed lease union for campaign fold children.
//!
//! Each role-specific lease remains owned by its cold verifier. This union
//! borrows it, pins the exact process-local campaign/remint authority pointer,
//! reruns the role validator, and accepts a fold projection only against the
//! registry and role geometry supplied by that same final remint.

const std = @import("std");

const authority_mod =
    @import("recursive_pipeline_campaign_final_remint_v2.zig");
const neutral_projection =
    @import("recursive_pipeline_campaign_fold_projection_v2.zig");

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Authority = authority_mod.CampaignFinalRemintAuthorityV2;
pub const Registry = authority_mod.Registry;
pub const Geometry = authority_mod.Geometry;
pub const Role = authority_mod.Role;

pub const Error = authority_mod.Error || error{
    CampaignFoldLeaseAuthorityMismatch,
    CampaignFoldLeaseProjectionMismatch,
};

pub const CampaignFoldProjectionV2 = neutral_projection.ProjectionV2;

/// Production-shaped sibling for nominal leases which all export the same
/// role-neutral campaign projection. The legacy generic above remains intact
/// for structural fixtures with their own Projection type.
pub fn TypedCampaignUnifiedFoldLeaseV2(
    comptime RealLease: type,
    comptime EmptyLease: type,
    comptime CommonLease: type,
) type {
    assertUnifiedRoleLease(
        RealLease,
        .ethereum_incremental_leaf_wrapper_v4,
    );
    assertUnifiedRoleLease(EmptyLease, .canonical_empty_field_v2);
    assertUnifiedRoleLease(CommonLease, .common_fold_field_v2);

    return struct {
        const Self = @This();

        pub const PayloadV2 = union(Role) {
            ethereum_incremental_leaf_wrapper_v4: *const RealLease,
            canonical_empty_field_v2: *const EmptyLease,
            common_fold_field_v2: *const CommonLease,
        };

        authority: *const Authority,
        payload: PayloadV2,

        pub fn fromReal(
            authority: *const Authority,
            lease: *const RealLease,
        ) !Self {
            return init(authority, .{
                .ethereum_incremental_leaf_wrapper_v4 = lease,
            });
        }

        pub fn fromEmpty(
            authority: *const Authority,
            lease: *const EmptyLease,
        ) !Self {
            return init(authority, .{
                .canonical_empty_field_v2 = lease,
            });
        }

        pub fn fromCommon(
            authority: *const Authority,
            lease: *const CommonLease,
        ) !Self {
            return init(authority, .{
                .common_fold_field_v2 = lease,
            });
        }

        pub fn role(self: *const Self) Role {
            return std.meta.activeTag(self.payload);
        }

        pub fn validateAgainst(
            self: *const Self,
            authority: *const Authority,
        ) !void {
            _ = try self.foldProjection(authority);
        }

        pub fn foldProjection(
            self: *const Self,
            authority: *const Authority,
        ) !CampaignFoldProjectionV2 {
            if (self.authority != authority)
                return error.CampaignFoldLeaseAuthorityMismatch;
            try authority.validateAgainstCampaign(
                authority.shape.campaign_namespace_sha256,
            );
            const result = switch (self.payload) {
                .ethereum_incremental_leaf_wrapper_v4 => |lease| blk: {
                    try lease.validateForCampaign(authority);
                    break :blk try lease.campaignFoldProjection(authority);
                },
                .canonical_empty_field_v2 => |lease| blk: {
                    try lease.validateForCampaign(authority);
                    break :blk try lease.campaignFoldProjection(authority);
                },
                .common_fold_field_v2 => |lease| blk: {
                    try lease.validateForCampaign(authority);
                    break :blk try lease.campaignFoldProjection(authority);
                },
            };
            try result.validateAgainstFinal(authority);
            if (result.role != self.role() or result.authority != authority)
                return error.CampaignFoldLeaseProjectionMismatch;
            return result;
        }

        fn init(
            authority: *const Authority,
            payload: PayloadV2,
        ) !Self {
            const result = Self{ .authority = authority, .payload = payload };
            try result.validateAgainst(authority);
            return result;
        }
    };
}

/// Role lease contract:
/// - exact `ROLE: Role`;
/// - `validateForCampaign(*const Authority) !void`;
/// - `foldProjection(*const Registry) !Projection`.
///
/// Projection must expose `role`, `geometry: *const Geometry`, and
/// `validateAgainst(*const Registry) !void`.
pub fn TypedCampaignFoldLeaseV2(
    comptime Projection: type,
    comptime RealLease: type,
    comptime EmptyLease: type,
    comptime CommonLease: type,
) type {
    assertProjectionContract(Projection);
    assertRoleLeaseContract(
        RealLease,
        .ethereum_incremental_leaf_wrapper_v4,
    );
    assertRoleLeaseContract(EmptyLease, .canonical_empty_field_v2);
    assertRoleLeaseContract(CommonLease, .common_fold_field_v2);

    return struct {
        const Self = @This();

        pub const PayloadV2 = union(Role) {
            ethereum_incremental_leaf_wrapper_v4: *const RealLease,
            canonical_empty_field_v2: *const EmptyLease,
            common_fold_field_v2: *const CommonLease,
        };

        authority: *const Authority,
        payload: PayloadV2,

        pub fn fromReal(
            authority: *const Authority,
            lease: *const RealLease,
        ) !Self {
            return init(authority, .{
                .ethereum_incremental_leaf_wrapper_v4 = lease,
            });
        }

        pub fn fromEmpty(
            authority: *const Authority,
            lease: *const EmptyLease,
        ) !Self {
            return init(authority, .{
                .canonical_empty_field_v2 = lease,
            });
        }

        pub fn fromCommon(
            authority: *const Authority,
            lease: *const CommonLease,
        ) !Self {
            return init(authority, .{
                .common_fold_field_v2 = lease,
            });
        }

        pub fn role(self: *const Self) Role {
            return std.meta.activeTag(self.payload);
        }

        pub fn validateAgainst(
            self: *const Self,
            authority: *const Authority,
        ) !void {
            _ = try self.projectAgainst(authority);
        }

        pub fn foldProjection(
            self: *const Self,
            authority: *const Authority,
        ) !Projection {
            return self.projectAgainst(authority);
        }

        fn init(
            authority: *const Authority,
            payload: PayloadV2,
        ) !Self {
            const result = Self{
                .authority = authority,
                .payload = payload,
            };
            try result.validateAgainst(authority);
            return result;
        }

        fn projectAgainst(
            self: *const Self,
            authority: *const Authority,
        ) !Projection {
            if (self.authority != authority)
                return error.CampaignFoldLeaseAuthorityMismatch;
            try authority.validateAgainstCampaign(
                authority.shape.campaign_namespace_sha256,
            );
            const registry = try authority.registryAuthority();
            const projection = switch (self.payload) {
                .ethereum_incremental_leaf_wrapper_v4 => |lease| blk: {
                    try lease.validateForCampaign(authority);
                    break :blk try lease.foldProjection(registry);
                },
                .canonical_empty_field_v2 => |lease| blk: {
                    try lease.validateForCampaign(authority);
                    break :blk try lease.foldProjection(registry);
                },
                .common_fold_field_v2 => |lease| blk: {
                    try lease.validateForCampaign(authority);
                    break :blk try lease.foldProjection(registry);
                },
            };
            try projection.validateAgainst(registry);
            const active_role = self.role();
            const expected_geometry = try authority.geometryForRole(
                active_role,
            );
            if (projection.role != active_role or
                projection.geometry != expected_geometry)
            {
                return error.CampaignFoldLeaseProjectionMismatch;
            }
            return projection;
        }
    };
}

fn assertRoleLeaseContract(comptime Lease: type, comptime role: Role) void {
    if (!@hasDecl(Lease, "ROLE") or Lease.ROLE != role)
        @compileError("campaign fold lease has wrong role");
    inline for (.{ "validateForCampaign", "foldProjection" }) |name|
        if (!@hasDecl(Lease, name))
            @compileError("campaign fold lease missing " ++ name);
}

fn assertUnifiedRoleLease(comptime Lease: type, comptime role: Role) void {
    if (!@hasDecl(Lease, "ROLE") or Lease.ROLE != role)
        @compileError("unified campaign fold lease has wrong role");
    inline for (.{ "validateForCampaign", "campaignFoldProjection" }) |name|
        if (!@hasDecl(Lease, name))
            @compileError("unified campaign fold lease missing " ++ name);
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(Lease, name))
            @compileError("unified campaign fold lease gained a codec");
}

fn assertProjectionContract(comptime Projection: type) void {
    inline for (.{ "role", "geometry" }) |name| if (!@hasField(
        Projection,
        name,
    )) @compileError("campaign fold projection missing " ++ name);
    if (!@hasDecl(Projection, "validateAgainst"))
        @compileError("campaign fold projection missing validateAgainst");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("campaign fold lease contract drifted");
    }
}

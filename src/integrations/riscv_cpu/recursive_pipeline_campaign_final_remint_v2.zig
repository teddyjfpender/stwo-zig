//! Process-local campaign binding for the final padding-remint authority.
//!
//! A worker receives one retained value which binds the authenticated runtime
//! campaign shape to exactly one independently cold-derived final remint. The
//! registry and every role geometry are borrowed only through that remint;
//! callers cannot assemble them from unrelated providers. This capability has
//! no codec and is rebuilt after each process boundary.

const std = @import("std");

const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");
const remint_mod = @import("recursive_common_wrapper_padding_remint_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Shape = shape_mod.CampaignShapeAuthorityV2;
pub const FinalRemint = remint_mod.FinalRemintAuthorityV2;
pub const Registry = remint_mod.Registry;
pub const Geometry = remint_mod.Geometry;
pub const Role = remint_mod.Role;

const AUTHORITY_DOMAIN =
    "stwo-zig/recursive-pipeline-campaign-final-remint/v2\x00";

pub const Error = shape_mod.Error || remint_mod.Error || error{
    CampaignFinalRemintMismatch,
};

pub const CampaignFinalRemintAuthorityV2 = struct {
    shape: *const Shape,
    final_remint: *const FinalRemint,
    binding_identity_sha256: [32]u8,

    pub fn init(
        shape: *const Shape,
        final_remint: *const FinalRemint,
    ) !CampaignFinalRemintAuthorityV2 {
        try shape.validate();
        try final_remint.validateSelf();
        const result = CampaignFinalRemintAuthorityV2{
            .shape = shape,
            .final_remint = final_remint,
            .binding_identity_sha256 = bindingIdentity(shape, final_remint),
        };
        try result.validateAgainstCampaign(shape.campaign_namespace_sha256);
        return result;
    }

    pub fn validateAgainstCampaign(
        self: *const CampaignFinalRemintAuthorityV2,
        campaign_namespace_sha256: [32]u8,
    ) !void {
        try self.shape.validateAgainstCampaign(campaign_namespace_sha256);
        try self.final_remint.validateSelf();
        if (!std.mem.eql(
            u8,
            &self.binding_identity_sha256,
            &bindingIdentity(self.shape, self.final_remint),
        )) return error.CampaignFinalRemintMismatch;
    }

    pub fn registryAuthority(
        self: *const CampaignFinalRemintAuthorityV2,
    ) !*const Registry {
        try self.validateAgainstCampaign(
            self.shape.campaign_namespace_sha256,
        );
        return &self.final_remint.registry;
    }

    pub fn geometryForRole(
        self: *const CampaignFinalRemintAuthorityV2,
        role: Role,
    ) !*const Geometry {
        try self.validateAgainstCampaign(
            self.shape.campaign_namespace_sha256,
        );
        const ordinal = @intFromEnum(role);
        if (ordinal >= self.final_remint.final_geometries.len)
            return error.CampaignFinalRemintMismatch;
        const geometry = &self.final_remint.final_geometries[ordinal];
        if (geometry.role != role) return error.CampaignFinalRemintMismatch;
        const registry = &self.final_remint.registry;
        const entry = try registry.entry(role);
        const expected = try @import("recursive_circuit_registry_v1.zig")
            .RegistryEntryV1.fromGeometry(geometry);
        if (!std.meta.eql(entry.*, expected))
            return error.CampaignFinalRemintMismatch;
        return geometry;
    }
};

fn bindingIdentity(
    shape: *const Shape,
    final_remint: *const FinalRemint,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&shape.campaign_namespace_sha256);
    hash.update(&shape.inventory_identity_sha256);
    hash.update(&shape.identity_sha256);
    hash.update(&final_remint.identity_sha256);
    hash.update(&final_remint.registry.identity_sha256);
    hash.update(&final_remint.parity.identity_sha256);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        SERIALIZABLE_FRESH_CAPABILITY or
        @hasDecl(CampaignFinalRemintAuthorityV2, "encode") or
        @hasDecl(CampaignFinalRemintAuthorityV2, "decode"))
    {
        @compileError("campaign final-remint authority contract drifted");
    }
}

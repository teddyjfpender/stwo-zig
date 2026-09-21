//! Pre-final campaign padding target for independently reminted role proofs.
//!
//! This process-local value breaks the FinalRemint bootstrap cycle.  The
//! active constructor derives and revalidates one pointwise target from three
//! independently cold-owned role geometries.  Each role may then prove at
//! that target and publish its own cold-derived final geometry.  Only the
//! existing FinalRemint constructor may combine those three later outputs
//! into registry/parity authority.
//!
//! A post-final constructor exists solely for reopening already-published
//! proofs after FinalRemint has been minted.  Neither form is a verifier
//! capability and neither has a codec.

const std = @import("std");

const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");
const remint_mod = @import("recursive_common_wrapper_padding_remint_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

pub const Shape = shape_mod.CampaignShapeAuthorityV2;
pub const PaddingTarget = remint_mod.PaddingTargetV2;
pub const FinalAuthority = final_mod.CampaignFinalRemintAuthorityV2;
pub const Role = remint_mod.Role;

const AUTHORITY_DOMAIN =
    "stwo-zig/recursive-pipeline-campaign-padding-target/v2\x00";

pub const Error = shape_mod.Error || remint_mod.Error || final_mod.Error || error{
    CampaignPaddingTargetMismatch,
};

pub const CampaignPaddingTargetV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    shape: Shape,
    target: PaddingTarget,
    identity_sha256: [32]u8,

    /// The ordered tuple is exactly `(real, empty, common)` and each owner is
    /// revalidated by `PaddingTargetV2.derive` before this value is minted.
    pub fn derive(
        shape: *const Shape,
        active_sources: anytype,
    ) !CampaignPaddingTargetV2 {
        try shape.validate();
        const target = try PaddingTarget.derive(active_sources);
        var result = CampaignPaddingTargetV2{
            .shape = shape.*,
            .target = target,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = identity(&result);
        try result.validateAgainstActive(active_sources);
        return result;
    }

    /// Reconstructs the same pre-final selector after all final geometries
    /// have already been cold-derived and admitted. This does not authorize
    /// creation of the FinalRemint that it consumes.
    pub fn fromFinal(
        final_authority: *const FinalAuthority,
    ) !CampaignPaddingTargetV2 {
        try final_authority.validateAgainstCampaign(
            final_authority.shape.campaign_namespace_sha256,
        );
        var result = CampaignPaddingTargetV2{
            .shape = final_authority.shape.*,
            .target = final_authority.final_remint.target,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = identity(&result);
        try result.validateAgainstFinal(final_authority);
        return result;
    }

    pub fn validateAgainstActive(
        self: *const CampaignPaddingTargetV2,
        active_sources: anytype,
    ) !void {
        try self.validateSelf();
        try self.target.validateAgainst(active_sources);
    }

    pub fn validateAgainstFinal(
        self: *const CampaignPaddingTargetV2,
        final_authority: *const FinalAuthority,
    ) !void {
        try self.validateSelf();
        try final_authority.validateAgainstCampaign(
            self.shape.campaign_namespace_sha256,
        );
        if (!std.meta.eql(final_authority.shape.*, self.shape)) {
            return error.CampaignPaddingTargetMismatch;
        }
        if (!std.meta.eql(
            self.target,
            final_authority.final_remint.target,
        )) return error.CampaignPaddingTargetMismatch;
    }

    pub fn validateSelf(self: *const CampaignPaddingTargetV2) !void {
        try self.shape.validate();
        try self.target.validateSelf();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            !std.mem.eql(
                u8,
                &self.identity_sha256,
                &identity(self),
            )) return error.CampaignPaddingTargetMismatch;
    }

    pub fn activeLogsForRole(
        self: *const CampaignPaddingTargetV2,
        role: Role,
    ) !remint_mod.LogVectorV2 {
        try self.validateSelf();
        return self.target.active_component_log_sizes[@intFromEnum(role)];
    }

    pub fn paddedLogs(
        self: *const CampaignPaddingTargetV2,
    ) !remint_mod.LogVectorV2 {
        try self.validateSelf();
        return self.target.target_padded_log_sizes;
    }

    pub fn validateRemintedGeometry(
        self: *const CampaignPaddingTargetV2,
        role: Role,
        geometry: *const remint_mod.Geometry,
    ) !void {
        try self.validateSelf();
        try self.target.validateRemintedGeometry(role, geometry);
    }
};

fn identity(value: *const CampaignPaddingTargetV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hash.update(&value.reserved);
    hash.update(&value.shape.campaign_namespace_sha256);
    hash.update(&value.shape.inventory_identity_sha256);
    hash.update(&value.shape.identity_sha256);
    hash.update(&value.target.identity_sha256);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY or
        @hasDecl(CampaignPaddingTargetV2, "encode") or
        @hasDecl(CampaignPaddingTargetV2, "decode"))
    {
        @compileError("campaign pre-final padding target drifted");
    }
}

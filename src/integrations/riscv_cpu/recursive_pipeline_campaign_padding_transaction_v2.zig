//! Process-local pre-final padding transaction for one recursive campaign.
//!
//! The flow is intentionally non-circular:
//! 1. `CampaignPaddingTargetV2` authenticates three active cold geometries.
//! 2. Each role independently proves and cold-opens at that target.
//! 3. `init` revalidates the active owners and the three final cold owners,
//!    then mints the only `FinalRemintAuthorityV2` admitted by this campaign.
//!
//! This owner and every authority it returns are process-local.  No geometry,
//! validation token, registry, or freshness capability has a codec here.

const std = @import("std");

const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const remint_mod = @import("recursive_common_wrapper_padding_remint_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const FINAL_OWNER_TARGET_VALIDATION_REQUIRED = true;

const TRANSACTION_DOMAIN =
    "stwo-zig/recursive-pipeline-campaign-padding-transaction/v2\x00";

pub const Error = target_mod.Error || remint_mod.Error || final_mod.Error || error{
    CampaignPaddingTransactionMismatch,
};

pub const FinalizedCampaignV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    reserved: [3]u8 = .{ 0, 0, 0 },
    target_identity_sha256: [32]u8,
    shape_identity_sha256: [32]u8,
    final_remint: remint_mod.FinalRemintAuthorityV2,
    identity_sha256: [32]u8,

    pub fn init(
        target: *const target_mod.CampaignPaddingTargetV2,
        active_sources: anytype,
        final_sources: anytype,
    ) !FinalizedCampaignV2 {
        try target.validateAgainstActive(active_sources);
        try validateFinalOwnersForTarget(target, final_sources);
        const final_remint = try remint_mod.FinalRemintAuthorityV2.mint(
            &target.target,
            active_sources,
            final_sources,
        );
        var result = FinalizedCampaignV2{
            .target_identity_sha256 = target.identity_sha256,
            .shape_identity_sha256 = target.shape.identity_sha256,
            .final_remint = final_remint,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = identity(&result);
        try result.validate(target, active_sources, final_sources);
        return result;
    }

    pub fn validate(
        self: *const FinalizedCampaignV2,
        target: *const target_mod.CampaignPaddingTargetV2,
        active_sources: anytype,
        final_sources: anytype,
    ) !void {
        try self.validateSelf(target);
        try target.validateAgainstActive(active_sources);
        try validateFinalOwnersForTarget(target, final_sources);
        try self.final_remint.validateAgainst(active_sources, final_sources);
    }

    pub fn validateSelf(
        self: *const FinalizedCampaignV2,
        target: *const target_mod.CampaignPaddingTargetV2,
    ) !void {
        try target.validateSelf();
        try self.final_remint.validateSelf();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            !std.mem.eql(
                u8,
                &self.target_identity_sha256,
                &target.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.shape_identity_sha256,
            &target.shape.identity_sha256,
        ) or !std.meta.eql(self.final_remint.target, target.target) or
            !std.mem.eql(u8, &self.identity_sha256, &identity(self)))
        {
            return error.CampaignPaddingTransactionMismatch;
        }
    }

    /// Borrows the stable transaction storage.  Moving or destroying this
    /// owner invalidates the returned process-local authority.
    pub fn authority(
        self: *const FinalizedCampaignV2,
        target: *const target_mod.CampaignPaddingTargetV2,
    ) !final_mod.CampaignFinalRemintAuthorityV2 {
        try self.validateSelf(target);
        return final_mod.CampaignFinalRemintAuthorityV2.init(
            &target.shape,
            &self.final_remint,
        );
    }
};

fn validateFinalOwnersForTarget(
    target: *const target_mod.CampaignPaddingTargetV2,
    final_sources: anytype,
) !void {
    const info = @typeInfo(@TypeOf(final_sources));
    switch (info) {
        .@"struct" => |structure| if (!structure.is_tuple or
            structure.fields.len != remint_mod.ROLE_COUNT)
        {
            @compileError(
                "final padding owners must be ordered (real, empty, common)",
            );
        },
        else => @compileError(
            "final padding owners must be ordered (real, empty, common)",
        ),
    }
    inline for (final_sources, 0..) |source, ordinal| {
        const SourcePointer = @TypeOf(source);
        const Source = switch (@typeInfo(SourcePointer)) {
            .pointer => |pointer| pointer.child,
            else => @compileError("final padding owners must be pointers"),
        };
        if (!@hasDecl(Source, "ROLE") or
            @intFromEnum(Source.ROLE) != ordinal or
            !@hasDecl(Source, "validateForPaddingTarget"))
        {
            @compileError(
                "final padding owner must retain its nominal target-bound cold proof",
            );
        }
        try source.validateForPaddingTarget(target);
    }
}

fn identity(value: *const FinalizedCampaignV2) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(TRANSACTION_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hash.update(&value.reserved);
    hash.update(&value.target_identity_sha256);
    hash.update(&value.shape_identity_sha256);
    hash.update(&value.final_remint.identity_sha256);
    hash.update(&value.final_remint.registry.identity_sha256);
    hash.update(&value.final_remint.parity.identity_sha256);
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
        !FINAL_OWNER_TARGET_VALIDATION_REQUIRED or
        @hasDecl(FinalizedCampaignV2, "encode") or
        @hasDecl(FinalizedCampaignV2, "decode"))
    {
        @compileError("campaign padding transaction drifted");
    }
}

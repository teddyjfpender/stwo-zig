//! Campaign-bound stage-102 source for one full Ethereum incremental leaf.
//!
//! The base materializer reconstructs the verifier transcript and native
//! composition graph. This owner additionally replays the complete role-aware
//! public-I/O stream at the unique capacity cold-audited across the campaign.
//! Neither a per-leaf live log nor a caller-provided capacity can enter the
//! universal wrapper through this type.

const std = @import("std");

const campaign_mod =
    @import("recursive_common_ethereum_incremental_leaf_campaign_provider_geometry_v4.zig");
const field_public =
    @import("recursive_common_ethereum_incremental_leaf_field_public_v4_schema3.zig");
const input_mod =
    @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const materializer =
    @import("recursive_common_ethereum_incremental_leaf_materializer_v4.zig");
const role_io =
    @import("recursive_common_ethereum_incremental_leaf_role_aware_io_v4.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const PRODUCTION_LEAF_COUNT = campaign_mod.PRODUCTION_LEAF_COUNT;
pub const PRODUCTION_ACTIVATION = false;
pub const CALLER_AUTHORED_CAPACITY_ADMITTED = false;
pub const PER_LEAF_GEOMETRY_IS_PROOF_AUTHORITY = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-campaign-materializer/v4-schema3\x00";

pub const Error = error{
    ArithmeticOverflow,
    EthereumIncrementalCampaignMaterializerMismatchV4,
};

pub fn PreparedCampaignCaptureV4ForCount(
    comptime Engine: type,
    comptime campaign_leaf_count: usize,
) type {
    const Campaign = campaign_mod.CampaignProviderGeometryAuthorityV4ForCount(
        campaign_leaf_count,
    );
    return PreparedCampaignCaptureV4ForAuthority(Engine, Campaign);
}

/// Runtime-count production materializer. The fixed-count sibling remains a
/// conformance fixture only.
pub fn PreparedOwnedCampaignCaptureV4(comptime Engine: type) type {
    return PreparedCampaignCaptureV4ForAuthority(
        Engine,
        campaign_mod.OwnedCampaignProviderGeometryV4,
    );
}

fn PreparedCampaignCaptureV4ForAuthority(
    comptime Engine: type,
    comptime Campaign: type,
) type {
    const Base = materializer.PreparedCaptureV4(Engine);
    return struct {
        allocator: std.mem.Allocator,
        format_version: u16 = FORMAT_VERSION,
        schema_version: u16 = SCHEMA_VERSION,
        campaign_leaf_index: u32,
        campaign_authority: *const Campaign,
        base: Base,
        role_aware_io: role_io.OwnedWitnessV4,
        schedule: field_public.OwnedPoseidonScheduleV4,
        provider_geometry: field_public.LiveProviderGeometryV4,
        identity_sha256: [32]u8,

        const Self = @This();

        /// Moves `input` only after campaign membership and all common-capacity
        /// reconstruction have succeeded. The campaign authority is borrowed
        /// and must outlive this owner and every derived cohort/capture.
        pub fn initOwned(
            allocator: std.mem.Allocator,
            input: *input_mod.FreshInputV4(Engine),
            campaign_authority: *const Campaign,
            campaign_leaf_index: usize,
        ) !Self {
            return initOwnedMeasured(
                allocator,
                input,
                campaign_authority,
                campaign_leaf_index,
                null,
            );
        }

        pub fn initOwnedMeasured(
            allocator: std.mem.Allocator,
            input: *input_mod.FreshInputV4(Engine),
            campaign_authority: *const Campaign,
            campaign_leaf_index: usize,
            metrics: ?*materializer.MaterializationMetricsV4,
        ) !Self {
            return initOwnedMeasuredWithExecution(
                allocator,
                input,
                campaign_authority,
                campaign_leaf_index,
                .{},
                metrics,
            );
        }

        pub fn initOwnedMeasuredWithExecution(
            allocator: std.mem.Allocator,
            input: *input_mod.FreshInputV4(Engine),
            campaign_authority: *const Campaign,
            campaign_leaf_index: usize,
            execution: materializer.MaterializationExecutionV4,
            metrics: ?*materializer.MaterializationMetricsV4,
        ) !Self {
            try campaign_authority.validateStructure();
            try campaign_authority.validateFreshInputAt(
                Engine,
                allocator,
                campaign_leaf_index,
                input,
            );

            var base = try Base.initOwnedMeasuredWithExecution(
                allocator,
                input,
                execution,
                metrics,
            );
            errdefer base.deinit();
            const capture = &base.input.stage101;
            var role_aware_io = try role_io.OwnedWitnessV4.initUnfrozenForAudit(
                allocator,
                &capture.public_data.data,
                &capture.role_aware_public.value,
                &capture.relations.base,
                campaign_authority.provider_geometry.role_io_tuple_capacity,
            );
            errdefer role_aware_io.deinit();
            var schedule = try field_public.OwnedPoseidonScheduleV4.init(
                Engine,
                allocator,
                &base.input,
                &role_aware_io,
            );
            errdefer schedule.deinit();
            const provider_geometry = try schedule.liveProviderGeometry();
            const index_u32 = std.math.cast(u32, campaign_leaf_index) orelse
                return error.ArithmeticOverflow;
            var result = Self{
                .allocator = allocator,
                .campaign_leaf_index = index_u32,
                .campaign_authority = campaign_authority,
                .base = base,
                .role_aware_io = role_aware_io,
                .schedule = schedule,
                .provider_geometry = provider_geometry,
                .identity_sha256 = undefined,
            };
            result.identity_sha256 = identity(Engine, &result);
            try result.validate();
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.schedule.deinit();
            self.role_aware_io.deinit();
            self.base.deinit();
            self.* = undefined;
        }

        pub fn validate(self: *const Self) !void {
            try self.campaign_authority.validateStructure();
            const leaf_index: usize = self.campaign_leaf_index;
            try self.campaign_authority.validateFreshInputAt(
                Engine,
                self.allocator,
                leaf_index,
                &self.base.input,
            );
            try self.base.validate();
            const capture = &self.base.input.stage101;
            try self.role_aware_io.validateAgainst(
                &capture.public_data.data,
                &capture.role_aware_public.value,
                &capture.relations.base,
            );
            try self.role_aware_io.public_sum_row.validateAgainstVerified(
                &capture.public_sums,
            );
            try self.schedule.validateAgainst(
                Engine,
                &self.base.input,
                &self.role_aware_io,
            );
            const expected_geometry = try self.schedule.liveProviderGeometry();
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION or
                leaf_index >= self.campaign_authority.active_tuple_counts.len or
                self.role_aware_io.active_tuple_count !=
                    self.campaign_authority.active_tuple_counts[leaf_index] or
                self.role_aware_io.padded_tuple_capacity !=
                    self.campaign_authority.provider_geometry.role_io_tuple_capacity or
                !sharedGeometryEql(
                    expected_geometry,
                    self.campaign_authority.provider_geometry,
                ) or !std.meta.eql(self.provider_geometry, expected_geometry) or
                !std.mem.eql(
                    u8,
                    &self.identity_sha256,
                    &identity(Engine, self),
                ))
            {
                return error.EthereumIncrementalCampaignMaterializerMismatchV4;
            }
        }

        pub fn providerCalls(
            self: *const Self,
        ) []const @import("stwo_riscv_frontend").air.memory_commitment.poseidon2_air.Call {
            return self.schedule.callsSlice();
        }
    };
}

pub fn PreparedCampaignCaptureV4(comptime Engine: type) type {
    return PreparedCampaignCaptureV4ForCount(Engine, PRODUCTION_LEAF_COUNT);
}

fn sharedGeometryEql(
    leaf: field_public.LiveProviderGeometryV4,
    campaign: field_public.LiveProviderGeometryV4,
) bool {
    var normalized = leaf;
    normalized.role_io_tuple_count = campaign.role_io_tuple_count;
    return std.meta.eql(normalized, campaign);
}

fn identity(comptime Engine: type, value: anytype) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u32, value.campaign_leaf_index);
    hash.update(&value.campaign_authority.authority_identity_sha256);
    hash.update(&value.base.identity_sha256);
    hash.update(&value.role_aware_io.identity_sha256);
    hash.update(&value.schedule.identity_sha256);
    hashInt(&hash, u32, value.provider_geometry.role_io_tuple_capacity);
    hashInt(&hash, u32, value.provider_geometry.provider_active_row_count);
    hashInt(&hash, u32, value.provider_geometry.provider_log_size);
    hashInt(&hash, u32, @sizeOf(Engine.Hasher.Hash));
    return hash.finalResult();
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        PRODUCTION_LEAF_COUNT != 210 or PRODUCTION_ACTIVATION or
        CALLER_AUTHORED_CAPACITY_ADMITTED or
        PER_LEAF_GEOMETRY_IS_PROOF_AUTHORITY or
        SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("campaign materializer V4 drifted");
    }
}

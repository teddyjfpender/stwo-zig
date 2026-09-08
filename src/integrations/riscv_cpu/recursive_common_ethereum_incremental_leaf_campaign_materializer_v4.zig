//! Campaign-bound stage-102 source for one full Ethereum incremental leaf.
//!
//! The base materializer reconstructs the verifier transcript and native
//! composition graph. This owner additionally replays the complete role-aware
//! public-I/O stream at the unique capacity cold-audited across the campaign.
//! Neither a per-leaf live log nor a caller-provided capacity can enter the
//! universal wrapper through this type.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

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

pub const InitialInputAdmissionV1 = @import("recursive_common_ethereum_initial_input_admission_v1.zig").InitialInputAdmissionV1;
const ProgramAdmission = @import("recursive_common_ethereum_incremental_leaf_program_admission_v1.zig").ProgramAdmissionV1;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 4;
pub const PRODUCTION_LEAF_COUNT = campaign_mod.PRODUCTION_LEAF_COUNT;
pub const PRODUCTION_ACTIVATION = false;
pub const CALLER_AUTHORED_CAPACITY_ADMITTED = false;
pub const PER_LEAF_GEOMETRY_IS_PROOF_AUTHORITY = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-campaign-materializer/v4-schema4\x00";

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
        program_admission: ?*ProgramAdmission = null,
        initial_input_admission: ?*InitialInputAdmissionV1 = null,
        role_aware_io: role_io.OwnedWitnessV4,
        schedule: field_public.OwnedPoseidonScheduleV4,
        provider_geometry: field_public.LiveProviderGeometryV4,
        identity_sha256: [32]u8,

        const Self = @This();

        /// Moves `input` only after campaign membership and all common-capacity
        /// reconstruction have succeeded. Retains a private immutable campaign
        /// snapshot; the caller may destroy its campaign after this returns.
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

        /// Admission owns the whole ELF independently of per-proof inputs.
        pub fn initOwnedMeasuredWithProgram(
            allocator: std.mem.Allocator,
            input: *input_mod.FreshInputV4(Engine),
            campaign_authority: *const Campaign,
            campaign_leaf_index: usize,
            elf_bytes: []const u8,
            execution: materializer.MaterializationExecutionV4,
            metrics: ?*materializer.MaterializationMetricsV4,
        ) !Self {
            const admitted = if (input.fixed_program) |fixed| blk: {
                if (fixed.hasCompletionOpening()) {
                    var source_sha: [32]u8 = undefined;
                    std.crypto.hash.sha2.Sha256.hash(elf_bytes, &source_sha, .{});
                    if (!std.meta.eql(source_sha, fixed.descriptor().elf_sha256)) return error.EthereumFixedProgramSourceMismatch;
                    break :blk try ProgramAdmission.createWithFixedProgram(allocator, fixed);
                }
                break :blk try ProgramAdmission.createFromElf(allocator, elf_bytes);
            } else try ProgramAdmission.createFromElf(allocator, elf_bytes);
            errdefer admitted.deinit();
            const root = input.stage101.role_aware_public.value.program_root orelse
                return error.EthereumProgramAdmissionRootMismatch;
            if (admitted.programRoot() != root) return error.EthereumProgramAdmissionRootMismatch;
            var result = try initOwnedMeasuredWithExecution(allocator, input, campaign_authority, campaign_leaf_index, execution, metrics);
            errdefer input.* = result.deinitRetainingInput();
            result.program_admission = admitted;
            result.identity_sha256 = identity(Engine, &result);
            // The newly owned admission was checked above; no fallible work
            // follows transfer, avoiding an ambiguous double-owner rollback.
            return result;
        }

        /// Explicit initial job shape; both admission owners survive destruction
        /// of the caller's retained source and admission handles.
        pub fn initOwnedMeasuredWithInitialInputs(
            allocator: std.mem.Allocator,
            input: *input_mod.FreshInputV4(Engine),
            campaign_authority: *const Campaign,
            campaign_leaf_index: usize,
            elf_bytes: []const u8,
            initial: *const InitialInputAdmissionV1,
            execution: materializer.MaterializationExecutionV4,
            metrics: ?*materializer.MaterializationMetricsV4,
        ) !Self {
            try initial.validateInput(input);
            const owned = try initial.clone(allocator);
            errdefer owned.deinit();
            var result = try initOwnedMeasuredWithProgram(allocator, input, campaign_authority, campaign_leaf_index, elf_bytes, execution, metrics);
            result.initial_input_admission = owned;
            result.identity_sha256 = identity(Engine, &result);
            return result;
        }

        pub fn claimShape(self: *const Self) !frontend.recursion.vm_public_claim.Shape {
            return if (self.initial_input_admission) |admitted| admitted.claimShape() else try frontend.recursion.vm_public_claim.defaultShape();
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

            const retained_campaign = try allocator.create(Campaign);
            errdefer allocator.destroy(retained_campaign);
            retained_campaign.* = if (@hasDecl(Campaign, "clone"))
                try campaign_authority.clone(allocator)
            else
                campaign_authority.*;
            errdefer if (@hasDecl(Campaign, "deinit")) retained_campaign.deinit();

            var base = try Base.initOwnedMeasuredWithExecution(
                allocator,
                input,
                execution,
                metrics,
            );
            errdefer input.* = base.deinitRetainingInput();
            const capture = &base.input.stage101;
            var role_aware_io = try role_io.OwnedWitnessV4.initWithCircuitProfile(
                allocator,
                &capture.public_data.data,
                &capture.role_aware_public.value,
                &capture.relations.base,
                campaign_authority.view().provider_geometry.role_io_tuple_capacity,
                capture.profile.circuitProfile(),
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
                .campaign_authority = retained_campaign,
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
            var input = self.deinitRetainingInput();
            input.deinit();
        }

        pub fn deinitRetainingInput(self: *Self) input_mod.FreshInputV4(Engine) {
            if (self.program_admission) |admitted| admitted.deinit();
            if (self.initial_input_admission) |admitted| admitted.deinit();
            self.schedule.deinit();
            self.role_aware_io.deinit();
            const input = self.base.deinitRetainingInput();
            const campaign = @constCast(self.campaign_authority);
            if (@hasDecl(Campaign, "deinit")) campaign.deinit();
            self.allocator.destroy(campaign);
            self.* = undefined;
            return input;
        }

        pub fn validate(self: *const Self) !void {
            const leaf_index: usize = self.campaign_leaf_index;
            if (self.initial_input_admission) |admitted| {
                if (self.program_admission == null) return error.EthereumInitialProgramOpeningRequired;
                try admitted.validateInput(&self.base.input);
            }
            if (self.program_admission) |admitted| {
                try admitted.validateFixedProgramOwner(self.base.input.fixed_program);
                const root = self.base.input.stage101.role_aware_public.value.program_root orelse return error.EthereumProgramAdmissionRootMismatch;
                if (admitted.programRoot() != root) return error.EthereumProgramAdmissionRootMismatch;
            }
            try self.base.validate();
            try campaign_mod.validatePreparedInputAt(
                Engine,
                self.campaign_authority,
                leaf_index,
                &self.base.input,
                &self.role_aware_io,
                &self.schedule,
            );
            const capture = &self.base.input.stage101;
            if (self.role_aware_io.circuit_profile != capture.profile.circuitProfile()) return error.RoleAwareIoClaimMismatchV4;
            try self.role_aware_io.public_sum_row.validateAgainstVerified(
                &capture.public_sums,
            );
            const expected_geometry = try self.schedule.liveProviderGeometry();
            if (self.format_version != FORMAT_VERSION or
                self.schema_version != SCHEMA_VERSION or
                leaf_index >= self.campaign_authority.view().active_tuple_counts.len or
                self.role_aware_io.active_tuple_count !=
                    self.campaign_authority.view().active_tuple_counts[leaf_index] or
                self.role_aware_io.padded_tuple_capacity !=
                    self.campaign_authority.view().provider_geometry.role_io_tuple_capacity or
                !sharedGeometryEql(
                    expected_geometry,
                    self.campaign_authority.view().provider_geometry,
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
    hash.update(&value.campaign_authority.view().authority_identity_sha256);
    hash.update(&value.base.identity_sha256);
    hashInt(&hash, u8, @intFromBool(value.program_admission != null));
    if (value.program_admission) |admitted| hash.update(&admitted.identitySha256());
    if (value.initial_input_admission) |admitted| {
        hash.update("initial-input-admission/v1\x00");
        hash.update(&admitted.identitySha256());
    }
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
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 4 or
        PRODUCTION_LEAF_COUNT != 210 or PRODUCTION_ACTIVATION or
        CALLER_AUTHORED_CAPACITY_ADMITTED or
        PER_LEAF_GEOMETRY_IS_PROOF_AUTHORITY or
        SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("campaign materializer V4 drifted");
    }
}

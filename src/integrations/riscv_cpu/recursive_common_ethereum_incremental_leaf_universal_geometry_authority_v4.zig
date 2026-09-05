//! Live-derived 36-row geometry authority for the role-0 V4 wrapper.
//!
//! This owner joins verifier-derived transcript geometry (rows 0--9), the
//! immovable authenticated rows-10--34 owner, and the fixed range provider.
//! The resulting manifest is derived from one runtime-count campaign authority
//! and the complete combined row-34 call inventory. The owner also retains the
//! verifier-derived schema-3 row source; claim closure remains unavailable.

const std = @import("std");

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const complete_provider =
    @import("recursive_common_ethereum_incremental_leaf_complete_provider_geometry_v4.zig");
const rows_10_34 =
    @import("recursive_common_ethereum_incremental_leaf_rows_10_34_v4.zig");
const transcript_geometry =
    @import("recursive_common_ethereum_incremental_leaf_transcript_geometry_v4.zig");
const transcript_program =
    @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4.zig");
const transcript_rows =
    @import("recursive_common_ethereum_incremental_leaf_transcript_rows_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const FULL_LOG_GEOMETRY_AVAILABLE = true;
pub const TRANSCRIPT_PROGRAM_AVAILABLE = true;
pub const COMPLETE_PROVIDER_AUTHORITY_REQUIRED = true;
pub const RUNTIME_CAMPAIGN_AUTHORITY_REQUIRED = true;
pub const ROW_MATERIALIZERS_AVAILABLE = true;
pub const CLAIM_CLOSURE_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-universal-geometry/v4-schema3\x00";

pub const Error = error{
    EthereumIncrementalUniversalGeometryMismatchV4,
};

pub const CompleteProviderGeometryV4 =
    complete_provider.CompleteProviderGeometryV4;

/// Stable heap owner because its rows-10--34 child retains internal and
/// sibling pointers. No detached log-size constructor is exposed.
pub fn OwnerV4(comptime Engine: type) type {
    const Materialized =
        campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine);
    const Suffix = rows_10_34.OwnerV4(Engine);
    const TranscriptRows = transcript_rows.OwnerV4(Engine);

    return opaque {
        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
        ) !*Self {
            return initWithLogSizes(allocator, materialized, null);
        }

        /// Builds the complete role-0 authority at a caller-authenticated
        /// target vector. Logical rows remain source-derived; every selected
        /// domain is checked against its active minimum before publication.
        pub fn initForLogSizes(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            requested_log_sizes: manifest_mod.LogSizesV4,
        ) !*Self {
            return initWithLogSizes(
                allocator,
                materialized,
                requested_log_sizes,
            );
        }

        fn initWithLogSizes(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            requested_log_sizes: ?manifest_mod.LogSizesV4,
        ) !*Self {
            try materialized.validate();
            const suffix = if (requested_log_sizes) |logs|
                try Suffix.initForLogSizes(
                    allocator,
                    materialized,
                    logs[10..35].*,
                )
            else
                try Suffix.init(allocator, materialized);
            var suffix_moved = false;
            errdefer if (!suffix_moved) suffix.deinit();
            const plans = try (try suffix.nativeCore()).scheduleView();
            const prefix = try transcript_geometry.AuthorityV4.mint(
                &materialized.base.transcript,
                plans.vm,
                plans.recursion,
            );
            var program = try transcript_program.ProgramAuthorityV4.init(
                Engine,
                allocator,
                materialized,
                plans.vm,
                plans.recursion,
            );
            var program_moved = false;
            errdefer if (!program_moved) program.deinit();
            const active_prefix_logs = prefix.log_sizes;
            const derived_logs = try deriveLogSizes(&prefix, suffix);
            const logs = requested_log_sizes orelse derived_logs;
            for (
                logs[0..active_prefix_logs.len],
                active_prefix_logs,
            ) |selected, minimum| if (selected < minimum or selected >= 31)
                return error.EthereumIncrementalUniversalGeometryMismatchV4;
            if (!std.mem.eql(
                u32,
                logs[active_prefix_logs.len..35],
                derived_logs[active_prefix_logs.len..35],
            )) return error.EthereumIncrementalUniversalGeometryMismatchV4;
            if (logs[35] != derived_logs[35])
                return error.EthereumIncrementalUniversalGeometryMismatchV4;
            const complete = try suffix.completeProviderGeometry();
            const manifest_value = try manifest_mod.buildForCampaignAuthority(
                logs,
                materialized.campaign_authority,
                complete,
            );
            try (try suffix.nativeCore()).validateAgainstManifest(
                &manifest_value,
            );

            const backing = try allocator.create(Storage);
            var backing_initialized = false;
            errdefer if (!backing_initialized) allocator.destroy(backing);
            backing.* = .{
                .allocator = allocator,
                .materialized = materialized,
                .prefix = prefix,
                .program = program,
                .rows = undefined,
                .rows_initialized = false,
                .suffix = suffix,
                .log_sizes = logs,
                .complete_provider = complete,
                .manifest_value = manifest_value,
                .identity_sha256 = undefined,
            };
            backing_initialized = true;
            suffix_moved = true;
            program_moved = true;
            errdefer backing.destroy();
            backing.rows = try TranscriptRows.init(
                allocator,
                materialized,
                &backing.program,
                &backing.prefix,
                plans.vm,
                plans.recursion,
            );
            backing.rows_initialized = true;
            backing.identity_sha256 = try backing.computeIdentity();
            try backing.validate();
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroy();
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validate();
        }

        pub fn transcriptGeometry(
            self: *const Self,
        ) !*const transcript_geometry.AuthorityV4 {
            try self.validate();
            return &storageConst(self).prefix;
        }

        pub fn transcriptProgram(
            self: *const Self,
        ) !*const transcript_program.ProgramAuthorityV4 {
            try self.validate();
            return &storageConst(self).program;
        }

        pub fn transcriptRows(
            self: *const Self,
        ) !*const TranscriptRows {
            try self.validate();
            return storageConst(self).rows;
        }

        pub fn rows10Through34(self: *const Self) !*const Suffix {
            try self.validate();
            return storageConst(self).suffix;
        }

        /// Mutable access is reserved for the complete 36-row cohort, which
        /// alone may finalize the shared row-34 provider after validating the
        /// full manifest.
        pub fn rows10Through34Mutable(self: *Self) !*Suffix {
            try self.validate();
            return storage(self).suffix;
        }

        pub fn logSizes(
            self: *const Self,
        ) !manifest_mod.LogSizesV4 {
            try self.validate();
            return storageConst(self).log_sizes;
        }

        pub fn manifest(self: *const Self) !*const manifest_mod.Manifest {
            try self.validate();
            return &storageConst(self).manifest_value;
        }

        pub fn completeProviderGeometry(
            self: *const Self,
        ) !CompleteProviderGeometryV4 {
            try self.validate();
            return storageConst(self).complete_provider;
        }

        pub fn identity(self: *const Self) ![32]u8 {
            try self.validate();
            return storageConst(self).identity_sha256;
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            prefix: transcript_geometry.AuthorityV4,
            program: transcript_program.ProgramAuthorityV4,
            rows: *TranscriptRows,
            rows_initialized: bool,
            suffix: *Suffix,
            log_sizes: manifest_mod.LogSizesV4,
            complete_provider: CompleteProviderGeometryV4,
            manifest_value: manifest_mod.Manifest,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                try self.materialized.validate();
                const plans = try (try self.suffix.nativeCore()).scheduleView();
                try self.prefix.validateAgainst(
                    &self.materialized.base.transcript,
                    plans.vm,
                    plans.recursion,
                );
                try self.program.validateAgainst(
                    Engine,
                    self.materialized,
                    plans.vm,
                    plans.recursion,
                );
                if (!self.rows_initialized)
                    return error.EthereumIncrementalUniversalGeometryMismatchV4;
                try self.rows.validate();
                try self.suffix.validate();
                const derived_logs = try deriveLogSizes(
                    &self.prefix,
                    self.suffix,
                );
                for (
                    self.log_sizes[0..self.prefix.log_sizes.len],
                    self.prefix.log_sizes,
                ) |selected, minimum| if (selected < minimum or selected >= 31)
                    return error.EthereumIncrementalUniversalGeometryMismatchV4;
                if (!std.mem.eql(
                    u32,
                    self.log_sizes[self.prefix.log_sizes.len..35],
                    derived_logs[self.prefix.log_sizes.len..35],
                ) or self.log_sizes[35] != derived_logs[35])
                    return error.EthereumIncrementalUniversalGeometryMismatchV4;
                const expected_complete =
                    try self.suffix.completeProviderGeometry();
                try manifest_mod.validateExactForCampaignAuthority(
                    &self.manifest_value,
                    self.log_sizes,
                    self.materialized.campaign_authority,
                    self.complete_provider,
                );
                try (try self.suffix.nativeCore()).validateAgainstManifest(
                    &self.manifest_value,
                );
                if (!std.meta.eql(
                    self.complete_provider,
                    expected_complete,
                ) or
                    !std.mem.eql(
                        u8,
                        &self.identity_sha256,
                        &(try self.computeIdentity()),
                    ))
                {
                    return error.EthereumIncrementalUniversalGeometryMismatchV4;
                }
            }

            fn computeIdentity(self: *const Storage) ![32]u8 {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update(IDENTITY_DOMAIN);
                hashInt(&hash, u16, FORMAT_VERSION);
                hashInt(&hash, u16, SCHEMA_VERSION);
                hash.update(&self.materialized.identity_sha256);
                hash.update(&self.materialized.campaign_authority
                    .authority_identity_sha256);
                hash.update(&self.prefix.identity_sha256);
                hash.update(&self.program.identity_sha256);
                const rows_view = try self.rows.views();
                hash.update(&rows_view.identity_sha256);
                hash.update(&(try self.suffix.identity()));
                hash.update(&self.complete_provider.identity_sha256);
                hash.update(&self.manifest_value.seal);
                for (self.log_sizes) |log_size|
                    hashInt(&hash, u32, log_size);
                return hash.finalResult();
            }

            fn destroy(self: *Storage) void {
                const allocator = self.allocator;
                if (self.rows_initialized) self.rows.deinit();
                self.program.deinit();
                self.suffix.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }
        };

        fn handle(value: *Storage) *Self {
            return @ptrCast(value);
        }

        fn storage(value: *Self) *Storage {
            return @ptrCast(@alignCast(value));
        }

        fn storageConst(value: *const Self) *const Storage {
            return @ptrCast(@alignCast(value));
        }
    };
}

fn deriveLogSizes(
    prefix: *const transcript_geometry.AuthorityV4,
    suffix: anytype,
) !manifest_mod.LogSizesV4 {
    var result: manifest_mod.LogSizesV4 = undefined;
    @memcpy(result[0..transcript_geometry.ROW_COUNT], &prefix.log_sizes);
    const suffix_logs = try suffix.logSizes();
    @memcpy(
        result[rows_10_34.FIRST_ROW .. rows_10_34.LAST_ROW + 1],
        &suffix_logs,
    );
    result[@intFromEnum(manifest_mod.ComponentKey.range_check_8_8)] =
        manifest_mod.RANGE_LOG_SIZE;
    return result;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        COMPONENT_COUNT != 36 or !FULL_LOG_GEOMETRY_AVAILABLE or
        !TRANSCRIPT_PROGRAM_AVAILABLE or
        !COMPLETE_PROVIDER_AUTHORITY_REQUIRED or
        !RUNTIME_CAMPAIGN_AUTHORITY_REQUIRED or
        !ROW_MATERIALIZERS_AVAILABLE or CLAIM_CLOSURE_AVAILABLE or
        PRODUCTION_ACTIVATION or transcript_geometry.FIRST_ROW != 0 or
        transcript_geometry.LAST_ROW != 9 or rows_10_34.FIRST_ROW != 10 or
        rows_10_34.LAST_ROW != 34 or manifest_mod.RANGE_LOG_SIZE != 16)
    {
        @compileError("Ethereum incremental universal geometry V4 drifted");
    }
}

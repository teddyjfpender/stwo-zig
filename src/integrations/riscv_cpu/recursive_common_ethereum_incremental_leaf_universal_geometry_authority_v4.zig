//! Live-derived 36-row geometry authority for the role-0 V4 wrapper.
//!
//! This owner joins verifier-derived transcript geometry (rows 0--9), the
//! immovable authenticated rows-10--34 owner, and the fixed range provider.
//! The resulting manifest is derived from one runtime-count campaign authority
//! and the complete combined row-34 call inventory. The owner also retains the
//! verifier-derived schema-3 row source; claim closure remains unavailable.

const std = @import("std");
const progress = @import("ethereum_wrapper_resources_v1.zig").progress;

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const complete_provider =
    @import("recursive_common_ethereum_incremental_leaf_complete_provider_geometry_v4.zig");
const native_core =
    @import("recursive_common_ethereum_incremental_leaf_native_core_v4.zig");
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
            var phase: ?std.time.Timer = std.time.Timer.start() catch null;
            progress("ETHEREUM_GEOMETRY_PREPARATION phase=begin\n", .{});
            try materialized.validate();
            markPreparationPhase(&phase, "materialized-admission");
            // Stable transcript ownership precedes native-row preparation.
            // Rows borrow these plans, prefix and program for their lifetime.
            const backing = try allocator.create(Storage);
            errdefer allocator.destroy(backing);
            backing.allocator = allocator;
            backing.materialized = materialized;
            backing.plans = try native_core.buildPlans(
                allocator,
                &materialized.base.captured_fri,
                materialized.campaign_authority.view().provider_geometry.role_io_tuple_capacity,
            );
            errdefer for (&backing.plans) |*plan| plan.deinit();
            backing.prefix = try transcript_geometry.AuthorityV4.mint(
                &materialized.base.transcript,
                &backing.plans[0],
                &backing.plans[1],
            );
            markPreparationPhase(&phase, "plans-prefix");
            backing.program = try transcript_program.ProgramAuthorityV4.init(
                Engine,
                allocator,
                materialized,
                &backing.plans[0],
                &backing.plans[1],
            );
            errdefer backing.program.deinit();
            markPreparationPhase(&phase, "program");
            backing.rows = try TranscriptRows.init(
                allocator,
                materialized,
                &backing.program,
                &backing.prefix,
                &backing.plans[0],
                &backing.plans[1],
            );
            errdefer backing.rows.deinit();
            markPreparationPhase(&phase, "transcript-rows");
            backing.suffix = try Suffix.initWithTranscript(allocator, materialized, if (requested_log_sizes) |logs| logs[10..35].* else null, &backing.program);
            errdefer backing.suffix.deinit();
            markPreparationPhase(&phase, "suffix");
            const suffix = backing.suffix;
            const prefix = &backing.prefix;
            const program = &backing.program;
            const suffix_view = try suffix.geometryView();
            const plans = try suffix_view.native.scheduleView();
            try prefix.validateAgainst(&materialized.base.transcript, plans.vm, plans.recursion);
            try program.validateAgainst(Engine, materialized, plans.vm, plans.recursion);
            const active_prefix_logs = prefix.log_sizes;
            const derived_logs = deriveLogSizes(prefix, suffix_view.log_sizes);
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
            const complete = suffix_view.complete_provider;
            const manifest_value = try manifest_mod.buildForCampaignAuthority(
                logs,
                materialized.campaign_authority,
                complete,
            );
            try suffix_view.native.validateAgainstManifest(
                &manifest_value,
            );

            backing.log_sizes = logs;
            backing.complete_provider = complete;
            backing.manifest_value = manifest_value;
            const rows_view = try backing.rows.views();
            backing.identity_sha256 = backing.computeIdentity(rows_view.identity_sha256, suffix_view.identity_sha256);
            markPreparationPhase(&phase, "manifest-projection");
            // Source admission and every child constructor completed in this
            // synchronous transaction. Only our local geometry projection is
            // new; no borrowed source or child has escaped for mutation.
            try backing.validatePrepared();
            markPreparationPhase(&phase, "local-finalization");
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroy();
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validate();
        }

        /// Internal proof construction reads our independently owned transcript
        /// rows and plans. Native inputs remain borrowed and are still admitted
        /// on every call. External source/proof admission must use validate.
        pub fn validateOperational(self: *const Self) !void {
            const value = storageConst(self);
            try value.materialized.validate();
            try value.suffix.validate();
            try value.validateProjection(false);
        }

        /// Read-only metadata admitted at construction. These allocations and
        /// fixed geometry remain immutable through provider finalization.
        /// Input, mutation and proof boundaries call `validate` explicitly.
        pub const GeometryViewV4 = struct {
            manifest: *const manifest_mod.Manifest,
            suffix: *const Suffix,
            log_sizes: manifest_mod.LogSizesV4,
            complete_provider: CompleteProviderGeometryV4,
            identity_sha256: [32]u8,
        };

        pub fn geometryView(self: *const Self) !GeometryViewV4 {
            const value = storageConst(self);
            return .{
                .manifest = &value.manifest_value,
                .suffix = value.suffix,
                .log_sizes = value.log_sizes,
                .complete_provider = value.complete_provider,
                .identity_sha256 = value.identity_sha256,
            };
        }

        pub fn transcriptGeometry(
            self: *const Self,
        ) !*const transcript_geometry.AuthorityV4 {
            return &storageConst(self).prefix;
        }

        pub fn transcriptProgram(
            self: *const Self,
        ) !*const transcript_program.ProgramAuthorityV4 {
            return &storageConst(self).program;
        }

        pub fn transcriptRows(
            self: *const Self,
        ) !*const TranscriptRows {
            return storageConst(self).rows;
        }

        pub fn rows10Through34(self: *const Self) !*const Suffix {
            return storageConst(self).suffix;
        }

        /// Mutable access is reserved for the complete 36-row cohort, which
        /// alone may finalize the shared row-34 provider after validating the
        /// full manifest.
        pub fn rows10Through34Mutable(self: *Self) !*Suffix {
            // Borrow the opaque child; no ownership or mutable fields escape.
            // Its native mutation methods authenticate their inputs before
            // writing. A getter check cannot replace that mutation boundary.
            return storage(self).suffix;
        }

        pub fn logSizes(
            self: *const Self,
        ) !manifest_mod.LogSizesV4 {
            return storageConst(self).log_sizes;
        }

        pub fn manifest(self: *const Self) !*const manifest_mod.Manifest {
            return &storageConst(self).manifest_value;
        }

        pub fn completeProviderGeometry(
            self: *const Self,
        ) !CompleteProviderGeometryV4 {
            return storageConst(self).complete_provider;
        }

        pub fn identity(self: *const Self) ![32]u8 {
            return storageConst(self).identity_sha256;
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            plans: native_core.PlanPairV4,
            prefix: transcript_geometry.AuthorityV4,
            program: transcript_program.ProgramAuthorityV4,
            rows: *TranscriptRows,
            suffix: *Suffix,
            log_sizes: manifest_mod.LogSizesV4,
            complete_provider: CompleteProviderGeometryV4,
            manifest_value: manifest_mod.Manifest,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                try self.materialized.validate();
                try self.suffix.validate();
                try self.validatePrepared();
            }

            // Private constructor finalization, or the tail of full external
            // admission above. This does not persist permission to skip a later
            // audit: Materialized remains borrowed and externally mutable.
            fn validatePrepared(self: *const Storage) !void {
                try self.validateProjection(true);
            }

            fn validateProjection(self: *const Storage, comptime admit_transcript_source: bool) !void {
                const suffix_view = try self.suffix.geometryView();
                const plans = try suffix_view.native.scheduleView();
                if (admit_transcript_source) {
                    try self.prefix.validateAgainst(
                        &self.materialized.base.transcript,
                        plans.vm,
                        plans.recursion,
                    );
                    try self.program.validateAgainstPreparedSource(
                        Engine,
                        self.materialized,
                        plans.vm,
                        plans.recursion,
                    );
                }
                // Transcript rows own their operational plans, metadata and
                // witness arrays. The cold branch additionally replays source.
                if (admit_transcript_source)
                    try self.rows.validateRowsAgainstLiveSource()
                else
                    try self.rows.validatePreparedRows();
                const rows_view = try self.rows.views();
                const derived_logs = deriveLogSizes(&self.prefix, suffix_view.log_sizes);
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
                const expected_complete = suffix_view.complete_provider;
                try manifest_mod.validateExactForCampaignAuthority(
                    &self.manifest_value,
                    self.log_sizes,
                    self.materialized.campaign_authority,
                    self.complete_provider,
                );
                // suffix.validate above admitted this same privately owned
                // native source. Check its manifest projection locally here.
                try suffix_view.native.validatePreparedAgainstManifest(
                    &self.manifest_value,
                );
                if (!std.meta.eql(
                    self.complete_provider,
                    expected_complete,
                ) or
                    !std.mem.eql(
                        u8,
                        &self.identity_sha256,
                        &self.computeIdentity(rows_view.identity_sha256, suffix_view.identity_sha256),
                    ))
                {
                    return error.EthereumIncrementalUniversalGeometryMismatchV4;
                }
            }

            fn computeIdentity(
                self: *const Storage,
                rows_identity: [32]u8,
                suffix_identity: [32]u8,
            ) [32]u8 {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update(IDENTITY_DOMAIN);
                hashInt(&hash, u16, FORMAT_VERSION);
                hashInt(&hash, u16, SCHEMA_VERSION);
                hash.update(&self.materialized.identity_sha256);
                hash.update(&self.materialized.campaign_authority.view()
                    .authority_identity_sha256);
                hash.update(&self.prefix.identity_sha256);
                hash.update(&self.program.identity_sha256);
                hash.update(&rows_identity);
                hash.update(&suffix_identity);
                hash.update(&self.complete_provider.identity_sha256);
                hash.update(&self.manifest_value.seal);
                for (self.log_sizes) |log_size|
                    hashInt(&hash, u32, log_size);
                return hash.finalResult();
            }

            fn destroy(self: *Storage) void {
                const allocator = self.allocator;
                self.rows.deinit();
                self.suffix.deinit();
                self.program.deinit();
                for (&self.plans) |*plan| plan.deinit();
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

fn markPreparationPhase(timer: *?std.time.Timer, comptime name: []const u8) void {
    const elapsed: ?u64 = if (timer.*) |*value| value.lap() else null;
    progress("ETHEREUM_GEOMETRY_PREPARATION phase={s} ns={?d}\n", .{ name, elapsed });
}

fn deriveLogSizes(
    prefix: *const transcript_geometry.AuthorityV4,
    suffix_logs: rows_10_34.LogSizesV4,
) manifest_mod.LogSizesV4 {
    var result: manifest_mod.LogSizesV4 = undefined;
    @memcpy(result[0..transcript_geometry.ROW_COUNT], &prefix.log_sizes);
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

//! Stable authenticated owner for role-0 universal rows 10--34.
//!
//! Rows 10--15 bind the exact stage-101 child statement, VM claim, and
//! role-aware public I/O. Rows 16--17 project the public-sum graph and verifier
//! schedule retained by the native core. Rows 18--34 are that native core,
//! including the single combined Poseidon provider inventory. Keeping all
//! owners behind one immovable allocation prevents a future transcript-prefix
//! adapter from substituting suffix logs, child hashes, or provider calls.
//!
//! This is deliberately not a complete universal cohort: rows 0--9 and the
//! fixed range provider remain separately owned, so this module cannot mint a
//! manifest, claims, proof, cold capture, or fold-child capability.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const transcript_program = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4.zig");
const native_identity_hash = @import("recursive_common_ethereum_incremental_leaf_native_identity_hash_v4.zig");
const field_frame_routing = @import("recursive_common_ethereum_incremental_leaf_field_frame_routing_v4.zig");
const publication_words = @import("recursive_common_ethereum_incremental_leaf_publication_words_v4.zig");
const native_publication_words = @import("recursive_common_ethereum_incremental_leaf_native_publication_words_v4.zig");

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const child_public =
    @import("recursive_common_ethereum_incremental_leaf_child_public_v4.zig");
const child_statement =
    @import("recursive_common_ethereum_incremental_leaf_child_statement_v4.zig");
const complete_provider =
    @import("recursive_common_ethereum_incremental_leaf_complete_provider_geometry_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const native_core =
    @import("recursive_common_ethereum_incremental_leaf_native_core_v4.zig");
const public_logup_control =
    @import("recursive_common_ethereum_incremental_leaf_public_logup_control_v4.zig");
const public_logup_input =
    @import("recursive_common_ethereum_incremental_leaf_public_logup_input_v4.zig");

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 4;
pub const FIRST_ROW: usize = 10;
pub const LAST_ROW: usize = 34;
pub const ROW_COUNT: usize = LAST_ROW - FIRST_ROW + 1;
pub const ROWS_10_THROUGH_34_AVAILABLE = true;
pub const COMPLETE_PROVIDER_AUTHORITY_AVAILABLE = true;
pub const TRANSCRIPT_PREFIX_AVAILABLE = false;
pub const CLAIM_CLOSURE_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-rows-10-34/v4-schema4\x00";

pub const Error = error{
    EthereumIncrementalRows10Through34MismatchV4,
};

pub const LogSizesV4 = [ROW_COUNT]u32;
pub const CompleteProviderGeometryV4 =
    complete_provider.CompleteProviderGeometryV4;

/// Heap-owned aggregate because every constituent retains pointers into its
/// own preprocessing, evaluation, or sibling authority. The returned opaque
/// pointer is the only success value and must outlive every borrowed view.
pub fn OwnerV4(comptime Engine: type) type {
    const Materialized =
        campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine);
    const ChildPublic = child_public.OwnerV4(Engine);
    const ChildStatement = child_statement.OwnerV4(Engine);
    const Native = native_core.OwnerV4(Engine);
    const PublicInput = public_logup_input.OwnerV4(Native);
    const PublicControl = public_logup_control.OwnerV4(Native);

    return opaque {
        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
        ) !*Self {
            return initWithLogSizes(allocator, materialized, null, null);
        }

        /// Target-native constructor. Rows 10--17 retain their authenticated
        /// logical sources and are placed in larger zero-initialized domains;
        /// rows 18--34 are rebuilt by the padded native-core constructor.
        pub fn initForLogSizes(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            requested_log_sizes: LogSizesV4,
        ) !*Self {
            return initWithLogSizes(
                allocator,
                materialized,
                requested_log_sizes,
                null,
            );
        }

        pub fn initWithTranscript(allocator: std.mem.Allocator, materialized: *const Materialized, requested_log_sizes: ?LogSizesV4, program: *const transcript_program.ProgramAuthorityV4) !*Self {
            return initWithLogSizes(allocator, materialized, requested_log_sizes, program);
        }

        fn initWithLogSizes(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            requested_log_sizes: ?LogSizesV4,
            transcript: ?*const transcript_program.ProgramAuthorityV4,
        ) !*Self {
            try materialized.validate();
            const identity_hashes: ?*native_identity_hash.OwnedPlan = if (transcript) |program| if (program.field_plan != null) try buildNativeIdentityHashes(allocator, materialized) else null else null;
            errdefer if (identity_hashes) |hashes| hashes.deinit();

            const child = try ChildPublic.init(allocator, materialized);
            errdefer child.deinit();
            const statement = try ChildStatement.init(
                allocator,
                materialized,
                child,
            );
            errdefer statement.deinit();
            const native = try Native.initWithIdentityHashes(allocator, materialized, child, statement, if (requested_log_sizes) |logs| logs[8..][0..native_core.ROW_COUNT].* else null, identity_hashes);
            errdefer native.deinit();
            const row16 = try PublicInput.init(allocator, native);
            errdefer row16.deinit();
            const row17 = try PublicControl.init(allocator, native);
            errdefer row17.deinit();

            const backing = try allocator.create(Storage);
            errdefer allocator.destroy(backing);
            backing.* = .{
                .allocator = allocator,
                .materialized = materialized,
                .transcript = transcript,
                .identity_hashes = identity_hashes,
                .child = child,
                .statement = statement,
                .row16 = row16,
                .row17 = row17,
                .native = native,
                .log_sizes = undefined,
                .minimum_log_sizes = undefined,
                .component_identities = undefined,
                .complete_provider = try native.completeProviderGeometry(),
                .identity_sha256 = undefined,
            };
            backing.minimum_log_sizes = try backing.deriveAdmissionLogSizes();
            backing.log_sizes = requested_log_sizes orelse backing.minimum_log_sizes;
            backing.component_identities = .{
                materialized.identity_sha256,
                (try child.binding()).identity_sha256,
                try statement.identity(),
                try row16.identity(),
                try row17.identity(),
                try native.authorityIdentity(),
            };
            backing.identity_sha256 = backing.computeIdentity();
            try backing.validate();
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroy();
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validate();
        }

        /// One synchronous preparation read of construction-admitted state.
        /// These borrowed opaque handles confer no proof/freshness authority;
        /// child admission still validates its inputs. Do not retain the view
        /// across native finalization or beyond this owner's lifetime.
        pub const PreparationViewV4 = struct {
            materialized: *const Materialized,
            child: *const ChildPublic,
            statement: *const ChildStatement,
            row16: *const PublicInput,
            row17: *const PublicControl,
            log_sizes: LogSizesV4,
            transcript: ?*const transcript_program.ProgramAuthorityV4,
            identity_hashes: ?*const native_identity_hash.OwnedPlan,
        };

        pub fn preparationView(self: *const Self) !PreparationViewV4 {
            const value = storageConst(self);
            return .{ .materialized = value.materialized, .child = value.child, .statement = value.statement, .row16 = value.row16, .row17 = value.row17, .log_sizes = value.log_sizes, .transcript = value.transcript, .identity_hashes = value.identity_hashes };
        }

        /// Borrowed metadata for one read-only preparation phase. This is not
        /// a new authority and must not be retained across native finalization.
        pub const GeometryViewV4 = struct {
            log_sizes: LogSizesV4,
            complete_provider: CompleteProviderGeometryV4,
            native: *const Native,
            identity_sha256: [32]u8,
        };

        pub fn geometryView(self: *const Self) !GeometryViewV4 {
            const value = storageConst(self);
            return .{
                .log_sizes = value.log_sizes,
                .complete_provider = value.complete_provider,
                .native = value.native,
                .identity_sha256 = value.identity_sha256,
            };
        }

        pub fn logSizes(self: *const Self) !LogSizesV4 {
            return storageConst(self).log_sizes;
        }

        pub fn completeProviderGeometry(
            self: *const Self,
        ) !CompleteProviderGeometryV4 {
            return storageConst(self).complete_provider;
        }

        pub fn childPublic(self: *const Self) !*const ChildPublic {
            return storageConst(self).child;
        }

        pub fn childStatement(self: *const Self) !*const ChildStatement {
            return storageConst(self).statement;
        }

        pub fn publicLogupInput(self: *const Self) !*const PublicInput {
            return storageConst(self).row16;
        }

        pub fn publicLogupControl(self: *const Self) !*const PublicControl {
            return storageConst(self).row17;
        }

        pub fn nativeCore(self: *const Self) !*const Native {
            return storageConst(self).native;
        }

        pub fn nativeCoreMutable(self: *Self) !*Native {
            // Borrow the opaque native owner for this source's lifetime.
            // Finalization, interaction preparation and component admission
            // retain their own full checks before any mutation or publication.
            return storage(self).native;
        }

        pub fn identity(self: *const Self) ![32]u8 {
            return storageConst(self).identity_sha256;
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            transcript: ?*const transcript_program.ProgramAuthorityV4,
            identity_hashes: ?*native_identity_hash.OwnedPlan,
            child: *ChildPublic,
            statement: *ChildStatement,
            row16: *PublicInput,
            row17: *PublicControl,
            native: *Native,
            log_sizes: LogSizesV4,
            /// Fixed metadata is admitted once while all constituent owners
            /// are constructed, and never changes during provider finalization.
            minimum_log_sizes: LogSizesV4,
            component_identities: [6][32]u8,
            complete_provider: CompleteProviderGeometryV4,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                // Revalidate mutable native proof state exactly at this explicit
                // boundary. Geometry/identity reads below are fixed metadata,
                // not recursive invocations of the ownership hierarchy.
                try self.native.validate();
                try self.statement.validate();
                try self.row16.validate();
                try self.row17.validate();
                const derived = self.minimum_log_sizes;
                for (self.log_sizes) |log_size| if (log_size < 4 or log_size >= 31)
                    return error.EthereumIncrementalRows10Through34MismatchV4;
                for (
                    self.log_sizes[0..8],
                    derived[0..8],
                ) |selected, minimum| if (selected < minimum)
                    return error.EthereumIncrementalRows10Through34MismatchV4;
                if (!std.mem.eql(
                    u32,
                    self.log_sizes[8..],
                    derived[8..],
                )) return error.EthereumIncrementalRows10Through34MismatchV4;
                const complete = try self.native.completeProviderGeometry();
                try complete.validate();
                if (!std.meta.eql(complete, self.complete_provider) or
                    !std.mem.eql(u32, self.log_sizes[8..], &(try self.native.componentLogSizes())) or
                    self.log_sizes[LAST_ROW - FIRST_ROW] !=
                        complete.provider_log_size or
                    !std.mem.eql(
                        u8,
                        &self.identity_sha256,
                        &self.computeIdentity(),
                    ))
                {
                    return error.EthereumIncrementalRows10Through34MismatchV4;
                }
            }

            fn deriveAdmissionLogSizes(self: *const Storage) !LogSizesV4 {
                var result: LogSizesV4 = undefined;
                var at: usize = 0;

                const statement_logs = try self.statement.logSizesWithAdditionalStatementRows(self.row16.statementRouting().rowCount());
                @memcpy(result[at..][0..statement_logs.len], &statement_logs);
                at += statement_logs.len;

                var child_logs = try self.child.logSizes();
                child_logs[1] = std.math.log2_int_ceil(usize, self.materialized.schedule.calls.len + if (self.identity_hashes) |hashes| hashes.rows().len else 0);
                @memcpy(result[at..][0..child_logs.len], &child_logs);
                at += child_logs.len;

                result[at] = try self.row16.logSize();
                at += 1;
                const control_rows = (try self.row17.preprocessing()).rows.len;
                const field_rows = if (self.transcript) |program| if (program.field_plan) |plan| field_frame_routing.rowCount(plan) else 0 else 0;
                const identity_rows = if (self.identity_hashes) |hashes| hashes.phases()[1].preimage_word_count else 0;
                const publication_control_rows = try std.math.add(usize, control_rows, publication_words.ROW_COUNT + native_publication_words.ROW_COUNT + field_rows + identity_rows);
                result[at] = @max(try self.row17.logSize(), std.math.log2_int_ceil(usize, publication_control_rows));
                at += 1;

                const native_logs = try self.native.componentLogSizes();
                @memcpy(result[at..][0..native_logs.len], &native_logs);
                at += native_logs.len;
                if (at != result.len)
                    return error.EthereumIncrementalRows10Through34MismatchV4;
                return result;
            }

            fn computeIdentity(self: *const Storage) [32]u8 {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update(IDENTITY_DOMAIN);
                hashInt(&hash, u16, FORMAT_VERSION);
                hashInt(&hash, u16, SCHEMA_VERSION);
                hashInt(&hash, u32, FIRST_ROW);
                hashInt(&hash, u32, LAST_ROW);
                for (self.component_identities) |identity_sha256| hash.update(&identity_sha256);
                if (self.transcript) |program| if (program.field_plan != null) hash.update(&program.identity_sha256);
                hash.update(&self.complete_provider.identity_sha256);
                for (self.log_sizes) |log_size|
                    hashInt(&hash, u32, log_size);
                return hash.finalResult();
            }

            fn destroy(self: *Storage) void {
                const allocator = self.allocator;
                self.row17.deinit();
                self.row16.deinit();
                self.native.deinit();
                if (self.identity_hashes) |hashes| hashes.deinit();
                self.statement.deinit();
                self.child.deinit();
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

fn buildNativeIdentityHashes(allocator: std.mem.Allocator, materialized: anytype) !*native_identity_hash.OwnedPlan {
    const native = &materialized.base.input.stage101.statement;
    const view = try native.public_data.authenticatedView();
    const core_public = try frontend.air.statement_v2.canonicalCorePublicData(&native.public_data);
    return native_identity_hash.OwnedPlan.initAdmitted(allocator, native.public_data.words(), try frontend.recursion.segment_statement_v2_transcript_layout.Layout.fromView(&view), .{
        .initial_pc = core_public.initial_pc,
        .final_pc = core_public.final_pc,
        .cycle_count = core_public.clock,
        .wire_id = native.public_data.wireId(),
        .component_descs = native.core.component_descs[0..native.core.n_components],
        .infra_descs = native.core.infra_descs[0..native.core.n_infra],
    }, native.authority_id, @intCast(materialized.schedule.calls.len));
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 4 or FIRST_ROW != 10 or
        LAST_ROW != 34 or ROW_COUNT != 25 or
        !ROWS_10_THROUGH_34_AVAILABLE or
        !COMPLETE_PROVIDER_AUTHORITY_AVAILABLE or
        TRANSCRIPT_PREFIX_AVAILABLE or CLAIM_CLOSURE_AVAILABLE or
        PRODUCTION_ACTIVATION or manifest_mod.COMPONENT_COUNT != 36 or
        child_statement.FIRST_ROW != 10 or child_statement.LAST_ROW != 11 or
        child_public.FIRST_ROW != 12 or child_public.LAST_ROW != 15 or
        public_logup_input.UNIVERSAL_ROW != 16 or
        public_logup_control.UNIVERSAL_ROW != 17 or
        native_core.FIRST_ROW != 18 or native_core.LAST_ROW != 34)
    {
        @compileError("Ethereum incremental rows 10--34 owner drifted");
    }
}

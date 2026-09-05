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
pub const SCHEMA_VERSION: u16 = 3;
pub const FIRST_ROW: usize = 10;
pub const LAST_ROW: usize = 34;
pub const ROW_COUNT: usize = LAST_ROW - FIRST_ROW + 1;
pub const ROWS_10_THROUGH_34_AVAILABLE = true;
pub const COMPLETE_PROVIDER_AUTHORITY_AVAILABLE = true;
pub const TRANSCRIPT_PREFIX_AVAILABLE = false;
pub const CLAIM_CLOSURE_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-rows-10-34/v4-schema3\x00";

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
            return initWithLogSizes(allocator, materialized, null);
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
            );
        }

        fn initWithLogSizes(
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            requested_log_sizes: ?LogSizesV4,
        ) !*Self {
            try materialized.validate();

            const child = try ChildPublic.init(allocator, materialized);
            errdefer child.deinit();
            const statement = try ChildStatement.init(
                allocator,
                materialized,
                child,
            );
            errdefer statement.deinit();
            const native = if (requested_log_sizes) |logs|
                try Native.initForLogSizes(
                    allocator,
                    materialized,
                    child,
                    logs[8..][0..native_core.ROW_COUNT].*,
                )
            else
                try Native.init(allocator, materialized, child);
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
                .child = child,
                .statement = statement,
                .row16 = row16,
                .row17 = row17,
                .native = native,
                .log_sizes = undefined,
                .identity_sha256 = undefined,
            };
            backing.log_sizes = if (requested_log_sizes) |logs|
                logs
            else
                try backing.derivedPhysicalLogSizes();
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

        pub fn logSizes(self: *const Self) !LogSizesV4 {
            try self.validate();
            return storageConst(self).log_sizes;
        }

        pub fn completeProviderGeometry(
            self: *const Self,
        ) !CompleteProviderGeometryV4 {
            try self.validate();
            return storageConst(self).native.completeProviderGeometry();
        }

        pub fn childPublic(self: *const Self) !*const ChildPublic {
            try self.validate();
            return storageConst(self).child;
        }

        pub fn childStatement(self: *const Self) !*const ChildStatement {
            try self.validate();
            return storageConst(self).statement;
        }

        pub fn publicLogupInput(self: *const Self) !*const PublicInput {
            try self.validate();
            return storageConst(self).row16;
        }

        pub fn publicLogupControl(self: *const Self) !*const PublicControl {
            try self.validate();
            return storageConst(self).row17;
        }

        pub fn nativeCore(self: *const Self) !*const Native {
            try self.validate();
            return storageConst(self).native;
        }

        pub fn nativeCoreMutable(self: *Self) !*Native {
            try self.validate();
            return storage(self).native;
        }

        pub fn identity(self: *const Self) ![32]u8 {
            try self.validate();
            return storageConst(self).identity_sha256;
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            materialized: *const Materialized,
            child: *ChildPublic,
            statement: *ChildStatement,
            row16: *PublicInput,
            row17: *PublicControl,
            native: *Native,
            log_sizes: LogSizesV4,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                try self.materialized.validate();
                try self.child.validate();
                try self.statement.validate();
                try self.row16.validate();
                try self.row17.validate();
                try self.native.validate();

                const derived = try self.derivedPhysicalLogSizes();
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
                if (self.log_sizes[LAST_ROW - FIRST_ROW] !=
                    complete.provider_log_size or
                    !std.mem.eql(
                        u8,
                        &self.identity_sha256,
                        &(try self.computeIdentity()),
                    ))
                {
                    return error.EthereumIncrementalRows10Through34MismatchV4;
                }
            }

            fn derivedPhysicalLogSizes(self: *const Storage) !LogSizesV4 {
                var result: LogSizesV4 = undefined;
                var at: usize = 0;

                const statement_logs = try self.statement.logSizes();
                @memcpy(result[at..][0..statement_logs.len], &statement_logs);
                at += statement_logs.len;

                const child_logs = try self.child.logSizes();
                @memcpy(result[at..][0..child_logs.len], &child_logs);
                at += child_logs.len;

                result[at] = try self.row16.logSize();
                at += 1;
                result[at] = try self.row17.logSize();
                at += 1;

                const native_logs = try self.native.componentLogSizes();
                @memcpy(result[at..][0..native_logs.len], &native_logs);
                at += native_logs.len;
                if (at != result.len)
                    return error.EthereumIncrementalRows10Through34MismatchV4;
                return result;
            }

            fn computeIdentity(self: *const Storage) ![32]u8 {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update(IDENTITY_DOMAIN);
                hashInt(&hash, u16, FORMAT_VERSION);
                hashInt(&hash, u16, SCHEMA_VERSION);
                hashInt(&hash, u32, FIRST_ROW);
                hashInt(&hash, u32, LAST_ROW);
                hash.update(&self.materialized.identity_sha256);
                const child_binding = try self.child.binding();
                hash.update(&child_binding.identity_sha256);
                hash.update(&(try self.statement.identity()));
                hash.update(&(try self.row16.identity()));
                hash.update(&(try self.row17.identity()));
                hash.update(&(try self.native.authorityIdentity()));
                const complete = try self.native.completeProviderGeometry();
                hash.update(&complete.identity_sha256);
                for (self.log_sizes) |log_size|
                    hashInt(&hash, u32, log_size);
                return hash.finalResult();
            }

            fn destroy(self: *Storage) void {
                const allocator = self.allocator;
                self.row17.deinit();
                self.row16.deinit();
                self.native.deinit();
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

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or FIRST_ROW != 10 or
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

//! Verifier-owned universal row-17 control slice for an Ethereum V4 leaf.
//!
//! The preprocessing is selected from the same authenticated VM/recursion
//! schedule pair already retained by the native verifier core. No proof shape,
//! term count, or step sequence is accepted from the wrapper caller.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const native_core =
    @import("recursive_common_ethereum_incremental_leaf_native_core_v4.zig");

const control = frontend.recursion.air.control_slice_witness;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const UNIVERSAL_ROW: usize = 17;
pub const ROW_17_SOURCE_AVAILABLE = true;
pub const CALLER_AUTHORED_SCHEDULE_ADMITTED = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-public-logup-control/v4-schema3\x00";

pub const Error = error{
    EthereumIncrementalPublicLogupControlMismatchV4,
};

pub fn OwnerV4(comptime NativeOwner: type) type {
    return opaque {
        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            native: *const NativeOwner,
        ) !*Self {
            try native.validate();
            const plans = try native.scheduleView();
            try plans.validate();
            const backing = try allocator.create(Storage);
            errdefer allocator.destroy(backing);
            var preprocessing_value = try control.PublicLogupPreprocessed.init(
                allocator,
                plans.vm,
                plans.vm_public_term_count,
                plans.recursion,
                plans.recursion_public_term_count,
            );
            var preprocessing_owned = true;
            errdefer if (preprocessing_owned) preprocessing_value.deinit();
            backing.* = .{
                .allocator = allocator,
                .native = native,
                .preprocessing = preprocessing_value,
                .identity_sha256 = undefined,
            };
            preprocessing_owned = false;
            backing.identity_sha256 = backing.computeIdentity();
            errdefer backing.destroy();
            try backing.validate();
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroy();
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validate();
        }

        pub fn preprocessing(
            self: *const Self,
        ) !*const control.PublicLogupPreprocessed {
            try self.validate();
            return &storageConst(self).preprocessing;
        }

        pub fn logSize(self: *const Self) !u32 {
            try self.validate();
            return storageConst(self).preprocessing.log_size;
        }

        pub fn identity(self: *const Self) ![32]u8 {
            try self.validate();
            return storageConst(self).identity_sha256;
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            native: *const NativeOwner,
            preprocessing: control.PublicLogupPreprocessed,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                try self.native.validate();
                const plans = try self.native.scheduleView();
                try plans.validate();
                try self.preprocessing.validateAgainst(
                    plans.vm,
                    plans.recursion,
                );
                if (self.preprocessing.vm_public_term_count !=
                    plans.vm_public_term_count or
                    self.preprocessing.recursion_public_term_count !=
                        plans.recursion_public_term_count or
                    self.preprocessing.activeStepCount(.segment_leaf) == 0 or
                    !std.mem.eql(
                        u8,
                        &self.identity_sha256,
                        &self.computeIdentity(),
                    ))
                {
                    return error.EthereumIncrementalPublicLogupControlMismatchV4;
                }
            }

            fn computeIdentity(self: *const Storage) [32]u8 {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update(IDENTITY_DOMAIN);
                hashInt(&hash, u16, FORMAT_VERSION);
                hashInt(&hash, u16, SCHEMA_VERSION);
                hashInt(&hash, u32, UNIVERSAL_ROW);
                for (self.preprocessing.vm_schedule_digest) |word|
                    hashInt(&hash, u32, word);
                for (self.preprocessing.recursion_schedule_digest) |word|
                    hashInt(&hash, u32, word);
                hashInt(
                    &hash,
                    u32,
                    self.preprocessing.vm_public_term_count,
                );
                hashInt(
                    &hash,
                    u32,
                    self.preprocessing.recursion_public_term_count,
                );
                hashInt(&hash, u32, self.preprocessing.log_size);
                hashInt(
                    &hash,
                    u32,
                    @as(u32, @intCast(self.preprocessing.rows.len)),
                );
                return hash.finalResult();
            }

            fn destroy(self: *Storage) void {
                const allocator = self.allocator;
                self.preprocessing.deinit();
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
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or UNIVERSAL_ROW != 17 or
        !ROW_17_SOURCE_AVAILABLE or CALLER_AUTHORED_SCHEDULE_ADMITTED or
        PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental public LogUp control V4 drifted");
    }
    _ = native_core;
}

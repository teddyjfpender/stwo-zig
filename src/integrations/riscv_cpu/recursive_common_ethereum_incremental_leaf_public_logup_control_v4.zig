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
            // Native construction admits these fixed plan allocations; row17
            // owns its projection independently and never mutates either plan.
            const plans = try native.scheduleView();
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
                .plans = plans,
                .preprocessing = preprocessing_value,
                .identity_sha256 = undefined,
            };
            preprocessing_owned = false;
            backing.identity_sha256 = backing.computeIdentity();
            errdefer backing.preprocessing.deinit();
            try backing.validate();
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroy();
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validate();
        }

        /// Borrowed read-only projection of privately owned immutable rows.
        /// Full checks belong to construction and explicit validate boundaries.
        pub const PreprocessingView = struct {
            rows: []const control.Row,
            log_size: u32,
        };

        pub fn preprocessing(self: *const Self) !PreprocessingView {
            const value = storageConst(self);
            return .{ .rows = value.preprocessing.rows, .log_size = value.preprocessing.log_size };
        }

        pub fn logSize(self: *const Self) !u32 {
            return storageConst(self).preprocessing.log_size;
        }

        pub fn identity(self: *const Self) ![32]u8 {
            return storageConst(self).identity_sha256;
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            plans: native_core.ScheduleViewV4,
            preprocessing: control.PublicLogupPreprocessed,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                // The borrowed plans have stable lifetime and immutable native
                // ownership. Check our independently owned exact projection,
                // without walking back through native/campaign validation.
                const plans = self.plans;
                try self.preprocessing.validateAgainstSealedPlans(
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

test "Ethereum control preparation reads immutable rows without revisiting native validation" {
    const allocator = std.testing.allocator;
    const recursion = frontend.recursion;
    const schedule = recursion.air.verifier_schedule;
    const shape = recursion.fixed_profile.ProofShapeV1{
        .air_program_id = recursion.poseidon2_channel.hashBytes("control-owner-air", 0x5450),
        .preprocessing_id = recursion.poseidon2_channel.hashBytes("control-owner-preprocessing", 0x5450),
        .table_layout_id = recursion.poseidon2_channel.hashBytes("control-owner-layout", 0x5450),
        .table_count = 16,
        .claimed_sum_count = 4,
        .sampled_value_count = 8,
        .preprocessed_column_count = 4,
        .tree_column_counts = .{ 4, 4, 4, 4 },
        .tree_heights = .{ 9, 9, 9, 9 },
        .column_log_degree = 8,
        .proof_wire_bytes = 1024,
        .fri = try recursion.fixed_profile.FriSchedule.init(8, recursion.protocol.PCS_CONFIG.fri_config),
    };
    var vm = try schedule.Plan.init(allocator, try schedule.ProgramSpec.init(.vm, 3, 2, 3, 2), shape);
    defer vm.deinit();
    var recursive = try schedule.Plan.init(allocator, try schedule.ProgramSpec.init(.recursion, 3, 0, 4, 2), shape);
    defer recursive.deinit();
    const Native = struct {
        plans: native_core.ScheduleViewV4,
        reads: *usize,
        pub fn scheduleView(self: *const @This()) !native_core.ScheduleViewV4 {
            self.reads.* += 1;
            try self.plans.validate();
            return self.plans;
        }
    };
    var reads: usize = 0;
    const native = Native{ .plans = .{ .vm = &vm, .recursion = &recursive, .vm_public_term_count = 2, .recursion_public_term_count = 0 }, .reads = &reads };
    const Owner = OwnerV4(Native);
    const owner = try Owner.init(allocator, &native);
    defer owner.deinit();
    const expected_identity = try owner.identity();
    for (0..16) |_| {
        const view = try owner.preprocessing();
        try std.testing.expect(@typeInfo(@TypeOf(view.rows)).pointer.is_const);
        try std.testing.expect(view.rows.len != 0);
        try std.testing.expectEqual(view.log_size, try owner.logSize());
        try std.testing.expectEqual(expected_identity, try owner.identity());
    }
    try owner.validate();
    try std.testing.expectEqual(@as(usize, 1), reads);
    // Deliberate internal fault: explicit validation still checks exact rows.
    const backing = Owner.storage(owner);
    const original = backing.preprocessing.rows[0].sequence;
    backing.preprocessing.rows[0].sequence += 1;
    try std.testing.expectError(error.ScheduleAuthorityMismatch, owner.validate());
    backing.preprocessing.rows[0].sequence = original;
    try owner.validate();
}

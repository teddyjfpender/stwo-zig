//! Owned, duplicate-preserving successful signer-recovery call storage.

const std = @import("std");
const abi = @import("../../isa/ethereum_signer_recovery.zig");

/// A call multiplicity must remain representable as a canonical M31 value.
pub const max_calls: usize = 0x7fff_fffe;

/// Exact successful-call authority consumed by the Ethereum recovery AIR.
pub const Record = struct {
    execution_clock: u32,
    pc: u32,
    io_ptr: u32,
    pointer_register: u5,
    pointer_previous_clock: u32,
    digest_big_endian: [abi.digest_size]u8,
    r_big_endian: [abi.scalar_size]u8,
    s_big_endian: [abi.scalar_size]u8,
    recovery_id: u32,
    public_key_xy_big_endian: [abi.public_key_size]u8,
    status: u32,
    input_previous_clocks: [abi.input_word_count]u32,
    output_previous_words: [abi.output_word_count]u32,
    output_previous_clocks: [abi.output_word_count]u32,
};

pub const Frozen = struct {
    storage: std.ArrayList(Record),
    allocator: std.mem.Allocator,
    allocation_growths: usize,

    pub fn records(self: *const Frozen) []const Record {
        return self.storage.items;
    }

    pub fn len(self: *const Frozen) usize {
        return self.storage.items.len;
    }

    pub fn capacity(self: *const Frozen) usize {
        return self.storage.capacity;
    }

    pub fn deinit(self: *Frozen) void {
        self.storage.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const Builder = struct {
    storage: std.ArrayList(Record) = .empty,
    allocator: std.mem.Allocator,
    limit: usize,
    allocation_growths: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        limit: usize,
    ) error{PrecompileCallLimitExceeded}!Builder {
        if (limit > max_calls) return error.PrecompileCallLimitExceeded;
        return .{ .allocator = allocator, .limit = limit };
    }

    pub fn deinit(self: *Builder) void {
        self.storage.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const Builder) usize {
        return self.storage.items.len;
    }

    pub fn records(self: *const Builder) []const Record {
        return self.storage.items;
    }

    pub fn reserveOne(self: *Builder) error{ OutOfMemory, PrecompileCallLimitExceeded }!void {
        if (self.storage.items.len >= self.limit)
            return error.PrecompileCallLimitExceeded;
        const old_capacity = self.storage.capacity;
        try self.storage.ensureUnusedCapacity(self.allocator, 1);
        if (self.storage.capacity != old_capacity) self.allocation_growths += 1;
    }

    pub fn appendAssumeCapacity(self: *Builder, record: Record) void {
        std.debug.assert(self.storage.items.len < self.limit);
        self.storage.appendAssumeCapacity(record);
    }

    pub fn freeze(self: *Builder) Frozen {
        const frozen = Frozen{
            .storage = self.storage,
            .allocator = self.allocator,
            .allocation_growths = self.allocation_growths,
        };
        self.storage = .empty;
        self.limit = 0;
        self.allocation_growths = 0;
        return frozen;
    }
};

fn testRecord(clock: u32) Record {
    return .{
        .execution_clock = clock,
        .pc = 0x1000 + 4 * clock,
        .io_ptr = 0x2000,
        .pointer_register = 5,
        .pointer_previous_clock = clock -| 1,
        .digest_big_endian = .{0} ** abi.digest_size,
        .r_big_endian = .{1} ** abi.scalar_size,
        .s_big_endian = .{2} ** abi.scalar_size,
        .recovery_id = 1,
        .public_key_xy_big_endian = .{3} ** abi.public_key_size,
        .status = abi.success_status,
        .input_previous_clocks = .{0} ** abi.input_word_count,
        .output_previous_words = .{0} ** abi.output_word_count,
        .output_previous_clocks = .{0} ** abi.output_word_count,
    };
}

test "signer-recovery call buffer preserves duplicate execution order" {
    var builder = try Builder.init(std.testing.allocator, 2);
    defer builder.deinit();
    const record = testRecord(1);
    try builder.reserveOne();
    builder.appendAssumeCapacity(record);
    try builder.reserveOne();
    builder.appendAssumeCapacity(record);

    var frozen = builder.freeze();
    defer frozen.deinit();
    try std.testing.expectEqual(@as(usize, 2), frozen.len());
    try std.testing.expectEqual(record, frozen.records()[0]);
    try std.testing.expectEqual(record, frozen.records()[1]);
}

test "signer-recovery call buffer limit fails before append" {
    var builder = try Builder.init(std.testing.allocator, 0);
    defer builder.deinit();
    try std.testing.expectError(error.PrecompileCallLimitExceeded, builder.reserveOne());
    try std.testing.expectEqual(@as(usize, 0), builder.len());
}

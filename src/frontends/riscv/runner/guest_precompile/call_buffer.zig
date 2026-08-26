//! Owned, duplicate-preserving guest Poseidon2 call storage.
//!
//! The mutable builder belongs to extension execution. `freeze` transfers its
//! allocation without copying or shrinking, so successful execution cannot
//! acquire a new failure point while handing immutable records to the prover.

const std = @import("std");

pub const lane_count: usize = 16;

/// `n_guest < p` is required when lifting M31 multiplicities back to integers.
pub const max_calls: usize = 0x7fff_fffe;

pub const Record = struct {
    execution_clock: u32,
    pc: u32,
    state_ptr: u32,
    pointer_register: u5,
    pointer_previous_clock: u32,
    input: [lane_count]u32,
    output: [lane_count]u32,
    memory_previous_clocks: [lane_count]u32,
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

    pub fn init(allocator: std.mem.Allocator, limit: usize) error{PrecompileCallLimitExceeded}!Builder {
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

    /// Complete the only fallible append work. Capacity growth is diagnostic
    /// state only and may remain after a later prepare-stage failure.
    pub fn reserveOne(self: *Builder) (error{ OutOfMemory, PrecompileCallLimitExceeded })!void {
        if (self.storage.items.len >= self.limit)
            return error.PrecompileCallLimitExceeded;
        const old_capacity = self.storage.capacity;
        try self.storage.ensureUnusedCapacity(self.allocator, 1);
        if (self.storage.capacity != old_capacity) self.allocation_growths += 1;
    }

    /// Commit one prepared record. `reserveOne` must have succeeded and no
    /// intervening append may occur.
    pub fn appendAssumeCapacity(self: *Builder, record: Record) void {
        std.debug.assert(self.storage.items.len < self.limit);
        self.storage.appendAssumeCapacity(record);
    }

    /// Transfer ownership without allocation. The moved-from builder remains
    /// a canonical empty value that is safe to deinitialize.
    pub fn freeze(self: *Builder) Frozen {
        const result = Frozen{
            .storage = self.storage,
            .allocator = self.allocator,
            .allocation_growths = self.allocation_growths,
        };
        self.storage = .empty;
        self.limit = 0;
        self.allocation_growths = 0;
        return result;
    }
};

fn testRecord(clock: u32, marker: u32) Record {
    return .{
        .execution_clock = clock,
        .pc = 0x1000 + 4 * clock,
        .state_ptr = 0x2000,
        .pointer_register = 5,
        .pointer_previous_clock = clock -| 1,
        .input = .{marker} ** lane_count,
        .output = .{marker +% 1} ** lane_count,
        .memory_previous_clocks = .{clock -| 1} ** lane_count,
    };
}

test "guest call buffer canonical empty freeze owns no allocation" {
    var builder = try Builder.init(std.testing.allocator, 8);
    defer builder.deinit();
    var frozen = builder.freeze();
    defer frozen.deinit();

    try std.testing.expectEqual(@as(usize, 0), frozen.len());
    try std.testing.expectEqual(@as(usize, 0), frozen.capacity());
    try std.testing.expectEqual(@as(usize, 0), frozen.allocation_growths);
    try std.testing.expectEqual(@as(usize, 0), builder.len());
}

test "guest call buffer preserves execution order and duplicate records" {
    var builder = try Builder.init(std.testing.allocator, 3);
    defer builder.deinit();
    const duplicate = testRecord(1, 7);
    try builder.reserveOne();
    builder.appendAssumeCapacity(duplicate);
    try builder.reserveOne();
    builder.appendAssumeCapacity(duplicate);
    try builder.reserveOne();
    builder.appendAssumeCapacity(testRecord(2, 9));

    var frozen = builder.freeze();
    defer frozen.deinit();
    try std.testing.expectEqual(@as(usize, 3), frozen.len());
    try std.testing.expectEqual(duplicate, frozen.records()[0]);
    try std.testing.expectEqual(duplicate, frozen.records()[1]);
    try std.testing.expectEqual(@as(u32, 2), frozen.records()[2].execution_clock);
}

test "guest call buffer bounds capacity and does not append on allocation failure" {
    var limited = try Builder.init(std.testing.allocator, 1);
    defer limited.deinit();
    try limited.reserveOne();
    limited.appendAssumeCapacity(testRecord(1, 0));
    try std.testing.expectError(error.PrecompileCallLimitExceeded, limited.reserveOne());
    try std.testing.expectEqual(@as(usize, 1), limited.len());

    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var fallible = try Builder.init(failing.allocator(), 1);
    defer fallible.deinit();
    try std.testing.expectError(error.OutOfMemory, fallible.reserveOne());
    try std.testing.expectEqual(@as(usize, 0), fallible.len());
    try std.testing.expectEqual(@as(usize, 0), fallible.allocation_growths);
}

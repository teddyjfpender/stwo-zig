//! Owned, duplicate-preserving Keccak-f call storage.
//!
//! Fifty little-endian words represent the 25 `u64` state lanes.  Keeping the
//! wide values outside ordinary execution rows prevents the base trace from
//! paying for an extension it does not use.

const std = @import("std");
const authority = @import("../../air/guest_precompile/keccakf_authority.zig");

pub const word_count: usize = 50;
pub const max_calls: usize = authority.candidate.maximum_calls;

pub const Record = struct {
    execution_clock: u32,
    pc: u32,
    state_ptr: u32,
    pointer_register: u5,
    pointer_previous_clock: u32,
    input: [word_count]u32,
    output: [word_count]u32,
    memory_previous_clocks: [word_count]u32,
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

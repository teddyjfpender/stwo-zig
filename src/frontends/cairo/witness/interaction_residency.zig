//! Backend-neutral ownership for retained Cairo lookup feeds.

const std = @import("std");

pub const Residency = struct {
    identity: u64,
    context: *anyopaque,
};

pub const LookupAllocationRequest = struct {
    rows: usize,
    word_columns: usize,
    interaction_columns: usize,
};

pub const LookupAllocation = struct {
    words: []u32,
    residency: Residency,
    context: *anyopaque,
    deinit_fn: *const fn (context: *anyopaque) void,

    pub fn deinit(self: *LookupAllocation) void {
        self.deinit_fn(self.context);
        self.* = undefined;
    }
};

pub const RetainedLookup = struct {
    words: []u32,
    allocation: ?LookupAllocation = null,

    pub fn deinit(self: *RetainedLookup, allocator: std.mem.Allocator) void {
        if (self.allocation) |*allocation|
            allocation.deinit()
        else
            allocator.free(self.words);
        self.* = undefined;
    }

    pub fn residency(self: RetainedLookup) ?Residency {
        return if (self.allocation) |allocation| allocation.residency else null;
    }
};

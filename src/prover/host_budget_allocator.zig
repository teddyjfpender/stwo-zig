//! Coordinator-only allocator wrapper for hard per-plan host-memory limits.
//!
//! Composition planning is single-threaded and routes every owned heap buffer
//! through this wrapper before workers launch. Helper-thread stacks and fixed
//! submission envelopes are reserved separately by the caller because they
//! belong to the shared pool, not to the child allocator.

const std = @import("std");

pub const HostBudgetAllocator = struct {
    child: std.mem.Allocator,
    limit: usize,
    live_bytes: usize = 0,
    peak_live_bytes: usize = 0,
    budget_exceeded: bool = false,

    pub fn init(child: std.mem.Allocator, limit: usize) HostBudgetAllocator {
        return .{ .child = child, .limit = limit };
    }

    pub fn allocator(self: *@This()) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    pub fn didExceedBudget(self: *const @This()) bool {
        return self.budget_exceeded;
    }

    fn admitsGrowth(self: *@This(), growth: usize) bool {
        if (growth > self.limit -| self.live_bytes) {
            self.budget_exceeded = true;
            return false;
        }
        return true;
    }

    fn recordGrowth(self: *@This(), growth: usize) void {
        self.live_bytes += growth;
        self.peak_live_bytes = @max(self.peak_live_bytes, self.live_bytes);
    }

    fn alloc(
        context: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *HostBudgetAllocator = @ptrCast(@alignCast(context));
        if (!self.admitsGrowth(len)) return null;
        const result = self.child.rawAlloc(len, alignment, return_address) orelse return null;
        self.recordGrowth(len);
        return result;
    }

    fn resize(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        const self: *HostBudgetAllocator = @ptrCast(@alignCast(context));
        const growth = new_len -| memory.len;
        if (!self.admitsGrowth(growth)) return false;
        if (!self.child.rawResize(memory, alignment, new_len, return_address)) return false;
        if (new_len >= memory.len) {
            self.recordGrowth(growth);
        } else {
            self.live_bytes -= memory.len - new_len;
        }
        return true;
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        const self: *HostBudgetAllocator = @ptrCast(@alignCast(context));
        const growth = new_len -| memory.len;
        if (!self.admitsGrowth(growth)) return null;
        const result = self.child.rawRemap(
            memory,
            alignment,
            new_len,
            return_address,
        ) orelse return null;
        if (new_len >= memory.len) {
            self.recordGrowth(growth);
        } else {
            self.live_bytes -= memory.len - new_len;
        }
        return result;
    }

    fn free(
        context: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *HostBudgetAllocator = @ptrCast(@alignCast(context));
        std.debug.assert(memory.len <= self.live_bytes);
        self.child.rawFree(memory, alignment, return_address);
        self.live_bytes -= memory.len;
    }
};

test "host budget allocator admits the exact live-byte boundary" {
    var bounded = HostBudgetAllocator.init(std.testing.allocator, 48);
    const allocator = bounded.allocator();
    const first = try allocator.alloc(u8, 32);
    defer allocator.free(first);
    const second = try allocator.alloc(u8, 16);
    try std.testing.expectEqual(@as(usize, 48), bounded.live_bytes);
    try std.testing.expectEqual(@as(usize, 48), bounded.peak_live_bytes);
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 1));
    try std.testing.expect(bounded.didExceedBudget());
    allocator.free(second);
    const replacement = try allocator.alloc(u8, 1);
    allocator.free(replacement);
    try std.testing.expectEqual(@as(usize, 48), bounded.peak_live_bytes);
}

test "host budget allocator distinguishes child exhaustion from its limit" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = 0,
    });
    var bounded = HostBudgetAllocator.init(failing.allocator(), 1024);
    try std.testing.expectError(error.OutOfMemory, bounded.allocator().alloc(u8, 1));
    try std.testing.expect(!bounded.didExceedBudget());
    try std.testing.expectEqual(@as(usize, 0), bounded.live_bytes);
}

test "host budget allocator accounts in-place resize and remap" {
    var storage: [128]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    var bounded = HostBudgetAllocator.init(fixed.allocator(), 64);
    const allocator = bounded.allocator();

    var memory = try allocator.alloc(u8, 32);
    try std.testing.expect(allocator.resize(memory, 48));
    memory.len = 48;
    try std.testing.expectEqual(@as(usize, 48), bounded.live_bytes);
    try std.testing.expect(allocator.resize(memory, 24));
    memory.len = 24;
    try std.testing.expectEqual(@as(usize, 24), bounded.live_bytes);

    memory = allocator.remap(memory, 40).?;
    try std.testing.expectEqual(@as(usize, 40), bounded.live_bytes);
    try std.testing.expectEqual(@as(usize, 48), bounded.peak_live_bytes);
    try std.testing.expect(allocator.remap(memory, 65) == null);
    try std.testing.expect(bounded.didExceedBudget());
    try std.testing.expectEqual(@as(usize, 40), bounded.live_bytes);

    allocator.free(memory);
    try std.testing.expectEqual(@as(usize, 0), bounded.live_bytes);
}

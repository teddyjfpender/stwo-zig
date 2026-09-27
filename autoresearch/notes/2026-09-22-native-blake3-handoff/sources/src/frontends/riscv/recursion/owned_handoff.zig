//! Bounded FIFO ownership transfer. This bounds queued payload, not process RSS.
const std = @import("std");

/// T supplies retainedBytes() !usize and deinit(). Its allocations must support
/// destruction on any participating thread. Queue addresses must remain stable.
pub fn Handoff(comptime T: type) type {
    return struct {
        const Self = @This();
        const Entry = struct { value: T, bytes: usize };
        allocator: std.mem.Allocator,
        slots: []?Entry,
        byte_limit: usize,
        bytes: usize = 0,
        head: usize = 0,
        count: usize = 0,
        closed: bool = false,
        cancelled: bool = false,
        mutex: std.Thread.Mutex = .{},
        changed: std.Thread.Condition = .{},

        pub fn init(a: std.mem.Allocator, capacity: usize, byte_limit: usize) !Self {
            if (capacity == 0 or byte_limit == 0) return error.InvalidHandoffLimits;
            const slots = try a.alloc(?Entry, capacity);
            @memset(slots, null);
            return .{ .allocator = a, .slots = slots, .byte_limit = byte_limit };
        }

        /// Join all participating threads before destruction.
        pub fn deinit(self: *Self) void {
            self.cancel();
            self.allocator.free(self.slots);
            self.* = undefined;
        }

        /// Failure preserves the caller's owner. Success clears it. The producer
        /// may retain one additional prepared value while blocked here; callers
        /// must reserve that memory separately from this queue's byte limit.
        pub fn send(self: *Self, value: *?T) !void {
            const size = try (value.* orelse return error.EmptyHandoffValue).retainedBytes();
            if (size > self.byte_limit) return error.HandoffValueTooLarge;
            self.mutex.lock();
            defer self.mutex.unlock();
            while (!self.closed and (self.count == self.slots.len or self.bytes > self.byte_limit - size))
                self.changed.wait(&self.mutex);
            if (self.closed) return error.HandoffClosed;
            const tail = (self.head + self.count) % self.slots.len;
            self.slots[tail] = .{ .value = value.*.?, .bytes = size };
            value.* = null;
            self.count += 1;
            self.bytes += size;
            self.changed.broadcast();
        }

        /// Returns null after graceful draining or immediately on cancellation.
        /// The consumer owns each received value, including its memory charge.
        pub fn receive(self: *Self) ?T {
            self.mutex.lock();
            defer self.mutex.unlock();
            while (self.count == 0 and !self.closed) self.changed.wait(&self.mutex);
            if (self.cancelled or self.count == 0) return null;
            return self.popLocked();
        }

        pub fn close(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.closed = true;
            self.changed.broadcast();
        }

        /// Wakes all waiters and destroys queued values outside the mutex.
        /// A value already received remains exclusively owned by its consumer.
        pub fn cancel(self: *Self) void {
            self.mutex.lock();
            self.closed = true;
            self.cancelled = true;
            self.changed.broadcast();
            self.mutex.unlock();
            while (true) {
                self.mutex.lock();
                const value = if (self.count == 0) null else self.popLocked();
                self.mutex.unlock();
                var owned = value orelse break;
                owned.deinit();
            }
        }

        fn popLocked(self: *Self) T {
            const entry = self.slots[self.head].?;
            self.slots[self.head] = null;
            self.head = (self.head + 1) % self.slots.len;
            self.count -= 1;
            self.bytes -= entry.bytes;
            self.changed.broadcast();
            return entry.value;
        }
    };
}

const Item = struct {
    id: usize,
    bytes: usize,
    destroyed: *std.atomic.Value(usize),
    pub fn retainedBytes(self: Item) !usize {
        return self.bytes;
    }
    pub fn deinit(self: *Item) void {
        _ = self.destroyed.fetchAdd(1, .monotonic);
    }
};

test "owned handoff FIFO wrapping close and byte admission" {
    var destroyed = std.atomic.Value(usize).init(0);
    var queue = try Handoff(Item).init(std.testing.allocator, 2, 8);
    defer queue.deinit();
    for (0..4) |id| {
        var value: ?Item = .{ .id = id, .bytes = 8, .destroyed = &destroyed };
        try queue.send(&value);
        try std.testing.expect(value == null);
        try std.testing.expectEqual(@as(usize, 8), queue.bytes);
        var received = queue.receive().?;
        try std.testing.expectEqual(id, received.id);
        received.deinit();
    }
    var oversized: ?Item = .{ .id = 4, .bytes = 9, .destroyed = &destroyed };
    try std.testing.expectError(error.HandoffValueTooLarge, queue.send(&oversized));
    try std.testing.expect(oversized != null);
    oversized.?.deinit();
    var last: ?Item = .{ .id = 5, .bytes = 8, .destroyed = &destroyed };
    try queue.send(&last);
    queue.close();
    var received = queue.receive().?;
    received.deinit();
    try std.testing.expect(queue.receive() == null);
    try std.testing.expectEqual(@as(usize, 6), destroyed.load(.monotonic));
}

test "owned handoff cancellation wakes producer and destroys queued ownership" {
    var destroyed = std.atomic.Value(usize).init(0);
    var queue = try Handoff(Item).init(std.testing.allocator, 2, 8);
    defer queue.deinit();
    var first: ?Item = .{ .id = 0, .bytes = 8, .destroyed = &destroyed };
    try queue.send(&first);
    const Worker = struct {
        fn run(q: *Handoff(Item), drops: *std.atomic.Value(usize)) void {
            var next: ?Item = .{ .id = 1, .bytes = 1, .destroyed = drops };
            q.send(&next) catch |err| {
                std.debug.assert(err == error.HandoffClosed);
                next.?.deinit();
                return;
            };
            @panic("cancelled send unexpectedly succeeded");
        }
    };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{ &queue, &destroyed });
    queue.cancel();
    thread.join();
    try std.testing.expect(queue.receive() == null);
    try std.testing.expectEqual(@as(usize, 0), queue.bytes);
    try std.testing.expectEqual(@as(usize, 2), destroyed.load(.monotonic));
}

test "owned handoff allocation failure and invalid limits" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, Handoff(Item).init(failing.allocator(), 1, 1));
    try std.testing.expectError(error.InvalidHandoffLimits, Handoff(Item).init(std.testing.allocator, 0, 1));
}

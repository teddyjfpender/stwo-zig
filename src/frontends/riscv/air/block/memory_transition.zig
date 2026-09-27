//! Bounded sorted-memory transition reader. The input is the externally sorted
//! runner event stream; first values come from independently admitted initial
//! state. These rows are witnesses, not proof authority. Execution/precompile
//! tuples, initialization and adjacency must all be constrained in the block AIR.
const std = @import("std");
const spool = @import("memory_spool.zig");
const event = @import("memory_event.zig");
const order = @import("memory_order.zig");

pub const Initial = struct {
    context: *anyopaque,
    load: *const fn (context: *anyopaque, space: u1, address: u32) anyerror!u32,
};

pub const Transition = struct {
    space: u1,
    address: u32,
    clock: u64,
    before: u32,
    after: u32,
    pub fn beforePoint(self: Transition) order.Point {
        return .{ .space = self.space, .address = self.address, .clock = self.clock, .value = self.before };
    }
    pub fn afterPoint(self: Transition) order.Point {
        return .{ .space = self.space, .address = self.address, .clock = self.clock, .value = self.after };
    }
};

pub const Reader = struct {
    sorted: spool.Reader,
    initial: Initial,
    previous: ?event.Event = null,
    count: u64 = 0,
    poisoned: bool = false,
    pub fn next(self: *Reader) !?Transition {
        if (self.poisoned) return error.InvalidMemoryTransitionReader;
        errdefer self.poisoned = true;
        const current = try self.sorted.next() orelse return null;
        if (self.previous) |prior| if (!event.Event.lessThan({}, prior, current)) return error.InvalidSortedMemoryStream;
        const before = if (self.previous) |prior| if (prior.key() == current.key()) prior.value else try self.initial.load(self.initial.context, current.space, current.address) else try self.initial.load(self.initial.context, current.space, current.address);
        self.previous = current;
        self.count = try std.math.add(u64, self.count, 1);
        return .{ .space = current.space, .address = current.address, .clock = current.clock, .before = before, .after = current.value };
    }
    pub fn deinit(self: *Reader) void {
        self.sorted.deinit();
        self.* = undefined;
    }
};

pub fn adjacency(previous: Transition, current: Transition) !order.Row {
    return order.witness(previous.afterPoint(), current.beforePoint());
}

test "sorted real memory accesses reconstruct before and after values across writes" {
    const a = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    var tracker = @import("../../runner/state_chain.zig").StateChainTracker.init(a);
    defer tracker.deinit();
    try tracker.recordMemTransition(0x2000, 1, 7, 9);
    try tracker.recordMemTransition(0x2000, 5, 9, 11);
    var writer = try spool.Spool.init(a, dir.dir, 2);
    defer writer.deinit();
    try writer.appendSegment(.{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 2 }, tracker.accesses.items);
    const Loader = struct {
        fn load(_: *anyopaque, space: u1, address: u32) anyerror!u32 {
            if (space != 1 or address != 0x2000) return error.MissingInitialMemoryValue;
            return 7;
        }
    };
    var context: u8 = 0;
    var reader = Reader{ .sorted = try writer.finish(), .initial = .{ .context = &context, .load = Loader.load } };
    defer reader.deinit();
    const first = (try reader.next()).?;
    const second = (try reader.next()).?;
    try std.testing.expectEqual(@as(u32, 7), first.before);
    try std.testing.expectEqual(@as(u32, 9), first.after);
    try std.testing.expectEqual(@as(u32, 9), second.before);
    try std.testing.expectEqual(@as(u32, 11), second.after);
    _ = try adjacency(first, second);
    try std.testing.expectEqual(@as(?Transition, null), try reader.next());
    try std.testing.expectEqual(@as(u64, 2), reader.count);
}

test "new sorted address requires an independently supplied initial value" {
    const a = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    var writer = try spool.Spool.init(a, dir.dir, 2);
    defer writer.deinit();
    try writer.append(.{ .space = 1, .address = 0x2000, .clock = 1, .value = 9 });
    const Loader = struct {
        fn load(_: *anyopaque, _: u1, _: u32) anyerror!u32 {
            return error.MissingInitialMemoryValue;
        }
    };
    var context: u8 = 0;
    var reader = Reader{ .sorted = try writer.finish(), .initial = .{ .context = &context, .load = Loader.load } };
    defer reader.deinit();
    try std.testing.expectError(error.MissingInitialMemoryValue, reader.next());
    try std.testing.expectError(error.InvalidMemoryTransitionReader, reader.next());
    try std.testing.expectEqual(@as(u64, 0), reader.count);
}

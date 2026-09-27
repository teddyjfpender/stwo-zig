//! Streaming, exact-count partition of the sorted block-memory witness.
//! Each instance carries its first predecessor link, even when that link crosses
//! an instance boundary. These rows still require PCS commitments and AIR
//! relation closure before they can be accepted as proof authority.
const std = @import("std");
const transition = @import("memory_transition.zig");
const order = @import("memory_order.zig");

pub const Sink = struct {
    context: *anyopaque,
    append: *const fn (context: *anyopaque, item: transition.Transition, link: ?order.Row) anyerror!void,
};

pub const Summary = struct {
    first_row: u64,
    rows: u32,
    first: transition.Transition,
    last: transition.Transition,
    pub fn endRow(self: Summary) u64 {
        return self.first_row + self.rows;
    }
};

pub const Partitioner = struct {
    reader: *transition.Reader,
    expected_rows: u64,
    instance_capacity: u32,
    capacity_plan: ?[]const u32 = null,
    capacity_index: usize = 0,
    emitted: u64 = 0,
    previous: ?transition.Transition = null,
    finished: bool = false,
    poisoned: bool = false,

    pub fn init(reader: *transition.Reader, expected_rows: u64, instance_capacity: u32) !Partitioner {
        if (expected_rows == 0 or instance_capacity == 0 or instance_capacity > (1 << 30) or
            !std.math.isPowerOfTwo(instance_capacity)) return error.InvalidMemoryInstancePlan;
        return .{ .reader = reader, .expected_rows = expected_rows, .instance_capacity = instance_capacity };
    }
    /// Borrowed exact AIR-size roster. A replay must use the same capacities
    /// as the first-round commitments; a trailing unused instance is invalid.
    pub fn initPlanned(reader: *transition.Reader, expected_rows: u64, capacities: []const u32) !Partitioner {
        if (expected_rows == 0 or capacities.len == 0) return error.InvalidMemoryInstancePlan;
        var coverage: u64 = 0;
        for (capacities, 0..) |capacity, index| {
            if (capacity == 0 or capacity > 1 << 30 or !std.math.isPowerOfTwo(capacity) or
                (index + 1 < capacities.len and coverage >= expected_rows))
                return error.InvalidMemoryInstancePlan;
            coverage = std.math.add(u64, coverage, capacity) catch return error.InvalidMemoryInstancePlan;
        }
        if (coverage < expected_rows or coverage - capacities[capacities.len - 1] >= expected_rows)
            return error.InvalidMemoryInstancePlan;
        return .{ .reader = reader, .expected_rows = expected_rows, .instance_capacity = capacities[0], .capacity_plan = capacities };
    }

    pub fn currentCapacity(self: *const Partitioner) !u32 {
        if (self.capacity_plan) |capacities| {
            if (self.capacity_index >= capacities.len) return error.InvalidMemoryInstancePlan;
            return capacities[self.capacity_index];
        }
        return self.instance_capacity;
    }

    /// Calls the sink exactly once per real event; padding is the component's
    /// responsibility. The caller must discard any partial sink output on
    /// failure. A failure poisons the partitioner and withholds its summary.
    pub fn next(self: *Partitioner, sink: Sink) !?Summary {
        if (self.poisoned) return error.InvalidMemoryInstancePhase;
        if (self.finished) return null;
        errdefer self.poisoned = true;
        if (self.emitted == self.expected_rows) {
            if (self.capacity_plan) |capacities| if (self.capacity_index != capacities.len)
                return error.InvalidMemoryInstancePlan;
            if (try self.reader.next() != null) return error.MemoryEventCensusOverflow;
            self.finished = true;
            return null;
        }
        const first_row = self.emitted;
        const capacity = try self.currentCapacity();
        const take: u32 = @intCast(@min(self.expected_rows - self.emitted, capacity));
        var first: ?transition.Transition = null;
        var last: transition.Transition = undefined;
        for (0..take) |_| {
            const item = (try self.reader.next()) orelse return error.MemoryEventCensusUnderflow;
            const link = if (self.previous) |prior| try transition.adjacency(prior, item) else null;
            try sink.append(sink.context, item, link);
            if (first == null) first = item;
            self.previous = item;
            last = item;
            self.emitted += 1;
        }
        // Never publish a final instance summary before checking that the
        // underlying event stream contains exactly the admitted census.
        if (self.capacity_plan) |capacities| {
            self.capacity_index += 1;
            if (self.emitted < self.expected_rows and self.capacity_index == capacities.len)
                return error.InvalidMemoryInstancePlan;
        }
        if (self.emitted == self.expected_rows) {
            if (self.capacity_plan) |capacities| if (self.capacity_index != capacities.len)
                return error.InvalidMemoryInstancePlan;
            if (try self.reader.next() != null) return error.MemoryEventCensusOverflow;
            self.finished = true;
        }
        return .{ .first_row = first_row, .rows = take, .first = first.?, .last = last };
    }
};

test "memory instances preserve every cross-boundary link without proof-count rounding" {
    const spool = @import("memory_spool.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var writer = try spool.Spool.init(std.testing.allocator, tmp.dir, 2);
    defer writer.deinit();
    for (0..5) |i| try writer.append(.{ .space = 1, .address = 4096, .clock = @as(u64, @intCast(i)) * 4 + 1, .value = @intCast(i + 1) });
    const Loader = struct {
        fn load(_: *anyopaque, _: u1, _: u32) anyerror!u32 {
            return 0;
        }
    };
    var context: u8 = 0;
    var reader = transition.Reader{ .sorted = try writer.finish(), .initial = .{ .context = &context, .load = Loader.load } };
    defer reader.deinit();
    const Recorder = struct {
        count: u64 = 0,
        linked: u64 = 0,
        fn append(pointer: *anyopaque, item: transition.Transition, link: ?order.Row) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(pointer));
            try std.testing.expectEqual(@as(u32, @intCast(self.count)), item.before);
            self.count += 1;
            if (link != null) self.linked += 1;
        }
    };
    var recorder = Recorder{};
    var partitioner = try Partitioner.init(&reader, 5, 2);
    const sink = Sink{ .context = &recorder, .append = Recorder.append };
    for ([_]u32{ 2, 2, 1 }, 0..) |expected, index| {
        const part = (try partitioner.next(sink)).?;
        try std.testing.expectEqual(expected, part.rows);
        try std.testing.expectEqual(@as(u64, @intCast(index * 2)), part.first_row);
    }
    try std.testing.expectEqual(@as(?Summary, null), try partitioner.next(sink));
    try std.testing.expectEqual(@as(?Summary, null), try partitioner.next(sink));
    try std.testing.expectEqual(@as(u64, 5), recorder.count);
    try std.testing.expectEqual(@as(u64, 4), recorder.linked);
}

test "planned memory AIR sizes preserve the ordered census and reject unused instances" {
    const spool = @import("memory_spool.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var writer = try spool.Spool.init(std.testing.allocator, tmp.dir, 4);
    defer writer.deinit();
    for (0..9) |i| try writer.append(.{ .space = 1, .address = 4096, .clock = @as(u64, @intCast(i)) * 4 + 1, .value = @intCast(i + 1) });
    const Loader = struct {
        fn load(_: *anyopaque, _: u1, _: u32) anyerror!u32 {
            return 0;
        }
    };
    const Count = struct {
        rows: u32 = 0,
        fn append(context: *anyopaque, _: transition.Transition, _: ?order.Row) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.rows += 1;
        }
    };
    var context: u8 = 0;
    var reader = transition.Reader{ .sorted = try writer.finish(), .initial = .{ .context = &context, .load = Loader.load } };
    defer reader.deinit();
    var partitioner = try Partitioner.initPlanned(&reader, 9, &.{ 8, 4 });
    var count = Count{};
    const sink = Sink{ .context = &count, .append = Count.append };
    try std.testing.expectEqual(@as(u32, 8), try partitioner.currentCapacity());
    try std.testing.expectEqual(@as(u32, 8), (try partitioner.next(sink)).?.rows);
    try std.testing.expectEqual(@as(u32, 4), try partitioner.currentCapacity());
    try std.testing.expectEqual(@as(u32, 1), (try partitioner.next(sink)).?.rows);
    try std.testing.expectEqual(@as(?Summary, null), try partitioner.next(sink));
    try std.testing.expectEqual(@as(u32, 9), count.rows);
    try std.testing.expectError(error.InvalidMemoryInstancePlan, Partitioner.initPlanned(&reader, 9, &.{ 8, 8, 4 }));
    try std.testing.expectError(error.InvalidMemoryInstancePlan, Partitioner.initPlanned(&reader, 9, &.{ 4, 4 }));
}

test "memory instance census detects truncation and excess before completion" {
    const spool = @import("memory_spool.zig");
    const Loader = struct {
        fn load(_: *anyopaque, _: u1, _: u32) anyerror!u32 {
            return 0;
        }
    };
    const NullSink = struct {
        fn append(_: *anyopaque, _: transition.Transition, _: ?order.Row) anyerror!void {}
    };
    for ([_]u64{ 1, 3 }) |expected| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var writer = try spool.Spool.init(std.testing.allocator, tmp.dir, 2);
        defer writer.deinit();
        for (0..2) |i| try writer.append(.{ .space = 1, .address = 4096, .clock = @as(u64, @intCast(i)) * 4 + 1, .value = @intCast(i) });
        var context: u8 = 0;
        var reader = transition.Reader{ .sorted = try writer.finish(), .initial = .{ .context = &context, .load = Loader.load } };
        defer reader.deinit();
        var partitioner = try Partitioner.init(&reader, expected, 2);
        const sink = Sink{ .context = &context, .append = NullSink.append };
        if (expected == 1) {
            try std.testing.expectError(error.MemoryEventCensusOverflow, partitioner.next(sink));
        } else {
            _ = (try partitioner.next(sink)).?;
            try std.testing.expectError(error.MemoryEventCensusUnderflow, partitioner.next(sink));
        }
        try std.testing.expectError(error.InvalidMemoryInstancePhase, partitioner.next(sink));
    }
}

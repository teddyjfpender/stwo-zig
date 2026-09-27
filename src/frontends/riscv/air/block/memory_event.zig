//! Checked projection of actual runner accesses into the block memory timeline.
//! Clock-gap filler records are deliberately excluded: the new sorted memory
//! table proves wide integer order and does not need synthetic M31 gap updates.
//! The event permutation and first-value admission remain proof obligations.
const std = @import("std");
const access_clock = @import("../../access_clock.zig");
const result = @import("../../runner/result.zig");
const tracker = @import("../../runner/state_chain.zig");
pub const Event = struct {
    space: u1,
    address: u32,
    clock: u64,
    value: u32,
    pub fn key(self: Event) u64 {
        return (@as(u64, self.space) << 32) | self.address;
    }
    pub fn lessThan(_: void, lhs: Event, rhs: Event) bool {
        if (lhs.key() != rhs.key()) return lhs.key() < rhs.key();
        return lhs.clock < rhs.clock;
    }
    /// Canonical 17-byte disk record for a bounded external sorter. The
    /// consumer validates the header/length and rechecks ordering and census.
    pub fn encode(self: Event) [17]u8 {
        var bytes: [17]u8 = undefined;
        bytes[0] = self.space;
        std.mem.writeInt(u32, bytes[1..5], self.address, .little);
        std.mem.writeInt(u64, bytes[5..13], self.clock, .little);
        std.mem.writeInt(u32, bytes[13..17], self.value, .little);
        return bytes;
    }
    pub fn decode(bytes: [17]u8) !Event {
        if (bytes[0] > 1) return error.InvalidMemorySpace;
        const event: Event = .{ .space = @intCast(bytes[0]), .address = std.mem.readInt(u32, bytes[1..5], .little), .clock = std.mem.readInt(u64, bytes[5..13], .little), .value = std.mem.readInt(u32, bytes[13..17], .little) };
        try event.validate();
        return event;
    }
    pub fn validate(self: Event) !void {
        if (self.space == 0 and self.address >= 32) return error.InvalidRegisterAddress;
        if (self.space == 1 and self.address & 3 != 0) return error.UnalignedMemoryAddress;
        if (self.clock == 0 or (self.clock - 1) % access_clock.STRIDE >= access_clock.MAX_ACCESSES_PER_INSTRUCTION) return error.InvalidBlockAccessClock;
    }
};
pub const Frame = struct {
    clock_frame: result.SegmentClockFrame,
    global_first_cycle: u64,
    cycle_count: u32,
    pub fn globalClock(self: Frame, local_clock: u32) !u64 {
        if (self.global_first_cycle == 0 or self.cycle_count == 0 or !access_clock.isCanonical(local_clock)) return error.InvalidBlockAccessClock;
        const last = try std.math.add(u64, self.global_first_cycle, self.cycle_count - 1);
        const first_bucket = try std.math.mul(u64, self.global_first_cycle - 1, access_clock.STRIDE);
        const upper = try std.math.add(u64, try std.math.mul(u64, last - 1, access_clock.STRIDE), access_clock.MAX_ACCESSES_PER_INSTRUCTION);
        const clock = switch (self.clock_frame) {
            .leaf_local => blk: {
                if (!access_clock.isWithinExecution(local_clock, self.cycle_count, false)) return error.AccessOutsideSegment;
                break :blk try std.math.add(u64, first_bucket, local_clock);
            },
            .global_continuous => @as(u64, local_clock),
        };
        if (clock <= first_bucket or clock > upper) return error.AccessOutsideSegment;
        return clock;
    }
    pub fn project(self: Frame, access: tracker.Access) !Event {
        const event: Event = .{ .space = access.addr_space, .address = access.addr, .clock = try self.globalClock(access.clk), .value = access.value };
        try event.validate();
        return event;
    }
};

test "block memory events share one global clock across leaf-local and continuous frames" {
    const first: Frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 3 };
    const second: Frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 4, .cycle_count = 2 };
    const global: Frame = .{ .clock_frame = .global_continuous, .global_first_cycle = 4, .cycle_count = 2 };
    try std.testing.expectEqual(@as(u64, 1), try first.globalClock(1));
    try std.testing.expectEqual(@as(u64, 11), try first.globalClock(11));
    try std.testing.expectEqual(@as(u64, 13), try second.globalClock(1));
    try std.testing.expectEqual(@as(u64, 19), try second.globalClock(7));
    try std.testing.expectEqual(@as(u64, 19), try global.globalClock(19));
    try std.testing.expectError(error.AccessOutsideSegment, second.globalClock(11));
    try std.testing.expectError(error.AccessOutsideSegment, global.globalClock(11));
    try std.testing.expectError(error.InvalidBlockAccessClock, second.globalClock(4));
    const very_late: Frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1 << 32, .cycle_count = 2 };
    try std.testing.expectEqual(@as(u64, (1 << 34) - 3), try very_late.globalClock(1));
}
test "block memory event projection validates real tracker access and wire encoding" {
    var chain = tracker.StateChainTracker.init(std.testing.allocator);
    defer chain.deinit();
    try chain.recordMemTransition(0x2000, 5, 1, 9);
    const frame: Frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 100, .cycle_count = 2 };
    const event = try frame.project(chain.accesses.items[0]);
    try std.testing.expectEqual(@as(u64, 401), event.clock);
    try std.testing.expectEqual(@as(u32, 9), event.value);
    try std.testing.expectEqualDeep(event, try Event.decode(event.encode()));
    var invalid = event.encode();
    invalid[0] = 2;
    try std.testing.expectError(error.InvalidMemorySpace, Event.decode(invalid));
    invalid = event.encode();
    invalid[1] |= 1;
    try std.testing.expectError(error.UnalignedMemoryAddress, Event.decode(invalid));
    try std.testing.expect(Event.lessThan({}, .{ .space = 0, .address = 31, .clock = std.math.maxInt(u64), .value = 0 }, event));
}

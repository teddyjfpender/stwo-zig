//! Exact before/after transitions through the shared bounded external sorter.
const std = @import("std");
const Event = @import("../air/block/memory_transition.zig").Transition;
const Record = struct {
    value: Event,
    pub fn validate(self: Record) !void {
        const v = self.value;
        if (v.space != 1 or v.address & 3 != 0 or v.clock == 0 or v.clock % 4 == 0) return error.InvalidV7TransitionRecord;
    }
    pub fn lessThan(_: void, left: Record, right: Record) bool {
        return if (left.value.address == right.value.address) left.value.clock < right.value.clock else left.value.address < right.value.address;
    }
    pub fn encode(self: Record) [21]u8 {
        var bytes: [21]u8 = undefined;
        bytes[0] = self.value.space;
        std.mem.writeInt(u32, bytes[1..5], self.value.address, .little);
        std.mem.writeInt(u64, bytes[5..13], self.value.clock, .little);
        std.mem.writeInt(u32, bytes[13..17], self.value.before, .little);
        std.mem.writeInt(u32, bytes[17..21], self.value.after, .little);
        return bytes;
    }
    pub fn decode(bytes: [21]u8) !Record {
        if (bytes[0] != 1) return error.InvalidV7TransitionRecord;
        const self = Record{ .value = .{ .space = 1, .address = std.mem.readInt(u32, bytes[1..5], .little), .clock = std.mem.readInt(u64, bytes[5..13], .little), .before = std.mem.readInt(u32, bytes[13..17], .little), .after = std.mem.readInt(u32, bytes[17..21], .little) } };
        try self.validate();
        return self;
    }
};
const Sort = struct {
    pub fn sort(values: []Record, _: []Record) !void {
        std.sort.pdq(Record, values, {}, Record.lessThan);
    }
};
const Impl = @import("../air/block/memory_sorter_v1.zig").For(Record, 21, Sort, "v7-transitions");
pub const Statistics = Impl.Statistics;
pub const Reader = struct {
    inner: Impl.Reader,
    pub fn next(self: *Reader) !?Event {
        return if (try self.inner.next()) |record| record.value else null;
    }
    pub fn deinit(self: *Reader) void {
        self.inner.deinit();
        self.* = undefined;
    }
};
pub const Spool = struct {
    inner: Impl.Spool,
    maximum: u64,
    pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, chunk: usize, maximum: u64) !Spool {
        if (maximum == 0) return error.V7ExecutionEventLimit;
        return .{ .inner = try Impl.Spool.init(a, dir, chunk), .maximum = maximum };
    }
    pub fn append(self: *Spool, value: Event) !void {
        if (self.inner.event_count >= self.maximum) return error.V7ExecutionEventLimit;
        try self.inner.append(.{ .value = value });
    }
    pub fn count(self: *const Spool) u64 {
        return self.inner.event_count;
    }
    pub fn statistics(self: *const Spool) Statistics {
        return self.inner.statistics;
    }
    pub fn finish(self: *Spool) !Reader {
        return .{ .inner = try self.inner.finish() };
    }
    pub fn deinit(self: *Spool) void {
        self.inner.deinit();
        self.* = undefined;
    }
};

test "transition sorter preserves before after through fanin boundary and rejects duplicate keys" {
    const a = std.testing.allocator;
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    var spool = try Spool.init(a, dir.dir, 4, 1000);
    defer spool.deinit();
    var expected: [129]Event = undefined;
    for (&expected, 0..) |*event, i| {
        event.* = .{ .space = 1, .address = @intCast(0x1000 + 4 * (i % 7)), .clock = @intCast(4 * (129 - i) + 1), .before = @intCast(i * 5), .after = @intCast(i * 11) };
        try spool.append(event.*);
    }
    std.sort.pdq(Event, &expected, {}, struct {
        fn less(_: void, l: Event, r: Event) bool {
            return Record.lessThan({}, .{ .value = l }, .{ .value = r });
        }
    }.less);
    var reader = try spool.finish();
    defer reader.deinit();
    for (expected) |want| try std.testing.expectEqualDeep(want, (try reader.next()).?);
    try std.testing.expect(try reader.next() == null);
    try std.testing.expectEqual(@as(u32, 33), spool.statistics().initial_runs);
    try std.testing.expectEqual(@as(u32, 2), spool.statistics().merge_passes);
    var duplicate_dir = std.testing.tmpDir(.{});
    defer duplicate_dir.cleanup();
    var duplicate = try Spool.init(a, duplicate_dir.dir, 4, 1000);
    defer duplicate.deinit();
    for (expected[0..128]) |event| try duplicate.append(event);
    var repeated = expected[0];
    repeated.before ^= 1;
    try duplicate.append(repeated);
    try std.testing.expectError(error.DuplicateOrUnsortedMemoryEvent, duplicate.finish());
}

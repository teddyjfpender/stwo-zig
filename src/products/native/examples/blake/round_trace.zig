//! Scalar row generator for the exact upstream Blake round component.

const std = @import("std");
const constants = @import("constants.zig");
const geometry = @import("geometry.zig");

pub const Row = [geometry.ROUND_MAIN_COLUMNS]u32;

pub const Output = struct {
    row: Row,
    output_state: [constants.STATE_SIZE]u32,
};

pub fn generate(
    input_state: [constants.STATE_SIZE]u32,
    message: [constants.MESSAGE_SIZE]u32,
    observer: anytype,
) Output {
    var writer = Writer(@TypeOf(observer)){
        .observer = observer,
        .row = undefined,
    };
    var state = input_state;
    for (state) |word| writer.appendU32(word);
    for (message) |word| writer.appendU32(word);

    writer.g(&state, .{ 0, 4, 8, 12 }, message[0], message[1]);
    writer.g(&state, .{ 1, 5, 9, 13 }, message[2], message[3]);
    writer.g(&state, .{ 2, 6, 10, 14 }, message[4], message[5]);
    writer.g(&state, .{ 3, 7, 11, 15 }, message[6], message[7]);
    writer.g(&state, .{ 0, 5, 10, 15 }, message[8], message[9]);
    writer.g(&state, .{ 1, 6, 11, 12 }, message[10], message[11]);
    writer.g(&state, .{ 2, 7, 8, 13 }, message[12], message[13]);
    writer.g(&state, .{ 3, 4, 9, 14 }, message[14], message[15]);
    std.debug.assert(writer.index == geometry.ROUND_MAIN_COLUMNS);

    return .{ .row = writer.row, .output_state = state };
}

fn Writer(comptime Observer: type) type {
    return struct {
        observer: Observer,
        row: Row,
        index: usize = 0,

        fn appendFelt(self: *@This(), value: u32) void {
            std.debug.assert(value < 0x8000_0000);
            self.row[self.index] = value;
            self.index += 1;
        }

        fn appendU32(self: *@This(), value: u32) void {
            self.appendFelt(value & 0xffff);
            self.appendFelt(value >> 16);
        }

        fn g(
            self: *@This(),
            state: *[constants.STATE_SIZE]u32,
            indices: [4]usize,
            message0: u32,
            message1: u32,
        ) void {
            const a = indices[0];
            const b = indices[1];
            const c = indices[2];
            const d = indices[3];

            state[a] = self.add3(state[a], state[b], message0);
            state[d] = self.xorRotate16(state[a], state[d]);
            state[c] = self.add2(state[c], state[d]);
            state[b] = self.xorRotate(state[b], state[c], 12);
            state[a] = self.add3(state[a], state[b], message1);
            state[d] = self.xorRotate(state[a], state[d], 8);
            state[c] = self.add2(state[c], state[d]);
            state[b] = self.xorRotate(state[b], state[c], 7);
        }

        fn add2(self: *@This(), a: u32, b: u32) u32 {
            const sum = a +% b;
            self.appendU32(sum);
            return sum;
        }

        fn add3(self: *@This(), a: u32, b: u32, c: u32) u32 {
            const sum = a +% b +% c;
            self.appendU32(sum);
            return sum;
        }

        fn split(self: *@This(), value: u32, width: u5) struct { low: u32, high: u32 } {
            const high = value >> width;
            const low = value & ((@as(u32, 1) << width) - 1);
            self.appendFelt(high);
            return .{ .low = low, .high = high };
        }

        fn xorRotate(self: *@This(), a: u32, b: u32, width: u5) u32 {
            const xor_value = a ^ b;
            const rotated = std.math.rotr(u32, xor_value, width);
            const al = self.split(a & 0xffff, width);
            const ah = self.split(a >> 16, width);
            const bl = self.split(b & 0xffff, width);
            const bh = self.split(b >> 16, width);

            _ = self.recordXor(width, al.low, bl.low);
            _ = self.recordXor(width, ah.low, bh.low);
            _ = self.recordXor(16 - width, al.high, bl.high);
            _ = self.recordXor(16 - width, ah.high, bh.high);
            return rotated;
        }

        fn xorRotate16(self: *@This(), a: u32, b: u32) u32 {
            const xor_value = a ^ b;
            const rotated = std.math.rotr(u32, xor_value, 16);
            const al = self.split(a & 0xffff, 8);
            const ah = self.split(a >> 16, 8);
            const bl = self.split(b & 0xffff, 8);
            const bh = self.split(b >> 16, 8);

            _ = self.recordXor(8, al.low, bl.low);
            _ = self.recordXor(8, ah.low, bh.low);
            _ = self.recordXor(8, al.high, bl.high);
            _ = self.recordXor(8, ah.high, bh.high);
            return rotated;
        }

        fn recordXor(self: *@This(), width: u5, a: u32, b: u32) u32 {
            const c = a ^ b;
            self.appendFelt(c);
            self.observer.record(width, a, b, c);
            return c;
        }
    };
}

const NullObserver = struct {
    fn record(_: NullObserver, _: u5, _: u32, _: u32, _: u32) void {}
};

test "exact Blake round row matches the independent word implementation" {
    var state: [constants.STATE_SIZE]u32 = undefined;
    var message: [constants.MESSAGE_SIZE]u32 = undefined;
    for (&state, 0..) |*word, index| word.* = @intCast(0x1020_3040 + index * 0x0101_0101);
    for (&message, 0..) |*word, index| word.* = @intCast(0x5060_7080 + index * 0x0001_0203);

    var expected = state;
    constants.round(&expected, message, 0);
    const output = generate(state, message, NullObserver{});
    try std.testing.expectEqualSlices(u32, &expected, &output.output_state);
    try std.testing.expectEqual(@as(usize, geometry.ROUND_MAIN_COLUMNS), output.row.len);
}

test "exact Blake round row emits 128 width-specific XOR lookups" {
    const CountingObserver = struct {
        count: *usize,
        widths: *[5]usize,

        fn record(self: @This(), width: u5, _: u32, _: u32, _: u32) void {
            self.count.* += 1;
            const index: usize = switch (width) {
                4 => 0,
                7 => 1,
                8 => 2,
                9 => 3,
                12 => 4,
                else => unreachable,
            };
            self.widths[index] += 1;
        }
    };

    var count: usize = 0;
    var widths = [_]usize{0} ** 5;
    _ = generate(
        [_]u32{0x1234_5678} ** constants.STATE_SIZE,
        [_]u32{0x9abc_def0} ** constants.MESSAGE_SIZE,
        CountingObserver{ .count = &count, .widths = &widths },
    );
    try std.testing.expectEqual(@as(usize, 128), count);
    try std.testing.expectEqualSlices(usize, &.{ 16, 16, 64, 16, 16 }, &widths);
}

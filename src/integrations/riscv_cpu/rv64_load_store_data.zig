//! Independently expected examples. Opcode encodings and little-endian fixture
//! bytes are not used as AIR equations or accepted host-computed lookup claims.
const std = @import("std");
const P = @import("rv64_load_store_public.zig");
pub const LOAD_ADDRESS: u64 = 0x1_0000_1000;
pub const STORE_ADDRESS: u64 = 0x2_0000_1000;
pub const HIGH_ADDRESS: u64 = 0xffff_ffff_ffff_ff00;
pub const LOAD_WORD: u64 = 0x80ff7f008001fffe;
pub const STORE_WORD: u64 = 0x1020304050607080;
pub const B: u64 = 0x0123456789abcdef;
pub const Data = struct {
    initial: [18]P.Cell,
    terminal: [18]P.Cell,
    operations: [49]P.Operation,
    pub fn expected(self: *const @This()) P.Expected {
        return .{ .initial = &self.initial, .terminal = &self.terminal, .operations = &self.operations, .split = 24 };
    }
};
pub fn loadWord(f3: u3, immediate: i12) u32 {
    return (@as(u32, @as(u12, @bitCast(immediate))) << 20) | (1 << 15) | (@as(u32, f3) << 12) | (2 << 7) | 0x03;
}
pub fn storeWord(f3: u3, immediate: i12) u32 {
    const imm: u32 = @as(u12, @bitCast(immediate));
    return ((imm >> 5) << 25) | (2 << 20) | (1 << 15) | (@as(u32, f3) << 12) | ((imm & 31) << 7) | 0x23;
}
pub fn fixture() Data {
    var result: Data = undefined;
    result.initial[0] = .{ .address = 0, .state = .{ .value = 0x1122334455667788, .rights = 3 } };
    result.initial[1] = .{ .address = LOAD_ADDRESS, .state = .{ .value = LOAD_WORD, .rights = 1 } };
    for (result.initial[2..17], 0..) |*cell, i| cell.* = .{ .address = STORE_ADDRESS + 8 * i, .state = .{ .value = STORE_WORD, .rights = if (i == 14) 2 else 3 } };
    result.initial[17] = .{ .address = HIGH_ADDRESS, .state = .{ .value = 0xfedcba9876543210, .rights = 1 } };
    result.terminal = result.initial;
    const Spec = struct { f3: u3, width: usize, values: []const u64 };
    const loads = [_]Spec{
        .{ .f3 = 0, .width = 1, .values = &.{ 0xfffffffffffffffe, 0xffffffffffffffff, 1, 0xffffffffffffff80, 0, 127, 0xffffffffffffffff, 0xffffffffffffff80 } },
        .{ .f3 = 4, .width = 1, .values = &.{ 254, 255, 1, 128, 0, 127, 255, 128 } },
        .{ .f3 = 1, .width = 2, .values = &.{ 0xfffffffffffffffe, 0xffffffffffff8001, 0x7f00, 0xffffffffffff80ff } },
        .{ .f3 = 5, .width = 2, .values = &.{ 0xfffe, 0x8001, 0x7f00, 0x80ff } },
        .{ .f3 = 2, .width = 4, .values = &.{ 0xffffffff8001fffe, 0xffffffff80ff7f00 } },
        .{ .f3 = 6, .width = 4, .values = &.{ 0x8001fffe, 0x80ff7f00 } },
        .{ .f3 = 3, .width = 8, .values = &.{LOAD_WORD} },
    };
    var index: usize = 0;
    for (loads) |spec| for (spec.values, 0..) |value, offset_index| {
        result.operations[index] = .{ .id = @intCast(index + 1), .instruction = loadWord(spec.f3, @intCast(offset_index * spec.width)), .a = LOAD_ADDRESS, .c = value, .epoch = 0, .tick = @intCast(4 * (index + 1)) };
        index += 1;
    };
    var store_index: usize = 0;
    for (0..4) |size| {
        const width = @as(usize, 1) << @intCast(size);
        for (0..8 / width) |position| {
            const cell = &result.terminal[2 + store_index];
            const offset = position * width;
            result.operations[index] = .{ .id = @intCast(index + 1), .instruction = storeWord(@intCast(size), @intCast(offset)), .a = cell.address, .b = B, .epoch = 1, .tick = @intCast(4 * (store_index + 1)) };
            var bytes: [8]u8 = undefined;
            var source: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, STORE_WORD, .little);
            std.mem.writeInt(u64, &source, B, .little);
            @memcpy(bytes[offset..][0..width], source[0..width]);
            cell.state.value = std.mem.readInt(u64, &bytes, .little);
            cell.state.epoch = 1;
            cell.state.tick = @intCast(4 * (store_index + 1));
            index += 1;
            store_index += 1;
        }
    }
    std.debug.assert(index == 44 and store_index == 15);
    result.operations[44] = .{ .id = 45, .instruction = storeWord(0, 2), .a = 0xffffffffffffffff, .b = 0x55, .epoch = 1, .tick = 64 };
    result.operations[45] = .{ .id = 46, .instruction = loadWord(3, -8), .a = HIGH_ADDRESS + 8, .c = 0xfedcba9876543210, .epoch = 2, .tick = 65540 };
    result.operations[46] = .{ .id = 47, .instruction = loadWord(0, 1), .a = 0, .c = 0x55, .epoch = 2, .tick = 65544 };
    result.operations[47] = .{ .id = 48, .instruction = storeWord(0, 0), .a = STORE_ADDRESS, .b = 0xef, .epoch = 2, .tick = 65548 };
    result.operations[48] = .{ .id = 49, .instruction = loadWord(4, 1), .a = 0, .c = 0x55, .epoch = 2, .tick = 131076 };
    result.terminal[0].state.value = 0x1122334455665588;
    result.terminal[0].state.epoch = 2;
    result.terminal[0].state.tick = 131076;
    result.terminal[1].state.epoch = 0;
    result.terminal[1].state.tick = 116;
    result.terminal[2].state.epoch = 2;
    result.terminal[2].state.tick = 65548;
    result.terminal[17].state.epoch = 2;
    result.terminal[17].state.tick = 65540;
    return result;
}

//! Host-syscall runner integration tests kept separate from the hot loop.

const std = @import("std");
const runner = @import("mod.zig");
const host_mod = runner.host_mod;

test "runner: runWithHost HALT syscall" {
    const instructions = [_]u32{
        @as(u32, 0) << 20 | (0 << 15) | (0b000 << 12) | (17 << 7) | 0x13,
        @as(u32, 42) << 20 | (0 << 15) | (0b000 << 12) | (10 << 7) | 0x13,
        0x00000073,
    };
    const elf = makeTestElf(&instructions);

    var rt = host_mod.HostRuntime.init(std.testing.allocator, &.{});
    defer rt.deinit();

    var result = try runner.runWithHost(std.testing.allocator, &elf, 1000, rt.interface());
    defer result.deinit();
    try std.testing.expectEqual(@as(?u32, 42), result.exit_code);
    try std.testing.expectEqual(@as(usize, 3), result.step_count);
}

test "runner: runWithHost WRITE syscall" {
    const instructions = [_]u32{
        @as(u32, 2) << 20 | (0 << 15) | (0b000 << 12) | (17 << 7) | 0x13,
        @as(u32, 1) << 20 | (0 << 15) | (0b000 << 12) | (10 << 7) | 0x13,
        (0x10 << 12) | (11 << 7) | 0x37,
        @as(u32, 4) << 20 | (0 << 15) | (0b000 << 12) | (12 << 7) | 0x13,
        0x00000073,
        @as(u32, 0) << 20 | (0 << 15) | (0b000 << 12) | (17 << 7) | 0x13,
        @as(u32, 0) << 20 | (0 << 15) | (0b000 << 12) | (10 << 7) | 0x13,
        0x00000073,
    };
    const elf = makeTestElf(&instructions);

    var rt = host_mod.HostRuntime.init(std.testing.allocator, &.{});
    defer rt.deinit();

    var result = try runner.runWithHost(std.testing.allocator, &elf, 1000, rt.interface());
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 4), rt.journalData().len);
    try std.testing.expectEqual(@as(?u32, 0), result.exit_code);
}

test "runner: runWithHost HINT_LEN and HINT_READ" {
    const hint_data = [_]u8{ 0xCA, 0xFE, 0xBA, 0xBE };
    const hints = [_][]const u8{&hint_data};
    const instructions = [_]u32{
        @as(u32, 240) << 20 | (0 << 15) | (0b000 << 12) | (17 << 7) | 0x13,
        0x00000073,
        @as(u32, 241) << 20 | (0 << 15) | (0b000 << 12) | (17 << 7) | 0x13,
        (0x20 << 12) | (10 << 7) | 0x37,
        @as(u32, 4) << 20 | (0 << 15) | (0b000 << 12) | (11 << 7) | 0x13,
        0x00000073,
        @as(u32, 0) << 20 | (0 << 15) | (0b000 << 12) | (17 << 7) | 0x13,
        @as(u32, 0) << 20 | (0 << 15) | (0b000 << 12) | (10 << 7) | 0x13,
        0x00000073,
    };
    const elf = makeTestElf(&instructions);

    var rt = host_mod.HostRuntime.init(std.testing.allocator, &hints);
    defer rt.deinit();

    var result = try runner.runWithHost(std.testing.allocator, &elf, 1000, rt.interface());
    defer result.deinit();
    try std.testing.expectEqual(@as(?u32, 0), result.exit_code);
}

test "runner: runWithHost null host is backwards compatible" {
    const instructions = [_]u32{
        @as(u32, 42) << 20 | (0 << 15) | (0b000 << 12) | (1 << 7) | 0x13,
        0x00000073,
    };
    const elf = makeTestElf(&instructions);

    var result = try runner.runWithHost(std.testing.allocator, &elf, 1000, null);
    defer result.deinit();
    try std.testing.expectEqual(@as(u32, 42), result.cpu_final.readReg(1));
    try std.testing.expectEqual(@as(usize, 2), result.step_count);
    try std.testing.expectEqual(@as(?u32, null), result.exit_code);
}

fn makeTestElf(instructions: []const u32) [84 + 64]u8 {
    var buf = [_]u8{0} ** (84 + 64);
    @memcpy(buf[0..4], "\x7fELF");
    buf[4] = 1;
    buf[5] = 1;
    buf[6] = 1;
    buf[16] = 2;
    buf[18] = 0xf3;
    buf[20] = 1;
    std.mem.writeInt(u32, buf[24..28], 0x10000, .little);
    buf[28] = 52;
    buf[40] = 52;
    buf[42] = 32;
    buf[44] = 1;
    buf[52] = 1;
    buf[56] = 84;
    std.mem.writeInt(u32, buf[60..64], 0x10000, .little);
    const code_size: u32 = @intCast(instructions.len * @sizeOf(u32));
    std.mem.writeInt(u32, buf[68..72], code_size, .little);
    std.mem.writeInt(u32, buf[72..76], code_size, .little);
    for (instructions, 0..) |inst, index| {
        const offset = 84 + index * @sizeOf(u32);
        std.mem.writeInt(u32, buf[offset..][0..4], inst, .little);
    }
    return buf;
}

const std = @import("std");
const capture = @import("../rv64_full_capture.zig");
const rv = @import("stwo_riscv_frontend").rv64;
const a = std.testing.allocator;
const pc: u64 = 0x100001000;
const config = rv.csp_contract.Config{ .elf = "unused", .input = "unused", .expected_digest = "0000000000000000000000000000000000000000000000000000000000000000", .symbols = .{ .input_start = 0x2000, .input_end = 0x3000, .halt_flag = 0x3000, .output_len = 0x3004, .output_data = 0x3008, .output_end = 0x4000, .stack_bottom = 0x4000, .stack_top = 0x5000 } };

fn elf() [288]u8 {
    var bytes: [288]u8 = @splat(0);
    @memcpy(bytes[0..4], "\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    std.mem.writeInt(u16, bytes[16..18], 2, .little);
    std.mem.writeInt(u16, bytes[18..20], 243, .little);
    std.mem.writeInt(u32, bytes[20..24], 1, .little);
    std.mem.writeInt(u64, bytes[24..32], pc, .little);
    std.mem.writeInt(u64, bytes[32..40], 64, .little);
    std.mem.writeInt(u16, bytes[52..54], 64, .little);
    std.mem.writeInt(u16, bytes[54..56], 56, .little);
    std.mem.writeInt(u16, bytes[56..58], 1, .little);
    std.mem.writeInt(u32, bytes[64..68], 1, .little);
    std.mem.writeInt(u32, bytes[68..72], 5, .little);
    std.mem.writeInt(u64, bytes[72..80], 256, .little);
    std.mem.writeInt(u64, bytes[80..88], pc, .little);
    std.mem.writeInt(u64, bytes[96..104], 32, .little);
    std.mem.writeInt(u64, bytes[104..112], 32, .little);
    std.mem.writeInt(u64, bytes[112..120], 1, .little);
    const instructions = [_]u32{ 0x000030b7, 0x02000113, 0x0020a223, 0x00100113, 0x0020a023, 0xffffffff, 0, 0 };
    for (instructions, 0..) |instruction, i| std.mem.writeInt(u32, bytes[256 + 4 * i ..][0..4], instruction, .little);
    return bytes;
}

test "rv64 full capture: one complete journal owns full immutable ROM and independent RAM boundaries" {
    const bytes = elf();
    var result = try capture.Capture.run(a, config, &bytes, &.{1}, .{ .expected_steps = 5 });
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 5), result.records.len);
    try std.testing.expectEqual(@as(usize, 8), result.program_words.len);
    try std.testing.expectEqual(@as(u64, pc), result.initial_pc);
    try std.testing.expectEqual(@as(u64, pc + 20), result.final_pc);
    try std.testing.expectEqual(@as(u64, pc + 28), result.program_addresses[7]);
    try std.testing.expectEqual(@as(u64, 0x5000), result.initial_registers[2]);
    try std.testing.expectEqual(@as(u64, 1), result.final_registers[2]);
    try std.testing.expectEqual(@as(usize, 1), result.cells.len);
    try std.testing.expectEqual(@as(u64, 0x3000), result.cells[0].address);
    try std.testing.expectEqual(@as(u64, 0), result.cells[0].initial);
    try std.testing.expectEqual(@as(u64, 0x2000000001), result.cells[0].final);
    try std.testing.expectEqual(@as(u32, 20), result.memory_clocks[0]);
    try std.testing.expectEqual(@as(u32, 17), result.register_clocks[1]);
    try std.testing.expectEqual(@as(u32, 18), result.register_clocks[2]);
    try std.testing.expect(result.opcodes[@intFromEnum(rv.decode.Opcode.LUI)]);
    try std.testing.expectEqual(@as(u64, 2), result.histogram[@intFromEnum(rv.decode.Opcode.SW)]);
    const statement = @import("../rv64_full_statement.zig").Statement{ .program = .{ .base = result.program_base, .words = result.program_words, .addresses = result.program_addresses }, .steps = @intCast(result.records.len), .initial_pc = result.initial_pc, .final_pc = result.final_pc, .initial_registers = result.initial_registers, .final_registers = result.final_registers, .cells = result.cells, .register_clocks = result.register_clocks, .memory_clocks = result.memory_clocks, .opcodes = result.opcodes };
    try statement.validate();
}

test "rv64 full capture: completion count digest and immutable executable admission fail closed" {
    const bytes = elf();
    try std.testing.expectError(error.InvalidRv64FullCompletion, capture.Capture.run(a, config, &bytes, &.{}, .{ .expected_steps = 6 }));
    try std.testing.expectError(error.InvalidRv64FullCompletion, capture.Capture.run(a, config, &bytes, &.{}, .{ .max_retirements = 4 }));
    var wrong_digest = config;
    wrong_digest.expected_digest = "1000000000000000000000000000000000000000000000000000000000000000";
    try std.testing.expectError(error.Rv64FullOutputMismatch, capture.Capture.run(a, wrong_digest, &bytes, &.{}, .{ .expected_steps = 5 }));
    var writable = bytes;
    std.mem.writeInt(u32, writable[68..72], 7, .little);
    try std.testing.expectError(error.InvalidRv64FullExecutable, capture.Capture.run(a, config, &writable, &.{}, .{ .expected_steps = 5 }));
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    const bytes = elf();
    var result = try capture.Capture.run(allocator, config, &bytes, &.{1}, .{ .expected_steps = 5 });
    defer result.deinit();
}
test "rv64 full capture: failures release journal loader and boundary allocations" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}

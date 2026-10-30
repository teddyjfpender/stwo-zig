//! Fallible initialization only. No instruction execution or proof generation.
const std = @import("std");
const Memory = @import("memory.zig").Memory;
const Loader = @import("elf_loader.zig");
const Session = @import("mod.zig").EthereumShaExecutionSession;
const instructions = [_]u32{ 0x00100093, 0x0000006f };
const elf = blk: {
    var bytes = @import("guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 256, .rv32im_zkvm_ethereum_sha_v1);
    const data_offset = std.mem.readInt(u32, bytes[88..92], .little);
    @memset(bytes[data_offset..][0..256], 0);
    std.mem.writeInt(u32, bytes[104..108], 0x40020, .little);
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([9]usize{ 2, 3, 4, 7, 8, 9, 10, 11, 12 }, [9]u32{ 0x100100, 0x40020, 0x100100, 0x11fffc, 0x120020, 0x100100, 0x100104, 0x100108, 0x100200 }) |index, value| std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    break :blk bytes;
};
const input = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9 };
fn sameMemory(a: *Memory, b: *Memory) !void {
    const left = try a.canonicalAlignedWordAddresses();
    const right = try b.canonicalAlignedWordAddresses();
    try std.testing.expectEqualSlices(u32, left, right);
    for (left) |address| try std.testing.expectEqual(a.readU32(address), b.readU32(address));
}
fn legacyLoad(memory: *Memory) void {
    // Independent compatibility write path over these exact two PT_LOADs.
    for (0..2) |i| {
        const p = 52 + i * 32;
        const offset = std.mem.readInt(u32, elf[p + 4 ..][0..4], .little);
        const address = std.mem.readInt(u32, elf[p + 8 ..][0..4], .little);
        const size = std.mem.readInt(u32, elf[p + 16 ..][0..4], .little);
        const memory_size = std.mem.readInt(u32, elf[p + 20 ..][0..4], .little);
        memory.loadSegment(address, elf[offset..][0..size]);
        memory.loadZeroes(address +% size, memory_size - size);
    }
}
test "fallible initialization bytes inventory wrapping and lazy BSS match compatibility writes" {
    var old = try Memory.initFallible(std.testing.allocator);
    defer old.deinit();
    var new = try Memory.initFallible(std.testing.allocator);
    defer new.deinit();
    const bytes = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2, 1 };
    for ([_]u32{ 0xfffd, 0xfffffffd }) |address| {
        old.writeSlice(address, &bytes);
        try new.writeSliceFallible(address, &bytes);
    }
    old.loadZeroes(0xfffe, 0x10007);
    try new.loadZeroesFallible(0xfffe, 0x10007);
    try sameMemory(&old, &new);
    try std.testing.expect(old.pages[2] == null and new.pages[2] == null);
    old.writeU32(0xfffffffe, 0x12345678);
    try new.writeU32Fallible(0xfffffffe, 0x12345678);
    try sameMemory(&old, &new);
}
fn bulkFailure(a: std.mem.Allocator) !void {
    var memory = try Memory.initFallible(a);
    defer memory.deinit();
    try memory.writeSliceFallible(0xfffffffd, &input);
    try memory.loadZeroesFallible(0x1fffd, 0x10010);
    try std.testing.expectEqual(@as(u8, 1), memory.readByte(0xfffffffd));
    try std.testing.expect(memory.alignedWordIsInitialized(0x20000));
    try std.testing.expect(memory.pages[2] == null);
}
test "fallible initialization every bulk allocation failure cleans up" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, bulkFailure, .{});
}
fn partialFailure(fail_offset: ?usize) !usize {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var memory = try Memory.initFallible(failing.allocator());
    defer memory.deinit();
    try memory.writeU32Fallible(0xfffc, 0xdecafbad);
    _ = try memory.canonicalAlignedWordAddresses();
    const before = failing.alloc_index;
    if (fail_offset) |offset| failing.fail_index = before + offset;
    const bytes = [_]u8{0x5a} ** 70000;
    if (fail_offset != null) {
        try std.testing.expectError(error.OutOfMemory, memory.writeSliceFallible(0xfffc, &bytes));
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(@as(u32, 0xdecafbad), memory.readU32(0xfffc));
        try std.testing.expectEqual(@as(u32, 0), memory.readU32(0x10000));
        try std.testing.expectEqual(@as(u32, 0), memory.readU32(0x20000));
        try std.testing.expectEqual(@as(usize, 1), memory.initialized_word_count);
        const addresses = try memory.canonicalAlignedWordAddresses();
        try std.testing.expectEqualSlices(u32, &.{0xfffc}, addresses);
    } else try memory.writeSliceFallible(0xfffc, &bytes);
    return failing.alloc_index - before;
}
test "fallible initialization prepare failure preserves bytes and inventory with partial zero pages" {
    const allocations = try partialFailure(null);
    for (0..allocations) |offset| _ = try partialFailure(offset);
}
fn elfFailure(a: std.mem.Allocator) !void {
    var memory = try Memory.initFallible(a);
    defer memory.deinit();
    const info = try Loader.loadElfForProfile(&elf, &memory, .rv32im_zkvm_ethereum_sha_v1);
    try std.testing.expectEqual(@as(u32, 0), memory.readU32(info.halt_flag));
    try std.testing.expectEqual(@as(u32, 0), memory.readU32(info.output_len));
    try std.testing.expect(memory.alignedWordIsInitialized(0x130000));
    try std.testing.expect(memory.pages[0x13] == null);
}
test "fallible initialization every ELF segment and BSS allocation failure propagates" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, elfFailure, .{});
}
fn sessionFailure(a: std.mem.Allocator) !void {
    var session = try Session.init(a, &elf, .{ .input = &input, .clock_frame = .leaf_local, .trace_retention = .segment_owned, .stop_on_halt_flag = true, .require_current_output_accesses = false });
    defer session.deinit();
    for (input, 0..) |value, i| try std.testing.expectEqual(value, session.memory.readByte(session.elf_info.input_start + @as(u32, @intCast(i))));
    try std.testing.expectEqual(@as(u32, 0), session.memory.readU32(session.elf_info.halt_flag));
    try std.testing.expectEqual(@as(u32, 0), session.memory.readU32(session.elf_info.output_len));
    try std.testing.expectEqual(session.elf_info.entry_point, session.cpu.pc);
    try std.testing.expectEqual(session.elf_info.stack_pointer, session.cpu.regs[2]);
    try std.testing.expectEqual(session.elf_info.global_pointer, session.cpu.regs[3]);
    try std.testing.expect(session.memory.pages[0x13] == null);
}
test "fallible initialization every Session private input and ELF allocation failure propagates" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, sessionFailure, .{});
}
test "fallible initialization Session initial bytes and ABI match compatibility loader" {
    var old = try Memory.initFallible(std.testing.allocator);
    defer old.deinit();
    legacyLoad(&old);
    old.writeSlice(0x11fffc, &input);
    var session = try Session.init(std.testing.allocator, &elf, .{ .input = &input });
    defer session.deinit();
    try sameMemory(&old, &session.memory);
    try Loader.validateReleaseAbiForProfile(&elf, .rv32im_zkvm_ethereum_sha_v1);
}

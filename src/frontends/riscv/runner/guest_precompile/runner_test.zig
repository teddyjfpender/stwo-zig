//! End-to-end extension-runner tests with exact admission metadata.

const std = @import("std");
const custom0 = @import("../../isa/custom0.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const runner = @import("../mod.zig");

const elf_size: usize = 592;
const note_offset: usize = 276;
const descriptor_offset: usize = note_offset + 20;
const program_offset: usize = 512;
const data_offset: usize = 528;

fn put(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}

fn makeExtensionElf(include_call: bool) [elf_size]u8 {
    var elf = [_]u8{0} ** elf_size;
    @memcpy(elf[0..4], "\x7fELF");
    elf[4] = 1;
    elf[5] = 1;
    elf[6] = 1;
    put(u16, &elf, 16, 2);
    put(u16, &elf, 18, 243);
    put(u32, &elf, 20, 1);
    put(u32, &elf, 24, 0x1000);
    put(u32, &elf, 28, 52);
    put(u32, &elf, 32, 128);
    put(u16, &elf, 40, 52);
    put(u16, &elf, 42, 32);
    put(u16, &elf, 44, 2);
    put(u16, &elf, 46, 40);
    put(u16, &elf, 48, 3);
    put(u16, &elf, 50, 1);

    // Executable and data PT_LOAD segments.
    put(u32, &elf, 52, 1);
    put(u32, &elf, 56, program_offset);
    put(u32, &elf, 60, 0x1000);
    put(u32, &elf, 68, 16);
    put(u32, &elf, 72, 16);
    put(u32, &elf, 76, 5);
    put(u32, &elf, 80, 4);
    put(u32, &elf, 84, 1);
    put(u32, &elf, 88, data_offset);
    put(u32, &elf, 92, 0x0010_0100);
    put(u32, &elf, 100, 64);
    put(u32, &elf, 104, 64);
    put(u32, &elf, 108, 6);
    put(u32, &elf, 112, 4);

    // shstrtab and exact non-allocated admission note.
    const strings = "\x00.shstrtab\x00.note.stwo.zkvm\x00";
    put(u32, &elf, 168, 1);
    put(u32, &elf, 172, 3);
    put(u32, &elf, 184, 248);
    put(u32, &elf, 188, strings.len);
    put(u32, &elf, 200, 1);
    @memcpy(elf[248 .. 248 + strings.len], strings);
    put(u32, &elf, 208, 11);
    put(u32, &elf, 212, 7);
    put(u32, &elf, 224, note_offset);
    put(u32, &elf, 228, 76);
    put(u32, &elf, 240, 4);

    const admission = execution_profile.admission;
    put(u32, &elf, note_offset, admission.note_name.len);
    put(u32, &elf, note_offset + 4, admission.descriptor_size);
    put(u32, &elf, note_offset + 8, admission.note_type);
    @memcpy(elf[note_offset + 12 .. note_offset + 17], admission.note_name);
    @memcpy(elf[descriptor_offset .. descriptor_offset + 8], admission.descriptor_magic);
    put(u16, &elf, descriptor_offset + 8, admission.schema_version);
    put(u16, &elf, descriptor_offset + 10, 1);
    put(u64, &elf, descriptor_offset + 12, execution_profile.poseidon2_capability_bit);
    put(u16, &elf, descriptor_offset + 20, execution_profile.poseidon2_abi_version);
    @memcpy(
        elf[descriptor_offset + 24 .. descriptor_offset + 56],
        &execution_profile.poseidon2_semantic_digest,
    );

    // x5 = 0x0010_0100; custom call or NOP; ECALL.
    const instructions = [_]u32{
        0x0010_02b7,
        0x1002_8293,
        if (include_call) custom0.encodePoseidon2(5) else 0x0000_0013,
        0x0000_0073,
    };
    for (instructions, 0..) |word, index| put(u32, &elf, program_offset + 4 * index, word);
    for (0..16) |lane| put(u32, &elf, data_offset + 4 * lane, @intCast(lane));
    return elf;
}

test "explicit extension runner retires one custom call outside the base trace" {
    const elf = makeExtensionElf(true);
    try std.testing.expectError(
        error.RequiredCapabilityUnavailable,
        runner.run(std.testing.allocator, &elf, 16),
    );

    var result = try runner.runPoseidon2Extension(std.testing.allocator, &elf, 16);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 4), result.base.step_count);
    try std.testing.expectEqual(@as(usize, 3), result.base.execution_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len());
    try std.testing.expectEqual(@as(usize, 1), result.execution_rows.rows().len);
    try std.testing.expectEqual(@as(u32, 3), result.calls.records()[0].execution_clock);
    try std.testing.expectEqual(@as(u32, 0x1008), result.calls.records()[0].pc);
    try std.testing.expectEqual(@as(u32, 0), result.execution_rows.rows()[0].call_index);
}

test "extension runner freezes zero calls canonically without changing base API" {
    const elf = makeExtensionElf(false);
    var result = try runner.runPoseidon2Extension(std.testing.allocator, &elf, 16);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.calls.len());
    try std.testing.expectEqual(@as(usize, 0), result.calls.capacity());
    try std.testing.expectEqual(@as(usize, 0), result.execution_rows.rows().len);
    try std.testing.expectEqual(@as(usize, 0), result.execution_rows.capacity());
}

//! Test-only builder for a minimal symbol-bearing Stark-V guest ELF.

const std = @import("std");
const sail_oracle = @import("../../frontends/riscv/runner/sail_oracle.zig");

const CODE_VADDR: u32 = 0x0001_0000;
const INPUT_START: u32 = 0x0018_0000;
const INPUT_END: u32 = INPUT_START + 12;
const INPUT_CAPACITY: usize = INPUT_END - INPUT_START;
const HALT_FLAG: u32 = 0x0010_0000;
const OUTPUT_LEN: u32 = 0x0010_0004;
const OUTPUT_DATA: u32 = 0x0010_0008;
const STACK_BOTTOM: u32 = 0x001F_FC00;
const STACK_TOP: u32 = 0x0020_0000;
const GLOBAL_POINTER: u32 = 0x0020_0800;
const OUTPUT_END: u32 = STACK_BOTTOM;

const Symbol = struct {
    name: []const u8,
    value: u32,
};

const instructions = [_]u32{
    0x0010_00B7, // LUI x1, __halt_flag
    0x0018_0237, // LUI x4, __input_start
    0x0002_2283, // LW x5, 0(x4): consume public input word 0
    0x0042_2303, // LW x6, 4(x4): consume public input word 1
    0x0082_2383, // LW x7, 8(x4): consume public input word 2
    0x0040_0113, // ADDI x2, x0, 4
    0x0020_A223, // SW x2, 4(x1): publish output_len = 4
    0x0050_A423, // SW x5, 8(x1): publish the loaded input word
    0x0010_0113, // ADDI x2, x0, 1
    0x0020_A023, // SW x2, 0(x1): set halt flag before the next fetch
};

const symbols = [_]Symbol{
    .{ .name = "__text_start", .value = CODE_VADDR },
    .{ .name = "__text_len", .value = instructions.len * 4 },
    .{ .name = "__data_start", .value = STACK_TOP },
    .{ .name = "__data_len", .value = 0 },
    .{ .name = "__global_pointer$", .value = GLOBAL_POINTER },
    .{ .name = "__stack_bottom", .value = STACK_BOTTOM },
    .{ .name = "__stack_top", .value = STACK_TOP },
    .{ .name = "__input_start", .value = INPUT_START },
    .{ .name = "__input_end", .value = INPUT_END },
    .{ .name = "__halt_flag", .value = HALT_FLAG },
    .{ .name = "__output_len", .value = OUTPUT_LEN },
    .{ .name = "__output_data", .value = OUTPUT_DATA },
    .{ .name = "__output_end", .value = OUTPUT_END },
};

const ELF_HEADER_SIZE: usize = 52;
const PROGRAM_HEADER_SIZE: usize = 32;
const SECTION_HEADER_SIZE: usize = 40;
const SYMBOL_ENTRY_SIZE: usize = 16;
const SECTION_COUNT: usize = 4;
const SHSTRTAB = "\x00.symtab\x00.strtab\x00.shstrtab\x00";

/// Build a release-shape guest with non-empty public input and output regions.
/// The caller owns the returned bytes.
pub fn buildPublicIoHaltElf(allocator: std.mem.Allocator) ![]u8 {
    const code_offset = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE;
    const code_size = instructions.len * @sizeOf(u32);
    const symtab_offset = code_offset + code_size;
    const symtab_size = (symbols.len + 1) * SYMBOL_ENTRY_SIZE;
    const strtab_size = comptime blk: {
        var size: usize = 1;
        for (symbols) |symbol| size += symbol.name.len + 1;
        break :blk size;
    };
    const strtab_offset = symtab_offset + symtab_size;
    const shstrtab_offset = strtab_offset + strtab_size;
    const section_headers_offset = shstrtab_offset + SHSTRTAB.len;
    const elf_size = section_headers_offset + SECTION_COUNT * SECTION_HEADER_SIZE;

    const elf = try allocator.alloc(u8, elf_size);
    @memset(elf, 0);

    elf[0..4].* = .{ 0x7F, 'E', 'L', 'F' };
    elf[4] = 1; // ELFCLASS32
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    writeU16(elf, 16, 2); // ET_EXEC
    writeU16(elf, 18, 0xF3); // EM_RISCV
    writeU32(elf, 20, 1);
    writeU32(elf, 24, CODE_VADDR);
    writeU32(elf, 28, ELF_HEADER_SIZE);
    writeU32(elf, 32, section_headers_offset);
    writeU16(elf, 40, ELF_HEADER_SIZE);
    writeU16(elf, 42, PROGRAM_HEADER_SIZE);
    writeU16(elf, 44, 1);
    writeU16(elf, 46, SECTION_HEADER_SIZE);
    writeU16(elf, 48, SECTION_COUNT);
    writeU16(elf, 50, 3); // .shstrtab section index

    writeU32(elf, ELF_HEADER_SIZE, 1); // PT_LOAD
    writeU32(elf, ELF_HEADER_SIZE + 4, code_offset);
    writeU32(elf, ELF_HEADER_SIZE + 8, CODE_VADDR);
    writeU32(elf, ELF_HEADER_SIZE + 16, code_size);
    writeU32(elf, ELF_HEADER_SIZE + 20, code_size);

    for (instructions, 0..) |instruction, index| {
        writeU32(elf, code_offset + index * @sizeOf(u32), instruction);
    }

    var string_offset: u32 = 1;
    var string_cursor = strtab_offset + 1;
    for (symbols, 0..) |symbol, index| {
        const symbol_offset = symtab_offset + (index + 1) * SYMBOL_ENTRY_SIZE;
        writeU32(elf, symbol_offset, string_offset);
        writeU32(elf, symbol_offset + 4, symbol.value);
        elf[symbol_offset + 12] = 0x10; // STB_GLOBAL
        writeU16(elf, symbol_offset + 14, 0xFFF1); // SHN_ABS

        @memcpy(elf[string_cursor .. string_cursor + symbol.name.len], symbol.name);
        string_cursor += symbol.name.len + 1;
        string_offset += @intCast(symbol.name.len + 1);
    }
    @memcpy(elf[shstrtab_offset .. shstrtab_offset + SHSTRTAB.len], SHSTRTAB);

    writeSectionHeader(elf, section_headers_offset, 0, 0, 0, 0, 0, 0);
    writeSectionHeader(
        elf,
        section_headers_offset + SECTION_HEADER_SIZE,
        1,
        2,
        symtab_offset,
        symtab_size,
        2,
        SYMBOL_ENTRY_SIZE,
    );
    writeSectionHeader(
        elf,
        section_headers_offset + 2 * SECTION_HEADER_SIZE,
        9,
        3,
        strtab_offset,
        strtab_size,
        0,
        0,
    );
    writeSectionHeader(
        elf,
        section_headers_offset + 3 * SECTION_HEADER_SIZE,
        17,
        3,
        shstrtab_offset,
        SHSTRTAB.len,
        0,
        0,
    );

    return elf;
}

/// The runner-initialized public-input region as the Sail oracle's seed
/// image. The image is derived from the fixture's declared input and address
/// constants, never from the retirement trace's load claims.
pub fn initialMemory(input: []const u8) ![INPUT_CAPACITY / 4]sail_oracle.MemoryWord {
    if (input.len > INPUT_CAPACITY) return error.InputTooLarge;

    var padded = [_]u8{0} ** INPUT_CAPACITY;
    @memcpy(padded[0..input.len], input);

    var words: [INPUT_CAPACITY / 4]sail_oracle.MemoryWord = undefined;
    for (&words, 0..) |*word, index| {
        const offset = index * @sizeOf(u32);
        word.* = .{
            .address = INPUT_START + @as(u32, @intCast(offset)),
            .value = std.mem.readInt(u32, padded[offset..][0..4], .little),
        };
    }
    return words;
}

fn writeSectionHeader(
    elf: []u8,
    offset: usize,
    name: u32,
    section_type: u32,
    file_offset: usize,
    size: usize,
    link: u32,
    entry_size: usize,
) void {
    writeU32(elf, offset, name);
    writeU32(elf, offset + 4, section_type);
    writeU32(elf, offset + 16, file_offset);
    writeU32(elf, offset + 20, size);
    writeU32(elf, offset + 24, link);
    writeU32(elf, offset + 28, @as(u32, if (section_type == 2) 1 else 0));
    writeU32(elf, offset + 32, 1);
    writeU32(elf, offset + 36, entry_size);
}

fn writeU16(bytes: []u8, offset: usize, value: anytype) void {
    std.mem.writeInt(u16, bytes[offset..][0..2], @intCast(value), .little);
}

fn writeU32(bytes: []u8, offset: usize, value: anytype) void {
    std.mem.writeInt(u32, bytes[offset..][0..4], @intCast(value), .little);
}

test "release ELF fixture derives the complete padded Sail input image" {
    const image = try initialMemory(&.{ 1, 2, 3, 4, 5, 6, 7, 8, 9 });
    try std.testing.expectEqual(@as(usize, 3), image.len);
    try std.testing.expectEqualDeep(
        [_]sail_oracle.MemoryWord{
            .{ .address = INPUT_START, .value = 0x0403_0201 },
            .{ .address = INPUT_START + 4, .value = 0x0807_0605 },
            .{ .address = INPUT_START + 8, .value = 0x0000_0009 },
        },
        image,
    );
    try std.testing.expectError(
        error.InputTooLarge,
        initialMemory(&([_]u8{0} ** (INPUT_CAPACITY + 1))),
    );
}

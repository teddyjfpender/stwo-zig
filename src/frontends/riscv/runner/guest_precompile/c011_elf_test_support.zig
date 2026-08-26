//! Test-only ELF emitter for a sequence of profile-labelled Poseidon2 calls.

const std = @import("std");
const custom0 = @import("../../isa/custom0.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const reference = @import("c011_scalar_reference_test_support.zig");

pub const state_base: u32 = 0x0030_0000;

pub const Completion = enum { ecall, self_loop };

const section_strings_offset: usize = 328;
const note_offset: usize = 384;
const descriptor_offset: usize = note_offset + 20;
const symbol_strings_offset: usize = 480;
const symbols_offset: usize = 544;
const program_offset: usize = 640;

pub const OwnedElf = struct {
    bytes: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedElf) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    states: []const reference.State,
) (std.mem.Allocator.Error || error{ EmptyCorpus, CorpusTooLarge })!OwnedElf {
    return buildWithCompletion(allocator, states, .ecall);
}

pub fn buildWithCompletion(
    allocator: std.mem.Allocator,
    states: []const reference.State,
    completion: Completion,
) (std.mem.Allocator.Error || error{ EmptyCorpus, CorpusTooLarge })!OwnedElf {
    if (states.len == 0) return error.EmptyCorpus;
    const word_count = std.math.mul(usize, states.len, 2) catch
        return error.CorpusTooLarge;
    const program_words = std.math.add(usize, word_count, 1) catch
        return error.CorpusTooLarge;
    const program_bytes = std.math.mul(usize, program_words, @sizeOf(u32)) catch
        return error.CorpusTooLarge;
    const data_bytes = std.math.mul(usize, states.len, @sizeOf(reference.State)) catch
        return error.CorpusTooLarge;
    const data_offset = std.mem.alignForward(usize, program_offset + program_bytes, 16);
    const elf_size = std.math.add(usize, data_offset, data_bytes) catch
        return error.CorpusTooLarge;
    const program_bytes_u32 = std.math.cast(u32, program_bytes) orelse
        return error.CorpusTooLarge;
    const data_bytes_u32 = std.math.cast(u32, data_bytes) orelse
        return error.CorpusTooLarge;
    if (@as(u64, state_base) + data_bytes_u32 > 0x4000_0000)
        return error.CorpusTooLarge;

    const elf = try allocator.alloc(u8, elf_size);
    errdefer allocator.free(elf);
    @memset(elf, 0);
    writeHeaders(elf, program_bytes_u32, data_offset, data_bytes_u32);
    writeAdmissionNote(elf);
    writeSymbols(elf, program_bytes_u32, data_bytes_u32);
    writeProgram(elf, states.len, completion);
    writeStates(elf[data_offset..], states);
    return .{ .bytes = elf, .allocator = allocator };
}

fn writeHeaders(
    elf: []u8,
    program_bytes: u32,
    data_offset: usize,
    data_bytes: u32,
) void {
    @memcpy(elf[0..4], "\x7fELF");
    elf[4] = 1;
    elf[5] = 1;
    elf[6] = 1;
    put(u16, elf, 16, 2);
    put(u16, elf, 18, 243);
    put(u32, elf, 20, 1);
    put(u32, elf, 24, 0x1000);
    put(u32, elf, 28, 52);
    put(u32, elf, 32, 128);
    put(u16, elf, 40, 52);
    put(u16, elf, 42, 32);
    put(u16, elf, 44, 2);
    put(u16, elf, 46, 40);
    put(u16, elf, 48, 5);
    put(u16, elf, 50, 1);

    // Executable segment.
    put(u32, elf, 52, 1);
    put(u32, elf, 56, program_offset);
    put(u32, elf, 60, 0x1000);
    put(u32, elf, 68, program_bytes);
    put(u32, elf, 72, program_bytes);
    put(u32, elf, 76, 5);
    put(u32, elf, 80, 4);

    // One contiguous writable segment, one 64-byte state per call.
    put(u32, elf, 84, 1);
    put(u32, elf, 88, @intCast(data_offset));
    put(u32, elf, 92, state_base);
    put(u32, elf, 100, data_bytes);
    put(u32, elf, 104, data_bytes);
    put(u32, elf, 108, 6);
    put(u32, elf, 112, 4);

    const section_strings = "\x00.shstrtab\x00.note.stwo.zkvm\x00.symtab\x00.strtab\x00";
    put(u32, elf, 168, 1);
    put(u32, elf, 172, 3);
    put(u32, elf, 184, section_strings_offset);
    put(u32, elf, 188, section_strings.len);
    put(u32, elf, 200, 1);
    @memcpy(
        elf[section_strings_offset .. section_strings_offset + section_strings.len],
        section_strings,
    );

    put(u32, elf, 208, 11);
    put(u32, elf, 212, 7);
    put(u32, elf, 224, note_offset);
    put(u32, elf, 228, 76);
    put(u32, elf, 240, 4);

    put(u32, elf, 248, 28);
    put(u32, elf, 252, 2);
    put(u32, elf, 264, symbols_offset);
    put(u32, elf, 268, 5 * 16);
    put(u32, elf, 272, 4);
    put(u32, elf, 276, 1);
    put(u32, elf, 280, 4);
    put(u32, elf, 284, 16);

    put(u32, elf, 288, 36);
    put(u32, elf, 292, 3);
    put(u32, elf, 304, symbol_strings_offset);
    put(u32, elf, 308, 49);
    put(u32, elf, 320, 1);
}

fn writeAdmissionNote(elf: []u8) void {
    const admission = execution_profile.admission;
    put(u32, elf, note_offset, admission.note_name.len);
    put(u32, elf, note_offset + 4, admission.descriptor_size);
    put(u32, elf, note_offset + 8, admission.note_type);
    @memcpy(elf[note_offset + 12 .. note_offset + 17], admission.note_name);
    @memcpy(elf[descriptor_offset .. descriptor_offset + 8], admission.descriptor_magic);
    put(u16, elf, descriptor_offset + 8, admission.schema_version);
    put(u16, elf, descriptor_offset + 10, 1);
    put(u64, elf, descriptor_offset + 12, execution_profile.poseidon2_capability_bit);
    put(u16, elf, descriptor_offset + 20, execution_profile.poseidon2_abi_version);
    @memcpy(
        elf[descriptor_offset + 24 .. descriptor_offset + 56],
        &execution_profile.poseidon2_semantic_digest,
    );
}

fn writeSymbols(elf: []u8, program_bytes: u32, data_bytes: u32) void {
    const names = "\x00__text_start\x00__text_len\x00__data_start\x00__data_len\x00";
    @memcpy(elf[symbol_strings_offset .. symbol_strings_offset + names.len], names);
    putSymbol(elf, 1, 1, 0x1000);
    putSymbol(elf, 2, 14, program_bytes);
    putSymbol(elf, 3, 25, state_base);
    putSymbol(elf, 4, 38, data_bytes);
}

fn putSymbol(elf: []u8, index: usize, name: u32, value: u32) void {
    const offset = symbols_offset + index * 16;
    put(u32, elf, offset, name);
    put(u32, elf, offset + 4, value);
}

fn writeProgram(elf: []u8, state_count: usize, completion: Completion) void {
    var cursor = program_offset;
    putInstruction(elf, &cursor, 0x0030_02b7); // LUI x5, 0x300.
    for (0..state_count) |index| {
        if (index != 0)
            putInstruction(elf, &cursor, 0x0402_8293); // ADDI x5, x5, 64.
        putInstruction(elf, &cursor, custom0.encodePoseidon2(5));
    }
    putInstruction(elf, &cursor, switch (completion) {
        .ecall => 0x0000_0073,
        .self_loop => 0x0000_006f,
    });
}

fn putInstruction(elf: []u8, cursor: *usize, instruction: u32) void {
    put(u32, elf, cursor.*, instruction);
    cursor.* += @sizeOf(u32);
}

fn writeStates(destination: []u8, states: []const reference.State) void {
    var cursor: usize = 0;
    for (states) |state| {
        for (state) |word| {
            put(u32, destination, cursor, word);
            cursor += @sizeOf(u32);
        }
    }
}

fn put(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}

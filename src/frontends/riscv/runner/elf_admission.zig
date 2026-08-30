//! Allocation-free parsing of exact zkVM execution-profile ELF metadata.
//!
//! Identity validation remains in `elf_loader.zig`; this module owns only the
//! section-table and note protocol so admission always completes before any
//! guest memory is loaded.

const std = @import("std");
const execution_profile = @import("../isa/execution_profile.zig");
const admission = execution_profile.admission;

pub const ExecutionProfile = execution_profile.ExecutionProfile;
pub const Error = error{
    InvalidSectionTable,
    InvalidAdmissionNote,
    DuplicateAdmissionNote,
    UnsupportedMachineProfile,
    UnsupportedRequiredCapabilities,
    UnsupportedPoseidon2Abi,
    UnsupportedKeccakfAbi,
    Poseidon2SemanticDigestMismatch,
    KeccakfSemanticDigestMismatch,
};

pub const sht_strtab: u32 = 3;
pub const sht_note: u32 = 7;
pub const shf_alloc: u32 = 1 << 1;
pub const section_header_size: usize = 40;

/// Parse admission after the caller has validated an ELF32 header and ensured
/// at least the complete 52-byte identity header is present.
pub fn parseAfterIdentityValidation(elf_bytes: []const u8) Error!ExecutionProfile {
    std.debug.assert(elf_bytes.len >= 52);
    const section_table_offset = @as(usize, readU32LE(elf_bytes[32..36]));
    const encoded_header_size = @as(usize, readU16LE(elf_bytes[46..48]));
    const encoded_section_count = @as(usize, readU16LE(elf_bytes[48..50]));
    const encoded_string_index = readU16LE(elf_bytes[50..52]);

    if (section_table_offset == 0) {
        if (encoded_section_count != 0 or encoded_string_index != 0)
            return error.InvalidSectionTable;
        return .rv32im_zkvm_v1;
    }
    if (encoded_header_size < section_header_size)
        return error.InvalidSectionTable;

    // ELF32 stores extended section counts and string-table indices in the
    // null section header. These forms must not make an authoritative note
    // appear absent merely because compact header fields overflowed.
    const section_zero = sectionHeader(
        elf_bytes,
        section_table_offset,
        encoded_header_size,
        0,
    ) orelse return error.InvalidSectionTable;
    const section_count = if (encoded_section_count == 0)
        @as(usize, readU32LE(section_zero[20..24]))
    else
        encoded_section_count;
    if (section_count == 0) {
        if (encoded_string_index != 0)
            return error.InvalidSectionTable;
        return .rv32im_zkvm_v1;
    }

    const table_size = std.math.mul(
        usize,
        section_count,
        encoded_header_size,
    ) catch return error.InvalidSectionTable;
    _ = boundedSlice(elf_bytes, section_table_offset, table_size) orelse
        return error.InvalidSectionTable;

    const section_name_index: usize = if (encoded_string_index == 0xffff)
        @as(usize, readU32LE(section_zero[24..28]))
    else
        @as(usize, encoded_string_index);
    if (section_name_index == 0)
        return .rv32im_zkvm_v1;
    if (section_name_index >= section_count)
        return error.InvalidSectionTable;

    const strings_header = sectionHeader(
        elf_bytes,
        section_table_offset,
        encoded_header_size,
        section_name_index,
    ) orelse return error.InvalidSectionTable;
    if (readU32LE(strings_header[4..8]) != sht_strtab)
        return error.InvalidSectionTable;
    const strings = boundedSlice(
        elf_bytes,
        @as(usize, readU32LE(strings_header[16..20])),
        @as(usize, readU32LE(strings_header[20..24])),
    ) orelse return error.InvalidSectionTable;

    var admission_header: ?[]const u8 = null;
    for (0..section_count) |index| {
        const header = sectionHeader(
            elf_bytes,
            section_table_offset,
            encoded_header_size,
            index,
        ) orelse return error.InvalidSectionTable;
        const name = sectionName(
            strings,
            @as(usize, readU32LE(header[0..4])),
        ) orelse return error.InvalidSectionTable;
        if (!std.mem.eql(u8, name, admission.section_name)) continue;
        if (admission_header != null)
            return error.DuplicateAdmissionNote;
        admission_header = header;
    }

    const header = admission_header orelse return .rv32im_zkvm_v1;
    if (readU32LE(header[4..8]) != sht_note or
        readU32LE(header[8..12]) & shf_alloc != 0 or
        readU32LE(header[32..36]) != 4)
    {
        return error.InvalidAdmissionNote;
    }

    const note_offset = @as(usize, readU32LE(header[16..20]));
    if (note_offset & 3 != 0)
        return error.InvalidAdmissionNote;
    const note_bytes = boundedSlice(
        elf_bytes,
        note_offset,
        @as(usize, readU32LE(header[20..24])),
    ) orelse return error.InvalidAdmissionNote;
    return parseNotePayload(note_bytes);
}

fn parseNotePayload(note_bytes: []const u8) Error!ExecutionProfile {
    var cursor: usize = 0;
    var note_count: usize = 0;
    var selected: ?ExecutionProfile = null;

    while (cursor < note_bytes.len) {
        const note_header = boundedSlice(note_bytes, cursor, 12) orelse
            return error.InvalidAdmissionNote;
        const name_size = @as(usize, readU32LE(note_header[0..4]));
        const descriptor_size = @as(usize, readU32LE(note_header[4..8]));
        const note_type = readU32LE(note_header[8..12]);

        const name_start = std.math.add(usize, cursor, 12) catch
            return error.InvalidAdmissionNote;
        const name = boundedSlice(note_bytes, name_start, name_size) orelse
            return error.InvalidAdmissionNote;
        const descriptor_start = align4(std.math.add(
            usize,
            name_start,
            name_size,
        ) catch return error.InvalidAdmissionNote) orelse
            return error.InvalidAdmissionNote;
        const descriptor = boundedSlice(
            note_bytes,
            descriptor_start,
            descriptor_size,
        ) orelse return error.InvalidAdmissionNote;
        const next = align4(std.math.add(
            usize,
            descriptor_start,
            descriptor_size,
        ) catch return error.InvalidAdmissionNote) orelse
            return error.InvalidAdmissionNote;
        if (next > note_bytes.len)
            return error.InvalidAdmissionNote;

        note_count += 1;
        if (note_count != 1)
            return error.DuplicateAdmissionNote;
        if (name_size != admission.note_name.len or
            !std.mem.eql(u8, name, admission.note_name) or
            note_type != admission.note_type or
            descriptor_size != admission.descriptor_size)
        {
            return error.InvalidAdmissionNote;
        }

        selected = try parseDescriptor(descriptor);
        cursor = next;
    }

    if (note_count != 1 or cursor != note_bytes.len)
        return error.InvalidAdmissionNote;
    return selected.?;
}

fn parseDescriptor(descriptor: []const u8) Error!ExecutionProfile {
    if (!std.mem.eql(u8, descriptor[0..8], admission.descriptor_magic) or
        readU16LE(descriptor[8..10]) != admission.schema_version)
    {
        return error.InvalidAdmissionNote;
    }

    if (readU16LE(descriptor[22..24]) != 0)
        return error.InvalidAdmissionNote;
    const profile = std.meta.intToEnum(
        ExecutionProfile,
        readU16LE(descriptor[10..12]),
    ) catch return error.UnsupportedMachineProfile;
    return switch (profile) {
        .rv32im_zkvm_v1 => error.UnsupportedMachineProfile,
        .rv32im_zkvm_poseidon2_v1 => blk: {
            if (readU64LE(descriptor[12..20]) != execution_profile.poseidon2_capability_bit)
                return error.UnsupportedRequiredCapabilities;
            if (readU16LE(descriptor[20..22]) != execution_profile.poseidon2_abi_version)
                return error.UnsupportedPoseidon2Abi;
            if (!std.mem.eql(u8, descriptor[24..56], &execution_profile.poseidon2_semantic_digest))
                return error.Poseidon2SemanticDigestMismatch;
            break :blk profile;
        },
        .rv32im_zkvm_keccakf_v1 => blk: {
            if (readU64LE(descriptor[12..20]) != execution_profile.keccakf_capability_bit)
                return error.UnsupportedRequiredCapabilities;
            if (readU16LE(descriptor[20..22]) != execution_profile.keccakf_abi_version)
                return error.UnsupportedKeccakfAbi;
            if (!std.mem.eql(u8, descriptor[24..56], &execution_profile.keccakf_semantic_digest))
                return error.KeccakfSemanticDigestMismatch;
            break :blk profile;
        },
    };
}

fn readU16LE(bytes: *const [2]u8) u16 {
    return @as(u16, bytes[0]) | (@as(u16, bytes[1]) << 8);
}

fn readU32LE(bytes: *const [4]u8) u32 {
    return @as(u32, bytes[0]) |
        (@as(u32, bytes[1]) << 8) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 24);
}

fn readU64LE(bytes: *const [8]u8) u64 {
    return @as(u64, readU32LE(bytes[0..4])) |
        (@as(u64, readU32LE(bytes[4..8])) << 32);
}

fn boundedSlice(bytes: []const u8, offset: usize, size: usize) ?[]const u8 {
    const end = std.math.add(usize, offset, size) catch return null;
    if (end > bytes.len) return null;
    return bytes[offset..end];
}

fn align4(value: usize) ?usize {
    const rounded = std.math.add(usize, value, 3) catch return null;
    return rounded & ~@as(usize, 3);
}

fn sectionHeader(
    elf_bytes: []const u8,
    table_offset: usize,
    entry_size: usize,
    index: usize,
) ?[]const u8 {
    const relative = std.math.mul(usize, index, entry_size) catch return null;
    const offset = std.math.add(usize, table_offset, relative) catch return null;
    return boundedSlice(elf_bytes, offset, section_header_size);
}

fn sectionName(strings: []const u8, offset: usize) ?[]const u8 {
    if (offset >= strings.len) return null;
    const tail = strings[offset..];
    const end = std.mem.indexOfScalar(u8, tail, 0) orelse return null;
    return tail[0..end];
}

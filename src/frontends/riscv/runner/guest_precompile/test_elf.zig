//! Canonical tiny ELF fixture for repository-owned extension tests.

const std = @import("std");
const custom0 = @import("../../isa/custom0.zig");
const bulk_memcpy = @import("../../isa/bulk_memcpy_candidate_v1.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const signer_abi = @import("../../isa/ethereum_signer_recovery.zig");
const stack_swap = @import("../../isa/stack_swap_candidate_v1.zig");
const stack_swap_registry = @import("../../isa/stack_swap_private_registry_v1.zig");

const section_strings_offset: usize = 328;
const note_offset: usize = 384;
const descriptor_offset: usize = note_offset + 20;
const symbol_strings_offset: usize = 480;
const symbols_offset: usize = 560;
const program_offset: usize = 640;
const poseidon_data_size: usize = 64;
const keccakf_data_size: usize = 256;

fn imageSize(comptime instruction_count: usize, comptime writable_size: usize) usize {
    return program_offset + instruction_count * @sizeOf(u32) + writable_size;
}

pub const elf_size: usize = imageSize(4, poseidon_data_size);

pub const Completion = enum { ecall, self_loop };

fn put(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}

pub fn build(include_call: bool, completion: Completion) [elf_size]u8 {
    const instructions = [_]u32{
        0x0010_02b7,
        0x1002_8293,
        if (include_call) custom0.encodePoseidon2(5) else 0x0000_0013,
        switch (completion) {
            .ecall => 0x0000_0073,
            .self_loop => 0x0000_006f,
        },
    };
    return buildProgram(
        instructions.len,
        &instructions,
        poseidon_data_size,
        .rv32im_zkvm_poseidon2_v1,
    );
}

pub const keccakf_elf_size: usize = imageSize(4, keccakf_data_size);

pub fn buildKeccakf(completion: Completion) [keccakf_elf_size]u8 {
    const instructions = [_]u32{
        0x0010_02b7,
        0x1002_8293,
        custom0.encodeKeccakf(5),
        switch (completion) {
            .ecall => 0x0000_0073,
            .self_loop => 0x0000_006f,
        },
    };
    return buildProgram(
        instructions.len,
        &instructions,
        keccakf_data_size,
        .rv32im_zkvm_keccakf_v1,
    );
}

pub const ethereum_instructions = [_]u32{
    0x0010_02b7, // LUI x5, 0x100.
    0x1002_8293, // ADDI x5, x5, 0x100: signer in/out record.
    custom0.encodeSecp256k1Recover(5),
    0x0a82_8313, // ADDI x6, x5, 168: adjacent Keccak state.
    custom0.encodeKeccakf(6),
    0x0000_0073, // ECALL.
};

const ethereum_data_size: usize = 384;
pub const ethereum_elf_size: usize =
    imageSize(ethereum_instructions.len, ethereum_data_size);

/// Valid fixed d=1, k=1 ECDSA recovery followed by one Keccak-f call.
pub fn buildEthereum() [ethereum_elf_size]u8 {
    var elf = buildProgram(
        ethereum_instructions.len,
        &ethereum_instructions,
        ethereum_data_size,
        .rv32im_zkvm_ethereum_v1,
    );
    const data_offset = program_offset + ethereum_instructions.len * @sizeOf(u32);
    var digest: [32]u8 = @splat(0);
    digest[31] = 1;
    const point = std.crypto.ecc.Secp256k1.basePoint.affineCoordinates();
    const r = point.x.toBytes(.big);
    const r_scalar = std.crypto.ecc.Secp256k1.scalar.Scalar.fromBytes(r, .big) catch
        unreachable;
    const s = r_scalar.add(.one).toBytes(.big);
    @memcpy(elf[data_offset + signer_abi.digest_offset ..][0..32], &digest);
    @memcpy(elf[data_offset + signer_abi.r_offset ..][0..32], &r);
    @memcpy(elf[data_offset + signer_abi.s_offset ..][0..32], &s);
    put(u32, &elf, data_offset + signer_abi.recovery_id_offset, 0);
    @memset(
        elf[data_offset + signer_abi.public_key_offset .. data_offset + signer_abi.record_size],
        0,
    );
    return elf;
}

pub const ethereum_bulk_memcpy_source: u32 = 0x0010_0100;
pub const ethereum_bulk_memcpy_destination: u32 = 0x0010_0140;
pub const ethereum_bulk_memcpy_length: usize = 32;
pub const ethereum_bulk_memcpy_instructions = [_]u32{
    0x0010_0537, // LUI a0, 0x100.
    0x1405_0513, // ADDI a0, a0, 0x140: destination.
    0x0010_05b7, // LUI a1, 0x100.
    0x1005_8593, // ADDI a1, a1, 0x100: source.
    0x0200_0613, // ADDI a2, x0, 32: byte length.
    bulk_memcpy.fixed_word,
    0x0000_0073, // ECALL.
};

const ethereum_bulk_memcpy_data_size: usize = 128;
pub const ethereum_bulk_memcpy_elf_size: usize =
    imageSize(ethereum_bulk_memcpy_instructions.len, ethereum_bulk_memcpy_data_size);

/// Minimal candidate-only Ethereum ELF with one sound aligned/disjoint call.
pub fn buildEthereumBulkMemcpyCandidate() [ethereum_bulk_memcpy_elf_size]u8 {
    var elf = buildProgram(
        ethereum_bulk_memcpy_instructions.len,
        &ethereum_bulk_memcpy_instructions,
        ethereum_bulk_memcpy_data_size,
        .rv32im_zkvm_ethereum_v1,
    );
    const data_offset = program_offset +
        ethereum_bulk_memcpy_instructions.len * @sizeOf(u32);
    for (elf[data_offset..][0..ethereum_bulk_memcpy_length], 0..) |*byte, index|
        byte.* = @intCast(index + 1);
    return elf;
}

pub const ethereum_combined_source: u32 = 0x0010_0100;
pub const ethereum_combined_bulk_destination: u32 = 0x0010_0140;
pub const ethereum_combined_swap_rhs: u32 = 0x0010_0180;
pub const ethereum_combined_word_bytes: usize = 32;
pub const ethereum_combined_swap_word: u32 =
    (@as(u32, stack_swap_registry.allocated_funct7) << 25) |
    (@as(u32, stack_swap.rhs_pointer_register) << 20) |
    (@as(u32, stack_swap.lhs_pointer_register) << 15) |
    @as(u32, stack_swap.major_opcode);
pub const ethereum_combined_instructions = [_]u32{
    0x0010_0537, // LUI a0, 0x100.
    0x1405_0513, // ADDI a0, a0, 0x140: bulk destination.
    0x0010_05b7, // LUI a1, 0x100.
    0x1005_8593, // ADDI a1, a1, 0x100: bulk source.
    0x0200_0613, // ADDI a2, x0, 32.
    bulk_memcpy.fixed_word,
    0x0010_0537, // LUI a0, 0x100.
    0x1405_0513, // ADDI a0, a0, 0x140: SWAP lhs.
    0x0010_05b7, // LUI a1, 0x100.
    0x1805_8593, // ADDI a1, a1, 0x180: SWAP rhs.
    ethereum_combined_swap_word,
    0x0000_006f, // JAL x0, 0: proof-bearing completion boundary.
};

const ethereum_combined_data_size: usize = 160;
pub const ethereum_combined_elf_size: usize =
    imageSize(ethereum_combined_instructions.len, ethereum_combined_data_size);

/// Final synthetic candidate ELF carrying both ordered private members.
pub fn buildEthereumCombinedCandidate() [ethereum_combined_elf_size]u8 {
    var elf = buildProgram(
        ethereum_combined_instructions.len,
        &ethereum_combined_instructions,
        ethereum_combined_data_size,
        .rv32im_zkvm_ethereum_v1,
    );
    const data_offset = program_offset +
        ethereum_combined_instructions.len * @sizeOf(u32);
    for (elf[data_offset..][0..ethereum_combined_word_bytes], 0..) |*byte, index|
        byte.* = @intCast(index + 1);
    for (elf[data_offset + 0x80 ..][0..ethereum_combined_word_bytes], 0..) |*byte, index|
        byte.* = @intCast(0x80 + index);
    return elf;
}

/// Minimal admitted program for temporal-recursion custody tests. Both
/// segments retire the same opcode family, while the second subsequently
/// reaches a genuine proof-bearing completion boundary.
pub const temporal_pair_instructions = [_]u32{
    0x0010_00B7, // LUI x1, 0x100.
    0x0010_0137, // LUI x2, 0x100.
    0x0000_006F, // JAL x0, 0: proof-bearing completion.
    0x0000_0013, // Unreachable NOP; retains canonical four-word geometry.
};

pub const temporal_pair_elf_size: usize =
    imageSize(temporal_pair_instructions.len, poseidon_data_size);

pub fn buildTemporalPair() [temporal_pair_elf_size]u8 {
    return buildProgram(
        temporal_pair_instructions.len,
        &temporal_pair_instructions,
        poseidon_data_size,
        .rv32im_zkvm_poseidon2_v1,
    );
}

/// Four adjacent single-instruction segments for the first multi-level
/// temporal aggregation gate.  A terminal self-loop remains outside all four
/// executed spans.
pub const temporal_quad_instructions = [_]u32{
    0x0010_00B7, // LUI x1, 0x100.
    0x0010_0137, // LUI x2, 0x100.
    0x0010_01B7, // LUI x3, 0x100.
    0x0010_0237, // LUI x4, 0x100.
    0x0000_006F, // JAL x0, 0: proof-bearing completion.
    0x0000_0013, // Unreachable NOP; keeps data clear of the terminal word.
};

pub const temporal_quad_elf_size: usize =
    imageSize(temporal_quad_instructions.len, poseidon_data_size);

pub fn buildTemporalQuad() [temporal_quad_elf_size]u8 {
    return buildProgram(
        temporal_quad_instructions.len,
        &temporal_quad_instructions,
        poseidon_data_size,
        .rv32im_zkvm_poseidon2_v1,
    );
}

/// A straight-line production witness containing at least one retirement from
/// every canonical RV32IM opcode family. The final self-loop is observed but
/// not retired, matching recursive segment completion semantics.
pub const all_family_instructions = [_]u32{
    0x0010_00B7, // LUI x1, 0x100: data segment base.
    0x1000_8093, // ADDI x1, x1, 0x100.
    0x0000_A283, // LW x5, 0(x1).
    0x0070_0313, // ADDI x6, x0, 7.
    0x0030_0393, // ADDI x7, x0, 3.
    0x0073_0433, // ADD x8, x6, x7.
    0x0003_0263, // BEQ x6, x0, +4 (not taken).
    0x0003_4263, // BLT x6, x0, +4 (not taken).
    0x0273_44B3, // DIV x9, x6, x7.
    0x0040_006F, // JAL x0, +4.
    0x0083_2513, // SLTI x10, x6, 8.
    0x0063_A5B3, // SLT x11, x7, x6.
    0x0273_0633, // MUL x12, x6, x7.
    0x0273_16B3, // MULH x13, x6, x7.
    0x0023_1713, // SLLI x14, x6, 2.
    0x0073_17B3, // SLL x15, x6, x7.
    0x0FF0_000F, // FENCE.
    0x0000_0817, // AUIPC x16, 0.
    0x00C8_0813, // ADDI x16, x16, 12.
    0x0008_0067, // JALR x0, x16, 0.
    0x00A0_A023, // SW x10, 0(x1).
    0x0000_006F, // JAL x0, 0: proof-bearing completion.
};

pub const all_family_elf_size: usize =
    imageSize(all_family_instructions.len, poseidon_data_size);

pub fn buildAllFamilies() [all_family_elf_size]u8 {
    return buildProgram(
        all_family_instructions.len,
        &all_family_instructions,
        poseidon_data_size,
        .rv32im_zkvm_poseidon2_v1,
    );
}

fn buildProgram(
    comptime instruction_count: usize,
    instructions: *const [instruction_count]u32,
    comptime writable_size: usize,
    comptime profile: execution_profile.ExecutionProfile,
) [imageSize(instruction_count, writable_size)]u8 {
    const program_size = instruction_count * @sizeOf(u32);
    const data_offset = program_offset + program_size;
    var elf = [_]u8{0} ** imageSize(instruction_count, writable_size);
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
    put(u16, &elf, 48, 5);
    put(u16, &elf, 50, 1);

    // Executable and one writable 16-word state segment.
    put(u32, &elf, 52, 1);
    put(u32, &elf, 56, program_offset);
    put(u32, &elf, 60, 0x1000);
    put(u32, &elf, 68, program_size);
    put(u32, &elf, 72, program_size);
    put(u32, &elf, 76, 5);
    put(u32, &elf, 80, 4);
    put(u32, &elf, 84, 1);
    put(u32, &elf, 88, data_offset);
    put(u32, &elf, 92, 0x0010_0100);
    put(u32, &elf, 100, writable_size);
    put(u32, &elf, 104, writable_size);
    put(u32, &elf, 108, 6);
    put(u32, &elf, 112, 4);

    // Section names, profile note, and declared-program symbols.
    const strings = "\x00.shstrtab\x00.note.stwo.zkvm\x00.symtab\x00.strtab\x00";
    put(u32, &elf, 168, 1);
    put(u32, &elf, 172, 3);
    put(u32, &elf, 184, section_strings_offset);
    put(u32, &elf, 188, strings.len);
    put(u32, &elf, 200, 1);
    @memcpy(
        elf[section_strings_offset .. section_strings_offset + strings.len],
        strings,
    );
    put(u32, &elf, 208, 11);
    put(u32, &elf, 212, 7);
    put(u32, &elf, 224, note_offset);
    put(u32, &elf, 228, 76);
    put(u32, &elf, 240, 4);

    // SHT_SYMTAB at section 3, linked to SHT_STRTAB section 4.
    put(u32, &elf, 248, 28);
    put(u32, &elf, 252, 2);
    put(u32, &elf, 264, symbols_offset);
    put(u32, &elf, 268, 3 * 16);
    put(u32, &elf, 272, 4);
    put(u32, &elf, 276, 1);
    put(u32, &elf, 280, 4);
    put(u32, &elf, 284, 16);
    put(u32, &elf, 288, 36);
    put(u32, &elf, 292, 3);
    const symbol_strings = "\x00__text_start\x00__text_len\x00";
    put(u32, &elf, 304, symbol_strings_offset);
    put(u32, &elf, 308, symbol_strings.len);
    put(u32, &elf, 320, 1);
    @memcpy(
        elf[symbol_strings_offset .. symbol_strings_offset + symbol_strings.len],
        symbol_strings,
    );

    // Null symbol, then the two exact declaration values consumed by capture.
    put(u32, &elf, symbols_offset + 16, 1);
    put(u32, &elf, symbols_offset + 20, 0x1000);
    put(u32, &elf, symbols_offset + 32, 14);
    put(u32, &elf, symbols_offset + 36, program_size);

    const admission = execution_profile.admission;
    put(u32, &elf, note_offset, admission.note_name.len);
    put(u32, &elf, note_offset + 4, admission.descriptor_size);
    put(u32, &elf, note_offset + 8, admission.note_type);
    @memcpy(elf[note_offset + 12 .. note_offset + 17], admission.note_name);
    @memcpy(elf[descriptor_offset .. descriptor_offset + 8], admission.descriptor_magic);
    put(u16, &elf, descriptor_offset + 8, admission.schema_version);
    put(u16, &elf, descriptor_offset + 10, @intFromEnum(profile));
    put(u64, &elf, descriptor_offset + 12, profile.requiredCapabilities());
    const abi_version, const semantic_digest = switch (profile) {
        .rv32im_zkvm_poseidon2_v1 => .{
            execution_profile.poseidon2_abi_version,
            execution_profile.poseidon2_semantic_digest,
        },
        .rv32im_zkvm_keccakf_v1 => .{
            execution_profile.keccakf_abi_version,
            execution_profile.keccakf_semantic_digest,
        },
        .rv32im_zkvm_ethereum_v1 => .{
            execution_profile.ethereum_abi_version,
            execution_profile.ethereum_semantic_digest,
        },
        .rv32im_zkvm_v1 => unreachable,
    };
    put(u16, &elf, descriptor_offset + 20, abi_version);
    @memcpy(
        elf[descriptor_offset + 24 .. descriptor_offset + 56],
        &semantic_digest,
    );

    for (instructions, 0..) |word, index|
        put(u32, &elf, program_offset + 4 * index, word);
    for (0..writable_size / @sizeOf(u32)) |lane|
        put(u32, &elf, data_offset + 4 * lane, @intCast(lane));
    return elf;
}

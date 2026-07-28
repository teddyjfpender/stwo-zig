//! Program-relation projection of the canonical Sail-facing decoder.
//!
//! There is one instruction decoder in the repository. This module only maps
//! an admitted architectural instruction into its proof-protocol tuple.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const isa_decode = @import("../../isa/decode.zig");
const opcode_manifest = @import("../../opcode_manifest.zig");
const opcode_mod = @import("opcode.zig");

pub const Opcode = opcode_mod.Opcode;
pub const ProgramValues = [4]u32;

pub const Error = error{
    InvalidInstruction,
    UnsupportedInstructionClass,
};

pub const DecodedInstruction = struct {
    opcode: Opcode,
    rd: u5,
    rs1: u5,
    rs2: u5,
    imm: i32,
};

pub fn decodeInstruction(word: u32) Error!DecodedInstruction {
    const decoded = isa_decode.DecodedInst.decode(word) catch
        return Error.InvalidInstruction;
    const proof_opcode = isa_decode.proofOpcode(decoded.opcode) catch
        return Error.UnsupportedInstructionClass;
    return .{
        .opcode = proof_opcode,
        .rd = decoded.rd,
        .rs1 = decoded.rs1,
        .rs2 = decoded.rs2,
        .imm = decoded.imm,
    };
}

/// Return the four values following `pc` in Stark-V's `program_access`
/// relation. Signed immediates use their canonical M31 representation.
pub fn decodeProgramWord(word: u32) Error!ProgramValues {
    const inst = try decodeInstruction(word);
    const id = inst.opcode.protocolId();
    return switch (opcode_manifest.entry(inst.opcode).program_shape) {
        .register => .{ id, inst.rd, inst.rs1, inst.rs2 },
        .store => .{ id, inst.rs1, inst.rs2, immediateToFelt(inst.imm) },
        .load => .{ id, inst.rs1, inst.rd, immediateToFelt(inst.imm) },
        .shift_immediate => .{ id, inst.rd, inst.rs1, @as(u32, @bitCast(inst.imm)) & 0x1f },
        .immediate => .{
            id,
            inst.rd,
            inst.rs1,
            @as(u32, @bitCast(inst.imm)) & 0xfff,
        },
        .jalr => .{ id, inst.rd, inst.rs1, immediateToFelt(inst.imm) },
        .lui => .{ id, inst.rd, (word >> 12) & 0xfffff, 0 },
        .auipc, .jal => .{ id, inst.rd, immediateToFelt(inst.imm), 0 },
        .branch => .{
            id,
            inst.rs1,
            inst.rs2,
            immediateToFelt(inst.imm),
        },
        .fence => .{
            id,
            inst.rd,
            inst.rs1,
            @as(u32, @bitCast(inst.imm)) & 0xfff,
        },
    };
}

pub fn immediateToFelt(immediate: i32) u32 {
    const signed: i64 = immediate;
    const modulus: i64 = m31.Modulus;
    return @intCast(@mod(signed, modulus));
}

fn encodeR(funct7: u32, funct3: u32) u32 {
    return (funct7 << 25) | (3 << 20) | (2 << 15) | (funct3 << 12) | (1 << 7) | 0x33;
}

fn encodeI(immediate: i32, funct3: u32, instruction_opcode: u32) u32 {
    const encoded: u32 = @bitCast(immediate);
    return ((encoded & 0xfff) << 20) | (2 << 15) | (funct3 << 12) | (1 << 7) | instruction_opcode;
}

fn encodeS(funct3: u32) u32 {
    return (3 << 20) | (2 << 15) | (funct3 << 12) | 0x23;
}

fn encodeB(funct3: u32) u32 {
    return (3 << 20) | (2 << 15) | (funct3 << 12) | (4 << 8) | 0x63;
}

test "decoded program: every proof-bearing RV32IM word maps to its protocol id" {
    const Case = struct { word: u32, opcode: Opcode };
    const cases = [_]Case{
        .{ .word = encodeR(0x00, 0), .opcode = .add },
        .{ .word = encodeR(0x20, 0), .opcode = .sub },
        .{ .word = encodeR(0x00, 1), .opcode = .sll },
        .{ .word = encodeR(0x00, 2), .opcode = .slt },
        .{ .word = encodeR(0x00, 3), .opcode = .sltu },
        .{ .word = encodeR(0x00, 4), .opcode = .xor },
        .{ .word = encodeR(0x00, 5), .opcode = .srl },
        .{ .word = encodeR(0x20, 5), .opcode = .sra },
        .{ .word = encodeR(0x00, 6), .opcode = .@"or" },
        .{ .word = encodeR(0x00, 7), .opcode = .@"and" },
        .{ .word = encodeI(-1, 0, 0x13), .opcode = .addi },
        .{ .word = encodeI(-1, 2, 0x13), .opcode = .slti },
        .{ .word = encodeI(-1, 3, 0x13), .opcode = .sltiu },
        .{ .word = encodeI(-1, 4, 0x13), .opcode = .xori },
        .{ .word = encodeI(-1, 6, 0x13), .opcode = .ori },
        .{ .word = encodeI(-1, 7, 0x13), .opcode = .andi },
        .{ .word = encodeI(3, 1, 0x13), .opcode = .slli },
        .{ .word = encodeI(3, 5, 0x13), .opcode = .srli },
        .{ .word = encodeI(0x403, 5, 0x13), .opcode = .srai },
        .{ .word = encodeI(-4, 0, 0x03), .opcode = .lb },
        .{ .word = encodeI(-4, 1, 0x03), .opcode = .lh },
        .{ .word = encodeI(-4, 2, 0x03), .opcode = .lw },
        .{ .word = encodeI(-4, 4, 0x03), .opcode = .lbu },
        .{ .word = encodeI(-4, 5, 0x03), .opcode = .lhu },
        .{ .word = encodeS(0), .opcode = .sb },
        .{ .word = encodeS(1), .opcode = .sh },
        .{ .word = encodeS(2), .opcode = .sw },
        .{ .word = encodeB(0), .opcode = .beq },
        .{ .word = encodeB(1), .opcode = .bne },
        .{ .word = encodeB(4), .opcode = .blt },
        .{ .word = encodeB(5), .opcode = .bge },
        .{ .word = encodeB(6), .opcode = .bltu },
        .{ .word = encodeB(7), .opcode = .bgeu },
        .{ .word = 0x000000ef, .opcode = .jal },
        .{ .word = encodeI(-1, 0, 0x67), .opcode = .jalr },
        .{ .word = 0x123450b7, .opcode = .lui },
        .{ .word = 0x12345097, .opcode = .auipc },
        .{ .word = encodeR(0x01, 0), .opcode = .mul },
        .{ .word = encodeR(0x01, 1), .opcode = .mulh },
        .{ .word = encodeR(0x01, 2), .opcode = .mulhsu },
        .{ .word = encodeR(0x01, 3), .opcode = .mulhu },
        .{ .word = encodeR(0x01, 4), .opcode = .div },
        .{ .word = encodeR(0x01, 5), .opcode = .divu },
        .{ .word = encodeR(0x01, 6), .opcode = .rem },
        .{ .word = encodeR(0x01, 7), .opcode = .remu },
        .{ .word = 0x0ff0000f, .opcode = .fence },
    };
    try std.testing.expectEqual(@as(usize, 46), cases.len);
    for (cases) |case| {
        const decoded = try decodeInstruction(case.word);
        try std.testing.expectEqual(case.opcode, decoded.opcode);
        try std.testing.expectEqual(case.opcode.protocolId(), (try decodeProgramWord(case.word))[0]);
    }
}

test "decoded program: pinned numeric tuple vectors" {
    const cases = [_]struct { word: u32, expected: ProgramValues }{
        .{ .word = 0x002081b3, .expected = .{ 0, 3, 1, 2 } },
        .{ .word = 0xfff30293, .expected = .{ 10, 5, 6, 4095 } },
        .{ .word = 0x00311093, .expected = .{ 16, 1, 2, 3 } },
        .{ .word = 0x0082a203, .expected = .{ 21, 5, 4, 8 } },
        .{ .word = 0x0042a623, .expected = .{ 26, 5, 4, 12 } },
        .{ .word = 0xabcde3b7, .expected = .{ 35, 7, 0xabcde, 0 } },
        .{ .word = 0x10000417, .expected = .{ 36, 8, 0x10000000, 0 } },
        .{ .word = 0x010000ef, .expected = .{ 33, 1, 16, 0 } },
        .{ .word = 0x00208463, .expected = .{ 27, 1, 2, 8 } },
        .{ .word = 0xf5358f8f, .expected = .{ 45, 31, 11, 0xf53 } },
    };
    for (cases) |case| try std.testing.expectEqual(case.expected, try decodeProgramWord(case.word));
}

test "decoded program: negative signed immediates use canonical M31" {
    const jalr = try decodeProgramWord(0xfff080e7);
    try std.testing.expectEqual(m31.Modulus - 1, jalr[3]);
    const branch = try decodeProgramWord(0xfe208ee3);
    try std.testing.expectEqual(m31.Modulus - 4, branch[3]);
}

test "decoded program: rejects the manifest-owned proof preflight matrix" {
    for (opcode_manifest.proof_rejection_vectors) |vector| {
        const expected: Error = switch (vector.kind) {
            .unsupported_instruction_class => Error.UnsupportedInstructionClass,
            .invalid_instruction => Error.InvalidInstruction,
        };
        try std.testing.expectError(expected, decodeProgramWord(vector.word));
    }
}

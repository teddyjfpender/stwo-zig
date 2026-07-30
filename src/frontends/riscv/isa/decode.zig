//! Strict Sail-compatible RISC-V RV32IM instruction decoder.
//!
//! Decodes a 32-bit instruction word into an `Opcode`, destination/source
//! register indices, and an immediate value. Supports all RV32IM
//! instructions in the proof-bearing profile.

const std = @import("std");
const opcode_manifest = @import("../opcode_manifest.zig");

/// All RV32IM opcodes.
pub const Opcode = enum(u8) {
    // ---- RV32I: R-type arithmetic ----
    ADD,
    SUB,
    XOR,
    OR,
    AND,
    SLL,
    SRL,
    SRA,
    SLT,
    SLTU,

    // ---- RV32I: I-type arithmetic ----
    ADDI,
    XORI,
    ORI,
    ANDI,
    SLLI,
    SRLI,
    SRAI,
    SLTI,
    SLTIU,

    // ---- RV32I: Loads ----
    LB,
    LBU,
    LH,
    LHU,
    LW,

    // ---- RV32I: Stores ----
    SB,
    SH,
    SW,

    // ---- RV32I: Branches ----
    BEQ,
    BNE,
    BLT,
    BGE,
    BLTU,
    BGEU,

    // ---- RV32I: Jumps ----
    JAL,
    JALR,

    // ---- RV32I: Upper immediates ----
    LUI,
    AUIPC,

    // ---- RV32M: Multiply / Divide ----
    MUL,
    MULH,
    MULHSU,
    MULHU,
    DIV,
    DIVU,
    REM,
    REMU,

    // ---- System / Misc ----
    ECALL,
    EBREAK,
    FENCE,
};

pub const ProofOpcodeError = error{UnsupportedForProof};

pub const OperandUsage = struct {
    reads_rs1: bool,
    reads_rs2: bool,
    writes_rd: bool,
};

/// Architectural integer-register usage for one decoded opcode. Reserved
/// encoding fields (for example FENCE rd/rs1) do not become register effects.
pub fn operandUsage(opcode: Opcode) OperandUsage {
    return switch (opcode) {
        .ADD,
        .SUB,
        .XOR,
        .OR,
        .AND,
        .SLL,
        .SRL,
        .SRA,
        .SLT,
        .SLTU,
        .MUL,
        .MULH,
        .MULHSU,
        .MULHU,
        .DIV,
        .DIVU,
        .REM,
        .REMU,
        => .{ .reads_rs1 = true, .reads_rs2 = true, .writes_rd = true },

        .ADDI,
        .XORI,
        .ORI,
        .ANDI,
        .SLLI,
        .SRLI,
        .SRAI,
        .SLTI,
        .SLTIU,
        .LB,
        .LBU,
        .LH,
        .LHU,
        .LW,
        .JALR,
        => .{ .reads_rs1 = true, .reads_rs2 = false, .writes_rd = true },

        .SB,
        .SH,
        .SW,
        .BEQ,
        .BNE,
        .BLT,
        .BGE,
        .BLTU,
        .BGEU,
        => .{ .reads_rs1 = true, .reads_rs2 = true, .writes_rd = false },

        .LUI,
        .AUIPC,
        .JAL,
        => .{ .reads_rs1 = false, .reads_rs2 = false, .writes_rd = true },

        .ECALL,
        .EBREAK,
        .FENCE,
        => .{ .reads_rs1 = false, .reads_rs2 = false, .writes_rd = false },
    };
}

pub fn isLoad(opcode: Opcode) bool {
    return switch (opcode) {
        .LB, .LBU, .LH, .LHU, .LW => true,
        else => false,
    };
}

pub fn isStore(opcode: Opcode) bool {
    return switch (opcode) {
        .SB, .SH, .SW => true,
        else => false,
    };
}

pub fn memoryWidthBytes(opcode: Opcode) ?u3 {
    return switch (opcode) {
        .LB, .LBU, .SB => 1,
        .LH, .LHU, .SH => 2,
        .LW, .SW => 4,
        else => null,
    };
}

/// Convert an architectural opcode into the current proof opcode.
///
/// The exhaustive switch is a compile-time coverage check over the runner's
/// instruction set. Environment-control instructions remain outside the proof
/// trace and fail closed at this boundary.
pub fn proofOpcode(opcode: Opcode) ProofOpcodeError!opcode_manifest.Opcode {
    return switch (opcode) {
        .ADD => .add,
        .SUB => .sub,
        .SLL => .sll,
        .SLT => .slt,
        .SLTU => .sltu,
        .XOR => .xor,
        .SRL => .srl,
        .SRA => .sra,
        .OR => .@"or",
        .AND => .@"and",
        .ADDI => .addi,
        .SLTI => .slti,
        .SLTIU => .sltiu,
        .XORI => .xori,
        .ORI => .ori,
        .ANDI => .andi,
        .SLLI => .slli,
        .SRLI => .srli,
        .SRAI => .srai,
        .LB => .lb,
        .LH => .lh,
        .LW => .lw,
        .LBU => .lbu,
        .LHU => .lhu,
        .SB => .sb,
        .SH => .sh,
        .SW => .sw,
        .BEQ => .beq,
        .BNE => .bne,
        .BLT => .blt,
        .BGE => .bge,
        .BLTU => .bltu,
        .BGEU => .bgeu,
        .JAL => .jal,
        .JALR => .jalr,
        .LUI => .lui,
        .AUIPC => .auipc,
        .MUL => .mul,
        .MULH => .mulh,
        .MULHSU => .mulhsu,
        .MULHU => .mulhu,
        .DIV => .div,
        .DIVU => .divu,
        .REM => .rem,
        .REMU => .remu,
        .FENCE => .fence,
        .ECALL,
        .EBREAK,
        => error.UnsupportedForProof,
    };
}

/// A fully-decoded RV32IM instruction.
pub const DecodedInst = struct {
    opcode: Opcode,
    rd: u5,
    rs1: u5,
    rs2: u5,
    imm: i32,

    /// Decode a 32-bit RISC-V instruction word.
    pub fn decode(inst: u32) !DecodedInst {
        const opcode_field: u7 = @truncate(inst);
        const rd: u5 = @truncate(inst >> 7);
        const funct3: u3 = @truncate(inst >> 12);
        const rs1: u5 = @truncate(inst >> 15);
        const rs2: u5 = @truncate(inst >> 20);
        const funct7: u7 = @truncate(inst >> 25);

        return switch (opcode_field) {
            // ----- R-type (OP = 0b0110011) -----
            0b0110011 => blk: {
                if (funct7 == 0b0000001) {
                    // RV32M extension
                    break :blk .{
                        .opcode = switch (funct3) {
                            0b000 => .MUL,
                            0b001 => .MULH,
                            0b010 => .MULHSU,
                            0b011 => .MULHU,
                            0b100 => .DIV,
                            0b101 => .DIVU,
                            0b110 => .REM,
                            0b111 => .REMU,
                        },
                        .rd = rd,
                        .rs1 = rs1,
                        .rs2 = rs2,
                        .imm = 0,
                    };
                }
                // Oracle-exact (funct3, funct7) matching: any other funct7
                // combination is an illegal instruction, never a base op.
                break :blk .{
                    .opcode = switch (funct3) {
                        0b000 => switch (funct7) {
                            0b0000000 => Opcode.ADD,
                            0b0100000 => Opcode.SUB,
                            else => return error.IllegalInstruction,
                        },
                        0b001 => if (funct7 == 0) Opcode.SLL else return error.IllegalInstruction,
                        0b010 => if (funct7 == 0) Opcode.SLT else return error.IllegalInstruction,
                        0b011 => if (funct7 == 0) Opcode.SLTU else return error.IllegalInstruction,
                        0b100 => if (funct7 == 0) Opcode.XOR else return error.IllegalInstruction,
                        0b101 => switch (funct7) {
                            0b0000000 => Opcode.SRL,
                            0b0100000 => Opcode.SRA,
                            else => return error.IllegalInstruction,
                        },
                        0b110 => if (funct7 == 0) Opcode.OR else return error.IllegalInstruction,
                        0b111 => if (funct7 == 0) Opcode.AND else return error.IllegalInstruction,
                    },
                    .rd = rd,
                    .rs1 = rs1,
                    .rs2 = rs2,
                    .imm = 0,
                };
            },

            // ----- I-type arithmetic (OP-IMM = 0b0010011) -----
            0b0010011 => blk: {
                const decoded_opcode: Opcode = switch (funct3) {
                    0b000 => .ADDI,
                    0b001 => if (funct7 == 0) .SLLI else return error.IllegalInstruction,
                    0b010 => .SLTI,
                    0b011 => .SLTIU,
                    0b100 => .XORI,
                    0b101 => switch (funct7) {
                        0b0000000 => .SRLI,
                        0b0100000 => .SRAI,
                        else => return error.IllegalInstruction,
                    },
                    0b110 => .ORI,
                    0b111 => .ANDI,
                };
                break :blk .{
                    .opcode = decoded_opcode,
                    .rd = rd,
                    .rs1 = rs1,
                    .rs2 = rs2,
                    .imm = switch (decoded_opcode) {
                        .SLLI, .SRLI, .SRAI => @as(i32, rs2),
                        else => decodeIImm(inst),
                    },
                };
            },

            // ----- I-type loads (LOAD = 0b0000011) -----
            0b0000011 => .{
                .opcode = switch (funct3) {
                    0b000 => .LB,
                    0b001 => .LH,
                    0b010 => .LW,
                    0b100 => .LBU,
                    0b101 => .LHU,
                    else => return error.IllegalInstruction,
                },
                .rd = rd,
                .rs1 = rs1,
                .rs2 = rs2,
                .imm = decodeIImm(inst),
            },

            // ----- S-type stores (STORE = 0b0100011) -----
            0b0100011 => .{
                .opcode = switch (funct3) {
                    0b000 => .SB,
                    0b001 => .SH,
                    0b010 => .SW,
                    else => return error.IllegalInstruction,
                },
                .rd = rd,
                .rs1 = rs1,
                .rs2 = rs2,
                .imm = decodeSImm(inst),
            },

            // ----- B-type branches (BRANCH = 0b1100011) -----
            0b1100011 => .{
                .opcode = switch (funct3) {
                    0b000 => .BEQ,
                    0b001 => .BNE,
                    0b100 => .BLT,
                    0b101 => .BGE,
                    0b110 => .BLTU,
                    0b111 => .BGEU,
                    else => return error.IllegalInstruction,
                },
                .rd = rd,
                .rs1 = rs1,
                .rs2 = rs2,
                .imm = decodeBImm(inst),
            },

            // ----- JAL (J-type, 0b1101111) -----
            0b1101111 => .{
                .opcode = .JAL,
                .rd = rd,
                .rs1 = rs1,
                .rs2 = rs2,
                .imm = decodeJImm(inst),
            },

            // ----- JALR (I-type, 0b1100111) -----
            0b1100111 => if (funct3 == 0) .{
                .opcode = .JALR,
                .rd = rd,
                .rs1 = rs1,
                .rs2 = rs2,
                .imm = decodeIImm(inst),
            } else error.IllegalInstruction,

            // ----- LUI (U-type, 0b0110111) -----
            0b0110111 => .{
                .opcode = .LUI,
                .rd = rd,
                .rs1 = rs1,
                .rs2 = rs2,
                .imm = decodeUImm(inst),
            },

            // ----- AUIPC (U-type, 0b0010111) -----
            0b0010111 => .{
                .opcode = .AUIPC,
                .rd = rd,
                .rs1 = rs1,
                .rs2 = rs2,
                .imm = decodeUImm(inst),
            },

            // ----- SYSTEM environment controls (0b1110011) -----
            0b1110011 => switch (inst) {
                0x00000073 => .{ .opcode = .ECALL, .rd = 0, .rs1 = 0, .rs2 = 0, .imm = 0 },
                0x00100073 => .{ .opcode = .EBREAK, .rd = 0, .rs1 = 0, .rs2 = 0, .imm = 0 },
                else => error.IllegalInstruction,
            },

            // ----- Base-I FENCE (MISC-MEM = 0b0001111) -----
            // Sail accepts reserved rs1/rd/fm fields as a forward-compatible
            // FENCE. Zifencei is disabled by the profile, so funct3=001 is
            // deliberately rejected.
            0b0001111 => if (funct3 == 0) .{
                .opcode = .FENCE,
                .rd = rd,
                .rs1 = rs1,
                .rs2 = rs2,
                .imm = decodeIImm(inst),
            } else error.IllegalInstruction,

            else => return error.IllegalInstruction,
        };
    }
};

// ---------------------------------------------------------------------------
// Immediate-field extraction helpers
// ---------------------------------------------------------------------------

/// I-type immediate: inst[31:20], sign-extended.
fn decodeIImm(inst: u32) i32 {
    const raw: i32 = @bitCast(inst);
    return raw >> 20; // arithmetic shift preserves sign
}

/// S-type immediate: { inst[31:25], inst[11:7] }, sign-extended.
fn decodeSImm(inst: u32) i32 {
    const hi: u32 = inst >> 25;
    const lo: u32 = (inst >> 7) & 0x1F;
    const combined: u32 = (hi << 5) | lo;
    // Sign-extend from 12 bits.
    return signExtend(combined, 12);
}

/// B-type immediate: { inst[31], inst[7], inst[30:25], inst[11:8], 0 }.
fn decodeBImm(inst: u32) i32 {
    const bit_31: u32 = (inst >> 31) & 1;
    const bit_7: u32 = (inst >> 7) & 1;
    const bits_30_25: u32 = (inst >> 25) & 0x3F;
    const bits_11_8: u32 = (inst >> 8) & 0xF;
    const combined: u32 = (bit_31 << 12) | (bit_7 << 11) | (bits_30_25 << 5) | (bits_11_8 << 1);
    return signExtend(combined, 13);
}

/// U-type immediate: inst[31:12] << 12.
fn decodeUImm(inst: u32) i32 {
    return @bitCast(inst & 0xFFFFF000);
}

/// J-type immediate: { inst[31], inst[19:12], inst[20], inst[30:21], 0 }.
fn decodeJImm(inst: u32) i32 {
    const bit_31: u32 = (inst >> 31) & 1;
    const bits_19_12: u32 = (inst >> 12) & 0xFF;
    const bit_20: u32 = (inst >> 20) & 1;
    const bits_30_21: u32 = (inst >> 21) & 0x3FF;
    const combined: u32 = (bit_31 << 20) | (bits_19_12 << 12) | (bit_20 << 11) | (bits_30_21 << 1);
    return signExtend(combined, 21);
}

/// Sign-extend a `bits`-wide unsigned value to i32.
fn signExtend(value: u32, comptime bits: u5) i32 {
    const shift: u5 = @intCast(32 - @as(u6, bits));
    const signed: i32 = @bitCast(value << shift);
    return signed >> shift;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "decode ADD x1, x2, x3 (0x003100B3)" {
    const inst = try DecodedInst.decode(0x003100B3);
    try std.testing.expectEqual(Opcode.ADD, inst.opcode);
    try std.testing.expectEqual(@as(u5, 1), inst.rd);
    try std.testing.expectEqual(@as(u5, 2), inst.rs1);
    try std.testing.expectEqual(@as(u5, 3), inst.rs2);
}

test "architectural operand and memory effects ignore encoding-only fields" {
    try std.testing.expect(operandUsage(.ADD).writes_rd);
    try std.testing.expect(!operandUsage(.SW).writes_rd);
    try std.testing.expect(!operandUsage(.FENCE).reads_rs1);
    try std.testing.expect(isLoad(.LHU));
    try std.testing.expect(isStore(.SB));
    try std.testing.expectEqual(@as(?u3, 2), memoryWidthBytes(.SH));
    try std.testing.expectEqual(@as(?u3, null), memoryWidthBytes(.FENCE));
}

test "decode ADDI x5, x0, 42 (0x02A00293)" {
    const inst = try DecodedInst.decode(0x02A00293);
    try std.testing.expectEqual(Opcode.ADDI, inst.opcode);
    try std.testing.expectEqual(@as(u5, 5), inst.rd);
    try std.testing.expectEqual(@as(u5, 0), inst.rs1);
    try std.testing.expectEqual(@as(i32, 42), inst.imm);
}

test "decode SW x5, 0(x2) (0x00512023)" {
    const inst = try DecodedInst.decode(0x00512023);
    try std.testing.expectEqual(Opcode.SW, inst.opcode);
    try std.testing.expectEqual(@as(u5, 2), inst.rs1);
    try std.testing.expectEqual(@as(u5, 5), inst.rs2);
    try std.testing.expectEqual(@as(i32, 0), inst.imm);
}

test "decode LW x6, 0(x2) (0x00012303)" {
    const inst = try DecodedInst.decode(0x00012303);
    try std.testing.expectEqual(Opcode.LW, inst.opcode);
    try std.testing.expectEqual(@as(u5, 6), inst.rd);
    try std.testing.expectEqual(@as(u5, 2), inst.rs1);
    try std.testing.expectEqual(@as(i32, 0), inst.imm);
}

test "decode BEQ x1, x2, +8 (0x00208463)" {
    const inst = try DecodedInst.decode(0x00208463);
    try std.testing.expectEqual(Opcode.BEQ, inst.opcode);
    try std.testing.expectEqual(@as(u5, 1), inst.rs1);
    try std.testing.expectEqual(@as(u5, 2), inst.rs2);
    try std.testing.expectEqual(@as(i32, 8), inst.imm);
}

test "decode JAL x1, +0 (0x000000EF)" {
    // JAL rd=1, offset=0 encodes as 0x000000EF
    const inst = try DecodedInst.decode(0x000000EF);
    try std.testing.expectEqual(Opcode.JAL, inst.opcode);
    try std.testing.expectEqual(@as(u5, 1), inst.rd);
    try std.testing.expectEqual(@as(i32, 0), inst.imm);
}

test "decode LUI x1, 0x12345000 (0x12345_0B7)" {
    const inst = try DecodedInst.decode(0x123450B7);
    try std.testing.expectEqual(Opcode.LUI, inst.opcode);
    try std.testing.expectEqual(@as(u5, 1), inst.rd);
    try std.testing.expectEqual(@as(i32, 0x12345000), inst.imm);
}

test "decode MUL x1, x2, x3 (0x023100B3)" {
    const inst = try DecodedInst.decode(0x023100B3);
    try std.testing.expectEqual(Opcode.MUL, inst.opcode);
    try std.testing.expectEqual(@as(u5, 1), inst.rd);
    try std.testing.expectEqual(@as(u5, 2), inst.rs1);
    try std.testing.expectEqual(@as(u5, 3), inst.rs2);
}

test "decoder and proof boundary reject the manifest-owned preflight matrix" {
    for (opcode_manifest.proof_rejection_vectors) |vector| {
        switch (vector.kind) {
            .unsupported_instruction_class => {
                const decoded = try DecodedInst.decode(vector.word);
                try std.testing.expectError(
                    error.UnsupportedForProof,
                    proofOpcode(decoded.opcode),
                );
            },
            .invalid_instruction => try std.testing.expectError(
                error.IllegalInstruction,
                DecodedInst.decode(vector.word),
            ),
        }
    }
}

test "proof opcode conversion covers the profile and rejects host controls" {
    var seen: [opcode_manifest.entries.len]bool = .{false} ** opcode_manifest.entries.len;
    var supported: usize = 0;
    inline for (@typeInfo(Opcode).@"enum".fields) |field| {
        const opcode: Opcode = @enumFromInt(field.value);
        if (proofOpcode(opcode)) |proof_opcode| {
            const id = proof_opcode.protocolId();
            try std.testing.expect(!seen[id]);
            seen[id] = true;
            supported += 1;
        } else |err| {
            try std.testing.expectEqual(error.UnsupportedForProof, err);
        }
    }
    try std.testing.expectEqual(opcode_manifest.entries.len, supported);
    for (seen) |present| try std.testing.expect(present);
    try std.testing.expectEqual(@as(u32, 0), (try proofOpcode(.ADD)).protocolId());
    try std.testing.expectEqual(@as(u32, 44), (try proofOpcode(.REMU)).protocolId());
    try std.testing.expectEqual(@as(u32, 45), (try proofOpcode(.FENCE)).protocolId());
    try std.testing.expectError(error.UnsupportedForProof, proofOpcode(.ECALL));
    try std.testing.expectError(error.UnsupportedForProof, proofOpcode(.EBREAK));
}

test "decode SUB x1, x2, x3 (0x403100B3)" {
    const inst = try DecodedInst.decode(0x403100B3);
    try std.testing.expectEqual(Opcode.SUB, inst.opcode);
    try std.testing.expectEqual(@as(u5, 1), inst.rd);
    try std.testing.expectEqual(@as(u5, 2), inst.rs1);
    try std.testing.expectEqual(@as(u5, 3), inst.rs2);
}

test "decode ADDI with negative immediate" {
    // ADDI x1, x0, -1  =>  0xFFF00093
    const inst = try DecodedInst.decode(0xFFF00093);
    try std.testing.expectEqual(Opcode.ADDI, inst.opcode);
    try std.testing.expectEqual(@as(u5, 1), inst.rd);
    try std.testing.expectEqual(@as(u5, 0), inst.rs1);
    try std.testing.expectEqual(@as(i32, -1), inst.imm);
}

test "decoder equivalence: Zig decoder vs known RV32IM instruction encodings" {
    // Verify our decoder produces the exact same output as the RISC-V spec
    // for a comprehensive set of known instruction encodings.
    const Expected = struct {
        encoding: u32,
        opcode: Opcode,
        rd: u5,
        rs1: u5,
        rs2: u5,
        imm: i32,
    };

    const cases = [_]Expected{
        // ADD x1, x2, x3
        .{ .encoding = 0x003100B3, .opcode = .ADD, .rd = 1, .rs1 = 2, .rs2 = 3, .imm = 0 },
        // SUB x2, x2, x3
        .{ .encoding = 0x40310133, .opcode = .SUB, .rd = 2, .rs1 = 2, .rs2 = 3, .imm = 0 },
        // ADDI x1, x0, 5
        .{ .encoding = 0x00500093, .opcode = .ADDI, .rd = 1, .rs1 = 0, .rs2 = 5, .imm = 5 },
        // LW x2, 0(x0)
        .{ .encoding = 0x00002103, .opcode = .LW, .rd = 2, .rs1 = 0, .rs2 = 0, .imm = 0 },
        // SW x1, 0(x2)
        .{ .encoding = 0x00112023, .opcode = .SW, .rd = 0, .rs1 = 2, .rs2 = 1, .imm = 0 },
        // BEQ x1, x2, 8
        .{ .encoding = 0x00208463, .opcode = .BEQ, .rd = 8, .rs1 = 1, .rs2 = 2, .imm = 8 },
        // JAL x1, 12
        .{ .encoding = 0x00C000EF, .opcode = .JAL, .rd = 1, .rs1 = 0, .rs2 = 12, .imm = 12 },
        // JALR x1, x1, 0
        .{ .encoding = 0x000080E7, .opcode = .JALR, .rd = 1, .rs1 = 1, .rs2 = 0, .imm = 0 },
        // LUI x3, 1
        .{ .encoding = 0x000011B7, .opcode = .LUI, .rd = 3, .rs1 = 0, .rs2 = 0, .imm = 0x1000 },
        // AUIPC x3, 1
        .{ .encoding = 0x00001197, .opcode = .AUIPC, .rd = 3, .rs1 = 0, .rs2 = 0, .imm = 0x1000 },
        // MUL x0, x1, x2
        .{ .encoding = 0x02208033, .opcode = .MUL, .rd = 0, .rs1 = 1, .rs2 = 2, .imm = 0 },
        // MULH x0, x1, x2
        .{ .encoding = 0x02209033, .opcode = .MULH, .rd = 0, .rs1 = 1, .rs2 = 2, .imm = 0 },
        // DIV x0, x1, x2
        .{ .encoding = 0x0220C033, .opcode = .DIV, .rd = 0, .rs1 = 1, .rs2 = 2, .imm = 0 },
        // SLLI x0, x0, 1
        .{ .encoding = 0x00101013, .opcode = .SLLI, .rd = 0, .rs1 = 0, .rs2 = 1, .imm = 1 },
        // ECALL
    };

    for (cases) |expected| {
        const inst = try DecodedInst.decode(expected.encoding);
        try std.testing.expectEqual(expected.opcode, inst.opcode);
        try std.testing.expectEqual(expected.rd, inst.rd);
        try std.testing.expectEqual(expected.rs1, inst.rs1);
        try std.testing.expectEqual(expected.rs2, inst.rs2);
        try std.testing.expectEqual(expected.imm, inst.imm);
    }
}

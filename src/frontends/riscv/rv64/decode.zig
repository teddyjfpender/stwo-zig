//! RV64IM, IALIGN=32. No compressed, atomic, floating-point or CSR extension.
//! Opcode values are private execution identifiers, never RV32 proof IDs.
pub const Opcode = enum(u8) {
    ADD,
    SUB,
    SLL,
    SLT,
    SLTU,
    XOR,
    SRL,
    SRA,
    OR,
    AND,
    ADDI,
    SLTI,
    SLTIU,
    XORI,
    ORI,
    ANDI,
    SLLI,
    SRLI,
    SRAI,
    ADDW,
    SUBW,
    SLLW,
    SRLW,
    SRAW,
    ADDIW,
    SLLIW,
    SRLIW,
    SRAIW,
    LB,
    LH,
    LW,
    LD,
    LBU,
    LHU,
    LWU,
    SB,
    SH,
    SW,
    SD,
    BEQ,
    BNE,
    BLT,
    BGE,
    BLTU,
    BGEU,
    JAL,
    JALR,
    LUI,
    AUIPC,
    MUL,
    MULH,
    MULHSU,
    MULHU,
    DIV,
    DIVU,
    REM,
    REMU,
    MULW,
    DIVW,
    DIVUW,
    REMW,
    REMUW,
    FENCE,
    ECALL,
    EBREAK,
    // Zbb BINARY subset. Appended so every RV64IM value above is unchanged.
    // `Instruction.decode` never yields these; only `decodeFor(.rv64im_zbb_binary, _)`
    // does, and only profiles with `execution_profile.isaOf(p) == .rv64im_zbb_binary` admit them.
    ANDN,
    ORN,
    XNOR,
    REV8,
    SEXT_B,
    SEXT_H,
    ZEXT_H,
};

/// The base RV64IM opcodes, in enum order (the pre-Zbb identity domain).
pub const BASE_OPCODE_COUNT: usize = @intFromEnum(Opcode.EBREAK) + 1;
pub fn isBase(op: Opcode) bool {
    return @intFromEnum(op) < BASE_OPCODE_COUNT;
}
pub fn baseOpcodes() [BASE_OPCODE_COUNT]Opcode {
    var out: [BASE_OPCODE_COUNT]Opcode = undefined;
    for (&out, 0..) |*op, i| op.* = @enumFromInt(i);
    return out;
}

/// Instruction-set option. `rv64im` is the default for every existing profile.
/// `rv64im_zbb_binary` adds exactly andn, orn, xnor, rev8 (RV64), sext.b,
/// sext.h and zext.h (RV64) with their standard Zbb encodings; every other
/// Zbb/Zba/Zbkb encoding (clz, cpop, max, rotates, orc.b, pack with rs2 != 0,
/// RV32 rev8, ...) stays illegal.
pub const Isa = enum(u8) { rv64im = 0, rv64im_zbb_binary = 1 };
pub fn decodeFor(isa: Isa, word: u32) Error!Instruction {
    return Instruction.decode(word) catch |err| switch (isa) {
        .rv64im => err,
        .rv64im_zbb_binary => decodeZbbBinary(word) orelse err,
    };
}
/// Exact-match decoder for the admitted Zbb BINARY subset (Bit-Manipulation
/// ISA-extensions v1.0.0, RV64 encodings). Null for anything else.
pub fn decodeZbbBinary(word: u32) ?Instruction {
    const rd: u5 = @truncate(word >> 7);
    const rs1: u5 = @truncate(word >> 15);
    const rs2: u5 = @truncate(word >> 20);
    const f3: u3 = @truncate(word >> 12);
    const f7: u7 = @truncate(word >> 25);
    const imm12: u12 = @truncate(word >> 20);
    const op: Opcode = switch (@as(u7, @truncate(word))) {
        0x33 => if (f7 == 0x20) switch (f3) {
            7 => .ANDN,
            6 => .ORN,
            4 => .XNOR,
            else => return null,
        } else return null,
        0x13 => switch (f3) {
            1 => switch (imm12) {
                0x604 => .SEXT_B,
                0x605 => .SEXT_H,
                else => return null,
            },
            5 => if (imm12 == 0x6b8) .REV8 else return null,
            else => return null,
        },
        // zext.h (RV64) is packw rd, rs1, x0; packw with rs2 != 0 stays illegal.
        0x3b => if (f7 == 0x04 and f3 == 4 and rs2 == 0) .ZEXT_H else return null,
        else => return null,
    };
    const unary = op != .ANDN and op != .ORN and op != .XNOR;
    return .{ .opcode = op, .rd = rd, .rs1 = rs1, .rs2 = if (unary) 0 else rs2 };
}

pub const Effects = struct { reads_rs1: bool, reads_rs2: bool, writes_rd: bool, memory_width: u4 = 0 };

/// Exhaustive architectural effects. Encoding-only register fields never
/// become witness reads. Future constraints must consume this same authority.
pub fn effects(op: Opcode) Effects {
    return switch (op) {
        .ADD,
        .SUB,
        .SLL,
        .SLT,
        .SLTU,
        .XOR,
        .SRL,
        .SRA,
        .OR,
        .AND,
        .ADDW,
        .SUBW,
        .SLLW,
        .SRLW,
        .SRAW,
        .MUL,
        .MULH,
        .MULHSU,
        .MULHU,
        .DIV,
        .DIVU,
        .REM,
        .REMU,
        .MULW,
        .DIVW,
        .DIVUW,
        .REMW,
        .REMUW,
        => .{ .reads_rs1 = true, .reads_rs2 = true, .writes_rd = true },
        .ADDI,
        .SLTI,
        .SLTIU,
        .XORI,
        .ORI,
        .ANDI,
        .SLLI,
        .SRLI,
        .SRAI,
        .ADDIW,
        .SLLIW,
        .SRLIW,
        .SRAIW,
        .JALR,
        => .{ .reads_rs1 = true, .reads_rs2 = false, .writes_rd = true },
        .LB, .LBU => .{ .reads_rs1 = true, .reads_rs2 = false, .writes_rd = true, .memory_width = 1 },
        .LH, .LHU => .{ .reads_rs1 = true, .reads_rs2 = false, .writes_rd = true, .memory_width = 2 },
        .LW, .LWU => .{ .reads_rs1 = true, .reads_rs2 = false, .writes_rd = true, .memory_width = 4 },
        .LD => .{ .reads_rs1 = true, .reads_rs2 = false, .writes_rd = true, .memory_width = 8 },
        .SB => .{ .reads_rs1 = true, .reads_rs2 = true, .writes_rd = false, .memory_width = 1 },
        .SH => .{ .reads_rs1 = true, .reads_rs2 = true, .writes_rd = false, .memory_width = 2 },
        .SW => .{ .reads_rs1 = true, .reads_rs2 = true, .writes_rd = false, .memory_width = 4 },
        .SD => .{ .reads_rs1 = true, .reads_rs2 = true, .writes_rd = false, .memory_width = 8 },
        .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU => .{ .reads_rs1 = true, .reads_rs2 = true, .writes_rd = false },
        .LUI, .AUIPC, .JAL => .{ .reads_rs1 = false, .reads_rs2 = false, .writes_rd = true },
        .FENCE, .ECALL, .EBREAK => .{ .reads_rs1 = false, .reads_rs2 = false, .writes_rd = false },
        .ANDN, .ORN, .XNOR => .{ .reads_rs1 = true, .reads_rs2 = true, .writes_rd = true },
        .REV8, .SEXT_B, .SEXT_H, .ZEXT_H => .{ .reads_rs1 = true, .reads_rs2 = false, .writes_rd = true },
    };
}

pub const Error = error{IllegalInstruction};
pub const Instruction = struct {
    opcode: Opcode,
    rd: u5,
    rs1: u5,
    rs2: u5,
    imm: i64 = 0,

    pub fn decode(word: u32) Error!Instruction {
        var result = Instruction{
            .opcode = undefined,
            .rd = @truncate(word >> 7),
            .rs1 = @truncate(word >> 15),
            .rs2 = @truncate(word >> 20),
        };
        const f3: u3 = @truncate(word >> 12);
        const f7: u7 = @truncate(word >> 25);
        const major: u7 = @truncate(word);
        result.opcode = switch (major) {
            0x33 => if (f7 == 1) switch (f3) {
                0 => .MUL,
                1 => .MULH,
                2 => .MULHSU,
                3 => .MULHU,
                4 => .DIV,
                5 => .DIVU,
                6 => .REM,
                7 => .REMU,
            } else switch (f3) {
                0 => if (f7 == 0) .ADD else if (f7 == 32) .SUB else return error.IllegalInstruction,
                1 => if (f7 == 0) .SLL else return error.IllegalInstruction,
                2 => if (f7 == 0) .SLT else return error.IllegalInstruction,
                3 => if (f7 == 0) .SLTU else return error.IllegalInstruction,
                4 => if (f7 == 0) .XOR else return error.IllegalInstruction,
                5 => if (f7 == 0) .SRL else if (f7 == 32) .SRA else return error.IllegalInstruction,
                6 => if (f7 == 0) .OR else return error.IllegalInstruction,
                7 => if (f7 == 0) .AND else return error.IllegalInstruction,
            },
            0x3b => if (f7 == 1) switch (f3) {
                0 => .MULW,
                4 => .DIVW,
                5 => .DIVUW,
                6 => .REMW,
                7 => .REMUW,
                else => return error.IllegalInstruction,
            } else switch (f3) {
                0 => if (f7 == 0) .ADDW else if (f7 == 32) .SUBW else return error.IllegalInstruction,
                1 => if (f7 == 0) .SLLW else return error.IllegalInstruction,
                5 => if (f7 == 0) .SRLW else if (f7 == 32) .SRAW else return error.IllegalInstruction,
                else => return error.IllegalInstruction,
            },
            0x13, 0x1b => blk: {
                result.imm = sext(word >> 20, 12);
                if (major == 0x1b) break :blk switch (f3) {
                    0 => .ADDIW,
                    1 => if (f7 == 0) .SLLIW else return error.IllegalInstruction,
                    5 => if (f7 == 0) .SRLIW else if (f7 == 32) .SRAIW else return error.IllegalInstruction,
                    else => return error.IllegalInstruction,
                };
                break :blk switch (f3) {
                    0 => .ADDI,
                    2 => .SLTI,
                    3 => .SLTIU,
                    4 => .XORI,
                    6 => .ORI,
                    7 => .ANDI,
                    1 => if (word >> 26 == 0) .SLLI else return error.IllegalInstruction,
                    5 => if (word >> 26 == 0) .SRLI else if (word >> 26 == 16) .SRAI else return error.IllegalInstruction,
                };
            },
            0x03 => blk: {
                result.imm = sext(word >> 20, 12);
                break :blk switch (f3) {
                    0 => .LB,
                    1 => .LH,
                    2 => .LW,
                    3 => .LD,
                    4 => .LBU,
                    5 => .LHU,
                    6 => .LWU,
                    else => return error.IllegalInstruction,
                };
            },
            0x23 => blk: {
                result.imm = sext(((word >> 25) << 5) | ((word >> 7) & 31), 12);
                break :blk switch (f3) {
                    0 => .SB,
                    1 => .SH,
                    2 => .SW,
                    3 => .SD,
                    else => return error.IllegalInstruction,
                };
            },
            0x63 => blk: {
                result.imm = sext(((word >> 31) << 12) | (((word >> 7) & 1) << 11) | (((word >> 25) & 63) << 5) | (((word >> 8) & 15) << 1), 13);
                break :blk switch (f3) {
                    0 => .BEQ,
                    1 => .BNE,
                    4 => .BLT,
                    5 => .BGE,
                    6 => .BLTU,
                    7 => .BGEU,
                    else => return error.IllegalInstruction,
                };
            },
            0x6f => blk: {
                result.imm = sext(((word >> 31) << 20) | (word & 0xff000) | (((word >> 20) & 1) << 11) | (((word >> 21) & 1023) << 1), 21);
                break :blk .JAL;
            },
            0x67 => blk: {
                if (f3 != 0) return error.IllegalInstruction;
                result.imm = sext(word >> 20, 12);
                break :blk .JALR;
            },
            0x37, 0x17 => blk: {
                result.imm = sext(word & 0xfffff000, 32);
                break :blk if (major == 0x37) .LUI else .AUIPC;
            },
            // FENCE's reserved rd/rs1 fields are ignored as required by the ISA.
            // FENCE.I, Ztso and other extensions are not admitted by this profile.
            0x0f => if (f3 == 0 and word >> 28 == 0) .FENCE else return error.IllegalInstruction,
            0x73 => if (word == 0x73) .ECALL else if (word == 0x00100073) .EBREAK else return error.IllegalInstruction,
            else => return error.IllegalInstruction,
        };
        switch (result.opcode) {
            .SLLI, .SRLI, .SRAI => result.imm = (word >> 20) & 63,
            .SLLIW, .SRLIW, .SRAIW => result.imm = (word >> 20) & 31,
            else => {},
        }
        return result;
    }
};

fn sext(value: u32, comptime bits: comptime_int) i64 {
    const shift = 32 - bits;
    return @as(i32, @bitCast(value << shift)) >> shift;
}

//! Sail-authoritative RV32IM opcode protocol and proof-family policy.
//!
//! The legacy Stark-V IDs remain stable for protocol-layout compatibility, but
//! accepted encodings and architectural semantics follow the pinned Sail model.
//! Every successfully retired profile instruction is listed exactly once here;
//! host-control instructions are listed separately and never receive a family.

const std = @import("std");

pub const schema_version: u32 = 3;
pub const semantic_authority_revision = "8c7f2da58de0ba5e4457e4de07e0046f0439f35f";
pub const legacy_layout_revision = "d478f783055aa0d73a93768a433a3c6c31c91d1c";

pub const Opcode = enum(u8) {
    add = 0,
    sub = 1,
    sll = 2,
    slt = 3,
    sltu = 4,
    xor = 5,
    srl = 6,
    sra = 7,
    @"or" = 8,
    @"and" = 9,
    addi = 10,
    slti = 11,
    sltiu = 12,
    xori = 13,
    ori = 14,
    andi = 15,
    slli = 16,
    srli = 17,
    srai = 18,
    lb = 19,
    lh = 20,
    lw = 21,
    lbu = 22,
    lhu = 23,
    sb = 24,
    sh = 25,
    sw = 26,
    beq = 27,
    bne = 28,
    blt = 29,
    bge = 30,
    bltu = 31,
    bgeu = 32,
    jal = 33,
    jalr = 34,
    lui = 35,
    auipc = 36,
    mul = 37,
    mulh = 38,
    mulhsu = 39,
    mulhu = 40,
    div = 41,
    divu = 42,
    rem = 43,
    remu = 44,
    /// Local protocol extension. IDs 0...44 retain the legacy layout.
    fence = 45,

    pub inline fn protocolId(self: Opcode) u32 {
        return @intFromEnum(self);
    }
};

pub const Family = enum(u8) {
    base_alu_reg,
    base_alu_imm,
    shifts_reg,
    shifts_imm,
    lt_reg,
    lt_imm,
    branch_eq,
    branch_lt,
    lui,
    auipc,
    jalr,
    jal,
    load_store,
    mul,
    mulh,
    div,
    fence,
};

pub const ProgramShape = enum {
    register,
    immediate,
    shift_immediate,
    load,
    store,
    branch,
    jal,
    jalr,
    lui,
    auipc,
    fence,
};

pub const EncodingClass = enum {
    r_type,
    i_type,
    s_type,
    b_type,
    u_type,
    j_type,
    misc_mem,
};

/// Relation order matches the pinned Stark-V transcript order.
pub const RelationDomain = enum(u4) {
    registers_state,
    memory_access,
    program_access,
    merkle,
    poseidon2,
    poseidon2_io,
    bitwise,
    range_check_20,
    range_check_8_11,
    range_check_8_8_4,
    range_check_8_8,
    range_check_m31,
};

pub const RelationSet = struct {
    bits: u16,

    pub fn contains(self: RelationSet, domain: RelationDomain) bool {
        return self.bits & (@as(u16, 1) << @intFromEnum(domain)) != 0;
    }

    pub fn count(self: RelationSet) u5 {
        return @popCount(self.bits);
    }
};

pub const ProofEligibility = enum {
    admitted,
};

pub const Entry = struct {
    opcode: Opcode,
    mnemonic: []const u8,
    family: Family,
    program_shape: ProgramShape,
    encoding_class: EncodingClass,
    witness_schema: Family,
    semantic_component: Family,
    relation_domains: RelationSet,
    execution_supported: bool,
    proof_eligibility: ProofEligibility,
};

const reg = ProgramShape.register;
const imm = ProgramShape.immediate;

/// Indexed by protocol ID. Order is part of the proof protocol.
pub const entries = [_]Entry{
    proof(.add, "add", .base_alu_reg, reg),
    proof(.sub, "sub", .base_alu_reg, reg),
    proof(.sll, "sll", .shifts_reg, reg),
    proof(.slt, "slt", .lt_reg, reg),
    proof(.sltu, "sltu", .lt_reg, reg),
    proof(.xor, "xor", .base_alu_reg, reg),
    proof(.srl, "srl", .shifts_reg, reg),
    proof(.sra, "sra", .shifts_reg, reg),
    proof(.@"or", "or", .base_alu_reg, reg),
    proof(.@"and", "and", .base_alu_reg, reg),
    proof(.addi, "addi", .base_alu_imm, imm),
    proof(.slti, "slti", .lt_imm, imm),
    proof(.sltiu, "sltiu", .lt_imm, imm),
    proof(.xori, "xori", .base_alu_imm, imm),
    proof(.ori, "ori", .base_alu_imm, imm),
    proof(.andi, "andi", .base_alu_imm, imm),
    proof(.slli, "slli", .shifts_imm, .shift_immediate),
    proof(.srli, "srli", .shifts_imm, .shift_immediate),
    proof(.srai, "srai", .shifts_imm, .shift_immediate),
    proof(.lb, "lb", .load_store, .load),
    proof(.lh, "lh", .load_store, .load),
    proof(.lw, "lw", .load_store, .load),
    proof(.lbu, "lbu", .load_store, .load),
    proof(.lhu, "lhu", .load_store, .load),
    proof(.sb, "sb", .load_store, .store),
    proof(.sh, "sh", .load_store, .store),
    proof(.sw, "sw", .load_store, .store),
    proof(.beq, "beq", .branch_eq, .branch),
    proof(.bne, "bne", .branch_eq, .branch),
    proof(.blt, "blt", .branch_lt, .branch),
    proof(.bge, "bge", .branch_lt, .branch),
    proof(.bltu, "bltu", .branch_lt, .branch),
    proof(.bgeu, "bgeu", .branch_lt, .branch),
    proof(.jal, "jal", .jal, .jal),
    proof(.jalr, "jalr", .jalr, .jalr),
    proof(.lui, "lui", .lui, .lui),
    proof(.auipc, "auipc", .auipc, .auipc),
    proof(.mul, "mul", .mul, reg),
    proof(.mulh, "mulh", .mulh, reg),
    proof(.mulhsu, "mulhsu", .mulh, reg),
    proof(.mulhu, "mulhu", .mulh, reg),
    proof(.div, "div", .div, reg),
    proof(.divu, "divu", .div, reg),
    proof(.rem, "rem", .div, reg),
    proof(.remu, "remu", .div, reg),
    proof(.fence, "fence", .fence, .fence),
};

fn proof(comptime opcode: Opcode, mnemonic: []const u8, comptime family_id: Family, shape: ProgramShape) Entry {
    return .{
        .opcode = opcode,
        .mnemonic = mnemonic,
        .family = family_id,
        .program_shape = shape,
        .encoding_class = encodingClass(shape),
        .witness_schema = family_id,
        .semantic_component = family_id,
        .relation_domains = relationDomains(family_id),
        .execution_supported = true,
        .proof_eligibility = .admitted,
    };
}

fn encodingClass(shape: ProgramShape) EncodingClass {
    return switch (shape) {
        .register => .r_type,
        .immediate, .shift_immediate, .load, .jalr => .i_type,
        .store => .s_type,
        .branch => .b_type,
        .lui, .auipc => .u_type,
        .jal => .j_type,
        .fence => .misc_mem,
    };
}

fn relationSet(comptime domains: anytype) RelationSet {
    var bits: u16 = 0;
    inline for (domains) |domain| bits |= @as(u16, 1) << @intFromEnum(domain);
    return .{ .bits = bits };
}

fn relationDomains(comptime family_id: Family) RelationSet {
    const base = [_]RelationDomain{ .registers_state, .memory_access, .program_access, .range_check_20 };
    return switch (family_id) {
        .base_alu_reg => relationSet(base ++ [_]RelationDomain{ .bitwise, .range_check_8_8 }),
        .base_alu_imm => relationSet(base ++ [_]RelationDomain{ .bitwise, .range_check_8_11, .range_check_8_8 }),
        .shifts_reg, .shifts_imm => relationSet(base ++ [_]RelationDomain{ .range_check_8_8, .range_check_m31 }),
        .lt_reg, .branch_lt => relationSet(base ++ [_]RelationDomain{.range_check_8_8}),
        .lt_imm, .lui => relationSet(base ++ [_]RelationDomain{.range_check_8_8_4}),
        .branch_eq => relationSet(base),
        .auipc, .jal => relationSet(base ++ [_]RelationDomain{ .range_check_8_8, .range_check_m31 }),
        // JALR bounds its sign-extended immediate through the (8,8,4) table on
        // top of the byte and M31 checks the other jump families use; the
        // row-local target binding is what makes the composed jump target a
        // bounded value rather than a free field element.
        .jalr => relationSet(base ++ [_]RelationDomain{ .range_check_8_8, .range_check_m31, .range_check_8_8_4 }),
        .load_store => relationSet(base ++ [_]RelationDomain{.range_check_m31}),
        .mul => relationSet(base ++ [_]RelationDomain{.range_check_8_11}),
        .mulh => relationSet(base ++ [_]RelationDomain{ .range_check_8_11, .range_check_m31 }),
        // The quotient-sign witness is bounded through range_check_m31; without
        // it a signed DIV row could choose the sign that makes its own
        // remainder bound vacuous.
        .div => relationSet(base ++ [_]RelationDomain{ .range_check_8_11, .range_check_8_8, .range_check_m31 }),
        .fence => relationSet([_]RelationDomain{ .registers_state, .program_access }),
    };
}

pub const UnsupportedClass = enum { system };

pub const UnsupportedEntry = struct {
    mnemonic: []const u8,
    class: UnsupportedClass,
    execution_supported: bool,
};

/// Architectural environment controls decoded for host dispatch but excluded
/// from the successful-retirement proof language.
pub const unsupported_entries = [_]UnsupportedEntry{
    .{ .mnemonic = "ecall", .class = .system, .execution_supported = true },
    .{ .mnemonic = "ebreak", .class = .system, .execution_supported = true },
};

pub const RejectionKind = enum {
    unsupported_instruction_class,
    invalid_instruction,
};

pub const RejectionVector = struct {
    name: []const u8,
    word: u32,
    kind: RejectionKind,
};

/// Canonical words that must fail before proof construction.
///
/// The first two entries correspond one-for-one with `unsupported_entries`.
/// Remaining entries cover disabled extensions and malformed/reserved
/// encodings within otherwise admitted primary opcodes.
pub const proof_rejection_vectors = [_]RejectionVector{
    .{ .name = "ecall", .word = 0x00000073, .kind = .unsupported_instruction_class },
    .{ .name = "ebreak", .word = 0x00100073, .kind = .unsupported_instruction_class },
    .{ .name = "fence.i-disabled", .word = 0x0000100f, .kind = .invalid_instruction },
    .{ .name = "lr.w-disabled", .word = atomicWord(0b00010, 0), .kind = .invalid_instruction },
    .{ .name = "sc.w-disabled", .word = atomicWord(0b00011, 3), .kind = .invalid_instruction },
    .{ .name = "amoswap.w-disabled", .word = atomicWord(0b00001, 3), .kind = .invalid_instruction },
    .{ .name = "amoadd.w-disabled", .word = atomicWord(0b00000, 3), .kind = .invalid_instruction },
    .{ .name = "amoand.w-disabled", .word = atomicWord(0b01100, 3), .kind = .invalid_instruction },
    .{ .name = "amoor.w-disabled", .word = atomicWord(0b01000, 3), .kind = .invalid_instruction },
    .{ .name = "amoxor.w-disabled", .word = atomicWord(0b00100, 3), .kind = .invalid_instruction },
    .{ .name = "amomin.w-disabled", .word = atomicWord(0b10000, 3), .kind = .invalid_instruction },
    .{ .name = "amomax.w-disabled", .word = atomicWord(0b10100, 3), .kind = .invalid_instruction },
    .{ .name = "amominu.w-disabled", .word = atomicWord(0b11000, 3), .kind = .invalid_instruction },
    .{ .name = "amomaxu.w-disabled", .word = atomicWord(0b11100, 3), .kind = .invalid_instruction },
    .{ .name = "csrrw-disabled", .word = 0x300110f3, .kind = .invalid_instruction },
    .{ .name = "load-fp", .word = 0x00002087, .kind = .invalid_instruction },
    .{ .name = "store-fp", .word = 0x00112027, .kind = .invalid_instruction },
    .{ .name = "op-fp", .word = 0x003100d3, .kind = .invalid_instruction },
    .{ .name = "vector", .word = 0x02000057, .kind = .invalid_instruction },
    .{ .name = "compressed", .word = 0x00000001, .kind = .invalid_instruction },
    .{ .name = "custom-0", .word = 0x0000000b, .kind = .invalid_instruction },
    .{ .name = "r-type-reserved-funct7", .word = registerWord(0b0000010, 0), .kind = .invalid_instruction },
    .{ .name = "r-type-invalid-sub-shape", .word = registerWord(0b0100000, 1), .kind = .invalid_instruction },
    .{ .name = "load-reserved-funct3", .word = 0x00003083, .kind = .invalid_instruction },
    .{ .name = "store-reserved-funct3", .word = 0x00113023, .kind = .invalid_instruction },
    .{ .name = "branch-reserved-funct3", .word = 0x0020a063, .kind = .invalid_instruction },
    .{ .name = "slli-reserved-funct7", .word = shiftWord(0b1111111, 31, 0b001), .kind = .invalid_instruction },
    .{ .name = "srli-reserved-funct7", .word = shiftWord(0b0000001, 3, 0b101), .kind = .invalid_instruction },
    .{ .name = "jalr-reserved-funct3", .word = 0x001170e7, .kind = .invalid_instruction },
    .{ .name = "invalid-primary-opcode", .word = 0x00000000, .kind = .invalid_instruction },
};

fn atomicWord(funct5: u32, rs2: u32) u32 {
    return (funct5 << 27) | (rs2 << 20) | (2 << 15) | (0b010 << 12) | (1 << 7) | 0x2f;
}

fn registerWord(funct7: u32, funct3: u32) u32 {
    return (funct7 << 25) | (3 << 20) | (2 << 15) | (funct3 << 12) | (1 << 7) | 0x33;
}

fn shiftWord(funct7: u32, shamt: u32, funct3: u32) u32 {
    return (funct7 << 25) | (shamt << 20) | (2 << 15) | (funct3 << 12) | (1 << 7) | 0x13;
}

pub fn entry(opcode: Opcode) *const Entry {
    return &entries[@intFromEnum(opcode)];
}

pub fn family(opcode: Opcode) Family {
    return entry(opcode).family;
}

pub const ValidationError = error{
    ProtocolIdMismatch,
    MnemonicMismatch,
    RejectionManifestMismatch,
    DuplicateEncoding,
};

pub fn validate() ValidationError!void {
    if (entries.len != @typeInfo(Opcode).@"enum".fields.len) return error.ProtocolIdMismatch;
    inline for (entries, 0..) |item, expected_id| {
        if (item.opcode.protocolId() != expected_id) return error.ProtocolIdMismatch;
        if (!std.mem.eql(u8, item.mnemonic, @tagName(item.opcode))) return error.MnemonicMismatch;
    }
    if (proof_rejection_vectors.len < unsupported_entries.len)
        return error.RejectionManifestMismatch;
    inline for (unsupported_entries, 0..) |unsupported, index| {
        const rejected = proof_rejection_vectors[index];
        if (!std.mem.eql(u8, unsupported.mnemonic, rejected.name) or
            rejected.kind != .unsupported_instruction_class)
            return error.RejectionManifestMismatch;
    }
    inline for (proof_rejection_vectors, 0..) |lhs, lhs_index| {
        inline for (proof_rejection_vectors[lhs_index + 1 ..]) |rhs| {
            if (lhs.word == rhs.word) return error.DuplicateEncoding;
        }
    }
}

test "opcode manifest is complete and preserves legacy protocol ids" {
    try validate();
    try std.testing.expectEqual(@as(usize, 46), entries.len);
    try std.testing.expectEqual(Family.base_alu_imm, family(.addi));
    try std.testing.expectEqual(Family.div, family(.remu));
    try std.testing.expectEqual(@as(u32, 44), Opcode.remu.protocolId());
    try std.testing.expectEqual(@as(u32, 45), Opcode.fence.protocolId());
}

test "host-control instructions have no proof-family field" {
    try std.testing.expectEqual(@as(usize, 2), unsupported_entries.len);
    inline for (unsupported_entries) |item| {
        try std.testing.expect(item.execution_supported);
        try std.testing.expect(item.mnemonic.len != 0);
    }
}

test "opcode manifest owns a unique fail-closed decoder matrix" {
    try validate();
    try std.testing.expectEqual(@as(usize, 30), proof_rejection_vectors.len);
}

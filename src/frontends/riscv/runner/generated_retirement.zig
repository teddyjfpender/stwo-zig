//! Compile-time registry for opcode families whose typed definition owns
//! architectural retirement and trace/access publication.
//!
//! Decode remains architectural. This registry turns the decoded enum into a
//! compact authority tag with one indexed load, then dispatches to the fixed,
//! allocation-free family transaction. Unsupported families return `false`
//! and remain on the legacy path; a migrated family cannot silently fall back.

const std = @import("std");
const protocol_opcode = @import("../air/program/opcode.zig").Opcode;
const decode = @import("decode.zig");
const auipc = @import("auipc_retirement.zig");
const base_alu_imm = @import("base_alu_imm_retirement.zig");
const base_alu_reg = @import("base_alu_reg_retirement.zig");
const branch_eq = @import("branch_eq_retirement.zig");
const branch_lt = @import("branch_lt_retirement.zig");
const fence = @import("fence_retirement.zig");
const jal = @import("jal_retirement.zig");
const jalr = @import("jalr_retirement.zig");
const lt_imm = @import("lt_imm_retirement.zig");
const lt_reg = @import("lt_reg_retirement.zig");
const lui = @import("lui_retirement.zig");
const shifts_imm = @import("shifts_imm_retirement.zig");
const shifts_reg = @import("shifts_reg_retirement.zig");
const load_store = @import("load_store_retirement.zig");
const mul = @import("mul_retirement.zig");
const mulh = @import("mulh_retirement.zig");
const div = @import("div_retirement.zig");
const Cpu = @import("cpu.zig").Cpu;
const Memory = @import("memory.zig").Memory;
const StateChainTracker = @import("state_chain.zig").StateChainTracker;
const Trace = @import("trace.zig").Trace;

pub const AuthorityKind = enum(u8) {
    lui = 0,
    fence = 1,
    addi = 2,
    xori = 3,
    ori = 4,
    andi = 5,
    auipc = 6,
    add = 7,
    sub = 8,
    xor = 9,
    or_reg = 10,
    and_reg = 11,
    jal = 12,
    jalr = 13,
    beq = 14,
    bne = 15,
    blt = 16,
    bltu = 17,
    bge = 18,
    bgeu = 19,
    slti = 20,
    sltiu = 21,
    slt = 22,
    sltu = 23,
    slli = 24,
    srli = 25,
    srai = 26,
    sll = 27,
    srl = 28,
    sra = 29,
    mul = 30,
    mulh = 31,
    mulhsu = 32,
    mulhu = 33,
    div = 34,
    divu = 35,
    rem = 36,
    remu = 37,
    lb = 38,
    lh = 39,
    lbu = 40,
    lhu = 41,
    lw = 42,
    sb = 43,
    sh = 44,
    sw = 45,
};

pub const Descriptor = struct {
    kind: AuthorityKind,
    opcode: decode.Opcode,
    protocol_id: u32,
    authority_binding_digest: [32]u8,
};

/// Canonical registry order is part of the executable dispatch identity.
pub const MIGRATED = [46]Descriptor{
    .{
        .kind = .lui,
        .opcode = .LUI,
        .protocol_id = lui.PINNED_AUTHORITY.binding.opcode_id,
        .authority_binding_digest = lui.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .fence,
        .opcode = .FENCE,
        .protocol_id = fence.PINNED_AUTHORITY.binding.opcode_id,
        .authority_binding_digest = fence.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .addi,
        .opcode = .ADDI,
        .protocol_id = base_alu_imm.PINNED_AUTHORITY.binding.opcode_ids[0],
        .authority_binding_digest = base_alu_imm.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .xori,
        .opcode = .XORI,
        .protocol_id = base_alu_imm.PINNED_AUTHORITY.binding.opcode_ids[1],
        .authority_binding_digest = base_alu_imm.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .ori,
        .opcode = .ORI,
        .protocol_id = base_alu_imm.PINNED_AUTHORITY.binding.opcode_ids[2],
        .authority_binding_digest = base_alu_imm.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .andi,
        .opcode = .ANDI,
        .protocol_id = base_alu_imm.PINNED_AUTHORITY.binding.opcode_ids[3],
        .authority_binding_digest = base_alu_imm.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .auipc,
        .opcode = .AUIPC,
        .protocol_id = auipc.PINNED_AUTHORITY.binding.opcode_id,
        .authority_binding_digest = auipc.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .add,
        .opcode = .ADD,
        .protocol_id = base_alu_reg.PINNED_AUTHORITY.binding.opcode_ids[0],
        .authority_binding_digest = base_alu_reg.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .sub,
        .opcode = .SUB,
        .protocol_id = base_alu_reg.PINNED_AUTHORITY.binding.opcode_ids[1],
        .authority_binding_digest = base_alu_reg.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .xor,
        .opcode = .XOR,
        .protocol_id = base_alu_reg.PINNED_AUTHORITY.binding.opcode_ids[2],
        .authority_binding_digest = base_alu_reg.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .or_reg,
        .opcode = .OR,
        .protocol_id = base_alu_reg.PINNED_AUTHORITY.binding.opcode_ids[3],
        .authority_binding_digest = base_alu_reg.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .and_reg,
        .opcode = .AND,
        .protocol_id = base_alu_reg.PINNED_AUTHORITY.binding.opcode_ids[4],
        .authority_binding_digest = base_alu_reg.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .jal,
        .opcode = .JAL,
        .protocol_id = jal.PINNED_AUTHORITY.binding.opcode_id,
        .authority_binding_digest = jal.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .jalr,
        .opcode = .JALR,
        .protocol_id = jalr.PINNED_AUTHORITY.binding.opcode_id,
        .authority_binding_digest = jalr.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .beq,
        .opcode = .BEQ,
        .protocol_id = branch_eq.PINNED_AUTHORITY.binding.opcode_ids[0],
        .authority_binding_digest = branch_eq.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .bne,
        .opcode = .BNE,
        .protocol_id = branch_eq.PINNED_AUTHORITY.binding.opcode_ids[1],
        .authority_binding_digest = branch_eq.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .blt,
        .opcode = .BLT,
        .protocol_id = branch_lt.PINNED_AUTHORITY.binding.opcode_ids[0],
        .authority_binding_digest = branch_lt.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .bltu,
        .opcode = .BLTU,
        .protocol_id = branch_lt.PINNED_AUTHORITY.binding.opcode_ids[1],
        .authority_binding_digest = branch_lt.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .bge,
        .opcode = .BGE,
        .protocol_id = branch_lt.PINNED_AUTHORITY.binding.opcode_ids[2],
        .authority_binding_digest = branch_lt.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .bgeu,
        .opcode = .BGEU,
        .protocol_id = branch_lt.PINNED_AUTHORITY.binding.opcode_ids[3],
        .authority_binding_digest = branch_lt.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .slti,
        .opcode = .SLTI,
        .protocol_id = lt_imm.PINNED_AUTHORITY.binding.opcode_ids[0],
        .authority_binding_digest = lt_imm.PINNED_AUTHORITY.binding_digest,
    },
    .{
        .kind = .sltiu,
        .opcode = .SLTIU,
        .protocol_id = lt_imm.PINNED_AUTHORITY.binding.opcode_ids[1],
        .authority_binding_digest = lt_imm.PINNED_AUTHORITY.binding_digest,
    },
    .{ .kind = .slt, .opcode = .SLT, .protocol_id = lt_reg.PINNED_AUTHORITY.binding.opcode_ids[0], .authority_binding_digest = lt_reg.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .sltu, .opcode = .SLTU, .protocol_id = lt_reg.PINNED_AUTHORITY.binding.opcode_ids[1], .authority_binding_digest = lt_reg.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .slli, .opcode = .SLLI, .protocol_id = shifts_imm.PINNED_AUTHORITY.binding.opcode_ids[0], .authority_binding_digest = shifts_imm.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .srli, .opcode = .SRLI, .protocol_id = shifts_imm.PINNED_AUTHORITY.binding.opcode_ids[1], .authority_binding_digest = shifts_imm.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .srai, .opcode = .SRAI, .protocol_id = shifts_imm.PINNED_AUTHORITY.binding.opcode_ids[2], .authority_binding_digest = shifts_imm.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .sll, .opcode = .SLL, .protocol_id = shifts_reg.PINNED_AUTHORITY.binding.opcode_ids[0], .authority_binding_digest = shifts_reg.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .srl, .opcode = .SRL, .protocol_id = shifts_reg.PINNED_AUTHORITY.binding.opcode_ids[1], .authority_binding_digest = shifts_reg.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .sra, .opcode = .SRA, .protocol_id = shifts_reg.PINNED_AUTHORITY.binding.opcode_ids[2], .authority_binding_digest = shifts_reg.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .mul, .opcode = .MUL, .protocol_id = mul.PINNED_AUTHORITY.binding.opcode_id, .authority_binding_digest = mul.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .mulh, .opcode = .MULH, .protocol_id = mulh.PINNED_AUTHORITY.binding.opcode_ids[0], .authority_binding_digest = mulh.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .mulhsu, .opcode = .MULHSU, .protocol_id = mulh.PINNED_AUTHORITY.binding.opcode_ids[1], .authority_binding_digest = mulh.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .mulhu, .opcode = .MULHU, .protocol_id = mulh.PINNED_AUTHORITY.binding.opcode_ids[2], .authority_binding_digest = mulh.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .div, .opcode = .DIV, .protocol_id = div.PINNED_AUTHORITY.binding.opcode_ids[0], .authority_binding_digest = div.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .divu, .opcode = .DIVU, .protocol_id = div.PINNED_AUTHORITY.binding.opcode_ids[1], .authority_binding_digest = div.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .rem, .opcode = .REM, .protocol_id = div.PINNED_AUTHORITY.binding.opcode_ids[2], .authority_binding_digest = div.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .remu, .opcode = .REMU, .protocol_id = div.PINNED_AUTHORITY.binding.opcode_ids[3], .authority_binding_digest = div.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .lb, .opcode = .LB, .protocol_id = load_store.PINNED_AUTHORITY.binding.opcode_ids[0], .authority_binding_digest = load_store.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .lh, .opcode = .LH, .protocol_id = load_store.PINNED_AUTHORITY.binding.opcode_ids[1], .authority_binding_digest = load_store.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .lbu, .opcode = .LBU, .protocol_id = load_store.PINNED_AUTHORITY.binding.opcode_ids[2], .authority_binding_digest = load_store.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .lhu, .opcode = .LHU, .protocol_id = load_store.PINNED_AUTHORITY.binding.opcode_ids[3], .authority_binding_digest = load_store.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .lw, .opcode = .LW, .protocol_id = load_store.PINNED_AUTHORITY.binding.opcode_ids[4], .authority_binding_digest = load_store.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .sb, .opcode = .SB, .protocol_id = load_store.PINNED_AUTHORITY.binding.opcode_ids[5], .authority_binding_digest = load_store.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .sh, .opcode = .SH, .protocol_id = load_store.PINNED_AUTHORITY.binding.opcode_ids[6], .authority_binding_digest = load_store.PINNED_AUTHORITY.binding_digest },
    .{ .kind = .sw, .opcode = .SW, .protocol_id = load_store.PINNED_AUTHORITY.binding.opcode_ids[7], .authority_binding_digest = load_store.PINNED_AUTHORITY.binding_digest },
};

const OPCODE_COUNT = @typeInfo(decode.Opcode).@"enum".fields.len;
const DISPATCH = blk: {
    var result = [_]?AuthorityKind{null} ** OPCODE_COUNT;
    for (MIGRATED) |descriptor| {
        const opcode_index = @intFromEnum(descriptor.opcode);
        if (result[opcode_index] != null)
            @compileError("duplicate generated retirement opcode");
        result[opcode_index] = descriptor.kind;
    }
    break :blk result;
};

pub inline fn descriptorFor(opcode: decode.Opcode) ?*const Descriptor {
    const kind = DISPATCH[@intFromEnum(opcode)] orelse return null;
    return &MIGRATED[@intFromEnum(kind)];
}

pub const RetireError = lui.RetireError || fence.RetireError ||
    base_alu_imm.RetireError || base_alu_reg.RetireError ||
    auipc.RetireError || jal.RetireError || jalr.RetireError ||
    branch_eq.RetireError || branch_lt.RetireError || lt_imm.RetireError ||
    lt_reg.RetireError || shifts_imm.RetireError || shifts_reg.RetireError ||
    mul.RetireError || mulh.RetireError || div.RetireError ||
    load_store.RetireError;

/// Retire one migrated instruction. `false` is returned only for an opcode
/// absent from `MIGRATED`; every registered family either publishes one whole
/// transaction or returns an error before logical mutation.
pub inline fn retireAtomic(
    cpu: *Cpu,
    memory: *Memory,
    exec_trace: *Trace,
    tracker: *StateChainTracker,
    instruction: decode.DecodedInst,
    inst_word: u32,
    instruction_clock: u32,
) RetireError!bool {
    const kind = DISPATCH[@intFromEnum(instruction.opcode)] orelse return false;
    switch (kind) {
        .lui => try lui.retireAtomic(
            &lui.PINNED_AUTHORITY,
            cpu,
            exec_trace,
            tracker,
            instruction,
            inst_word,
            instruction_clock,
        ),
        .fence => try fence.retireAtomic(
            &fence.PINNED_AUTHORITY,
            cpu,
            exec_trace,
            tracker,
            instruction,
            inst_word,
            instruction_clock,
        ),
        .addi, .xori, .ori, .andi => try base_alu_imm.retireAtomic(
            &base_alu_imm.PINNED_AUTHORITY,
            cpu,
            exec_trace,
            tracker,
            instruction,
            inst_word,
            instruction_clock,
        ),
        .auipc => try auipc.retireAtomic(
            &auipc.PINNED_AUTHORITY,
            cpu,
            exec_trace,
            tracker,
            instruction,
            inst_word,
            instruction_clock,
        ),
        .add, .sub, .xor, .or_reg, .and_reg => try base_alu_reg.retireAtomic(
            &base_alu_reg.PINNED_AUTHORITY,
            cpu,
            exec_trace,
            tracker,
            instruction,
            inst_word,
            instruction_clock,
        ),
        .jal => try jal.retireAtomic(
            &jal.PINNED_AUTHORITY,
            cpu,
            exec_trace,
            tracker,
            instruction,
            inst_word,
            instruction_clock,
        ),
        .jalr => try jalr.retireAtomic(
            &jalr.PINNED_AUTHORITY,
            cpu,
            exec_trace,
            tracker,
            instruction,
            inst_word,
            instruction_clock,
        ),
        .beq, .bne => try branch_eq.retireAtomic(
            &branch_eq.PINNED_AUTHORITY,
            cpu,
            exec_trace,
            tracker,
            instruction,
            inst_word,
            instruction_clock,
        ),
        .blt, .bltu, .bge, .bgeu => try branch_lt.retireAtomic(
            &branch_lt.PINNED_AUTHORITY,
            cpu,
            exec_trace,
            tracker,
            instruction,
            inst_word,
            instruction_clock,
        ),
        .slti, .sltiu => try lt_imm.retireAtomic(
            &lt_imm.PINNED_AUTHORITY,
            cpu,
            exec_trace,
            tracker,
            instruction,
            inst_word,
            instruction_clock,
        ),
        .slt, .sltu => try lt_reg.retireAtomic(&lt_reg.PINNED_AUTHORITY, cpu, exec_trace, tracker, instruction, inst_word, instruction_clock),
        .slli, .srli, .srai => try shifts_imm.retireAtomic(&shifts_imm.PINNED_AUTHORITY, cpu, exec_trace, tracker, instruction, inst_word, instruction_clock),
        .sll, .srl, .sra => try shifts_reg.retireAtomic(&shifts_reg.PINNED_AUTHORITY, cpu, exec_trace, tracker, instruction, inst_word, instruction_clock),
        .mul => try mul.retireAtomic(&mul.PINNED_AUTHORITY, cpu, exec_trace, tracker, instruction, inst_word, instruction_clock),
        .mulh, .mulhsu, .mulhu => try mulh.retireAtomic(&mulh.PINNED_AUTHORITY, cpu, exec_trace, tracker, instruction, inst_word, instruction_clock),
        .div, .divu, .rem, .remu => try div.retireAtomic(&div.PINNED_AUTHORITY, cpu, exec_trace, tracker, instruction, inst_word, instruction_clock),
        .lb, .lh, .lbu, .lhu, .lw, .sb, .sh, .sw => try load_store.retireAtomic(&load_store.PINNED_AUTHORITY, cpu, memory, exec_trace, tracker, instruction, inst_word, instruction_clock),
    }
    return true;
}

test "generated retirement registry is dense exact and fail closed" {
    try std.testing.expectEqual(@as(usize, 46), MIGRATED.len);
    try std.testing.expectEqual(AuthorityKind.lui, descriptorFor(.LUI).?.kind);
    try std.testing.expectEqual(AuthorityKind.fence, descriptorFor(.FENCE).?.kind);
    try std.testing.expectEqual(AuthorityKind.addi, descriptorFor(.ADDI).?.kind);
    try std.testing.expectEqual(AuthorityKind.xori, descriptorFor(.XORI).?.kind);
    try std.testing.expectEqual(AuthorityKind.ori, descriptorFor(.ORI).?.kind);
    try std.testing.expectEqual(AuthorityKind.andi, descriptorFor(.ANDI).?.kind);
    try std.testing.expectEqual(AuthorityKind.auipc, descriptorFor(.AUIPC).?.kind);
    try std.testing.expectEqual(AuthorityKind.add, descriptorFor(.ADD).?.kind);
    try std.testing.expectEqual(AuthorityKind.sub, descriptorFor(.SUB).?.kind);
    try std.testing.expectEqual(AuthorityKind.xor, descriptorFor(.XOR).?.kind);
    try std.testing.expectEqual(AuthorityKind.or_reg, descriptorFor(.OR).?.kind);
    try std.testing.expectEqual(AuthorityKind.and_reg, descriptorFor(.AND).?.kind);
    try std.testing.expectEqual(AuthorityKind.jal, descriptorFor(.JAL).?.kind);
    try std.testing.expectEqual(AuthorityKind.jalr, descriptorFor(.JALR).?.kind);
    try std.testing.expectEqual(AuthorityKind.beq, descriptorFor(.BEQ).?.kind);
    try std.testing.expectEqual(AuthorityKind.bne, descriptorFor(.BNE).?.kind);
    try std.testing.expectEqual(AuthorityKind.blt, descriptorFor(.BLT).?.kind);
    try std.testing.expectEqual(AuthorityKind.bltu, descriptorFor(.BLTU).?.kind);
    try std.testing.expectEqual(AuthorityKind.bge, descriptorFor(.BGE).?.kind);
    try std.testing.expectEqual(AuthorityKind.bgeu, descriptorFor(.BGEU).?.kind);
    try std.testing.expectEqual(AuthorityKind.slti, descriptorFor(.SLTI).?.kind);
    try std.testing.expectEqual(AuthorityKind.sltiu, descriptorFor(.SLTIU).?.kind);
    try std.testing.expect(descriptorFor(.ECALL) == null);
    try std.testing.expect(descriptorFor(.EBREAK) == null);
    try std.testing.expectEqual(
        protocol_opcode.lui.protocolId(),
        descriptorFor(.LUI).?.protocol_id,
    );
    try std.testing.expectEqual(
        protocol_opcode.fence.protocolId(),
        descriptorFor(.FENCE).?.protocol_id,
    );
    try std.testing.expectEqual(protocol_opcode.addi.protocolId(), descriptorFor(.ADDI).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.xori.protocolId(), descriptorFor(.XORI).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.ori.protocolId(), descriptorFor(.ORI).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.andi.protocolId(), descriptorFor(.ANDI).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.auipc.protocolId(), descriptorFor(.AUIPC).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.add.protocolId(), descriptorFor(.ADD).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.sub.protocolId(), descriptorFor(.SUB).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.xor.protocolId(), descriptorFor(.XOR).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.@"or".protocolId(), descriptorFor(.OR).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.@"and".protocolId(), descriptorFor(.AND).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.jal.protocolId(), descriptorFor(.JAL).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.jalr.protocolId(), descriptorFor(.JALR).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.beq.protocolId(), descriptorFor(.BEQ).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.bne.protocolId(), descriptorFor(.BNE).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.blt.protocolId(), descriptorFor(.BLT).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.bltu.protocolId(), descriptorFor(.BLTU).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.bge.protocolId(), descriptorFor(.BGE).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.bgeu.protocolId(), descriptorFor(.BGEU).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.slti.protocolId(), descriptorFor(.SLTI).?.protocol_id);
    try std.testing.expectEqual(protocol_opcode.sltiu.protocolId(), descriptorFor(.SLTIU).?.protocol_id);
    for (MIGRATED) |descriptor| {
        try std.testing.expectEqual(
            (try decode.proofOpcode(descriptor.opcode)).protocolId(),
            descriptor.protocol_id,
        );
    }
}

comptime {
    const fields = @typeInfo(decode.Opcode).@"enum".fields;
    for (fields, 0..) |field, index| {
        if (field.value != index)
            @compileError("generated retirement requires dense Opcode tags");
    }
    for (MIGRATED, 0..) |descriptor, index| {
        if (@intFromEnum(descriptor.kind) != index)
            @compileError("generated retirement kinds must match registry order");
    }
    for (MIGRATED) |descriptor| {
        const expected = decode.proofOpcode(descriptor.opcode) catch
            @compileError("generated retirement registered a non-proof opcode");
        if (descriptor.protocol_id != expected.protocolId())
            @compileError("generated retirement protocol opcode drifted");
    }
}

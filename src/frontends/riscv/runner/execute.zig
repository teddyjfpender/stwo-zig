//! Fail-closed legacy execution boundary.
//!
//! Every proof-bearing RV32IM opcode retires through `generated_retirement`;
//! this module retains only the host-visible system-instruction errors. Keeping
//! the old entry point explicit prevents a second mutable semantics authority
//! from silently reappearing.

const std = @import("std");
const Cpu = @import("cpu.zig").Cpu;
const Memory = @import("memory.zig").Memory;
const decode = @import("decode.zig");
const Opcode = decode.Opcode;
const DecodedInst = decode.DecodedInst;

pub const ExecuteError = error{
    Ecall,
    Ebreak,
    /// This opcode has migrated to a generated, failure-atomic retirement
    /// authority and must be dispatched before entering the legacy executor.
    GeneratedRetirementRequired,
    MisalignedMemoryAccess,
    InstructionAddressMisaligned,
};

/// Execute a single decoded instruction, mutating `cpu` and `mem`.
/// Returns system-instruction errors to the host and rejects every opcode now
/// owned by generated failure-atomic retirement.
pub fn execute(cpu: *Cpu, mem: *Memory, inst: DecodedInst) ExecuteError!void {
    _ = mem;
    switch (inst.opcode) {
        // ----------------------------------------------------------------
        // R-type arithmetic
        // ----------------------------------------------------------------
        .ADD, .SUB, .XOR, .OR, .AND => return error.GeneratedRetirementRequired,
        .SLL, .SRL, .SRA, .SLT, .SLTU => return error.GeneratedRetirementRequired,

        // ----------------------------------------------------------------
        // I-type arithmetic
        // ----------------------------------------------------------------
        .ADDI, .XORI, .ORI, .ANDI => return error.GeneratedRetirementRequired,
        .SLLI, .SRLI, .SRAI => return error.GeneratedRetirementRequired,
        .SLTI, .SLTIU => return error.GeneratedRetirementRequired,

        // ----------------------------------------------------------------
        // Loads (I-type)
        // ----------------------------------------------------------------
        .LB, .LBU, .LH, .LHU, .LW => return error.GeneratedRetirementRequired,

        // ----------------------------------------------------------------
        // Stores (S-type)
        // ----------------------------------------------------------------
        .SB, .SH, .SW => return error.GeneratedRetirementRequired,

        // ----------------------------------------------------------------
        // Branches (B-type)
        // ----------------------------------------------------------------
        .BEQ, .BNE => return error.GeneratedRetirementRequired,
        .BLT, .BLTU, .BGE, .BGEU => return error.GeneratedRetirementRequired,

        // ----------------------------------------------------------------
        // Jumps
        // ----------------------------------------------------------------
        .JAL => return error.GeneratedRetirementRequired,
        .JALR => return error.GeneratedRetirementRequired,

        // ----------------------------------------------------------------
        // Upper immediates
        // ----------------------------------------------------------------
        .LUI => return error.GeneratedRetirementRequired,
        .AUIPC => return error.GeneratedRetirementRequired,

        // ----------------------------------------------------------------
        // RV32M: Multiply / Divide
        // ----------------------------------------------------------------
        .MUL,
        .MULH,
        .MULHSU,
        .MULHU,
        .DIV,
        .DIVU,
        .REM,
        .REMU,
        => return error.GeneratedRetirementRequired,

        // ----------------------------------------------------------------
        // System
        // ----------------------------------------------------------------
        .FENCE => return error.GeneratedRetirementRequired,
        .ECALL => return error.Ecall,
        .EBREAK => return error.Ebreak,
    }

    // Default: advance PC by 4 (branches/jumps return early).
    cpu.pc +%= 4;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn makeTestCpuAndMem() struct { cpu: Cpu, mem: Memory } {
    return .{
        .cpu = Cpu.init(0x1000, 0x8000_0000),
        .mem = Memory.init(std.testing.allocator),
    };
}

test "legacy execute refuses production-migrated BASE_ALU_REG" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    t.cpu.writeReg(2, 10);
    t.cpu.writeReg(3, 20);
    const words = [_]u32{
        0x003100B3, // ADD x1, x2, x3
        0x403100B3, // SUB x1, x2, x3
        0x003140B3, // XOR x1, x2, x3
        0x003160B3, // OR  x1, x2, x3
        0x003170B3, // AND x1, x2, x3
    };
    for (words) |word| {
        const before = t.cpu;
        try std.testing.expectError(
            error.GeneratedRetirementRequired,
            execute(&t.cpu, &t.mem, try DecodedInst.decode(word)),
        );
        try std.testing.expectEqualDeep(before, t.cpu);
    }
}

test "legacy execute refuses production-migrated LT_REG and register shifts" {
    inline for ([_]Opcode{ .SLT, .SLTU, .SLL, .SRL, .SRA }) |opcode| {
        var t = makeTestCpuAndMem();
        defer t.mem.deinit();
        t.cpu.writeReg(2, 0x8000_0001);
        t.cpu.writeReg(3, 7);
        const before = t.cpu;
        try std.testing.expectError(
            error.GeneratedRetirementRequired,
            execute(&t.cpu, &t.mem, .{
                .opcode = opcode,
                .rd = 1,
                .rs1 = 2,
                .rs2 = 3,
                .imm = 0,
            }),
        );
        try std.testing.expectEqualDeep(before, t.cpu);
    }
}

test "legacy execute refuses production-migrated BASE_ALU_IMM" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    t.cpu.writeReg(1, 100);
    const words = [_]u32{
        0x02A08293, // ADDI x5, x1, 42
        0x02A0C293, // XORI x5, x1, 42
        0x02A0E293, // ORI x5, x1, 42
        0x02A0F293, // ANDI x5, x1, 42
    };
    for (words) |word| {
        const before = t.cpu;
        try std.testing.expectError(
            error.GeneratedRetirementRequired,
            execute(&t.cpu, &t.mem, try DecodedInst.decode(word)),
        );
        try std.testing.expectEqualDeep(before, t.cpu);
    }
}

test "legacy execute refuses production-migrated immediate shifts" {
    inline for ([_]Opcode{ .SLLI, .SRLI, .SRAI }) |opcode| {
        var t = makeTestCpuAndMem();
        defer t.mem.deinit();
        t.cpu.writeReg(2, 0x8000_0001);
        const before = t.cpu;
        try std.testing.expectError(
            error.GeneratedRetirementRequired,
            execute(&t.cpu, &t.mem, .{
                .opcode = opcode,
                .rd = 1,
                .rs1 = 2,
                .rs2 = 0,
                .imm = 7,
            }),
        );
        try std.testing.expectEqualDeep(before, t.cpu);
    }
}

test "legacy execute refuses production-migrated LOAD_STORE without mutation" {
    inline for ([_]Opcode{ .LB, .LH, .LW, .LBU, .LHU, .SB, .SH, .SW }) |opcode| {
        var t = makeTestCpuAndMem();
        defer t.mem.deinit();
        t.cpu.writeReg(2, 0x2000);
        t.cpu.writeReg(3, 0xCAFE_BABE);
        t.mem.writeU32(0x2000, 0x1234_5678);
        const inst = DecodedInst{
            .opcode = opcode,
            .rd = 1,
            .rs1 = 2,
            .rs2 = 3,
            .imm = 0,
        };
        const before = t.cpu;
        try std.testing.expectError(
            error.GeneratedRetirementRequired,
            execute(&t.cpu, &t.mem, inst),
        );
        try std.testing.expectEqualDeep(before, t.cpu);
        try std.testing.expectEqual(@as(u32, 0x1234_5678), t.mem.readU32(0x2000));
    }
}

test "legacy execute refuses production-migrated BRANCH_EQ opcodes" {
    inline for ([_]u32{
        0x0020_8463, // BEQ x1, x2, +8
        0x0020_9463, // BNE x1, x2, +8
    }) |word| {
        var t = makeTestCpuAndMem();
        defer t.mem.deinit();
        t.cpu.writeReg(1, 42);
        t.cpu.writeReg(2, 42);
        const inst = try DecodedInst.decode(word);
        const before = t.cpu;
        try std.testing.expectError(
            error.GeneratedRetirementRequired,
            execute(&t.cpu, &t.mem, inst),
        );
        try std.testing.expectEqualDeep(before, t.cpu);
    }
}

test "legacy execute refuses production-migrated BRANCH_LT opcodes" {
    inline for ([_]u32{
        0x0062_c463, // BLT  x5, x6, +8
        0x0062_e463, // BLTU x5, x6, +8
        0x0053_5463, // BGE  x6, x5, +8
        0x0053_7463, // BGEU x6, x5, +8
    }) |word| {
        var t = makeTestCpuAndMem();
        defer t.mem.deinit();
        t.cpu.writeReg(5, 0x8000_0000);
        t.cpu.writeReg(6, 0xffff_ffff);
        const inst = try DecodedInst.decode(word);
        const before = t.cpu;
        try std.testing.expectError(
            error.GeneratedRetirementRequired,
            execute(&t.cpu, &t.mem, inst),
        );
        try std.testing.expectEqualDeep(before, t.cpu);
    }
}

test "legacy execute refuses production-migrated LT_IMM opcodes" {
    inline for ([_]u32{
        0x0002_a313, // SLTI  x6, x5, 0
        0xfff2_b393, // SLTIU x7, x5, -1
    }) |word| {
        var t = makeTestCpuAndMem();
        defer t.mem.deinit();
        t.cpu.writeReg(5, 0x8000_0000);
        const inst = try DecodedInst.decode(word);
        const before = t.cpu;
        try std.testing.expectError(
            error.GeneratedRetirementRequired,
            execute(&t.cpu, &t.mem, inst),
        );
        try std.testing.expectEqualDeep(before, t.cpu);
    }
}

test "legacy execute refuses production-migrated JAL" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    // JAL x1, +0 => 0x000000EF
    const inst = try DecodedInst.decode(0x000000EF);
    const before = t.cpu;
    try std.testing.expectError(
        error.GeneratedRetirementRequired,
        execute(&t.cpu, &t.mem, inst),
    );
    try std.testing.expectEqualDeep(before, t.cpu);
}

test "legacy execute refuses production-migrated JALR" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    t.cpu.writeReg(2, 0x1000);
    const inst = try DecodedInst.decode(0x0041_00e7); // JALR x1, x2, +4
    const before = t.cpu;
    try std.testing.expectError(
        error.GeneratedRetirementRequired,
        execute(&t.cpu, &t.mem, inst),
    );
    try std.testing.expectEqualDeep(before, t.cpu);
}

test "legacy execute refuses production-migrated LUI" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    // LUI x1, 0x12345 => 0x123450B7
    const inst = try DecodedInst.decode(0x123450B7);
    const before = t.cpu;
    try std.testing.expectError(
        error.GeneratedRetirementRequired,
        execute(&t.cpu, &t.mem, inst),
    );
    try std.testing.expectEqualDeep(before, t.cpu);
}

test "legacy execute refuses production-migrated AUIPC" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    const inst = try DecodedInst.decode(0x1234_5097);
    const before = t.cpu;
    try std.testing.expectError(
        error.GeneratedRetirementRequired,
        execute(&t.cpu, &t.mem, inst),
    );
    try std.testing.expectEqualDeep(before, t.cpu);
}

test "legacy execute refuses production-migrated FENCE" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    const inst = try DecodedInst.decode(0xf538_8f8f);
    const before = t.cpu;
    try std.testing.expectError(
        error.GeneratedRetirementRequired,
        execute(&t.cpu, &t.mem, inst),
    );
    try std.testing.expectEqualDeep(before, t.cpu);
}

test "legacy execute refuses production-migrated RV32M without mutation" {
    inline for ([_]Opcode{ .MUL, .MULH, .MULHSU, .MULHU, .DIV, .DIVU, .REM, .REMU }) |opcode| {
        var t = makeTestCpuAndMem();
        defer t.mem.deinit();
        t.cpu.writeReg(2, 100);
        t.cpu.writeReg(3, 7);
        const before = t.cpu;
        try std.testing.expectError(
            error.GeneratedRetirementRequired,
            execute(&t.cpu, &t.mem, .{
                .opcode = opcode,
                .rd = 1,
                .rs1 = 2,
                .rs2 = 3,
                .imm = 0,
            }),
        );
        try std.testing.expectEqualDeep(before, t.cpu);
    }
}

test "execute ECALL returns error" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    // The runner synthesizes ECALL (SYSTEM words are outside the pinned
    // decode contract); execute keeps its syscall error surface.
    const inst = DecodedInst{ .opcode = .ECALL, .rd = 0, .rs1 = 0, .rs2 = 0, .imm = 0 };
    const result = execute(&t.cpu, &t.mem, inst);
    try std.testing.expectError(error.Ecall, result);
}

//! RV32IM instruction execution.
//!
//! Implements all 45 RV32IM instructions using wrapping arithmetic.

const std = @import("std");
const isa_profile = @import("../isa/profile.zig");
const Cpu = @import("cpu.zig").Cpu;
const Memory = @import("memory.zig").Memory;
const decode = @import("decode.zig");
const Opcode = decode.Opcode;
const DecodedInst = decode.DecodedInst;

pub const ExecuteError = error{
    Ecall,
    Ebreak,
    MisalignedMemoryAccess,
    InstructionAddressMisaligned,
};

fn requireAligned(addr: u32, alignment: u32) ExecuteError!void {
    std.debug.assert(std.math.isPowerOfTwo(alignment));
    if (addr & (alignment - 1) != 0) return error.MisalignedMemoryAccess;
}

/// Execute a single decoded instruction, mutating `cpu` and `mem`.
/// Returns system-instruction errors to the host and rejects memory accesses
/// that the pinned Stark-V AIR cannot represent.
pub fn execute(cpu: *Cpu, mem: *Memory, inst: DecodedInst) ExecuteError!void {
    switch (inst.opcode) {
        // ----------------------------------------------------------------
        // R-type arithmetic
        // ----------------------------------------------------------------
        .ADD => cpu.writeReg(inst.rd, cpu.readReg(inst.rs1) +% cpu.readReg(inst.rs2)),
        .SUB => cpu.writeReg(inst.rd, cpu.readReg(inst.rs1) -% cpu.readReg(inst.rs2)),
        .XOR => cpu.writeReg(inst.rd, cpu.readReg(inst.rs1) ^ cpu.readReg(inst.rs2)),
        .OR => cpu.writeReg(inst.rd, cpu.readReg(inst.rs1) | cpu.readReg(inst.rs2)),
        .AND => cpu.writeReg(inst.rd, cpu.readReg(inst.rs1) & cpu.readReg(inst.rs2)),
        .SLL => {
            const shamt: u5 = @truncate(cpu.readReg(inst.rs2));
            cpu.writeReg(inst.rd, cpu.readReg(inst.rs1) << shamt);
        },
        .SRL => {
            const shamt: u5 = @truncate(cpu.readReg(inst.rs2));
            cpu.writeReg(inst.rd, cpu.readReg(inst.rs1) >> shamt);
        },
        .SRA => {
            const shamt: u5 = @truncate(cpu.readReg(inst.rs2));
            const signed: i32 = @bitCast(cpu.readReg(inst.rs1));
            cpu.writeReg(inst.rd, @bitCast(signed >> shamt));
        },
        .SLT => {
            const a: i32 = @bitCast(cpu.readReg(inst.rs1));
            const b: i32 = @bitCast(cpu.readReg(inst.rs2));
            cpu.writeReg(inst.rd, if (a < b) @as(u32, 1) else 0);
        },
        .SLTU => {
            cpu.writeReg(inst.rd, if (cpu.readReg(inst.rs1) < cpu.readReg(inst.rs2)) @as(u32, 1) else 0);
        },

        // ----------------------------------------------------------------
        // I-type arithmetic
        // ----------------------------------------------------------------
        .ADDI => cpu.writeReg(inst.rd, cpu.readReg(inst.rs1) +% @as(u32, @bitCast(inst.imm))),
        .XORI => cpu.writeReg(inst.rd, cpu.readReg(inst.rs1) ^ @as(u32, @bitCast(inst.imm))),
        .ORI => cpu.writeReg(inst.rd, cpu.readReg(inst.rs1) | @as(u32, @bitCast(inst.imm))),
        .ANDI => cpu.writeReg(inst.rd, cpu.readReg(inst.rs1) & @as(u32, @bitCast(inst.imm))),
        .SLLI => {
            const shamt: u5 = @truncate(@as(u32, @bitCast(inst.imm)));
            cpu.writeReg(inst.rd, cpu.readReg(inst.rs1) << shamt);
        },
        .SRLI => {
            const shamt: u5 = @truncate(@as(u32, @bitCast(inst.imm)));
            cpu.writeReg(inst.rd, cpu.readReg(inst.rs1) >> shamt);
        },
        .SRAI => {
            const shamt: u5 = @truncate(@as(u32, @bitCast(inst.imm)));
            const signed: i32 = @bitCast(cpu.readReg(inst.rs1));
            cpu.writeReg(inst.rd, @bitCast(signed >> shamt));
        },
        .SLTI => {
            const a: i32 = @bitCast(cpu.readReg(inst.rs1));
            cpu.writeReg(inst.rd, if (a < inst.imm) @as(u32, 1) else 0);
        },
        .SLTIU => {
            cpu.writeReg(inst.rd, if (cpu.readReg(inst.rs1) < @as(u32, @bitCast(inst.imm))) @as(u32, 1) else 0);
        },

        // ----------------------------------------------------------------
        // Loads (I-type)
        // ----------------------------------------------------------------
        .LB => {
            const addr = cpu.readReg(inst.rs1) +% @as(u32, @bitCast(inst.imm));
            const byte = mem.readByte(addr);
            // Sign-extend from 8 bits.
            const signed: i8 = @bitCast(byte);
            cpu.writeReg(inst.rd, @bitCast(@as(i32, signed)));
        },
        .LBU => {
            const addr = cpu.readReg(inst.rs1) +% @as(u32, @bitCast(inst.imm));
            cpu.writeReg(inst.rd, @as(u32, mem.readByte(addr)));
        },
        .LH => {
            const addr = cpu.readReg(inst.rs1) +% @as(u32, @bitCast(inst.imm));
            try requireAligned(addr, 2);
            const half = mem.readU16(addr);
            const signed: i16 = @bitCast(half);
            cpu.writeReg(inst.rd, @bitCast(@as(i32, signed)));
        },
        .LHU => {
            const addr = cpu.readReg(inst.rs1) +% @as(u32, @bitCast(inst.imm));
            try requireAligned(addr, 2);
            cpu.writeReg(inst.rd, @as(u32, mem.readU16(addr)));
        },
        .LW => {
            const addr = cpu.readReg(inst.rs1) +% @as(u32, @bitCast(inst.imm));
            try requireAligned(addr, 4);
            cpu.writeReg(inst.rd, mem.readU32(addr));
        },

        // ----------------------------------------------------------------
        // Stores (S-type)
        // ----------------------------------------------------------------
        .SB => {
            const addr = cpu.readReg(inst.rs1) +% @as(u32, @bitCast(inst.imm));
            mem.writeByte(addr, @truncate(cpu.readReg(inst.rs2)));
        },
        .SH => {
            const addr = cpu.readReg(inst.rs1) +% @as(u32, @bitCast(inst.imm));
            try requireAligned(addr, 2);
            mem.writeU16(addr, @truncate(cpu.readReg(inst.rs2)));
        },
        .SW => {
            const addr = cpu.readReg(inst.rs1) +% @as(u32, @bitCast(inst.imm));
            try requireAligned(addr, 4);
            mem.writeU32(addr, cpu.readReg(inst.rs2));
        },

        // ----------------------------------------------------------------
        // Branches (B-type)
        // ----------------------------------------------------------------
        .BEQ => {
            if (cpu.readReg(inst.rs1) == cpu.readReg(inst.rs2)) {
                const target = cpu.pc +% @as(u32, @bitCast(inst.imm));
                isa_profile.requireInstructionAligned(target) catch
                    return error.InstructionAddressMisaligned;
                cpu.pc = target;
                return; // skip the default pc += 4
            }
        },
        .BNE => {
            if (cpu.readReg(inst.rs1) != cpu.readReg(inst.rs2)) {
                const target = cpu.pc +% @as(u32, @bitCast(inst.imm));
                isa_profile.requireInstructionAligned(target) catch
                    return error.InstructionAddressMisaligned;
                cpu.pc = target;
                return;
            }
        },
        .BLT => {
            const a: i32 = @bitCast(cpu.readReg(inst.rs1));
            const b: i32 = @bitCast(cpu.readReg(inst.rs2));
            if (a < b) {
                const target = cpu.pc +% @as(u32, @bitCast(inst.imm));
                isa_profile.requireInstructionAligned(target) catch
                    return error.InstructionAddressMisaligned;
                cpu.pc = target;
                return;
            }
        },
        .BGE => {
            const a: i32 = @bitCast(cpu.readReg(inst.rs1));
            const b: i32 = @bitCast(cpu.readReg(inst.rs2));
            if (a >= b) {
                const target = cpu.pc +% @as(u32, @bitCast(inst.imm));
                isa_profile.requireInstructionAligned(target) catch
                    return error.InstructionAddressMisaligned;
                cpu.pc = target;
                return;
            }
        },
        .BLTU => {
            if (cpu.readReg(inst.rs1) < cpu.readReg(inst.rs2)) {
                const target = cpu.pc +% @as(u32, @bitCast(inst.imm));
                isa_profile.requireInstructionAligned(target) catch
                    return error.InstructionAddressMisaligned;
                cpu.pc = target;
                return;
            }
        },
        .BGEU => {
            if (cpu.readReg(inst.rs1) >= cpu.readReg(inst.rs2)) {
                const target = cpu.pc +% @as(u32, @bitCast(inst.imm));
                isa_profile.requireInstructionAligned(target) catch
                    return error.InstructionAddressMisaligned;
                cpu.pc = target;
                return;
            }
        },

        // ----------------------------------------------------------------
        // Jumps
        // ----------------------------------------------------------------
        .JAL => {
            const target = cpu.pc +% @as(u32, @bitCast(inst.imm));
            isa_profile.requireInstructionAligned(target) catch
                return error.InstructionAddressMisaligned;
            cpu.writeReg(inst.rd, cpu.pc +% 4);
            cpu.pc = target;
            return; // don't add 4
        },
        .JALR => {
            const target = (cpu.readReg(inst.rs1) +% @as(u32, @bitCast(inst.imm))) & 0xFFFF_FFFE;
            isa_profile.requireInstructionAligned(target) catch
                return error.InstructionAddressMisaligned;
            cpu.writeReg(inst.rd, cpu.pc +% 4);
            cpu.pc = target;
            return;
        },

        // ----------------------------------------------------------------
        // Upper immediates
        // ----------------------------------------------------------------
        .LUI => cpu.writeReg(inst.rd, @bitCast(inst.imm)),
        .AUIPC => cpu.writeReg(inst.rd, cpu.pc +% @as(u32, @bitCast(inst.imm))),

        // ----------------------------------------------------------------
        // RV32M: Multiply / Divide
        // ----------------------------------------------------------------
        .MUL => {
            const result = @as(u32, @truncate(
                @as(u64, @bitCast(@as(i64, @as(i32, @bitCast(cpu.readReg(inst.rs1)))) *% @as(i64, @as(i32, @bitCast(cpu.readReg(inst.rs2)))))),
            ));
            cpu.writeReg(inst.rd, result);
        },
        .MULH => {
            const a: i64 = @as(i32, @bitCast(cpu.readReg(inst.rs1)));
            const b: i64 = @as(i32, @bitCast(cpu.readReg(inst.rs2)));
            const product: i64 = a *% b;
            cpu.writeReg(inst.rd, @truncate(@as(u64, @bitCast(product)) >> 32));
        },
        .MULHSU => {
            const a: i64 = @as(i32, @bitCast(cpu.readReg(inst.rs1)));
            const b: i64 = @intCast(@as(u64, cpu.readReg(inst.rs2)));
            const product: i64 = a *% b;
            cpu.writeReg(inst.rd, @truncate(@as(u64, @bitCast(product)) >> 32));
        },
        .MULHU => {
            const a: u64 = cpu.readReg(inst.rs1);
            const b: u64 = cpu.readReg(inst.rs2);
            const product: u64 = a *% b;
            cpu.writeReg(inst.rd, @truncate(product >> 32));
        },
        .DIV => {
            const a: i32 = @bitCast(cpu.readReg(inst.rs1));
            const b: i32 = @bitCast(cpu.readReg(inst.rs2));
            if (b == 0) {
                // Division by zero: result is -1 per spec.
                cpu.writeReg(inst.rd, @bitCast(@as(i32, -1)));
            } else if (a == std.math.minInt(i32) and b == -1) {
                // Overflow: result is the dividend.
                cpu.writeReg(inst.rd, @bitCast(a));
            } else {
                cpu.writeReg(inst.rd, @bitCast(@divTrunc(a, b)));
            }
        },
        .DIVU => {
            const a = cpu.readReg(inst.rs1);
            const b = cpu.readReg(inst.rs2);
            if (b == 0) {
                cpu.writeReg(inst.rd, 0xFFFF_FFFF);
            } else {
                cpu.writeReg(inst.rd, a / b);
            }
        },
        .REM => {
            const a: i32 = @bitCast(cpu.readReg(inst.rs1));
            const b: i32 = @bitCast(cpu.readReg(inst.rs2));
            if (b == 0) {
                cpu.writeReg(inst.rd, @bitCast(a));
            } else if (a == std.math.minInt(i32) and b == -1) {
                cpu.writeReg(inst.rd, 0);
            } else {
                cpu.writeReg(inst.rd, @bitCast(@rem(a, b)));
            }
        },
        .REMU => {
            const a = cpu.readReg(inst.rs1);
            const b = cpu.readReg(inst.rs2);
            if (b == 0) {
                cpu.writeReg(inst.rd, a);
            } else {
                cpu.writeReg(inst.rd, a % b);
            }
        },

        // ----------------------------------------------------------------
        // System
        // ----------------------------------------------------------------
        .FENCE => {}, // No-op in single-threaded zkVM.
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

test "execute ADD" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    t.cpu.writeReg(2, 10);
    t.cpu.writeReg(3, 20);
    // ADD x1, x2, x3
    const inst = try DecodedInst.decode(0x003100B3);
    try execute(&t.cpu, &t.mem, inst);
    try std.testing.expectEqual(@as(u32, 30), t.cpu.readReg(1));
    try std.testing.expectEqual(@as(u32, 0x1004), t.cpu.pc);
}

test "execute SUB" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    t.cpu.writeReg(2, 50);
    t.cpu.writeReg(3, 20);
    // SUB x1, x2, x3
    const inst = try DecodedInst.decode(0x403100B3);
    try execute(&t.cpu, &t.mem, inst);
    try std.testing.expectEqual(@as(u32, 30), t.cpu.readReg(1));
}

test "execute ADDI" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    t.cpu.writeReg(1, 100);
    // ADDI x5, x1, 42  =>  0x02A08293
    const inst = try DecodedInst.decode(0x02A08293);
    try execute(&t.cpu, &t.mem, inst);
    try std.testing.expectEqual(@as(u32, 142), t.cpu.readReg(5));
}

test "execute LW / SW roundtrip" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    t.cpu.writeReg(2, 0x2000); // base address in x2
    t.cpu.writeReg(5, 0xCAFE_BABE);
    // SW x5, 0(x2) => 0x00512023
    const sw_inst = try DecodedInst.decode(0x00512023);
    try execute(&t.cpu, &t.mem, sw_inst);
    // LW x6, 0(x2) => 0x00012303
    const lw_inst = try DecodedInst.decode(0x00012303);
    try execute(&t.cpu, &t.mem, lw_inst);
    try std.testing.expectEqual(@as(u32, 0xCAFE_BABE), t.cpu.readReg(6));
}

test "execute rejects misaligned halfword and word accesses" {
    const cases = [_]struct { opcode: Opcode, addr: u32 }{
        .{ .opcode = .LH, .addr = 0x2001 },
        .{ .opcode = .LHU, .addr = 0x2001 },
        .{ .opcode = .SH, .addr = 0x2001 },
        .{ .opcode = .LW, .addr = 0x2002 },
        .{ .opcode = .SW, .addr = 0x2002 },
    };
    for (cases) |case| {
        var t = makeTestCpuAndMem();
        defer t.mem.deinit();
        t.cpu.writeReg(2, case.addr);
        t.cpu.writeReg(3, 0xCAFE_BABE);
        const inst = DecodedInst{
            .opcode = case.opcode,
            .rd = 1,
            .rs1 = 2,
            .rs2 = 3,
            .imm = 0,
        };
        try std.testing.expectError(error.MisalignedMemoryAccess, execute(&t.cpu, &t.mem, inst));
        try std.testing.expectEqual(@as(u32, 0x1000), t.cpu.pc);
        try std.testing.expectEqual(@as(u32, 0), t.cpu.readReg(1));
        try std.testing.expectEqual(@as(u32, 0), t.mem.readU32(case.addr & ~@as(u32, 3)));
    }
}

test "execute preserves unrestricted byte access" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    t.cpu.writeReg(2, 0x2001);
    t.cpu.writeReg(3, 0xAB);
    try execute(&t.cpu, &t.mem, .{
        .opcode = .SB,
        .rd = 0,
        .rs1 = 2,
        .rs2 = 3,
        .imm = 0,
    });
    try execute(&t.cpu, &t.mem, .{
        .opcode = .LBU,
        .rd = 1,
        .rs1 = 2,
        .rs2 = 0,
        .imm = 0,
    });
    try std.testing.expectEqual(@as(u32, 0xAB), t.cpu.readReg(1));
}

test "execute BEQ taken" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    t.cpu.writeReg(1, 42);
    t.cpu.writeReg(2, 42);
    // BEQ x1, x2, +8 => 0x00208463
    const inst = try DecodedInst.decode(0x00208463);
    try execute(&t.cpu, &t.mem, inst);
    try std.testing.expectEqual(@as(u32, 0x1008), t.cpu.pc); // 0x1000 + 8
}

test "execute BEQ not taken" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    t.cpu.writeReg(1, 42);
    t.cpu.writeReg(2, 43);
    const inst = try DecodedInst.decode(0x00208463);
    try execute(&t.cpu, &t.mem, inst);
    try std.testing.expectEqual(@as(u32, 0x1004), t.cpu.pc); // fallthrough
}

test "execute JAL" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    // JAL x1, +0 => 0x000000EF
    const inst = try DecodedInst.decode(0x000000EF);
    try execute(&t.cpu, &t.mem, inst);
    try std.testing.expectEqual(@as(u32, 0x1004), t.cpu.readReg(1)); // return address
    try std.testing.expectEqual(@as(u32, 0x1000), t.cpu.pc); // pc + 0
}

test "execute LUI" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    // LUI x1, 0x12345 => 0x123450B7
    const inst = try DecodedInst.decode(0x123450B7);
    try execute(&t.cpu, &t.mem, inst);
    try std.testing.expectEqual(@as(u32, 0x12345000), t.cpu.readReg(1));
}

test "execute MUL" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    t.cpu.writeReg(2, 7);
    t.cpu.writeReg(3, 6);
    // MUL x1, x2, x3 => 0x023100B3
    const inst = try DecodedInst.decode(0x023100B3);
    try execute(&t.cpu, &t.mem, inst);
    try std.testing.expectEqual(@as(u32, 42), t.cpu.readReg(1));
}

test "execute DIV by zero" {
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();
    t.cpu.writeReg(2, 100);
    t.cpu.writeReg(3, 0);
    // DIV x1, x2, x3 => 0x0231_40B3
    const inst = try DecodedInst.decode(0x023140B3);
    try execute(&t.cpu, &t.mem, inst);
    try std.testing.expectEqual(@as(u32, 0xFFFF_FFFF), t.cpu.readReg(1)); // -1
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

test "executor equivalence: instruction sequence produces expected CPU state" {
    // Run a sequence of instructions and verify the final register values
    // match the RISC-V spec exactly.
    //
    // Program:
    //   ADDI x1, x0, 10      # x1 = 10
    //   ADDI x2, x0, 20      # x2 = 20
    //   ADD  x3, x1, x2      # x3 = 30
    //   SUB  x4, x2, x1      # x4 = 10
    //   MUL  x5, x1, x2      # x5 = 200
    //   SLL  x6, x1, x2      # x6 = 10 << (20 & 0x1F) = 10 << 20 = 10485760
    //   SLT  x7, x1, x2      # x7 = 1  (10 < 20)
    //   XOR  x8, x1, x2      # x8 = 10 ^ 20 = 30
    var t = makeTestCpuAndMem();
    defer t.mem.deinit();

    const instructions = [_]u32{
        0x00A00093, // ADDI x1, x0, 10
        0x01400113, // ADDI x2, x0, 20
        0x002081B3, // ADD  x3, x1, x2
        0x40110233, // SUB  x4, x2, x1
        0x022082B3, // MUL  x5, x1, x2
        0x00209333, // SLL  x6, x1, x2
        0x0020A3B3, // SLT  x7, x1, x2
        0x0020C433, // XOR  x8, x1, x2
    };

    for (instructions) |inst_word| {
        const inst = try DecodedInst.decode(inst_word);
        try execute(&t.cpu, &t.mem, inst);
    }

    // Verify all registers match expected values from the RISC-V spec.
    try std.testing.expectEqual(@as(u32, 10), t.cpu.readReg(1)); // x1 = 10
    try std.testing.expectEqual(@as(u32, 20), t.cpu.readReg(2)); // x2 = 20
    try std.testing.expectEqual(@as(u32, 30), t.cpu.readReg(3)); // x3 = 30
    try std.testing.expectEqual(@as(u32, 10), t.cpu.readReg(4)); // x4 = 10
    try std.testing.expectEqual(@as(u32, 200), t.cpu.readReg(5)); // x5 = 200
    try std.testing.expectEqual(@as(u32, 10485760), t.cpu.readReg(6)); // x6 = 10 << 20
    try std.testing.expectEqual(@as(u32, 1), t.cpu.readReg(7)); // x7 = 1 (10 < 20)
    try std.testing.expectEqual(@as(u32, 30), t.cpu.readReg(8)); // x8 = 10 ^ 20 = 30

    // Verify PC advanced by 4 for each instruction (8 instructions * 4 = 32).
    try std.testing.expectEqual(@as(u32, 0x1000 + 32), t.cpu.pc);
}

//! RISC-V RV32IM CPU state.
//!
//! Models the 32 general-purpose integer registers (x0 hardwired to zero)
//! and the program counter of a RISC-V RV32IM hart.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

/// Number of integer registers (x0 .. x31).
pub const N_REGISTERS: usize = 32;

pub const Cpu = struct {
    /// General-purpose registers x0..x31.  x0 is hardwired to 0 and writes
    /// to it are silently discarded.
    regs: [N_REGISTERS]u32,
    /// Program counter.
    pc: u32,

    /// Create a fresh CPU with `pc = entry_point`, x2 (sp) = `stack_pointer`,
    /// and all other registers zeroed.
    pub fn init(entry_point: u32, stack_pointer: u32) Cpu {
        var cpu = Cpu{
            .regs = [_]u32{0} ** N_REGISTERS,
            .pc = entry_point,
        };
        // x2 is the stack pointer by convention.
        cpu.regs[2] = stack_pointer;
        return cpu;
    }

    /// Read a register value.  Reading x0 always returns 0.
    pub fn readReg(self: Cpu, reg: u5) u32 {
        if (reg == 0) return 0;
        return self.regs[reg];
    }

    /// Write a register value.  Writes to x0 are silently ignored.
    pub fn writeReg(self: *Cpu, reg: u5, value: u32) void {
        if (reg != 0) {
            self.regs[reg] = value;
        }
    }

    /// Project the CPU state to a 3-element M31 tuple `[pc, sp, fp]`
    /// (analogous to a CasmState for trace integration).
    ///
    /// - `pc` — program counter
    /// - `sp` — stack pointer (x2)
    /// - `fp` — frame pointer (x8/s0)
    ///
    /// Each value is reduced modulo the M31 prime (2^31 - 1).
    pub fn toCasmLikeState(self: Cpu) [3]M31 {
        return .{
            M31.fromU64(@as(u64, self.pc)),
            M31.fromU64(@as(u64, self.readReg(2))), // sp
            M31.fromU64(@as(u64, self.readReg(8))), // fp / s0
        };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Cpu.init sets entry point and stack pointer" {
    const cpu = Cpu.init(0x1000, 0x8000_0000);
    try std.testing.expectEqual(@as(u32, 0x1000), cpu.pc);
    try std.testing.expectEqual(@as(u32, 0x8000_0000), cpu.readReg(2));
}

test "Cpu.readReg(x0) always returns 0" {
    var cpu = Cpu.init(0, 0);
    cpu.regs[0] = 42; // force-set the backing storage
    try std.testing.expectEqual(@as(u32, 0), cpu.readReg(0));
}

test "Cpu.writeReg to x0 is a no-op" {
    var cpu = Cpu.init(0, 0);
    cpu.writeReg(0, 0xDEAD_BEEF);
    try std.testing.expectEqual(@as(u32, 0), cpu.readReg(0));
}

test "Cpu.writeReg/readReg roundtrip" {
    var cpu = Cpu.init(0, 0);
    cpu.writeReg(10, 0x1234_5678);
    try std.testing.expectEqual(@as(u32, 0x1234_5678), cpu.readReg(10));
}

test "Cpu.toCasmLikeState returns M31 values" {
    var cpu = Cpu.init(100, 200);
    cpu.writeReg(8, 300); // fp
    const state = cpu.toCasmLikeState();
    try std.testing.expectEqual(@as(u32, 100), state[0].v);
    try std.testing.expectEqual(@as(u32, 200), state[1].v);
    try std.testing.expectEqual(@as(u32, 300), state[2].v);
}

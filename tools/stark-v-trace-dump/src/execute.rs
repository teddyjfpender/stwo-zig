use super::decode::{DecodedInst, Opcode};
use super::elf::Memory;

// ---------------------------------------------------------------------------
// CPU state and executor
// ---------------------------------------------------------------------------

pub(super) struct Cpu {
    pub(super) regs: [u32; 32],
    pub(super) pc: u32,
}

impl Cpu {
    pub(super) fn new(entry_point: u32, stack_pointer: u32) -> Self {
        let mut regs = [0u32; 32];
        regs[2] = stack_pointer; // x2 = sp
        Self {
            regs,
            pc: entry_point,
        }
    }

    pub(super) fn read_reg(&self, r: u8) -> u32 {
        if r == 0 {
            0
        } else {
            self.regs[r as usize]
        }
    }

    fn write_reg(&mut self, r: u8, val: u32) {
        if r != 0 {
            self.regs[r as usize] = val;
        }
    }
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

pub(super) enum ExecResult {
    Continue,
    Halt,
}

pub(super) fn execute(cpu: &mut Cpu, mem: &mut Memory, inst: &DecodedInst) -> ExecResult {
    let rs1_v = cpu.read_reg(inst.rs1);
    let rs2_v = cpu.read_reg(inst.rs2);

    match inst.opcode {
        // -- R-type arithmetic --
        Opcode::ADD => cpu.write_reg(inst.rd, rs1_v.wrapping_add(rs2_v)),
        Opcode::SUB => cpu.write_reg(inst.rd, rs1_v.wrapping_sub(rs2_v)),
        Opcode::XOR => cpu.write_reg(inst.rd, rs1_v ^ rs2_v),
        Opcode::OR => cpu.write_reg(inst.rd, rs1_v | rs2_v),
        Opcode::AND => cpu.write_reg(inst.rd, rs1_v & rs2_v),
        Opcode::SLL => cpu.write_reg(inst.rd, rs1_v << (rs2_v & 0x1F)),
        Opcode::SRL => cpu.write_reg(inst.rd, rs1_v >> (rs2_v & 0x1F)),
        Opcode::SRA => {
            let signed = rs1_v as i32;
            cpu.write_reg(inst.rd, (signed >> (rs2_v & 0x1F)) as u32);
        }
        Opcode::SLT => {
            let a = rs1_v as i32;
            let b = rs2_v as i32;
            cpu.write_reg(inst.rd, if a < b { 1 } else { 0 });
        }
        Opcode::SLTU => {
            cpu.write_reg(inst.rd, if rs1_v < rs2_v { 1 } else { 0 });
        }

        // -- I-type arithmetic --
        Opcode::ADDI => cpu.write_reg(inst.rd, rs1_v.wrapping_add(inst.imm as u32)),
        Opcode::XORI => cpu.write_reg(inst.rd, rs1_v ^ (inst.imm as u32)),
        Opcode::ORI => cpu.write_reg(inst.rd, rs1_v | (inst.imm as u32)),
        Opcode::ANDI => cpu.write_reg(inst.rd, rs1_v & (inst.imm as u32)),
        Opcode::SLLI => cpu.write_reg(inst.rd, rs1_v << (inst.imm as u32 & 0x1F)),
        Opcode::SRLI => cpu.write_reg(inst.rd, rs1_v >> (inst.imm as u32 & 0x1F)),
        Opcode::SRAI => {
            let signed = rs1_v as i32;
            cpu.write_reg(inst.rd, (signed >> (inst.imm as u32 & 0x1F)) as u32);
        }
        Opcode::SLTI => {
            let a = rs1_v as i32;
            cpu.write_reg(inst.rd, if a < inst.imm { 1 } else { 0 });
        }
        Opcode::SLTIU => {
            cpu.write_reg(inst.rd, if rs1_v < (inst.imm as u32) { 1 } else { 0 });
        }

        // -- Loads --
        Opcode::LB => {
            let addr = rs1_v.wrapping_add(inst.imm as u32);
            let byte = mem.read_byte(addr);
            let signed = byte as i8;
            cpu.write_reg(inst.rd, signed as i32 as u32);
        }
        Opcode::LBU => {
            let addr = rs1_v.wrapping_add(inst.imm as u32);
            cpu.write_reg(inst.rd, mem.read_byte(addr) as u32);
        }
        Opcode::LH => {
            let addr = rs1_v.wrapping_add(inst.imm as u32);
            let half = mem.read_u16(addr);
            let signed = half as i16;
            cpu.write_reg(inst.rd, signed as i32 as u32);
        }
        Opcode::LHU => {
            let addr = rs1_v.wrapping_add(inst.imm as u32);
            cpu.write_reg(inst.rd, mem.read_u16(addr) as u32);
        }
        Opcode::LW => {
            let addr = rs1_v.wrapping_add(inst.imm as u32);
            cpu.write_reg(inst.rd, mem.read_u32(addr));
        }

        // -- Stores --
        Opcode::SB => {
            let addr = rs1_v.wrapping_add(inst.imm as u32);
            mem.write_byte(addr, rs2_v as u8);
        }
        Opcode::SH => {
            let addr = rs1_v.wrapping_add(inst.imm as u32);
            mem.write_u16(addr, rs2_v as u16);
        }
        Opcode::SW => {
            let addr = rs1_v.wrapping_add(inst.imm as u32);
            mem.write_u32(addr, rs2_v);
        }

        // -- Branches --
        Opcode::BEQ => {
            if rs1_v == rs2_v {
                cpu.pc = cpu.pc.wrapping_add(inst.imm as u32);
                return ExecResult::Continue;
            }
        }
        Opcode::BNE => {
            if rs1_v != rs2_v {
                cpu.pc = cpu.pc.wrapping_add(inst.imm as u32);
                return ExecResult::Continue;
            }
        }
        Opcode::BLT => {
            if (rs1_v as i32) < (rs2_v as i32) {
                cpu.pc = cpu.pc.wrapping_add(inst.imm as u32);
                return ExecResult::Continue;
            }
        }
        Opcode::BGE => {
            if (rs1_v as i32) >= (rs2_v as i32) {
                cpu.pc = cpu.pc.wrapping_add(inst.imm as u32);
                return ExecResult::Continue;
            }
        }
        Opcode::BLTU => {
            if rs1_v < rs2_v {
                cpu.pc = cpu.pc.wrapping_add(inst.imm as u32);
                return ExecResult::Continue;
            }
        }
        Opcode::BGEU => {
            if rs1_v >= rs2_v {
                cpu.pc = cpu.pc.wrapping_add(inst.imm as u32);
                return ExecResult::Continue;
            }
        }

        // -- Jumps --
        Opcode::JAL => {
            cpu.write_reg(inst.rd, cpu.pc.wrapping_add(4));
            cpu.pc = cpu.pc.wrapping_add(inst.imm as u32);
            return ExecResult::Continue;
        }
        Opcode::JALR => {
            let target = (rs1_v.wrapping_add(inst.imm as u32)) & 0xFFFF_FFFE;
            cpu.write_reg(inst.rd, cpu.pc.wrapping_add(4));
            cpu.pc = target;
            return ExecResult::Continue;
        }

        // -- Upper immediates --
        Opcode::LUI => cpu.write_reg(inst.rd, inst.imm as u32),
        Opcode::AUIPC => cpu.write_reg(inst.rd, cpu.pc.wrapping_add(inst.imm as u32)),

        // -- RV32M: Multiply --
        Opcode::MUL => {
            let result = (rs1_v as i32 as i64).wrapping_mul(rs2_v as i32 as i64) as u64;
            cpu.write_reg(inst.rd, result as u32);
        }
        Opcode::MULH => {
            let a = rs1_v as i32 as i64;
            let b = rs2_v as i32 as i64;
            let product = a.wrapping_mul(b) as u64;
            cpu.write_reg(inst.rd, (product >> 32) as u32);
        }
        Opcode::MULHSU => {
            let a = rs1_v as i32 as i64;
            let b = rs2_v as u64 as i64;
            let product = a.wrapping_mul(b) as u64;
            cpu.write_reg(inst.rd, (product >> 32) as u32);
        }
        Opcode::MULHU => {
            let a = rs1_v as u64;
            let b = rs2_v as u64;
            let product = a.wrapping_mul(b);
            cpu.write_reg(inst.rd, (product >> 32) as u32);
        }

        // -- RV32M: Divide --
        Opcode::DIV => {
            let a = rs1_v as i32;
            let b = rs2_v as i32;
            if b == 0 {
                cpu.write_reg(inst.rd, (-1i32) as u32);
            } else if a == i32::MIN && b == -1 {
                cpu.write_reg(inst.rd, a as u32);
            } else {
                cpu.write_reg(inst.rd, a.wrapping_div(b) as u32);
            }
        }
        Opcode::DIVU => {
            let a = rs1_v;
            let b = rs2_v;
            if b == 0 {
                cpu.write_reg(inst.rd, 0xFFFF_FFFF);
            } else {
                cpu.write_reg(inst.rd, a / b);
            }
        }
        Opcode::REM => {
            let a = rs1_v as i32;
            let b = rs2_v as i32;
            if b == 0 {
                cpu.write_reg(inst.rd, a as u32);
            } else if a == i32::MIN && b == -1 {
                cpu.write_reg(inst.rd, 0);
            } else {
                cpu.write_reg(inst.rd, a.wrapping_rem(b) as u32);
            }
        }
        Opcode::REMU => {
            let a = rs1_v;
            let b = rs2_v;
            if b == 0 {
                cpu.write_reg(inst.rd, a);
            } else {
                cpu.write_reg(inst.rd, a % b);
            }
        }

        // -- System --
        Opcode::ECALL => return ExecResult::Halt,
        Opcode::EBREAK => return ExecResult::Halt,
    }

    // Default: advance PC by 4 (branches/jumps return early).
    cpu.pc = cpu.pc.wrapping_add(4);
    ExecResult::Continue
}

// ---------------------------------------------------------------------------
// Main runner
// ---------------------------------------------------------------------------

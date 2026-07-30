//! Self-contained RV32IM executor that loads a RISC-V ELF binary,
//! runs it to completion (or ECALL/EBREAK), and dumps the full
//! execution trace as JSON.
//!
//! The JSON output matches the trace schema used by stwo-zig's
//! RISC-V prover so the two can be compared for execution equivalence.

use clap::Parser;
use serde::Serialize;
use std::fs;
use std::process;

mod decode;
mod elf;
mod execute;

use decode::{decode, Opcode};
use elf::{load_elf, Memory};
use execute::{execute, Cpu, ExecResult};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "stark-v-trace-dump")]
#[command(about = "Run a RISC-V ELF and dump execution trace as JSON")]
struct Args {
    /// Path to the RV32IM ELF binary.
    #[arg(long)]
    elf: String,

    /// Path to write the JSON trace output.
    #[arg(long)]
    output: String,

    /// Maximum number of steps before halting (default: 1_000_000).
    #[arg(long, default_value_t = 1_000_000)]
    max_steps: usize,

    /// Initial stack pointer value (default: 0x7FFF0000).
    #[arg(long, default_value_t = 0x7FFF_0000)]
    stack_pointer: u32,
}

// ---------------------------------------------------------------------------
// JSON output schema
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TraceStep {
    clk: usize,
    pc: u32,
    opcode: &'static str,
    rd: u8,
    rs1: u8,
    rs2: u8,
    imm: i32,
    rs1_val: u32,
    rs2_val: u32,
    rd_val: u32,
    mem_addr: u32,
    mem_val: u32,
    is_load: bool,
    is_store: bool,
    branch_taken: bool,
    next_pc: u32,
}

#[derive(Serialize)]
struct TraceOutput {
    initial_pc: u32,
    final_pc: u32,
    final_regs: [u32; 32],
    total_steps: usize,
    steps: Vec<TraceStep>,
}

fn run_elf(elf_bytes: &[u8], max_steps: usize, stack_pointer: u32) -> Result<TraceOutput, String> {
    let mut mem = Memory::new();
    let elf_info = load_elf(elf_bytes, &mut mem)?;

    eprintln!(
        "ELF loaded: entry=0x{:08X}, segments={}",
        elf_info.entry_point, elf_info.segments_loaded
    );

    let mut cpu = Cpu::new(elf_info.entry_point, stack_pointer);
    let initial_pc = cpu.pc;
    let mut steps: Vec<TraceStep> = Vec::new();

    for clk in 0..max_steps {
        let pc_before = cpu.pc;
        let inst_word = mem.read_u32(cpu.pc);
        let inst = match decode(inst_word) {
            Ok(i) => i,
            Err(e) => {
                eprintln!("Decode error at PC=0x{:08X}: {}", cpu.pc, e);
                break;
            }
        };

        // Capture pre-execution register values.
        let rs1_val = cpu.read_reg(inst.rs1);
        let rs2_val = cpu.read_reg(inst.rs2);

        // Capture memory address and value for load/store before execution.
        let mut mem_addr: u32 = 0;
        let mut mem_val: u32 = 0;
        let is_load = inst.opcode.is_load();
        let is_store = inst.opcode.is_store();

        if is_load || is_store {
            mem_addr = rs1_val.wrapping_add(inst.imm as u32);
            if is_load {
                mem_val = match inst.opcode {
                    Opcode::LB | Opcode::LBU => mem.read_byte(mem_addr) as u32,
                    Opcode::LH | Opcode::LHU => mem.read_u16(mem_addr) as u32,
                    Opcode::LW => mem.read_u32(mem_addr),
                    _ => 0,
                };
            } else {
                mem_val = rs2_val;
            }
        }

        // Execute.
        let halted = matches!(execute(&mut cpu, &mut mem, &inst), ExecResult::Halt);

        let rd_val = cpu.read_reg(inst.rd);
        let next_pc = cpu.pc;
        let branch_taken = next_pc != pc_before.wrapping_add(4);

        steps.push(TraceStep {
            clk,
            pc: pc_before,
            opcode: inst.opcode.name(),
            rd: inst.rd,
            rs1: inst.rs1,
            rs2: inst.rs2,
            imm: inst.imm,
            rs1_val,
            rs2_val,
            rd_val,
            mem_addr,
            mem_val,
            is_load,
            is_store,
            branch_taken,
            next_pc,
        });

        if halted {
            break;
        }
    }

    let total_steps = steps.len();
    eprintln!(
        "Execution complete: {} steps, final PC=0x{:08X}",
        total_steps, cpu.pc
    );

    Ok(TraceOutput {
        initial_pc,
        final_pc: cpu.pc,
        final_regs: cpu.regs,
        total_steps,
        steps,
    })
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let args = Args::parse();

    let elf_bytes = match fs::read(&args.elf) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to read ELF '{}': {}", args.elf, e);
            process::exit(1);
        }
    };

    let trace = match run_elf(&elf_bytes, args.max_steps, args.stack_pointer) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Execution failed: {}", e);
            process::exit(1);
        }
    };

    let json = match serde_json::to_string_pretty(&trace) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("JSON serialization failed: {}", e);
            process::exit(1);
        }
    };

    match fs::write(&args.output, &json) {
        Ok(()) => {
            eprintln!("Trace written to {}", args.output);
        }
        Err(e) => {
            eprintln!("Failed to write output '{}': {}", args.output, e);
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests;

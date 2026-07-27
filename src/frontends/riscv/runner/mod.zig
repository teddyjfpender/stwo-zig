//! RISC-V RV32IM runner — fetch/decode/execute loop with ELF loading.
//!
//! Provides a complete functional simulator for RV32IM programs.
//! Supports optional host syscall interface for guest↔host communication.

const std = @import("std");
const isa_profile = @import("../isa/profile.zig");
pub const cpu = @import("cpu.zig");
pub const decode = @import("decode.zig");
pub const memory = @import("memory.zig");
pub const execute_mod = @import("execute.zig");
pub const elf_loader = @import("elf_loader.zig");
pub const trace = @import("trace.zig");
pub const trace_dump = @import("trace_dump.zig");
/// Test-only bridge to the pinned Sail oracle; see `sail_oracle.zig`.
pub const sail_oracle = @import("sail_oracle.zig");
pub const state_chain = @import("state_chain.zig");
pub const memory_state = @import("memory_state.zig");
pub const result_mod = @import("result.zig");
const access_witness = @import("access_witness.zig");
pub const host_mod = @import("../host/mod.zig");

pub const Cpu = cpu.Cpu;
pub const Memory = memory.Memory;
pub const DecodedInst = decode.DecodedInst;
pub const Opcode = decode.Opcode;
pub const HostInterface = host_mod.HostInterface;
pub const CompletionReason = result_mod.CompletionReason;
pub const OutputWord = result_mod.OutputWord;
pub const RunResult = result_mod.RunResult;

/// Run a RISC-V ELF program to completion (or until `max_steps`).
///
/// The program terminates when an ECALL instruction is encountered
/// or when `max_steps` is reached. This is the backwards-compatible
/// entry point — ECALL always halts.
pub fn run(allocator: std.mem.Allocator, elf_bytes: []const u8, max_steps: usize) !RunResult {
    return runWithHost(allocator, elf_bytes, max_steps, null);
}

/// Run an ELF using its linker-defined input buffer and halt flag.
/// This is compatible with stark-v guest binaries.
pub fn runWithInput(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    input: []const u8,
    max_steps: usize,
) !RunResult {
    return runConfigured(allocator, elf_bytes, max_steps, null, input, true, true);
}

/// Run a RISC-V ELF program with optional host syscall handling.
///
/// When `host` is non-null, ECALL dispatches to the host interface
/// which reads a7 for the syscall number and handles it. When `host`
/// is null, ECALL halts (backwards-compatible behavior).
pub fn runWithHost(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    max_steps: usize,
    host: ?HostInterface,
) !RunResult {
    return runConfigured(allocator, elf_bytes, max_steps, host, &.{}, false, false);
}

fn runConfigured(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    max_steps: usize,
    host: ?HostInterface,
    input: []const u8,
    stop_on_halt_flag: bool,
    strict_completion: bool,
) !RunResult {
    var mem = Memory.init(allocator);
    defer mem.deinit();

    const elf_info = try elf_loader.loadElf(elf_bytes, &mem);
    var rv_cpu = Cpu.init(elf_info.entry_point, elf_info.stack_pointer);
    rv_cpu.writeReg(3, elf_info.global_pointer);
    const initial_pc = rv_cpu.pc;
    const initial_regs = snapshotRegisters(rv_cpu);
    if (input.len != 0) {
        const input_capacity = elf_info.input_end -| elf_info.input_start;
        if (input.len > input_capacity) return error.InputTooLarge;
        mem.writeSlice(elf_info.input_start, input);
    }
    var exec_trace = trace.Trace.init(allocator);
    errdefer exec_trace.deinit();
    exec_trace.initial_pc = rv_cpu.pc;
    var chain_tracker = state_chain.StateChainTracker.init(allocator);
    errdefer chain_tracker.deinit();
    var exit_code: ?u32 = null;
    var completion_reason: CompletionReason = undefined;

    var steps: usize = 0;
    while (true) {
        if (stop_on_halt_flag) {
            if (mem.readU32(elf_info.halt_flag) != 0) {
                completion_reason = .halt_flag;
                break;
            }
        }
        if (steps >= max_steps) {
            if (strict_completion) return error.MaxStepsExceeded;
            completion_reason = .max_steps;
            break;
        }
        const pc_before = rv_cpu.pc;
        isa_profile.requireInstructionAligned(pc_before) catch
            return error.InstructionAddressMisaligned;
        const inst_word = mem.readU32(rv_cpu.pc);
        if (strict_completion and (inst_word == 0x00000073 or inst_word == 0x00100073))
            return error.InvalidInstruction;
        const inst = DecodedInst.decode(inst_word) catch {
            if (strict_completion) return error.InvalidInstruction;
            completion_reason = .invalid_instruction;
            break;
        };

        // Capture pre-execution register values.
        const rs1_val = rv_cpu.readReg(inst.rs1);
        const rs2_val = rv_cpu.readReg(inst.rs2);
        const rd_prev_val = rv_cpu.readReg(inst.rd);
        const access_clk: u32 = @intCast(steps + 1);
        const access = access_witness.capture(&chain_tracker, inst, access_clk);

        // The zkVM completion sentinel is an environment event, not a retired
        // instruction: `jal x0, 0`, or `jalr x0` targeting itself.
        const is_self_loop = switch (inst.opcode) {
            .JAL => inst.rd == 0 and inst.imm == 0,
            .JALR => inst.rd == 0 and
                ((rs1_val +% @as(u32, @bitCast(inst.imm))) & ~@as(u32, 1)) == pc_before,
            else => false,
        };
        if (is_self_loop) {
            completion_reason = .self_loop;
            break;
        }

        // Capture memory address and value for load/store instructions
        // BEFORE execution modifies CPU state.
        var mem_addr: u32 = 0;
        var mem_val: u32 = 0;
        var mem_prev_word: u32 = 0;
        var mem_prev_clk: u32 = 0;
        const is_load = decode.isLoad(inst.opcode);
        const is_store = decode.isStore(inst.opcode);

        if (is_load or is_store) {
            mem_addr = rs1_val +% @as(u32, @bitCast(inst.imm));
            const aligned_addr = mem_addr & ~@as(u32, 3);
            mem_prev_word = mem.readU32(aligned_addr);
            mem_prev_clk = state_chain.StateChainTracker.effectivePreviousClock(
                chain_tracker.mem_last_clk.get(aligned_addr) orelse 0,
                access_clk,
            );
            if (is_load) {
                mem_val = switch (inst.opcode) {
                    .LB, .LBU => @as(u32, mem.readByte(mem_addr)),
                    .LH, .LHU => @as(u32, mem.readU16(mem_addr)),
                    .LW => mem.readU32(mem_addr),
                    else => 0,
                };
            } else {
                mem_val = rs2_val;
            }
        }

        // Execute the instruction.
        var halted = false;
        execute_mod.execute(&rv_cpu, &mem, inst) catch |err| switch (err) {
            error.Ecall => {
                if (host) |h| {
                    // Dispatch to host syscall handler.
                    const result = h.handleSyscall(&rv_cpu, &mem);

                    // Record any memory writes the syscall performed
                    // into the state chain tracker.
                    for (h.lastMemoryWrites()) |mw| {
                        try chain_tracker.recordMemTransition(
                            mw.addr,
                            access_clk,
                            mw.previous_value,
                            mw.value,
                        );
                    }

                    // Record any register writes (a0 return value).
                    // The syscall may have written a0 (x10) as a return value.
                    // We capture rd_val below which will pick up the new a0.

                    switch (result) {
                        .Halt => |code| {
                            exit_code = code;
                            completion_reason = .host_halt;
                            halted = true;
                        },
                        .Continue => {
                            // Advance PC past the ECALL instruction.
                            rv_cpu.pc +%= 4;
                        },
                    }
                } else {
                    completion_reason = .ecall;
                    halted = true;
                }
            },
            error.Ebreak => {
                completion_reason = .ebreak;
                halted = true;
            },
            error.MisalignedMemoryAccess => return error.MisalignedMemoryAccess,
            error.InstructionAddressMisaligned => return error.InstructionAddressMisaligned,
        };

        const rd_val = rv_cpu.readReg(inst.rd);

        // Record trace row.
        try exec_trace.append(.{
            .clk = access_clk,
            .pc = pc_before,
            .opcode = inst.opcode,
            .rd = inst.rd,
            .rs1 = inst.rs1,
            .rs2 = inst.rs2,
            .imm = inst.imm,
            .rs1_val = rs1_val,
            .rs2_val = rs2_val,
            .rs1_prev_clk = access.rs1_prev_clock,
            .rs2_prev_clk = access.rs2_prev_clock,
            .rd_prev_val = rd_prev_val,
            .rd_prev_clk = access.rd_prev_clock,
            .rd_val = rd_val,
            .mem_addr = mem_addr,
            .mem_val = mem_val,
            .mem_prev_word = mem_prev_word,
            .mem_next_word = if (is_load or is_store)
                mem.readU32(mem_addr & ~@as(u32, 3))
            else
                0,
            .mem_prev_clk = mem_prev_clk,
            .is_load = is_load,
            .is_store = is_store,
            .branch_taken = (rv_cpu.pc != pc_before + 4),
            .next_pc = rv_cpu.pc,
            .inst_word = inst_word,
        });

        // Record state chain accesses.
        // Pinned Stark-V places every operand access for an instruction at
        // the same one-based execution clock, in source-then-destination order.
        try access.recordRegisters(
            &chain_tracker,
            inst,
            access_clk,
            rs1_val,
            rs2_val,
            rd_prev_val,
            rd_val,
        );
        if (is_load or is_store) {
            const aligned_addr = mem_addr & ~@as(u32, 3);
            try chain_tracker.recordMemTransition(
                aligned_addr,
                access_clk,
                mem_prev_word,
                mem.readU32(aligned_addr),
            );
        }

        steps += 1;

        if (halted) break;

        // Backup infinite-loop halt: the retired instruction left PC unchanged.
        if (rv_cpu.pc == pc_before) {
            completion_reason = .stalled_pc;
            break;
        }
    }

    exec_trace.final_pc = rv_cpu.pc;

    const owned_input = try allocator.dupe(u8, input);
    errdefer allocator.free(owned_input);
    const captured_output = try captureOutput(
        allocator,
        &mem,
        &chain_tracker,
        elf_info,
        strict_completion,
    );
    errdefer {
        if (captured_output.bytes) |output| allocator.free(output);
        allocator.free(captured_output.words);
    }
    const completion_address: u32 = switch (completion_reason) {
        .halt_flag => elf_info.halt_flag,
        .self_loop => rv_cpu.pc,
        else => 0,
    };
    const completion_value: u32 = switch (completion_reason) {
        .halt_flag => mem.readU32(elf_info.halt_flag),
        .self_loop => mem.readU32(rv_cpu.pc),
        else => 0,
    };
    const completion_clock: u32 = switch (completion_reason) {
        .halt_flag => chain_tracker.mem_last_clk.get(elf_info.halt_flag & ~@as(u32, 3)) orelse 0,
        else => 0,
    };
    const rw_memory = try memory_state.capture(
        allocator,
        &mem,
        &chain_tracker,
        elf_info.memory_layout,
        memory_state.SegmentRole.single(),
        captured_output.len,
        if (completion_reason == .halt_flag)
            elf_info.halt_flag & ~@as(u32, 3)
        else
            null,
    );
    chain_tracker.releaseMemoryBaselines();
    errdefer {
        var owned = rw_memory;
        owned.deinit(allocator);
    }

    return .{
        .initial_pc = initial_pc,
        .initial_regs = initial_regs,
        .cpu_final = rv_cpu,
        .final_pc = rv_cpu.pc,
        .final_regs = snapshotRegisters(rv_cpu),
        .step_count = steps,
        .completion_reason = completion_reason,
        .completion_address = completion_address,
        .completion_value = completion_value,
        .completion_clock = completion_clock,
        .input = owned_input,
        .input_start = elf_info.input_start,
        .input_end = elf_info.input_end,
        .output = captured_output.bytes,
        .output_len = captured_output.len,
        .output_len_addr = elf_info.output_len,
        .output_data_addr = elf_info.output_data,
        .output_end_addr = elf_info.output_end,
        .output_words = captured_output.words,
        .execution_trace = exec_trace,
        .state_chain_tracker = chain_tracker,
        .rw_memory = rw_memory,
        .exit_code = exit_code,
        .allocator = allocator,
    };
}

const CapturedOutput = struct {
    bytes: ?[]u8,
    len: u32,
    words: []OutputWord,
};

fn snapshotRegisters(rv_cpu: Cpu) [32]u32 {
    var regs: [32]u32 = undefined;
    for (&regs, 0..) |*value, index| {
        value.* = rv_cpu.readReg(@intCast(index));
    }
    return regs;
}

fn captureOutput(
    allocator: std.mem.Allocator,
    mem: *const Memory,
    tracker: *const state_chain.StateChainTracker,
    elf_info: elf_loader.ElfInfo,
    require_access: bool,
) !CapturedOutput {
    const output_len = mem.readU32(elf_info.output_len);
    const capacity = elf_info.output_end -| elf_info.output_data;
    const valid_len = output_len != 0 and output_len <= capacity;

    var bytes: ?[]u8 = null;
    errdefer if (bytes) |output| allocator.free(output);
    if (valid_len) {
        const output = try allocator.alloc(u8, output_len);
        mem.readSlice(elf_info.output_data, output);
        bytes = output;
    }

    var words: std.ArrayList(OutputWord) = .{};
    errdefer words.deinit(allocator);
    try appendOutputWord(
        allocator,
        &words,
        mem,
        tracker,
        elf_info.output_len & ~@as(u32, 3),
        require_access,
    );

    if (valid_len) {
        const first = elf_info.output_data & ~@as(u32, 3);
        const end = @as(u64, elf_info.output_data) + output_len;
        const end_aligned = (end + 3) & ~@as(u64, 3);
        var addr: u64 = first;
        while (addr < end_aligned) : (addr += 4) {
            try appendOutputWord(
                allocator,
                &words,
                mem,
                tracker,
                @intCast(addr),
                require_access,
            );
        }
    }

    return .{
        .bytes = bytes,
        .len = output_len,
        .words = try words.toOwnedSlice(allocator),
    };
}

fn appendOutputWord(
    allocator: std.mem.Allocator,
    words: *std.ArrayList(OutputWord),
    mem: *const Memory,
    tracker: *const state_chain.StateChainTracker,
    addr: u32,
    require_access: bool,
) !void {
    const clock = tracker.mem_last_clk.get(addr) orelse {
        if (require_access) return error.OutputAddressNotAccessed;
        return;
    };
    try words.append(allocator, .{
        .addr = addr,
        .value = mem.readU32(addr),
        .clock = clock,
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "runner: run minimal ELF to ecall" {
    // Build a tiny ELF that executes:
    //   0x10000: ADDI x1, x0, 42   (0x02A00093)
    //   0x10004: ECALL              (0x00000073)
    var mem_for_elf = Memory.init(std.testing.allocator);
    defer mem_for_elf.deinit();

    // We'll construct the ELF in-memory with 2 instructions.
    var elf_buf: [92]u8 = [_]u8{0} ** 92;

    // ELF header
    elf_buf[0] = 0x7F;
    elf_buf[1] = 'E';
    elf_buf[2] = 'L';
    elf_buf[3] = 'F';
    elf_buf[4] = 1; // ELFCLASS32
    elf_buf[5] = 1; // ELFDATA2LSB
    elf_buf[6] = 1; // EI_VERSION
    elf_buf[16] = 2; // e_type = ET_EXEC
    elf_buf[18] = 0xF3; // e_machine = EM_RISCV
    elf_buf[20] = 1; // e_version
    // e_entry = 0x10000
    elf_buf[24] = 0x00;
    elf_buf[25] = 0x00;
    elf_buf[26] = 0x01;
    elf_buf[27] = 0x00;
    // e_phoff = 52
    elf_buf[28] = 52;
    // e_ehsize = 52
    elf_buf[40] = 52;
    // e_phentsize = 32
    elf_buf[42] = 32;
    // e_phnum = 1
    elf_buf[44] = 1;

    // Program header at offset 52
    elf_buf[52] = 1; // p_type = PT_LOAD
    elf_buf[56] = 84; // p_offset = 84
    // p_vaddr = 0x10000
    elf_buf[60] = 0x00;
    elf_buf[61] = 0x00;
    elf_buf[62] = 0x01;
    elf_buf[63] = 0x00;
    // p_filesz = 8 (2 instructions)
    elf_buf[68] = 8;
    // p_memsz = 8
    elf_buf[72] = 8;

    // Instructions at offset 84
    // ADDI x1, x0, 42 = 0x02A00093
    elf_buf[84] = 0x93;
    elf_buf[85] = 0x00;
    elf_buf[86] = 0xA0;
    elf_buf[87] = 0x02;
    // ECALL = 0x00000073
    elf_buf[88] = 0x73;
    elf_buf[89] = 0x00;
    elf_buf[90] = 0x00;
    elf_buf[91] = 0x00;

    var result = try run(std.testing.allocator, &elf_buf, 1000);
    defer result.deinit();
    try std.testing.expectEqual(@as(u32, 42), result.cpu_final.readReg(1));
    try std.testing.expectEqual(@as(usize, 2), result.step_count);
    try std.testing.expectEqual(@as(usize, 2), result.execution_trace.rows.items.len);
    try std.testing.expectEqual(CompletionReason.ecall, result.completion_reason);
    try std.testing.expectEqual(@as(u32, 0x10000), result.initial_pc);
    try std.testing.expectEqual(@as(u32, 0x10004), result.final_pc);
    try std.testing.expectEqual(elf_loader.DEFAULT_STACK_POINTER, result.initial_regs[2]);
    try std.testing.expectEqual(elf_loader.DEFAULT_GLOBAL_POINTER, result.initial_regs[3]);
    try std.testing.expectEqual(@as(u32, 42), result.final_regs[1]);
}

test "runner: runWithInput captures Stark-V public IO with access clocks" {
    const instructions = [_]u32{
        0x0010_00B7, // LUI x1, 0x100: x1 = 0x0010_0000
        0x0040_0113, // ADDI x2, x0, 4
        0x0020_A223, // SW x2, 4(x1): output length
        0x02A0_0193, // ADDI x3, x0, 42
        0x0030_A423, // SW x3, 8(x1): output data
        0x0010_0113, // ADDI x2, x0, 1
        0x0020_A023, // SW x2, 0(x1): halt flag
    };
    const elf = makeTestElf(&instructions);

    var result = try runWithInput(std.testing.allocator, &elf, &.{}, 1000);
    defer result.deinit();

    try std.testing.expectEqual(CompletionReason.halt_flag, result.completion_reason);
    try std.testing.expectEqual(@as(usize, instructions.len), result.step_count);
    try std.testing.expectEqual(@as(u32, 4), result.output_len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 42, 0, 0, 0 }, result.output.?);
    try std.testing.expectEqual(@as(usize, 2), result.output_words.len);
    try std.testing.expectEqual(OutputWord{
        .addr = elf_loader.DEFAULT_OUTPUT_LEN,
        .value = 4,
        .clock = 3,
    }, result.output_words[0]);
    try std.testing.expectEqual(OutputWord{
        .addr = elf_loader.DEFAULT_OUTPUT_DATA,
        .value = 42,
        .clock = 5,
    }, result.output_words[1]);
    try std.testing.expect(result.rw_memory.segment_role.is_first);
    try std.testing.expect(result.rw_memory.segment_role.is_last);
    var output_role_count: usize = 0;
    for (result.rw_memory.words) |word| {
        if (word.role.is_public_output) output_role_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), output_role_count);
}

test "runner: runWithInput rejects an invalid instruction" {
    const instructions = [_]u32{0};
    const elf = makeTestElf(&instructions);
    try std.testing.expectError(
        error.InvalidInstruction,
        runWithInput(std.testing.allocator, &elf, &.{}, 1000),
    );
}

test "runner: strict completion rejects SYSTEM words before compatibility synthesis" {
    for ([_]u32{ 0x00000073, 0x00100073 }) |system_word| {
        const instructions = [_]u32{system_word};
        const elf = makeTestElf(&instructions);
        try std.testing.expectError(
            error.InvalidInstruction,
            runWithInput(std.testing.allocator, &elf, &.{}, 1000),
        );
    }
}

test "runner: runWithInput rejects max-step exhaustion" {
    const instructions = [_]u32{
        0x0010_0093, // ADDI x1, x0, 1
        0x0010_8093, // ADDI x1, x1, 1
    };
    const elf = makeTestElf(&instructions);
    try std.testing.expectError(
        error.MaxStepsExceeded,
        runWithInput(std.testing.allocator, &elf, &.{}, 1),
    );
}

test "runner: mem_addr and mem_val captured for load/store" {
    // Build a tiny ELF that executes:
    //   0x10000: ADDI x1, x0, 0x55   (0x05500093)  -- x1 = 0x55
    //   0x10004: ADDI x2, x0, 0x100  (0x10000113)  -- x2 = 0x100 (store addr)
    //   0x10008: SW   x1, 0(x2)      (0x00112023)  -- mem[0x100] = 0x55
    //   0x1000C: LW   x3, 0(x2)      (0x00012183)  -- x3 = mem[0x100] = 0x55
    //   0x10010: ECALL                (0x00000073)
    const n_insts = 5;
    const code_size = n_insts * 4;
    const elf_size = 84 + code_size;
    var elf_buf: [elf_size]u8 = [_]u8{0} ** elf_size;

    // ELF header
    elf_buf[0] = 0x7F;
    elf_buf[1] = 'E';
    elf_buf[2] = 'L';
    elf_buf[3] = 'F';
    elf_buf[4] = 1; // ELFCLASS32
    elf_buf[5] = 1; // ELFDATA2LSB
    elf_buf[6] = 1; // EI_VERSION
    elf_buf[16] = 2; // e_type = ET_EXEC
    elf_buf[18] = 0xF3; // e_machine = EM_RISCV
    elf_buf[20] = 1; // e_version
    // e_entry = 0x10000
    elf_buf[24] = 0x00;
    elf_buf[25] = 0x00;
    elf_buf[26] = 0x01;
    elf_buf[27] = 0x00;
    // e_phoff = 52
    elf_buf[28] = 52;
    // e_ehsize = 52
    elf_buf[40] = 52;
    // e_phentsize = 32
    elf_buf[42] = 32;
    // e_phnum = 1
    elf_buf[44] = 1;

    // Program header at offset 52
    elf_buf[52] = 1; // p_type = PT_LOAD
    elf_buf[56] = 84; // p_offset = 84
    // p_vaddr = 0x10000
    elf_buf[60] = 0x00;
    elf_buf[61] = 0x00;
    elf_buf[62] = 0x01;
    elf_buf[63] = 0x00;
    // p_filesz
    elf_buf[68] = code_size;
    // p_memsz
    elf_buf[72] = code_size;

    // Instructions at offset 84
    const instructions = [n_insts]u32{
        0x05500093, // ADDI x1, x0, 0x55
        0x10000113, // ADDI x2, x0, 0x100
        0x00112023, // SW x1, 0(x2)
        0x00012183, // LW x3, 0(x2)
        0x00000073, // ECALL
    };
    for (instructions, 0..) |inst_word, i| {
        const offset = 84 + i * 4;
        elf_buf[offset] = @truncate(inst_word);
        elf_buf[offset + 1] = @truncate(inst_word >> 8);
        elf_buf[offset + 2] = @truncate(inst_word >> 16);
        elf_buf[offset + 3] = @truncate(inst_word >> 24);
    }

    var result = try run(std.testing.allocator, &elf_buf, 1000);
    defer result.deinit();

    const rows = result.execution_trace.rows.items;
    try std.testing.expectEqual(@as(usize, 5), rows.len);

    // Row 0: ADDI - no memory access
    try std.testing.expectEqual(@as(u32, 0), rows[0].mem_addr);
    try std.testing.expectEqual(@as(u32, 0), rows[0].mem_val);
    try std.testing.expect(!rows[0].is_load);
    try std.testing.expect(!rows[0].is_store);

    // Row 2: SW x1, 0(x2) - store addr=0x100, val=0x55
    try std.testing.expect(rows[2].is_store);
    try std.testing.expectEqual(@as(u32, 0x100), rows[2].mem_addr);
    try std.testing.expectEqual(@as(u32, 0x55), rows[2].mem_val);
    try std.testing.expectEqual(@as(u32, 0), rows[2].mem_prev_word);
    try std.testing.expectEqual(@as(u32, 0x55), rows[2].mem_next_word);
    try std.testing.expectEqual(@as(u32, 0), rows[2].mem_prev_clk);

    // Row 3: LW x3, 0(x2) - load addr=0x100, val=0x55
    try std.testing.expect(rows[3].is_load);
    try std.testing.expectEqual(@as(u32, 0x100), rows[3].mem_addr);
    try std.testing.expectEqual(@as(u32, 0x55), rows[3].mem_val);
    try std.testing.expectEqual(@as(u32, 0x55), rows[3].mem_prev_word);
    try std.testing.expectEqual(@as(u32, 0x55), rows[3].mem_next_word);
    try std.testing.expectEqual(@as(u32, 3), rows[3].mem_prev_clk);

    // Verify final register state
    try std.testing.expectEqual(@as(u32, 0x55), result.cpu_final.readReg(3));
}

test "runner: runWithHost HALT syscall" {
    // ELF that does:
    //   ADDI a7, x0, 0    (set syscall number = HALT)
    //   ADDI a0, x0, 42   (set exit code = 42)
    //   ECALL              (trigger syscall)
    const instructions = [_]u32{
        // ADDI x17, x0, 0 (a7 = 0 = HALT)
        @as(u32, 0) << 20 | (0 << 15) | (0b000 << 12) | (17 << 7) | 0x13,
        // ADDI x10, x0, 42 (a0 = 42)
        @as(u32, 42) << 20 | (0 << 15) | (0b000 << 12) | (10 << 7) | 0x13,
        // ECALL
        0x00000073,
    };
    const elf = makeTestElf(&instructions);

    var rt = host_mod.HostRuntime.init(std.testing.allocator, &.{});
    defer rt.deinit();

    var result = try runWithHost(std.testing.allocator, &elf, 1000, rt.interface());
    defer result.deinit();

    try std.testing.expectEqual(@as(?u32, 42), result.exit_code);
    try std.testing.expectEqual(@as(usize, 3), result.step_count);
}

test "runner: runWithHost WRITE syscall" {
    // ELF that does:
    //   ADDI x10, x0, 'H'    store 'H' at 0x2000 via SW
    //   LUI  x11, 0x2000     x11 = 0x2000 (high bits)
    //   -- actually let's use a simpler approach: write a known byte
    //   ADDI a7, x0, 2    (WRITE syscall)
    //   ADDI a0, x0, 1    (fd = stdout)
    //   LUI  a1, 0x10     (buf_ptr = 0x10000, which has our ELF code bytes)
    //   ADDI a2, x0, 4    (len = 4)
    //   ECALL
    //   ADDI a7, x0, 0    (HALT)
    //   ADDI a0, x0, 0    (exit code 0)
    //   ECALL
    const instructions = [_]u32{
        // ADDI x17, x0, 2 (a7 = WRITE)
        @as(u32, 2) << 20 | (0 << 15) | (0b000 << 12) | (17 << 7) | 0x13,
        // ADDI x10, x0, 1 (a0 = fd=1 stdout)
        @as(u32, 1) << 20 | (0 << 15) | (0b000 << 12) | (10 << 7) | 0x13,
        // LUI x11, 0x10 (a1 = 0x10000 - point at code itself as data)
        (0x10 << 12) | (11 << 7) | 0x37,
        // ADDI x12, x0, 4 (a2 = 4 bytes)
        @as(u32, 4) << 20 | (0 << 15) | (0b000 << 12) | (12 << 7) | 0x13,
        // ECALL (WRITE)
        0x00000073,
        // ADDI x17, x0, 0 (a7 = HALT)
        @as(u32, 0) << 20 | (0 << 15) | (0b000 << 12) | (17 << 7) | 0x13,
        // ADDI x10, x0, 0 (a0 = exit code 0)
        @as(u32, 0) << 20 | (0 << 15) | (0b000 << 12) | (10 << 7) | 0x13,
        // ECALL (HALT)
        0x00000073,
    };
    const elf = makeTestElf(&instructions);

    var rt = host_mod.HostRuntime.init(std.testing.allocator, &.{});
    defer rt.deinit();

    var result = try runWithHost(std.testing.allocator, &elf, 1000, rt.interface());
    defer result.deinit();

    // Should have written 4 bytes from code area to journal.
    try std.testing.expectEqual(@as(usize, 4), rt.journalData().len);
    try std.testing.expectEqual(@as(?u32, 0), result.exit_code);
}

test "runner: runWithHost HINT_LEN and HINT_READ" {
    const hint_data = [_]u8{ 0xCA, 0xFE, 0xBA, 0xBE };
    const hints = [_][]const u8{&hint_data};

    const instructions = [_]u32{
        // HINT_LEN: a7=240
        @as(u32, 240) << 20 | (0 << 15) | (0b000 << 12) | (17 << 7) | 0x13,
        0x00000073, // ECALL — a0 gets hint length (4)

        // HINT_READ: a7=241, a0=0x20000, a1=4
        @as(u32, 241) << 20 | (0 << 15) | (0b000 << 12) | (17 << 7) | 0x13,
        // LUI x10, 0x20 (a0 = 0x20000)
        (0x20 << 12) | (10 << 7) | 0x37,
        // ADDI x11, x0, 4 (a1 = 4)
        @as(u32, 4) << 20 | (0 << 15) | (0b000 << 12) | (11 << 7) | 0x13,
        0x00000073, // ECALL (HINT_READ)

        // HALT: a7=0
        @as(u32, 0) << 20 | (0 << 15) | (0b000 << 12) | (17 << 7) | 0x13,
        @as(u32, 0) << 20 | (0 << 15) | (0b000 << 12) | (10 << 7) | 0x13,
        0x00000073, // ECALL (HALT)
    };
    const elf = makeTestElf(&instructions);

    var rt = host_mod.HostRuntime.init(std.testing.allocator, &hints);
    defer rt.deinit();

    var result = try runWithHost(std.testing.allocator, &elf, 1000, rt.interface());
    defer result.deinit();

    try std.testing.expectEqual(@as(?u32, 0), result.exit_code);
}

test "runner: runWithHost null host is backwards compatible" {
    // Same ELF as original ECALL test — should halt immediately on ECALL.
    const instructions = [_]u32{
        // ADDI x1, x0, 42
        @as(u32, 42) << 20 | (0 << 15) | (0b000 << 12) | (1 << 7) | 0x13,
        // ECALL
        0x00000073,
    };
    const elf = makeTestElf(&instructions);

    var result = try runWithHost(std.testing.allocator, &elf, 1000, null);
    defer result.deinit();

    try std.testing.expectEqual(@as(u32, 42), result.cpu_final.readReg(1));
    try std.testing.expectEqual(@as(usize, 2), result.step_count);
    try std.testing.expectEqual(@as(?u32, null), result.exit_code);
}

/// Helper: build a minimal ELF from instruction words.
fn makeTestElf(instructions: []const u32) [84 + 64]u8 {
    const max_insts = 16;
    const code_size = instructions.len * 4;
    _ = max_insts;
    var buf: [84 + 64]u8 = [_]u8{0} ** (84 + 64);

    // ELF header
    buf[0] = 0x7F;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = 1; // ELFCLASS32
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EI_VERSION
    buf[16] = 2; // ET_EXEC
    buf[18] = 0xF3; // EM_RISCV
    buf[20] = 1; // e_version
    // e_entry = 0x10000
    std.mem.writeInt(u32, buf[24..28], 0x10000, .little);
    buf[28] = 52; // e_phoff
    buf[40] = 52; // e_ehsize
    buf[42] = 32; // e_phentsize
    buf[44] = 1; // e_phnum

    // Program header
    buf[52] = 1; // PT_LOAD
    buf[56] = 84; // p_offset
    std.mem.writeInt(u32, buf[60..64], 0x10000, .little); // p_vaddr
    std.mem.writeInt(u32, buf[68..72], @intCast(code_size), .little); // p_filesz
    std.mem.writeInt(u32, buf[72..76], @intCast(code_size), .little); // p_memsz

    // Instructions
    for (instructions, 0..) |inst, i| {
        const off = 84 + i * 4;
        std.mem.writeInt(u32, buf[off..][0..4], inst, .little);
    }

    return buf;
}

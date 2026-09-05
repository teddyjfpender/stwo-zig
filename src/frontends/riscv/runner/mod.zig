//! RISC-V RV32IM runner — fetch/decode/execute loop with ELF loading.

const std = @import("std");
const execution_profile = @import("../isa/execution_profile.zig");
pub const ethereum = @import("ethereum.zig");
pub const cpu = @import("cpu.zig");
pub const decode = @import("decode.zig");
pub const memory = @import("memory.zig");
pub const execute_mod = @import("execute.zig");
pub const auipc_retirement = @import("auipc_retirement.zig");
pub const base_alu_imm_retirement = @import("base_alu_imm_retirement.zig");
pub const base_alu_reg_retirement = @import("base_alu_reg_retirement.zig");
pub const branch_eq_retirement = @import("branch_eq_retirement.zig");
pub const branch_lt_retirement = @import("branch_lt_retirement.zig");
pub const elf_loader = @import("elf_loader.zig");
pub const trace = @import("trace.zig");
pub const trace_dump = @import("trace_dump.zig");
pub const fence_retirement = @import("fence_retirement.zig");
pub const jal_retirement = @import("jal_retirement.zig");
pub const jalr_retirement = @import("jalr_retirement.zig");
pub const lt_imm_retirement = @import("lt_imm_retirement.zig");
pub const lt_reg_retirement = @import("lt_reg_retirement.zig");
pub const lui_retirement = @import("lui_retirement.zig");
pub const shifts_imm_retirement = @import("shifts_imm_retirement.zig");
pub const shifts_reg_retirement = @import("shifts_reg_retirement.zig");
pub const load_store_retirement = @import("load_store_retirement.zig");
pub const mul_retirement = @import("mul_retirement.zig");
pub const mulh_retirement = @import("mulh_retirement.zig");
pub const div_retirement = @import("div_retirement.zig");
/// Compile-time registry for production typed retirement authorities.
pub const generated_retirement = @import("generated_retirement.zig");
pub const guest_precompile = @import("guest_precompile/mod.zig");
/// Test-only bridge to the pinned Sail oracle; see `sail_oracle.zig`.
pub const sail_oracle = @import("sail_oracle.zig");
pub const state_chain = @import("state_chain.zig");
pub const memory_state = @import("memory_state.zig");
pub const minimal_trace = @import("minimal_trace/mod.zig");
pub const result_mod = @import("result.zig");
pub const segment_session = @import("segment_session.zig");
pub const host_mod = @import("../host/mod.zig");

pub const Cpu = cpu.Cpu;
pub const Memory = memory.Memory;
pub const DecodedInst = decode.DecodedInst;
pub const Opcode = decode.Opcode;
pub const HostInterface = host_mod.HostInterface;
pub const CompletionReason = result_mod.CompletionReason;
pub const OutputWord = result_mod.OutputWord;
pub const RunResult = result_mod.RunResult;
pub const Poseidon2RunResult = result_mod.Poseidon2RunResult;
pub const KeccakfRunResult = result_mod.KeccakfRunResult;
pub const EthereumRunResult = result_mod.EthereumRunResult;
pub const SegmentResult = result_mod.SegmentResult;
pub const Poseidon2SegmentResult = result_mod.Poseidon2SegmentResult;
pub const KeccakfSegmentResult = result_mod.KeccakfSegmentResult;
pub const EthereumSegmentResult = result_mod.EthereumSegmentResult;
pub const ContinuationToken = result_mod.ContinuationToken;
pub const SegmentClockFrame = result_mod.SegmentClockFrame;
pub const SessionOptions = segment_session.SessionOptions;
pub const TraceRetention = segment_session.TraceRetention;
pub const RetirementObserverV1 = segment_session.RetirementObserverV1;
pub const PreRetirementBoundaryV1 = segment_session.PreRetirementBoundaryV1;
pub const PreRetirementBoundaryObserverV1 =
    segment_session.PreRetirementBoundaryObserverV1;
pub const ExecutionSession = segment_session.ExecutionSession;
pub const BaseExecutionSession = ExecutionSession(.rv32im_zkvm_v1);
pub const Poseidon2ExecutionSession = ExecutionSession(.rv32im_zkvm_poseidon2_v1);
pub const KeccakfExecutionSession = ExecutionSession(.rv32im_zkvm_keccakf_v1);
pub const EthereumExecutionSession = ethereum.ExecutionSession;

const ExecutionProfile = execution_profile.ExecutionProfile;

fn ConfiguredResult(comptime profile: ExecutionProfile) type {
    return switch (profile) {
        .rv32im_zkvm_v1 => RunResult,
        .rv32im_zkvm_poseidon2_v1 => Poseidon2RunResult,
        .rv32im_zkvm_keccakf_v1 => KeccakfRunResult,
        .rv32im_zkvm_ethereum_v1 => EthereumRunResult,
    };
}

/// Run a RISC-V ELF program to completion (or until `max_steps`).
///
/// The program terminates when an ECALL instruction is encountered
/// or when `max_steps` is reached. This is the backwards-compatible
/// entry point — ECALL always halts.
pub fn run(allocator: std.mem.Allocator, elf_bytes: []const u8, max_steps: usize) !RunResult {
    return runWithHost(allocator, elf_bytes, max_steps, null);
}

/// Run an ELF using its linker-defined input buffer and halt flag (legacy-ABI compatible).
pub fn runWithInput(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    input: []const u8,
    max_steps: usize,
) !RunResult {
    return runConfigured(
        .rv32im_zkvm_v1,
        allocator,
        elf_bytes,
        max_steps,
        null,
        input,
        true,
        true,
    );
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
    return runConfigured(
        .rv32im_zkvm_v1,
        allocator,
        elf_bytes,
        max_steps,
        host,
        &.{},
        false,
        false,
    );
}

/// Explicit diagnostic execution entry for the admitted Poseidon2 profile.
/// Proof production remains unavailable until the extension statement lands.
pub fn runPoseidon2Extension(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    max_steps: usize,
) !Poseidon2RunResult {
    return runConfigured(
        .rv32im_zkvm_poseidon2_v1,
        allocator,
        elf_bytes,
        max_steps,
        null,
        &.{},
        false,
        false,
    );
}

/// Execute an admitted Poseidon2-profile ELF through `runWithInput`'s exact
/// linker-declared input, halt, and strict-completion contract. C-013's two
/// arms receive identical input while admission keeps CUSTOM-0 out of base RV32IM.
pub fn runPoseidon2ExtensionWithInput(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    input: []const u8,
    max_steps: usize,
) !Poseidon2RunResult {
    return runConfigured(
        .rv32im_zkvm_poseidon2_v1,
        allocator,
        elf_bytes,
        max_steps,
        null,
        input,
        true,
        true,
    );
}

/// Execute an explicitly admitted Keccak-f ELF. CUSTOM-0 retirement is kept
/// outside the base trace and retained in the typed Keccak call authority.
pub fn runKeccakfExtension(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    max_steps: usize,
) !KeccakfRunResult {
    return runConfigured(
        .rv32im_zkvm_keccakf_v1,
        allocator,
        elf_bytes,
        max_steps,
        null,
        &.{},
        false,
        false,
    );
}

/// Strict input/halt variant used by proof production and benchmarks.
pub fn runKeccakfExtensionWithInput(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    input: []const u8,
    max_steps: usize,
) !KeccakfRunResult {
    return runConfigured(
        .rv32im_zkvm_keccakf_v1,
        allocator,
        elf_bytes,
        max_steps,
        null,
        input,
        true,
        true,
    );
}

pub const runEthereumExtension = ethereum.run;
pub const runEthereumExtensionWithInput = ethereum.runWithInput;

fn runConfigured(
    comptime profile: ExecutionProfile,
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    max_steps: usize,
    host: ?HostInterface,
    input: []const u8,
    stop_on_halt_flag: bool,
    strict_completion: bool,
) !ConfiguredResult(profile) {
    var session = try ExecutionSession(profile).initLegacy(allocator, elf_bytes, .{
        .host = host,
        .input = input,
        .stop_on_halt_flag = stop_on_halt_flag,
        .strict_completion = strict_completion,
    });
    defer session.deinit();
    return session.runLegacy(max_steps);
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

test "runner: production LUI uses typed retirement transaction" {
    const instructions = [_]u32{
        0x1234_50b7, // LUI x1,  0x12345
        0xffff_f037, // LUI x0,  0xfffff (discarded)
        0x0000_0073, // ECALL
    };
    const elf = makeTestElf(&instructions);

    var result = try run(std.testing.allocator, &elf, 1000);
    defer result.deinit();

    try std.testing.expectEqual(@as(u32, 0x1234_5000), result.final_regs[1]);
    try std.testing.expectEqual(@as(u32, 0), result.final_regs[0]);
    try std.testing.expectEqual(@as(usize, instructions.len), result.step_count);
    try std.testing.expectEqual(@as(usize, instructions.len), result.execution_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 2), result.state_chain_tracker.accesses.items.len);
    try std.testing.expectEqual(Opcode.LUI, result.execution_trace.rows.items[0].opcode);
    try std.testing.expectEqual(@as(u32, 0x1234_5000), result.execution_trace.rows.items[0].rd_val);
    try std.testing.expectEqual(Opcode.LUI, result.execution_trace.rows.items[1].opcode);
    try std.testing.expectEqual(@as(u32, 0), result.execution_trace.rows.items[1].rd_val);
    try std.testing.expectEqual(CompletionReason.ecall, result.completion_reason);
}

test "runner: production FENCE uses typed empty-effect retirement transaction" {
    const fence_word = (@as(u32, 0xf53) << 20) |
        (@as(u32, 17) << 15) |
        (@as(u32, 31) << 7) |
        0b0001111;
    const instructions = [_]u32{
        0x1234_50b7, // LUI x1, 0x12345: establish a non-empty access chain.
        fence_word, // FENCE with non-zero reserved rd/rs1/immediate fields.
        0x0000_0073, // ECALL
    };
    const elf = makeTestElf(&instructions);

    var result = try run(std.testing.allocator, &elf, 1000);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, instructions.len), result.step_count);
    try std.testing.expectEqual(@as(usize, instructions.len), result.execution_trace.rows.items.len);
    // Only LUI owns a register transition; FENCE's reserved register fields do
    // not become architectural accesses.
    try std.testing.expectEqual(@as(usize, 1), result.state_chain_tracker.accesses.items.len);
    const row = result.execution_trace.rows.items[1];
    try std.testing.expectEqual(Opcode.FENCE, row.opcode);
    try std.testing.expectEqual(@as(u5, 31), row.rd);
    try std.testing.expectEqual(@as(u5, 17), row.rs1);
    try std.testing.expectEqual(@as(i32, -173), row.imm);
    try std.testing.expectEqual(row.rd_prev_val, row.rd_val);
    try std.testing.expectEqual(@as(u32, 0), row.rd_prev_clk);
    try std.testing.expectEqual(row.pc +% 4, row.next_pc);
    try std.testing.expect(!row.branch_taken);
    try std.testing.expectEqual(CompletionReason.ecall, result.completion_reason);
}

test "runner: production JAL uses typed retirement transaction" {
    const instructions = [_]u32{
        0x0080_00ef, // JAL x1, +8: skip the following instruction.
        0xffff_f137, // LUI x2, 0xfffff: unreachable.
        0x0040_006f, // JAL x0, +4: a retired fallthrough-equivalent jump.
        0x0000_0073, // ECALL
    };
    const elf = makeTestElf(&instructions);

    var result = try run(std.testing.allocator, &elf, 1000);
    defer result.deinit();

    try std.testing.expectEqual(@as(u32, 0x1_0004), result.final_regs[1]);
    try std.testing.expectEqual(@as(u32, 0), result.final_regs[0]);
    try std.testing.expectEqual(result.initial_regs[2], result.final_regs[2]);
    try std.testing.expectEqual(@as(usize, 3), result.step_count);
    try std.testing.expectEqual(@as(usize, 3), result.execution_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 2), result.state_chain_tracker.accesses.items.len);

    const linked = result.execution_trace.rows.items[0];
    try std.testing.expectEqual(Opcode.JAL, linked.opcode);
    try std.testing.expectEqual(@as(u5, 1), linked.rd);
    try std.testing.expectEqual(@as(u32, 0x1_0004), linked.rd_val);
    try std.testing.expectEqual(@as(u32, 0x1_0008), linked.next_pc);
    try std.testing.expect(linked.branch_taken);

    const discarded = result.execution_trace.rows.items[1];
    try std.testing.expectEqual(Opcode.JAL, discarded.opcode);
    try std.testing.expectEqual(@as(u5, 0), discarded.rd);
    try std.testing.expectEqual(@as(u32, 0), discarded.rd_val);
    try std.testing.expectEqual(@as(u32, 0x1_000c), discarded.next_pc);
    try std.testing.expect(!discarded.branch_taken);
    try std.testing.expectEqual(CompletionReason.ecall, result.completion_reason);
}

test "runner: production JALR uses typed retirement transaction" {
    const instructions = [_]u32{
        0x0000_0297, // AUIPC x5, 0: x5 = 0x10000.
        0x00c2_80e7, // JALR x1, x5, +12: target 0x1000c.
        0xffff_f137, // LUI x2, 0xfffff: unreachable.
        0x0102_8067, // JALR x0, x5, +16: retired fallthrough target.
        0x0000_0073, // ECALL
    };
    const elf = makeTestElf(&instructions);

    var result = try run(std.testing.allocator, &elf, 1000);
    defer result.deinit();

    try std.testing.expectEqual(@as(u32, 0x1_0008), result.final_regs[1]);
    try std.testing.expectEqual(@as(u32, 0), result.final_regs[0]);
    try std.testing.expectEqual(result.initial_regs[2], result.final_regs[2]);
    try std.testing.expectEqual(@as(usize, 4), result.step_count);
    try std.testing.expectEqual(@as(usize, 4), result.execution_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 5), result.state_chain_tracker.accesses.items.len);

    const linked = result.execution_trace.rows.items[1];
    try std.testing.expectEqual(Opcode.JALR, linked.opcode);
    try std.testing.expectEqual(@as(u5, 5), linked.rs1);
    try std.testing.expectEqual(@as(u32, 0x1_0000), linked.rs1_val);
    try std.testing.expectEqual(@as(u5, 1), linked.rd);
    try std.testing.expectEqual(@as(u32, 0x1_0008), linked.rd_val);
    try std.testing.expectEqual(@as(u32, 0x1_000c), linked.next_pc);
    try std.testing.expect(linked.branch_taken);

    const discarded = result.execution_trace.rows.items[2];
    try std.testing.expectEqual(Opcode.JALR, discarded.opcode);
    try std.testing.expectEqual(@as(u5, 0), discarded.rd);
    try std.testing.expectEqual(@as(u32, 0), discarded.rd_val);
    try std.testing.expectEqual(@as(u32, 0x1_0010), discarded.next_pc);
    try std.testing.expect(!discarded.branch_taken);
    try std.testing.expectEqual(CompletionReason.ecall, result.completion_reason);
}

test "runner: production BRANCH_EQ uses typed retirement transactions" {
    const instructions = [_]u32{
        0x0010_0093, // ADDI x1, x0, 1.
        0x0010_0113, // ADDI x2, x0, 1.
        0x0020_8463, // BEQ  x1, x2, +8: taken, skip the next instruction.
        0xffff_f1b7, // LUI  x3, 0xfffff: unreachable.
        0x0020_9263, // BNE  x1, x2, +4: not taken.
        0x0011_0113, // ADDI x2, x2, 1.
        0x0020_9463, // BNE  x1, x2, +8: taken, skip the next instruction.
        0xffff_f237, // LUI  x4, 0xfffff: unreachable.
        0x0010_8263, // BEQ  x1, x1, +4: taken but sequential next PC.
        0x0000_0073, // ECALL.
    };
    const elf = makeTestElf(&instructions);

    var result = try run(std.testing.allocator, &elf, 1000);
    defer result.deinit();

    try std.testing.expectEqual(@as(u32, 1), result.final_regs[1]);
    try std.testing.expectEqual(@as(u32, 2), result.final_regs[2]);
    try std.testing.expectEqual(result.initial_regs[3], result.final_regs[3]);
    try std.testing.expectEqual(@as(u32, 0), result.final_regs[4]);
    try std.testing.expectEqual(@as(usize, 8), result.step_count);
    try std.testing.expectEqual(@as(usize, 8), result.execution_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 14), result.state_chain_tracker.accesses.items.len);

    const branches = [_]struct {
        trace_index: usize,
        opcode: Opcode,
        pc: u32,
        next_pc: u32,
        branch_taken: bool,
        source_1: u32,
        source_2: u32,
    }{
        .{ .trace_index = 2, .opcode = .BEQ, .pc = 0x1_0008, .next_pc = 0x1_0010, .branch_taken = true, .source_1 = 1, .source_2 = 1 },
        .{ .trace_index = 3, .opcode = .BNE, .pc = 0x1_0010, .next_pc = 0x1_0014, .branch_taken = false, .source_1 = 1, .source_2 = 1 },
        .{ .trace_index = 5, .opcode = .BNE, .pc = 0x1_0018, .next_pc = 0x1_0020, .branch_taken = true, .source_1 = 1, .source_2 = 2 },
        .{ .trace_index = 6, .opcode = .BEQ, .pc = 0x1_0020, .next_pc = 0x1_0024, .branch_taken = false, .source_1 = 1, .source_2 = 1 },
    };
    for (branches) |expected| {
        const row = result.execution_trace.rows.items[expected.trace_index];
        try std.testing.expectEqual(expected.opcode, row.opcode);
        try std.testing.expectEqual(expected.pc, row.pc);
        try std.testing.expectEqual(expected.next_pc, row.next_pc);
        try std.testing.expectEqual(expected.branch_taken, row.branch_taken);
        try std.testing.expectEqual(expected.source_1, row.rs1_val);
        try std.testing.expectEqual(expected.source_2, row.rs2_val);
        try std.testing.expectEqual(row.rd_prev_val, row.rd_val);
    }
    try std.testing.expectEqual(CompletionReason.ecall, result.completion_reason);
}

test "runner: production BRANCH_LT uses typed retirement transactions" {
    const instructions = [_]u32{
        0x8000_02b7, // LUI   x5, 0x80000: signed minimum, unsigned high bit.
        0xfff0_0313, // ADDI  x6, x0, -1: signed -1, unsigned maximum.
        0x0062_c463, // BLT   x5, x6, +8: taken.
        0xffff_fa37, // LUI   x20, 0xfffff: unreachable.
        0x0053_4263, // BLT   x6, x5, +4: not taken.
        0x0062_e463, // BLTU  x5, x6, +8: taken.
        0xffff_fab7, // LUI   x21, 0xfffff: unreachable.
        0x0053_6263, // BLTU  x6, x5, +4: not taken.
        0x0053_5463, // BGE   x6, x5, +8: taken.
        0xffff_fb37, // LUI   x22, 0xfffff: unreachable.
        0x0062_d263, // BGE   x5, x6, +4: not taken.
        0x0053_7463, // BGEU  x6, x5, +8: taken.
        0xffff_fbb7, // LUI   x23, 0xfffff: unreachable.
        0x0062_f263, // BGEU  x5, x6, +4: not taken.
        0x0000_0073, // ECALL.
    };
    const elf = makeTestElf(&instructions);

    var result = try run(std.testing.allocator, &elf, 1000);
    defer result.deinit();

    try std.testing.expectEqual(@as(u32, 0x8000_0000), result.final_regs[5]);
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), result.final_regs[6]);
    inline for ([_]usize{ 20, 21, 22, 23 }) |register|
        try std.testing.expectEqual(
            result.initial_regs[register],
            result.final_regs[register],
        );
    try std.testing.expectEqual(@as(usize, 11), result.step_count);
    try std.testing.expectEqual(@as(usize, 11), result.execution_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 19), result.state_chain_tracker.accesses.items.len);

    const branches = [_]struct {
        trace_index: usize,
        opcode: Opcode,
        pc: u32,
        next_pc: u32,
        branch_taken: bool,
    }{
        .{ .trace_index = 2, .opcode = .BLT, .pc = 0x1_0008, .next_pc = 0x1_0010, .branch_taken = true },
        .{ .trace_index = 3, .opcode = .BLT, .pc = 0x1_0010, .next_pc = 0x1_0014, .branch_taken = false },
        .{ .trace_index = 4, .opcode = .BLTU, .pc = 0x1_0014, .next_pc = 0x1_001c, .branch_taken = true },
        .{ .trace_index = 5, .opcode = .BLTU, .pc = 0x1_001c, .next_pc = 0x1_0020, .branch_taken = false },
        .{ .trace_index = 6, .opcode = .BGE, .pc = 0x1_0020, .next_pc = 0x1_0028, .branch_taken = true },
        .{ .trace_index = 7, .opcode = .BGE, .pc = 0x1_0028, .next_pc = 0x1_002c, .branch_taken = false },
        .{ .trace_index = 8, .opcode = .BGEU, .pc = 0x1_002c, .next_pc = 0x1_0034, .branch_taken = true },
        .{ .trace_index = 9, .opcode = .BGEU, .pc = 0x1_0034, .next_pc = 0x1_0038, .branch_taken = false },
    };
    for (branches) |expected| {
        const row = result.execution_trace.rows.items[expected.trace_index];
        try std.testing.expectEqual(expected.opcode, row.opcode);
        try std.testing.expectEqual(expected.pc, row.pc);
        try std.testing.expectEqual(expected.next_pc, row.next_pc);
        try std.testing.expectEqual(expected.branch_taken, row.branch_taken);
        try std.testing.expectEqual(
            if (row.rs1 == 5) @as(u32, 0x8000_0000) else 0xffff_ffff,
            row.rs1_val,
        );
        try std.testing.expectEqual(
            if (row.rs2 == 5) @as(u32, 0x8000_0000) else 0xffff_ffff,
            row.rs2_val,
        );
        try std.testing.expectEqual(row.rd_prev_val, row.rd_val);
    }
    try std.testing.expectEqual(CompletionReason.ecall, result.completion_reason);
}

test "runner: production LT_IMM uses typed retirement transactions" {
    const instructions = [_]u32{
        0x8000_02b7, // LUI   x5, 0x80000: signed minimum, unsigned high bit.
        0x0002_a313, // SLTI  x6, x5, 0: true.
        0x0002_a013, // SLTI  x0, x5, 0: true result discarded.
        0x8002_a413, // SLTI  x8, x5, -2048: true.
        0x0000_2493, // SLTI  x9, x0, 0: false equality.
        0xfff2_b393, // SLTIU x7, x5, -1: true.
        0x0002_b513, // SLTIU x10, x5, 0: false.
        0xfff0_3593, // SLTIU x11, x0, -1: true.
        0x8002_a293, // SLTI  x5, x5, -2048: true with rd == rs1.
        0x0000_0073, // ECALL.
    };
    const elf = makeTestElf(&instructions);

    var result = try run(std.testing.allocator, &elf, 1000);
    defer result.deinit();

    try std.testing.expectEqual(@as(u32, 1), result.final_regs[5]);
    try std.testing.expectEqual(@as(u32, 1), result.final_regs[6]);
    try std.testing.expectEqual(@as(u32, 1), result.final_regs[7]);
    try std.testing.expectEqual(@as(u32, 1), result.final_regs[8]);
    try std.testing.expectEqual(@as(u32, 0), result.final_regs[9]);
    try std.testing.expectEqual(@as(u32, 0), result.final_regs[10]);
    try std.testing.expectEqual(@as(u32, 1), result.final_regs[11]);
    try std.testing.expectEqual(@as(u32, 0), result.final_regs[0]);
    try std.testing.expectEqual(@as(usize, instructions.len), result.step_count);
    try std.testing.expectEqual(
        @as(usize, instructions.len),
        result.execution_trace.rows.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 17),
        result.state_chain_tracker.accesses.items.len,
    );

    const expectations = [_]struct {
        opcode: Opcode,
        value: u32,
        rd: u5,
    }{
        .{ .opcode = .SLTI, .value = 1, .rd = 6 },
        .{ .opcode = .SLTI, .value = 0, .rd = 0 },
        .{ .opcode = .SLTI, .value = 1, .rd = 8 },
        .{ .opcode = .SLTI, .value = 0, .rd = 9 },
        .{ .opcode = .SLTIU, .value = 1, .rd = 7 },
        .{ .opcode = .SLTIU, .value = 0, .rd = 10 },
        .{ .opcode = .SLTIU, .value = 1, .rd = 11 },
        .{ .opcode = .SLTI, .value = 1, .rd = 5 },
    };
    for (expectations, 1..) |expected, trace_index| {
        const row = result.execution_trace.rows.items[trace_index];
        try std.testing.expectEqual(expected.opcode, row.opcode);
        try std.testing.expectEqual(expected.rd, row.rd);
        try std.testing.expectEqual(expected.value, row.rd_val);
        try std.testing.expectEqual(row.pc +% 4, row.next_pc);
        try std.testing.expect(!row.branch_taken);
    }
    try std.testing.expectEqual(CompletionReason.ecall, result.completion_reason);
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
        .clock = 11,
    }, result.output_words[0]);
    try std.testing.expectEqual(OutputWord{
        .addr = elf_loader.DEFAULT_OUTPUT_DATA,
        .value = 42,
        .clock = 19,
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
    try std.testing.expectEqual(@as(u32, 11), rows[3].mem_prev_clk);

    // Verify final register state
    try std.testing.expectEqual(@as(u32, 0x55), result.cpu_final.readReg(3));
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

test {
    _ = @import("segment_continuation_test.zig");
}

//! CPU integration tests for backend-neutral RISC-V proof orchestration.

const std = @import("std");
const riscv_cpu = @import("../../integrations/riscv_cpu/mod.zig");
const prover = @import("../../frontends/riscv/prover.zig");
const runner_mod = @import("../../frontends/riscv/runner/mod.zig");
const memory_state = @import("../../frontends/riscv/runner/memory_state.zig");
const trace_mod = @import("../../frontends/riscv/runner/trace.zig");
const pcs_core = @import("stwo_core").pcs;
const qm31 = @import("stwo_core").fields.qm31;

const CpuProverEngine = riscv_cpu.CpuProverEngine;
const Channel = CpuProverEngine.Channel;
const ProverError = prover.ProverError;
const QM31 = qm31.QM31;
const proveRiscV = riscv_cpu.proveRiscV;
const verifyRiscV = riscv_cpu.verifyRiscV;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "riscv prover: end-to-end ELF prove and verify" {
    const alloc = std.testing.allocator;

    // Build a guest that commits one public output word then self-halts.
    const n_insts = 6;
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
        0x001000B7, // LUI x1, 0x100 -- io RW region base
        0x00400113, // ADDI x2, x0, 4 -- output length
        0x0020A223, // SW x2, 4(x1)
        0x02A00193, // ADDI x3, x0, 42 -- output word
        0x0030A423, // SW x3, 8(x1)
        0x0000006F, // JAL x0, 0 -- runner stops before tracing the sentinel
    };
    for (instructions, 0..) |inst_word, i| {
        const offset = 84 + i * 4;
        elf_buf[offset] = @truncate(inst_word);
        elf_buf[offset + 1] = @truncate(inst_word >> 8);
        elf_buf[offset + 2] = @truncate(inst_word >> 16);
        elf_buf[offset + 3] = @truncate(inst_word >> 24);
    }

    // Step 1: Run the ELF
    var run_result = try runner_mod.run(alloc, &elf_buf, 1000);
    defer run_result.deinit();

    // Verify execution correctness
    try std.testing.expectEqual(@as(u32, 0x0010_0000), run_result.cpu_final.readReg(1));
    try std.testing.expectEqual(@as(u32, 4), run_result.output_len);
    try std.testing.expectEqualSlices(u8, &.{ 42, 0, 0, 0 }, run_result.output.?);

    // Step 2: Prove
    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = .{
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
        },
    };

    var owned_statement = try riscv_cpu.proveAndVerifyElf(alloc, &elf_buf, 1000, config);
    defer owned_statement.deinit(alloc);
    const statement = owned_statement.statement;
    try std.testing.expect(statement.n_components > 1);
    try std.testing.expectEqual(@as(u32, 4), statement.public_data.io_entries.output_len);
    try std.testing.expect(statement.public_data.io_entries.output_words.len >= 2);
    try std.testing.expectEqual(
        @as(u32, 42),
        statement.public_data.io_entries.output_words[1].value,
    );
}

test "riscv prover: prove, verify, and sample one runner trace against Sail" {
    const alloc = std.testing.allocator;
    const elf = runner_mod.trace_dump.buildTestElf(9, .{
        0x00100093, // ADDI x1, x0, 1
        0x00100093,
        0x00100093,
        0x00100093,
        0x00100093,
        0x00100093,
        0x00100093,
        0x00100093,
        0x0000006f, // JAL x0, 0: completion sentinel, not a retirement
    });
    var run = try runner_mod.run(alloc, &elf, 1000);
    defer run.deinit();
    try std.testing.expectEqual(@as(usize, 8), run.step_count);

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = .{
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
        },
    };

    const output = try proveRiscV(alloc, config, &run.execution_trace, null, null);
    defer output.deinitAfterProofMoved(alloc);

    try std.testing.expectEqual(@as(u32, 1), output.statement.n_components);
    try std.testing.expectEqual(
        trace_mod.OpcodeFamily.base_alu_imm,
        output.statement.component_descs[0].family,
    );
    try std.testing.expectEqual(@as(u32, 4), output.statement.component_descs[0].log_size);

    try verifyRiscV(alloc, config, output.statement, output.proof, output.interaction_claim);

    // This exact runner trace is the one just proven. Keep the sampled Sail
    // assertion last so a visibly absent oracle costs no proof assertion.
    try runner_mod.sail_oracle.requireAgreement(
        alloc,
        "CPU prover eight-ADDI runner guest",
        &elf,
        &run.execution_trace,
        run.cpu_final,
        &.{},
    );
}

fn singleAddTrace(allocator: std.mem.Allocator, result: u32) !trace_mod.Trace {
    var trace = trace_mod.Trace.init(allocator);
    errdefer trace.deinit();
    trace.initial_pc = 0x1000;
    trace.final_pc = 0x1004;
    try trace.append(.{
        .clk = 1,
        .pc = 0x1000,
        .opcode = .ADD,
        .rd = 3,
        .rs1 = 1,
        .rs2 = 2,
        .imm = 0,
        .rs1_val = 7,
        .rs2_val = 9,
        .rd_val = result,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004,
        .inst_word = 0x002081b3,
    });
    return trace;
}

test "riscv prover: base alu register semantics reject forged ADD" {
    const allocator = std.testing.allocator;

    var honest = try singleAddTrace(allocator, 16);
    defer honest.deinit();
    const output = try proveRiscV(allocator, TEST_PCS_CONFIG, &honest, null, null);
    defer output.deinitAfterProofMoved(allocator);
    try verifyRiscV(
        allocator,
        TEST_PCS_CONFIG,
        output.statement,
        output.proof,
        output.interaction_claim,
    );

    var forged = try singleAddTrace(allocator, 17);
    defer forged.deinit();
    try std.testing.expectError(
        error.InvalidSemanticWitness,
        proveRiscV(allocator, TEST_PCS_CONFIG, &forged, null, null),
    );
}

fn singleAddiTrace(allocator: std.mem.Allocator, result: u32) !trace_mod.Trace {
    var trace = trace_mod.Trace.init(allocator);
    errdefer trace.deinit();
    trace.initial_pc = 0x1000;
    trace.final_pc = 0x1004;
    try trace.append(.{
        .clk = 1,
        .pc = 0x1000,
        .opcode = .ADDI,
        .rd = 1,
        .rs1 = 0,
        .rs2 = 0,
        .imm = 1,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = result,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004,
        .inst_word = 0x00100093,
    });
    return trace;
}

test "riscv prover: base alu immediate semantics reject forged ADDI" {
    const allocator = std.testing.allocator;

    var honest = try singleAddiTrace(allocator, 1);
    defer honest.deinit();
    const output = try proveRiscV(allocator, TEST_PCS_CONFIG, &honest, null, null);
    defer output.deinitAfterProofMoved(allocator);
    try verifyRiscV(
        allocator,
        TEST_PCS_CONFIG,
        output.statement,
        output.proof,
        output.interaction_claim,
    );

    var forged = try singleAddiTrace(allocator, 2);
    defer forged.deinit();
    try std.testing.expectError(
        error.InvalidSemanticWitness,
        proveRiscV(allocator, TEST_PCS_CONFIG, &forged, null, null),
    );
}

test "riscv prover: multi-family splitting" {
    const alloc = std.testing.allocator;
    var exec_trace = trace_mod.Trace.init(alloc);
    defer exec_trace.deinit();

    exec_trace.initial_pc = 0x1000;

    for (0..4) |i| {
        try exec_trace.append(.{
            .clk = @intCast(i + 1),
            .pc = @intCast(0x1000 + i * 4),
            .opcode = .ADD,
            .rd = 1,
            .rs1 = 2,
            .rs2 = 3,
            .imm = 0,
            .rs1_val = 10,
            .rs2_val = 20,
            .rs1_prev_clk = @intCast(i),
            .rs2_prev_clk = @intCast(i),
            .rd_prev_val = if (i == 0) 0 else 30,
            .rd_prev_clk = @intCast(i),
            .rd_val = 30,
            .mem_addr = 0,
            .mem_val = 0,
            .is_load = false,
            .is_store = false,
            .branch_taken = false,
            .next_pc = @intCast(0x1000 + (i + 1) * 4),
            .inst_word = 0x003100b3,
        });
    }
    for (0..8) |i| {
        try exec_trace.append(.{
            .clk = @intCast(5 + i),
            .pc = @intCast(0x1010 + i * 4),
            .opcode = .ADDI,
            .rd = 4,
            .rs1 = 1,
            .rs2 = 0,
            .imm = 5,
            .rs1_val = 30,
            .rs2_val = 0,
            .rs1_prev_clk = @intCast(4 + i),
            .rd_prev_val = if (i == 0) 0 else 35,
            .rd_prev_clk = if (i == 0) 0 else @intCast(4 + i),
            .rd_val = 35,
            .mem_addr = 0,
            .mem_val = 0,
            .is_load = false,
            .is_store = false,
            .branch_taken = false,
            .next_pc = @intCast(0x1010 + (i + 1) * 4),
            .inst_word = 0x00508213,
        });
    }
    for (0..4) |i| {
        try exec_trace.append(.{
            .clk = @intCast(13 + i),
            .pc = @intCast(0x1030 + i * 4),
            .opcode = .BEQ,
            .rd = 0,
            .rs1 = 1,
            .rs2 = 2,
            .imm = 8,
            .rs1_val = 30,
            .rs2_val = 10,
            .rs1_prev_clk = @intCast(12 + i),
            .rs2_prev_clk = if (i == 0) 4 else @intCast(12 + i),
            .rd_val = 0,
            .mem_addr = 0,
            .mem_val = 0,
            .is_load = false,
            .is_store = false,
            .branch_taken = false,
            .next_pc = @intCast(0x1030 + (i + 1) * 4),
            .inst_word = 0x00208463,
        });
    }
    exec_trace.final_pc = 0x1040;

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = .{
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
        },
    };

    const output = try proveRiscV(alloc, config, &exec_trace, null, null);
    defer output.deinitAfterProofMoved(alloc);

    // Should have 3 components.
    try std.testing.expectEqual(@as(u32, 3), output.statement.n_components);

    // Verify families are in pinned transcript order.
    try std.testing.expectEqual(
        trace_mod.OpcodeFamily.base_alu_imm,
        output.statement.component_descs[0].family,
    );
    try std.testing.expectEqual(
        trace_mod.OpcodeFamily.base_alu_reg,
        output.statement.component_descs[1].family,
    );
    try std.testing.expectEqual(
        trace_mod.OpcodeFamily.branch_eq,
        output.statement.component_descs[2].family,
    );

    // Every small opcode family is padded to the minimum log-size 4 domain.
    try std.testing.expectEqual(@as(u32, 4), output.statement.component_descs[0].log_size);
    try std.testing.expectEqual(@as(u32, 4), output.statement.component_descs[1].log_size);
    try std.testing.expectEqual(@as(u32, 4), output.statement.component_descs[2].log_size);

    // Verify takes ownership of the proof.
    try verifyRiscV(alloc, config, output.statement, output.proof, output.interaction_claim);
}

test "riscv prover: ADDI + ADD + BNE split prove and verify" {
    const alloc = std.testing.allocator;
    var exec_trace = trace_mod.Trace.init(alloc);
    defer exec_trace.deinit();

    exec_trace.initial_pc = 0x1000;

    for (0..4) |i| {
        try exec_trace.append(.{
            .clk = @intCast(i + 1),
            .pc = @intCast(0x1000 + i * 4),
            .opcode = .ADDI,
            .rd = 1,
            .rs1 = 0,
            .rs2 = 0,
            .imm = @intCast(i + 1),
            .rs1_val = 0,
            .rs2_val = 0,
            .rs1_prev_clk = @intCast(i),
            .rd_prev_val = @intCast(i),
            .rd_prev_clk = @intCast(i),
            .rd_val = @intCast(i + 1),
            .mem_addr = 0,
            .mem_val = 0,
            .is_load = false,
            .is_store = false,
            .branch_taken = false,
            .next_pc = @intCast(0x1000 + (i + 1) * 4),
            .inst_word = (@as(u32, @intCast(i + 1)) << 20) | 0x00000093,
        });
    }
    // 2 ADD instructions
    for (0..2) |i| {
        const step = 4 + i;
        try exec_trace.append(.{
            .clk = @intCast(step + 1),
            .pc = @intCast(0x1000 + step * 4),
            .opcode = .ADD,
            .rd = 3,
            .rs1 = 1,
            .rs2 = 2,
            .imm = 0,
            .rs1_val = 4,
            .rs2_val = 20,
            .rs1_prev_clk = @intCast(4 + i),
            .rs2_prev_clk = if (i == 0) 0 else 5,
            .rd_prev_val = if (i == 0) 0 else 24,
            .rd_prev_clk = if (i == 0) 0 else 5,
            .rd_val = 24,
            .mem_addr = 0,
            .mem_val = 0,
            .is_load = false,
            .is_store = false,
            .branch_taken = false,
            .next_pc = @intCast(0x1000 + (step + 1) * 4),
            .inst_word = 0x002081b3,
        });
    }
    // 2 BNE instructions (branch_eq family). Taken branches jump +8, so each
    // row consumes the previous row's next_pc and the state chain telescopes.
    var branch_pc: u32 = 0x1000 + 6 * 4;
    for (0..2) |i| {
        const step = 6 + i;
        try exec_trace.append(.{
            .clk = @intCast(step + 1),
            .pc = branch_pc,
            .opcode = .BNE,
            .rd = 0,
            .rs1 = 1,
            .rs2 = 2,
            .imm = 8,
            .rs1_val = 4,
            .rs2_val = 20,
            .rs1_prev_clk = @intCast(6 + i),
            .rs2_prev_clk = @intCast(6 + i),
            .rd_val = 0,
            .mem_addr = 0,
            .mem_val = 0,
            .is_load = false,
            .is_store = false,
            .branch_taken = true,
            .next_pc = branch_pc + 8,
            .inst_word = 0x00209463,
        });
        branch_pc += 8;
    }
    exec_trace.final_pc = branch_pc;

    const config = pcs_core.PcsConfig{
        .pow_bits = 0,
        .fri_config = .{
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
        },
    };

    // Verify correct family grouping.
    const counts = try exec_trace.groupByOpcodeFamily(alloc);
    try std.testing.expectEqual(@as(usize, 4), counts.get(.base_alu_imm));
    try std.testing.expectEqual(@as(usize, 2), counts.get(.base_alu_reg));
    try std.testing.expectEqual(@as(usize, 2), counts.get(.branch_eq));
    try std.testing.expectEqual(@as(usize, 8), counts.total());

    // Prove with component splitting.
    const output = try proveRiscV(alloc, config, &exec_trace, null, null);
    defer output.deinitAfterProofMoved(alloc);

    // Verify statement: 3 components in pinned transcript order.
    try std.testing.expectEqual(@as(u32, 3), output.statement.n_components);
    try std.testing.expectEqual(@as(u32, 8), output.statement.total_steps);

    // Component 0: base_alu_imm (ADDI, 4 rows, padded to the minimum domain).
    try std.testing.expectEqual(trace_mod.OpcodeFamily.base_alu_imm, output.statement.component_descs[0].family);
    try std.testing.expectEqual(@as(u32, 4), output.statement.component_descs[0].log_size);

    // Component 1: base_alu_reg (ADD, 2 rows, padded to the minimum domain).
    try std.testing.expectEqual(trace_mod.OpcodeFamily.base_alu_reg, output.statement.component_descs[1].family);
    try std.testing.expectEqual(@as(u32, 4), output.statement.component_descs[1].log_size);

    // Component 2: branch_eq (BNE, 2 rows, padded to the minimum domain).
    try std.testing.expectEqual(trace_mod.OpcodeFamily.branch_eq, output.statement.component_descs[2].family);
    try std.testing.expectEqual(@as(u32, 4), output.statement.component_descs[2].log_size);

    // Verify the proof (takes ownership).
    try verifyRiscV(alloc, config, output.statement, output.proof, output.interaction_claim);
}

fn testAddiTrace(alloc: std.mem.Allocator, n: usize) !trace_mod.Trace {
    var exec_trace = trace_mod.Trace.init(alloc);
    errdefer exec_trace.deinit();
    exec_trace.initial_pc = 0x1000;
    for (0..n) |i| {
        try exec_trace.append(.{
            .clk = @intCast(i + 1),
            .pc = @intCast(0x1000 + i * 4),
            .opcode = .ADDI,
            .rd = 1,
            .rs1 = 0,
            .rs2 = 0,
            .imm = 1,
            .rs1_val = 0,
            .rs2_val = 0,
            .rs1_prev_clk = @intCast(i),
            .rd_prev_val = if (i == 0) 0 else 1,
            .rd_prev_clk = @intCast(i),
            .rd_val = 1,
            .mem_addr = 0,
            .mem_val = 0,
            .is_load = false,
            .is_store = false,
            .branch_taken = false,
            .next_pc = @intCast(0x1000 + (i + 1) * 4),
            .inst_word = 0x00100093,
        });
    }
    exec_trace.final_pc = @intCast(0x1000 + n * 4);
    return exec_trace;
}

const TEST_PCS_CONFIG = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
    },
};

test "riscv prover: tampered interaction claim is rejected" {
    const alloc = std.testing.allocator;
    var exec_trace = try testAddiTrace(alloc, 8);
    defer exec_trace.deinit();

    const output = try proveRiscV(alloc, TEST_PCS_CONFIG, &exec_trace, null, null);
    defer output.deinitAfterProofMoved(alloc);

    var tampered = output.interaction_claim.*;
    tampered.opcode_claims[0][0] = tampered.opcode_claims[0][0].add(QM31.one());

    // verifyRiscV consumes the proof on failure as well. Either the global
    // cancellation or the OODS check must reject; don't over-specify which.
    const result = verifyRiscV(alloc, TEST_PCS_CONFIG, output.statement, output.proof, &tampered);
    try std.testing.expect(std.meta.isError(result));
}

test "riscv prover: tampered interaction PoW is rejected before relation draws" {
    const alloc = std.testing.allocator;
    var exec_trace = try testAddiTrace(alloc, 8);
    defer exec_trace.deinit();

    const output = try proveRiscV(alloc, TEST_PCS_CONFIG, &exec_trace, null, null);
    defer output.deinitAfterProofMoved(alloc);
    var tampered = output.interaction_claim.*;
    tampered.interaction_pow +%= 1;
    try std.testing.expectError(
        error.InvalidInteractionProofOfWork,
        verifyRiscV(alloc, TEST_PCS_CONFIG, output.statement, output.proof, &tampered),
    );
}

test "riscv prover: opcode batch claims cannot cross-cancel" {
    const alloc = std.testing.allocator;
    var exec_trace = try testAddiTrace(alloc, 8);
    defer exec_trace.deinit();

    const output = try proveRiscV(alloc, TEST_PCS_CONFIG, &exec_trace, null, null);
    defer output.deinitAfterProofMoved(alloc);
    var tampered = output.interaction_claim.*;
    tampered.opcode_claims[0][0] = tampered.opcode_claims[0][0].add(QM31.one());
    tampered.opcode_claims[0][1] = tampered.opcode_claims[0][1].sub(QM31.one());
    try std.testing.expect(std.meta.isError(verifyRiscV(
        alloc,
        TEST_PCS_CONFIG,
        output.statement,
        output.proof,
        &tampered,
    )));
}

test "riscv prover: proof-chosen preprocessed selector root is rejected" {
    const alloc = std.testing.allocator;
    var exec_trace = try testAddiTrace(alloc, 8);
    defer exec_trace.deinit();

    var output = try proveRiscV(alloc, TEST_PCS_CONFIG, &exec_trace, null, null);
    defer output.deinitAfterProofMoved(alloc);
    output.proof.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    try std.testing.expectError(
        ProverError.InvalidPreprocessedCommitment,
        verifyRiscV(
            alloc,
            TEST_PCS_CONFIG,
            output.statement,
            output.proof,
            output.interaction_claim,
        ),
    );
}

test "riscv prover: missing program binder is rejected before PCS verification" {
    const alloc = std.testing.allocator;
    var exec_trace = try testAddiTrace(alloc, 4);
    defer exec_trace.deinit();

    const output = try proveRiscV(alloc, TEST_PCS_CONFIG, &exec_trace, null, null);
    defer output.deinitAfterProofMoved(alloc);
    var statement = output.statement;
    statement.n_infra = 0;
    try std.testing.expectError(
        ProverError.InvalidStatement,
        verifyRiscV(
            alloc,
            TEST_PCS_CONFIG,
            statement,
            output.proof,
            output.interaction_claim,
        ),
    );
}

test "riscv prover: tampered final_pc is rejected" {
    const alloc = std.testing.allocator;
    var exec_trace = try testAddiTrace(alloc, 8);
    defer exec_trace.deinit();

    const output = try proveRiscV(alloc, TEST_PCS_CONFIG, &exec_trace, null, null);
    defer output.deinitAfterProofMoved(alloc);

    var tampered_statement = output.statement;
    tampered_statement.final_pc += 4;

    const result = verifyRiscV(
        alloc,
        TEST_PCS_CONFIG,
        tampered_statement,
        output.proof,
        output.interaction_claim,
    );
    try std.testing.expect(std.meta.isError(result));
}

test "riscv prover: tampered RW-memory root presence is rejected" {
    const alloc = std.testing.allocator;
    var exec_trace = try testAddiTrace(alloc, 4);
    defer exec_trace.deinit();
    var words = [_]memory_state.WordState{.{
        .addr = 0x1000,
        .initial_word = 0x0403_0201,
        .final_word = 0x0807_0605,
        .final_clock = 4,
    }};
    const snapshot = memory_state.Snapshot{
        .layout = std.mem.zeroes(memory_state.MemoryLayout),
        .segment_role = memory_state.SegmentRole.single(),
        .words = &words,
    };
    const output = try proveRiscV(alloc, TEST_PCS_CONFIG, &exec_trace, null, &snapshot);
    defer output.deinitAfterProofMoved(alloc);
    try std.testing.expect(output.statement.public_data.initial_rw_root != null);
    try std.testing.expect(output.statement.public_data.final_rw_root != null);

    var statement = output.statement;
    statement.public_data.final_rw_root = null;
    try std.testing.expect(std.meta.isError(verifyRiscV(
        alloc,
        TEST_PCS_CONFIG,
        statement,
        output.proof,
        output.interaction_claim,
    )));
}

test "riscv prover: public register mutation changes the transcript" {
    const alloc = std.testing.allocator;
    var exec_trace = try testAddiTrace(alloc, 4);
    defer exec_trace.deinit();

    const output = try proveRiscV(alloc, TEST_PCS_CONFIG, &exec_trace, null, null);
    defer output.deinitAfterProofMoved(alloc);
    var statement = output.statement;
    statement.public_data.final_regs[1] = 99;
    try std.testing.expect(std.meta.isError(verifyRiscV(
        alloc,
        TEST_PCS_CONFIG,
        statement,
        output.proof,
        output.interaction_claim,
    )));
}

test "riscv prover: public clock mutation is rejected" {
    const alloc = std.testing.allocator;
    var exec_trace = try testAddiTrace(alloc, 4);
    defer exec_trace.deinit();

    const output = try proveRiscV(alloc, TEST_PCS_CONFIG, &exec_trace, null, null);
    defer output.deinitAfterProofMoved(alloc);
    var statement = output.statement;
    statement.public_data.clock +%= 1;
    try std.testing.expectError(error.InvalidStatement, verifyRiscV(
        alloc,
        TEST_PCS_CONFIG,
        statement,
        output.proof,
        output.interaction_claim,
    ));
}

test "riscv prover: exact program component exposes every paired claim" {
    const alloc = std.testing.allocator;
    var exec_trace = try testAddiTrace(alloc, 4);
    defer exec_trace.deinit();

    var output = try proveRiscV(alloc, TEST_PCS_CONFIG, &exec_trace, null, null);
    defer output.deinit(alloc);

    const claim = output.interaction_claim;
    try std.testing.expectEqual(output.statement.n_components, claim.n_components);
    try std.testing.expectEqual(output.statement.n_infra, claim.n_infra);
    var expected = QM31.zero();
    for (claim.program_claims[0]) |program_claim| {
        expected = expected.add(program_claim);
    }
    try std.testing.expect((try claim.infraClaimTotal(.program, 0)).eql(expected));
}

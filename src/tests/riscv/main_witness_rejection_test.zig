//! CP-06 production rejection of mutated committed witness cells.

const std = @import("std");
const pcs = @import("stwo_core").pcs;
const riscv_cpu = @import("stwo_riscv_cpu_integration");
const prover = @import("stwo_riscv_frontend").prover_mod;
const orchestration = @import("stwo_riscv_frontend").testing.prover_orchestration;
const witness_hook = @import("stwo_riscv_frontend").testing.witness_hook;
const public_data_mod = @import("stwo_riscv_frontend").air.public_data;
const memory_poseidon = @import("stwo_riscv_frontend").air.memory_commitment.poseidon2;
const runner = @import("stwo_riscv_frontend").runner;
const trace_mod = @import("stwo_riscv_frontend").runner.trace;
const release_elf_fixture = @import("release_elf_fixture.zig");
const strict_clock_fixture = @import("strict_clock_fixture.zig");

const Mutation = orchestration.TestWitnessMutation;

const RejectingStatementAdmission = struct {
    invocation_count: usize = 0,

    fn admit(context: *anyopaque, statement: *const prover.RiscVStatement) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.invocation_count += 1;
        // The callback must observe the production-derived statement, not a
        // caller-provided shadow. Requiring an active family makes an
        // accidentally early invocation fail for the fixture below.
        if (statement.n_components == 0) return error.EmptyAdmissionStatement;
        return error.StatementAdmissionRejected;
    }
};

const TEST_PCS_CONFIG = pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
    },
};

const ReleaseFixture = struct {
    allocator: std.mem.Allocator,
    elf: []u8,
    run: runner.RunResult,
    input_words: []u32,
    output_words: []public_data_mod.OutputWord,

    fn init(allocator: std.mem.Allocator) !ReleaseFixture {
        const elf = try release_elf_fixture.buildPublicIoHaltElf(allocator);
        errdefer allocator.free(elf);
        const input = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9 };
        var run = try runner.runWithInput(allocator, elf, &input, 1000);
        errdefer run.deinit();
        const input_words = try public_data_mod.packInputWords(allocator, &input);
        errdefer allocator.free(input_words);
        const output_words = try allocator.alloc(public_data_mod.OutputWord, run.output_words.len);
        errdefer allocator.free(output_words);
        for (run.output_words, output_words) |word, *output| output.* = .{
            .addr = word.addr,
            .value = word.value,
            .clock = word.clock,
        };
        return .{
            .allocator = allocator,
            .elf = elf,
            .run = run,
            .input_words = input_words,
            .output_words = output_words,
        };
    }

    fn deinit(self: *ReleaseFixture) void {
        self.allocator.free(self.output_words);
        self.allocator.free(self.input_words);
        self.run.deinit();
        self.allocator.free(self.elf);
        self.* = undefined;
    }

    fn publicData(self: *const ReleaseFixture) public_data_mod.PublicData {
        return .{
            .initial_pc = self.run.initial_pc,
            .final_pc = self.run.final_pc,
            .clock = @intCast(self.run.step_count),
            .initial_regs = self.run.initial_regs,
            .final_regs = self.run.final_regs,
            .reg_last_clock = self.run.state_chain_tracker.reg_last_clk,
            .program_root = null,
            .initial_rw_root = null,
            .final_rw_root = null,
            .completion = public_data_mod.completionFromRun(self.run) catch unreachable,
            .io_entries = .{
                .input_start = self.run.input_start,
                .input_len = @intCast(self.run.input.len),
                .input_words = self.input_words,
                .output_len = self.run.output_len,
                .output_len_addr = self.run.output_len_addr,
                .output_data_addr = self.run.output_data_addr,
                .output_words = self.output_words,
            },
        };
    }
};

fn expectCommittedMutationRejectedWithExecution(
    fixture: *const ReleaseFixture,
    mutation: Mutation,
    execution: orchestration.ExecutionOptions,
) !void {
    var channel = riscv_cpu.CpuProverEngine.Channel{};
    const output = orchestration.runRiscVWithEngineAndPublicDataUsingChannelAndExecution(
        riscv_cpu.CpuProverEngine,
        .prove,
        fixture.allocator,
        TEST_PCS_CONFIG,
        &fixture.run.execution_trace,
        &fixture.run.state_chain_tracker,
        &fixture.run.rw_memory,
        null,
        fixture.publicData(),
        &channel,
        mutation,
        null,
        execution,
    ) catch |err| {
        try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
        return;
    };
    defer output.deinitAfterProofMoved(fixture.allocator);
    try std.testing.expect(std.meta.isError(riscv_cpu.verifyRiscV(
        fixture.allocator,
        TEST_PCS_CONFIG,
        output.statement,
        output.proof,
        output.interaction_claim,
    )));
}

fn expectCommittedMutationRejected(fixture: *const ReleaseFixture, mutation: Mutation) !void {
    return expectCommittedMutationRejectedWithExecution(fixture, mutation, .{});
}

fn mainCell(target: witness_hook.Target, column: u32, row: u32) Mutation {
    return .{ .main = .{ .target = target, .column = column, .logical_row = row } };
}

fn interactionCell(target: witness_hook.Target, column: u32, row: u32) Mutation {
    return .{ .interaction = .{
        .target = target,
        .column = column,
        .logical_row = row,
    } };
}

fn preprocessedCell(
    target: witness_hook.Target,
    column: u32,
    row: u32,
) Mutation {
    return .{ .preprocessed = .{ .target = target, .column = column, .logical_row = row } };
}

test "riscv proving or verification rejects each committed witness mutation class" {
    var fixture = try ReleaseFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const cases = [_]struct { label: []const u8, mutation: Mutation }{
        .{ .label = "merkle leaf", .mutation = mainCell(.{ .infrastructure = .{ .kind = .merkle } }, 3, 0) },
        .{ .label = "merkle sibling", .mutation = mainCell(.{ .infrastructure = .{ .kind = .merkle } }, 4, 0) },
        .{ .label = "merkle index", .mutation = mainCell(.{ .infrastructure = .{ .kind = .merkle } }, 1, 0) },
        .{ .label = "merkle cur", .mutation = mainCell(.{ .infrastructure = .{ .kind = .merkle } }, 5, 0) },
        .{ .label = "poseidon input", .mutation = mainCell(.{ .infrastructure = .{ .kind = .poseidon2 } }, 1, 0) },
        .{ .label = "poseidon intermediate", .mutation = mainCell(.{ .infrastructure = .{ .kind = .poseidon2 } }, 17, 0) },
        .{ .label = "poseidon output", .mutation = mainCell(.{ .infrastructure = .{ .kind = .poseidon2 } }, 427, 0) },
        .{ .label = "memory value", .mutation = mainCell(.{ .infrastructure = .{ .kind = .memory } }, 2, 0) },
        .{ .label = "memory address", .mutation = mainCell(.{ .infrastructure = .{ .kind = .memory } }, 0, 0) },
        .{ .label = "memory clock", .mutation = mainCell(.{ .infrastructure = .{ .kind = .memory } }, 1, 0) },
        .{ .label = "lookup request", .mutation = mainCell(.{ .opcode = .{ .family = .lui } }, 14, 0) },
        .{ .label = "lookup table value", .mutation = preprocessedCell(.{ .infrastructure = .{ .kind = .range_check_8_8_4 } }, 1, 0) },
        .{ .label = "lookup table multiplicity", .mutation = mainCell(.{ .infrastructure = .{ .kind = .range_check_8_8_4 } }, 0, 0) },
        // Tree-2 cells are changed after the honest claim exists. Row zero
        // exercises the recurrence anchor; row one exercises its cross-row
        // transition under the exact compiler-owned interaction mask.
        .{ .label = "interaction anchor", .mutation = interactionCell(.{ .opcode = .{ .family = .lui } }, 0, 0) },
        .{ .label = "interaction cross-row recurrence", .mutation = interactionCell(.{ .opcode = .{ .family = .lui } }, 0, 1) },
    };

    for (cases) |case| {
        expectCommittedMutationRejected(&fixture, case.mutation) catch |err| {
            std.debug.print("mutated {s} did not reject correctly: {s}\n", .{ case.label, @errorName(err) });
            return err;
        };
    }
}

test "bounded Tree-2 executor rejects anchor and cross-row interaction forgeries" {
    var fixture = try ReleaseFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const target: witness_hook.Target = .{ .opcode = .{ .family = .lui } };

    for ([_]usize{ 1, 2, 4 }) |worker_count| {
        try expectCommittedMutationRejectedWithExecution(
            &fixture,
            interactionCell(target, 0, 1),
            .{ .cpu = .{
                .worker_count = worker_count,
                .host_byte_budget = std.math.maxInt(usize),
                .contention_policy = .strict,
            } },
        );
    }
    try expectCommittedMutationRejectedWithExecution(
        &fixture,
        interactionCell(target, 0, 0),
        .{ .cpu = .{
            .worker_count = 4,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .strict,
        } },
    );
}

test "statement admission rejects before transcript binding or Tree 0 commitment" {
    var fixture = try ReleaseFixture.init(std.testing.allocator);
    defer fixture.deinit();

    var channel = riscv_cpu.CpuProverEngine.Channel{};
    const pristine_digest = channel.digestBytes();
    const pristine_draw_count = channel.n_draws;
    var admission_probe: RejectingStatementAdmission = .{};

    const result = orchestration.runRiscVWithEngineAndPublicDataUsingChannelAndExecution(
        riscv_cpu.CpuProverEngine,
        .prove,
        fixture.allocator,
        TEST_PCS_CONFIG,
        &fixture.run.execution_trace,
        &fixture.run.state_chain_tracker,
        &fixture.run.rw_memory,
        null,
        fixture.publicData(),
        &channel,
        null,
        null,
        .{ .statement_admission = .{
            .context = &admission_probe,
            .admit_fn = RejectingStatementAdmission.admit,
        } },
    );
    if (result) |unexpected| {
        var output = unexpected;
        defer output.deinit(fixture.allocator);
        return error.ExpectedStatementAdmissionRejection;
    } else |err| {
        try std.testing.expectEqual(error.StatementAdmissionRejected, err);
    }

    try std.testing.expectEqual(@as(usize, 1), admission_probe.invocation_count);
    try std.testing.expectEqual(pristine_draw_count, channel.n_draws);
    try std.testing.expectEqualSlices(u8, pristine_digest[0..], channel.digestBytes()[0..]);
}

test "riscv verifier distinguishes absent RW root from present default root" {
    var trace = try testAddiTrace(std.testing.allocator, 4);
    defer trace.deinit();
    const output = try riscv_cpu.proveRiscV(std.testing.allocator, TEST_PCS_CONFIG, &trace, null, null);
    defer output.deinitAfterProofMoved(std.testing.allocator);
    try std.testing.expect(output.statement.public_data.initial_rw_root == null);

    var statement = output.statement;
    statement.public_data.initial_rw_root = memory_poseidon.DEFAULT_HASHES[0];
    try std.testing.expect(std.meta.isError(riscv_cpu.verifyRiscV(
        std.testing.allocator,
        TEST_PCS_CONFIG,
        statement,
        output.proof,
        output.interaction_claim,
    )));
}

fn testAddiTrace(allocator: std.mem.Allocator, n: usize) !trace_mod.Trace {
    var trace = trace_mod.Trace.init(allocator);
    errdefer trace.deinit();
    trace.initial_pc = 0x1000;
    for (0..n) |i| try trace.append(.{
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
    strict_clock_fixture.assignRegisterClocks(trace.rows.items);
    trace.final_pc = @intCast(0x1000 + n * 4);
    return trace;
}

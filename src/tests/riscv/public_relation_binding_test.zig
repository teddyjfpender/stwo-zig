//! Algebraic public-statement binding over retained production commitments.

const std = @import("std");
const riscv_cpu = @import("../../integrations/riscv_cpu/mod.zig");
const public_data_mod = @import("../../frontends/riscv/air/public_data.zig");
const relation_export = @import("../../frontends/riscv/air/relation_export.zig");
const memory_boundary = @import("../../frontends/riscv/air/memory_commitment/boundary.zig");
const runner = @import("../../frontends/riscv/runner/mod.zig");
const pcs = @import("stwo_core").pcs;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const release_elf_fixture = @import("release_elf_fixture.zig");

const PublicData = public_data_mod.PublicData;
const RelationDiagnostic = @import("../../frontends/riscv/prover.zig").RelationDiagnostic;

const TEST_PCS_CONFIG = pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
    },
};

fn diagnose(
    allocator: std.mem.Allocator,
    run: *const runner.RunResult,
    public_data: PublicData,
) !RelationDiagnostic {
    return riscv_cpu.diagnoseRiscVRelations(
        allocator,
        TEST_PCS_CONFIG,
        &run.execution_trace,
        &run.state_chain_tracker,
        &run.rw_memory,
        public_data,
    );
}

fn expectOnlyDomainOpen(
    allocator: std.mem.Allocator,
    run: *const runner.RunResult,
    baseline: *const RelationDiagnostic,
    public_data: PublicData,
    open_domain: relation_export.Domain,
) !void {
    const mutated = try diagnose(allocator, run, public_data);

    // Tree 0 and Tree 1 are commitments to the same preprocessed and main
    // buffers. Only the public compensation and transcript-derived challenges
    // differ in this diagnostic run.
    try std.testing.expectEqualSlices(
        u8,
        &baseline.bundle.claims.preprocessed_tree,
        &mutated.bundle.claims.preprocessed_tree,
    );
    try std.testing.expectEqualSlices(
        u8,
        &baseline.bundle.claims.main_tree,
        &mutated.bundle.claims.main_tree,
    );
    try std.testing.expectError(error.UnbalancedRelationDomain, mutated.bundle.validate());

    for (0..relation_export.DOMAIN_COUNT) |domain_index| {
        const residue = mutated.bundle.aggregate.domain_sums[domain_index]
            .add(mutated.bundle.public.domains[domain_index]);
        if (domain_index == @intFromEnum(open_domain)) {
            try std.testing.expect(!residue.isZero());
        } else {
            try std.testing.expect(residue.isZero());
        }
    }
}

test "riscv public statement: nonempty input proves and binds every public class" {
    const allocator = std.testing.allocator;
    const elf = try release_elf_fixture.buildPublicIoHaltElf(allocator);
    defer allocator.free(elf);

    const input = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    var run = try runner.runWithInput(allocator, elf, &input, 1000);
    defer run.deinit();
    try std.testing.expectEqual(runner.CompletionReason.halt_flag, run.completion_reason);
    try std.testing.expectEqualSlices(u8, input[0..4], run.output.?);

    const input_words = try public_data_mod.packInputWords(allocator, run.input);
    defer allocator.free(input_words);
    const output_words = try allocator.alloc(public_data_mod.OutputWord, run.output_words.len);
    defer allocator.free(output_words);
    for (run.output_words, output_words) |source, *destination| {
        destination.* = .{ .addr = source.addr, .value = source.value, .clock = source.clock };
    }

    const public_data = PublicData{
        .initial_pc = run.initial_pc,
        .final_pc = run.final_pc,
        .clock = @intCast(run.step_count),
        .initial_regs = run.initial_regs,
        .final_regs = run.final_regs,
        .reg_last_clock = run.state_chain_tracker.reg_last_clk,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = try public_data_mod.completionFromRun(run),
        .io_entries = .{
            .input_start = run.input_start,
            .input_len = @intCast(run.input.len),
            .input_words = input_words,
            .output_len = run.output_len,
            .output_len_addr = run.output_len_addr,
            .output_data_addr = run.output_data_addr,
            .output_words = output_words,
        },
    };

    const baseline = try diagnose(allocator, &run, public_data);
    try baseline.bundle.validate();

    // CP-11 compares these prefixes after every canonical Stark-V component.
    // Keep the non-empty input path explicit: its public memory term must be
    // nonzero and independently compensated by committed execution tuples.
    var prefix = QM31.zero();
    for (baseline.bundle.claims.claims, baseline.bundle.claims.prefixes) |claim, observed| {
        prefix = prefix.add(claim);
        try std.testing.expect(prefix.eql(observed));
    }
    try std.testing.expect(prefix.eql(baseline.bundle.claims.total));
    const memory_domain = @intFromEnum(relation_export.Domain.memory_access);
    try std.testing.expect(!baseline.bundle.public.domains[memory_domain].isZero());
    try std.testing.expect(
        baseline.bundle.aggregate.domain_sums[memory_domain]
            .add(baseline.bundle.public.domains[memory_domain])
            .isZero(),
    );

    // The same nine-byte statement, including its partial final input word,
    // must pass the production proof path rather than only the diagnostic.
    const proof = try riscv_cpu.proveRiscVWithPublicData(
        allocator,
        TEST_PCS_CONFIG,
        &run.execution_trace,
        &run.state_chain_tracker,
        &run.rw_memory,
        null,
        public_data,
    );
    defer proof.deinitAfterProofMoved(allocator);
    try riscv_cpu.verifyRiscV(
        allocator,
        TEST_PCS_CONFIG,
        proof.statement,
        proof.proof,
        proof.interaction_claim,
    );

    // A CPU boundary substitution is rejected before any commitment can be
    // made because it disagrees with the execution trace endpoint.
    var mutated = public_data;
    mutated.final_pc +%= 4;
    try std.testing.expectError(error.InvalidStatement, diagnose(allocator, &run, mutated));

    mutated = public_data;
    mutated.initial_regs[3] +%= 1;
    try expectOnlyDomainOpen(
        allocator,
        &run,
        &baseline,
        mutated,
        .memory_access,
    );

    mutated = public_data;
    mutated.final_regs[3] +%= 1;
    try expectOnlyDomainOpen(
        allocator,
        &run,
        &baseline,
        mutated,
        .memory_access,
    );

    input_words[0] +%= 1;
    try expectOnlyDomainOpen(
        allocator,
        &run,
        &baseline,
        public_data,
        .memory_access,
    );
    input_words[0] -%= 1;

    // Preserve the length word's structural invariant and mutate one output
    // data word, which reaches the memory-access compensation unchanged.
    try std.testing.expect(output_words.len >= 2);
    output_words[1].value +%= 1;
    try expectOnlyDomainOpen(
        allocator,
        &run,
        &baseline,
        public_data,
        .memory_access,
    );
    output_words[1].value -%= 1;

    // Supplying a concrete root asserts equality with the root derived from
    // the fixed memory snapshot. A different root fails at production
    // precommit, before transcript binding could mask the mismatch.
    var boundary = try memory_boundary.build(allocator, run.rw_memory.words);
    defer boundary.deinit(allocator);
    const initial_root = boundary.initial_tree orelse return error.MissingInitialTree;
    mutated = public_data;
    mutated.initial_rw_root = initial_root.root ^ 1;
    try std.testing.expectError(error.InvalidStatement, diagnose(allocator, &run, mutated));
}

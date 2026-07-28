//! Convenience ELF execution, proof, and verification transaction.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const public_data_mod = @import("../air/public_data.zig");
const runner_mod = @import("../runner/mod.zig");
const orchestration = @import("orchestration.zig");
const types = @import("types.zig");
const verifier = @import("verifier.zig");

/// Run a RISC-V ELF, prove execution, and verify the proof.
/// Verification consumes the proof; the returned public-I/O slices are owned.
pub fn proveAndVerifyElfWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    max_steps: usize,
    pcs_config: pcs_core.PcsConfig,
) !types.OwnedRiscVStatement {
    var run_result = try runner_mod.run(allocator, elf_bytes, max_steps);
    defer run_result.deinit();

    const input_words = try public_data_mod.packInputWords(allocator, run_result.input);
    errdefer allocator.free(input_words);
    const output_words = try allocator.alloc(public_data_mod.OutputWord, run_result.output_words.len);
    errdefer allocator.free(output_words);
    for (run_result.output_words, 0..) |word, i| output_words[i] = .{
        .addr = word.addr,
        .value = word.value,
        .clock = word.clock,
    };
    const public_data = types.PublicData{
        .initial_pc = run_result.initial_pc,
        .final_pc = run_result.final_pc,
        .clock = @intCast(run_result.step_count),
        .initial_regs = run_result.initial_regs,
        .final_regs = run_result.final_regs,
        .reg_last_clock = run_result.state_chain_tracker.reg_last_clk,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = try public_data_mod.completionFromRun(run_result),
        .io_entries = .{
            .input_start = run_result.input_start,
            .input_len = @intCast(run_result.input.len),
            .input_words = input_words,
            .output_len = run_result.output_len,
            .output_len_addr = run_result.output_len_addr,
            .output_data_addr = run_result.output_data_addr,
            .output_words = output_words,
        },
    };
    const output = try orchestration.runRiscVWithEngineAndPublicData(
        Engine,
        .prove,
        allocator,
        pcs_config,
        &run_result.execution_trace,
        &run_result.state_chain_tracker,
        &run_result.rw_memory,
        null,
        public_data,
    );
    defer output.deinitAfterProofMoved(allocator);

    try verifier.verifyRiscVWithEngine(
        Engine,
        allocator,
        pcs_config,
        output.statement,
        output.proof,
        output.interaction_claim,
    );

    return types.OwnedRiscVStatement.init(output.statement, input_words, output_words);
}

const std = @import("std");
const core = @import("stwo_core");
const public = @import("../air/public_data.zig");
const execution = @import("blake3_execution_trace.zig");

test "BLAKE3 execution commitment real runner proves and independently verifies" {
    checkExecution() catch |err| {
        std.debug.print("BLAKE3 execution join: {s}\n", .{@errorName(err)});
        return err;
    };
}
fn checkExecution() !void {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x00708093, 0x00100137, 0x00100193, 0x00312223, 0x00312423, 0x0000006f }; // x1=12; publish one output byte with value 1; self-loop
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var run = try @import("../runner/mod.zig").runWithInput(a, &elf, &.{}, 100);
    defer run.deinit();
    try std.testing.expectEqual(@as(u32, 12), run.final_regs[1]);
    try std.testing.expectEqual(@as(usize, 6), run.step_count);
    try std.testing.expectEqualSlices(u8, &.{1}, run.output.?);
    const outputs = try a.alloc(public.OutputWord, run.output_words.len);
    defer a.free(outputs);
    for (outputs, run.output_words) |*target, source| target.* = .{ .addr = source.addr, .value = source.value, .clock = source.clock };
    var data = public.Blake3PublicData{
        .initial_pc = run.initial_pc,
        .final_pc = run.final_pc,
        .clock = @intCast(run.step_count),
        .initial_regs = run.initial_regs,
        .final_regs = run.final_regs,
        .reg_last_clock = run.state_chain_tracker.reg_last_clk,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = try public.completionFromRun(run),
        .io_entries = .{ .input_start = run.input_start, .input_len = 0, .input_words = &.{}, .output_len = 1, .output_len_addr = run.output_len_addr, .output_data_addr = run.output_data_addr, .output_words = outputs },
    };
    var memory = try @import("blake3_commitment_witness.zig").build(a, @as(@import("../air/program/commitment.zig").DeclaredDecodeAuthority, .base), .{run.execution_trace.rows.items}, &run.rw_memory, @import("commitment_program_witness.zig").completionFetch(data.completion), 100);
    defer memory.deinit();
    try memory.bindPublic(&data);
    var plan = try memory.plan(a);
    defer plan.deinit();
    const admission = try @import("blake3_commitment_plan.zig").Admission.init(&plan, try plan.identity());
    const hashes = try @import("blake3_commitment_columns.zig").Owner.init(a, admission);
    defer hashes.deinit();
    try hashes.prepareMain(&memory);
    const native = try execution.Owner.init(a, &run.execution_trace, data, &run.state_chain_tracker);
    defer native.deinit();
    try native.includeCommitments(hashes);
    const saved = native.statement.component_descs[0];
    native.statement.component_descs[0].n_columns += 1;
    try std.testing.expectError(error.InvalidStatement, native.statement.validateBlake3Execution());
    native.statement.component_descs[0] = saved;
    native.statement.component_descs[0].n_rows -= 1;
    try std.testing.expectError(error.InvalidStatement, native.statement.validateBlake3Execution());
    native.statement.component_descs[0] = saved;
    const last = native.statement.n_infra - 1;
    const saved_table = native.statement.infra_descs[last];
    native.statement.infra_descs[last].n_rows -= 1;
    try std.testing.expectError(error.InvalidStatement, native.statement.validateBlake3Execution());
    native.statement.infra_descs[last] = saved_table;
    const proof_api = @import("blake3_execution_proof.zig");
    const api = proof_api.ForBackend(@import("stwo_cpu_backend").CpuBackend);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var result = try api.prove(a, native, hashes, admission, config);
    var owns_proof = true;
    defer if (owns_proof) result.proof.deinit(a);
    var substituted = result.proof.stark.commitment_scheme_proof.commitments.items[0];
    substituted[31] ^= 0x80;
    try std.testing.expectError(error.UntrustedBlake3Preprocessing, proof_api.admitPreprocessedRoot(result.proof.stark.commitment_scheme_proof.commitments.items[0], substituted));
    try std.testing.expect(native.interaction_ready);
    try std.testing.expectError(error.LookupTablesAlreadyPrepared, native.includeCommitments(hashes));
    try std.testing.expectError(error.InvalidExecutionPhase, api.prove(a, native, hashes, admission, config));
    const prepared = try api.PreparedVerifier.init(a, &native.statement, admission, config);
    defer prepared.deinit();
    const expected_id = prepared.id; // Derived from verifier-owned source inputs.
    try std.testing.expectEqualSlices(u8, &expected_id, &result.proof.key_id);
    try std.testing.expectEqual(@as(usize, 0), prepared.hashes.?.columns[0].items.len);
    try std.testing.expectEqual(@as(usize, 0), prepared.hashes.?.columns[1].items.len);
    const raw = try @import("blake3_execution_codec.zig").encode(a, &result.proof, prepared, expected_id);
    defer a.free(raw);
    result.proof.deinit(a);
    owns_proof = false;
    // Retained admission owns the source slices; later caller mutation cannot
    // silently select another statement or commitment schedule.
    outputs[0].value = 123;
    plan.programs[0].multiplicity += 1;
    try prepared.validate(expected_id);
    outputs[0].value = 1;
    plan.programs[0].multiplicity -= 1;
    try @import("blake3_execution_artifact_test_support.zig").check(api, a, prepared, expected_id, raw, result.transcript_digest, &memory);
}

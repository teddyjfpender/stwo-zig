//! Exercise the conversion through a real runner snapshot and commitment owner.
const std = @import("std");
const public = @import("stwo_riscv_rv32").modules.air_public_data;
const source = @import("stwo_riscv_rv32").modules.recursion_air_blake3_memory_snapshot;
test "BLAKE3 memory update proves runner snapshot conversion agrees with full roots" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x00708093, 0x00100137, 0x00012223, 0x0000006f };
    var elf = @import("stwo_riscv_rv32").modules.runner_guest_precompile_test_elf.buildProgram(instructions.len, &instructions, 4, .rv32im_zkvm_v1);
    declareInput(&elf);
    var run = try @import("stwo_riscv_frontend").modules.runner_mod.runWithInput(a, &elf, &.{ 1, 2, 3, 255 }, 100);
    defer run.deinit();
    const outputs = try a.alloc(public.OutputWord, run.output_words.len);
    defer a.free(outputs);
    for (outputs, run.output_words) |*target, word| target.* = .{ .addr = word.addr, .value = word.value, .clock = word.clock };
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
        .io_entries = .{ .input_start = run.input_start, .input_len = 4, .input_words = &.{0xff030201}, .output_len = 0, .output_len_addr = run.output_len_addr, .output_data_addr = run.output_data_addr, .output_words = outputs },
    };
    var memory = try @import("stwo_riscv_rv32").modules.prover_blake3_commitment_witness.build(a, @as(@import("stwo_riscv_rv32").modules.air_program_commitment.DeclaredDecodeAuthority, .base), .{run.execution_trace.rows.items}, &run.rw_memory, @import("stwo_riscv_rv32").modules.prover_commitment_program_witness.completionFetch(data.completion), 100);
    defer memory.deinit();
    try memory.bindPublic(&data);
    var plan = try memory.plan(a);
    defer plan.deinit();
    const admission = try @import("stwo_riscv_rv32").modules.prover_blake3_commitment_plan.Admission.init(&plan, try plan.identity());
    for ([_]source.Side{ .entry, .exit }) |side| {
        var full = try source.fromSnapshot(a, &run.rw_memory, side, .continuation);
        defer full.deinit();
        var conversion = try memory.prepareContinuation(a, side, &data, admission, full.root, 100000, 99999);
        defer conversion.deinit();
        try @import("stwo_riscv_rv32").modules.recursion_air_blake3_memory_custody.admit(&conversion.plan, side, &data, admission, a);
        try std.testing.expectEqualDeep(full.root, conversion.plan.roots[conversion.plan.roots.len - 1]);
        var wrong = full.root;
        wrong.bytes[31] ^= 0x80;
        try std.testing.expectError(error.UntrustedMemoryUpdateChain, memory.prepareContinuation(a, side, &data, admission, wrong, 100000, 99999));
        var untrusted = admission;
        untrusted.expected_id[0] ^= 1;
        try std.testing.expectError(error.UntrustedCommitmentPlan, memory.prepareContinuation(a, side, &data, untrusted, full.root, 100000, 99999));
    }
}

// Extend the shared tiny ELF's symbol table into its two reserved symbol slots.
fn declareInput(elf: []u8) void {
    const names = "\x00__text_start\x00__text_len\x00__input_start\x00__input_end\x00";
    @memcpy(elf[480..][0..names.len], names);
    std.mem.writeInt(u32, elf[308..312], names.len, .little);
    std.mem.writeInt(u32, elf[268..272], 5 * 16, .little);
    std.mem.writeInt(u32, elf[608..612], @intCast(std.mem.indexOf(u8, names, "__input_start").?), .little);
    std.mem.writeInt(u32, elf[612..616], 0x00100100, .little);
    std.mem.writeInt(u32, elf[624..628], @intCast(std.mem.indexOf(u8, names, "__input_end").?), .little);
    std.mem.writeInt(u32, elf[628..632], 0x00100104, .little);
}

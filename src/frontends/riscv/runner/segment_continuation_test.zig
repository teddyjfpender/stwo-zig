//! Segmented runner parity and continuation-integrity tests.

const std = @import("std");
const result_mod = @import("result.zig");
const segment_session = @import("segment_session.zig");

const CompletionReason = result_mod.CompletionReason;
const ContinuationToken = result_mod.ContinuationToken;
const OutputWord = result_mod.OutputWord;
const BaseExecutionSession = segment_session.ExecutionSession(.rv32im_zkvm_v1);
const Poseidon2ExecutionSession = segment_session.ExecutionSession(.rv32im_zkvm_poseidon2_v1);

fn run(allocator: std.mem.Allocator, elf_bytes: []const u8, max_steps: usize) !result_mod.RunResult {
    var session = try BaseExecutionSession.initLegacy(allocator, elf_bytes, .{});
    defer session.deinit();
    return session.runLegacy(max_steps);
}

fn runPoseidon2Extension(
    allocator: std.mem.Allocator,
    elf_bytes: []const u8,
    max_steps: usize,
) !result_mod.Poseidon2RunResult {
    var session = try Poseidon2ExecutionSession.initLegacy(allocator, elf_bytes, .{});
    defer session.deinit();
    return session.runLegacy(max_steps);
}

/// Build a minimal ELF from instruction words.
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

test "runner: one-shot and two adjacent segments have exact execution parity" {
    const instructions = [_]u32{
        0x0010_0137, // LUI  x2, 0x100: x2 = default halt-flag address.
        0x0550_0093, // ADDI x1, x0, 0x55.
        0x0011_2023, // SW   x1, 0(x2).
        0x0001_2183, // LW   x3, 0(x2), chaining to the prior segment's store.
        0x1001_0213, // ADDI x4, x2, 0x100: a word absent at the first boundary.
        0x0012_2023, // SW   x1, 0(x4): materialize it only in segment two.
        0x0010_8093, // ADDI x1, x1, 1.
        0x0000_0073, // ECALL.
    };
    const elf = makeTestElf(&instructions);

    var one_shot = try run(std.testing.allocator, &elf, 100);
    defer one_shot.deinit();

    var session = try BaseExecutionSession.init(std.testing.allocator, &elf, .{});
    defer session.deinit();
    var first = try session.startSegment(3);
    defer first.deinit();
    const continuation = first.continuation.?;
    var second = try session.resumeSegment(continuation, 100);
    defer second.deinit();

    try std.testing.expect(first.segment_role.is_first);
    try std.testing.expect(!first.segment_role.is_last);
    try std.testing.expect(first.completion_reason == null);
    try std.testing.expect(first.output == null);
    try std.testing.expectEqual(@as(u64, 1), first.global_first_cycle);
    try std.testing.expectEqual(@as(usize, 3), first.cycle_count);
    try std.testing.expect(!second.segment_role.is_first);
    try std.testing.expect(second.segment_role.is_last);
    try std.testing.expectEqual(CompletionReason.ecall, second.completion_reason.?);
    try std.testing.expectError(
        error.SegmentedExecutionRequiresPublicDataV2,
        first.requireV1SingleExecution(),
    );
    try std.testing.expectError(
        error.SegmentedExecutionRequiresPublicDataV2,
        second.requireV1SingleExecution(),
    );
    try std.testing.expectEqual(@as(u64, 4), second.global_first_cycle);
    try std.testing.expectEqual(@as(usize, 5), second.cycle_count);
    try std.testing.expect(std.meta.eql(first.exit_cpu, second.entry_cpu));
    try first.rw_memory.requireContinuationTo(second.rw_memory);
    var first_has_late_word = false;
    for (first.rw_memory.words) |word|
        first_has_late_word = first_has_late_word or word.addr == 0x0010_0100;
    try std.testing.expect(!first_has_late_word);
    const late_word = for (second.rw_memory.words) |word| {
        if (word.addr == 0x0010_0100) break word;
    } else return error.MissingLateSegmentWord;
    try std.testing.expectEqual(@as(u32, 0), late_word.initial_word);
    try std.testing.expectEqual(@as(u32, 0x55), late_word.final_word);
    try std.testing.expect(std.meta.eql(
        first.exit_access_clocks.register_clocks,
        second.entry_access_clocks.register_clocks,
    ));
    try std.testing.expectEqualSlices(
        result_mod.MemoryAccessClock,
        first.exit_access_clocks.memory_clocks,
        second.entry_access_clocks.memory_clocks,
    );

    try std.testing.expectEqual(one_shot.step_count, first.cycle_count + second.cycle_count);
    try std.testing.expectEqual(
        one_shot.execution_trace.rows.items.len,
        session.execution_trace.rows.items.len,
    );
    try std.testing.expect(std.meta.eql(one_shot.cpu_final, second.exit_cpu));
    try std.testing.expectEqual(one_shot.final_pc, second.exit_cpu.pc);
    try std.testing.expect(std.meta.eql(
        one_shot.rw_memory.exitIdentity(),
        second.rw_memory.exitIdentity(),
    ));
    try std.testing.expect(std.meta.eql(
        one_shot.state_chain_tracker.reg_last_clk,
        second.exit_access_clocks.register_clocks,
    ));
    try std.testing.expectEqual(
        one_shot.state_chain_tracker.mem_last_clk.count(),
        second.exit_access_clocks.memory_clocks.len,
    );
    for (second.exit_access_clocks.memory_clocks) |entry|
        try std.testing.expectEqual(
            entry.clock,
            one_shot.state_chain_tracker.mem_last_clk.get(entry.addr).?,
        );
    const first_rows = first.execution_trace.rows.items;
    const second_rows = second.execution_trace.rows.items;
    try std.testing.expectEqual(one_shot.execution_trace.rows.items.len, first_rows.len + second_rows.len);
    for (one_shot.execution_trace.rows.items, 0..) |expected, index| {
        const actual = if (index < first_rows.len)
            first_rows[index]
        else
            second_rows[index - first_rows.len];
        try std.testing.expect(std.meta.eql(expected, actual));
    }
    try std.testing.expectEqual(@as(u32, 11), second_rows[0].mem_prev_clk);
    try std.testing.expectEqual(one_shot.output_len, second.output_len);
    try std.testing.expectEqual(one_shot.output == null, second.output == null);
    if (one_shot.output) |expected_output|
        try std.testing.expectEqualSlices(u8, expected_output, second.output.?);
    try std.testing.expectEqualSlices(OutputWord, one_shot.output_words, second.output_words);

    const one_shot_accesses = one_shot.state_chain_tracker.accesses.items;
    const first_accesses = first.state_chain_tracker.accesses.items;
    const second_accesses = second.state_chain_tracker.accesses.items;
    try std.testing.expectEqual(one_shot_accesses.len, first_accesses.len + second_accesses.len);
    for (one_shot_accesses, 0..) |expected, index| {
        const actual = if (index < first_accesses.len)
            first_accesses[index]
        else
            second_accesses[index - first_accesses.len];
        try std.testing.expect(std.meta.eql(expected, actual));
    }
}

test "runner: mutated continuation rejects before session mutation" {
    const instructions = [_]u32{
        0x0010_0093, // ADDI x1, x0, 1.
        0x0010_8093, // ADDI x1, x1, 1.
        0x0000_0073, // ECALL.
    };
    const elf = makeTestElf(&instructions);
    var session = try BaseExecutionSession.init(std.testing.allocator, &elf, .{});
    defer session.deinit();
    var first = try session.startSegment(1);
    defer first.deinit();
    const expected = first.continuation.?;

    const cpu_before = session.cpu;
    const steps_before = session.global_steps;
    const segment_before = session.next_segment_index;
    const clock_count_before = session.memory_clocks.count();
    var mutations = [_]ContinuationToken{expected} ** 7;
    mutations[0].schema_version +%= 1;
    mutations[1].session_tag ^= 1;
    mutations[2].next_segment_index +%= 1;
    mutations[3].next_cycle +%= 1;
    mutations[4].cpu.pc +%= 4;
    mutations[5].rw_memory.fingerprint ^= 1;
    mutations[6].access_clocks ^= 1;
    for (mutations) |mutated| {
        try std.testing.expectError(
            error.ContinuationMismatch,
            session.resumeSegment(mutated, 100),
        );
        try std.testing.expect(std.meta.eql(cpu_before, session.cpu));
        try std.testing.expectEqual(steps_before, session.global_steps);
        try std.testing.expectEqual(segment_before, session.next_segment_index);
        try std.testing.expectEqual(clock_count_before, session.memory_clocks.count());
        try std.testing.expect(std.meta.eql(expected, session.pending_continuation.?));
    }

    try std.testing.expectError(
        error.ZeroSegmentStepBudget,
        session.resumeSegment(expected, 0),
    );
    try std.testing.expect(std.meta.eql(cpu_before, session.cpu));
    try std.testing.expect(std.meta.eql(expected, session.pending_continuation.?));

    var second = try session.resumeSegment(expected, 100);
    defer second.deinit();
    try std.testing.expectEqual(CompletionReason.ecall, second.completion_reason.?);
    try std.testing.expectEqual(@as(u32, 2), second.exit_cpu.readReg(1));
}

test "runner: only a complete first-and-last segment has V1 shape" {
    const instructions = [_]u32{
        0x0010_0093, // ADDI x1, x0, 1.
        0x0000_0073, // ECALL.
    };
    const elf = makeTestElf(&instructions);
    var session = try BaseExecutionSession.init(std.testing.allocator, &elf, .{});
    defer session.deinit();
    var complete = try session.startSegment(100);
    defer complete.deinit();
    try complete.requireV1SingleExecution();
}

test "runner: Poseidon2 extension logs remain segment-owned across resume" {
    const test_elf = @import("guest_precompile/test_elf.zig");
    const elf = test_elf.build(true, .ecall);
    var one_shot = try runPoseidon2Extension(std.testing.allocator, &elf, 16);
    defer one_shot.deinit();

    var session = try Poseidon2ExecutionSession.init(std.testing.allocator, &elf, .{});
    defer session.deinit();
    // Yield immediately before CUSTOM-0 so the resumed segment must carry the
    // omitted retirement while retaining exact global-clock adjacency.
    var first = try session.startSegment(2);
    defer first.deinit();
    var second = try session.resumeSegment(first.base.continuation.?, 16);
    defer second.deinit();

    try std.testing.expectEqual(@as(usize, 0), first.calls.len());
    try std.testing.expectEqual(@as(usize, 0), first.execution_rows.rows().len);
    try std.testing.expectEqual(@as(usize, 1), second.calls.len());
    try std.testing.expectEqual(@as(usize, 1), second.execution_rows.rows().len);
    try std.testing.expectEqual(@as(u32, 3), second.calls.records()[0].execution_clock);
    try first.base.execution_trace.validateClockRange(0, 2, 0);
    try second.base.execution_trace.validateClockRange(2, 4, 1);
    try one_shot.base.execution_trace.validateClockRange(0, 4, 1);
    try std.testing.expectEqual(
        first.base.global_first_cycle + first.base.cycle_count,
        second.base.global_first_cycle,
    );
    try std.testing.expectEqual(CompletionReason.ecall, second.base.completion_reason.?);
    try std.testing.expect(std.meta.eql(one_shot.base.cpu_final, second.base.exit_cpu));
    try first.base.rw_memory.requireContinuationTo(second.base.rw_memory);
    try std.testing.expectEqual(
        one_shot.base.execution_trace.rows.items.len,
        first.base.execution_trace.rows.items.len + second.base.execution_trace.rows.items.len,
    );
}

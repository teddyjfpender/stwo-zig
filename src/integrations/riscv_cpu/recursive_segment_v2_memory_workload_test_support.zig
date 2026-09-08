//! Execution checks for the fixed-size mutable-memory recursion ladder.
//! This models word updates independently of ELF instruction decoding.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const runner = frontend.runner;
const fixture = frontend.testing.guest_precompile_test_elf;

pub const native_steps: usize = 64;
pub const continuation_steps: usize = 16;

pub fn validateSegment(
    result: *const runner.SegmentResult,
    address_count: usize,
    cumulative_steps: usize,
    segment_steps: usize,
) !void {
    return validateSegmentWithCompletion(result, address_count, cumulative_steps, segment_steps, false, 0);
}

/// Same independent instruction/memory model with an explicit completed-leaf
/// boundary. The terminal self-loop is observed but is not a retired row.
pub fn validateCompletedSegment(
    result: *const runner.SegmentResult,
    address_count: usize,
    cumulative_steps: usize,
    segment_steps: usize,
) !void {
    return validateSegmentWithCompletion(result, address_count, cumulative_steps, segment_steps, true, 0);
}

pub fn validateSeededSegment(
    result: *const runner.SegmentResult,
    address_count: usize,
    cumulative_steps: usize,
    segment_steps: usize,
    completed: bool,
    initial_word: u32,
) !void {
    return validateSegmentWithCompletion(result, address_count, cumulative_steps, segment_steps, completed, initial_word);
}

fn validateSegmentWithCompletion(
    result: *const runner.SegmentResult,
    address_count: usize,
    cumulative_steps: usize,
    segment_steps: usize,
    completed: bool,
    initial_word: u32,
) !void {
    switch (address_count) {
        1, 4, 16 => {},
        else => return error.InvalidMemoryAddressCount,
    }
    if (segment_steps > cumulative_steps or cumulative_steps > 2 + 3 * fixture.recursion_memory_updates)
        return error.InvalidMemoryWorkloadSteps;
    try std.testing.expectEqual(segment_steps, result.cycle_count);
    try std.testing.expectEqual(segment_steps, result.execution_trace.rows.items.len);
    if (completed) {
        try std.testing.expectEqual(@as(usize, 2 + 3 * fixture.recursion_memory_updates), cumulative_steps);
        try std.testing.expect(result.continuation == null);
        try std.testing.expectEqual(runner.CompletionReason.self_loop, result.completion_reason orelse return error.ExpectedMemoryWorkloadCompletion);
        try std.testing.expect(result.segment_role.is_last);
    } else {
        try std.testing.expect(result.continuation != null);
        try std.testing.expect(result.completion_reason == null);
        try std.testing.expect(!result.segment_role.is_last);
    }
    const first_step = cumulative_steps - segment_steps;
    var words: [16]u32 = @splat(0);
    @memset(words[0..address_count], initial_word);
    var entry_words = words;
    var registers: [32]u32 = @splat(0);
    registers[2] = runner.elf_loader.DEFAULT_STACK_POINTER;
    registers[3] = runner.elf_loader.DEFAULT_GLOBAL_POINTER;
    var loads: usize = 0;
    var stores: usize = 0;
    var touched: [16]bool = @splat(false);
    for (0..address_count) |index| {
        const address = fixture.recursion_memory_base + fixture.recursion_memory_stride * @as(u32, @intCast(index));
        try std.testing.expect(result.rw_memory.layout.isRwAddr(address));
        try std.testing.expect(result.rw_memory.layout.isRwAddr(address + 3));
    }
    for (0..cumulative_steps) |step| {
        if (step == first_step) {
            entry_words = words;
            try std.testing.expectEqualSlices(u32, &registers, &result.entry_cpu.regs);
            try std.testing.expectEqual(@as(u32, @intCast(0x1000 + 4 * step)), result.entry_cpu.pc);
        }
        const row = if (step >= first_step) &result.execution_trace.rows.items[step - first_step] else null;
        if (row) |actual| {
            try std.testing.expectEqual(@as(u32, @intCast(0x1000 + 4 * step)), actual.pc);
            try std.testing.expectEqual(actual.pc + 4, actual.next_pc);
        }
        if (step < 2) {
            registers[5] = if (step == 0) 0x0010_0000 else fixture.recursion_memory_base;
            if (row) |actual| {
                try std.testing.expect(actual.opcode == @as(frontend.runner.decode.Opcode, if (step == 0) .LUI else .ADDI));
                try std.testing.expectEqual(registers[5], actual.rd_val);
                try std.testing.expect(!actual.is_load and !actual.is_store);
            }
            continue;
        }
        const index = ((step - 2) / 3) % address_count;
        const phase = (step - 2) % 3;
        const before = words[index];
        switch (phase) {
            0 => registers[6] = before,
            1 => registers[6] +%= 1,
            2 => words[index] = registers[6],
            else => unreachable,
        }
        if (row) |actual| {
            const expected_opcode: frontend.runner.decode.Opcode = switch (phase) {
                0 => .LW,
                1 => .ADDI,
                2 => .SW,
                else => unreachable,
            };
            try std.testing.expectEqual(expected_opcode, actual.opcode);
            try std.testing.expectEqual(@as(u5, if (phase == 1) 6 else 5), actual.rs1);
            try std.testing.expectEqual(if (phase == 1) before else fixture.recursion_memory_base, actual.rs1_val);
            try std.testing.expectEqual(phase == 0, actual.is_load);
            try std.testing.expectEqual(phase == 2, actual.is_store);
            if (phase != 2) try std.testing.expectEqual(registers[6], actual.rd_val);
            if (phase != 1) {
                try std.testing.expectEqual(fixture.recursion_memory_base + fixture.recursion_memory_stride * @as(u32, @intCast(index)), actual.mem_addr);
                try std.testing.expectEqual(registers[6], actual.mem_val);
                try std.testing.expectEqual(before, actual.mem_prev_word);
                try std.testing.expectEqual(words[index], actual.mem_next_word);
                touched[index] = true;
                if (phase == 0) loads += 1 else stores += 1;
            }
        }
    }
    try std.testing.expectEqualSlices(u32, &registers, &result.exit_cpu.regs);
    try std.testing.expectEqual(@as(u32, @intCast(0x1000 + 4 * cumulative_steps)), result.exit_cpu.pc);
    var found: [16]bool = @splat(false);
    var entry_nonzero: usize = 0;
    var exit_nonzero: usize = 0;
    for (result.rw_memory.words) |word| {
        if (word.initial_word != 0) entry_nonzero += 1;
        if (word.final_word != 0) exit_nonzero += 1;
        if (word.addr < fixture.recursion_memory_base or word.addr >= fixture.recursion_memory_base + 16 * fixture.recursion_memory_stride) continue;
        try std.testing.expectEqual(@as(u32, 0), word.addr % 4);
        const offset = word.addr - fixture.recursion_memory_base;
        if (offset % fixture.recursion_memory_stride != 0) {
            // Loaded but untouched zero words remain absent from the sparse
            // opening. A write between selected addresses is a fixture bug.
            try std.testing.expectEqual(@as(u32, 0), word.initial_word);
            try std.testing.expectEqual(@as(u32, 0), word.final_word);
            continue;
        }
        const index = offset / fixture.recursion_memory_stride;
        try std.testing.expect(!found[index]);
        found[index] = true;
        try std.testing.expectEqual(entry_words[index], word.initial_word);
        try std.testing.expectEqual(words[index], word.final_word);
    }
    for (touched, found) |accessed, present| if (accessed) try std.testing.expect(present);
    var expected_entry_nonzero: usize = 0;
    var expected_exit_nonzero: usize = 0;
    for (entry_words, words) |before, after| {
        if (before != 0) expected_entry_nonzero += 1;
        if (after != 0) expected_exit_nonzero += 1;
    }
    try std.testing.expectEqual(expected_entry_nonzero, entry_nonzero);
    try std.testing.expectEqual(expected_exit_nonzero, exit_nonzero);
    if (first_step == 0) try std.testing.expectEqual(address_count, std.mem.count(bool, &touched, &.{true}));
    std.debug.print(
        "SEGMENT_V2_MEMORY_EXECUTION address_count={d} initial_word={d} segment_cycles={d} cumulative_cycles={d} " ++
            "loads={d} stores={d} distinct_accessed={d} stride_bytes={d} " ++
            "entry_nonzero_words={d} exit_nonzero_words={d} exit_pc={x}\n",
        .{ address_count, initial_word, segment_steps, cumulative_steps, loads, stores, std.mem.count(bool, &touched, &.{true}), fixture.recursion_memory_stride, entry_nonzero, exit_nonzero, result.exit_cpu.pc },
    );
}

/// Cheap execution admission before any native or recursive proof is built.
pub fn checkWorkload(allocator: std.mem.Allocator) !void {
    try std.testing.expectError(error.InvalidMemoryAddressCount, fixture.buildRecursionMemory(0));
    try std.testing.expectError(error.InvalidMemoryAddressCount, fixture.buildRecursionMemory(2));
    for (fixture.recursion_memory_address_counts) |address_count| {
        const elf = try fixture.buildRecursionMemory(address_count);
        var session = try runner.Poseidon2ExecutionSession.init(allocator, &elf, .{});
        defer session.deinit();
        var first = try session.startSegment(native_steps);
        defer first.deinit();
        try validateSegment(&first.base, address_count, native_steps, native_steps);
        // These are execution admission checks, kept ahead of expensive proofs.
        {
            const original = first.base.execution_trace.rows.items[2].mem_val;
            defer first.base.execution_trace.rows.items[2].mem_val = original;
            first.base.execution_trace.rows.items[2].mem_val ^= 1;
            try std.testing.expectError(error.TestExpectedEqual, validateSegment(&first.base, address_count, native_steps, native_steps));
        }
        {
            const original = first.base.execution_trace.rows.items[2].mem_addr;
            defer first.base.execution_trace.rows.items[2].mem_addr = original;
            first.base.execution_trace.rows.items[2].mem_addr += 4;
            try std.testing.expectError(error.TestExpectedEqual, validateSegment(&first.base, address_count, native_steps, native_steps));
        }
        for (first.base.rw_memory.words) |*word| {
            if (word.addr != fixture.recursion_memory_base) continue;
            const original = word.final_word;
            defer word.final_word = original;
            word.final_word ^= 1;
            try std.testing.expectError(error.TestExpectedEqual, validateSegment(&first.base, address_count, native_steps, native_steps));
            break;
        }
        var second = try session.resumeSegment(first.base.continuation.?, continuation_steps);
        defer second.deinit();
        try validateSegment(&second.base, address_count, native_steps + continuation_steps, continuation_steps);
    }
}

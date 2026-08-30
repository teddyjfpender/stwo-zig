//! Transaction, custody, and fail-closed tests for the Keccak-f candidate.

const std = @import("std");
const authority = @import("../../air/guest_precompile/keccakf_authority.zig");
const custom0 = @import("../../isa/custom0.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const call_buffer = @import("keccakf_call_buffer.zig");
const candidate = @import("keccakf_v1.zig");

fn testLayout() MemoryLayout {
    return .{
        .program_base = 0x1000,
        .program_end = 0x1100,
        .data_base = 0x2000,
        .data_end = 0x3000,
        .stack_bottom = 0x4000,
        .stack_top = 0x5000,
        .io_base = 0x6000,
        .io_end = 0x7000,
        .input_base = 0x6000,
        .input_end = 0x6100,
        .output_len_addr = 0x6200,
        .output_data_addr = 0x6204,
        .output_base = 0x6200,
        .output_end = 0x7000,
    };
}

fn inputState() authority.State {
    var state: authority.State = undefined;
    for (&state, 0..) |*lane, index|
        lane.* = @as(u64, index) *% 0x9e3779b97f4a7c15;
    return state;
}

fn writeState(memory: *Memory, ptr: u32, state: authority.State) void {
    for (state, 0..) |lane, index| {
        memory.writeU32(ptr + @as(u32, @intCast(index * 8)), @truncate(lane));
        memory.writeU32(ptr + @as(u32, @intCast(index * 8 + 4)), @truncate(lane >> 32));
    }
}

fn readState(memory: *const Memory, ptr: u32) authority.State {
    var state: authority.State = undefined;
    for (&state, 0..) |*lane, index| {
        const low = memory.readU32(ptr + @as(u32, @intCast(index * 8)));
        const high = memory.readU32(ptr + @as(u32, @intCast(index * 8 + 4)));
        lane.* = low | (@as(u64, high) << 32);
    }
    return state;
}

test "keccakf candidate: transaction commits exact output clocks and records" {
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var calls = try call_buffer.Builder.init(std.testing.allocator, 2);
    defer calls.deinit();
    var rows = try candidate.ExecutionRowsBuilder.init(std.testing.allocator, 2);
    defer rows.deinit();
    var cpu = Cpu.init(0x1000, 0x4000);
    const ptr: u32 = 0x2000;
    cpu.writeReg(5, ptr);
    const input = inputState();
    writeState(&memory, ptr, input);

    try candidate.executeCandidate(
        custom0.encodeKeccakf(5),
        1,
        &cpu,
        &memory,
        testLayout(),
        &tracker,
        &calls,
        &rows,
    );
    var expected = input;
    authority.permute(&expected);
    try std.testing.expectEqual(expected, readState(&memory, ptr));
    try std.testing.expectEqual(@as(u32, 0x1004), cpu.pc);
    try std.testing.expectEqual(@as(usize, 1), calls.len());
    try std.testing.expectEqual(@as(usize, 1), rows.len());
    try std.testing.expectEqual(@as(u32, 1), calls.records()[0].execution_clock);
    try std.testing.expectEqual(@as(u32, ptr), calls.records()[0].state_ptr);
    try std.testing.expectEqual(@as(u32, 0), rows.rows()[0].call_index);
    try std.testing.expectEqual(@as(usize, candidate.word_count + 1), tracker.accesses.items.len);
    try std.testing.expectEqual(@as(u32, 1), tracker.reg_last_clk[5]);
    for (0..candidate.word_count) |index| {
        const addr = ptr + @as(u32, @intCast(index * 4));
        try std.testing.expectEqual(@as(u32, 2), tracker.mem_last_clk.get(addr).?);
    }
}

test "keccakf candidate: invalid encoding alignment span and clock are fail atomic" {
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var calls = try call_buffer.Builder.init(std.testing.allocator, 4);
    defer calls.deinit();
    var rows = try candidate.ExecutionRowsBuilder.init(std.testing.allocator, 4);
    defer rows.deinit();
    var cpu = Cpu.init(0x1000, 0x4000);
    cpu.writeReg(5, 0x2000);
    const before = inputState();
    writeState(&memory, 0x2000, before);

    const cases = [_]struct { word: u32, clock: u32, pointer: u32, expected: anyerror }{
        .{ .word = custom0.encodeKeccakf(5) | 0x80, .clock = 1, .pointer = 0x2000, .expected = error.InvalidPrecompileEncoding },
        .{ .word = custom0.encodeKeccakf(5), .clock = 0, .pointer = 0x2000, .expected = error.PrecompileClockOutOfRange },
        .{ .word = custom0.encodeKeccakf(5), .clock = 1, .pointer = 0x2004, .expected = error.PrecompileAddressMisaligned },
        .{ .word = custom0.encodeKeccakf(5), .clock = 1, .pointer = 0x2f80, .expected = error.PrecompileSpanOutsideRwMemory },
    };
    for (cases) |case| {
        cpu.writeReg(5, case.pointer);
        try std.testing.expectError(case.expected, candidate.executeCandidate(
            case.word,
            case.clock,
            &cpu,
            &memory,
            testLayout(),
            &tracker,
            &calls,
            &rows,
        ));
        try std.testing.expectEqual(@as(u32, 0x1000), cpu.pc);
        try std.testing.expectEqual(@as(usize, 0), calls.len());
        try std.testing.expectEqual(@as(usize, 0), rows.len());
        try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
    }
    try std.testing.expectEqual(before, readState(&memory, 0x2000));
}

test "keccakf candidate: call limit failure cannot publish architecture" {
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var calls = try call_buffer.Builder.init(std.testing.allocator, 0);
    defer calls.deinit();
    var rows = try candidate.ExecutionRowsBuilder.init(std.testing.allocator, 1);
    defer rows.deinit();
    var cpu = Cpu.init(0x1000, 0x4000);
    cpu.writeReg(5, 0x2000);
    const before = inputState();
    writeState(&memory, 0x2000, before);

    try std.testing.expectError(error.PrecompileCallLimitExceeded, candidate.executeCandidate(
        custom0.encodeKeccakf(5),
        1,
        &cpu,
        &memory,
        testLayout(),
        &tracker,
        &calls,
        &rows,
    ));
    try std.testing.expectEqual(before, readState(&memory, 0x2000));
    try std.testing.expectEqual(@as(u32, 0x1000), cpu.pc);
    try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
}

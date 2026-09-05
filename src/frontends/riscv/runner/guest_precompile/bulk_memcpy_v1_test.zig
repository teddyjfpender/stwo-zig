//! Synthetic execution, custody, mutation, and fail-atomic coverage for the
//! candidate-only bulk-memcpy runner.

const std = @import("std");

const access_clock = @import("../../access_clock.zig");
const abi = @import("../../isa/bulk_memcpy_candidate_v1.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const Trace = @import("../trace.zig").Trace;
const subject = @import("bulk_memcpy_v1.zig");
const call_buffer = @import("bulk_memcpy_call_buffer_v1.zig");
const tape_mod = @import("bulk_memcpy_session_tape_v1.zig");

const source: u32 = 0x2001;
const destination: u32 = 0x2081;
const length: u32 = 34;
const word_count: usize = 9;

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

fn sourceBytes() [length]u8 {
    var result: [length]u8 = undefined;
    for (&result, 0..) |*byte, index| byte.* = @intCast(0x40 + index);
    return result;
}

fn initializeMemory(memory: *Memory) void {
    const input = sourceBytes();
    memory.writeByte(source - 1, 0x1a);
    memory.writeSlice(source, &input);
    memory.writeByte(source + length, 0x1b);
    memory.writeByte(destination - 1, 0xd1);
    memory.writeSlice(destination, &(.{0xa5} ** length));
    memory.writeByte(destination + length, 0xd2);
}

fn initializeCpu() Cpu {
    var cpu = Cpu.init(0x1000, 0x4000);
    cpu.writeReg(abi.destination_register, destination);
    cpu.writeReg(abi.source_register, source);
    cpu.writeReg(abi.length_register, length);
    return cpu;
}

fn destinationWindow(memory: *const Memory) [length + 2]u8 {
    var result: [length + 2]u8 = undefined;
    memory.readSlice(destination - 1, &result);
    return result;
}

fn dataWindow(memory: *const Memory) [0x100]u8 {
    var result: [0x100]u8 = undefined;
    memory.readSlice(0x2000, &result);
    return result;
}

test "bulk memcpy runner commits exact bytes clocks and frozen custody" {
    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    initializeMemory(&memory);
    var tracker = StateChainTracker.init(std.testing.allocator);
    defer tracker.deinit();
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    var tape = try tape_mod.Builder.init(
        std.testing.allocator,
        2,
        2 * word_count,
        0,
    );
    defer tape.deinit();
    var cpu = initializeCpu();

    try subject.executeWithRecordedClock(
        abi.fixed_word,
        1,
        &cpu,
        &memory,
        testLayout(),
        &tracker,
        &trace,
        &tape,
    );

    const input = sourceBytes();
    const output = destinationWindow(&memory);
    try std.testing.expectEqual(@as(u8, 0xd1), output[0]);
    try std.testing.expectEqual(input, output[1 .. 1 + length].*);
    try std.testing.expectEqual(@as(u8, 0xd2), output[length + 1]);
    try std.testing.expectEqual(@as(u8, 0x1a), memory.readByte(source - 1));
    try std.testing.expectEqual(@as(u8, 0x1b), memory.readByte(source + length));
    try std.testing.expectEqual(@as(u32, 0x1004), cpu.pc);

    try std.testing.expectEqual(@as(usize, 1), tape.len());
    try std.testing.expectEqual(word_count, tape.wordLen());
    try std.testing.expectEqual(@as(usize, 1), tape.rowLen());
    try std.testing.expectEqual(@as(u32, 0), tape.records()[0].caller.call_index);
    try std.testing.expectEqualDeep(
        call_buffer.AlignedSpanIdentity{
            .source = .{
                .first_word = source / 4,
                .word_count = @intCast(word_count),
                .end_word_exclusive = source / 4 + @as(u32, @intCast(word_count)),
            },
            .destination = .{
                .first_word = destination / 4,
                .word_count = @intCast(word_count),
                .end_word_exclusive = destination / 4 + @as(u32, @intCast(word_count)),
            },
        },
        tape.records()[0].aligned_spans,
    );
    try std.testing.expectEqual(@as(u32, 0), tape.records()[0].first_word_row);
    try std.testing.expectEqual(@as(u32, word_count), tape.records()[0].word_row_count);
    try std.testing.expectEqualDeep(
        [_]bool{ false, true, true, true },
        tape.wordRows()[0].byte_mask,
    );
    try std.testing.expectEqualDeep(
        [_]bool{ true, true, true, false },
        tape.wordRows()[word_count - 1].byte_mask,
    );
    try std.testing.expectEqual(@as(u32, 0), tape.rows()[0].call_index);
    try std.testing.expectEqual(abi.fixed_word, tape.rows()[0].inst_word);
    try tape.validate();

    const register_clock = access_clock.encode(1, .first);
    const memory_clock = access_clock.encode(1, .second);
    try std.testing.expectEqual(
        @as(usize, 3 + 2 * word_count),
        tracker.accesses.items.len,
    );
    for ([_]u5{
        abi.destination_register,
        abi.source_register,
        abi.length_register,
    }) |register| try std.testing.expectEqual(
        register_clock,
        tracker.reg_last_clk[register],
    );
    for (0..word_count) |index| {
        const offset: u32 = @intCast(4 * index);
        try std.testing.expectEqual(
            memory_clock,
            tracker.mem_last_clk.get((source & ~@as(u32, 3)) + offset).?,
        );
        try std.testing.expectEqual(
            memory_clock,
            tracker.mem_last_clk.get((destination & ~@as(u32, 3)) + offset).?,
        );
        try std.testing.expectEqual(memory_clock, tracker.accesses.items[3 + 2 * index].clk);
        try std.testing.expectEqual(memory_clock, tracker.accesses.items[4 + 2 * index].clk);
    }
    try trace.validateClockRange(0, 1, 1);

    var frozen = tape.freeze();
    defer frozen.deinit();
    try frozen.validate();

    frozen.calls.word_rows.items[0].destination_after[1] +%= 1;
    try std.testing.expectError(error.InvalidBulkMemcpyCallBuffer, frozen.validate());
    frozen.calls.word_rows.items[0].destination_after[1] -%= 1;
    try frozen.validate();

    frozen.execution_rows.items[0].call_index = 1;
    try std.testing.expectError(error.InvalidBulkMemcpySessionTape, frozen.validate());
    frozen.execution_rows.items[0].call_index = 0;
    try frozen.validate();

    frozen.execution_rows.items[0].inst_word ^= 1;
    try std.testing.expectError(error.InvalidBulkMemcpySessionTape, frozen.validate());
    frozen.execution_rows.items[0].inst_word ^= 1;
    try frozen.validate();

    frozen.calls.calls.items[0].aligned_spans.source.end_word_exclusive += 1;
    try std.testing.expectError(
        error.InvalidBulkMemcpyAlignedSpanIdentity,
        frozen.validate(),
    );
    frozen.calls.calls.items[0].aligned_spans.source.end_word_exclusive -= 1;
    try frozen.validate();

    const original_caller = frozen.calls.calls.items[0].caller;
    frozen.calls.calls.items[0].caller.length = 32;
    frozen.calls.calls.items[0].caller.destination = source + 32;
    try std.testing.expectError(
        error.BulkMemcpyWordSpansOverlap,
        frozen.validate(),
    );
    frozen.calls.calls.items[0].caller = original_caller;
    try frozen.validate();

    var telemetry = call_buffer.AdmissionTelemetry{};
    try telemetry.observe(original_caller.call());
    var collision = original_caller.call();
    collision.length = 32;
    collision.destination = collision.source + 32;
    try telemetry.observe(collision);
    try telemetry.validate();
    try std.testing.expectEqual(
        call_buffer.ExactFraction{ .numerator = 1, .denominator = 2 },
        try telemetry.alignedWordRejectedFraction(),
    );
}

test "bulk memcpy runner rejects encoding span and tape failures atomically" {
    const Case = struct {
        word: u32 = abi.fixed_word,
        clock: u32 = 1,
        source_address: u32 = source,
        destination_address: u32 = destination,
        byte_length: u32 = length,
        call_limit: usize = 1,
        word_limit: usize = word_count,
        expected: anyerror,
    };
    const cases = [_]Case{
        .{ .word = abi.fixed_word ^ 1, .expected = error.InvalidCall },
        .{ .clock = 0, .expected = error.ProfileClockAuthorityMismatch },
        .{ .byte_length = 31, .expected = error.InvalidCall },
        .{
            .destination_address = source + 16,
            .expected = error.InvalidCall,
        },
        // Byte ranges are adjacent, but both touch aligned word 0x2020. The
        // current AIR cannot advance that word twice at one memory subclock.
        .{
            .source_address = 0x2001,
            .destination_address = 0x2021,
            .byte_length = 32,
            .expected = error.BulkMemcpyWordSpansOverlap,
        },
        .{
            .source_address = 0x2fe1,
            .destination_address = 0x2081,
            .byte_length = 34,
            .expected = error.BulkMemcpySpanOutsideRwMemory,
        },
        .{ .call_limit = 0, .expected = error.BulkMemcpyTapeLimitExceeded },
        .{ .word_limit = word_count - 1, .expected = error.BulkMemcpyTapeLimitExceeded },
    };

    for (cases) |case| {
        var memory = try Memory.initFallible(std.testing.allocator);
        defer memory.deinit();
        initializeMemory(&memory);
        var tracker = StateChainTracker.init(std.testing.allocator);
        defer tracker.deinit();
        var trace = Trace.init(std.testing.allocator);
        defer trace.deinit();
        var tape = try tape_mod.Builder.init(
            std.testing.allocator,
            case.call_limit,
            case.word_limit,
            0,
        );
        defer tape.deinit();
        var cpu = initializeCpu();
        cpu.writeReg(abi.source_register, case.source_address);
        cpu.writeReg(abi.destination_register, case.destination_address);
        cpu.writeReg(abi.length_register, case.byte_length);
        const cpu_before = cpu;
        const data_before = dataWindow(&memory);

        try std.testing.expectError(case.expected, subject.executeWithRecordedClock(
            case.word,
            case.clock,
            &cpu,
            &memory,
            testLayout(),
            &tracker,
            &trace,
            &tape,
        ));
        try std.testing.expectEqualDeep(cpu_before, cpu);
        try std.testing.expectEqual(data_before, dataWindow(&memory));
        try std.testing.expectEqual(@as(usize, 0), tracker.accesses.items.len);
        try std.testing.expectEqual(@as(usize, 0), tape.len());
        try std.testing.expectEqual(@as(usize, 0), tape.wordLen());
        try std.testing.expectEqual(@as(usize, 0), tape.rowLen());
        try trace.validateClockRange(0, 0, 0);
    }
}

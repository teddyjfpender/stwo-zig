//! Trace-custody and allocation tests for the candidate bulk-memcpy profile.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

const abi = @import("../../isa/bulk_memcpy_candidate_v1.zig");
const caller = @import("bulk_memcpy_caller_candidate_v1.zig");
const words = @import("bulk_memcpy_word_candidate_v1.zig");
const subject = @import("bulk_memcpy_trace_v1.zig");
const session = @import("../../runner/guest_precompile/bulk_memcpy_session_tape_v1.zig");

const first_word_count: usize = 9;
const second_word_count: usize = 8;

test "bulk memcpy trace preserves exact caller and word rows with canonical padding" {
    var tape = try tapeFixture(std.testing.allocator);
    defer tape.deinit();
    var bundle = try subject.generate(std.testing.allocator, &tape);
    defer bundle.deinit();
    try bundle.validateAgainst(&tape);

    try std.testing.expectEqual(@as(u32, 1), bundle.caller.log_size);
    try std.testing.expectEqual(@as(u32, 2), bundle.caller.logical_rows);
    try std.testing.expectEqual(@as(usize, 2), bundle.caller.domainSize());
    try std.testing.expectEqual(@as(u32, 5), bundle.words.log_size);
    try std.testing.expectEqual(@as(u32, 17), bundle.words.logical_rows);
    try std.testing.expectEqual(@as(usize, 32), bundle.words.domainSize());

    for (tape.records(), 0..) |record, logical| {
        try std.testing.expectEqualDeep(
            (try caller.materialize(record.caller)).encode(),
            bundle.caller.mainRow(logical),
        );
    }
    for (tape.wordRows(), 0..) |row, logical| {
        try std.testing.expectEqualDeep(row.encode(), bundle.words.mainRow(logical));
    }
    for (17..bundle.words.domainSize()) |logical| {
        for (bundle.words.mainRow(logical)) |value|
            try std.testing.expect(value.isZero());
    }
    try expectSelectors(&bundle.caller);
    try expectSelectors(&bundle.words);

    const caller_physical = subject.committedRow(0, bundle.caller.log_size);
    const caller_cell = caller.Layout.active * bundle.caller.domainSize() + caller_physical;
    const saved_caller = bundle.caller.main_storage[caller_cell];
    bundle.caller.main_storage[caller_cell] = M31.zero();
    try std.testing.expectError(
        error.TraceContentMismatch,
        bundle.validateAgainst(&tape),
    );
    bundle.caller.main_storage[caller_cell] = saved_caller;

    const word_physical = subject.committedRow(3, bundle.words.log_size);
    const word_cell = words.Layout.destination_after * bundle.words.domainSize() + word_physical;
    const saved_word = bundle.words.main_storage[word_cell];
    bundle.words.main_storage[word_cell] = saved_word.add(M31.one());
    try std.testing.expectError(
        error.TraceContentMismatch,
        bundle.validateAgainst(&tape),
    );
    bundle.words.main_storage[word_cell] = saved_word;

    const padding_physical = subject.committedRow(17, bundle.words.log_size);
    const active_cell = subject.active_prefix_column * bundle.words.domainSize() +
        padding_physical;
    bundle.words.preprocessed_storage[active_cell] = M31.one();
    try std.testing.expectError(
        error.TraceContentMismatch,
        bundle.validateAgainst(&tape),
    );
    bundle.words.preprocessed_storage[active_cell] = M31.zero();
    try bundle.validateAgainst(&tape);
}

test "bulk memcpy trace rejects cold PC and execution-order mutations before allocation" {
    var tape = try tapeFixture(std.testing.allocator);
    defer tape.deinit();

    tape.calls.calls.items[0].caller.pc = 0x1002;
    tape.execution_rows.items[0].pc = 0x1002;
    for (tape.calls.word_rows.items[0..first_word_count]) |*row| row.pc = 0x1002;
    try tape.validate();
    var pc_failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.InvalidProgramCounter,
        subject.generate(pc_failing.allocator(), &tape),
    );
    try std.testing.expect(!pc_failing.has_induced_failure);

    tape.calls.calls.items[0].caller.pc = 0x1000;
    tape.execution_rows.items[0].pc = 0x1000;
    for (tape.calls.word_rows.items[0..first_word_count]) |*row| row.pc = 0x1000;
    tape.calls.calls.items[1].caller.execution_clock = 1;
    tape.execution_rows.items[1].execution_clock = 1;
    for (tape.calls.word_rows.items[first_word_count..]) |*row|
        row.execution_clock = 1;
    try tape.validate();
    var order_failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.InvalidExecutionOrder,
        subject.generate(order_failing.allocator(), &tape),
    );
    try std.testing.expect(!order_failing.has_induced_failure);
}

test "bulk memcpy trace gives empty custody a canonical minimum domain" {
    var builder = try session.Builder.init(std.testing.allocator, 0, 0, 0);
    var tape = builder.freeze();
    defer tape.deinit();
    var bundle = try subject.generate(std.testing.allocator, &tape);
    defer bundle.deinit();
    try bundle.validateAgainst(&tape);

    try std.testing.expectEqual(@as(u32, 1), bundle.caller.log_size);
    try std.testing.expectEqual(@as(u32, 1), bundle.words.log_size);
    try std.testing.expectEqual(@as(u32, 0), bundle.caller.logical_rows);
    try std.testing.expectEqual(@as(u32, 0), bundle.words.logical_rows);
    for (0..bundle.caller.domainSize()) |logical| {
        for (bundle.caller.mainRow(logical)) |value|
            try std.testing.expect(value.isZero());
    }
    try expectSelectors(&bundle.caller);
    try expectSelectors(&bundle.words);
}

test "bulk memcpy trace releases every partial allocation" {
    var tape = try tapeFixture(std.testing.allocator);
    defer tape.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseAllocationFailures,
        .{&tape},
    );
}

fn exerciseAllocationFailures(
    allocator: std.mem.Allocator,
    tape: *const session.Frozen,
) !void {
    var bundle = try subject.generate(allocator, tape);
    defer bundle.deinit();
    try bundle.validateAgainst(tape);
}

fn tapeFixture(allocator: std.mem.Allocator) !session.Frozen {
    var builder = try session.Builder.init(
        allocator,
        2,
        first_word_count + second_word_count,
        7,
    );
    errdefer builder.deinit();

    const first = caller.Record{
        .execution_clock = 1,
        .pc = 0x1000,
        .destination_previous_clock = 0,
        .source_previous_clock = 0,
        .length_previous_clock = 0,
        .destination = 0x2081,
        .source = 0x2001,
        .length = 34,
        .call_index = 0,
    };
    var first_rows: [first_word_count]words.Row = undefined;
    for (&first_rows, 0..) |*row, index| row.* = try words.materializeRow(
        first.call(),
        @intCast(index),
        wordInput(index, 0x20, 0xa0),
    );
    try builder.reserveOne(first_rows.len);
    builder.appendAssumeCapacity(abi.fixed_word, first, &first_rows);

    const second = caller.Record{
        .execution_clock = 2,
        .pc = 0x1004,
        .destination_previous_clock = 0,
        .source_previous_clock = 0,
        .length_previous_clock = 0,
        .destination = 0x2300,
        .source = 0x2200,
        .length = 32,
        .call_index = 1,
    };
    var second_rows: [second_word_count]words.Row = undefined;
    for (&second_rows, 0..) |*row, index| row.* = try words.materializeRow(
        second.call(),
        @intCast(index),
        wordInput(index, 0x40, 0xc0),
    );
    try builder.reserveOne(second_rows.len);
    builder.appendAssumeCapacity(abi.fixed_word, second, &second_rows);
    try builder.validate();

    var tape = builder.freeze();
    errdefer tape.deinit();
    try tape.validate();
    return tape;
}

fn wordInput(index: usize, source_seed: u8, destination_seed: u8) words.WordInput {
    const offset: u8 = @intCast(index);
    return .{
        .source_previous_clock = 0,
        .destination_previous_clock = 0,
        .source_bytes = .{
            source_seed +% offset,
            source_seed +% offset +% 1,
            source_seed +% offset +% 2,
            source_seed +% offset +% 3,
        },
        .destination_before = .{
            destination_seed +% offset,
            destination_seed +% offset +% 1,
            destination_seed +% offset +% 2,
            destination_seed +% offset +% 3,
        },
    };
}

fn expectSelectors(trace: anytype) !void {
    const size = trace.domainSize();
    for (0..size) |logical| {
        const physical = subject.committedRow(logical, trace.log_size);
        try std.testing.expectEqual(
            logical == 0,
            trace.preprocessedColumn(subject.domain_first_column)[physical].isOne(),
        );
        try std.testing.expectEqual(
            logical + 1 == size,
            trace.preprocessedColumn(subject.domain_last_column)[physical].isOne(),
        );
        try std.testing.expectEqual(
            logical < trace.logical_rows,
            trace.preprocessedColumn(subject.active_prefix_column)[physical].isOne(),
        );
    }
}

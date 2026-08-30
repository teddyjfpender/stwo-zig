//! Bounded Keccak main-trace construction and fail-atomic mutation tests.

const std = @import("std");
const authority = @import("keccakf_authority.zig");
const call_buffer = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const counters_mod = @import("keccakf_multiplicities.zig");
const subject = @import("keccakf_trace.zig");
const witness = @import("keccakf_witness.zig");

fn record(seed: u32) call_buffer.Record {
    var input: [call_buffer.word_count]u32 = undefined;
    for (&input, 0..) |*word, index| word.* = seed +% @as(u32, @intCast(17 * index));
    var state = subject.stateFromWords(input);
    authority.permute(&state);
    var output: [call_buffer.word_count]u32 = undefined;
    for (state, 0..) |lane, index| {
        output[2 * index] = @truncate(lane);
        output[2 * index + 1] = @truncate(lane >> 32);
    }
    return .{
        .execution_clock = seed + 1,
        .pc = seed + 4,
        .state_ptr = 0x1000,
        .pointer_register = 3,
        .pointer_previous_clock = 0,
        .input = input,
        .output = output,
        .memory_previous_clocks = @splat(0),
    };
}

test "keccakf trace: odd call count writes exact selectors and padding" {
    const records = [_]call_buffer.Record{ record(1), record(2), record(3) };
    var counters = try counters_mod.Counters.init(std.testing.allocator);
    defer counters.deinit();
    var trace = try subject.generateShard(
        std.testing.allocator,
        &records,
        7,
        &counters,
    );
    defer trace.deinit();
    try std.testing.expectEqual(@as(u32, 6), trace.log_size);
    try std.testing.expectEqual(@as(u32, 58), trace.n_rows);
    try std.testing.expectEqual(@as(u32, 3), trace.call_count);
    try std.testing.expect(trace.preprocessedColumn(subject.Layout.is_first)[
        subject.committedRow(0, trace.log_size)
    ].isOne());
    try std.testing.expectEqual(
        @as(u32, 7),
        trace.mainAt(subject.Layout.io_a, 0).toU32(),
    );
    try std.testing.expectEqual(
        @as(u32, 8),
        trace.mainAt(subject.Layout.io_b, 1).toU32(),
    );
    try std.testing.expectEqual(
        @as(u32, 9),
        trace.mainAt(subject.Layout.io_a, witness.row_count).toU32(),
    );
    try std.testing.expect(trace.preprocessedColumn(subject.Layout.second_active)[
        subject.committedRow(28, trace.log_size)
    ].isOne());
    try std.testing.expect(trace.preprocessedColumn(subject.Layout.second_active)[
        subject.committedRow(witness.row_count + 28, trace.log_size)
    ].isZero());
    try std.testing.expect(trace.mainAt(subject.Layout.in_use_b, 28).isOne());
    try std.testing.expect(trace.mainAt(
        subject.Layout.in_use_b,
        witness.row_count + 28,
    ).isZero());
    for (trace.n_rows..trace.domainSize()) |logical_row| {
        try std.testing.expect(trace.mainAt(subject.Layout.in_use_a, logical_row).isZero());
    }
    try counters.validateTotals();
}

test "keccakf trace: output and range mutations fail without counter publication" {
    var malformed = record(9);
    malformed.output[17] ^= 1;
    var counters = try counters_mod.Counters.init(std.testing.allocator);
    defer counters.deinit();
    try std.testing.expectError(
        error.OutputMismatch,
        subject.generateShard(std.testing.allocator, &.{malformed}, 0, &counters),
    );
    try std.testing.expectEqual(@as(usize, 0), counters.slots);
    try std.testing.expectError(
        error.EmptyShard,
        subject.generateShard(std.testing.allocator, &.{}, 0, &counters),
    );
    try std.testing.expectError(
        error.CallIndexOutOfRange,
        subject.generateShard(
            std.testing.allocator,
            &.{record(11)},
            authority.candidate.maximum_calls,
            &counters,
        ),
    );
}

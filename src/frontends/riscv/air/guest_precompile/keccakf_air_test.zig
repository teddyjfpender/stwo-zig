//! Row-level direct AIR and whole-multiset LogUp closure tests.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const authority = @import("keccakf_authority.zig");
const call_buffer = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const direct = @import("keccakf_direct.zig");
const interaction = @import("keccakf_interaction_plan.zig");
const counters_mod = @import("keccakf_multiplicities.zig");
const relations_mod = @import("keccakf_relations.zig");
const tables = @import("keccakf_tables.zig");
const trace_mod = @import("keccakf_trace.zig");
const witness = @import("keccakf_witness.zig");

const RootSink = struct {
    count: usize = 0,
    failures: usize = 0,

    pub fn add(self: *RootSink, value: M31, degree: u8) void {
        std.debug.assert(degree >= 1 and degree <= direct.maximum_constraint_degree);
        self.count += 1;
        self.failures += @intFromBool(!value.isZero());
    }
};

fn record(seed: u32) call_buffer.Record {
    var input: [call_buffer.word_count]u32 = undefined;
    for (&input, 0..) |*word, index| word.* = seed +% @as(u32, @intCast(31 * index));
    var state = trace_mod.stateFromWords(input);
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
        .pointer_register = 4,
        .pointer_previous_clock = 0,
        .input = input,
        .output = output,
        .memory_previous_clocks = @splat(0),
    };
}

test "keccakf AIR: all direct rows vanish and a committed mutation is visible" {
    const records = [_]call_buffer.Record{ record(1), record(2), record(3) };
    var counters = try counters_mod.Counters.init(std.testing.allocator);
    defer counters.deinit();
    var trace = try trace_mod.generateShard(std.testing.allocator, &records, 0, &counters);
    defer trace.deinit();

    for (0..trace.domainSize()) |logical_row| {
        var sink = RootSink{};
        try evaluateDirectRow(&trace, logical_row, &sink);
        try std.testing.expectEqual(direct.constraint_count, sink.count);
        try std.testing.expectEqual(@as(usize, 0), sink.failures);
    }

    const mutated_row = trace_mod.committedRow(0, trace.log_size);
    trace.main_storage[(trace_mod.Layout.state + 19) * trace.domainSize() + mutated_row] =
        trace.main_storage[(trace_mod.Layout.state + 19) * trace.domainSize() + mutated_row]
            .add(M31.one());
    var sink = RootSink{};
    try evaluateDirectRow(&trace, 0, &sink);
    try std.testing.expect(sink.failures != 0);
}

test "keccakf AIR: provider, table, and packed I/O multisets cancel exactly" {
    const records = [_]call_buffer.Record{ record(11), record(13), record(17) };
    var counters = try counters_mod.Counters.init(std.testing.allocator);
    defer counters.deinit();
    var trace = try trace_mod.generateShard(std.testing.allocator, &records, 0, &counters);
    defer trace.deinit();
    const relations = relations_mod.Relations.dummy();

    var total = QM31.zero();
    for (0..trace.domainSize()) |logical_row| {
        const main = readMain(&trace, logical_row);
        const next = readState(&trace, offset(trace.domainSize(), logical_row, 1));
        const selectors = readSelectors(&trace, logical_row);
        const pairs = try interaction.rowPairsBase(&main, &next, &selectors, &relations);
        for (pairs) |pair| total = total
            .add(pair.n1.mul(try pair.d1.inv()))
            .add(pair.n2.mul(try pair.d2.inv()));
    }
    for ([_]tables.Kind{ .chi, .xor5 }) |kind| {
        for (counters.values(kind), 0..) |multiplicity, row| {
            if (multiplicity.isZero()) continue;
            const tuple = try tables.tupleAt(kind, row);
            const denominator = switch (kind) {
                .chi => relations.chi.combineBase(tuple),
                .xor5 => relations.xor5.combineBase(tuple),
            };
            total = total.add((try denominator.inv()).mulM31(multiplicity));
        }
    }
    for (records, 0..) |item, call_index| {
        const tuple = try relations_mod.ioTuple(
            call_index,
            trace_mod.stateFromWords(item.input),
            trace_mod.stateFromWords(item.output),
        );
        total = total.add(try relations.io.combineBase(tuple).inv());
    }
    try std.testing.expect(total.isZero());

    var current = readMain(&trace, 2);
    const next = readState(&trace, 3);
    const selectors = readSelectors(&trace, 2);
    const honest = try interaction.rowPairsBase(&current, &next, &selectors, &relations);
    current[trace_mod.Layout.state + 7] =
        current[trace_mod.Layout.state + 7].add(M31.one());
    const forged = try interaction.rowPairsBase(&current, &next, &selectors, &relations);
    var changed = false;
    for (honest, forged) |before, after| {
        changed = changed or !before.d1.eql(after.d1) or !before.d2.eql(after.d2);
    }
    try std.testing.expect(changed);
}

fn evaluateDirectRow(trace: *const trace_mod.Shard, row: usize, sink: *RootSink) !void {
    const main = readMain(trace, row);
    const previous_main = readMain(trace, offset(trace.domainSize(), row, -1));
    const previous_io = previous_main[trace_mod.Layout.io_a..trace_mod.Layout.state];
    const minus_two = readState(trace, offset(trace.domainSize(), row, -2));
    const minus_one = readState(trace, offset(trace.domainSize(), row, -1));
    const plus_one = readState(trace, offset(trace.domainSize(), row, 1));
    const plus_two = readState(trace, offset(trace.domainSize(), row, 2));
    const selectors = readSelectors(trace, row);
    const second = trace.preprocessedColumn(trace_mod.Layout.second_active)[
        trace_mod.committedRow(row, trace.log_size)
    ];
    return direct.evaluateGeneric(
        M31,
        &main,
        previous_io,
        &minus_two,
        &minus_one,
        &plus_one,
        &plus_two,
        &selectors,
        second,
        sink,
    );
}

fn readMain(trace: *const trace_mod.Shard, row: usize) [trace_mod.Layout.main_columns]M31 {
    var result: [trace_mod.Layout.main_columns]M31 = undefined;
    for (&result, 0..) |*value, column| value.* = trace.mainAt(column, row);
    return result;
}

fn readState(trace: *const trace_mod.Shard, row: usize) [witness.state_cell_count]M31 {
    var result: [witness.state_cell_count]M31 = undefined;
    for (&result, 0..) |*value, cell| value.* =
        trace.mainAt(trace_mod.Layout.state + cell, row);
    return result;
}

fn readSelectors(trace: *const trace_mod.Shard, row: usize) [witness.row_count]M31 {
    var result: [witness.row_count]M31 = undefined;
    const committed = trace_mod.committedRow(row, trace.log_size);
    for (&result, 0..) |*value, group| value.* =
        trace.preprocessedColumn(trace_mod.Layout.row_group + group)[committed];
    return result;
}

fn offset(size: usize, row: usize, delta: isize) usize {
    return @intCast(@mod(
        @as(isize, @intCast(row)) + delta,
        @as(isize, @intCast(size)),
    ));
}

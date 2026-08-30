//! Interaction-column recurrence, claim, and mutation tests.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const work_pool = @import("stwo_prover_engine").work_pool;
const authority = @import("keccakf_authority.zig");
const call_buffer = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const counters_mod = @import("keccakf_multiplicities.zig");
const subject = @import("keccakf_interaction.zig");
const plan = @import("keccakf_interaction_plan.zig");
const relations_mod = @import("keccakf_relations.zig");
const trace_mod = @import("keccakf_trace.zig");
const logup = @import("../logup.zig");

fn record(seed: u32) call_buffer.Record {
    var input: [call_buffer.word_count]u32 = undefined;
    for (&input, 0..) |*word, index| word.* = seed +% @as(u32, @intCast(13 * index));
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
        .state_ptr = 0x2000,
        .pointer_register = 5,
        .pointer_previous_clock = 0,
        .input = input,
        .output = output,
        .memory_previous_clocks = @splat(0),
    };
}

test "keccakf interaction: all 961 compact recurrences close over odd padding" {
    const records = [_]call_buffer.Record{ record(1), record(2), record(3) };
    var counters = try counters_mod.Counters.init(std.testing.allocator);
    defer counters.deinit();
    var trace = try trace_mod.generateShard(std.testing.allocator, &records, 0, &counters);
    defer trace.deinit();
    const relations = relations_mod.Relations.dummy();
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    var result = try subject.generate(std.testing.allocator, &trace, &relations, &pool);
    defer result.deinit(std.testing.allocator);

    for (0..trace.domainSize()) |logical_row| {
        const main = subject.readMain(&trace, logical_row);
        const next = subject.readState(&trace, (logical_row + 1) % trace.domainSize());
        const selectors = subject.readSelectors(&trace, logical_row);
        const pairs = try plan.rowPairsBase(&main, &next, &selectors, &relations);
        const current_row = trace_mod.committedRow(logical_row, trace.log_size);
        const previous_row = trace_mod.committedRow(
            (logical_row + trace.domainSize() - 1) % trace.domainSize(),
            trace.log_size,
        );
        for (pairs, 0..) |pair, batch| {
            const current = secureAt(&result.columns, batch, current_row);
            const previous = secureAt(&result.columns, batch, previous_row);
            const is_first = QM31.fromBase(M31.fromCanonical(
                @intFromBool(logical_row == 0),
            ));
            try std.testing.expect(logup.pairConstraint(
                current,
                previous,
                is_first,
                result.claims[batch],
                pair,
            ).isZero());
        }
    }

    const row = trace_mod.committedRow(2, trace.log_size);
    result.columns[0][row] = result.columns[0][row].add(M31.one());
    const main = subject.readMain(&trace, 2);
    const next = subject.readState(&trace, 3);
    const selectors = subject.readSelectors(&trace, 2);
    const pairs = try plan.rowPairsBase(&main, &next, &selectors, &relations);
    const current = secureAt(&result.columns, 0, row);
    const previous = secureAt(
        &result.columns,
        0,
        trace_mod.committedRow(1, trace.log_size),
    );
    try std.testing.expect(!logup.pairConstraint(
        current,
        previous,
        QM31.zero(),
        result.claims[0],
        pairs[0],
    ).isZero());
}

fn secureAt(
    columns: *const [subject.column_count][]M31,
    batch: usize,
    row: usize,
) QM31 {
    return QM31.fromM31(
        columns[4 * batch][row],
        columns[4 * batch + 1][row],
        columns[4 * batch + 2][row],
        columns[4 * batch + 3][row],
    );
}

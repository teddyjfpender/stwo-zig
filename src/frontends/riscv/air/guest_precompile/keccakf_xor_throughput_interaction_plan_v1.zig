//! Hybrid Keccak LogUp plan: compact chi plus three-position xor5 rows.
//!
//! This profile is useful only after the larger xor table is amortized.  It
//! retains the compact one-output chi semantics and batches three independent
//! parity positions into each xor5 lookup.  Table, state-I/O, and caller
//! batches occupy disjoint ranges so their public claimed sums remain typed.

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const logup = @import("../logup.zig");
const authority = @import("keccakf_authority.zig");
const caller = @import("keccakf_caller.zig");
const relations_mod = @import("keccakf_relations.zig");
const throughput = @import("keccakf_throughput_interaction_plan_v1.zig");
const trace = @import("keccakf_trace.zig");
const witness = @import("keccakf_witness.zig");

pub const production_active = false;
pub const chi_event_count: usize =
    authority.geometry.compact.chi_lookups_per_round;
pub const xor5_event_count: usize = authority.geometry.xor5_lookups_per_round;
pub const table_event_count: usize = chi_event_count + xor5_event_count;
pub const table_batch_count: usize = (table_event_count + 1) / 2;
pub const io_batch_count: usize = 1;
pub const permutation_batch_count: usize = table_batch_count + io_batch_count;
pub const batch_count: usize = permutation_batch_count + caller.batch_count;
pub const interaction_column_count: usize = 4 * batch_count;

pub const Error = error{InvalidTraceShape};

pub fn rowPairsBase(
    main: []const M31,
    next_state: []const M31,
    caller_output_state: []const M31,
    selectors: []const M31,
    relations: *const relations_mod.Relations,
) Error![batch_count]logup.RowPair {
    return rowPairsGeneric(
        M31,
        main,
        next_state,
        caller_output_state,
        selectors,
        relations,
    );
}

pub fn rowPairs(
    main: []const QM31,
    next_state: []const QM31,
    caller_output_state: []const QM31,
    selectors: []const QM31,
    relations: *const relations_mod.Relations,
) Error![batch_count]logup.RowPair {
    return rowPairsGeneric(
        QM31,
        main,
        next_state,
        caller_output_state,
        selectors,
        relations,
    );
}

pub fn rowPairsGeneric(
    comptime S: type,
    main: []const S,
    next_state: []const S,
    caller_output_state: []const S,
    selectors: []const S,
    relations: anytype,
) Error![batch_count]logup.RowPairFor(InteractionScalar(S)) {
    if (main.len != trace.Layout.main_columns or
        next_state.len != witness.state_cell_count or
        caller_output_state.len != witness.state_cell_count or
        selectors.len != witness.row_count)
    {
        return error.InvalidTraceShape;
    }
    var round_active = S.zero();
    for (selectors[2..26]) |selector| round_active = round_active.add(selector);
    const request = lift(S, round_active).neg();
    var table_events: [table_event_count]logup.RowPairFor(
        InteractionScalar(S),
    ) = undefined;

    for (0..chi_event_count) |event| {
        const x = event % 5;
        const position = event / 5;
        const y = position / authority.lane_bits;
        const z = position % authority.lane_bits;
        var tuple: relations_mod.ChiTupleFor(S) = undefined;
        for (0..authority.geometry.compact.chi_input_count) |offset| {
            const output_x = (x + offset) % 5;
            const source_x = (output_x + 3 * y) % 5;
            const source_y = output_x;
            const rotation = authority.rho_offsets[source_x][source_y];
            const source_z = (z + authority.lane_bits - rotation) %
                authority.lane_bits;
            tuple[offset] = main[
                trace.Layout.state + stateCell(source_x, source_y, source_z)
            ].add(main[
                trace.Layout.parity +
                    ((source_x + 4) % 5) * authority.lane_bits + source_z
            ]).add(main[
                trace.Layout.parity +
                    ((source_x + 1) % 5) * authority.lane_bits +
                    (source_z + 63) % 64
            ]);
        }
        var iota = S.zero();
        if (x == 0 and y == 0) for (0..authority.round_count) |round| {
            if (((authority.round_constants[round] >> @intCast(z)) & 1) != 0)
                iota = iota.add(selectors[2 + round]);
        };
        tuple[3] = iota;
        tuple[4] = next_state[stateCell(x, y, z)];
        tuple[5] = S.zero();
        table_events[event] = logup.RowPairFor(InteractionScalar(S)).single(
            request,
            denominator(S, tuple, relations.chi),
        );
    }
    for (0..xor5_event_count) |event| {
        table_events[chi_event_count + event] = logup.RowPairFor(
            InteractionScalar(S),
        ).single(
            request,
            denominator(
                S,
                try throughput.xor5Tuple(S, main, event),
                relations.xor5,
            ),
        );
    }

    var result: [batch_count]logup.RowPairFor(InteractionScalar(S)) = undefined;
    for (result[0..table_batch_count], 0..) |*pair, batch| {
        const first = 2 * batch;
        pair.* = if (first + 1 < table_event_count) .{
            .n1 = table_events[first].n1,
            .d1 = table_events[first].d1,
            .n2 = table_events[first + 1].n1,
            .d2 = table_events[first + 1].d1,
        } else table_events[first];
    }

    var io_a: relations_mod.IoTupleFor(S) = undefined;
    var io_b: relations_mod.IoTupleFor(S) = undefined;
    for (&io_a, &io_b, 0..) |*a, *b, field| {
        a.* = main[trace.Layout.io_a + field];
        b.* = main[trace.Layout.io_b + field];
    }
    result[table_batch_count] = .{
        .n1 = lift(S, selectors[0]).neg(),
        .d1 = denominator(S, io_a, relations.io),
        .n2 = lift(S, selectors[1].mul(main[trace.Layout.in_use_b])).neg(),
        .d2 = denominator(S, io_b, relations.io),
    };

    const caller_pairs = try caller.rowPairs(
        S,
        main[trace.Layout.caller..][0..caller.Layout.main_columns],
        main[trace.Layout.state..][0..witness.state_cell_count],
        caller_output_state,
        main[trace.Layout.io_a..][0..relations_mod.io_arity],
        main[trace.Layout.io_b..][0..relations_mod.io_arity],
        selectors[0],
        selectors[1],
        main[trace.Layout.in_use_b],
        relations,
    );
    @memcpy(result[permutation_batch_count..], &caller_pairs);
    return result;
}

fn denominator(
    comptime S: type,
    tuple: anytype,
    relation: anytype,
) InteractionScalar(S) {
    if (comptime S == M31) return relation.combineBase(tuple);
    if (comptime S == QM31) return relation.combineSecure(tuple);
    return relation.combine(tuple);
}

fn lift(comptime S: type, value: S) InteractionScalar(S) {
    if (comptime S == M31) return QM31.fromBase(value);
    return value;
}

pub fn InteractionScalar(comptime S: type) type {
    return if (S == M31) QM31 else S;
}

inline fn stateCell(x: usize, y: usize, z: usize) usize {
    return authority.laneIndex(x, y) * authority.lane_bits + z;
}

comptime {
    if (chi_event_count != 1_600 or xor5_event_count != 107 or
        table_event_count != 1_707 or table_batch_count != 854 or
        permutation_batch_count != 855 or batch_count != 935 or
        interaction_column_count != 3_740 or production_active)
    {
        @compileError("Keccak xor-throughput interaction geometry drifted");
    }
}

//! Compact 1,922-event / 961-batch LogUp plan for paired Keccak-f rows.
//!
//! Round rows request one tuple per chi output bit and one tuple per parity
//! position. The larger shard interaction is tiny at latency-oriented shard
//! sizes and reduces the fixed table universes by roughly 230x.

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const logup = @import("../logup.zig");
const authority = @import("keccakf_authority.zig");
const relations_mod = @import("keccakf_relations.zig");
const trace = @import("keccakf_trace.zig");
const witness = @import("keccakf_witness.zig");

pub const chi_event_count: usize = authority.geometry.compact.chi_lookups_per_round;
pub const xor5_event_count: usize = authority.geometry.compact.xor5_lookups_per_round;
pub const io_event_count: usize = 2;
pub const event_count: usize = chi_event_count + xor5_event_count + io_event_count;
pub const batch_count: usize = (event_count + 1) / 2;
pub const interaction_column_count: usize = 4 * batch_count;

pub const Error = error{InvalidTraceShape};

pub fn rowPairs(
    main: []const QM31,
    next_state: []const QM31,
    selectors: []const QM31,
    relations: *const relations_mod.Relations,
) Error![batch_count]logup.RowPair {
    return rowPairsFor(QM31, main, next_state, selectors, relations);
}

pub fn rowPairsBase(
    main: []const M31,
    next_state: []const M31,
    selectors: []const M31,
    relations: *const relations_mod.Relations,
) Error![batch_count]logup.RowPair {
    return rowPairsFor(M31, main, next_state, selectors, relations);
}

fn rowPairsFor(
    comptime S: type,
    main: []const S,
    next_state: []const S,
    selectors: []const S,
    relations: *const relations_mod.Relations,
) Error![batch_count]logup.RowPair {
    if (main.len != trace.Layout.main_columns or
        next_state.len != witness.state_cell_count or
        selectors.len != witness.row_count)
    {
        return error.InvalidTraceShape;
    }
    var round_active = S.zero();
    for (selectors[2..26]) |selector| round_active = round_active.add(selector);
    const request = lift(S, round_active).neg();
    var events: [event_count]logup.RowPair = undefined;

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
                trace.Layout.state + stateCell(
                    source_x,
                    source_y,
                    source_z,
                )
            ].add(main[
                trace.Layout.parity +
                    ((source_x + 4) % 5) * authority.lane_bits + source_z
            ])
                .add(main[
                trace.Layout.parity +
                    ((source_x + 1) % 5) * authority.lane_bits +
                    (source_z + 63) % 64
            ]);
        }
        var iota = S.zero();
        if (x == 0 and y == 0) for (0..authority.round_count) |round| {
            if (((authority.round_constants[round] >> @intCast(z)) & 1) != 0) {
                iota = iota.add(selectors[2 + round]);
            }
        };
        tuple[3] = iota;
        tuple[4] = next_state[stateCell(x, y, z)];
        tuple[5] = S.zero();
        events[event] = logup.RowPair.single(
            request,
            denominator(S, tuple, relations.chi),
        );
    }

    for (0..xor5_event_count) |event| {
        var tuple: relations_mod.Xor5TupleFor(S) = undefined;
        const x = event / authority.lane_bits;
        const z = event % authority.lane_bits;
        for (0..5) |y| tuple[y] =
            main[trace.Layout.state + stateCell(x, y, z)];
        tuple[5] = main[trace.Layout.parity + event];
        events[chi_event_count + event] = logup.RowPair.single(
            request,
            denominator(S, tuple, relations.xor5),
        );
    }

    var io_a_tuple: relations_mod.IoTupleFor(S) = undefined;
    var io_b_tuple: relations_mod.IoTupleFor(S) = undefined;
    for (&io_a_tuple, &io_b_tuple, 0..) |*a, *b, field| {
        a.* = main[trace.Layout.io_a + field];
        b.* = main[trace.Layout.io_b + field];
    }
    events[event_count - 2] = logup.RowPair.single(
        lift(S, selectors[0]).neg(),
        denominator(S, io_a_tuple, relations.io),
    );
    events[event_count - 1] = logup.RowPair.single(
        lift(S, selectors[1].mul(main[trace.Layout.in_use_b])).neg(),
        denominator(S, io_b_tuple, relations.io),
    );

    var result: [batch_count]logup.RowPair = undefined;
    for (&result, 0..) |*pair, batch| {
        const first = 2 * batch;
        pair.* = if (first + 1 < event_count) .{
            .n1 = events[first].n1,
            .d1 = events[first].d1,
            .n2 = events[first + 1].n1,
            .d2 = events[first + 1].d1,
        } else events[first];
    }
    return result;
}

fn denominator(
    comptime S: type,
    tuple: anytype,
    relation: anytype,
) QM31 {
    if (comptime S == M31) return relation.combineBase(tuple);
    if (comptime S == QM31) return relation.combineSecure(tuple);
    @compileError("Keccak interaction supports M31 and QM31 rows");
}

fn lift(comptime S: type, value: S) QM31 {
    if (comptime S == M31) return QM31.fromBase(value);
    if (comptime S == QM31) return value;
    @compileError("Keccak interaction supports M31 and QM31 rows");
}

fn mulSmall(comptime S: type, value: S, coefficient: u32) S {
    if (comptime S == M31) return value.mul(M31.fromCanonical(coefficient));
    if (comptime S == QM31) return value.mulM31(M31.fromCanonical(coefficient));
    @compileError("Keccak interaction supports M31 and QM31 rows");
}

inline fn stateCell(x: usize, y: usize, z: usize) usize {
    return authority.laneIndex(x, y) * authority.lane_bits + z;
}

comptime {
    if (event_count != 1922 or batch_count != 961 or
        interaction_column_count != 3844)
    {
        @compileError("Keccak-f interaction geometry drifted");
    }
}

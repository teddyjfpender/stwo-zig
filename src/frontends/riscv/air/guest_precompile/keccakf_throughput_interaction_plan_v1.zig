//! High-throughput LogUp plan for the paired Keccak-f trace.
//!
//! Five chi outputs share one lookup and three parity positions share one
//! lookup.  The trace and caller semantics are byte-identical to the compact
//! profile; only the verifier-program-bound lookup interpretation changes.

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const logup = @import("../logup.zig");
const authority = @import("keccakf_authority.zig");
const caller = @import("keccakf_caller.zig");
const relations_mod = @import("keccakf_relations.zig");
const trace = @import("keccakf_trace.zig");
const witness = @import("keccakf_witness.zig");

pub const chi_event_count: usize = authority.geometry.chi_lookups_per_round;
pub const xor5_event_count: usize = authority.geometry.xor5_lookups_per_round;
pub const io_event_count: usize = 2;
pub const permutation_event_count: usize = chi_event_count + xor5_event_count +
    io_event_count;
pub const permutation_batch_count: usize = (permutation_event_count + 1) / 2;
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
    var events: [permutation_event_count]logup.RowPairFor(
        InteractionScalar(S),
    ) = undefined;

    for (0..chi_event_count) |event| {
        events[event] = logup.RowPairFor(InteractionScalar(S)).single(
            request,
            denominator(
                S,
                try chiTuple(S, main, next_state, selectors, event),
                relations.chi,
            ),
        );
    }
    for (0..xor5_event_count) |event| {
        events[chi_event_count + event] = logup.RowPairFor(
            InteractionScalar(S),
        ).single(
            request,
            denominator(S, try xor5Tuple(S, main, event), relations.xor5),
        );
    }

    var io_a: relations_mod.IoTupleFor(S) = undefined;
    var io_b: relations_mod.IoTupleFor(S) = undefined;
    for (&io_a, &io_b, 0..) |*a, *b, field| {
        a.* = main[trace.Layout.io_a + field];
        b.* = main[trace.Layout.io_b + field];
    }
    events[permutation_event_count - 2] = logup.RowPairFor(
        InteractionScalar(S),
    ).single(
        lift(S, selectors[0]).neg(),
        denominator(S, io_a, relations.io),
    );
    events[permutation_event_count - 1] = logup.RowPairFor(
        InteractionScalar(S),
    ).single(
        lift(S, selectors[1].mul(main[trace.Layout.in_use_b])).neg(),
        denominator(S, io_b, relations.io),
    );

    var result: [batch_count]logup.RowPairFor(InteractionScalar(S)) = undefined;
    for (result[0..permutation_batch_count], 0..) |*pair, batch| {
        const first = 2 * batch;
        pair.* = if (first + 1 < permutation_event_count) .{
            .n1 = events[first].n1,
            .d1 = events[first].d1,
            .n2 = events[first + 1].n1,
            .d2 = events[first + 1].d1,
        } else events[first];
    }
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

pub fn chiTuple(
    comptime S: type,
    main: []const S,
    next_state: []const S,
    selectors: []const S,
    event: usize,
) Error![6]S {
    if (main.len != trace.Layout.main_columns or
        next_state.len != witness.state_cell_count or
        selectors.len != witness.row_count or event >= chi_event_count)
    {
        return error.InvalidTraceShape;
    }
    const y = event / authority.lane_bits;
    const z = event % authority.lane_bits;
    var result: [6]S = undefined;
    var packed_value = S.zero();
    var power: u32 = 1;
    for (0..5) |x| {
        const source_x = (x + 3 * y) % 5;
        const source_y = x;
        const rotation = authority.rho_offsets[source_x][source_y];
        const source_z = (z + authority.lane_bits - rotation) %
            authority.lane_bits;
        const theta = main[
            trace.Layout.state + stateCell(source_x, source_y, source_z)
        ].add(main[
            trace.Layout.parity +
                ((source_x + 4) % 5) * authority.lane_bits + source_z
        ]).add(main[
            trace.Layout.parity +
                ((source_x + 1) % 5) * authority.lane_bits +
                (source_z + 63) % 64
        ]);
        packed_value = packed_value.add(mulSmall(S, theta, power));
        power *= authority.geometry.chi_input_radix;
        result[1 + x] = next_state[stateCell(x, y, z)];
    }
    if (y == 0) for (0..authority.round_count) |round| {
        if (((authority.round_constants[round] >> @intCast(z)) & 1) != 0) {
            packed_value = packed_value.add(mulSmall(
                S,
                selectors[2 + round],
                authority.geometry.chi_span,
            ));
        }
    };
    result[0] = packed_value;
    return result;
}

pub fn xor5Tuple(
    comptime S: type,
    main: []const S,
    event: usize,
) Error![6]S {
    if (main.len != trace.Layout.main_columns or event >= xor5_event_count)
        return error.InvalidTraceShape;
    var result: [6]S = @splat(S.zero());
    for (0..authority.geometry.xor5_batch) |offset| {
        const position = event * authority.geometry.xor5_batch + offset;
        if (position >= authority.geometry.parity_positions) continue;
        const x = position / authority.lane_bits;
        const z = position % authority.lane_bits;
        var sum = S.zero();
        for (0..5) |y| sum = sum.add(
            main[trace.Layout.state + stateCell(x, y, z)],
        );
        result[offset] = sum;
        result[authority.geometry.xor5_batch + offset] =
            main[trace.Layout.parity + position];
    }
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

fn mulSmall(comptime S: type, value: S, coefficient: u32) S {
    if (comptime S == M31) return value.mul(M31.fromCanonical(coefficient));
    if (comptime S == QM31) return value.mulM31(M31.fromCanonical(coefficient));
    return value.mul(S.fromBase(M31.fromCanonical(coefficient)));
}

pub fn InteractionScalar(comptime S: type) type {
    return if (S == M31) QM31 else S;
}

inline fn stateCell(x: usize, y: usize, z: usize) usize {
    return authority.laneIndex(x, y) * authority.lane_bits + z;
}

comptime {
    if (chi_event_count != 320 or xor5_event_count != 107 or
        permutation_event_count != 429 or permutation_batch_count != 215 or
        batch_count != 295 or interaction_column_count != 1_180)
    {
        @compileError("Keccak-f throughput interaction geometry drifted");
    }
}

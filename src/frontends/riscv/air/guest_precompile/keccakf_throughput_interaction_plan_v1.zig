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
const tuples = @import("keccakf_lookup_tuples.zig");

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
    return tuples.throughputChi(
        S,
        Scale(S).apply,
        main[trace.Layout.state..][0..witness.state_cell_count],
        main[trace.Layout.parity..][0..authority.geometry.parity_positions],
        next_state,
        selectors[2..][0..authority.round_count],
        event,
    );
}

pub fn xor5Tuple(
    comptime S: type,
    main: []const S,
    event: usize,
) Error![6]S {
    if (main.len != trace.Layout.main_columns or event >= xor5_event_count)
        return error.InvalidTraceShape;
    return tuples.throughputXor5(
        S,
        main[trace.Layout.state..][0..witness.state_cell_count],
        main[trace.Layout.parity..][0..authority.geometry.parity_positions],
        event,
    );
}

fn Scale(comptime S: type) type {
    return struct {
        fn apply(value: S, coefficient: u32) S {
            return mulSmall(S, value, coefficient);
        }
    };
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

comptime {
    if (chi_event_count != 320 or xor5_event_count != 107 or
        permutation_event_count != 429 or permutation_batch_count != 215 or
        batch_count != 295 or interaction_column_count != 1_180)
    {
        @compileError("Keccak-f throughput interaction geometry drifted");
    }
}

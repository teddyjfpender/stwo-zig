//! Streaming direct constraints for the paired Keccak-f component.
//!
//! The evaluator never materializes its 6,043 roots.  A caller-provided sink
//! consumes them in canonical order, keeping both verifier and domain-worker
//! stacks bounded even though the component is intentionally wide.

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const caller = @import("keccakf_caller.zig");
const relations = @import("keccakf_relations.zig");
const trace = @import("keccakf_trace.zig");
const witness = @import("keccakf_witness.zig");

pub const maximum_constraint_degree: u8 = 3;
pub const activation_constraints: usize = 2;
pub const io_continuity_constraints: usize = 2 * relations.io_arity;
pub const inactive_b_constraints: usize = relations.io_arity;
pub const io_binding_constraints: usize = relations.state_chunk_count;
pub const boundary_boolean_constraints: usize = witness.state_cell_count;
pub const slice_glue_constraints: usize = witness.state_cell_count;
pub const terminal_parity_constraints: usize = witness.parity_cell_count;
pub const padding_constraints: usize = trace.Layout.main_columns;
pub const constraint_count: usize = activation_constraints +
    io_continuity_constraints + inactive_b_constraints +
    io_binding_constraints + boundary_boolean_constraints +
    slice_glue_constraints + terminal_parity_constraints +
    padding_constraints + caller.direct_constraint_count;

pub const Error = error{InvalidTraceShape};

/// All inputs are evaluations at the same trace point except the explicitly
/// named row offsets.  `previous` is needed only for the compact I/O block;
/// the four state windows own the two slice-glue boundaries.
pub fn evaluateGeneric(
    comptime S: type,
    main: []const S,
    previous_io: []const S,
    state_minus_two: []const S,
    state_minus_one: []const S,
    state_plus_one: []const S,
    state_plus_two: []const S,
    selectors: []const S,
    second_active: S,
    sink: anytype,
) Error!void {
    if (main.len != trace.Layout.main_columns or
        previous_io.len != 2 * relations.io_arity or
        state_minus_two.len != witness.state_cell_count or
        state_minus_one.len != witness.state_cell_count or
        state_plus_one.len != witness.state_cell_count or
        state_plus_two.len != witness.state_cell_count or
        selectors.len != witness.row_count)
    {
        return error.InvalidTraceShape;
    }
    const one = S.one();
    var active = S.zero();
    for (selectors) |selector| active = active.add(selector);
    const continuation = active.sub(selectors[0]);
    const in_use_a = main[trace.Layout.in_use_a];
    const in_use_b = main[trace.Layout.in_use_b];
    sink.add(in_use_a.sub(active), 1);
    sink.add(in_use_b.sub(second_active), 1);

    for (0..2 * relations.io_arity) |field| {
        const column = trace.Layout.io_a + field;
        sink.add(continuation.mul(main[column].sub(previous_io[field])), 2);
    }
    const inactive_b = active.sub(second_active);
    for (0..relations.io_arity) |field| sink.add(
        inactive_b.mul(main[trace.Layout.io_b + field]),
        2,
    );

    const boundary_selector = selectors[0]
        .add(selectors[1])
        .add(selectors[27])
        .add(selectors[28]);
    for (0..relations.state_chunk_count) |chunk| {
        const packed_state = packCurrentStateChunk(S, main, chunk);
        const input_offset = 1 + chunk;
        const output_offset = 1 + relations.state_chunk_count + chunk;
        const binding = selectors[0].mul(
            main[trace.Layout.io_a + input_offset].sub(packed_state),
        ).add(selectors[1].mul(in_use_b).mul(
            main[trace.Layout.io_b + input_offset].sub(packed_state),
        )).add(selectors[27].mul(
            main[trace.Layout.io_a + output_offset].sub(packed_state),
        )).add(selectors[28].mul(in_use_b).mul(
            main[trace.Layout.io_b + output_offset].sub(packed_state),
        ));
        sink.add(binding, 3);
    }

    for (0..witness.state_cell_count) |cell| {
        const value = main[trace.Layout.state + cell];
        sink.add(boundary_selector.mul(value.mul(one.sub(value))), 3);
        const input_glue = value
            .sub(state_minus_two[cell])
            .sub(mulSmall(S, state_minus_one[cell], 8));
        const output_glue = value
            .sub(state_plus_one[cell])
            .sub(mulSmall(S, state_plus_two[cell], 8));
        sink.add(
            selectors[2].mul(input_glue).add(selectors[26].mul(output_glue)),
            2,
        );
    }

    const parity_zero_selector = boundary_selector.add(selectors[26]);
    for (0..witness.parity_cell_count) |cell| sink.add(
        parity_zero_selector.mul(main[trace.Layout.parity + cell]),
        2,
    );

    const padding = one.sub(active);
    for (main) |value| sink.add(padding.mul(value), 2);

    const caller_active = selectors[0].add(
        selectors[1].mul(in_use_b),
    );
    try caller.evaluateDirect(
        S,
        main[trace.Layout.caller..][0..caller.Layout.main_columns],
        caller_active,
        sink,
    );
}

fn packCurrentStateChunk(
    comptime S: type,
    main: []const S,
    chunk: usize,
) S {
    const first = chunk * relations.state_chunk_bits;
    const count = @min(
        relations.state_chunk_bits,
        witness.state_cell_count - first,
    );
    var result = S.zero();
    var coefficient: u32 = 1;
    for (0..count) |offset| {
        result = result.add(mulSmall(
            S,
            main[trace.Layout.state + first + offset],
            coefficient,
        ));
        coefficient <<= 1;
    }
    return result;
}

fn mulSmall(comptime S: type, value: S, coefficient: u32) S {
    if (comptime S == M31) return value.mul(M31.fromCanonical(coefficient));
    if (comptime S == QM31) return value.mulM31(M31.fromCanonical(coefficient));
    return value.mul(S.fromBase(M31.fromCanonical(coefficient)));
}

comptime {
    if (constraint_count != 6174 or maximum_constraint_degree != 3)
        @compileError("Keccak-f direct constraint geometry drifted");
}

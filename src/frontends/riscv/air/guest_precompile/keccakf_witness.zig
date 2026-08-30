//! Paired 29-row Keccak-f witness and direct constraint authority.
//!
//! One slot owns two calls. Boundary rows contain plain bits; the 25 round
//! groups contain `a + 8*b` sliced cells. Every nonlinear transition is routed
//! through the versioned chi/xor5 table functions in `keccakf_authority.zig`.
//! This module is field-independent on purpose: witness construction and all
//! semantic mutations are settled before a Stwo component commits columns.

const std = @import("std");
const authority = @import("keccakf_authority.zig");

pub const state_cell_count = authority.width_bits;
pub const parity_cell_count = authority.candidate.parity_positions;
pub const row_count = authority.candidate.rows_per_slot;

pub const Row = struct {
    in_use_a: u8 = 0,
    in_use_b: u8 = 0,
    state: [state_cell_count]u8 = @splat(0),
    parity: [parity_cell_count]u8 = @splat(0),
};

pub const Slot = struct {
    rows: [row_count]Row = @splat(.{}),
};

pub const Error = authority.Error || error{
    BoundaryNotBoolean,
    EmptySlotNotCanonical,
    InvalidActivation,
    InvalidChiTransition,
    InvalidParityNormalization,
    InvalidRoundState,
    InvalidSliceGlue,
    InvalidXor5Lookup,
};

pub fn buildSlot(input_a: ?authority.State, input_b: ?authority.State) Error!Slot {
    if (input_a == null and input_b != null) return error.InvalidActivation;
    var slot = Slot{};
    if (input_a == null) return slot;

    const trace_a = authority.buildTrace(input_a.?);
    const trace_b = authority.buildTrace(input_b orelse @splat(0));
    for (&slot.rows) |*row| {
        row.in_use_a = 1;
        row.in_use_b = @intFromBool(input_b != null);
    }

    writePlainState(&slot.rows[0].state, trace_a[0]);
    writePlainState(&slot.rows[1].state, trace_b[0]);
    for (0..authority.round_count + 1) |round_state| {
        const row = &slot.rows[2 + round_state];
        writeSlicedState(&row.state, trace_a[round_state], trace_b[round_state]);
        if (round_state != authority.round_count) {
            const columns_a = authority.ThetaColumns.init(trace_a[round_state]);
            const columns_b = authority.ThetaColumns.init(trace_b[round_state]);
            for (0..parity_cell_count) |position| {
                const x = position / authority.lane_bits;
                const z = position % authority.lane_bits;
                row.parity[position] = columns_a.parities[x][z] +
                    authority.candidate.slot_base * columns_b.parities[x][z];
            }
        }
    }
    writePlainState(&slot.rows[27].state, trace_a[authority.round_count]);
    writePlainState(&slot.rows[28].state, trace_b[authority.round_count]);
    return slot;
}

pub fn validateSlot(slot: *const Slot) Error!void {
    const active_a = slot.rows[0].in_use_a;
    const active_b = slot.rows[0].in_use_b;
    if (active_a > 1 or active_b > 1 or active_b > active_a)
        return error.InvalidActivation;
    for (slot.rows) |row| {
        if (row.in_use_a != active_a or row.in_use_b != active_b)
            return error.InvalidActivation;
    }
    if (active_a == 0) {
        const zero = Slot{};
        if (!std.meta.eql(slot.*, zero)) return error.EmptySlotNotCanonical;
        return;
    }

    try validateBoundary(&slot.rows[0].state);
    try validateBoundary(&slot.rows[1].state);
    try validateBoundary(&slot.rows[27].state);
    try validateBoundary(&slot.rows[28].state);
    for (0..state_cell_count) |cell| {
        if (slot.rows[2].state[cell] != slot.rows[0].state[cell] +
            authority.candidate.slot_base * slot.rows[1].state[cell])
        {
            return error.InvalidSliceGlue;
        }
        if (slot.rows[26].state[cell] != slot.rows[27].state[cell] +
            authority.candidate.slot_base * slot.rows[28].state[cell])
        {
            return error.InvalidSliceGlue;
        }
    }

    for (0..authority.round_count) |round| {
        try validateRound(slot, round);
    }
    for (slot.rows[26].parity) |value|
        if (value != 0) return error.InvalidRoundState;
}

fn validateRound(slot: *const Slot, round: usize) Error!void {
    const current = &slot.rows[2 + round];
    const next = &slot.rows[3 + round];

    for (0..parity_cell_count) |position| {
        const row = try compactXor5LookupRow(slot, round, position);
        const entry = authority.compactXor5TableEntry(row) catch
            return error.InvalidXor5Lookup;
        if (entry.output != current.parity[position])
            return error.InvalidParityNormalization;
    }

    for (0..5) |y| {
        for (0..authority.lane_bits) |z| {
            for (0..5) |x| {
                const table_row = try compactChiLookupRow(slot, round, x, y, z);
                const entry = authority.compactChiTableEntry(table_row) catch
                    return error.InvalidChiTransition;
                if (next.state[stateCell(x, y, z)] != entry.output)
                    return error.InvalidChiTransition;
            }
        }
    }
}

/// Canonical xor5 lookup row for one three-position parity batch.  The same
/// helper feeds validation, LogUp requests, and multiplicity accumulation so
/// those three authorities cannot silently disagree.
pub fn xor5LookupRow(
    slot: *const Slot,
    round: usize,
    first_position: usize,
) Error!u32 {
    if (round >= authority.round_count or first_position >= parity_cell_count)
        return error.InvalidXor5Lookup;
    const current = &slot.rows[2 + round];
    var sums: [authority.candidate.xor5_batch][2]u8 = @splat(.{ 0, 0 });
    for (0..authority.candidate.xor5_batch) |offset| {
        const position = first_position + offset;
        if (position >= parity_cell_count) continue;
        const x = position / authority.lane_bits;
        const z = position % authority.lane_bits;
        for (0..5) |y| {
            const decoded = decodeSlicedBit(current.state[stateCell(x, y, z)]) orelse
                return error.InvalidRoundState;
            sums[offset][0] += decoded[0];
            sums[offset][1] += decoded[1];
        }
    }
    return authority.xor5TableRow(sums) catch error.InvalidXor5Lookup;
}

/// Canonical chi lookup row for one five-bit output row.  Inputs are derived
/// only from committed current-state/parity cells and the public round index.
pub fn chiLookupRow(
    slot: *const Slot,
    round: usize,
    y: usize,
    z: usize,
) Error!u32 {
    if (round >= authority.round_count or y >= 5 or z >= authority.lane_bits)
        return error.InvalidChiTransition;
    const current = &slot.rows[2 + round];
    var theta_a: [5]u8 = undefined;
    var theta_b: [5]u8 = undefined;
    for (0..5) |x| {
        const source_x = (x + 3 * y) % 5;
        const source_y = x;
        const rotation = authority.rho_offsets[source_x][source_y];
        const source_z = (z + authority.lane_bits - rotation) % authority.lane_bits;
        const source = decodeSlicedBit(
            current.state[stateCell(source_x, source_y, source_z)],
        ) orelse return error.InvalidRoundState;
        const parity_left = decodeSlicedBit(current.parity[
            ((source_x + 4) % 5) * authority.lane_bits + source_z
        ]) orelse return error.InvalidParityNormalization;
        const parity_right = decodeSlicedBit(current.parity[
            ((source_x + 1) % 5) * authority.lane_bits + (source_z + 63) % 64
        ]) orelse return error.InvalidParityNormalization;
        theta_a[x] = source[0] + parity_left[0] + parity_right[0];
        theta_b[x] = source[1] + parity_left[1] + parity_right[1];
    }
    const iota = y == 0 and
        ((authority.round_constants[round] >> @intCast(z)) & 1) != 0;
    return authority.chiTableRow(theta_a, theta_b, iota) catch
        error.InvalidChiTransition;
}

/// Canonical compact parity lookup for one `(x,z)` position.
pub fn compactXor5LookupRow(
    slot: *const Slot,
    round: usize,
    position: usize,
) Error!u32 {
    if (round >= authority.round_count or position >= parity_cell_count)
        return error.InvalidXor5Lookup;
    const current = &slot.rows[2 + round];
    const x = position / authority.lane_bits;
    const z = position % authority.lane_bits;
    var input: [authority.candidate.compact.xor_input_count]u8 = undefined;
    for (&input, 0..) |*value, y| value.* = current.state[stateCell(x, y, z)];
    return authority.compactXor5TableRow(input) catch error.InvalidXor5Lookup;
}

/// Canonical compact chi lookup for one output bit of one paired execution.
pub fn compactChiLookupRow(
    slot: *const Slot,
    round: usize,
    x: usize,
    y: usize,
    z: usize,
) Error!u32 {
    if (round >= authority.round_count or x >= 5 or y >= 5 or
        z >= authority.lane_bits)
    {
        return error.InvalidChiTransition;
    }
    var theta: [authority.candidate.compact.chi_input_count]u8 = undefined;
    for (&theta, 0..) |*value, offset| value.* = slicedTheta(
        slot,
        round,
        (x + offset) % 5,
        y,
        z,
    );
    const iota = x == 0 and y == 0 and
        ((authority.round_constants[round] >> @intCast(z)) & 1) != 0;
    return authority.compactChiTableRow(theta, iota) catch
        error.InvalidChiTransition;
}

fn slicedTheta(
    slot: *const Slot,
    round: usize,
    x: usize,
    y: usize,
    z: usize,
) u8 {
    const current = &slot.rows[2 + round];
    const source_x = (x + 3 * y) % 5;
    const source_y = x;
    const rotation = authority.rho_offsets[source_x][source_y];
    const source_z = (z + authority.lane_bits - rotation) % authority.lane_bits;
    return current.state[stateCell(source_x, source_y, source_z)] +
        current.parity[((source_x + 4) % 5) * authority.lane_bits + source_z] +
        current.parity[
            ((source_x + 1) % 5) * authority.lane_bits +
                (source_z + 63) % 64
        ];
}

fn validateBoundary(cells: *const [state_cell_count]u8) Error!void {
    for (cells) |value| if (value > 1) return error.BoundaryNotBoolean;
}

fn writePlainState(cells: *[state_cell_count]u8, state: authority.State) void {
    for (0..5) |y| for (0..5) |x| for (0..authority.lane_bits) |z| {
        cells[stateCell(x, y, z)] = authority.bit(state, x, y, z);
    };
}

fn writeSlicedState(
    cells: *[state_cell_count]u8,
    state_a: authority.State,
    state_b: authority.State,
) void {
    for (0..5) |y| for (0..5) |x| for (0..authority.lane_bits) |z| {
        cells[stateCell(x, y, z)] = authority.bit(state_a, x, y, z) +
            authority.candidate.slot_base * authority.bit(state_b, x, y, z);
    };
}

inline fn stateCell(x: usize, y: usize, z: usize) usize {
    return authority.laneIndex(x, y) * authority.lane_bits + z;
}

inline fn decodeSlicedBit(value: u8) ?[2]u8 {
    const a = value % authority.candidate.slot_base;
    const b = value / authority.candidate.slot_base;
    if (a > 1 or b > 1) return null;
    return .{ a, b };
}

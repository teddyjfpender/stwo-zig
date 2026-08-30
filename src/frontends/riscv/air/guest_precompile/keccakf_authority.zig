//! Keccak-f[1600] semantic and candidate-AIR geometry authority.
//!
//! The execution ABI operates on 25 little-endian `u64` lanes in place.  This
//! module deliberately contains no prover or runner state: it is the small,
//! independently testable authority used to validate both before a Keccak
//! execution profile is admitted.
//!
//! The paired sliced witness follows the public two-operation construction
//! used by Polygon ZisK's Apache-2.0/MIT Keccak machine, independently restated
//! here for Stwo's typed-AIR and LogUp model.  A cell stores `a + 8*b`; theta's
//! five-bit sums are normalized by a 3-at-a-time table and one chi lookup owns
//! a complete five-bit row plus the iota bit.

const std = @import("std");

pub const lane_count: usize = 25;
pub const lane_bits: usize = 64;
pub const width_bits: usize = lane_count * lane_bits;
pub const round_count: usize = 24;
pub const State = [lane_count]u64;
pub const PermutationTrace = [round_count + 1]State;

pub const round_constants = [round_count]u64{
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
};

/// Rotation offsets indexed as `[x][y]` in Keccak's 5x5 lane grid.
pub const rho_offsets = [5][5]u6{
    .{ 0, 36, 3, 41, 18 },
    .{ 1, 44, 10, 45, 2 },
    .{ 62, 6, 43, 15, 61 },
    .{ 28, 55, 25, 21, 56 },
    .{ 27, 20, 39, 8, 14 },
};

pub const candidate = struct {
    pub const lanes_per_row: usize = 25;
    pub const rows_per_state: usize = lane_count / lanes_per_row;
    pub const operations_per_slot: usize = 2;
    pub const slot_base: u8 = 8;
    pub const state_groups: usize = 2 + (round_count + 1) + 2;
    pub const rows_per_slot: usize = state_groups * rows_per_state;
    pub const state_cells_per_row: usize = lanes_per_row * lane_bits;
    pub const parity_positions: usize = 5 * lane_bits;
    pub const parity_cells_per_row: usize =
        std.math.divCeil(usize, parity_positions, rows_per_state) catch unreachable;
    pub const xor5_batch: usize = 3;
    pub const xor5_radix: u32 = 36;
    pub const xor5_table_rows: usize = 36 * 36 * 36;
    pub const xor5_lookups_per_round: usize =
        std.math.divCeil(usize, parity_positions, xor5_batch) catch unreachable;
    pub const chi_digit_radix: u32 = 16;
    pub const chi_input_radix: u32 = 28;
    pub const chi_row_width: usize = 5;
    pub const chi_span: u32 = 28 * 28 * 28 * 28 * 28;
    pub const chi_table_rows: usize = 2 * 16 * 16 * 16 * 16 * 16;
    pub const chi_lookups_per_round: usize = 5 * lane_bits;
    pub const chi_lookups_per_slot: usize = round_count * chi_lookups_per_round;
    pub const xor5_lookups_per_slot: usize = round_count * xor5_lookups_per_round;

    /// Small/medium-proof geometry. One chi output and one parity position are
    /// checked per lookup, shrinking the fixed universes from 2^21/2^16 to
    /// 2^13/2^10 while retaining the paired `a + 8*b` witness encoding.
    pub const compact = struct {
        pub const chi_input_count: usize = 3;
        pub const chi_input_radix: u32 = 16;
        pub const chi_table_rows: usize = 2 * 16 * 16 * 16;
        pub const chi_lookups_per_round: usize = width_bits;
        pub const chi_lookups_per_slot: usize = round_count * @This().chi_lookups_per_round;
        pub const xor_input_count: usize = 5;
        pub const xor_input_radix: u32 = 4;
        pub const xor5_table_rows: usize = 4 * 4 * 4 * 4 * 4;
        pub const xor5_lookups_per_round: usize = parity_positions;
        pub const xor5_lookups_per_slot: usize = round_count * @This().xor5_lookups_per_round;
    };
    /// All-source LogUp coefficients must remain strictly below M31's modulus.
    /// Chi is the limiting bus, and an odd trailing operation still owns a
    /// complete paired slot.
    pub const maximum_slots: usize = (0x7fff_fffe) / compact.chi_lookups_per_slot;
    pub const maximum_calls: usize = operations_per_slot * maximum_slots;
};

pub const ThetaColumns = struct {
    sums: [5][lane_bits]u8,
    parities: [5][lane_bits]u8,

    pub fn init(state: State) ThetaColumns {
        var result = ThetaColumns{
            .sums = @splat(@splat(0)),
            .parities = @splat(@splat(0)),
        };
        for (0..5) |x| {
            for (0..lane_bits) |z| {
                var sum: u8 = 0;
                for (0..5) |y| sum += bit(state, x, y, z);
                result.sums[x][z] = sum;
                result.parities[x][z] = sum & 1;
            }
        }
        return result;
    }

    /// Integer theta output feeding chi position `(x,y,z)`, before reduction.
    /// Its range is `[0,3]`; parity is the actual Keccak bit.
    pub fn thetaOutputAtChiSource(
        self: *const ThetaColumns,
        state: State,
        x: usize,
        y: usize,
        z: usize,
    ) u8 {
        const source_x = (x + 3 * y) % 5;
        const source_y = x;
        const rotation = rho_offsets[source_x][source_y];
        const source_z = (z + lane_bits - rotation) % lane_bits;
        return bit(state, source_x, source_y, source_z) +
            self.parities[(source_x + 4) % 5][source_z] +
            self.parities[(source_x + 1) % 5][(source_z + 63) % 64];
    }
};

pub const ChiTableEntry = struct {
    packed_input: u32,
    output: [5]u8,
};

pub const Xor5TableEntry = struct {
    sliced_sums: [candidate.xor5_batch]u8,
    sliced_parities: [candidate.xor5_batch]u8,
};

pub const CompactChiTableEntry = struct {
    theta: [candidate.compact.chi_input_count]u8,
    iota: u8,
    output: u8,
};

pub const CompactXor5TableEntry = struct {
    input: [candidate.compact.xor_input_count]u8,
    output: u8,
};

pub const Error = error{
    InvalidChiDigit,
    InvalidChiRow,
    InvalidRound,
    InvalidXor5Digit,
    InvalidXor5Row,
    TraceInputMismatch,
    TraceRoundMismatch,
};

pub inline fn laneIndex(x: usize, y: usize) usize {
    return y * 5 + x;
}

pub inline fn bit(state: State, x: usize, y: usize, z: usize) u8 {
    return @truncate((state[laneIndex(x, y)] >> @intCast(z)) & 1);
}

pub fn applyRound(state: *State, round: usize) Error!void {
    if (round >= round_count) return error.InvalidRound;

    var columns = [_]u64{0} ** 5;
    for (0..5) |x| {
        for (0..5) |y| columns[x] ^= state[laneIndex(x, y)];
    }
    for (0..5) |x| {
        const delta = columns[(x + 4) % 5] ^
            std.math.rotl(u64, columns[(x + 1) % 5], 1);
        for (0..5) |y| state[laneIndex(x, y)] ^= delta;
    }

    var rho_pi: State = @splat(0);
    for (0..5) |x| {
        for (0..5) |y| {
            rho_pi[laneIndex(y, (2 * x + 3 * y) % 5)] =
                std.math.rotl(u64, state[laneIndex(x, y)], rho_offsets[x][y]);
        }
    }
    for (0..5) |y| {
        for (0..5) |x| {
            state[laneIndex(x, y)] = rho_pi[laneIndex(x, y)] ^
                (~rho_pi[laneIndex((x + 1) % 5, y)] &
                    rho_pi[laneIndex((x + 2) % 5, y)]);
        }
    }
    state[0] ^= round_constants[round];
}

pub fn permute(state: *State) void {
    for (0..round_count) |round| applyRound(state, round) catch unreachable;
}

pub fn buildTrace(input: State) PermutationTrace {
    var trace: PermutationTrace = undefined;
    trace[0] = input;
    for (0..round_count) |round| {
        trace[round + 1] = trace[round];
        applyRound(&trace[round + 1], round) catch unreachable;
    }
    return trace;
}

pub fn validateTrace(input: State, trace: *const PermutationTrace) Error!void {
    if (!std.mem.eql(u64, &input, &trace[0])) return error.TraceInputMismatch;
    for (0..round_count) |round| {
        var expected = trace[round];
        try applyRound(&expected, round);
        if (!std.mem.eql(u64, &expected, &trace[round + 1]))
            return error.TraceRoundMismatch;
    }
}

pub fn chiTableRow(theta_a: [5]u8, theta_b: [5]u8, iota: bool) Error!u32 {
    var row: u32 = 0;
    var x: usize = 5;
    while (x != 0) {
        x -= 1;
        if (theta_a[x] >= 4 or theta_b[x] >= 4) return error.InvalidChiDigit;
        row = row * candidate.chi_digit_radix + theta_a[x] + 4 * @as(u32, theta_b[x]);
    }
    if (iota) row += candidate.chi_digit_radix * candidate.chi_digit_radix *
        candidate.chi_digit_radix * candidate.chi_digit_radix * candidate.chi_digit_radix;
    return row;
}

pub fn chiTableEntry(row: u32) Error!ChiTableEntry {
    if (row >= candidate.chi_table_rows) return error.InvalidChiRow;
    const chi_half: u32 = candidate.chi_table_rows / 2;
    const iota: u8 = @intFromBool(row >= chi_half);
    var encoded = row % chi_half;
    var theta_a: [5]u8 = undefined;
    var theta_b: [5]u8 = undefined;
    var packed_input: u32 = @as(u32, iota) * candidate.chi_span;
    var power: u32 = 1;
    for (0..5) |x| {
        const digit: u8 = @truncate(encoded % candidate.chi_digit_radix);
        encoded /= candidate.chi_digit_radix;
        theta_a[x] = digit & 3;
        theta_b[x] = digit >> 2;
        packed_input += power * (theta_a[x] + candidate.slot_base * @as(u32, theta_b[x]));
        power *= candidate.chi_input_radix;
    }

    var output: [5]u8 = undefined;
    for (0..5) |x| {
        const next = (x + 1) % 5;
        const next2 = (x + 2) % 5;
        const out_a = (theta_a[x] + (1 - (theta_a[next] & 1)) *
            (theta_a[next2] & 1) + if (x == 0) iota else 0) & 1;
        const out_b = (theta_b[x] + (1 - (theta_b[next] & 1)) *
            (theta_b[next2] & 1) + if (x == 0) iota else 0) & 1;
        output[x] = out_a + candidate.slot_base * out_b;
    }
    return .{ .packed_input = packed_input, .output = output };
}

pub fn xor5TableRow(sums: [candidate.xor5_batch][2]u8) Error!u32 {
    var row: u32 = 0;
    var index: usize = candidate.xor5_batch;
    while (index != 0) {
        index -= 1;
        const sum_a = sums[index][0];
        const sum_b = sums[index][1];
        if (sum_a >= 6 or sum_b >= 6) return error.InvalidXor5Digit;
        row = row * candidate.xor5_radix + sum_a + 6 * @as(u32, sum_b);
    }
    return row;
}

pub fn xor5TableEntry(row: u32) Error!Xor5TableEntry {
    if (row >= candidate.xor5_table_rows) return error.InvalidXor5Row;
    var encoded = row;
    var result: Xor5TableEntry = undefined;
    for (0..candidate.xor5_batch) |index| {
        const digit: u8 = @truncate(encoded % candidate.xor5_radix);
        encoded /= candidate.xor5_radix;
        const sum_a = digit % 6;
        const sum_b = digit / 6;
        result.sliced_sums[index] = sum_a + candidate.slot_base * sum_b;
        result.sliced_parities[index] = (sum_a & 1) + candidate.slot_base * (sum_b & 1);
    }
    return result;
}

/// Compact one-output chi table. Each theta input stores two independent
/// values in `[0,3]` as `a + 8*b`; the table applies parity, chi, and iota to
/// both executions without expanding a five-output Cartesian product.
pub fn compactChiTableRow(
    theta: [candidate.compact.chi_input_count]u8,
    iota: bool,
) Error!u32 {
    var row: u32 = 0;
    var power: u32 = 1;
    for (theta) |value| {
        const a = value % candidate.slot_base;
        const b = value / candidate.slot_base;
        if (a >= 4 or b >= 4) return error.InvalidChiDigit;
        row += power * (a + 4 * @as(u32, b));
        power *= candidate.compact.chi_input_radix;
    }
    if (iota) row += power;
    return row;
}

pub fn compactChiTableEntry(row: u32) Error!CompactChiTableEntry {
    if (row >= candidate.compact.chi_table_rows) return error.InvalidChiRow;
    var encoded = row;
    var result: CompactChiTableEntry = undefined;
    for (&result.theta) |*value| {
        const digit: u8 = @truncate(encoded % candidate.compact.chi_input_radix);
        encoded /= candidate.compact.chi_input_radix;
        value.* = (digit & 3) + candidate.slot_base * (digit >> 2);
    }
    result.iota = @truncate(encoded);
    const a0 = result.theta[0] & 1;
    const a1 = result.theta[1] & 1;
    const a2 = result.theta[2] & 1;
    const b0 = (result.theta[0] / candidate.slot_base) & 1;
    const b1 = (result.theta[1] / candidate.slot_base) & 1;
    const b2 = (result.theta[2] / candidate.slot_base) & 1;
    result.output = (a0 ^ ((1 - a1) & a2) ^ result.iota) +
        candidate.slot_base * (b0 ^ ((1 - b1) & b2) ^ result.iota);
    return result;
}

/// Compact one-output parity table over five paired sliced input bits.
pub fn compactXor5TableRow(
    input: [candidate.compact.xor_input_count]u8,
) Error!u32 {
    var row: u32 = 0;
    var power: u32 = 1;
    for (input) |value| {
        const a = value % candidate.slot_base;
        const b = value / candidate.slot_base;
        if (a >= 2 or b >= 2) return error.InvalidXor5Digit;
        row += power * (a + 2 * @as(u32, b));
        power *= candidate.compact.xor_input_radix;
    }
    return row;
}

pub fn compactXor5TableEntry(row: u32) Error!CompactXor5TableEntry {
    if (row >= candidate.compact.xor5_table_rows) return error.InvalidXor5Row;
    var encoded = row;
    var result = CompactXor5TableEntry{ .input = undefined, .output = 0 };
    var a: u8 = 0;
    var b: u8 = 0;
    for (&result.input) |*value| {
        const digit: u8 = @truncate(encoded % candidate.compact.xor_input_radix);
        encoded /= candidate.compact.xor_input_radix;
        const bit_a = digit & 1;
        const bit_b = digit >> 1;
        value.* = bit_a + candidate.slot_base * bit_b;
        a ^= bit_a;
        b ^= bit_b;
    }
    result.output = a + candidate.slot_base * b;
    return result;
}

/// Validate every nonlinear/table boundary for two round traces.  This does
/// not merely recompute the output permutation: it proves that the candidate
/// paired witness decodes to both independent Keccak executions round by round.
pub fn validatePairedTraces(
    trace_a: *const PermutationTrace,
    trace_b: *const PermutationTrace,
) Error!void {
    try validateTrace(trace_a[0], trace_a);
    try validateTrace(trace_b[0], trace_b);
    for (0..round_count) |round| {
        const columns_a = ThetaColumns.init(trace_a[round]);
        const columns_b = ThetaColumns.init(trace_b[round]);

        var position: usize = 0;
        while (position < candidate.parity_positions) : (position += candidate.xor5_batch) {
            var sums: [candidate.xor5_batch][2]u8 = @splat(.{ 0, 0 });
            for (0..candidate.xor5_batch) |offset| {
                const current = position + offset;
                if (current >= candidate.parity_positions) continue;
                const x = current / lane_bits;
                const z = current % lane_bits;
                sums[offset] = .{ columns_a.sums[x][z], columns_b.sums[x][z] };
            }
            const normalized = try xor5TableEntry(try xor5TableRow(sums));
            for (0..candidate.xor5_batch) |offset| {
                const current = position + offset;
                const expected = if (current < candidate.parity_positions) blk: {
                    const x = current / lane_bits;
                    const z = current % lane_bits;
                    break :blk columns_a.parities[x][z] +
                        candidate.slot_base * columns_b.parities[x][z];
                } else 0;
                if (normalized.sliced_parities[offset] != expected)
                    return error.TraceRoundMismatch;
            }
        }

        for (0..5) |y| {
            for (0..lane_bits) |z| {
                var theta_a: [5]u8 = undefined;
                var theta_b: [5]u8 = undefined;
                for (0..5) |x| {
                    theta_a[x] = columns_a.thetaOutputAtChiSource(trace_a[round], x, y, z);
                    theta_b[x] = columns_b.thetaOutputAtChiSource(trace_b[round], x, y, z);
                }
                const iota = y == 0 and ((round_constants[round] >> @intCast(z)) & 1) != 0;
                const entry = try chiTableEntry(try chiTableRow(theta_a, theta_b, iota));
                for (0..5) |x| {
                    const expected = bit(trace_a[round + 1], x, y, z) +
                        candidate.slot_base * bit(trace_b[round + 1], x, y, z);
                    if (entry.output[x] != expected) return error.TraceRoundMismatch;
                }
            }
        }
    }
}

//! Pure compact and throughput Keccak lookup algebra shared by RV32 and RV64 adapters.
//! No opcode, runner, caller, placement, challenge or proof geometry is owned here.
const authority = @import("keccakf_authority.zig");
pub fn chi(comptime S: type, state: []const S, parity: []const S, next: []const S, round_selectors: []const S, event: usize) [6]S {
    const x = event % 5;
    const position = event / 5;
    const y = position / authority.lane_bits;
    const z = position % authority.lane_bits;
    var tuple: [6]S = undefined;
    for (0..authority.geometry.compact.chi_input_count) |offset| {
        const output_x = (x + offset) % 5;
        const source_x = (output_x + 3 * y) % 5;
        const source_y = output_x;
        const rotation = authority.rho_offsets[source_x][source_y];
        const source_z = (z + authority.lane_bits - rotation) % authority.lane_bits;
        tuple[offset] = state[cell(source_x, source_y, source_z)]
            .add(parity[((source_x + 4) % 5) * authority.lane_bits + source_z])
            .add(parity[((source_x + 1) % 5) * authority.lane_bits + (source_z + 63) % 64]);
    }
    var iota = S.zero();
    if (x == 0 and y == 0) for (0..authority.round_count) |round| {
        if (((authority.round_constants[round] >> @intCast(z)) & 1) != 0) iota = iota.add(round_selectors[round]);
    };
    tuple[3] = iota;
    tuple[4] = next[cell(x, y, z)];
    tuple[5] = S.zero();
    return tuple;
}
pub fn xor5(comptime S: type, state: []const S, parity: []const S, event: usize) [6]S {
    const x = event / authority.lane_bits;
    const z = event % authority.lane_bits;
    var tuple: [6]S = undefined;
    for (0..5) |y| tuple[y] = state[cell(x, y, z)];
    tuple[5] = parity[event];
    return tuple;
}
/// Throughput five-output chi row `(y,z)` (`keccakf_throughput_tables_v1.zig`):
/// tuple[0] packs the five theta values base 28 (`28^5 * 2 < p`) plus the iota
/// bit at `28^5`; tuple[1..6] are the five next-state cells `x = 0..4`.
/// `scale(value, constant)` multiplies by a small canonical constant.
pub fn throughputChi(comptime S: type, comptime scale: anytype, state: []const S, parity: []const S, next: []const S, round_selectors: []const S, event: usize) [6]S {
    const y = event / authority.lane_bits;
    const z = event % authority.lane_bits;
    var tuple: [6]S = undefined;
    var packed_value = S.zero();
    var power: u32 = 1;
    for (0..5) |x| {
        const source_x = (x + 3 * y) % 5;
        const source_y = x;
        const rotation = authority.rho_offsets[source_x][source_y];
        const source_z = (z + authority.lane_bits - rotation) % authority.lane_bits;
        const theta = state[cell(source_x, source_y, source_z)]
            .add(parity[((source_x + 4) % 5) * authority.lane_bits + source_z])
            .add(parity[((source_x + 1) % 5) * authority.lane_bits + (source_z + 63) % 64]);
        packed_value = packed_value.add(scale(theta, power));
        power *= authority.geometry.chi_input_radix;
        tuple[1 + x] = next[cell(x, y, z)];
    }
    if (y == 0) for (0..authority.round_count) |round| {
        if (((authority.round_constants[round] >> @intCast(z)) & 1) != 0) packed_value = packed_value.add(scale(round_selectors[round], authority.geometry.chi_span));
    };
    tuple[0] = packed_value;
    return tuple;
}
/// Throughput xor5 row: three column sums then their three parities. The
/// final event's positions beyond 320 are the all-zero table entry.
pub fn throughputXor5(comptime S: type, state: []const S, parity: []const S, event: usize) [6]S {
    var tuple: [6]S = @splat(S.zero());
    for (0..authority.geometry.xor5_batch) |offset| {
        const position = event * authority.geometry.xor5_batch + offset;
        if (position >= authority.geometry.parity_positions) continue;
        const x = position / authority.lane_bits;
        const z = position % authority.lane_bits;
        var sum = S.zero();
        for (0..5) |y| sum = sum.add(state[cell(x, y, z)]);
        tuple[offset] = sum;
        tuple[authority.geometry.xor5_batch + offset] = parity[position];
    }
    return tuple;
}
inline fn cell(x: usize, y: usize, z: usize) usize {
    return authority.laneIndex(x, y) * authority.lane_bits + z;
}

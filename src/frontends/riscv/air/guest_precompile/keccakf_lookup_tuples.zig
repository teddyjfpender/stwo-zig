//! Pure compact Keccak lookup algebra shared by RV32 and RV64 adapters.
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
inline fn cell(x: usize, y: usize, z: usize) usize {
    return authority.laneIndex(x, y) * authority.lane_bits + z;
}

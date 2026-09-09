//! One Poseidon2 round schedule for degree-three witness and AIR layouts.
const M31 = @import("stwo_core").fields.m31.M31;
const constants = @import("poseidon2_constants.zig");
const legacy = @import("poseidon2_air.zig");
const WIDTH = legacy.WIDTH;

fn base(comptime S: type, word: u32) S {
    if (S == M31) return M31.fromCanonical(word);
    return S.fromBase(M31.fromCanonical(word));
}

pub fn external(comptime S: type, state: *[WIDTH]S) void {
    if (S == M31) return legacy.externalMatrixM31(state);
    legacy.externalMatrixSecure(S, state);
}

/// One round schedule shared by witness construction and polynomial replay.
pub fn walk(comptime S: type, state: *[WIDTH]S, context: anytype) void {
    external(S, state);
    for (constants.EXTERNAL_ROUND[0..4]) |round| fullRound(S, state, context, round);
    for (constants.INTERNAL_ROUND) |constant| {
        state[0] = context.sbox(state[0].add(base(S, constant)));
        if (S == M31) legacy.internalMatrixM31(state, constants.INTERNAL_MATRIX) else legacy.internalMatrixSecure(S, state, constants.INTERNAL_MATRIX);
    }
    for (constants.EXTERNAL_ROUND[4..8]) |round| fullRound(S, state, context, round);
}

fn fullRound(comptime S: type, state: *[WIDTH]S, context: anytype, round: [WIDTH]u32) void {
    for (state, round) |*value, constant| value.* = context.sbox(value.add(base(S, constant)));
    external(S, state);
}

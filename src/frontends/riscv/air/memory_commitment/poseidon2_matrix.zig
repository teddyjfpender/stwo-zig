//! Shared scalar Poseidon2 matrix equations; no witness or prover dependencies.
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
pub const WIDTH: usize = 16;

pub fn externalMatrixM31(state: *[WIDTH]M31) void {
    externalMatrixSecure(M31, state);
}

pub fn externalMatrixSecure(comptime S: type, state: *[WIDTH]S) void {
    for (0..4) |block| {
        const start = 4 * block;
        const mixed = m4Secure(S, state[start..][0..4].*);
        @memcpy(state[start..][0..4], &mixed);
    }
    for (0..4) |lane| {
        const sum = state[lane].add(state[lane + 4]).add(state[lane + 8]).add(state[lane + 12]);
        for (0..4) |block| {
            const index = 4 * block + lane;
            state[index] = state[index].add(sum);
        }
    }
}

pub fn m4M31(input: [4]M31) [4]M31 {
    return m4Secure(M31, input);
}

pub fn m4Secure(comptime S: type, input: [4]S) [4]S {
    const t0 = input[0].add(input[1]);
    const t1 = input[2].add(input[3]);
    const t2 = input[1].add(input[1]).add(t1);
    const t3 = input[3].add(input[3]).add(t0);
    const t4 = t1.add(t1).add(t1.add(t1)).add(t3);
    const t5 = t0.add(t0).add(t0.add(t0)).add(t2);
    return .{ t3.add(t5), t5, t2.add(t4), t4 };
}

pub fn internalMatrixM31(state: *[WIDTH]M31, diagonal: [WIDTH]u32) void {
    var sum = M31.zero();
    for (state) |value| sum = sum.add(value);
    for (state, diagonal) |*value, coefficient| {
        value.* = value.mul(M31.fromCanonical(coefficient)).add(sum);
    }
}

pub fn internalMatrixSecure(comptime S: type, state: *[WIDTH]S, diagonal: [WIDTH]u32) void {
    var sum = S.zero();
    for (state) |value| sum = sum.add(value);
    for (state, diagonal) |*value, coefficient| {
        value.* = if (S == QM31)
            value.mulM31(M31.fromCanonical(coefficient)).add(sum)
        else
            value.mul(S.fromBase(M31.fromCanonical(coefficient))).add(sum);
    }
}

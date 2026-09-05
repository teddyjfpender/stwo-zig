//! Minimal pinned Stark-V Poseidon2-M31 permutation for sparse memory roots.
//!
//! Memory commitment nodes hash two scalar children in lanes 0 and 1 and use
//! output lane 0. This deliberately excludes trace generation; the Poseidon2
//! AIR component must separately consume the same `(input, output)` calls.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const constants = @import("poseidon2_constants.zig");

pub const WIDTH: usize = 16;
pub const State = [WIDTH]M31;
pub const DEFAULT_HASHES = constants.DEFAULT_HASHES;

pub fn hashPair(left: u32, right: u32) u32 {
    var state: State = .{M31.zero()} ** WIDTH;
    state[0] = M31.fromU64(left);
    state[1] = M31.fromU64(right);
    permute(&state);
    return state[0].v;
}

/// Four independent memory-tree node hashes evaluated in AArch64 AdvSIMD
/// lanes. This is byte-for-byte equivalent to four `hashPair` calls; it only
/// changes the execution schedule used by bulk continuation-root builders.
pub fn hashPairs4(left: [4]u32, right: [4]u32) [4]u32 {
    var state: [WIDTH]m31.Vec4u32 =
        .{@as(m31.Vec4u32, @splat(0))} ** WIDTH;
    state[0] = @bitCast(left);
    state[1] = @bitCast(right);
    permute4(&state);
    return @bitCast(state[0]);
}

pub fn permute(state: *State) void {
    externalMatrix(state);
    for (constants.EXTERNAL_ROUND[0..4]) |round| fullRound(state, round);
    for (constants.INTERNAL_ROUND) |round_constant| {
        state[0] = sbox(state[0].add(M31.fromCanonical(round_constant)));
        internalMatrix(state);
    }
    for (constants.EXTERNAL_ROUND[4..8]) |round| fullRound(state, round);
}

fn fullRound(state: *State, round: [WIDTH]u32) void {
    for (state, round) |*value, constant| {
        value.* = sbox(value.add(M31.fromCanonical(constant)));
    }
    externalMatrix(state);
}

inline fn sbox(value: M31) M31 {
    return value.square().square().mul(value);
}

fn externalMatrix(state: *State) void {
    for (0..4) |block| {
        const base = 4 * block;
        const output = m4(state[base..][0..4].*);
        @memcpy(state[base..][0..4], &output);
    }

    for (0..4) |lane| {
        const sum = state[lane]
            .add(state[lane + 4])
            .add(state[lane + 8])
            .add(state[lane + 12]);
        for (0..4) |block| {
            const index = 4 * block + lane;
            state[index] = state[index].add(sum);
        }
    }
}

fn m4(input: [4]M31) [4]M31 {
    const t0 = input[0].add(input[1]);
    const t1 = input[2].add(input[3]);
    const t2 = input[1].add(input[1]).add(t1);
    const t3 = input[3].add(input[3]).add(t0);
    const t4 = t1.add(t1).add(t1.add(t1)).add(t3);
    const t5 = t0.add(t0).add(t0.add(t0)).add(t2);
    return .{ t3.add(t5), t5, t2.add(t4), t4 };
}

fn internalMatrix(state: *State) void {
    var sum = M31.zero();
    for (state) |value| sum = sum.add(value);
    for (state, constants.INTERNAL_MATRIX) |*value, diagonal| {
        value.* = value.mul(M31.fromCanonical(diagonal)).add(sum);
    }
}

fn permute4(state: *[WIDTH]m31.Vec4u32) void {
    externalMatrix4(state);
    for (constants.EXTERNAL_ROUND[0..4]) |round| fullRound4(state, round);
    for (constants.INTERNAL_ROUND) |round_constant| {
        const constant: m31.Vec4u32 = @splat(round_constant);
        state[0] = sbox4(m31.addVec4(state[0], constant));
        internalMatrix4(state);
    }
    for (constants.EXTERNAL_ROUND[4..8]) |round| fullRound4(state, round);
}

fn fullRound4(
    state: *[WIDTH]m31.Vec4u32,
    round: [WIDTH]u32,
) void {
    for (state, round) |*value, constant| {
        const constant_vector: m31.Vec4u32 = @splat(constant);
        value.* = sbox4(m31.addVec4(value.*, constant_vector));
    }
    externalMatrix4(state);
}

inline fn sbox4(value: m31.Vec4u32) m31.Vec4u32 {
    const squared = m31.mulVec4(value, value);
    return m31.mulVec4(m31.mulVec4(squared, squared), value);
}

fn externalMatrix4(state: *[WIDTH]m31.Vec4u32) void {
    for (0..4) |block| {
        const base = 4 * block;
        const output = m4Vec(state[base..][0..4].*);
        @memcpy(state[base..][0..4], &output);
    }
    for (0..4) |lane| {
        const sum = m31.addVec4(
            m31.addVec4(state[lane], state[lane + 4]),
            m31.addVec4(state[lane + 8], state[lane + 12]),
        );
        for (0..4) |block| {
            const index = 4 * block + lane;
            state[index] = m31.addVec4(state[index], sum);
        }
    }
}

fn m4Vec(input: [4]m31.Vec4u32) [4]m31.Vec4u32 {
    const t0 = m31.addVec4(input[0], input[1]);
    const t1 = m31.addVec4(input[2], input[3]);
    const t2 = m31.addVec4(m31.addVec4(input[1], input[1]), t1);
    const t3 = m31.addVec4(m31.addVec4(input[3], input[3]), t0);
    const t4 = m31.addVec4(
        m31.addVec4(t1, t1),
        m31.addVec4(m31.addVec4(t1, t1), t3),
    );
    const t5 = m31.addVec4(
        m31.addVec4(t0, t0),
        m31.addVec4(m31.addVec4(t0, t0), t2),
    );
    return .{ m31.addVec4(t3, t5), t5, m31.addVec4(t2, t4), t4 };
}

fn internalMatrix4(state: *[WIDTH]m31.Vec4u32) void {
    var sum: m31.Vec4u32 = @splat(0);
    for (state) |value| sum = m31.addVec4(sum, value);
    for (state, constants.INTERNAL_MATRIX) |*value, diagonal| {
        const coefficient: m31.Vec4u32 = @splat(diagonal);
        value.* = m31.addVec4(m31.mulVec4(value.*, coefficient), sum);
    }
}

test "memory Poseidon2: pinned default hash chain" {
    var expected = [_]u32{0} ** constants.DEFAULT_HASHES.len;
    var depth: usize = expected.len - 1;
    while (depth > 0) {
        depth -= 1;
        expected[depth] = hashPair(expected[depth + 1], expected[depth + 1]);
    }
    try std.testing.expectEqualSlices(u32, &constants.DEFAULT_HASHES, &expected);
}

test "memory Poseidon2: scalar pair vector is stable" {
    try std.testing.expectEqual(@as(u32, 1975699496), hashPair(1, 2));
}

test "memory Poseidon2: four-lane hashes equal scalar hashes" {
    const left = [4]u32{ 1, 0, 17, DEFAULT_HASHES[12] };
    const right = [4]u32{ 2, 9, 23, DEFAULT_HASHES[12] };
    const actual = hashPairs4(left, right);
    for (0..4) |index|
        try std.testing.expectEqual(
            hashPair(left[index], right[index]),
            actual[index],
        );
}

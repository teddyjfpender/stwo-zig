//! S31 lowering of the repository's pinned Stark-V Poseidon2-M31 permutation.
//! Constants and round order come from the RISC-V commitment implementation;
//! the host oracle uses its recursion-channel leaf and node construction.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const reference = @import("s31_poseidon_ref");
const constants = reference.constants;
const channel = reference.channel;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = circuit.builder.Var;
const Simd = circuit.builder.simd.Simd;
const State = [16]Var;

pub fn leafWords(words: []const M31) [8]M31 {
    const digest = channel.hashCanonicalWords(words, channel.LEAF_TAG);
    var result: [8]M31 = undefined;
    for (&result, digest) |*out, word| out.* = M31.fromCanonical(word);
    return result;
}

pub fn pairWords(left: []const M31, right: []const M31) [8]M31 {
    std.debug.assert(left.len == 8 and right.len == 8);
    var children: channel.MerkleHasher.Children = undefined;
    for (left, 0..) |word, index| children.left[index] = word.toU32();
    for (right, 0..) |word, index| children.right[index] = word.toU32();
    const digest = channel.MerkleHasher.hashChildren(children);
    var result: [8]M31 = undefined;
    for (&result, digest) |*out, word| out.* = M31.fromCanonical(word);
    return result;
}

pub fn leafCircuit(comptime V: type, ctx: *circuit.builder.Context(V), input: Simd) !Simd {
    std.debug.assert(input.len > 0 and input.len <= 16 and input.len % 4 == 0);
    var state: State = [_]Var{ctx.zero()} ** 16;
    state[15] = ctx.one();
    var filled: usize = 0;
    for (0..input.len) |index| {
        const word = try circuit.builder.simd.unpackIdx(V, ctx, input, index);
        state[filled] = try ctx.add(state[filled], word);
        filled += 1;
        if (filled == 8) {
            try permute(V, ctx, &state);
            filled = 0;
        }
    }
    state[filled] = try ctx.add(state[filled], ctx.one());
    try permute(V, ctx, &state);
    return packDigest(V, ctx, state);
}

pub fn pairCircuit(comptime V: type, ctx: *circuit.builder.Context(V), left: Simd, right: Simd) !Simd {
    std.debug.assert(left.len == 8 and right.len == 8);
    var state: State = undefined;
    for (0..8) |index| {
        state[index] = try circuit.builder.simd.unpackIdx(V, ctx, left, index);
        state[8 + index] = try circuit.builder.simd.unpackIdx(V, ctx, right, index);
    }
    try permute(V, ctx, &state);
    return packDigest(V, ctx, state);
}

fn packDigest(comptime V: type, ctx: *circuit.builder.Context(V), state: State) !Simd {
    var words: [8]circuit.builder.wrappers.M31Wrapper(Var) = undefined;
    for (&words, state[0..8]) |*word, value| word.* = .newUnsafe(value);
    return circuit.builder.simd.pack(V, ctx, &words);
}

fn constant(comptime V: type, ctx: *circuit.builder.Context(V), value: u32) !Var {
    return ctx.constant(QM31.fromBase(M31.fromCanonical(value)));
}

fn sbox(comptime V: type, ctx: *circuit.builder.Context(V), value: Var) !Var {
    const squared = try ctx.mul(value, value);
    return ctx.mul(try ctx.mul(squared, squared), value);
}

fn m4(comptime V: type, ctx: *circuit.builder.Context(V), input: [4]Var) ![4]Var {
    const t0 = try ctx.add(input[0], input[1]);
    const t1 = try ctx.add(input[2], input[3]);
    const t2 = try ctx.add(try ctx.add(input[1], input[1]), t1);
    const t3 = try ctx.add(try ctx.add(input[3], input[3]), t0);
    const t4 = try ctx.add(try ctx.add(t1, t1), try ctx.add(t1, t1));
    const t5 = try ctx.add(try ctx.add(t0, t0), try ctx.add(t0, t0));
    return .{
        try ctx.add(t3, try ctx.add(t5, t2)),
        try ctx.add(t5, t2),
        try ctx.add(t2, try ctx.add(t4, t3)),
        try ctx.add(t4, t3),
    };
}

fn externalMatrix(comptime V: type, ctx: *circuit.builder.Context(V), state: *State) !void {
    for (0..4) |block| {
        const base = 4 * block;
        const mixed = try m4(V, ctx, state[base..][0..4].*);
        @memcpy(state[base..][0..4], &mixed);
    }
    for (0..4) |lane| {
        const sum = try ctx.add(
            try ctx.add(state[lane], state[lane + 4]),
            try ctx.add(state[lane + 8], state[lane + 12]),
        );
        for (0..4) |block| {
            const index = 4 * block + lane;
            state[index] = try ctx.add(state[index], sum);
        }
    }
}

fn internalMatrix(comptime V: type, ctx: *circuit.builder.Context(V), state: *State) !void {
    var sum = ctx.zero();
    for (state.*) |value| sum = try ctx.add(sum, value);
    for (state, constants.INTERNAL_MATRIX) |*value, diagonal| {
        value.* = try ctx.add(try ctx.mul(value.*, try constant(V, ctx, diagonal)), sum);
    }
}

fn fullRound(comptime V: type, ctx: *circuit.builder.Context(V), state: *State, round: [16]u32) !void {
    for (state, round) |*value, round_constant| {
        value.* = try sbox(V, ctx, try ctx.add(value.*, try constant(V, ctx, round_constant)));
    }
    try externalMatrix(V, ctx, state);
}

fn permute(comptime V: type, ctx: *circuit.builder.Context(V), state: *State) !void {
    try externalMatrix(V, ctx, state);
    for (constants.EXTERNAL_ROUND[0..4]) |round| try fullRound(V, ctx, state, round);
    for (constants.INTERNAL_ROUND) |round_constant| {
        state[0] = try sbox(V, ctx, try ctx.add(state[0], try constant(V, ctx, round_constant)));
        try internalMatrix(V, ctx, state);
    }
    for (constants.EXTERNAL_ROUND[4..8]) |round| try fullRound(V, ctx, state, round);
}

test "pinned Poseidon2 leaf and node vectors agree with recursion hash" {
    const words = [8]M31{ M31.fromCanonical(1), M31.fromCanonical(2), M31.fromCanonical(3), M31.fromCanonical(4), M31.fromCanonical(5), M31.fromCanonical(6), M31.fromCanonical(7), M31.fromCanonical(8) };
    const left = leafWords(&words);
    const right_words = [_]M31{M31.fromCanonical(9)} ** 8;
    const right = leafWords(&right_words);
    const parent = pairWords(&left, &right);
    try std.testing.expect(!std.meta.eql(left, right));
    try std.testing.expect(!std.meta.eql(parent, left));
}

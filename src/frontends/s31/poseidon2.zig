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

/// Scalar wires for recursive state binding. Callers must constrain each
/// input to M31 (u16 openings satisfy that precondition). This follows the
/// same rate-eight leaf domain and padding as `leafCircuit`, without SIMD
/// packing/unpacking gates in a verifier circuit.
pub fn leafScalarCircuit(comptime V: type, ctx: *circuit.builder.Context(V), input: []const Var) ![8]Var {
    if (input.len == 0 or input.len > 16 or input.len % 4 != 0)
        return error.InvalidPoseidonLeafLength;
    var state: State = [_]Var{ctx.zero()} ** 16;
    state[15] = ctx.one();
    var filled: usize = 0;
    for (input) |word| {
        state[filled] = try ctx.add(state[filled], word);
        filled += 1;
        if (filled == 8) {
            try permute(V, ctx, &state);
            filled = 0;
        }
    }
    state[filled] = try ctx.add(state[filled], ctx.one());
    try permute(V, ctx, &state);
    return state[0..8].*;
}

/// Ordered pair of two eight-word M31 digests, for checking a transition
/// commitment inside the recursion circuit. Callers constrain digest inputs.
pub fn pairScalarCircuit(comptime V: type, ctx: *circuit.builder.Context(V), left: [8]Var, right: [8]Var) ![8]Var {
    var state: State = undefined;
    @memcpy(state[0..8], &left);
    @memcpy(state[8..16], &right);
    try permute(V, ctx, &state);
    return state[0..8].*;
}

pub fn linkRootCircuit(comptime V: type, ctx: *circuit.builder.Context(V), old_hash: [16]Var, new_hash: [16]Var) ![8]Var {
    const old_root = try leafScalarCircuit(V, ctx, &old_hash);
    const new_root = try leafScalarCircuit(V, ctx, &new_hash);
    return pairScalarCircuit(V, ctx, old_root, new_root);
}

/// Constraint kernel for a recursive header transition. The supplied roots
/// must already be authenticated by the two child-proof verifiers. It guesses
/// and range-checks each old/new hash limb as u16. These equalities bind the
/// leaf's ordered pair to the prior fold state inside the outer AIR.
pub fn constrainLinkedState(
    comptime V: type,
    ctx: *circuit.builder.Context(V),
    old_hash_values: [16]V,
    new_hash_values: [16]V,
    authenticated_old_root: [8]Var,
    authenticated_link_root: [8]Var,
) ![8]Var {
    var old_hash: [16]Var = undefined;
    var new_hash: [16]Var = undefined;
    for (old_hash_values, &old_hash) |value, *out| out.* = try ctx.guessU16(value);
    for (new_hash_values, &new_hash) |value, *out| out.* = try ctx.guessU16(value);
    const old_root = try leafScalarCircuit(V, ctx, &old_hash);
    const new_root = try leafScalarCircuit(V, ctx, &new_hash);
    const link_root = try pairScalarCircuit(V, ctx, old_root, new_root);
    for (old_root, authenticated_old_root) |computed, claimed| try ctx.eq(computed, claimed);
    for (link_root, authenticated_link_root) |computed, claimed| try ctx.eq(computed, claimed);
    return new_root;
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

test "scalar transition commitment matches pinned host hash and value-free topology" {
    const old_u16 = [16]u32{ 57967, 2700, 61878, 29363, 42689, 18082, 25518, 20471, 7827, 25987, 23265, 39944, 54888, 25, 0, 0 };
    const new_u16 = [16]u32{ 24648, 6379, 7103, 8214, 32483, 37012, 35580, 30018, 16660, 55151, 22865, 34475, 36456, 33690, 0, 0 };
    const expected = [8]u32{ 928491885, 399009276, 910063533, 515587455, 1714177619, 700256356, 272818236, 1829149449 };
    var old_words: [16]M31 = undefined;
    var new_words: [16]M31 = undefined;
    for (old_u16, &old_words) |word, *out| out.* = M31.fromCanonical(word);
    for (new_u16, &new_words) |word, *out| out.* = M31.fromCanonical(word);
    const old_host = leafWords(&old_words);
    const new_host = leafWords(&new_words);
    const host = pairWords(&old_host, &new_host);
    for (host, expected) |word, want| try std.testing.expectEqual(want, word.toU32());

    var values = try circuit.builder.Context(QM31).init(std.testing.allocator, 8);
    defer values.deinit();
    var old_wires: [16]Var = undefined;
    var new_wires: [16]Var = undefined;
    for (old_u16, &old_wires) |word, *out|
        out.* = try values.guessU16(QM31.fromBase(M31.fromCanonical(word)));
    for (new_u16, &new_wires) |word, *out|
        out.* = try values.guessU16(QM31.fromBase(M31.fromCanonical(word)));
    const output = try linkRootCircuit(QM31, &values, old_wires, new_wires);
    try values.setOutputs(&output);
    try values.finalize(false);
    try std.testing.expect(try values.isCircuitValid());
    for (output, expected) |wire, want|
        try std.testing.expectEqual(QM31.fromBase(M31.fromCanonical(want)), values.value_table.items[wire.idx]);

    var topology = try circuit.builder.Context(circuit.builder.NoValue).init(std.testing.allocator, 8);
    defer topology.deinit();
    var old_empty: [16]Var = undefined;
    var new_empty: [16]Var = undefined;
    for (&old_empty) |*out| out.* = try topology.guessU16(.{});
    for (&new_empty) |*out| out.* = try topology.guessU16(.{});
    const empty_output = try linkRootCircuit(circuit.builder.NoValue, &topology, old_empty, new_empty);
    try topology.setOutputs(&empty_output);
    try topology.finalize(false);
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    try std.testing.expectEqualDeep(values.circuit.add.items, topology.circuit.add.items);
    try std.testing.expectEqualDeep(values.circuit.mul.items, topology.circuit.mul.items);
    try std.testing.expectEqualDeep(values.circuit.eq.items, topology.circuit.eq.items);
    try std.testing.expectEqualDeep(values.circuit.m31_to_u32.items, topology.circuit.m31_to_u32.items);
    try std.testing.expectEqualDeep(values.circuit.output.items, topology.circuit.output.items);
}

test "recursive link kernel rejects changed prior-state and leaf commitments" {
    const old_u16 = [16]u32{ 57967, 2700, 61878, 29363, 42689, 18082, 25518, 20471, 7827, 25987, 23265, 39944, 54888, 25, 0, 0 };
    const new_u16 = [16]u32{ 24648, 6379, 7103, 8214, 32483, 37012, 35580, 30018, 16660, 55151, 22865, 34475, 36456, 33690, 0, 0 };
    var old_words: [16]M31 = undefined;
    var new_words: [16]M31 = undefined;
    for (old_u16, &old_words) |word, *out| out.* = M31.fromCanonical(word);
    for (new_u16, &new_words) |word, *out| out.* = M31.fromCanonical(word);
    const old_host = leafWords(&old_words);
    const new_host = leafWords(&new_words);
    const link_host = pairWords(&old_host, &new_host);

    var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 8);
    defer ctx.deinit();
    var old_values: [16]QM31 = undefined;
    var new_values: [16]QM31 = undefined;
    var prior_root: [8]Var = undefined;
    var link_root: [8]Var = undefined;
    for (old_u16, &old_values) |word, *out| out.* = QM31.fromBase(M31.fromCanonical(word));
    for (new_u16, &new_values) |word, *out| out.* = QM31.fromBase(M31.fromCanonical(word));
    for (old_host, &prior_root) |word, *out| out.* = try ctx.guessM31(QM31.fromBase(word));
    for (link_host, &link_root) |word, *out| out.* = try ctx.guessM31(QM31.fromBase(word));
    const result = try constrainLinkedState(QM31, &ctx, old_values, new_values, prior_root, link_root);
    try ctx.setOutputs(&result);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
    for (result, new_host) |wire, word|
        try std.testing.expectEqual(QM31.fromBase(word), ctx.value_table.items[wire.idx]);

    const original_prior = ctx.value_table.items[prior_root[0].idx];
    ctx.value_table.items[prior_root[0].idx] = QM31.fromBase(old_host[0].add(M31.one()));
    try std.testing.expect(!try ctx.isCircuitValid());
    ctx.value_table.items[prior_root[0].idx] = original_prior;

    const original_link = ctx.value_table.items[link_root[0].idx];
    ctx.value_table.items[link_root[0].idx] = QM31.fromBase(link_host[0].add(M31.one()));
    try std.testing.expect(!try ctx.isCircuitValid());
    ctx.value_table.items[link_root[0].idx] = original_link;
    try std.testing.expect(try ctx.isCircuitValid());
}

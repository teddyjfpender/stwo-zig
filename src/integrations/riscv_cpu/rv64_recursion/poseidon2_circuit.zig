//! Exact pinned Stark-V width16 Poseidon2 arithmetic prototype. Inputs must
//! already be M31-constrained wires. No shipping proof profile selects this
//! module; width24 parameter/framing qualification is a separate gate.
const std = @import("std");
const Core = @import("stwo_core");
const Frontend = @import("stwo_circuit_frontend");
const Native = @import("stwo_riscv_frontend").air.memory_commitment.poseidon2;
const K = Native.constants;
const Q = Core.fields.qm31.QM31;
const M = Core.fields.m31.M31;
const Var = Frontend.builder.Var;
const Context = Frontend.builder.Context(Q);
const Error = Frontend.builder.context.Error;
pub const WIDTH = 16;
fn constant(ctx: *Context, value: u32) Error!Var {
    return ctx.constant(Q.fromBase(M.fromCanonical(value)));
}
fn sbox(ctx: *Context, value: Var) Error!Var {
    const square = try ctx.mul(value, value);
    return ctx.mul(try ctx.mul(square, square), value);
}
fn m4(ctx: *Context, input: [4]Var) Error![4]Var {
    const t0 = try ctx.add(input[0], input[1]);
    const t1 = try ctx.add(input[2], input[3]);
    const t2 = try ctx.add(try ctx.add(input[1], input[1]), t1);
    const t3 = try ctx.add(try ctx.add(input[3], input[3]), t0);
    const t4 = try ctx.add(try ctx.add(try ctx.add(t1, t1), try ctx.add(t1, t1)), t3);
    const t5 = try ctx.add(try ctx.add(try ctx.add(t0, t0), try ctx.add(t0, t0)), t2);
    return .{ try ctx.add(t3, t5), t5, try ctx.add(t2, t4), t4 };
}
fn external(ctx: *Context, state: *[WIDTH]Var) Error!void {
    for (0..4) |block| state[4 * block ..][0..4].* = try m4(ctx, state[4 * block ..][0..4].*);
    for (0..4) |lane| {
        const sum = try ctx.add(try ctx.add(try ctx.add(state[lane], state[lane + 4]), state[lane + 8]), state[lane + 12]);
        for (0..4) |block| state[4 * block + lane] = try ctx.add(state[4 * block + lane], sum);
    }
}
fn full(ctx: *Context, state: *[WIDTH]Var, round: [WIDTH]u32) Error!void {
    for (state, round) |*value, c| value.* = try sbox(ctx, try ctx.add(value.*, try constant(ctx, c)));
    try external(ctx, state);
}
/// Constrain actual QM31 ports, rather than trusting a phantom field type.
pub fn requireM31(ctx: *Context, value: Var) Error!void {
    const outside_base = try ctx.constant(Q.fromU32Unchecked(0, 1, 1, 1));
    try ctx.eq(try ctx.pointwiseMul(value, outside_base), ctx.zero());
}
pub fn permute(ctx: *Context, state: *[WIDTH]Var) Error!void {
    for (state) |value| try requireM31(ctx, value);
    return permuteBase(ctx, state);
}
fn permuteBase(ctx: *Context, state: *[WIDTH]Var) Error!void {
    try external(ctx, state);
    for (K.EXTERNAL_ROUND[0..4]) |round| try full(ctx, state, round);
    for (K.INTERNAL_ROUND) |round| {
        state[0] = try sbox(ctx, try ctx.add(state[0], try constant(ctx, round)));
        var sum = ctx.zero();
        for (state) |value| sum = try ctx.add(sum, value);
        for (state, K.INTERNAL_MATRIX) |*value, diagonal| value.* = try ctx.add(try ctx.mul(value.*, try constant(ctx, diagonal)), sum);
    }
    for (K.EXTERNAL_ROUND[4..8]) |round| try full(ctx, state, round);
}

/// Canonical-field sponge with an explicit capacity tag and end marker.
/// This is the width16 prototype only; digest width is not a production ABI.
pub fn hashCanonical(ctx: *Context, words: []const Var, tag: u32) Error![8]Var {
    for (words) |value| try requireM31(ctx, value);
    var state: [WIDTH]Var = @splat(ctx.zero());
    state[WIDTH - 1] = try constant(ctx, tag);
    var filled: usize = 0;
    for (words) |value| {
        state[filled] = try ctx.add(state[filled], value);
        filled += 1;
        if (filled == 8) {
            try permuteBase(ctx, &state);
            filled = 0;
        }
    }
    state[filled] = try ctx.add(state[filled], ctx.one());
    try permuteBase(ctx, &state);
    return state[0..8].*;
}

test "Poseidon2 circuit width16 exact pinned native parity and output mutation" {
    const a = std.testing.allocator;
    for (0..4) |case| {
        var input: Native.State = undefined;
        for (&input, 0..) |*value, i| value.* = M.fromCanonical(@intCast(if (case == 0) 0 else if (case == 1) i else if (case == 2) 2147483646 else i * 117 + 31));
        var expected = input;
        Native.permute(&expected);
        for ([_]bool{ false, true }) |mutation| {
            var ctx = try Context.init(a, 0);
            defer ctx.deinit();
            ctx.assert_eq_on_eval = false;
            var state: [WIDTH]Var = undefined;
            for (&state, input) |*value, native| value.* = try ctx.guessM31(Q.fromBase(native));
            try permute(&ctx, &state);
            for (state, expected, 0..) |value, native, i| try ctx.eq(value, try ctx.constant(Q.fromBase(if (mutation and i == case) native.add(M.one()) else native)));
            try ctx.finalize(false);
            try std.testing.expectEqual(!mutation, try ctx.isCircuitValid());
            if (case == 1 and !mutation) std.debug.print("\nPOSEIDON2_W16_CIRCUIT_CENSUS qm31_ops={} eq={} variables={} blake_g={} triple_xor={} m31_to_u32={}\n", .{ ctx.gate_counts.qm31_ops, ctx.gate_counts.eq, ctx.circuit.n_vars, ctx.gate_counts.blake_g_gate, ctx.gate_counts.triple_xor, ctx.gate_counts.m31_to_u32 });
        }
    }
}

test "Poseidon2 circuit rejects non-base QM31 input ports" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    ctx.assert_eq_on_eval = false;
    var state: [WIDTH]Var = undefined;
    for (&state, 0..) |*value, i| value.* = try ctx.guess(if (i == 7) Q.fromU32Unchecked(1, 1, 0, 0) else Q.zero());
    try permute(&ctx, &state);
    try ctx.finalize(false);
    try std.testing.expect(!try ctx.isCircuitValid());
}

test "Poseidon2 width16 framed hash source parity and exact raw cell census" {
    const native_channel = @import("stwo_riscv_frontend").recursion.poseidon2_channel;
    const a = std.testing.allocator;
    for ([_]usize{ 0, 8, 16, 18, 52, 128, 304, 479 }) |count| {
        var ctx = try Context.init(a, 0);
        defer ctx.deinit();
        const native = try a.alloc(M, count);
        defer a.free(native);
        const wires = try a.alloc(Var, count);
        defer a.free(wires);
        for (native, wires, 0..) |*value, *wire, i| {
            value.* = M.fromCanonical(@intCast(i * 97 + 3));
            wire.* = try ctx.guess(Q.fromBase(value.*));
        }
        const digest = try hashCanonical(&ctx, wires, 1);
        const expected = native_channel.hashCanonicalWords(native, 1);
        for (digest, expected) |wire, value| try ctx.eq(wire, try constant(&ctx, value));
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        const g = ctx.gate_counts;
        const raw_main_cells = 12 * g.qm31_ops + 4 * g.eq;
        const raw_interaction_base_cells = 16 * g.qm31_ops + 8 * g.eq;
        std.debug.print("\nPOSEIDON2_W16_HASH_CENSUS words={} rate=8 digest_words=8 permutations={} qm31_ops={} eq={} raw_main_cells={} raw_interaction_base_cells={} variables={}\n", .{ count, (count + 1 + 7) / 8, g.qm31_ops, g.eq, raw_main_cells, raw_interaction_base_cells, ctx.circuit.n_vars });
    }
}

test "Poseidon2 comparison baseline exact existing Blake leaf raw circuit cells" {
    const a = std.testing.allocator;
    const B = Frontend.builder;
    const H = Core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
    const Facts = @import("../outer_gkr/profile.zig");
    for ([_]usize{ 8, 16, 18, 52, 128, 304, 479 }) |count| {
        var ctx = try Context.init(a, 0);
        defer ctx.deinit();
        const native = try a.alloc(M, count);
        defer a.free(native);
        const wires = try a.alloc(B.wrappers.M31Wrapper(Var), count);
        defer a.free(wires);
        for (native, wires, 0..) |*value, *wire, i| {
            value.* = M.fromCanonical(@intCast(i * 97 + 3));
            wire.* = .newUnsafe(try ctx.guess(Q.fromBase(value.*)));
        }
        const digest = try Frontend.native_verifier.merkle.hashLeafM31s(Q, &ctx, wires);
        var hasher = H.defaultWithInitialState();
        hasher.updateLeaf(native);
        const expected = try B.blake.constantHash(Q, &ctx, B.blake.hashValueFromDigest(Q, hasher.finalize()));
        for (digest.words, expected.words) |wire, value| try ctx.eq(wire.get(), value.get());
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        var main: u64 = 0;
        var inter: u64 = 0;
        const rows_by_component = [_]u64{ ctx.gate_counts.eq, ctx.gate_counts.qm31_ops, ctx.gate_counts.triple_xor, ctx.gate_counts.m31_to_u32, ctx.gate_counts.blake_g_gate };
        for (rows_by_component, Facts.FACTS[0..5], 0..) |rows, fact, i| {
            main += rows * fact.main;
            inter += rows * Facts.classicInteractionBaseColumns(@enumFromInt(i));
        }
        std.debug.print("\nBLAKE_LEAF_CIRCUIT_CENSUS words={} raw_main_cells={} raw_interaction_base_cells={} gates={f}\n", .{ count, main, inter, std.json.fmt(ctx.gate_counts, .{}) });
    }
}

//! Width24 circuit prototype sharing the exact native Plonky3 permutation.
//! Packed mode represents FOUR independent M31 states in QM31 coordinates;
//! its multiplications are pointwise, never extension-field x^5.
const std = @import("std");
const Core = @import("stwo_core");
const B = @import("stwo_circuit_frontend").builder;
const P = Core.crypto.poseidon2_m31_w24;
const Base = @import("poseidon2_circuit.zig");
const Q = Core.fields.qm31.QM31;
const M = Core.fields.m31.M31;
const Var = B.Var;
const Context = B.Context(Q);
const Error = B.context.Error;
const Ops = struct {
    ctx: *Context,
    packed_lanes: bool,
    pub fn constant(self: @This(), value: u32) Error!Var {
        const m = M.fromCanonical(value);
        return self.ctx.constant(if (self.packed_lanes) Q.fromM31(m, m, m, m) else Q.fromBase(m));
    }
    pub fn add(self: @This(), x: Var, y: Var) Error!Var {
        return self.ctx.add(x, y);
    }
    pub fn sub(self: @This(), x: Var, y: Var) Error!Var {
        return self.ctx.sub(x, y);
    }
    pub fn mul(self: @This(), x: Var, y: Var) Error!Var {
        return if (self.packed_lanes) self.ctx.pointwiseMul(x, y) else self.ctx.mul(x, y);
    }
};
pub fn permute(ctx: *Context, state: *[24]Var) !void {
    for (state) |value| try Base.requireM31(ctx, value);
    try P.permuteFor(Var, Ops{ .ctx = ctx, .packed_lanes = false }, state);
}
pub fn permute4(ctx: *Context, state: *[24]Var) !void {
    try P.permuteFor(Var, Ops{ .ctx = ctx, .packed_lanes = true }, state);
}
/// Boundary adapter for actual scalar proof ports. An extension-valued
/// forged BaseWrapper cannot enter the packed hash through this path.
pub fn packBasePorts(ctx: *Context, words: [4]Var) !Var {
    for (words) |word| try Base.requireM31(ctx, word);
    return B.ops.fromPartialEvals(Q, ctx, words);
}
pub fn unpackBasePorts(ctx: *Context, word: Var) ![4]Var {
    const packed_words = [1]Var{word};
    const simd = B.simd.Simd.fromPacked(&packed_words, 4);
    var out: [4]Var = undefined;
    for (&out, 0..) |*value, i| value.* = try B.simd.unpackIdx(Q, ctx, simd, i);
    return out;
}
/// All four lanes must have the same message length, with canonical M31
/// values represented directly by each QM31 coordinate. No u32 is reduced.
pub fn hashCanonical4(ctx: *Context, words: []const Var, tag: u32) ![9]Var {
    const ops = Ops{ .ctx = ctx, .packed_lanes = true };
    var state: [24]Var = @splat(ctx.zero());
    state[22] = try ops.constant(1);
    state[23] = try ops.constant(tag);
    var filled: usize = 0;
    for (words) |value| {
        state[filled] = try ctx.add(state[filled], value);
        filled += 1;
        if (filled == 12) {
            try permute4(ctx, &state);
            filled = 0;
        }
    }
    state[filled] = try ctx.add(state[filled], try ops.constant(1));
    try permute4(ctx, &state);
    return state[0..9].*;
}
pub fn hashCanonical(ctx: *Context, words: []const Var, tag: u32) ![9]Var {
    for (words) |value| try Base.requireM31(ctx, value);
    const ops = Ops{ .ctx = ctx, .packed_lanes = false };
    var state: [24]Var = @splat(ctx.zero());
    state[22] = try ops.constant(1);
    state[23] = try ops.constant(tag);
    var filled: usize = 0;
    for (words) |value| {
        state[filled] = try ctx.add(state[filled], value);
        filled += 1;
        if (filled == 12) {
            try P.permuteFor(Var, ops, &state);
            filled = 0;
        }
    }
    state[filled] = try ctx.add(state[filled], ctx.one());
    try P.permuteFor(Var, ops, &state);
    return state[0..9].*;
}
fn hashNative(words: []const M, tag: u32) [9]M {
    var state: P.State = @splat(M.zero());
    state[22] = M.one();
    state[23] = M.fromCanonical(tag);
    var filled: usize = 0;
    for (words) |value| {
        state[filled] = state[filled].add(value);
        filled += 1;
        if (filled == 12) {
            P.permute(&state);
            filled = 0;
        }
    }
    state[filled] = state[filled].add(M.one());
    P.permute(&state);
    return state[0..9].*;
}
test "Poseidon2 width24 packed4 exact native lane parity, mutants and raw cell census" {
    const a = std.testing.allocator;
    for ([_]usize{ 0, 9, 18, 52, 128, 304, 479 }) |count| {
        var ctx = try Context.init(a, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        const wires = try a.alloc(Var, count);
        defer a.free(wires);
        var values: [4][]M = undefined;
        for (&values) |*v| v.* = try a.alloc(M, count);
        defer for (values) |v| a.free(v);
        for (wires, 0..) |*wire, i| {
            var coords: [4]M = undefined;
            for (&coords, 0..) |*m, lane| {
                m.* = M.fromCanonical(@intCast(i * 97 + lane * 17 + 3));
                values[lane][i] = m.*;
            }
            wire.* = try ctx.guess(Q.fromM31Array(coords));
        }
        const digest = try hashCanonical4(&ctx, wires, 1);
        var expected: [4][9]M = undefined;
        for (&expected, values) |*out, input| out.* = hashNative(input, 1);
        for (digest, 0..) |wire, i| {
            var coords: [4]M = undefined;
            for (&coords, 0..) |*m, lane| m.* = expected[lane][i];
            try ctx.eq(wire, try ctx.constant(Q.fromM31Array(coords)));
        }
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        const g = ctx.gate_counts;
        std.debug.print("\nPOSEIDON2_W24_PACK4_HASH_CENSUS words_per_hash={} hashes=4 rate=12 digest_words=9 permutations_per_hash={} qm31_ops={} eq={} raw_main_cells={} raw_interaction_base_cells={} variables={}\n", .{ count, (count + 12) / 12, g.qm31_ops, g.eq, 12 * g.qm31_ops + 4 * g.eq, 16 * g.qm31_ops + 8 * g.eq, ctx.circuit.n_vars });
    }
    // One extension coordinate deliberately differs: all four lane outputs
    // remain constrained to their own exact native values.
    for (0..4) |bad_lane| {
        var ctx = try Context.init(a, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        var state: [24]Var = undefined;
        var expected: [4]P.State = undefined;
        for (&state, 0..) |*wire, i| {
            var coords: [4]M = undefined;
            for (&coords, 0..) |*m, lane| {
                m.* = M.fromCanonical(@intCast(i + lane));
                expected[lane][i] = m.*;
            }
            wire.* = try ctx.guess(Q.fromM31Array(coords));
        }
        for (&expected) |*native| P.permute(native);
        try permute4(&ctx, &state);
        for (state, 0..) |wire, i| {
            var coords: [4]M = undefined;
            for (&coords, 0..) |*m, lane| m.* = if (i == 7 and lane == bad_lane) expected[lane][i].add(M.one()) else expected[lane][i];
            try ctx.eq(wire, try ctx.constant(Q.fromM31Array(coords)));
        }
        try ctx.finalize(false);
        try std.testing.expect(!try ctx.isCircuitValid());
    }
}

test "Poseidon2 packed port adapter rejects extension-valued scalar inputs" {
    const a = std.testing.allocator;
    for (0..5) |bad| {
        var ctx = try Context.init(a, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        var words: [4]Var = undefined;
        for (&words, 0..) |*value, i| value.* = try ctx.guess(if (i == bad) Q.fromU32Unchecked(@intCast(i + 1), 1, 0, 0) else Q.fromU32Unchecked(@intCast(i + 1), 0, 0, 0));
        const unpacked = try unpackBasePorts(&ctx, try packBasePorts(&ctx, words));
        for (unpacked, 0..) |value, i| try ctx.eq(value, try ctx.constant(Q.fromU32Unchecked(@intCast(i + 1), 0, 0, 0)));
        try ctx.finalize(false);
        try std.testing.expectEqual(bad == 4, try ctx.isCircuitValid());
    }
}

test "Poseidon2 width24 scalar framed hash source parity and raw cell census" {
    const a = std.testing.allocator;
    for ([_]usize{ 0, 9, 18, 52, 128, 304, 479 }) |count| {
        var ctx = try Context.init(a, 0);
        defer ctx.deinit();
        const values = try a.alloc(M, count);
        defer a.free(values);
        const wires = try a.alloc(Var, count);
        defer a.free(wires);
        for (values, wires, 0..) |*value, *wire, i| {
            value.* = M.fromCanonical(@intCast(i * 97 + 3));
            wire.* = try ctx.guess(Q.fromBase(value.*));
        }
        const digest = try hashCanonical(&ctx, wires, 1);
        const expected = hashNative(values, 1);
        for (digest, expected) |wire, value| try ctx.eq(wire, try ctx.constant(Q.fromBase(value)));
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        const g = ctx.gate_counts;
        std.debug.print("\nPOSEIDON2_W24_SCALAR_HASH_CENSUS words={} hashes=1 rate=12 digest_words=9 permutations={} qm31_ops={} eq={} raw_main_cells={} raw_interaction_base_cells={} variables={}\n", .{ count, (count + 12) / 12, g.qm31_ops, g.eq, 12 * g.qm31_ops + 4 * g.eq, 16 * g.qm31_ops + 8 * g.eq, ctx.circuit.n_vars });
    }
}

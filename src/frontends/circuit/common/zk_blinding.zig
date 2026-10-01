//! ZK blinding: random rows in every witness component.
//!
//! Port of `add_zk_blinding` and its helpers in
//! `crates/circuit_common/src/finalize.rs` (https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230). Each round draws 26 words
//! from `ChaCha20Rng::from_seed(seed)` in the order qm31_ops (12), eq (4),
//! triple_xor (3), m31_to_u32 (1), blake_g_gate (6). Every fresh variable is
//! yielded by a trivial `x + 0 = x` (or `0 + y = y`) add gate, not by a guess,
//! so blinding runs after `finalize`.

const std = @import("std");
const stwo_core = @import("stwo_core");
const builder = @import("../builder/mod.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const ChaCha20Rng = stwo_core.crypto.chacha20_rng.ChaCha20Rng;
const Var = builder.Var;
const U32Wrapper = builder.wrappers.U32Wrapper;

pub const Error = builder.context.Error || error{NotFinalized};

/// `add_zk_blinding`: `n_padding` rounds of random rows.
pub fn addZkBlinding(comptime V: type, ctx: *builder.Context(V), seed: [32]u8, n_padding: usize) Error!void {
    if (!ctx.finalized) return error.NotFinalized;
    var rng = ChaCha20Rng.fromSeed(seed);
    for (0..n_padding) |_| {
        try qm31Blinding(V, ctx, &rng);
        try eqBlinding(V, ctx, &rng);
        try tripleXorBlinding(V, ctx, &rng);
        try m31ToU32Blinding(V, ctx, &rng);
        try blakeGGateBlinding(V, ctx, &rng);
    }
}

fn randomQm31(rng: *ChaCha20Rng) QM31 {
    const a = rng.nextU32();
    const b = rng.nextU32();
    const c = rng.nextU32();
    const d = rng.nextU32();
    return builder.ivalue.qm31FromU32s(a, b, c, d);
}

/// Three qm31_ops rows: `x + 0 = x`, `0 + y = y`, `z + 0 = z`.
fn qm31Blinding(comptime V: type, ctx: *builder.Context(V), rng: *ChaCha20Rng) builder.context.Error!void {
    const zero = ctx.zero();
    const x = try ctx.newVar(builder.ivalue.fromQm31(V, randomQm31(rng)));
    try ctx.addInto(x, zero, x);
    const y = try ctx.newVar(builder.ivalue.fromQm31(V, randomQm31(rng)));
    try ctx.addInto(zero, y, y);
    const z = try ctx.newVar(builder.ivalue.fromQm31(V, randomQm31(rng)));
    try ctx.addInto(z, zero, z);
}

/// One eq row `x = x` on a random, yielded `x`.
fn eqBlinding(comptime V: type, ctx: *builder.Context(V), rng: *ChaCha20Rng) builder.context.Error!void {
    const x = try ctx.newVar(builder.ivalue.fromQm31(V, randomQm31(rng)));
    try ctx.addInto(x, ctx.zero(), x);
    try ctx.eq(x, x);
}

/// A fresh, yielded `u32` wire holding a random word.
fn randomU32Var(comptime V: type, ctx: *builder.Context(V), rng: *ChaCha20Rng) builder.context.Error!U32Wrapper(Var) {
    const x = try ctx.newVar(builder.ivalue.packU32(V, rng.nextU32()));
    try ctx.addInto(x, ctx.zero(), x);
    return .newUnsafe(x);
}

/// A fresh, yielded M31 wire holding a random word reduced modulo P.
fn randomM31Var(comptime V: type, ctx: *builder.Context(V), rng: *ChaCha20Rng) builder.context.Error!Var {
    const x = try ctx.newVar(builder.ivalue.fromQm31(V, builder.ivalue.qm31FromU32s(rng.nextU32(), 0, 0, 0)));
    try ctx.addInto(x, ctx.zero(), x);
    return x;
}

fn tripleXorBlinding(comptime V: type, ctx: *builder.Context(V), rng: *ChaCha20Rng) builder.context.Error!void {
    const a = try randomU32Var(V, ctx, rng);
    const b = try randomU32Var(V, ctx, rng);
    const c = try randomU32Var(V, ctx, rng);
    _ = try builder.blake.tripleXor(V, ctx, a, b, c);
}

fn m31ToU32Blinding(comptime V: type, ctx: *builder.Context(V), rng: *ChaCha20Rng) builder.context.Error!void {
    const input = try randomM31Var(V, ctx, rng);
    _ = try builder.blake.m31ToU32(V, ctx, input);
}

fn blakeGGateBlinding(comptime V: type, ctx: *builder.Context(V), rng: *ChaCha20Rng) builder.context.Error!void {
    var inputs: [6]U32Wrapper(Var) = undefined;
    for (&inputs) |*input| input.* = try randomU32Var(V, ctx, rng);
    _ = try builder.blake.blakeGGate(V, ctx, inputs[0], inputs[1], inputs[2], inputs[3], inputs[4], inputs[5]);
}

test "zk blinding: one round draws 26 words into the upstream rows" {
    const gpa = std.testing.allocator;
    var ctx = try builder.Context(QM31).init(gpa, 0);
    defer ctx.deinit();
    try ctx.finalize(false);
    const seed: [32]u8 = @splat(7);
    const before = ctx.circuit.n_vars;
    try addZkBlinding(QM31, &ctx, seed, 2);

    // Per round: 3 + 1 + 3 + 1 + 6 fresh inputs, 1 triple_xor output, 1
    // m31_to_u32 output and 4 blake_g outputs.
    try std.testing.expectEqual(before + 2 * 20, ctx.circuit.n_vars);
    try std.testing.expectEqual(@as(usize, 2), ctx.circuit.eq.items.len);
    try std.testing.expectEqual(@as(usize, 2), ctx.circuit.triple_xor.items.len);
    try std.testing.expectEqual(@as(usize, 2), ctx.circuit.m31_to_u32.items.len);
    try std.testing.expectEqual(@as(usize, 2), ctx.circuit.blake_g_gate.items.len);

    // The values are the ChaCha20 stream, read in upstream order.
    var rng = ChaCha20Rng.fromSeed(seed);
    var words: [52]u32 = undefined;
    for (&words) |*w| w.* = rng.nextU32();
    const v = ctx.values();
    try std.testing.expect(v[before].eql(builder.ivalue.qm31FromU32s(words[0], words[1], words[2], words[3])));
    try std.testing.expect(v[before + 3].eql(builder.ivalue.qm31FromU32s(words[12], words[13], words[14], words[15])));
    try std.testing.expect(v[before + 4].eql(builder.ivalue.packU32(QM31, words[16])));
    try std.testing.expect(v[before + 8].eql(builder.ivalue.qm31FromU32s(words[19], 0, 0, 0)));
    try std.testing.expect(v[before + 10].eql(builder.ivalue.packU32(QM31, words[20])));
    try std.testing.expect(v[before + 20].eql(builder.ivalue.qm31FromU32s(words[26], words[27], words[28], words[29])));

    try std.testing.expectEqual(null, try ctx.circuit.firstYieldViolation(gpa));
    try std.testing.expect(try ctx.isCircuitValid());
}

test "zk blinding: requires a finalized context and matches topology mode" {
    const gpa = std.testing.allocator;
    var topology = try builder.Context(builder.NoValue).init(gpa, 0);
    defer topology.deinit();
    try std.testing.expectError(error.NotFinalized, addZkBlinding(builder.NoValue, &topology, @splat(1), 1));
    try topology.finalize(false);
    try addZkBlinding(builder.NoValue, &topology, @splat(1), 3);
    var values = try builder.Context(QM31).init(gpa, 0);
    defer values.deinit();
    try values.finalize(false);
    try addZkBlinding(QM31, &values, @splat(1), 3);
    const a = try builder.debug_format.circuitText(gpa, &values.circuit);
    defer gpa.free(a);
    const b = try builder.debug_format.circuitText(gpa, &topology.circuit);
    defer gpa.free(b);
    try std.testing.expectEqualStrings(a, b);
}

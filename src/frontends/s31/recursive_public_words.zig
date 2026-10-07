//! Bind a recursive verifier's packed u32 public words to canonical M31
//! wires. S31 leaf outputs are M31, while the verifier transcript represents
//! each word as (low_u16, high_u16, 0, 0) in QM31. These encodings must not
//! be treated as the same circuit variable.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const poseidon2 = @import("poseidon2.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = circuit.builder.Var;
const Blake = circuit.builder.blake;
const NoValue = circuit.builder.NoValue;

/// `packed_output` must be the actual output claim used by the child STARK
/// verifier. The M31 values are witnessed and constrained here; each is
/// re-encoded as u32 and equated to the corresponding verified public word.
pub fn bindCanonicalM31Output(
    comptime V: type,
    ctx: *circuit.builder.Context(V),
    packed_output: Blake.HashValue(Var),
    values: [8]V,
) ![8]Var {
    var words: [8]Var = undefined;
    for (packed_output.words, values, &words) |packed_word, value, *out| {
        const canonical = try ctx.guessM31(value);
        const encoded = try Blake.m31ToU32(V, ctx, canonical);
        try ctx.eq(encoded.get(), packed_word.get());
        out.* = canonical;
    }
    return words;
}

test "recursive public words bind packed u32 to canonical M31" {
    const expected = [8]u32{ 928491885, 399009276, 910063533, 515587455, 1714177619, 700256356, 272818236, 1829149449 };
    var word_values: [8]QM31 = undefined;
    for (expected, &word_values) |word, *value|
        value.* = QM31.fromBase(M31.fromCanonical(word));

    var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 8);
    defer ctx.deinit();
    const output = try Blake.guessHash(QM31, &ctx, Blake.hashValue(QM31, expected));
    const canonical = try bindCanonicalM31Output(QM31, &ctx, output, word_values);
    try ctx.setOutputs(&canonical);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
    for (canonical, word_values) |wire, value|
        try std.testing.expectEqual(value, ctx.value_table.items[wire.idx]);

    const original = ctx.value_table.items[canonical[0].idx];
    ctx.value_table.items[canonical[0].idx] = QM31.fromBase(M31.fromCanonical(expected[0] + 1));
    try std.testing.expect(!try ctx.isCircuitValid());
    ctx.value_table.items[canonical[0].idx] = original;
    try std.testing.expect(try ctx.isCircuitValid());

    var topology = try circuit.builder.Context(NoValue).init(std.testing.allocator, 8);
    defer topology.deinit();
    const packed_empty = try Blake.guessHash(NoValue, &topology, Blake.hashValue(NoValue, @splat(0)));
    const empty = try bindCanonicalM31Output(NoValue, &topology, packed_empty, [_]NoValue{.{}} ** 8);
    try topology.setOutputs(&empty);
    try topology.finalize(false);
    try std.testing.expectEqual(ctx.circuit.n_vars, topology.circuit.n_vars);
    try std.testing.expectEqualDeep(ctx.circuit.add.items, topology.circuit.add.items);
    try std.testing.expectEqualDeep(ctx.circuit.eq.items, topology.circuit.eq.items);
    try std.testing.expectEqualDeep(ctx.circuit.m31_to_u32.items, topology.circuit.m31_to_u32.items);
    try std.testing.expectEqualDeep(ctx.circuit.output.items, topology.circuit.output.items);
}

test "recursive public words reject a noncanonical u32 claim" {
    const raw_words = [8]u32{ core.fields.m31.Modulus, 0, 0, 0, 0, 0, 0, 0 };
    var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 8);
    defer ctx.deinit();
    const output = try Blake.guessHash(QM31, &ctx, Blake.hashValue(QM31, raw_words));
    const canonical = try bindCanonicalM31Output(QM31, &ctx, output, .{QM31.zero()} ** 8);
    try ctx.setOutputs(&canonical);
    try ctx.finalize(false);
    try std.testing.expect(!try ctx.isCircuitValid());
}

test "packed child statement composes with constrained Bitcoin state link" {
    const old_u16 = [16]u32{ 57967, 2700, 61878, 29363, 42689, 18082, 25518, 20471, 7827, 25987, 23265, 39944, 54888, 25, 0, 0 };
    const new_u16 = [16]u32{ 24648, 6379, 7103, 8214, 32483, 37012, 35580, 30018, 16660, 55151, 22865, 34475, 36456, 33690, 0, 0 };
    const link_words = [8]u32{ 928491885, 399009276, 910063533, 515587455, 1714177619, 700256356, 272818236, 1829149449 };
    var old_values: [16]QM31 = undefined;
    var new_values: [16]QM31 = undefined;
    var old_host: [16]M31 = undefined;
    for (old_u16, &old_values, &old_host) |word, *value, *host| {
        host.* = M31.fromCanonical(word);
        value.* = QM31.fromBase(host.*);
    }
    for (new_u16, &new_values) |word, *value| value.* = QM31.fromBase(M31.fromCanonical(word));
    const old_root = poseidon2.leafWords(&old_host);
    var claimed_values: [8]QM31 = undefined;
    for (link_words, &claimed_values) |word, *value| value.* = QM31.fromBase(M31.fromCanonical(word));

    var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 8);
    defer ctx.deinit();
    const child_claim = try Blake.guessHash(QM31, &ctx, Blake.hashValue(QM31, link_words));
    const bound_link = try bindCanonicalM31Output(QM31, &ctx, child_claim, claimed_values);
    var authenticated_old: [8]Var = undefined;
    for (old_root, &authenticated_old) |word, *out| out.* = try ctx.guessM31(QM31.fromBase(word));
    const new_root = try poseidon2.constrainLinkedState(QM31, &ctx, old_values, new_values, authenticated_old, bound_link);
    try ctx.setOutputs(&new_root);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());

    const original = ctx.value_table.items[authenticated_old[0].idx];
    ctx.value_table.items[authenticated_old[0].idx] = QM31.fromBase(old_root[0].add(M31.one()));
    try std.testing.expect(!try ctx.isCircuitValid());
    ctx.value_table.items[authenticated_old[0].idx] = original;
    try std.testing.expect(try ctx.isCircuitValid());
}

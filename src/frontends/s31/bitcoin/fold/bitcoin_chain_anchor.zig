//! A proofable fixed-layout anchor for a Bitcoin hash-chain fold. Its eight
//! public words are exactly the key-pinned checkpoint root. It has no private
//! Bitcoin claim; the checkpoint is an explicit trust input to the fold key.
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const std = @import("std");

const QM31 = core.fields.qm31.QM31;
const Var = circuit.builder.Var;
const Blake = circuit.builder.blake;
const Sizes = circuit.common.finalize.ComponentSizes;

pub fn build(
    comptime V: type,
    allocator: std.mem.Allocator,
    checkpoint: [8]u32,
    targets: Sizes,
) !circuit.builder.Context(V) {
    for (checkpoint) |word| if (word >= core.fields.m31.Modulus) return error.NonCanonicalCheckpoint;
    var ctx = try circuit.builder.Context(V).init(allocator, circuit.common.component_list.N_RESERVED);
    errdefer ctx.deinit();
    const public_words = try Blake.constantHash(V, &ctx, Blake.hashValue(QM31, checkpoint));
    var outputs: [8]Var = undefined;
    for (public_words.words, &outputs) |word, *wire| wire.* = word.get();
    try ctx.setOutputs(&outputs);
    try ctx.finalize(false);
    try circuit.common.finalize.padToTargets(V, &ctx, targets);
    return ctx;
}

test "Bitcoin checkpoint anchor has the same AIR in value and topology modes" {
    const checkpoint = [8]u32{ 93892305, 397617766, 1762064199, 2128125525, 211345822, 958247097, 595994426, 1074837273 };
    const targets: Sizes = .{ .eq = 1024, .qm31_ops = 1024, .m31_to_u32 = 1024, .triple_xor = 1024, .blake_g_gate = 1024 };
    var values = try build(QM31, std.testing.allocator, checkpoint, targets);
    defer values.deinit();
    var topology = try build(circuit.builder.NoValue, std.testing.allocator, checkpoint, targets);
    defer topology.deinit();
    try std.testing.expect(try values.isCircuitValid());
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    try std.testing.expectEqualDeep(values.circuit.add.items, topology.circuit.add.items);
    try std.testing.expectEqualDeep(values.circuit.eq.items, topology.circuit.eq.items);
    try std.testing.expectEqualDeep(values.circuit.triple_xor.items, topology.circuit.triple_xor.items);
    try std.testing.expectEqualDeep(values.circuit.m31_to_u32.items, topology.circuit.m31_to_u32.items);
    try std.testing.expectEqualDeep(values.circuit.blake_g_gate.items, topology.circuit.blake_g_gate.items);
    try std.testing.expectEqualDeep(values.circuit.output.items, topology.circuit.output.items);
    for (values.circuit.output.items[1..9], checkpoint) |wire, expected|
        try std.testing.expectEqual(expected, circuit.builder.ivalue.unpackU32(QM31, values.value_table.items[wire]));
    values.value_table.items[values.circuit.output.items[1]] = QM31.zero();
    try std.testing.expect(!try values.isCircuitValid());

    var invalid = checkpoint;
    invalid[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalCheckpoint, build(circuit.builder.NoValue, std.testing.allocator, invalid, targets));
}

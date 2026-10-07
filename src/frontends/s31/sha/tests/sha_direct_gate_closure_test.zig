//! Algebraic integration check for the direct caller's Gate lookup boundary.
//! The full joined STARK must perform this same zero-sum check after both
//! interaction claims are committed. This test alone is not a proof.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const relation = @import("../../language/relation.zig");
const compiler = @import("../../language/relation_compiler.zig");
const plan = @import("../config/sha_chip_plan.zig");
const caller = @import("../air/sha_caller_stream_air.zig");
const bus = @import("../air/sha_caller_stream_bus.zig");
const word_bus = @import("../air/sha_direct_word_bus.zig");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;

test "direct caller Gate claim closes against the sparse-wide Bitcoin circuit" {
    const a = std.testing.allocator;
    const source = @embedFile("../../examples/bitcoin/bitcoin_header_pow.s31.json");
    var program = try relation.parseProgram(a, source);
    defer program.deinit();
    var assignment = try relation.parseAssignment(a, @embedFile("../../examples/bitcoin/bitcoin_header_pow.valid.json"));
    defer assignment.deinit();

    var value_maps = compiler.Maps{};
    defer value_maps.deinit(a);
    var values = try compiler.compileShaChipWithSpans(QM31, a, program.value, assignment.value, &value_maps);
    defer values.deinit();
    var topology_maps = compiler.Maps{};
    defer topology_maps.deinit(a);
    var topology = try compiler.compileShaChipWithSpans(circuit.builder.NoValue, a, program.value, null, &topology_maps);
    defer topology.deinit();
    const addresses = value_maps.sha_boundaries.items[0].addresses;
    try std.testing.expectEqualSlices(u32, &addresses, &topology_maps.sha_boundaries.items[0].addresses);
    const raw = circuit.common.finalize.rawComponentSizes(.fromBuilder(&topology.circuit));
    const targets: circuit.common.finalize.ComponentSizes = .{
        .eq = circuit.common.finalize.paddedSize(raw.eq),
        .qm31_ops = circuit.common.finalize.paddedSize(raw.qm31_ops),
        .m31_to_u32 = circuit.common.finalize.paddedSize(raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    };
    try circuit.common.finalize.padToTargets(QM31, &values, targets);
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &topology, targets);
    var pp = try circuit.common.sparse_wide.Circuit.fromBuilderCircuitWithShaBoundary(a, &topology.circuit, .{ .addresses = addresses });
    defer pp.deinit(a);
    var base = try circuit.witness.sparse_wide.writeBase(a, values.values(), &pp);
    defer base.deinit();

    const words = try relation.inputValues(a, assignment.value, program.value.inputs[0]);
    defer a.free(words);
    var header: [80]u8 = undefined;
    for (words, 0..) |word, i|
        std.mem.writeInt(u16, header[2 * i ..][0..2], @intCast(word.toU32()), .little);
    const statement = caller.Statement{
        .digest = plan.prepare(header).digest,
        .config = .{ .gate_addresses = addresses, .first_call_id = 1 },
    };
    var fixed = try bus.writeFixed(a, statement.config);
    defer fixed.deinit();
    var caller_fixed = try caller.writeFixed(a, statement);
    defer caller_fixed.deinit();
    var main = try caller.writeMain(a, header);
    defer main.deinit();
    try caller.validateCommittedTrace(statement, caller_fixed.values, main.values);

    var channel = @import("stwo_circuit_cpu_integration").prove.profiles.Blake2sM31MerkleChannel.Channel{};
    channel.mixFelts(&.{QM31.fromBase(M31.fromCanonical(0x5333_3103))});
    const gate_challenge = try core.channel.lookup_transcript.drawLookupElements(a, &channel);
    const word_challenge = try core.channel.lookup_transcript.drawLookupElements(a, &channel);
    const gate = word_bus.Elements.init(gate_challenge.z, gate_challenge.alpha);
    const word = word_bus.Elements.init(word_challenge.z, word_challenge.alpha);
    var circuit_interaction = try circuit.witness.sparse_wide.writeInteraction(a, &base, &pp, gate_challenge.z, gate_challenge.alpha);
    defer circuit_interaction.deinit();
    var caller_interaction = try bus.writeInteraction(a, fixed.values, main.values, statement.config, gate, word);
    defer caller_interaction.deinit();
    const circuit_sum = try circuit.witness.sparse_wide.lookupSum(base.output_values, circuit_interaction.claimed_sums, gate_challenge.z, gate_challenge.alpha);
    try std.testing.expect(circuit_sum.add(caller_interaction.gate_claimed_sum).isZero());

    // A different private header preserves the caller's local equations but
    // cannot impersonate the circuit's committed Gate values.
    var altered = header;
    altered[0] ^= 1;
    var changed_main = try caller.writeMain(a, altered);
    defer changed_main.deinit();
    var changed_interaction = try bus.writeInteraction(a, fixed.values, changed_main.values, statement.config, gate, word);
    defer changed_interaction.deinit();
    try std.testing.expect(!circuit_sum.add(changed_interaction.gate_claimed_sum).isZero());
}

//! One private Bitcoin header, one sparse-wide circuit, one direct SHA AIR
//! roster, one PCS/FRI proof. The v2 profile publishes only the Poseidon root;
//! the SHA digest is a private witness connected through the Gate lookup.
//! The low PoW/query config is test-only.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const relation = @import("../../language/relation.zig");
const compiler = @import("../../language/relation_compiler.zig");
const sha_plan = @import("../config/sha_chip_plan.zig");
const joint = @import("../proving/sha_direct_circuit_prover.zig");
const native = @import("../verification/sha_direct_circuit_native_verifier.zig");
const profile = @import("../config/sha_direct_circuit_profile.zig");

test "one private Bitcoin header has a single circuit and direct SHA proof" {
    const a = std.testing.allocator;
    const source = @embedFile("../../examples/bitcoin/bitcoin_header_pow.s31.json");
    var program = try relation.parseProgram(a, source);
    defer program.deinit();
    var assignment = try relation.parseAssignment(a, @embedFile("../../examples/bitcoin/bitcoin_header_pow.valid.json"));
    defer assignment.deinit();
    var value_maps = compiler.Maps{};
    defer value_maps.deinit(a);
    var values = try compiler.compileShaChipWithSpans(core.fields.qm31.QM31, a, program.value, assignment.value, &value_maps);
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
    try circuit.common.finalize.padToTargets(core.fields.qm31.QM31, &values, targets);
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &topology, targets);
    var pp = try circuit.common.sparse_wide.Circuit.fromBuilderCircuitWithShaBoundary(a, &topology.circuit, .{ .addresses = addresses });
    defer pp.deinit(a);
    const input_words = try relation.inputValues(a, assignment.value, program.value.inputs[0]);
    defer a.free(input_words);
    var header: [80]u8 = undefined;
    for (input_words, 0..) |word, i|
        std.mem.writeInt(u16, header[2 * i ..][0..2], @intCast(word.toU32()), .little);
    const statement = @import("../config/sha_direct_private_join_profile.zig").PublicStatement{
        .digest_visibility = .private,
        .config = .{ .gate_addresses = addresses, .first_call_id = 1 },
    };
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &source_digest, .{});
    const production = std.posix.getenv("S31_SHA_DIRECT_PRODUCTION_BENCH") != null;
    const fri = try core.pcs.config_v2.FriConfigV2.init(if (production) 26 else 0, 0, 1, if (production) 70 else 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, @max(pp.traceLogSize(), 7));
    const key = try native.deriveKey(a, source_digest, &pp, @intCast(values.circuit.n_vars), statement, pcs);
    try std.testing.expect(std.mem.allEqual(u8, &key.statement.digest, 0));
    const canonical_fixed = try native.canonicalFixedColumns(a, &pp, statement);
    defer native.freeCanonicalFixedColumns(a, canonical_fixed);
    const caller_fixed_offset = profile.shaPrefix().fixed;
    for (20..28) |row| {
        const storage = @import("../air/sha_caller_stream_air.zig").storageIndex(row);
        for ([_]usize{ 3, 6, 7 }) |digest_column| {
            try std.testing.expect(canonical_fixed[caller_fixed_offset + digest_column].values[storage].isZero());
        }
    }
    const public_words = try relation.claimedWords(a, program.value, assignment.value);
    var outputs: [8]core.fields.qm31.QM31 = undefined;
    for (public_words, 0..) |word, i|
        outputs[i] = core.fields.qm31.QM31.fromM31(
            core.fields.m31.M31.fromCanonical(word & 0xffff),
            core.fields.m31.M31.fromCanonical(word >> 16),
            core.fields.m31.M31.zero(),
            core.fields.m31.M31.zero(),
        );
    var bundle = try cpu.air.parse(a, @embedFile("s31_air_programs"));
    defer bundle.deinit();
    var timer = try std.time.Timer.start();
    var metrics = joint.Metrics{};
    var proof = try joint.prove(a, values.values(), &pp, &bundle, pcs, .{
        .source_digest = source_digest,
        .n_vars = @intCast(values.circuit.n_vars),
        .statement = statement,
        .header = header,
        .metrics = &metrics,
    });
    defer proof.deinit();
    const prove_ns = timer.read();
    try std.testing.expectEqualDeep(key.fixed_root, proof.key.fixed_root);
    try std.testing.expectEqualSlices(core.fields.qm31.QM31, &outputs, proof.outputs);
    const bytes = try joint.serialize(a, &proof);
    defer a.free(bytes);
    timer.reset();
    try native.verifyBytes(a, .{ .key = key, .public_outputs = &outputs }, bytes);
    const verify_ns = timer.read();
    std.debug.print("S31_SHA_DIRECT_CIRCUIT verified=true digest_public=false calls=3 components={d} columns={any} prove_ms={d} verify_ms={d} proof_bytes={d} pow_bits={d} queries={d}\n", .{
        profile.component_count,        profile.debugWidths(), prove_ns / std.time.ns_per_ms,
        verify_ns / std.time.ns_per_ms, bytes.len,             fri.pow_bits,
        fri.n_queries,
    });
    std.debug.print("S31_SHA_DIRECT_CIRCUIT_STAGES witness_ms={d} fixed_commit_ms={d} main_commit_ms={d} interaction_ms={d} interaction_pow_ms={d} interaction_commit_ms={d} fri_ms={d} fri_pow_ms={d} columns={d}/{d}/{d}\n", .{
        metrics.witness_ns / std.time.ns_per_ms,
        metrics.fixed_commit_ns / std.time.ns_per_ms,
        metrics.main_commit_ns / std.time.ns_per_ms,
        metrics.interaction_ns / std.time.ns_per_ms,
        metrics.interaction_pow_ns / std.time.ns_per_ms,
        metrics.interaction_commit_ns / std.time.ns_per_ms,
        metrics.fri_ns / std.time.ns_per_ms,
        metrics.fri_pow_ns / std.time.ns_per_ms,
        metrics.fixed_columns,
        metrics.main_columns,
        metrics.interaction_columns,
    });
    var changed_outputs = outputs;
    changed_outputs[0] = changed_outputs[0].add(core.fields.qm31.QM31.one());
    if (native.verifyBytes(a, .{ .key = key, .public_outputs = &changed_outputs }, bytes)) |_|
        return error.ChangedPublicOutputAccepted
    else |_| {}
    var changed_key = key;
    changed_key.source_digest[0] ^= 1;
    try std.testing.expectError(error.WrongDirectCircuitKeyDigest, native.verifyBytes(a, .{ .key = changed_key, .public_outputs = &outputs }, bytes));
    changed_key = key;
    changed_key.statement.digest[0] ^= 1;
    try std.testing.expectError(error.PrivateShaDigestMustBeZero, native.verifyBytes(a, .{ .key = changed_key, .public_outputs = &outputs }, bytes));
    changed_key = key;
    changed_key.statement.digest_visibility = .public;
    try std.testing.expectError(error.PublicDigestForbiddenInDirectCircuitV2, native.verifyBytes(a, .{ .key = changed_key, .public_outputs = &outputs }, bytes));
    const changed_bytes = try a.dupe(u8, bytes);
    defer a.free(changed_bytes);
    changed_bytes[profile.magic.len + 8 + 16 * 4] ^= 1;
    if (native.verifyBytes(a, .{ .key = key, .public_outputs = &outputs }, changed_bytes)) |_|
        return error.ChangedGateClaimAccepted
    else |_| {}
    var changed_header = header;
    changed_header[0] ^= 1;
    try std.testing.expect(!std.mem.eql(u8, &sha_plan.prepare(header).digest, &sha_plan.prepare(changed_header).digest));
    try std.testing.expectError(error.InvalidDirectCircuitGateClosure, joint.prove(a, values.values(), &pp, &bundle, pcs, .{
        .source_digest = source_digest,
        .n_vars = @intCast(values.circuit.n_vars),
        .statement = statement,
        .header = changed_header,
    }));
}

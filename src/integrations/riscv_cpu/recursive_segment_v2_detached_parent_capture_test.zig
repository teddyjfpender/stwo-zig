//! Real recursive-parent capture and consuming arithmetic regression. The
//! retained parent is verified; this gate does not prove its next consumer.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const verifier = @import("recursive_segment_v2_detached_parent_verifier.zig");
const command = @import("recursive_segment_v2_detached_parent_command.zig");
const cohort = @import("recursive_segment_v2_detached_parent_cohort.zig");
const composition = @import("recursive_segment_v2_detached_composition.zig");
const v3 = recursion.recursion_air_composition_circuit_v3;
const QM31 = core.fields.qm31.QM31;

test "detached parent capture replays genuine sparse cohort after input destruction" {
    const allocator = std.testing.allocator;
    var key: *command.OwnedKeyV1 = undefined;
    var expected: verifier.ExpectedV1 = undefined;
    var claims: verifier.ClaimsV1 = undefined;
    const Owner = @import("recursive_segment_v2_detached_child_transcript.zig").ParentOwnedV1;
    var owner: *Owner = undefined;
    {
        var input_arena = std.heap.ArenaAllocator.init(allocator);
        defer input_arena.deinit();
        const a = input_arena.allocator();
        const directory = try std.process.getEnvVarOwned(a, "STWO_DETACHED_PARENT_BUNDLE");
        const pin_hex = try std.process.getEnvVarOwned(a, "STWO_DETACHED_PARENT_KEY_SHA256");
        const expected_path = try std.process.getEnvVarOwned(a, "STWO_DETACHED_PARENT_EXPECTED_ROOT");
        var pin: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pin, pin_hex);
        var dir = try std.fs.cwd().openDir(directory, .{});
        defer dir.close();
        const key_bytes = try dir.readFileAlloc(a, "key.json", command.MAX_KEY_BYTES);
        key = try command.OwnedKeyV1.admit(allocator, key_bytes, pin);
        errdefer key.deinit();
        expected = try command.decodeExpected(a, try std.fs.cwd().readFileAlloc(a, expected_path, command.MAX_INPUT_BYTES));
        const envelope = try command.decodeClaims(a, try dir.readFileAlloc(a, "claims.json", command.MAX_INPUT_BYTES));
        claims = envelope.claims;
        const proof = try dir.readFileAlloc(a, "proof.bin", envelope.proof_bytes);
        try std.testing.expectEqual(envelope.proof_bytes, proof.len);
        try std.testing.expectEqual(envelope.proof_sha256, command.hash(proof));
        const terminal = try verifier.verify(allocator, key.key(), &expected, claims, proof);
        owner = try Owner.init(allocator, key_bytes, pin, &expected, claims, proof);
        errdefer owner.deinit();
        try std.testing.expectEqual(terminal, owner.terminal());
        // The owner must copy all three inputs, including fixed public words.
        @memset(key_bytes, 0);
        @memset(&expected, core.fields.m31.M31.zero());
        claims.values = @splat(QM31.zero());
        @memset(proof, 0); // No borrowed input survives the arena destruction.
    }
    defer key.deinit();
    defer owner.deinit();
    try @import("recursive_segment_v2_detached_boundary.zig").testing.parentBoundary(allocator, owner);
    expected = owner.expected().*;
    claims = owner.claims();
    const capture = owner.captureView();
    var layout = try owner.compositionLayout(allocator);
    defer layout.deinit();
    const profile = v3.InputProfileV3{ .sampled_value_count = layout.sampled_value_count };
    const components = try cohort.OwnedComponentsV1.init(allocator, &key.key().manifest, key.key().parameters, owner.relations(), claims);
    defer components.deinit();
    var program = try composition.recordDetached(.binary_node, allocator, &key.key().manifest, &layout, profile, components);
    defer program.circuit.deinit();
    defer allocator.free(program.bindings);
    const inputs = try allocator.alloc(QM31, try recursion.air.composition_circuit.recursionInputCount(profile.graphProfile()));
    defer allocator.free(inputs);
    try owner.writeCompositionInputs(profile, inputs);
    const scratch = try allocator.alloc(QM31, program.circuit.nodes.len);
    defer allocator.free(scratch);
    try program.circuit.evaluateInto(inputs, scratch);
    var mutations: usize = 0;
    for (program.bindings, 0..) |binding, index| {
        const mutate = switch (binding.source) {
            .claimed_sum => |coordinate| coordinate.word_index == 0,
            .sampled_value => |coordinate| coordinate.item_index == layout.offsets[v3.capture_layout_v3.COMPOSITION_TREE_INDEX][0],
            else => false,
        };
        if (!mutate) continue;
        const saved = inputs[index];
        defer inputs[index] = saved;
        inputs[index] = saved.add(QM31.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, program.circuit.evaluateInto(inputs, scratch));
        mutations += 1;
    }
    try std.testing.expectEqual(@as(usize, 45), mutations);
    const prefix_module = @import("recursive_segment_v2_detached_prefix.zig");
    const prefix = try prefix_module.OwnedV1.init(allocator, owner, 1);
    defer prefix.deinit();
    const transcript = try @import("recursive_segment_v2_detached_pcs_rows.zig").OwnedV1.init(allocator, owner, prefix, 1);
    defer transcript.deinit();
    var public_limbs: usize = 0;
    for (prefix.view().payload) |row| {
        const pp = row.preprocessing;
        if (pp.source_kind != .statement) continue;
        try std.testing.expectEqual(@as(u32, 0), pp.constant_mask);
        try std.testing.expectEqual(@as(u32, 1), pp.input_use_count);
        const word = pp.item_index - prefix_module.RAW_WIRE_BASE;
        try std.testing.expect(word < expected.len and pp.limb_index < 2);
        const wanted = (expected[word].toU32() >> @as(u5, @intCast(pp.limb_index * 16))) & 0xffff;
        try std.testing.expectEqual(wanted, row.value.toU32());
        public_limbs += 1;
    }
    try std.testing.expectEqual(@as(usize, 2 * expected.len), public_limbs);
    try std.testing.expectEqual(owner.recordingView().trace.poseidon_calls.len, prefix.view().provider.len + transcript.view().provider.len);
    const prepared_composition = try composition.OwnedV1.init(allocator, owner);
    defer prepared_composition.deinit();
    try std.testing.expectEqual(program.circuit.nodes.len, prepared_composition.evaluatedValues().len);
    const pcs = try @import("recursive_segment_v2_detached_pcs_checks.zig").OwnedV1.init(allocator, owner, 1);
    defer pcs.deinit();
    std.debug.print("DETACHED_PARENT_CAPTURE active_rows={d} physical_claims={d} sampled_values={d} graph_nodes={d} rejected_claims_and_samples={d} public_transcript_limbs={d} input_destroyed=true parent_verified=true consumer_proof_created=false\n", .{ key.key().manifest.roster_count, claims.values.len, capture.sampled_values.len, program.circuit.nodes.len, mutations, public_limbs });
}

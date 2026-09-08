//! Recursive transcript witness reconstructed from an explicitly keyed proof.
//! No grandchild artifacts, producer cohort, or native closure receipts enter
//! this path. The result is witness data; parent AIR must still constrain it.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const verifier = @import("recursive_common_fold_detached_verifier_v2.zig");
const public = @import("recursive_field_node_public_v2.zig");
const program_mod = @import("recursive_secure_transcript_program_v1.zig");
const rows_mod = @import("recursive_secure_transcript_rows_v1.zig");
const recording = recursion.recording_poseidon_channel_v4;
const universal = recursion.air.universal_challenges;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const capture_mod = @import("recursive_common_fold_composition_capture_v2.zig");
const manifest_mod = @import("recursive_common_fold_universal_manifest_v2.zig");
const composition_v3 = recursion.recursion_air_composition_circuit_v3;

pub const Owned = struct {
    allocator: std.mem.Allocator,
    key: verifier.Key,
    node: public.NodePublicV2,
    claims: verifier.Claims,
    capture: verifier.ProofCapture,
    program: program_mod.Program,
    execution: recording.ExecutionV4,
    relations: universal.UniversalRelations,
    query_words: [193]M31,
    query_log_size: u32,

    pub fn init(allocator: std.mem.Allocator, key: *const verifier.Key, node: *const public.NodePublicV2, claims: *const verifier.Claims, nonce: u64, proof_bytes: []const u8) !Owned {
        return initWithNamespace(allocator, key, node, claims, nonce, proof_bytes, null);
    }

    pub fn initEthereumFoldV1(allocator: std.mem.Allocator, key: *const verifier.EthereumKeyV1, node: *const public.NodePublicV2, claims: *const verifier.Claims, nonce: u64, proof_bytes: []const u8) !Owned {
        try key.validate();
        return initWithNamespace(allocator, &key.key, node, claims, nonce, proof_bytes, key);
    }

    fn initWithNamespace(allocator: std.mem.Allocator, key: *const verifier.Key, node: *const public.NodePublicV2, claims: *const verifier.Claims, nonce: u64, proof_bytes: []const u8, ethereum_key: ?*const verifier.EthereumKeyV1) !Owned {
        var capture: verifier.ProofCapture = undefined;
        const terminal = if (ethereum_key) |admission| try admission.verifyWithCapture(allocator, node, claims, nonce, proof_bytes, &capture) else try verifier.verifyWithCapture(allocator, key, node, claims, nonce, proof_bytes, &capture);
        errdefer capture.deinit(allocator);
        var program = if (ethereum_key) |admission| try program_mod.Program.initEthereumFoldKeyV1(allocator, admission, &capture) else try program_mod.Program.init(allocator, .common_fold, &key.manifest, &capture);
        errdefer program.deinit();
        const query_log_size = try @import("recursive_common_wrapper_authority_v2.zig").queryLogSizeFromCapture(&capture);
        var channel = recording.Channel.init(allocator);
        defer channel.deinit();
        var draws: [universal.DRAW_COUNT]QM31 = undefined;
        var relation_at: usize = 0;
        var query_words: [193]M31 = undefined;
        var query_at: usize = 0;
        const query_mask = (@as(u32, 1) << @intCast(query_log_size)) - 1;
        for (program.operations) |op| {
            channel.setContextTag(@intFromEnum(op.context));
            switch (op.effect) {
                .mix => try mix(&channel, op, node, claims, &capture),
                .pow => {
                    const value = switch (op.item) {
                        0 => nonce,
                        1 => capture.proof_of_work,
                        else => return error.InvalidDetachedTranscript,
                    };
                    if (!channel.verifyPowNonce(op.pow_bits, value)) return error.InvalidDetachedTranscript;
                    channel.mixU64(value);
                },
                .draw => {
                    const words = channel.drawU32s();
                    const value = secure(words[0..4].*);
                    switch (op.draw) {
                        .relation => {
                            if (op.item * 2 != relation_at or relation_at + 2 > draws.len) return error.InvalidDetachedTranscript;
                            draws[relation_at] = value;
                            draws[relation_at + 1] = secure(words[4..8].*);
                            relation_at += 2;
                        },
                        .queries => {
                            if (op.item != query_at or query_at + op.draw_word_count > query_words.len) return error.InvalidDetachedTranscript;
                            for (words[0..op.draw_word_count]) |word| {
                                if (word >= core.fields.m31.Modulus or (word & query_mask) != capture.queries.raw[query_at]) return error.InvalidDetachedTranscript;
                                query_words[query_at] = M31.fromCanonical(word);
                                query_at += 1;
                            }
                        },
                        .composition => try same(value, capture.composition_randomness),
                        .oods => try same(value, capture.oods_seed),
                        .deep => try same(value, capture.deep_randomness),
                        .fri_alpha => try same(value, capture.fri.layers[op.item].folding_alpha),
                        .none => return error.InvalidDetachedTranscript,
                    }
                },
            }
        }
        if (relation_at != draws.len or query_at != query_words.len) return error.InvalidDetachedTranscript;
        var execution = try channel.finish();
        errdefer execution.deinit();
        try program.validateRecording(&execution);
        if (!std.meta.eql(terminal, recursion.protocol.transcriptId(execution.final_digest, execution.final_draw_count))) return error.InvalidDetachedTranscript;
        const relations = universal.UniversalRelations.fromDraws(&draws);
        try relations.validate();
        return .{ .allocator = allocator, .key = key.*, .node = node.*, .claims = claims.*, .capture = capture, .program = program, .execution = execution, .relations = relations, .query_words = query_words, .query_log_size = query_log_size };
    }

    pub fn deinit(self: *Owned) void {
        self.execution.deinit();
        self.program.deinit();
        self.capture.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn view(self: *const Owned) rows_mod.View {
        return .{ .program = &self.program, .execution = &self.execution };
    }
};

/// Reuse the native composition recorder with definitions rebuilt from the key.
/// No witness cohort or replay receipt is needed to record and evaluate the AIR.
pub const Composition = struct {
    allocator: std.mem.Allocator,
    layout: composition_v3.capture_layout_v3.CaptureLayoutV3,
    profile: composition_v3.InputProfileV3,
    program: capture_mod.OwnedProgram,
    inputs: []QM31,
    values: []QM31,

    pub fn init(allocator: std.mem.Allocator, transcript: *const Owned) !Composition {
        var layout = try composition_v3.capture_layout_v3.CaptureLayoutV3.initAuthenticatedBinaryWithProviderRow(allocator, .common_fold_field_v2, 34, &transcript.key.manifest, &transcript.capture);
        errdefer layout.deinit();
        const profile = composition_v3.InputProfileV3{ .sampled_value_count = layout.sampled_value_count, .field_public_extra_word_count = public.AIR_WORD_COUNT - public.STATEMENT_WORD_COUNT };
        try profile.validate();
        const providers = try recursion.air.universal_shared_provider.SharedProviderRelations.init(&transcript.relations);
        const components = try verifier.Components.init(allocator, &transcript.key, &transcript.claims, &transcript.relations, &providers);
        defer components.deinit();
        var program = try capture_mod.recordProgram(recordComponents, allocator, &transcript.key.manifest, &layout, profile, components);
        errdefer program.deinit();
        const inputs = try allocator.alloc(QM31, try recursion.air.composition_circuit.recursionInputCount(profile.graphProfile()));
        errdefer allocator.free(inputs);
        var claims: [composition_v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31 = undefined;
        try composition_v3.writeClaimInputsForManifest(.binary_node, .common_fold_field_v2, &transcript.claims.values, &transcript.claims.poseidon_partials, &claims);
        try capture_mod.writePublicInputs(profile, &transcript.node, &claims, &transcript.relations, &transcript.capture, inputs);
        const values = try allocator.alloc(QM31, program.circuit.nodes.len);
        errdefer allocator.free(values);
        try program.circuit.evaluateInto(inputs, values);
        return .{ .allocator = allocator, .layout = layout, .profile = profile, .program = program, .inputs = inputs, .values = values };
    }

    pub fn deinit(self: *Composition) void {
        self.allocator.free(self.values);
        self.allocator.free(self.inputs);
        self.program.deinit();
        self.layout.deinit();
        self.* = undefined;
    }
};

fn recordComponents(program: anytype, components: *const verifier.Components) @TypeOf(program.finishProgram()) {
    inline for (manifest_mod.catalog.LOGICAL_ROWS, 0..) |entry, index|
        _ = try program.recordTypedComponent(entry.row, &components.logical[index]);
    _ = try program.recordPoseidonProvider(&components.poseidon);
    _ = try program.recordRangeCheck8x8Provider(&components.range_component);
    return program.finishProgram();
}

fn mix(channel: *recording.Channel, op: program_mod.Operation, node: *const public.NodePublicV2, claims: *const verifier.Claims, capture: *const verifier.ProofCapture) !void {
    if (op.source.isConstantPayload()) {
        if (op.payload_words > op.constant_words.len) return error.InvalidDetachedTranscript;
        var words: [16]M31 = undefined;
        for (op.constant_words[0..op.payload_words], words[0..op.payload_words]) |word, *out| out.* = M31.fromCanonical(word);
        channel.mixCanonicalM31Words(words[0..op.payload_words]);
        return;
    }
    switch (op.source) {
        .commitment => mixRoot(channel, capture.commitments[op.item]),
        .statement => channel.mixU32s(&try node.canonicalAirWords()),
        .claim_value => channel.mixFelts(&.{claims.values[op.item]}),
        .provider_partial => channel.mixFelts(&claims.poseidon_partials),
        .sampled_values => channel.mixFelts(capture.sampled_values),
        .fri_commitment => mixRoot(channel, capture.fri.layers[op.item].commitment),
        .last_layer => channel.mixFelts(capture.last_layer_coefficients),
        else => return error.InvalidDetachedTranscript,
    }
}

fn mixRoot(channel: *recording.Channel, root: recording.Digest) void {
    var words: [8]M31 = undefined;
    for (root, &words) |word, *out| out.* = M31.fromCanonical(word);
    channel.mixCanonicalM31Words(&words);
}

fn secure(words: [4]u32) QM31 {
    return QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
}

fn same(actual: QM31, expected: QM31) !void {
    if (!actual.eql(expected)) return error.InvalidDetachedTranscript;
}

test "detached common-fold transcript reconstructs verified challenges and query words" {
    const allocator = std.testing.allocator;
    const transport = @import("recursive_common_fold_verifier_command_v2.zig");
    const directory = try std.process.getEnvVarOwned(allocator, "STWO_RECURSION_VERIFIER_INPUT_DIR");
    defer allocator.free(directory);
    var dir = try std.fs.cwd().openDir(directory, .{});
    defer dir.close();
    var key: verifier.Key = undefined;
    var inputs: transport.PublicInputs = undefined;
    var witness: Owned = undefined;
    {
        const key_bytes = try dir.readFileAlloc(allocator, "key.json", 1024 * 1024);
        defer allocator.free(key_bytes);
        var expected: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, "d851a6465f6edb02cbeb8a3bc8173b40b86ad6642e07b791478e8b08975a9b37");
        key = try transport.decodeKey(allocator, key_bytes, expected);
        const input_bytes = try dir.readFileAlloc(allocator, "inputs.json", 1024 * 1024);
        defer allocator.free(input_bytes);
        inputs = try transport.decodeInputs(allocator, input_bytes);
        const proof = try dir.readFileAlloc(allocator, "proof.bin", inputs.proof_bytes);
        defer allocator.free(proof);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(proof, &digest, .{});
        try std.testing.expectEqualDeep(inputs.proof_sha256, digest);
        witness = try Owned.init(allocator, &key, &inputs.node, &inputs.claims, inputs.interaction_pow_nonce, proof);
    }
    defer witness.deinit();
    // Input byte buffers are gone. The parent can still prepare owned AIR rows.
    var rows = try witness.view().prepareTranscriptRows(allocator, 1);
    defer rows.deinit();
    try std.testing.expectEqual(@as(usize, 193), witness.query_words.len);
    try std.testing.expectEqual(@as(usize, 47), rows.challenges.len);
    try std.testing.expectEqual(@as(usize, 454), rows.statement.len);
    try std.testing.expectEqual(.common_preprocessed_root, witness.program.operations[0].source);
    for (rows.payload[0..8], key.preprocessed_root) |row, word| {
        try std.testing.expectEqual(@as(u32, 1), row.preprocessing.constant_mask);
        try std.testing.expectEqual(word, row.preprocessing.constant_value);
        try std.testing.expectEqual(word, row.value.toU32());
    }
    const air_check = @import("recursive_secure_transcript_rows_v1_test.zig");
    try air_check.validate(&rows, &witness.program, &witness.execution);
    const original_root_word = rows.payload[0].value;
    rows.payload[0].value = original_root_word.add(M31.one());
    try std.testing.expectError(error.TranscriptConstraintMismatch, air_check.validate(&rows, &witness.program, &witness.execution));
    rows.payload[0].value = original_root_word;
    witness.program.operations[0].constant_words[0] ^= 1;
    try std.testing.expectError(error.InvalidRecursiveTranscriptProgram, witness.program.validateRecording(&witness.execution));
    witness.program.operations[0].constant_words[0] ^= 1;
    var total = (try @import("recursive_common_fold_public_output_v3.zig").derive(&inputs.node, &witness.relations)).claimed_sum;
    for (inputs.claims.values) |claim| total = total.add(claim);
    try std.testing.expect(total.isZero());
    var composition = try Composition.init(allocator, &witness);
    defer composition.deinit();
    const statement_start = 1 + composition_v3.PROGRAM_KIND_COUNT;
    composition.inputs[statement_start] = composition.inputs[statement_start].add(QM31.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, composition.program.circuit.evaluateInto(composition.inputs, composition.values));
    witness.execution.operations[0].context_tag ^= 1;
    try std.testing.expectError(error.InvalidRecording, witness.program.validateRecording(&witness.execution));
    witness.execution.operations[0].context_tag ^= 1;
    const changed_words = @constCast(witness.execution.hash_frames[0].words);
    changed_words[0] = changed_words[0].add(M31.one());
    if (witness.program.validateRecording(&witness.execution)) |_| return error.ChangedTranscriptAccepted else |_| {}
    std.debug.print("COMMON_FOLD_DETACHED_TRANSCRIPT proof_verified=true grandchild_inputs=false input_buffers_destroyed=true queries=193 relation_draws=94 changed_recording_rejected=true\n", .{});
}

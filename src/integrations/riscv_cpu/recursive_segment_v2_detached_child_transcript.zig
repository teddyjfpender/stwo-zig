//! Owned witness for the next recursive consumer of a detached SegmentV2 proof.
//! The sole verifier flow runs with the canonical recording channel. Native
//! replay validates its complete sponge execution; no legacy prefix is forged.
//! These projections are witness data, not admission of a parent circuit.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const recursion = frontend.recursion;
const verifier = @import("recursive_segment_v2_detached_verifier.zig");
const command = @import("recursive_segment_v2_detached_command.zig");
const components = @import("recursive_segment_v2_verifier_components.zig");
const recording = recursion.recording_poseidon_channel_v4;
const universal = recursion.air.universal_challenges;
const PublicData = frontend.air.public_data_v2.PublicDataV2;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Digest = recursion.poseidon2_channel.Digest;
const CirclePoint = core.circle.CirclePointQM31;

/// All slices are const, including nested capture views returned individually.
/// They remain valid until the owner is destroyed.
pub const CaptureViewV1 = struct {
    commitments: []const Digest,
    sampled_values: []const QM31,
    queried_values: []const M31,
    deep_answers: []const QM31,
    raw_queries: []const usize,
    unique_queries: []const usize,
    last_layer_coefficients: []const QM31,
    proof_of_work: u64,
    composition_randomness: QM31,
    oods_seed: QM31,
    deep_randomness: QM31,
    trace_count: usize,
    fri_layer_count: usize,
};
pub const FriLayerViewV1 = struct {
    commitment: Digest,
    folding_alpha: QM31,
    fold_step: u32,
    fold_width: u32,
    path_depth: u32,
    query_count: usize,
    positions: []const usize,
    values: []const QM31,
    siblings: []const Digest,
};
pub const TracePathViewV1 = struct { positions: []const usize, path_depth: u32, siblings: []const Digest };
pub const RecordingViewV1 = struct {
    trace: recording.TranscriptTrace,
    operations: []const recording.OperationV4,
    final_digest: Digest,
    final_draw_count: u32,
    identity_sha256: [32]u8,
};

pub const OwnedV1 = opaque {
    const Storage = struct {
        allocator: std.mem.Allocator,
        key: *command.OwnedKeyV1,
        expected: command.OwnedExpectedV1,
        claims: verifier.ClaimsV1,
        capture: verifier.ProofCapture,
        execution: recording.ExecutionV4,
        relations: components.Relations,
        terminal: Digest,
        key_sha256: [32]u8,
        proof_sha256: [32]u8,
    };

    /// Independently supplied key hash is mandatory. No pointer into caller
    /// key, statement, claims or serialized proof survives this transaction.
    pub fn init(allocator: std.mem.Allocator, key_json: []const u8, independent_key_sha256: [32]u8, expected_input: *const PublicData, input_claims: verifier.ClaimsV1, proof_bytes: []const u8) !*OwnedV1 {
        const owned_key = try command.OwnedKeyV1.admit(allocator, key_json, independent_key_sha256);
        errdefer owned_key.deinit();
        _ = try expected_input.metadata();
        const words = try allocator.dupe(M31, expected_input.words());
        errdefer allocator.free(words);
        const admitted_expected = try PublicData.authenticate(words);
        if (!std.meta.eql(admitted_expected.wireId(), expected_input.wireId())) return error.DetachedChildExpectedWireChanged;
        const owned_expected = command.OwnedExpectedV1{ .allocator = allocator, .words = words, .data = admitted_expected };
        var channel = recording.Channel.init(allocator);
        defer channel.deinit();
        var capture: verifier.ProofCapture = undefined;
        const result = try verifier.verifyWithCaptureRecording(allocator, owned_key.key(), &owned_expected.data, input_claims, proof_bytes, &channel, &capture);
        errdefer capture.deinit(allocator);
        // finish validates every recorded hash, PoW and draw against the native
        // channel, including the whole PCS/FRI suffix used by the real verifier.
        var execution = try channel.finish();
        errdefer execution.deinit();
        if (!std.meta.eql(result.terminal, recursion.protocol.transcriptId(execution.final_digest, execution.final_draw_count))) return error.DetachedChildTerminalMismatch;
        try validateDraws(&execution, &capture, &result.relations, owned_key.key().pcs_config.fri_config.n_queries);
        const owned_storage = try allocator.create(Storage);
        owned_storage.* = .{ .allocator = allocator, .key = owned_key, .expected = owned_expected, .claims = input_claims, .capture = capture, .execution = execution, .relations = result.relations, .terminal = result.terminal, .key_sha256 = independent_key_sha256, .proof_sha256 = command.hash(proof_bytes) };
        return @ptrCast(owned_storage);
    }

    pub fn deinit(self: *OwnedV1) void {
        const value: *Storage = @ptrCast(@alignCast(self));
        const allocator = value.allocator;
        value.execution.deinit();
        value.capture.deinit(allocator);
        value.expected.deinit();
        value.key.deinit();
        allocator.destroy(value);
    }
    fn storage(self: *const OwnedV1) *const Storage {
        return @ptrCast(@alignCast(self));
    }
    pub fn key(self: *const OwnedV1) *const verifier.KeyV1 {
        return self.storage().key.key();
    }
    pub fn expected(self: *const OwnedV1) *const PublicData {
        return &self.storage().expected.data;
    }
    pub fn claims(self: *const OwnedV1) verifier.ClaimsV1 {
        return self.storage().claims;
    }
    pub fn relations(self: *const OwnedV1) *const components.Relations {
        return &self.storage().relations;
    }
    pub fn terminal(self: *const OwnedV1) Digest {
        return self.storage().terminal;
    }
    pub fn keySha256(self: *const OwnedV1) [32]u8 {
        return self.storage().key_sha256;
    }
    pub fn proofSha256(self: *const OwnedV1) [32]u8 {
        return self.storage().proof_sha256;
    }
    pub fn recordingView(self: *const OwnedV1) RecordingViewV1 {
        const execution = &self.storage().execution;
        return .{ .trace = execution.trace(), .operations = execution.operations, .final_digest = execution.final_digest, .final_draw_count = execution.final_draw_count, .identity_sha256 = execution.identity_sha256 };
    }
    pub fn captureView(self: *const OwnedV1) CaptureViewV1 {
        const value = &self.storage().capture;
        return .{ .commitments = value.commitments, .sampled_values = value.sampled_values, .queried_values = value.queried_values, .deep_answers = value.deep_answers, .raw_queries = value.queries.raw, .unique_queries = value.queries.unique, .last_layer_coefficients = value.last_layer_coefficients, .proof_of_work = value.proof_of_work, .composition_randomness = value.composition_randomness, .oods_seed = value.oods_seed, .deep_randomness = value.deep_randomness, .trace_count = value.trace_paths.len, .fri_layer_count = value.fri.layers.len };
    }
    pub fn friLayer(self: *const OwnedV1, index: usize) FriLayerViewV1 {
        const value = &self.storage().capture.fri.layers[index];
        return .{ .commitment = value.commitment, .folding_alpha = value.folding_alpha, .fold_step = value.fold_step, .fold_width = value.fold_width, .path_depth = value.path_depth, .query_count = value.query_count, .positions = value.positions, .values = value.values, .siblings = value.siblings };
    }
    pub fn tracePath(self: *const OwnedV1, index: usize) TracePathViewV1 {
        const value = &self.storage().capture.trace_paths[index];
        return .{ .positions = value.positions, .path_depth = value.path_depth, .siblings = value.siblings };
    }
    /// Build the canonical composition projection without exposing mutable
    /// nested capture storage. The returned layout owns its allocations.
    pub fn compositionLayout(self: *const OwnedV1, allocator: std.mem.Allocator) !recursion.recursion_air_composition_circuit_v3.capture_layout_v3.CaptureLayoutV3 {
        return recursion.recursion_air_composition_circuit_v3.capture_layout_v3.CaptureLayoutV3.initSegment(allocator, &self.key().manifest, &self.storage().capture);
    }
    pub fn columnLogSizes(self: *const OwnedV1, tree: usize) []const u32 {
        return self.storage().capture.column_log_sizes[tree];
    }
    pub fn sampledPoints(self: *const OwnedV1, tree: usize, column: usize) []const CirclePoint {
        return self.storage().capture.sampled_points[tree][column];
    }
};

/// Independently map retained draw operations to the verifier-minted fields.
/// This checks ownership associations, not a second description of mix order.
fn validateDraws(execution: *const recording.ExecutionV4, capture: *const verifier.ProofCapture, relations: *const components.Relations, query_count: usize) !void {
    if (capture.queries.raw.len != query_count) return error.DetachedChildQueryMismatch;
    const query_log = try @import("recursive_common_wrapper_authority_v2.zig").queryLogSizeFromCapture(capture);
    if (query_log >= 32) return error.DetachedChildQueryMismatch;
    const query_mask = (@as(u32, 1) << @intCast(query_log)) - 1;
    var draw_at: usize = 0;
    var query_at: usize = 0;
    for (execution.operations) |operation| {
        if (operation.effect != .draw) continue;
        if (operation.hash_count != 1) return error.DetachedChildDrawMismatch;
        const frame = execution.hash_frames[operation.first_hash_id];
        if (frame.purpose != .draw) return error.DetachedChildDrawMismatch;
        const words = frame.output[0..recording.RATE].*;
        if (draw_at < universal.RELATION_COUNT) {
            const element = relations.elements[draw_at];
            try same(secure(words[0..4].*), element.z);
            try same(secure(words[4..8].*), element.alpha);
        } else switch (draw_at - universal.RELATION_COUNT) {
            0 => try same(secure(words[0..4].*), capture.composition_randomness),
            1 => try same(secure(words[0..4].*), capture.oods_seed),
            2 => try same(secure(words[0..4].*), capture.deep_randomness),
            else => |suffix_at| {
                const fri_at = suffix_at - 3;
                if (fri_at < capture.fri.layers.len) {
                    try same(secure(words[0..4].*), capture.fri.layers[fri_at].folding_alpha);
                } else {
                    if (query_at >= query_count) return error.DetachedChildDrawMismatch;
                    for (words[0..@min(recording.RATE, query_count - query_at)]) |word| {
                        if (capture.queries.raw[query_at] != @as(usize, word.toU32() & query_mask)) return error.DetachedChildQueryMismatch;
                        query_at += 1;
                    }
                }
            },
        }
        draw_at += 1;
    }
    const query_draws = std.math.divCeil(usize, query_count, recording.RATE) catch unreachable;
    if (query_at != query_count or draw_at != universal.RELATION_COUNT + 3 + capture.fri.layers.len + query_draws) return error.DetachedChildDrawMismatch;
}

fn secure(words: [4]M31) QM31 {
    return QM31.fromU32Unchecked(words[0].toU32(), words[1].toU32(), words[2].toU32(), words[3].toU32());
}
fn same(actual: QM31, expected_value: QM31) !void {
    if (!actual.eql(expected_value)) return error.DetachedChildDrawMismatch;
}

// Required real inputs; absence is a gate failure, never a skipped test.
// The key pin is supplied independently, not read from the candidate bundle.
test "SegmentV2 detached child owns genuine capture and exact recorded transcript" {
    const allocator = std.testing.allocator;
    const directory = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_CHILD_BUNDLE");
    defer allocator.free(directory);
    const pin_hex = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_CHILD_KEY_SHA256");
    defer allocator.free(pin_hex);
    const expected_path = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_CHILD_EXPECTED_WIRE");
    defer allocator.free(expected_path);
    const args = try command.parseArguments(&.{ directory, pin_hex, expected_path });
    var dir = try std.fs.cwd().openDir(args.directory, .{});
    defer dir.close();
    const key_json = try dir.readFileAlloc(allocator, "key.json", command.MAX_KEY_BYTES);
    defer allocator.free(key_json);
    const expected_json = try std.fs.cwd().readFileAlloc(allocator, args.expected_wire_path, command.MAX_INPUT_BYTES);
    defer allocator.free(expected_json);
    var expected = try command.OwnedExpectedV1.decode(allocator, expected_json);
    defer expected.deinit();
    const claims_json = try dir.readFileAlloc(allocator, "claims.json", command.MAX_INPUT_BYTES);
    defer allocator.free(claims_json);
    const input = try command.decodeClaims(allocator, claims_json);
    const proof_bytes = try dir.readFileAlloc(allocator, "proof.bin", input.proof_bytes);
    defer allocator.free(proof_bytes);
    try std.testing.expectEqual(input.proof_bytes, proof_bytes.len);
    try std.testing.expectEqual(input.proof_sha256, command.hash(proof_bytes));
    const key = try command.OwnedKeyV1.admit(allocator, key_json, args.independent_key_sha256);
    defer key.deinit();
    var ordinary_capture: verifier.ProofCapture = undefined;
    const ordinary_terminal = try verifier.verifyWithCapture(allocator, key.key(), &expected.data, input.claims, proof_bytes, &ordinary_capture);
    defer ordinary_capture.deinit(allocator);

    // The owner must survive both hostile writes and destruction of every
    // supplied dynamic allocation. No native producer exists in this test.
    const owner = blk: {
        const caller_key = try allocator.dupe(u8, key_json);
        defer allocator.free(caller_key);
        const caller_proof = try allocator.dupe(u8, proof_bytes);
        defer allocator.free(caller_proof);
        var caller_expected = try command.OwnedExpectedV1.decode(allocator, expected_json);
        defer caller_expected.deinit();
        var caller_claims = input.claims;
        const value = try OwnedV1.init(allocator, caller_key, args.independent_key_sha256, &caller_expected.data, caller_claims, caller_proof);
        @memset(caller_key, 0);
        @memset(caller_proof, 0);
        @memset(caller_expected.words, M31.zero());
        caller_claims.values = @splat(QM31.zero());
        break :blk value;
    };
    defer owner.deinit();
    try std.testing.expectEqual(ordinary_terminal, owner.terminal());
    try std.testing.expectEqualDeep(ordinary_capture, owner.storage().capture);
    try std.testing.expectEqualDeep(key.key().*, owner.key().*);
    try std.testing.expectEqualDeep(input.claims, owner.claims());
    try std.testing.expectEqualSlices(M31, expected.data.words(), owner.expected().words());
    try std.testing.expectEqual(input.proof_sha256, owner.proofSha256());
    try std.testing.expectEqual(args.independent_key_sha256, owner.keySha256());
    // Replaying this retained recording is a diagnostic, not an operational
    // getter. Its closure is checked once at owner admission above.
    try owner.storage().execution.validate();
    const before = owner.recordingView();
    for (0..3) |_| {
        _ = owner.key();
        _ = owner.expected();
        _ = owner.claims();
        _ = owner.relations();
        _ = owner.captureView();
        for (0..ordinary_capture.trace_paths.len) |tree| {
            _ = owner.tracePath(tree);
            for (0..owner.columnLogSizes(tree).len) |column| _ = owner.sampledPoints(tree, column);
        }
        for (0..ordinary_capture.fri.layers.len) |layer| _ = owner.friLayer(layer);
    }
    try std.testing.expectEqual(before.identity_sha256, owner.recordingView().identity_sha256);
    try @import("recursive_segment_v2_detached_composition.zig").testFromVerifiedChild(allocator, owner);

    var wrong_pin = args.independent_key_sha256;
    wrong_pin[0] ^= 1;
    try std.testing.expectError(error.DetachedKeyHashMismatch, OwnedV1.init(allocator, key_json, wrong_pin, &expected.data, input.claims, proof_bytes));
    try std.testing.expectError(error.EndOfStream, OwnedV1.init(allocator, key_json, args.independent_key_sha256, &expected.data, input.claims, proof_bytes[0 .. proof_bytes.len - 1]));
    const trailing = try allocator.alloc(u8, proof_bytes.len + 1);
    defer allocator.free(trailing);
    @memcpy(trailing[0..proof_bytes.len], proof_bytes);
    trailing[proof_bytes.len] = 0;
    try std.testing.expectError(error.TrailingProofBytes, OwnedV1.init(allocator, key_json, args.independent_key_sha256, &expected.data, input.claims, trailing));
    var wrong_claims = input.claims;
    wrong_claims.values[36] = wrong_claims.values[36].add(QM31.one());
    try std.testing.expectError(error.SegmentV2PublicInputClaimMismatch, OwnedV1.init(allocator, key_json, args.independent_key_sha256, &expected.data, wrong_claims, proof_bytes));

    // Use a second genuine, canonically authenticated statement. A raw
    // register edit would fail Span/job/lineage admission before the verifier.
    const other_expected_path = try std.process.getEnvVarOwned(allocator, "STWO_SEGMENT_V2_CHILD_OTHER_EXPECTED_WIRE");
    defer allocator.free(other_expected_path);
    const other_expected_json = try std.fs.cwd().readFileAlloc(allocator, other_expected_path, command.MAX_INPUT_BYTES);
    defer allocator.free(other_expected_json);
    var other_expected = try command.OwnedExpectedV1.decode(allocator, other_expected_json);
    defer other_expected.deinit();
    try std.testing.expectEqual(expected.words.len, other_expected.words.len);
    try std.testing.expect(!std.meta.eql(expected.data.wireId(), other_expected.data.wireId()));
    try std.testing.expectError(error.SegmentV2PublicInputClaimMismatch, OwnedV1.init(allocator, key_json, args.independent_key_sha256, &other_expected.data, input.claims, proof_bytes));

    // Change an actual sampled opening and canonically serialize it. Decoder
    // shape acceptance must not mask the required cryptographic rejection.
    const postcard = @import("interop_postcard");
    var stream = std.io.fixedBufferStream(proof_bytes);
    var changed_proof = try postcard.deserializeProof(recursion.engine.Hasher, allocator, stream.reader());
    defer changed_proof.deinit(allocator);
    const sampled = changed_proof.commitment_scheme_proof.sampled_values.items;
    const opening = &sampled[sampled.len - 1][0][0];
    opening.* = opening.add(QM31.one());
    var changed_bytes: std.ArrayList(u8) = .empty;
    defer changed_bytes.deinit(allocator);
    try postcard.serializeProof(recursion.engine.Hasher, changed_bytes.writer(allocator), changed_proof);
    try std.testing.expectError(error.OodsNotMatching, OwnedV1.init(allocator, key_json, args.independent_key_sha256, &expected.data, input.claims, changed_bytes.items));
    const captured = owner.captureView();
    std.debug.print("SEGMENT_V2_DETACHED_CHILD transcript_operations={d} poseidon_calls={d} sampled_values={d} queried_values={d} fri_layers={d} raw_queries={d} input_bytes={d} caller_destroyed=true\n", .{
        before.operations.len, before.trace.poseidon_calls.len, captured.sampled_values.len, captured.queried_values.len, captured.fri_layer_count, captured.raw_queries.len, proof_bytes.len,
    });
}
